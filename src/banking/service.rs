<conf-func>  \    //! Banking Integration — Service Layer (Issue #407)
//!
//! Handles:
//! - Account linkage with BVN/NIN identity verification
//! - Mandate creation and revocation
//! - Idempotent debit/credit transfers via Paystack/Flutterwave
</conf-func>  \  <value>
use super::models::{
    BankMandate, BankTransferLog, CreateMandateRequest, InitiateTransferRequest,
    LinkAccountRequest, LinkedBankAccount, TransferDirection,
};
use super::repository::BankingRepository;
use crate::payments::factory::PaymentProviderFactory;
use crate::services::bank_verification::{BankVerificationConfig, BankVerificationService};
use reqwest::Client as HttpClient;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;
</value>  \  <dir>
pub struct BankingService {
    repo: BankingRepository,
    verification: BankVerificationService,
    provider_factory: Arc<PaymentProviderFactory>,
    http: HttpClient,
}
</dir>  \  <util-lib>
impl BankingService {
    pub fn new(pool: PgPool, provider_factory: Arc<PaymentProviderFactory>) -> Self {
        let verification = BankVerificationService::with_provider_factory(provider_factory.clone());
        Self {
            repo: BankingRepository::new(pool),
            verification,
            provider_factory,
            http: HttpClient::new(),
        }
    }

    // ── Account Linkage ───────────────────────────────────────────────────────

    /// Verify account ownership via BVN/NIN, then tokenize and store.
    /// Sensitive credentials are never persisted in plaintext.
    #[instrument(skip(self, req), fields(user_id = %user_id))]
    pub async fn link_account(
        &self,
        user_id: Uuid,
        req: LinkAccountRequest,
    ) -> anyhow::Result<LinkedBankAccount> {
        // 1. Verify account ownership with payment provider
        let verification = self
            .verification
            .verify_account(&req.bank_code, &req.account_number, &req.account_name)
            .await
            .map_err(|e| {
                warn!(error = %e, "Bank account verification failed");
                anyhow::anyhow!("Account verification failed: {}", e)
            })?;

        info!(
            account_name = %verification.account_name,
            bank_code = %req.bank_code,
            "Bank account verified"
        );

        // 2. Tokenize: use SHA-256 of (account_number + bank_code) as stable token
        //    In production this would call a vault/tokenization service.
        let token_input = format!("{}:{}", req.account_number, req.bank_code);
        let account_token = format!("{:x}", Sha256::digest(token_input.as_bytes()));

        // 3. Mask account number for display
        let mask_len = req.account_number.len().saturating_sub(4);
        let account_mask = format!("****{}", &req.account_number[mask_len..]);

        // 4. Hash identity number (BVN/NIN) — never store plaintext
        let identity_hash = Some(format!(
            "{:x}",
            Sha256::digest(req.identity_number.as_bytes())
        ));

        // 5. Persist
        let account = self
            .repo
            .insert_linked_account(
                user_id,
                &account_token,
                &account_mask,
                &verification.account_name,
                &req.bank_code,
                verification.bank_name.as_deref().unwrap_or(""),
                "NGN",
                identity_hash.as_deref(),
                "flutterwave",
            )
            .await?;

        info!(account_id = %account.id, "Bank account linked successfully");
        Ok(account)
    }
</util-lib>  \  <ctrl>
    pub async fn unlink_account(&self, id: Uuid, user_id: Uuid) -> anyhow::Result<()> {
        let account = self.repo.get_linked_account(id).await?;
        if account.user_id != user_id {
            anyhow::bail!("Account does not belong to user");
        }
        self.repo
            .update_linked_account_status(id, "unlinked")
            .await?;
        info!(account_id = %id, "Bank account unlinked");
        Ok(())
    }
</ctrl>  \  <p>
    pub async fn list_accounts(&self, user_id: Uuid) -> anyhow::Result<Vec<LinkedBankAccount>> {
        self.repo.list_linked_accounts_for_user(user_id).await
    }

    // ── Mandate Management ────────────────────────────────────────────────────

    /// Create a direct debit/credit mandate via the payment provider.
    #[instrument(skip(self, req), fields(user_id = %user_id))]
    pub async fn create_mandate(
        &self,
        user_id: Uuid,
        req: CreateMandateRequest,
    ) -> anyhow::Result<BankMandate> {
        let account = self.repo.get_linked_account(req.linked_account_id).await?;
        if account.user_id != user_id {
            anyhow::bail!("Account does not belong to user");
        }
        if account.status != "active" {
            anyhow::bail!("Account is not active");
        }

        // In production: call provider API to create mandate and get authorization code.
        // Here we generate a deterministic reference for the mock path.
        let provider_reference = format!(
            "MANDATE-{}-{}",
            req.linked_account_id,
            chrono::Utc::now().timestamp()
        );

        let mandate = self
            .repo
            .insert_mandate(
                req.linked_account_id,
                user_id,
                &req.mandate_type,
                req.max_amount,
                &provider_reference,
                "paystack",
            )
            .await?;

        info!(mandate_id = %mandate.id, "Mandate created");
        Ok(mandate)
    }

    pub async fn revoke_mandate(&self, id: Uuid, user_id: Uuid) -> anyhow::Result<()> {
        // Verify ownership via the linked account
        let mandate = self.get_mandate_for_user(id, user_id).await?;
        self.repo.revoke_mandate(mandate.id).await?;
        info!(mandate_id = %id, "Mandate revoked");
        Ok(())
    }

    async fn get_mandate_for_user(&self, id: Uuid, user_id: Uuid) -> anyhow::Result<BankMandate> {
        // Fetch via linked account ownership check
        let row: Option<BankMandate> = sqlx::query_as(
            "SELECT bm.* FROM bank_mandates bm WHERE bm.id = $1 AND bm.user_id = $2",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(self.repo.pool())
        .await?;
        row.ok_or_else(|| anyhow::anyhow!("Mandate not found or access denied"))
    }
</p>  \  <conf>
    // ── Idempotent Transfers ──────────────────────────────────────────────────

    /// Initiate a debit or credit transfer with strict idempotency.
    /// If the idempotency_key already exists, returns the existing record without
    /// re-submitting to the provider.
    #[instrument(skip(self, req), fields(idempotency_key = %req.idempotency_key))]
    pub async fn initiate_transfer(
        &self,
        req: InitiateTransferRequest,
    ) -> anyhow::Result<BankTransferLog> {
        // 1. Idempotency check — return early if already processed
        if let Some(existing) = self
            .repo
            .get_transfer_by_idempotency_key(&req.idempotency_key)
            .await?
        {
            info!(
                idempotency_key = %req.idempotency_key,
                status = %existing.status,
                "Returning existing transfer (idempotent)"
            );
            return Ok(existing);
        }

        // 2. Validate mandate if provided
        if let Some(mandate_id) = req.mandate_id {
            let mandate = self
                .repo
                .get_active_mandate(req.linked_account_id, &req.direction.to_string())
                .await?;
            match &mandate {
                None => anyhow::bail!("No active mandate for this account and direction"),
                Some(m) if m.id != mandate_id => anyhow::bail!("Mandate ID mismatch"),
                Some(m) if req.amount > m.max_amount => {
                    anyhow::bail!("Amount exceeds mandate limit")
                }
                _ => {}
            }
        }

        // 3. Create pending transfer record (idempotent upsert)
        let transfer = self
            .repo
            .upsert_transfer(
                &req.idempotency_key,
                req.mandate_id,
                req.linked_account_id,
                &req.direction.to_string(),
                req.amount,
                &req.currency,
                "paystack",
            )
            .await?;

        // 4. Submit to provider (async — status updated via webhook or polling)
        let result = self.submit_to_provider(&transfer).await;

        match result {
            Ok(provider_ref) => {
                self.repo
                    .update_transfer_status(transfer.id, "pending", Some(&provider_ref), None, None)
                    .await?;
                info!(
                    transfer_id = %transfer.id,
                    provider_ref = %provider_ref,
                    "Transfer submitted to provider"
                );
            }
            Err(e) => {
                error!(transfer_id = %transfer.id, error = %e, "Provider submission failed");
                self.repo
                    .update_transfer_status(transfer.id, "failed", None, None, Some(&e.to_string()))
                    .await?;
            }
        }

        // Return the latest state
        self.repo
            .get_transfer_by_idempotency_key(&req.idempotency_key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Transfer record missing after upsert"))
    }

    /// Submit transfer to payment provider. Returns provider reference on success.
    async fn submit_to_provider(&self, transfer: &BankTransferLog) -> anyhow::Result<String> {
        let account = self
            .repo
            .get_linked_account(transfer.linked_account_id)
            .await?;

        let paystack_key = std::env::var("PAYSTACK_SECRET_KEY")
            .map_err(|_| anyhow::anyhow!("PAYSTACK_SECRET_KEY not configured"))?;

        let payload = serde_json::json!({
            "source": "balance",
            "amount": transfer.amount,
            "recipient": account.account_token,
            "reference": transfer.idempotency_key,
            "currency": transfer.currency,
        });

        let url = match transfer.direction.as_str() {
            "credit" => "https://api.paystack.co/transfer",
            _ => "https://api.paystack.co/charge/authorization",
        };

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.http
                .post(url)
                .bearer_auth(&paystack_key)
                .json(&payload)
                .send(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Provider request timed out"))??;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Provider error: {}", body);
        }

        let json: serde_json::Value = resp.json().await?;
        let reference = json
            .pointer("/data/reference")
            .or_else(|| json.pointer("/data/transfer_code"))
            .and_then(|v| v.as_str())
            .unwrap_or(&transfer.idempotency_key)
            .to_string();

        Ok(reference)
    }
}
</conf>  \  <util-conf>
// Allow repository to expose pool for internal queries
impl BankingRepository {
    pub(super) fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
}
</util-conf>
