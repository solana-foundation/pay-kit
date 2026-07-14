//! Server-side payment verification for the Solana subscription intent.
//!
//! Generates 402 challenges that pin the subscriber to an on-chain `Plan` and
//! a per-period charging cadence, then verifies activation credentials by
//! re-deriving the `SubscriptionDelegation` PDA and asserting the on-chain
//! state matches the challenge.
//!
//! Renewals are server-driven on-chain transactions and do not pass through
//! this handler.
//!
//! # Quick Start
//!
//! ```ignore
//! use crate::mpp::server::subscription::{SubscriptionConfig, SubscriptionServer};
//! use crate::mpp::protocol::intents::SubscriptionPeriodUnit;
//!
//! let server = SubscriptionServer::new(SubscriptionConfig {
//!     plan_id: "8tWb...".to_string(),
//!     mint: "EPjFW...".to_string(),
//!     token_program: crate::mpp::protocol::solana::programs::TOKEN_PROGRAM.to_string(),
//!     decimals: 6,
//!     puller: "5fKb...".to_string(),
//!     recipient: "9xAX...".to_string(),
//!     period_unit: SubscriptionPeriodUnit::Day,
//!     period_count: 30,
//!     ..Default::default()
//! })?;
//!
//! let challenge = server.subscription_challenge("10000000")?;
//! ```

use std::sync::Arc;

use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use crate::mpp::error::Error;
use crate::mpp::expires;
use crate::mpp::program::subscriptions::{
    find_subscription_pda, parse_pubkey, INSTRUCTION_SUBSCRIBE, INSTRUCTION_TRANSFER_SUBSCRIPTION,
    SUBSCRIPTIONS_PROGRAM_ID,
};
use crate::mpp::protocol::core::{
    compute_challenge_id, Base64UrlJson, PaymentChallenge, PaymentCredential, Receipt, ReceiptKind,
};
use crate::mpp::protocol::intents::SubscriptionMethodDetails;
use crate::mpp::protocol::intents::{
    ActivatePayload, SubscriptionAction, SubscriptionPeriodUnit, SubscriptionReceiptExtensions,
    SubscriptionRequest,
};
use crate::mpp::protocol::solana::default_rpc_url;
use crate::mpp::server::charge::VerificationError;
use crate::mpp::store::{MemoryStore, Store};

const METHOD_NAME: &str = "solana";
const INTENT_NAME: &str = "subscription";

/// Configuration for a subscription server route.
#[derive(Clone)]
pub struct SubscriptionConfig {
    /// Base58 of the on-chain `Plan` PDA.
    pub plan_id: String,
    /// Base58 of the SPL token mint (must equal `plan.mint`).
    pub mint: String,
    /// Decimal precision of the mint.
    pub decimals: u8,
    /// Base58 of the SPL Token / Token-2022 program ID.
    pub token_program: String,
    /// Base58 of the server's puller pubkey (in `plan.pullers` or `plan.owner`).
    pub puller: String,
    /// Base58 of the primary recipient wallet.
    pub recipient: String,
    /// Billing period unit. The Solana profile rejects `month`.
    pub period_unit: SubscriptionPeriodUnit,
    /// Positive integer count of `period_unit` per billing period.
    pub period_count: u64,
    /// Optional RFC3339 expiry of the recurring authorization.
    pub subscription_expires: Option<String>,
    /// Solana network: mainnet, devnet, testnet, or localnet.
    pub network: String,
    /// Subscriptions program ID. Defaults to the canonical mainnet deployment.
    pub program_id: Option<String>,
    /// Override the public RPC for the configured network.
    pub rpc_url: Option<String>,
    /// HMAC secret for challenge IDs. REQUIRED — the SDK refuses to
    /// fall back to env-var lookups so misconfigured deployments fail
    /// at boot instead of silently using whatever happened to be in
    /// the process env.
    pub challenge_binding_secret: String,
    /// 402 realm string. REQUIRED — the operator picks an explicit
    /// value rather than inheriting an SDK-side default that's
    /// invisible at config-review time.
    pub realm: String,
    /// Route/resource this endpoint protects. When set, it is embedded in the
    /// challenge (HMAC-bound) and re-checked at verify time so a challenge
    /// issued for one route cannot be redeemed against another that shares this
    /// server's challenge-binding secret, realm, mint, and recipient. `None`
    /// disables the check for single-route deployments. Mirrors the TypeScript
    /// MPP server's `resource` binding.
    pub resource: Option<String>,
    /// If `true`, the server pays activation transaction fees.
    pub fee_payer: bool,
    /// Fee-payer signer (used when `fee_payer` is `true`). Required at
    /// verify time to co-sign the activation transaction; optional at
    /// challenge time if `fee_payer_pubkey` is set explicitly.
    pub fee_payer_signer: Option<Arc<dyn solana_keychain::SolanaSigner>>,
    /// Fee-payer pubkey emitted as `methodDetails.feePayerKey` in the
    /// challenge. When `None`, falls back to the `fee_payer_signer`'s
    /// pubkey. Set this when the server has the pubkey but not the
    /// private key at challenge time (e.g. a stateless middleware that
    /// re-builds the SubscriptionServer per request).
    pub fee_payer_pubkey: Option<String>,
    /// Replay-protection store.
    pub store: Option<Arc<dyn Store>>,

    // ── Pre-published Plan terms ────────────────────────────────────────
    //
    // These fields are emitted into `methodDetails` so the client can
    // build a `SubscribeData` instruction without round-tripping the
    // Plan account from RPC. They mirror the immutable terms the
    // on-chain program validates against in `Subscribe::process`.
    /// Numeric `plan_id` (the u64 the program reads from `SubscribeData`).
    /// The string `plan_id` above is the PDA derived from this value.
    /// Required for proper subscribe-instruction construction.
    pub plan_id_numeric: Option<u64>,
    /// Plan PDA bump seed.
    pub plan_bump: Option<u8>,
    /// Plan's `created_at` unix timestamp — set when the Plan was first
    /// published on-chain. Must be passed verbatim to `SubscribeData`
    /// or the program rejects with a terms mismatch.
    pub plan_created_at: Option<i64>,
    /// Human-readable description carried into the `PaymentChallenge` and
    /// the embedded `SubscriptionRequest`. Surfaces in client UIs (Touch
    /// ID prompts, `pay subscriptions list/status`) so users can see what
    /// they're paying for. Typically the endpoint's `description:` YAML
    /// field.
    pub description: Option<String>,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            plan_id: String::new(),
            mint: String::new(),
            decimals: 6,
            token_program: String::new(),
            puller: String::new(),
            recipient: String::new(),
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: 30,
            subscription_expires: None,
            network: "mainnet".into(),
            program_id: None,
            rpc_url: None,
            challenge_binding_secret: String::new(),
            realm: String::new(),
            resource: None,
            fee_payer: false,
            fee_payer_signer: None,
            fee_payer_pubkey: None,
            store: None,
            plan_id_numeric: None,
            plan_bump: None,
            plan_created_at: None,
            description: None,
        }
    }
}

/// Server-side handler for the Solana subscription intent.
#[derive(Clone)]
pub struct SubscriptionServer {
    config: SubscriptionConfig,
    program_id: String,
    challenge_binding_secret: String,
    realm: String,
    #[allow(dead_code)]
    store: Arc<dyn Store>,
    #[allow(dead_code)]
    rpc_url: String,
}

impl SubscriptionServer {
    /// Create a new server handler from config. Validates pubkeys and
    /// period bounds eagerly; misconfigured servers fail at boot, not on
    /// the first challenge.
    pub fn new(config: SubscriptionConfig) -> Result<Self, Error> {
        if config.plan_id.is_empty() {
            return Err(Error::InvalidConfig("plan_id is required".into()));
        }
        if config.mint.is_empty() {
            return Err(Error::InvalidConfig("mint is required".into()));
        }
        if config.token_program.is_empty() {
            return Err(Error::InvalidConfig("token_program is required".into()));
        }
        if config.puller.is_empty() {
            return Err(Error::InvalidConfig("puller is required".into()));
        }
        if config.recipient.is_empty() {
            return Err(Error::InvalidConfig("recipient is required".into()));
        }
        if config.challenge_binding_secret.is_empty() {
            return Err(Error::InvalidConfig(
                "challenge_binding_secret is required".into(),
            ));
        }
        if config.realm.is_empty() {
            return Err(Error::InvalidConfig("realm is required".into()));
        }

        // Validate all pubkeys parse.
        parse_pubkey(&config.plan_id, "plan_id")?;
        parse_pubkey(&config.mint, "mint")?;
        parse_pubkey(&config.token_program, "token_program")?;
        parse_pubkey(&config.puller, "puller")?;
        parse_pubkey(&config.recipient, "recipient")?;

        // Validate the period mapping.
        config.period_unit.to_period_hours(config.period_count)?;

        let program_id = config
            .program_id
            .clone()
            .unwrap_or_else(|| SUBSCRIPTIONS_PROGRAM_ID.to_string());
        parse_pubkey(&program_id, "program_id")?;

        let challenge_binding_secret = config.challenge_binding_secret.clone();
        let realm = config.realm.clone();

        let store: Arc<dyn Store> = config
            .store
            .clone()
            .unwrap_or_else(|| Arc::new(MemoryStore::new()));

        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&config.network).to_string());

        Ok(SubscriptionServer {
            config,
            program_id,
            challenge_binding_secret,
            realm,
            store,
            rpc_url,
        })
    }

    /// Generate a 402 subscription challenge for the configured amount per period.
    pub fn subscription_challenge(
        &self,
        amount_base_units: &str,
    ) -> Result<PaymentChallenge, Error> {
        if amount_base_units.is_empty() {
            return Err(Error::Other("amount is required".into()));
        }
        // Parse to validate it's a positive integer in base units.
        let _amount: u64 = amount_base_units
            .parse()
            .map_err(|_| Error::Other(format!("Invalid amount: {amount_base_units}")))?;

        // Build the typed methodDetails struct. The wire form is
        // camelCase serde-driven from the struct definition; no manual
        // JSON pokery.
        let fee_payer_key = if self.config.fee_payer {
            self.config.fee_payer_pubkey.clone().or_else(|| {
                self.config
                    .fee_payer_signer
                    .as_ref()
                    .map(|s| s.pubkey().to_string())
            })
        } else {
            None
        };
        let recent_blockhash = {
            // Pre-fetch a recent blockhash on the configured RPC. The
            // client's activation builder honours `recentBlockhash` and
            // skips its own RPC roundtrip — important in sandbox/proxy
            // setups where the agent might not have a usable RPC URL.
            // Best-effort: if the fetch fails (RPC down, wrong URL) the
            // challenge still goes out and the client falls back.
            use solana_rpc_client::rpc_client::RpcClient;
            let rpc = RpcClient::new(self.rpc_url.clone());
            rpc.get_latest_blockhash().ok().map(|h| h.to_string())
        };
        let expected_period_hours = self
            .config
            .period_unit
            .to_period_hours(self.config.period_count)
            .ok();

        let method_details = SubscriptionMethodDetails {
            plan_id: self.config.plan_id.clone(),
            mint: self.config.mint.clone(),
            token_program: self.config.token_program.clone(),
            decimals: Some(self.config.decimals),
            puller: self.config.puller.clone(),
            // The Plan owner / merchant. The server doesn't model this
            // separately yet — pay-server uses operator.recipient (the
            // puller) as the plan owner. When the operator publishes
            // the plan they ARE the merchant; this is correct for the
            // common case. Surface it explicitly in methodDetails so
            // the client doesn't have to guess.
            merchant: Some(self.config.puller.clone()),
            recipient: Some(self.config.recipient.clone()),
            amount: Some(amount_base_units.to_string()),
            program_id: Some(self.program_id.clone()),
            network: Some(self.config.network.clone()),
            fee_payer: self.config.fee_payer,
            fee_payer_key,
            recent_blockhash,
            plan_id_numeric: self.config.plan_id_numeric,
            plan_bump: self.config.plan_bump,
            expected_period_hours,
            expected_created_at: self.config.plan_created_at,
        };
        let method_details_value = serde_json::to_value(&method_details)
            .map_err(|e| Error::Other(format!("Failed to serialize methodDetails: {e}")))?;

        let request = SubscriptionRequest {
            amount: amount_base_units.to_string(),
            currency: self.config.mint.clone(),
            period_unit: self.config.period_unit,
            period_count: self.config.period_count.to_string(),
            recipient: self.config.recipient.clone(),
            subscription_expires: self.config.subscription_expires.clone(),
            description: self.config.description.clone(),
            resource: self.config.resource.clone(),
            method_details: Some(method_details_value),
            ..Default::default()
        };

        let encoded = Base64UrlJson::from_typed(&request)?;
        let default_expires = expires::minutes(5);

        Ok(PaymentChallenge::with_challenge_binding_secret_full(
            &self.challenge_binding_secret,
            &self.realm,
            METHOD_NAME,
            INTENT_NAME,
            encoded,
            Some(&default_expires),
            None,
            // Surface the endpoint description on the top-level challenge
            // too — pay's client checks challenge.description first when
            // building the Touch ID prompt, falling back to
            // request.description only when the top-level is unset.
            self.config.description.as_deref(),
            None,
        ))
    }

    // ── Verify ──────────────────────────────────────────────────────────

    /// Verify a subscription activation credential.
    ///
    /// Returns a [`ReceiptKind::Subscription`] on success: the activation
    /// transaction has been broadcast (with server co-signature when fee
    /// sponsorship is configured), confirmed on-chain, and the resulting
    /// `SubscriptionDelegation` account has been validated against the
    /// challenge's terms.
    ///
    /// Implements the spec's §authorization-scope-verification flow:
    ///
    /// 1. Tier-1 HMAC check on the echoed challenge id.
    /// 2. Pinned-field check (method, intent, realm match this server).
    /// 3. Decode the activation payload.
    /// 4. Reject `type="signature"` combined with `feePayer=true`.
    /// 5. Validate the activation transaction's instruction scope.
    /// 6. Co-sign as fee payer when configured, then broadcast.
    /// 7. Re-derive the `SubscriptionDelegation` PDA and fetch its state.
    /// 8. Assert the snapshotted terms match the challenge.
    /// 9. Build a `ReceiptKind::Subscription`.
    pub async fn verify_credential(
        &self,
        credential: &PaymentCredential,
    ) -> Result<ReceiptKind, VerificationError> {
        // ── Tier 1: HMAC ─────────────────────────────────────────────────
        let expected_id = compute_challenge_id(
            &self.challenge_binding_secret,
            &self.realm,
            credential.challenge.method.as_str(),
            credential.challenge.intent.as_str(),
            credential.challenge.request.raw(),
            credential.challenge.expires.as_deref(),
            credential.challenge.digest.as_deref(),
            credential.challenge.opaque.as_ref().map(|o| o.raw()),
        );
        if credential.challenge.id != expected_id {
            return Err(VerificationError::credential_mismatch(
                "Challenge HMAC mismatch — this server did not issue the echoed challenge",
            ));
        }

        // ── Tier 2: pinned fields ────────────────────────────────────────
        if credential.challenge.method.as_str() != METHOD_NAME {
            return Err(VerificationError::credential_mismatch(format!(
                "Credential method `{}` does not match this server (expected `{METHOD_NAME}`)",
                credential.challenge.method
            )));
        }
        if credential.challenge.intent.as_str() != INTENT_NAME {
            return Err(VerificationError::credential_mismatch(format!(
                "Credential intent `{}` is not a subscription",
                credential.challenge.intent
            )));
        }
        if credential.challenge.realm != self.realm {
            return Err(VerificationError::credential_mismatch(format!(
                "Credential realm `{}` does not match this server (expected `{}`)",
                credential.challenge.realm, self.realm
            )));
        }

        // ── Decode the challenge request ─────────────────────────────────
        let request: SubscriptionRequest = credential.challenge.request.decode().map_err(|e| {
            VerificationError::invalid_payload(format!("Failed to decode request: {e}"))
        })?;

        if request.currency != self.config.mint {
            return Err(VerificationError::credential_mismatch(format!(
                "Credential mint `{}` does not match this server (expected `{}`)",
                request.currency, self.config.mint
            )));
        }
        if request.recipient != self.config.recipient {
            return Err(VerificationError::credential_mismatch(
                "Credential recipient does not match this server",
            ));
        }
        // Route binding: the challenge's resource must match this route's
        // resource, so a challenge issued for one route cannot be redeemed
        // against another that shares this server's challenge-binding secret,
        // realm, mint, and recipient. Fail closed on any mismatch (including a
        // resource-bound challenge presented to an unbound route and vice
        // versa). Mirrors the TypeScript MPP server's `resource` binding.
        if request.resource != self.config.resource {
            return Err(VerificationError::credential_mismatch(
                "Credential resource does not match this server's route",
            ));
        }

        // ── Decode the activation payload ───────────────────────────────
        // The credential's `payload` may carry either a raw `ActivatePayload`
        // (the spec's intended shape per draft-solana-subscription-00) or a
        // tagged `SubscriptionAction::Activate(...)` wrapper. Accept both for
        // forward-compatibility, but reject anything else.
        let activate = decode_activate_payload(credential)?;

        let payload_type = activate.payload_type.as_str();
        let fee_payer_configured = self.config.fee_payer && self.config.fee_payer_signer.is_some();
        if payload_type == "signature" && fee_payer_configured {
            return Err(VerificationError::invalid_payload(
                "type=\"signature\" credentials cannot be used with fee sponsorship",
            ));
        }

        // ── Settle the activation transaction ────────────────────────────
        let (subscriber, activation_signature) = match payload_type {
            "transaction" => {
                let tx_b64 = activate.transaction.as_deref().ok_or_else(|| {
                    VerificationError::invalid_payload(
                        "type=\"transaction\" payload missing `transaction` field",
                    )
                })?;
                let mut tx = decode_base64_transaction(tx_b64)?;
                let subscriber = extract_subscriber_from_tx(&tx, &request, &self.config)?;
                validate_activation_scope(&tx, &request, &self.program_id)?;

                if fee_payer_configured {
                    co_sign_as_fee_payer(&mut tx, self.config.fee_payer_signer.as_ref().unwrap())
                        .await?;
                }

                // Idempotent broadcast: if the delegation PDA already exists
                // (a previous activation landed on-chain but the receipt
                // round-trip failed), skip the broadcast — the on-chain
                // `Subscribe` instruction would reject with
                // `AlreadySubscribed` (0x205) and abort the whole tx,
                // burying the actual outcome. The subsequent fetch +
                // terms-check on lines below catches any divergence.
                let program_id = parse_pubkey(&self.program_id, "program_id")
                    .map_err(|e| VerificationError::new(e.to_string()))?;
                let plan_pda = parse_pubkey(&self.config.plan_id, "plan_id")
                    .map_err(|e| VerificationError::new(e.to_string()))?;
                let (delegation_pda, _) =
                    find_subscription_pda(&plan_pda, &subscriber, &program_id);
                let delegation_already_exists = self
                    .fetch_subscription_delegation(&delegation_pda)
                    .await
                    .is_ok();

                let sig = if delegation_already_exists {
                    // Look up the original landing tx so the receipt can
                    // carry the signature instead of the bare PDA.
                    self.fetch_subscription_creation_signature(&delegation_pda)
                        .await
                        .ok()
                } else {
                    Some(self.broadcast_and_confirm(&tx).await?.to_string())
                };
                (subscriber, sig)
            }
            "signature" => {
                // Push mode (client already broadcast). Not yet supported
                // in v0 — the spec defines it but extracting the
                // subscriber from a fetched transaction requires a
                // versioned-message-aware account_keys reader we don't
                // ship in pay-kit yet.
                return Err(VerificationError::invalid_payload(
                    "Push-mode (type=\"signature\") activation is not yet supported by this server. \
                     Use type=\"transaction\" for v0.",
                ));
            }
            other => {
                return Err(VerificationError::invalid_payload(format!(
                    "Unsupported payload type `{other}` (expected `transaction` or `signature`)"
                )))
            }
        };

        // ── Derive subscription PDA and read on-chain state ──────────────
        let program_id = parse_pubkey(&self.program_id, "program_id")
            .map_err(|e| VerificationError::new(e.to_string()))?;
        let plan_pda = parse_pubkey(&self.config.plan_id, "plan_id")
            .map_err(|e| VerificationError::new(e.to_string()))?;
        let (subscription_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);

        let delegation = self
            .fetch_subscription_delegation(&subscription_pda)
            .await?;

        // ── Validate snapshotted terms ──────────────────────────────────
        let expected_amount: u64 = request.amount.parse().map_err(|_| {
            VerificationError::invalid_payload(format!(
                "Challenge amount `{}` is not a positive integer",
                request.amount
            ))
        })?;
        let expected_period_hours = request
            .period_hours()
            .map_err(|e| VerificationError::invalid_payload(e.to_string()))?;

        if delegation.amount_per_period != expected_amount {
            return Err(VerificationError::credential_mismatch(format!(
                "SubscriptionDelegation amount mismatch: expected {expected_amount}, got {}",
                delegation.amount_per_period
            )));
        }
        if delegation.period_hours != expected_period_hours {
            return Err(VerificationError::credential_mismatch(format!(
                "SubscriptionDelegation period mismatch: expected {expected_period_hours}h, got {}h",
                delegation.period_hours
            )));
        }
        if delegation.plan_pda != plan_pda {
            return Err(VerificationError::credential_mismatch(format!(
                "SubscriptionDelegation plan mismatch: expected {plan_pda}, got {}",
                delegation.plan_pda
            )));
        }
        // Mint isn't stored on the delegation — the on-chain `Subscribe`
        // ix binds the delegation's terms to the parent Plan's mint, and
        // we already validated `plan_pda` matches the configured plan.
        if delegation.amount_pulled_in_period != expected_amount {
            return Err(VerificationError::new(
                "Activation transaction did not execute the first-period charge",
            ));
        }

        // ── Build the receipt ───────────────────────────────────────────
        let period_start_secs = delegation.current_period_start_ts;
        let period_end_secs = period_start_secs.saturating_add(expected_period_hours as i64 * 3600);

        let receipt = ReceiptKind::Subscription {
            base: Receipt {
                status: crate::mpp::protocol::core::ReceiptStatus::Success,
                method: METHOD_NAME.into(),
                timestamp: format_rfc3339_seconds(now_unix_secs()),
                reference: subscription_pda.to_string(),
                challenge_id: credential.challenge.id.clone(),
            },
            extensions: SubscriptionReceiptExtensions {
                subscription_id: subscription_pda.to_string(),
                plan_id: self.config.plan_id.clone(),
                period_index: "0".to_string(),
                period_start_ts: format_rfc3339_seconds(period_start_secs),
                period_end_ts: format_rfc3339_seconds(period_end_secs),
                expires_at: request.subscription_expires.clone(),
                activation_signature,
            },
        };
        Ok(receipt)
    }

    /// Broadcast a signed transaction and wait for `confirmed` (NOT
    /// `finalized`). The 402 caller is blocked on this round-trip, so
    /// every extra slot is a second of UX latency. `confirmed` means
    /// supermajority observed it (~1-2 slots, ~400-800ms); finalisation
    /// happens behind the scenes regardless and the subscription will
    /// still be honoured on the next request.
    async fn broadcast_and_confirm(
        &self,
        tx: &Transaction,
    ) -> Result<Signature, VerificationError> {
        use solana_commitment_config::CommitmentConfig;
        use solana_rpc_client::rpc_client::RpcClient;
        let rpc_url = self.rpc_url.clone();
        let serialized = bincode::serialize(tx).map_err(|e| {
            VerificationError::invalid_payload(format!("Failed to serialise tx: {e}"))
        })?;
        // RpcClient is blocking; offload to a worker thread.
        tokio::task::spawn_blocking(move || {
            let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
            let tx: Transaction = bincode::deserialize(&serialized)
                .map_err(|e| VerificationError::invalid_payload(format!("tx round-trip: {e}")))?;
            rpc.send_and_confirm_transaction(&tx).map_err(|e| {
                VerificationError::transaction_failed(format!("Broadcast failed: {e}"))
            })
        })
        .await
        .map_err(|e| VerificationError::network_error(format!("RPC task join: {e}")))?
    }

    async fn fetch_subscription_delegation(
        &self,
        subscription_pda: &Pubkey,
    ) -> Result<SubscriptionDelegationView, VerificationError> {
        use solana_rpc_client::rpc_client::RpcClient;
        let rpc_url = self.rpc_url.clone();
        let pda = *subscription_pda;
        tokio::task::spawn_blocking(move || {
            let rpc = RpcClient::new(rpc_url);
            let account = rpc.get_account(&pda).map_err(|e| {
                VerificationError::not_found(format!(
                    "SubscriptionDelegation account {pda} not found: {e}"
                ))
            })?;
            decode_subscription_delegation(&account.data).map_err(VerificationError::new)
        })
        .await
        .map_err(|e| VerificationError::network_error(format!("RPC task join: {e}")))?
    }

    /// Look up the activation transaction signature for an existing
    /// `SubscriptionDelegation` PDA by walking `getSignaturesForAddress`.
    ///
    /// The PDA's signature history is "newest first"; the original
    /// `Subscribe` transaction is the last entry. We page through with a
    /// reasonable limit — for a freshly-activated subscription this is
    /// just one entry, and a long-lived subscription with many renewals
    /// would still yield the activation tx as the oldest record.
    async fn fetch_subscription_creation_signature(
        &self,
        subscription_pda: &Pubkey,
    ) -> Result<String, VerificationError> {
        use solana_rpc_client::rpc_client::RpcClient;
        let rpc_url = self.rpc_url.clone();
        let pda = *subscription_pda;
        tokio::task::spawn_blocking(move || {
            let rpc = RpcClient::new(rpc_url);
            let sigs = rpc.get_signatures_for_address(&pda).map_err(|e| {
                VerificationError::network_error(format!(
                    "getSignaturesForAddress({pda}) failed: {e}"
                ))
            })?;
            // The activation tx is the oldest signature for this PDA — the
            // RPC returns newest-first, so take the last entry.
            sigs.into_iter().last().map(|s| s.signature).ok_or_else(|| {
                VerificationError::not_found(format!(
                    "No signatures returned for SubscriptionDelegation {pda}"
                ))
            })
        })
        .await
        .map_err(|e| VerificationError::network_error(format!("RPC task join: {e}")))?
    }

    // ── Accessors ──

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn plan_id(&self) -> &str {
        &self.config.plan_id
    }

    pub fn mint(&self) -> &str {
        &self.config.mint
    }

    pub fn recipient(&self) -> &str {
        &self.config.recipient
    }

    pub fn puller(&self) -> &str {
        &self.config.puller
    }

    pub fn program_id(&self) -> &str {
        &self.program_id
    }

    pub fn period_unit(&self) -> SubscriptionPeriodUnit {
        self.config.period_unit
    }

    pub fn period_count(&self) -> u64 {
        self.config.period_count
    }
}

// ── Verify helpers ──────────────────────────────────────────────────────────

/// Pluck the `ActivatePayload` out of a credential's `payload` field,
/// accepting both the raw `ActivatePayload` shape (the v0 spec) and the
/// tagged `SubscriptionAction::Activate(...)` wrapper.
fn decode_activate_payload(
    credential: &PaymentCredential,
) -> Result<ActivatePayload, VerificationError> {
    if let Ok(action) = serde_json::from_value::<SubscriptionAction>(credential.payload.clone()) {
        let SubscriptionAction::Activate(payload) = action;
        return Ok(payload);
    }
    serde_json::from_value::<ActivatePayload>(credential.payload.clone())
        .map_err(|e| VerificationError::invalid_payload(format!("Failed to decode payload: {e}")))
}

/// Base64-decode + bincode-deserialise the activation transaction. The
/// client sends it in standard base64 per the spec.
fn decode_base64_transaction(b64: &str) -> Result<Transaction, VerificationError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        .map_err(|e| VerificationError::invalid_payload(format!("Tx base64 decode: {e}")))?;
    bincode::deserialize(&bytes)
        .map_err(|e| VerificationError::invalid_payload(format!("Tx bincode decode: {e}")))
}

/// Extract the subscriber pubkey from the activation transaction.
///
/// When fee sponsorship is in play, the fee payer (first signer) is the
/// server; the subscriber is the next signer that isn't the puller.
/// Otherwise the subscriber is `account_keys[0]`.
fn extract_subscriber_from_tx(
    tx: &Transaction,
    _request: &SubscriptionRequest,
    config: &SubscriptionConfig,
) -> Result<Pubkey, VerificationError> {
    let keys = &tx.message.account_keys;
    if keys.is_empty() {
        return Err(VerificationError::invalid_payload(
            "Transaction has no account keys",
        ));
    }
    let puller = parse_pubkey(&config.puller, "puller")
        .map_err(|e| VerificationError::new(e.to_string()))?;

    // Determine whether the activation tx was built with the server
    // sponsoring fees. We check the `fee_payer` flag — NOT the
    // `fee_payer_signer` Option — because stateless middlewares
    // (pay-server's per-request SubscriptionServer) carry the pubkey
    // but not the signer at verify time. The fee-payer pubkey lives
    // either in `fee_payer_pubkey` (explicit override) or in the
    // signer (when one is configured).
    let fee_payer_in_play = config.fee_payer;
    let fee_payer_pubkey: Option<Pubkey> = if fee_payer_in_play {
        let key_str = config.fee_payer_pubkey.clone().or_else(|| {
            config
                .fee_payer_signer
                .as_ref()
                .map(|s| s.pubkey().to_string())
        });
        match key_str {
            Some(s) => Some(
                parse_pubkey(&s, "fee_payer_key")
                    .map_err(|e| VerificationError::new(e.to_string()))?,
            ),
            None => None,
        }
    } else {
        None
    };

    if let Some(fp) = fee_payer_pubkey.filter(|_| fee_payer_in_play) {
        // account_keys[0] is the fee-payer (the server's wallet); the
        // subscriber is the next signer that's neither the fee-payer
        // nor the puller.
        let signer_count = tx.message.header.num_required_signatures as usize;
        for k in keys.iter().take(signer_count).skip(1) {
            if *k != puller && *k != fp {
                return Ok(*k);
            }
        }
        return Err(VerificationError::invalid_payload(
            "Could not identify subscriber among transaction signers",
        ));
    }

    let first = keys[0];
    if first == puller {
        return Err(VerificationError::invalid_payload(
            "Subscriber cannot equal the server puller",
        ));
    }
    Ok(first)
}

/// Static scope check per spec §authorization-scope-verification.
///
/// Requires exactly one Subscribe instruction and exactly one
/// TransferSubscription instruction on the configured subscriptions
/// program, with Subscribe ordered before TransferSubscription.
fn validate_activation_scope(
    tx: &Transaction,
    _request: &SubscriptionRequest,
    program_id_str: &str,
) -> Result<(), VerificationError> {
    let program_id = parse_pubkey(program_id_str, "program_id")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let keys = &tx.message.account_keys;

    let mut subscribe_idx: Option<usize> = None;
    let mut transfer_idx: Option<usize> = None;
    for (i, ix) in tx.message.instructions.iter().enumerate() {
        let prog_idx = ix.program_id_index as usize;
        if prog_idx >= keys.len() {
            continue;
        }
        if keys[prog_idx] != program_id {
            continue;
        }
        let Some(disc) = ix.data.first().copied() else {
            continue;
        };
        if disc == INSTRUCTION_SUBSCRIBE {
            if subscribe_idx.is_some() {
                return Err(VerificationError::invalid_payload(
                    "Activation tx contains multiple subscribe instructions",
                ));
            }
            subscribe_idx = Some(i);
        } else if disc == INSTRUCTION_TRANSFER_SUBSCRIPTION {
            if transfer_idx.is_some() {
                return Err(VerificationError::invalid_payload(
                    "Activation tx contains multiple transfer_subscription instructions",
                ));
            }
            transfer_idx = Some(i);
        }
    }

    let subscribe = subscribe_idx.ok_or_else(|| {
        VerificationError::invalid_payload("Activation tx is missing subscribe instruction")
    })?;
    let transfer = transfer_idx.ok_or_else(|| {
        VerificationError::invalid_payload(
            "Activation tx is missing transfer_subscription instruction",
        )
    })?;
    if transfer < subscribe {
        return Err(VerificationError::invalid_payload(
            "subscribe must precede transfer_subscription in activation tx",
        ));
    }
    Ok(())
}

/// Sign the transaction's message with the server's fee-payer signer and
/// fill the matching slot in `tx.signatures`. The client has already
/// signed as the subscriber and (when fee sponsorship is in play) left an
/// empty signature slot at the fee-payer index.
async fn co_sign_as_fee_payer(
    tx: &mut Transaction,
    signer: &Arc<dyn solana_keychain::SolanaSigner>,
) -> Result<(), VerificationError> {
    let pubkey = signer.pubkey();
    let idx = tx
        .message
        .account_keys
        .iter()
        .position(|k| *k == pubkey)
        .ok_or_else(|| {
            VerificationError::invalid_payload(
                "Fee payer pubkey not present in activation transaction",
            )
        })?;
    let msg_bytes = tx.message_data();
    let sig_bytes = signer
        .sign_message(&msg_bytes)
        .await
        .map_err(|e| VerificationError::new(format!("Fee-payer signing failed: {e}")))?;
    if tx.signatures.len() <= idx {
        return Err(VerificationError::invalid_payload(
            "Transaction signatures vec is shorter than account_keys",
        ));
    }
    tx.signatures[idx] = Signature::from(<[u8; 64]>::from(sig_bytes));
    Ok(())
}

/// Minimal in-process view of the on-chain `SubscriptionDelegation`
/// account — only the fields verify needs to validate against the
/// challenge. Mirrors the `#[repr(C, packed)]` layout in
/// `solana-program/subscriptions/program/src/state/subscription_delegation.rs`:
///
/// ```text
///   off  size  field
///   ---  ----  -----------------------------------------
///     0     1  header.discriminator
///     1     1  header.version
///     2     1  header.bump
///     3    32  header.delegator (= subscriber)
///    35    32  header.delegatee (= plan_pda)
///    67    32  header.payer
///    99     8  header.init_id
///   107     8  terms.amount      (= amount_per_period)
///   115     8  terms.period_hours
///   123     8  terms.created_at
///   131     8  amount_pulled_in_period
///   139     8  current_period_start_ts
///   147     8  expires_at_ts
/// ```
///
/// Mint isn't stored on the delegation — it lives on the parent Plan, and
/// the on-chain `Subscribe` already binds the delegation's terms to that
/// plan's mint, so we don't re-check it here.
#[derive(Debug, Clone)]
pub struct SubscriptionDelegationView {
    pub subscriber: Pubkey,
    pub plan_pda: Pubkey,
    pub amount_per_period: u64,
    pub period_hours: u64,
    pub current_period_start_ts: i64,
    pub amount_pulled_in_period: u64,
}

const SUBSCRIPTION_DELEGATION_LEN: usize = 1  // discriminator
    + 1  // version
    + 1  // bump
    + 32 // header.delegator (subscriber)
    + 32 // header.delegatee  (plan_pda)
    + 32 // header.payer
    + 8  // header.init_id
    + 8  // terms.amount
    + 8  // terms.period_hours
    + 8  // terms.created_at
    + 8  // amount_pulled_in_period
    + 8  // current_period_start_ts
    + 8; // expires_at_ts

fn decode_subscription_delegation(data: &[u8]) -> Result<SubscriptionDelegationView, String> {
    if data.len() < SUBSCRIPTION_DELEGATION_LEN {
        return Err(format!(
            "SubscriptionDelegation account too short: {} bytes (need >= {SUBSCRIPTION_DELEGATION_LEN})",
            data.len()
        ));
    }
    // header.discriminator(1) + version(1) + bump(1) = 3 bytes before delegator.
    let mut off = 3;
    let subscriber = Pubkey::try_from(&data[off..off + 32]).map_err(|e| e.to_string())?;
    off += 32;
    let plan_pda = Pubkey::try_from(&data[off..off + 32]).map_err(|e| e.to_string())?;
    off += 32;
    off += 32; // payer
    off += 8; // init_id
    let amount_per_period = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    off += 8;
    let period_hours = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    off += 8;
    off += 8; // terms.created_at — not used by the verifier
    let amount_pulled_in_period = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    off += 8;
    let current_period_start_ts = i64::from_le_bytes(data[off..off + 8].try_into().unwrap());

    Ok(SubscriptionDelegationView {
        subscriber,
        plan_pda,
        amount_per_period,
        period_hours,
        current_period_start_ts,
        amount_pulled_in_period,
    })
}

/// Format a unix-seconds timestamp as RFC 3339 in UTC. Avoids pulling in
/// `time` here — Hinnant's civil-from-days implementation lives next to
/// the accounts module on the pay side; we reproduce it locally so this
/// crate stays dep-light.
fn format_rfc3339_seconds(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400) as u32;
    let h = secs_of_day / 3600;
    let m = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::server::mock_rpc::{MockRpc, TransactionExpectation};
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::Message;
    use solana_pubkey::Pubkey;

    fn keypair_base58() -> String {
        // Deterministic pubkey for tests — actual key material is not used.
        Pubkey::new_unique().to_string()
    }

    fn make_config() -> SubscriptionConfig {
        SubscriptionConfig {
            plan_id: keypair_base58(),
            mint: keypair_base58(),
            token_program: crate::mpp::protocol::solana::programs::TOKEN_PROGRAM.to_string(),
            puller: keypair_base58(),
            recipient: keypair_base58(),
            challenge_binding_secret: "test-secret".to_string(),
            realm: "test-realm".to_string(),
            ..Default::default()
        }
    }

    fn transaction_with_instructions(payer: Pubkey, instructions: Vec<Instruction>) -> Transaction {
        Transaction::new_unsigned(Message::new(&instructions, Some(&payer)))
    }

    fn subscription_instruction(program_id: Pubkey, discriminator: u8) -> Instruction {
        Instruction {
            program_id,
            accounts: Vec::new(),
            data: vec![discriminator],
        }
    }

    fn subscription_delegation_data(
        subscriber: Pubkey,
        plan_pda: Pubkey,
        amount: u64,
        period_hours: u64,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(SUBSCRIPTION_DELEGATION_LEN);
        data.extend_from_slice(&[2, 1, 255]);
        data.extend_from_slice(subscriber.as_ref());
        data.extend_from_slice(plan_pda.as_ref());
        data.extend_from_slice(Pubkey::new_unique().as_ref());
        data.extend_from_slice(&77i64.to_le_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&period_hours.to_le_bytes());
        data.extend_from_slice(&1_700_000_000i64.to_le_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&1_700_000_000i64.to_le_bytes());
        data.extend_from_slice(&0i64.to_le_bytes());
        assert_eq!(data.len(), SUBSCRIPTION_DELEGATION_LEN);
        data
    }

    fn bind_echo_id(challenge: &mut crate::mpp::protocol::core::ChallengeEcho) {
        challenge.id = compute_challenge_id(
            "test-secret",
            &challenge.realm,
            challenge.method.as_str(),
            challenge.intent.as_str(),
            challenge.request.raw(),
            challenge.expires.as_deref(),
            challenge.digest.as_deref(),
            challenge.opaque.as_ref().map(|opaque| opaque.raw()),
        );
    }

    #[test]
    fn rejects_missing_required_fields() {
        let mut cfg = make_config();
        cfg.plan_id = String::new();
        assert!(SubscriptionServer::new(cfg).is_err());
    }

    #[test]
    fn rejects_invalid_pubkeys() {
        let mut cfg = make_config();
        cfg.plan_id = "not-a-pubkey".into();
        assert!(SubscriptionServer::new(cfg).is_err());
    }

    #[test]
    fn rejects_invalid_configured_pubkeys() {
        type ConfigMutation = Box<dyn Fn(&mut SubscriptionConfig)>;

        let cases: Vec<ConfigMutation> = vec![
            Box::new(|config| config.mint = "not-a-pubkey".into()),
            Box::new(|config| config.token_program = "not-a-pubkey".into()),
            Box::new(|config| config.puller = "not-a-pubkey".into()),
            Box::new(|config| config.recipient = "not-a-pubkey".into()),
        ];
        for mutate in cases {
            let mut config = make_config();
            mutate(&mut config);
            assert!(SubscriptionServer::new(config).is_err());
        }
    }

    #[test]
    fn rejects_out_of_range_period() {
        let mut cfg = make_config();
        cfg.period_unit = SubscriptionPeriodUnit::Day;
        cfg.period_count = 400;
        assert!(SubscriptionServer::new(cfg).is_err());
    }

    #[test]
    fn challenge_is_well_formed() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let challenge = server
            .subscription_challenge("10000000")
            .expect("challenge");
        let header = challenge.to_header().expect("header");
        assert!(header.contains("intent=\"subscription\""));
        assert!(header.contains("method=\"solana\""));
        assert!(header.contains("realm=\"test-realm\""));
    }

    #[test]
    fn challenge_request_encodes_period_and_plan() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let plan_id = server.plan_id().to_string();
        let challenge = server.subscription_challenge("10000000").unwrap();

        // Decode the base64url request and verify it pins the plan and period.
        let header = challenge.to_header().unwrap();
        let request_b64 = extract_request_param(&header).expect("request param");
        let bytes = crate::mpp::protocol::core::base64url_decode(&request_b64).unwrap();
        let parsed: SubscriptionRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.period_unit, SubscriptionPeriodUnit::Day);
        assert_eq!(parsed.period_count, "30");
        let md = parsed.method_details.as_ref().unwrap();
        assert_eq!(md.get("planId").unwrap().as_str().unwrap(), plan_id);
    }

    #[test]
    fn rejects_invalid_amount() {
        let server = SubscriptionServer::new(make_config()).unwrap();
        assert!(server.subscription_challenge("not-a-number").is_err());
        assert!(server.subscription_challenge("").is_err());
    }

    #[test]
    fn rejects_each_missing_required_field() {
        type ConfigMutation = Box<dyn Fn(&mut SubscriptionConfig)>;

        let cases: Vec<(&str, ConfigMutation)> = vec![
            ("mint", Box::new(|c| c.mint = String::new())),
            (
                "token_program",
                Box::new(|c| c.token_program = String::new()),
            ),
            ("puller", Box::new(|c| c.puller = String::new())),
            ("recipient", Box::new(|c| c.recipient = String::new())),
        ];
        for (label, mutate) in cases {
            let mut cfg = make_config();
            mutate(&mut cfg);
            let err = SubscriptionServer::new(cfg)
                .err()
                .unwrap_or_else(|| panic!("{label}"));
            assert!(
                format!("{err}").contains(label),
                "expected error for {label} field, got: {err}"
            );
        }
    }

    #[test]
    fn rejects_invalid_program_id_override() {
        let mut cfg = make_config();
        cfg.program_id = Some("not-a-pubkey".into());
        assert!(SubscriptionServer::new(cfg).is_err());
    }

    #[test]
    fn rejects_empty_challenge_binding_secret() {
        let mut cfg = make_config();
        cfg.challenge_binding_secret = String::new();
        assert!(SubscriptionServer::new(cfg).is_err());
    }

    #[test]
    fn rejects_empty_realm() {
        let mut cfg = make_config();
        cfg.realm = String::new();
        assert!(SubscriptionServer::new(cfg).is_err());
    }

    #[test]
    fn challenge_emits_fee_payer_when_signer_configured() {
        use solana_keychain::MemorySigner;
        let mut cfg = make_config();
        cfg.fee_payer = true;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        cfg.fee_payer_signer = Some(Arc::new(MemorySigner::from_bytes(&kp).expect("kp")));

        let server = SubscriptionServer::new(cfg).expect("server");
        let challenge = server
            .subscription_challenge("10000000")
            .expect("challenge");
        let header = challenge.to_header().expect("header");
        let request_b64 = header
            .split("request=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("request param");
        let bytes = crate::mpp::protocol::core::base64url_decode(request_b64).unwrap();
        let parsed: SubscriptionRequest = serde_json::from_slice(&bytes).unwrap();
        let md = parsed.method_details.as_ref().unwrap();
        assert_eq!(md.get("feePayer").unwrap().as_bool(), Some(true));
        assert!(md.get("feePayerKey").is_some());
    }

    #[test]
    fn accessors_expose_config_values() {
        let cfg = make_config();
        let expected_plan = cfg.plan_id.clone();
        let expected_mint = cfg.mint.clone();
        let expected_recipient = cfg.recipient.clone();
        let expected_puller = cfg.puller.clone();
        let expected_program = SUBSCRIPTIONS_PROGRAM_ID.to_string();
        let server = SubscriptionServer::new(cfg).expect("server");
        assert_eq!(server.realm(), "test-realm");
        assert_eq!(server.plan_id(), expected_plan);
        assert_eq!(server.mint(), expected_mint);
        assert_eq!(server.recipient(), expected_recipient);
        assert_eq!(server.puller(), expected_puller);
        assert_eq!(server.program_id(), expected_program);
        assert_eq!(server.period_unit(), SubscriptionPeriodUnit::Day);
        assert_eq!(server.period_count(), 30);
    }

    #[test]
    fn default_rpc_url_covers_each_network() {
        assert_eq!(default_rpc_url("devnet"), "https://api.devnet.solana.com");
        assert_eq!(default_rpc_url("localnet"), "http://localhost:8899");
        // `mainnet` is the canonical slug; the legacy `mainnet-beta`
        // alias still resolves so existing clients don't break.
        assert_eq!(
            default_rpc_url("mainnet"),
            "https://api.mainnet-beta.solana.com"
        );
        assert_eq!(
            default_rpc_url("mainnet-beta"),
            "https://api.mainnet-beta.solana.com"
        );
        // Unknown network falls through to the mainnet RPC.
        assert_eq!(
            default_rpc_url("custom"),
            "https://api.mainnet-beta.solana.com"
        );
    }

    #[test]
    fn week_period_round_trip_in_challenge() {
        let mut cfg = make_config();
        cfg.period_unit = SubscriptionPeriodUnit::Week;
        cfg.period_count = 2;
        let server = SubscriptionServer::new(cfg).expect("server");
        let challenge = server.subscription_challenge("5000000").unwrap();
        let header = challenge.to_header().unwrap();
        let request_b64 = header
            .split("request=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("request param");
        let bytes = crate::mpp::protocol::core::base64url_decode(request_b64).unwrap();
        let parsed: SubscriptionRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.period_unit, SubscriptionPeriodUnit::Week);
        assert_eq!(parsed.period_count, "2");
    }

    fn extract_request_param(header: &str) -> Option<String> {
        // header looks like: Payment realm="...", method="solana", intent="subscription", request="..."
        let needle = "request=\"";
        let start = header.find(needle)? + needle.len();
        let rest = &header[start..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }

    // ── Verify helpers (static portions) ──────────────────────────────

    #[test]
    fn decode_subscription_delegation_reads_fields_at_correct_offsets() {
        // Build a 155-byte SubscriptionDelegation account by hand, mirroring
        // the on-chain `#[repr(C, packed)]` layout: header(107) +
        // terms(24) + amount_pulled(8) + period_start(8) + expires(8).
        let mut data = Vec::with_capacity(SUBSCRIPTION_DELEGATION_LEN);
        data.push(2); // header.discriminator
        data.push(1); // header.version
        data.push(255); // header.bump
        let subscriber = [1u8; 32];
        let plan_pda = [2u8; 32];
        let payer = [3u8; 32];
        data.extend_from_slice(&subscriber); // header.delegator
        data.extend_from_slice(&plan_pda); // header.delegatee
        data.extend_from_slice(&payer);
        data.extend_from_slice(&77i64.to_le_bytes()); // header.init_id
        data.extend_from_slice(&9_990_000u64.to_le_bytes()); // terms.amount
        data.extend_from_slice(&720u64.to_le_bytes()); // terms.period_hours
        data.extend_from_slice(&1_780_000_000i64.to_le_bytes()); // terms.created_at
        data.extend_from_slice(&9_990_000u64.to_le_bytes()); // amount_pulled_in_period
        data.extend_from_slice(&1_700_000_000i64.to_le_bytes()); // current_period_start_ts
        data.extend_from_slice(&0i64.to_le_bytes()); // expires_at_ts
        assert_eq!(data.len(), SUBSCRIPTION_DELEGATION_LEN);

        let view = decode_subscription_delegation(&data).unwrap();
        assert_eq!(view.subscriber.to_bytes(), subscriber);
        assert_eq!(view.plan_pda.to_bytes(), plan_pda);
        assert_eq!(view.amount_per_period, 9_990_000);
        assert_eq!(view.period_hours, 720);
        assert_eq!(view.current_period_start_ts, 1_700_000_000);
        assert_eq!(view.amount_pulled_in_period, 9_990_000);
    }

    #[test]
    fn decode_subscription_delegation_rejects_short_data() {
        let short = vec![0u8; 50];
        assert!(decode_subscription_delegation(&short).is_err());
    }

    #[test]
    fn format_rfc3339_seconds_round_trips_known_timestamps() {
        // 2024-01-15T12:03:10Z = 1705320190
        assert_eq!(
            format_rfc3339_seconds(1_705_320_190),
            "2024-01-15T12:03:10Z"
        );
        // Epoch.
        assert_eq!(format_rfc3339_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_seconds(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn decode_activate_payload_accepts_raw_shape() {
        let challenge = make_test_challenge_for_payload();
        let credential = crate::mpp::protocol::core::PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".to_string(),
                transaction: Some("AQAAAA==".to_string()),
                signature: None,
            },
        );
        let payload = decode_activate_payload(&credential).expect("decode");
        assert_eq!(payload.payload_type, "transaction");
        assert!(payload.transaction.is_some());
    }

    #[test]
    fn decode_activate_payload_accepts_subscription_action_wrapper() {
        let challenge = make_test_challenge_for_payload();
        let credential = crate::mpp::protocol::core::PaymentCredential::new(
            challenge.to_echo(),
            SubscriptionAction::Activate(ActivatePayload {
                payload_type: "transaction".to_string(),
                transaction: Some("AQAAAA==".to_string()),
                signature: None,
            }),
        );
        let payload = decode_activate_payload(&credential).expect("decode");
        assert_eq!(payload.payload_type, "transaction");
    }

    #[test]
    fn decode_activate_payload_rejects_garbage() {
        let challenge = make_test_challenge_for_payload();
        let credential = crate::mpp::protocol::core::PaymentCredential::new(
            challenge.to_echo(),
            serde_json::json!({"random": "object"}),
        );
        // ActivatePayload has `type` as required; this should not parse.
        assert!(decode_activate_payload(&credential).is_err());
    }

    #[test]
    fn decode_base64_transaction_accepts_a_serialized_transaction_and_rejects_invalid_input() {
        let payer = Pubkey::new_unique();
        let tx = transaction_with_instructions(payer, Vec::new());
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&tx).unwrap());

        let decoded = decode_base64_transaction(&encoded).expect("serialized transaction");
        assert_eq!(decoded.message.account_keys, tx.message.account_keys);
        assert!(decode_base64_transaction("not base64").is_err());
        assert!(decode_base64_transaction("AQ==").is_err());
    }

    #[test]
    fn extract_subscriber_rejects_empty_or_puller_transactions() {
        let config = make_config();
        let request = SubscriptionRequest::default();

        let empty = Transaction::new_unsigned(Message::default());
        assert!(extract_subscriber_from_tx(&empty, &request, &config).is_err());

        let puller = parse_pubkey(&config.puller, "puller").unwrap();
        let puller_paid = transaction_with_instructions(puller, Vec::new());
        assert!(extract_subscriber_from_tx(&puller_paid, &request, &config).is_err());
    }

    #[test]
    fn extract_subscriber_uses_payer_without_fee_sponsorship() {
        let config = make_config();
        let subscriber = Pubkey::new_unique();
        let tx = transaction_with_instructions(subscriber, Vec::new());

        assert_eq!(
            extract_subscriber_from_tx(&tx, &SubscriptionRequest::default(), &config).unwrap(),
            subscriber
        );
    }

    #[test]
    fn extract_subscriber_skips_fee_payer_and_puller_when_sponsored() {
        let mut config = make_config();
        let fee_payer = Pubkey::new_unique();
        let subscriber = Pubkey::new_unique();
        let puller = parse_pubkey(&config.puller, "puller").unwrap();
        config.fee_payer = true;
        config.fee_payer_pubkey = Some(fee_payer.to_string());

        let instruction = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![
                AccountMeta::new_readonly(puller, false),
                AccountMeta::new_readonly(subscriber, true),
            ],
            data: Vec::new(),
        };
        let tx = transaction_with_instructions(fee_payer, vec![instruction]);

        assert_eq!(
            extract_subscriber_from_tx(&tx, &SubscriptionRequest::default(), &config).unwrap(),
            subscriber
        );

        config.fee_payer_pubkey = Some("not-a-pubkey".into());
        assert!(extract_subscriber_from_tx(&tx, &SubscriptionRequest::default(), &config).is_err());
    }

    #[test]
    fn extract_subscriber_rejects_sponsored_transaction_without_a_subscriber() {
        let mut config = make_config();
        let fee_payer = Pubkey::new_unique();
        let puller = parse_pubkey(&config.puller, "puller").unwrap();
        config.fee_payer = true;
        config.fee_payer_pubkey = Some(fee_payer.to_string());
        let instruction = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new_readonly(puller, false)],
            data: Vec::new(),
        };
        let tx = transaction_with_instructions(fee_payer, vec![instruction]);

        assert!(extract_subscriber_from_tx(&tx, &SubscriptionRequest::default(), &config).is_err());
    }

    #[test]
    fn validate_activation_scope_enforces_presence_uniqueness_and_order() {
        let program_id = Pubkey::new_unique();
        let program_id_string = program_id.to_string();
        let payer = Pubkey::new_unique();
        let request = SubscriptionRequest::default();
        let subscribe = subscription_instruction(program_id, INSTRUCTION_SUBSCRIBE);
        let transfer = subscription_instruction(program_id, INSTRUCTION_TRANSFER_SUBSCRIPTION);

        let valid = transaction_with_instructions(payer, vec![subscribe.clone(), transfer.clone()]);
        validate_activation_scope(&valid, &request, &program_id_string)
            .expect("valid activation scope");

        for instructions in [
            vec![],
            vec![subscribe.clone()],
            vec![transfer.clone(), subscribe.clone()],
            vec![subscribe.clone(), subscribe.clone(), transfer.clone()],
            vec![subscribe.clone(), transfer.clone(), transfer.clone()],
        ] {
            let tx = transaction_with_instructions(payer, instructions);
            assert!(validate_activation_scope(&tx, &request, &program_id_string).is_err());
        }

        let foreign = transaction_with_instructions(
            payer,
            vec![
                subscription_instruction(Pubkey::new_unique(), INSTRUCTION_SUBSCRIBE),
                subscription_instruction(program_id, INSTRUCTION_SUBSCRIBE),
                subscription_instruction(program_id, INSTRUCTION_TRANSFER_SUBSCRIPTION),
            ],
        );
        validate_activation_scope(&foreign, &request, &program_id_string)
            .expect("foreign instructions are outside the activation scope");
    }

    #[tokio::test]
    async fn co_sign_as_fee_payer_signs_matching_slot_and_rejects_bad_transactions() {
        use solana_keychain::MemorySigner;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(signing_key.as_bytes());
        keypair[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        let signer: Arc<dyn solana_keychain::SolanaSigner> =
            Arc::new(MemorySigner::from_bytes(&keypair).expect("signer"));

        let mut tx = transaction_with_instructions(signer.pubkey(), Vec::new());
        co_sign_as_fee_payer(&mut tx, &signer)
            .await
            .expect("co-sign");
        assert_ne!(tx.signatures[0], Signature::default());

        let mut missing_signer = transaction_with_instructions(Pubkey::new_unique(), Vec::new());
        assert!(co_sign_as_fee_payer(&mut missing_signer, &signer)
            .await
            .is_err());

        let mut missing_signature_slot = transaction_with_instructions(signer.pubkey(), Vec::new());
        missing_signature_slot.signatures.clear();
        assert!(co_sign_as_fee_payer(&mut missing_signature_slot, &signer)
            .await
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_broadcasts_and_validates_a_subscription_activation() {
        let rpc = MockRpc::start().await;
        let mut config = make_config();
        config.rpc_url = Some(rpc.url());
        let server = SubscriptionServer::new(config).expect("server");

        let signing_key = SigningKey::from_bytes(&[19u8; 32]);
        let subscriber = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
        let plan_pda = parse_pubkey(server.plan_id(), "plan_id").unwrap();
        let program_id = parse_pubkey(server.program_id(), "program_id").unwrap();
        let (delegation_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);
        let valid_delegation = subscription_delegation_data(subscriber, plan_pda, 100, 720);

        rpc.set_account(delegation_pda.to_string(), vec![0], program_id.to_string());
        let instructions = vec![
            subscription_instruction(program_id, INSTRUCTION_SUBSCRIBE),
            subscription_instruction(program_id, INSTRUCTION_TRANSFER_SUBSCRIPTION),
        ];
        rpc.expect_transaction(
            TransactionExpectation::new(subscriber, instructions.clone())
                .with_account_data_transition(
                    delegation_pda.to_string(),
                    vec![0],
                    valid_delegation,
                ),
        );

        let mut transaction = Transaction::new_unsigned(Message::new_with_blockhash(
            &instructions,
            Some(&subscriber),
            &Hash::default(),
        ));
        transaction.signatures[0] =
            Signature::from(signing_key.sign(&transaction.message_data()).to_bytes());
        let encoded_transaction = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&transaction).expect("serialize transaction"));

        let challenge = server.subscription_challenge("100").expect("challenge");
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(encoded_transaction),
                signature: None,
            },
        );

        let receipt = server
            .verify_credential(&credential)
            .await
            .expect("activation receipt");
        let ReceiptKind::Subscription { extensions, .. } = receipt else {
            panic!("expected subscription receipt");
        };
        assert_eq!(extensions.subscription_id, delegation_pda.to_string());
        assert!(extensions.activation_signature.is_some());
        rpc.assert_transaction_consumed();
    }

    // A challenge issued for one route (resource) must not verify against
    // another route that only happens to share this server's challenge-binding
    // secret, realm, mint, and recipient. The mismatch is caught at the
    // pinned-field stage, before any RPC. Regression for the cross-language
    // route-binding finding (mirrors the TypeScript MPP server's resource
    // binding).
    #[tokio::test(flavor = "multi_thread")]
    async fn challenge_bound_to_one_route_is_rejected_on_another() {
        let rpc = MockRpc::start().await;
        let mut route_a = make_config();
        route_a.rpc_url = Some(rpc.url());
        route_a.resource = Some("solana-subscription:/premium/articles".to_string());
        // Route B shares every binding input with route A except the resource.
        let mut route_b = route_a.clone();
        route_b.resource = Some("solana-subscription:/premium/videos".to_string());

        let server_a = SubscriptionServer::new(route_a).expect("route a server");
        let server_b = SubscriptionServer::new(route_b).expect("route b server");

        let challenge = server_a.subscription_challenge("100").expect("challenge");
        let payload = || ActivatePayload {
            payload_type: "transaction".into(),
            transaction: Some("AQ==".into()),
            signature: None,
        };

        // Cross-route redemption fails closed on the resource binding.
        let cross_route = server_b
            .verify_credential(&PaymentCredential::new(challenge.to_echo(), payload()))
            .await
            .expect_err("cross-route challenge must be rejected");
        assert!(
            cross_route.to_string().contains("resource does not match"),
            "expected a resource-binding rejection, got: {cross_route}"
        );

        // The same challenge clears the resource gate on its issuing route: it
        // advances past the pinned-field checks and only then fails on the
        // deliberately malformed activation payload, never on resource.
        let same_route = server_a
            .verify_credential(&PaymentCredential::new(challenge.to_echo(), payload()))
            .await
            .expect_err("malformed activation payload must still fail");
        assert!(
            !same_route.to_string().contains("resource does not match"),
            "issuing route must not reject its own challenge on resource: {same_route}"
        );
    }

    // The resource binding fails closed in BOTH directions: a resource-bound
    // route rejects a challenge that carries no resource, and a route with no
    // configured resource rejects a resource-bound challenge.
    #[tokio::test(flavor = "multi_thread")]
    async fn resource_binding_fails_closed_in_both_directions() {
        let rpc = MockRpc::start().await;
        let mut bound_cfg = make_config();
        bound_cfg.rpc_url = Some(rpc.url());
        bound_cfg.resource = Some("solana-subscription:/paid".to_string());
        let mut unbound_cfg = bound_cfg.clone();
        unbound_cfg.resource = None;

        let bound = SubscriptionServer::new(bound_cfg).expect("bound server");
        let unbound = SubscriptionServer::new(unbound_cfg).expect("unbound server");
        let payload = || ActivatePayload {
            payload_type: "transaction".into(),
            transaction: Some("AQ==".into()),
            signature: None,
        };

        // Resource-less challenge must not satisfy a resource-bound route.
        let unbound_challenge = unbound.subscription_challenge("100").expect("challenge");
        let bound_rejects = bound
            .verify_credential(&PaymentCredential::new(
                unbound_challenge.to_echo(),
                payload(),
            ))
            .await
            .expect_err("resource-less challenge must not satisfy a bound route");
        assert!(
            bound_rejects
                .to_string()
                .contains("resource does not match"),
            "got: {bound_rejects}"
        );

        // Resource-bound challenge must not satisfy a route with no resource.
        let bound_challenge = bound.subscription_challenge("100").expect("challenge");
        let unbound_rejects = unbound
            .verify_credential(&PaymentCredential::new(
                bound_challenge.to_echo(),
                payload(),
            ))
            .await
            .expect_err("bound challenge must not satisfy an unbound route");
        assert!(
            unbound_rejects
                .to_string()
                .contains("resource does not match"),
            "got: {unbound_rejects}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_rejects_hmac_valid_tampering_before_rpc() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let challenge = server.subscription_challenge("100").expect("challenge");

        let mut wrong_method = challenge.to_echo();
        wrong_method.method = "other".into();
        bind_echo_id(&mut wrong_method);
        assert!(server
            .verify_credential(&PaymentCredential::new(
                wrong_method,
                ActivatePayload {
                    payload_type: "transaction".into(),
                    transaction: Some("AQ==".into()),
                    signature: None,
                },
            ))
            .await
            .is_err());

        let mut wrong_intent = challenge.to_echo();
        wrong_intent.intent = "charge".into();
        bind_echo_id(&mut wrong_intent);
        assert!(server
            .verify_credential(&PaymentCredential::new(
                wrong_intent,
                ActivatePayload {
                    payload_type: "transaction".into(),
                    transaction: Some("AQ==".into()),
                    signature: None,
                },
            ))
            .await
            .is_err());

        let mut wrong_realm = challenge.to_echo();
        wrong_realm.realm = "other-realm".into();
        bind_echo_id(&mut wrong_realm);
        assert!(server
            .verify_credential(&PaymentCredential::new(
                wrong_realm,
                ActivatePayload {
                    payload_type: "transaction".into(),
                    transaction: Some("AQ==".into()),
                    signature: None,
                },
            ))
            .await
            .is_err());

        let mut wrong_currency = challenge.to_echo();
        let mut request: SubscriptionRequest = wrong_currency.request.decode().unwrap();
        request.currency = Pubkey::new_unique().to_string();
        wrong_currency.request = Base64UrlJson::from_typed(&request).unwrap();
        bind_echo_id(&mut wrong_currency);
        assert!(server
            .verify_credential(&PaymentCredential::new(
                wrong_currency,
                ActivatePayload {
                    payload_type: "transaction".into(),
                    transaction: Some("AQ==".into()),
                    signature: None,
                },
            ))
            .await
            .is_err());

        let mut wrong_recipient = challenge.to_echo();
        let mut request: SubscriptionRequest = wrong_recipient.request.decode().unwrap();
        request.recipient = Pubkey::new_unique().to_string();
        wrong_recipient.request = Base64UrlJson::from_typed(&request).unwrap();
        bind_echo_id(&mut wrong_recipient);
        assert!(server
            .verify_credential(&PaymentCredential::new(
                wrong_recipient,
                ActivatePayload {
                    payload_type: "transaction".into(),
                    transaction: Some("AQ==".into()),
                    signature: None,
                },
            ))
            .await
            .is_err());

        assert!(server
            .verify_credential(&PaymentCredential::new(
                challenge.to_echo(),
                serde_json::json!({"type": "unknown"}),
            ))
            .await
            .is_err());

        assert!(server
            .verify_credential(&PaymentCredential::new(
                challenge.to_echo(),
                ActivatePayload {
                    payload_type: "transaction".into(),
                    transaction: None,
                    signature: None,
                },
            ))
            .await
            .is_err());

        let payer = Pubkey::new_unique();
        let malformed_scope = transaction_with_instructions(payer, Vec::new());
        let malformed_scope = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&malformed_scope).unwrap());
        assert!(server
            .verify_credential(&PaymentCredential::new(
                challenge.to_echo(),
                ActivatePayload {
                    payload_type: "transaction".into(),
                    transaction: Some(malformed_scope),
                    signature: None,
                },
            ))
            .await
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_rejects_signature_payload_with_fee_sponsorship() {
        use solana_keychain::MemorySigner;

        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(signing_key.as_bytes());
        keypair[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        let mut config = make_config();
        config.fee_payer = true;
        config.fee_payer_signer = Some(Arc::new(MemorySigner::from_bytes(&keypair).unwrap()));
        let server = SubscriptionServer::new(config).expect("server");
        let challenge = server.subscription_challenge("100").expect("challenge");

        let error = server
            .verify_credential(&PaymentCredential::new(
                challenge.to_echo(),
                ActivatePayload {
                    payload_type: "signature".into(),
                    transaction: None,
                    signature: Some("already-sent".into()),
                },
            ))
            .await
            .expect_err("fee-sponsored push credentials must be rejected");
        assert!(format!("{error}").contains("fee sponsorship"));
    }

    fn make_test_challenge_for_payload() -> crate::mpp::protocol::core::PaymentChallenge {
        let body = SubscriptionRequest {
            amount: "1".into(),
            currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "30".into(),
            recipient: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".into(),
            ..Default::default()
        };
        let encoded = Base64UrlJson::from_typed(&body).unwrap();
        // Different secret + realm than `make_config()` so the
        // challenge id HMAC will deliberately mismatch when fed into
        // the test server's `verify_credential` — that's what the
        // HMAC-rejection test actually exercises.
        PaymentChallenge::with_challenge_binding_secret(
            "different-secret",
            "different-realm",
            "solana",
            "subscription",
            encoded,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_rejects_hmac_mismatch() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let bad_challenge = make_test_challenge_for_payload(); // different realm
        let credential = crate::mpp::protocol::core::PaymentCredential::new(
            bad_challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".to_string(),
                transaction: Some("AQAAAA==".to_string()),
                signature: None,
            },
        );
        let err = server
            .verify_credential(&credential)
            .await
            .expect_err("HMAC mismatch must reject");
        assert!(format!("{err:?}").to_lowercase().contains("hmac"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_rejects_push_mode_v0() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        // Build a challenge through the server itself so HMAC + pinned
        // fields pass, then submit a type="signature" payload.
        let challenge = server
            .subscription_challenge("10000000")
            .expect("challenge");
        let credential = crate::mpp::protocol::core::PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "signature".into(),
                transaction: None,
                signature: Some("5J8Sig".into()),
            },
        );
        let err = server
            .verify_credential(&credential)
            .await
            .expect_err("v0 rejects push mode");
        let msg = format!("{err:?}").to_lowercase();
        assert!(
            msg.contains("push-mode") || msg.contains("not yet supported"),
            "{err:?}"
        );
    }

    // Drive a full `type="transaction"` activation whose broadcast produces the
    // caller-supplied on-chain `SubscriptionDelegation`. The signing key is
    // fixed so the delegation PDA is deterministic; the builder closure receives
    // the derived `(subscriber, plan_pda)` so a test can pin or corrupt any
    // snapshotted term.
    async fn drive_fresh_activation(
        challenge_amount: &str,
        broadcast_fails: bool,
        delegation: impl FnOnce(Pubkey, Pubkey) -> Vec<u8>,
    ) -> Result<ReceiptKind, VerificationError> {
        let rpc = MockRpc::start().await;
        let mut config = make_config();
        config.rpc_url = Some(rpc.url());
        let server = SubscriptionServer::new(config).expect("server");

        let signing_key = SigningKey::from_bytes(&[19u8; 32]);
        let subscriber = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
        let plan_pda = parse_pubkey(server.plan_id(), "plan_id").unwrap();
        let program_id = parse_pubkey(server.program_id(), "program_id").unwrap();
        let (delegation_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);
        let instructions = vec![
            subscription_instruction(program_id, INSTRUCTION_SUBSCRIBE),
            subscription_instruction(program_id, INSTRUCTION_TRANSFER_SUBSCRIPTION),
        ];

        rpc.set_account(delegation_pda.to_string(), vec![0], program_id.to_string());
        if broadcast_fails {
            rpc.fail_send("fixture rejects the activation broadcast");
        } else {
            rpc.expect_transaction(
                TransactionExpectation::new(subscriber, instructions.clone())
                    .with_account_data_transition(
                        delegation_pda.to_string(),
                        vec![0],
                        delegation(subscriber, plan_pda),
                    ),
            );
        }

        let mut transaction = Transaction::new_unsigned(Message::new_with_blockhash(
            &instructions,
            Some(&subscriber),
            &Hash::default(),
        ));
        transaction.signatures[0] =
            Signature::from(signing_key.sign(&transaction.message_data()).to_bytes());
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&transaction).expect("serialize transaction"));
        let challenge = server
            .subscription_challenge(challenge_amount)
            .expect("challenge");
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(encoded),
                signature: None,
            },
        );
        server.verify_credential(&credential).await
    }

    // The snapshotted-terms checks fail closed: if the confirmed on-chain
    // delegation diverges from the challenge (amount, period, plan, or the
    // first-period pull), the receipt is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_rejects_divergent_onchain_terms() {
        // amount mismatch: delegation charges a different per-period amount.
        let wrong_amount = drive_fresh_activation("100", false, |sub, plan| {
            subscription_delegation_data(sub, plan, 999, 720)
        })
        .await
        .expect_err("amount mismatch must reject");
        assert!(wrong_amount.to_string().contains("amount mismatch"));

        // period mismatch: delegation encodes a different period_hours.
        let wrong_period = drive_fresh_activation("100", false, |sub, plan| {
            subscription_delegation_data(sub, plan, 100, 24)
        })
        .await
        .expect_err("period mismatch must reject");
        assert!(wrong_period.to_string().contains("period mismatch"));

        // plan mismatch: delegation points at a different Plan PDA.
        let wrong_plan = drive_fresh_activation("100", false, |sub, _plan| {
            subscription_delegation_data(sub, Pubkey::new_unique(), 100, 720)
        })
        .await
        .expect_err("plan mismatch must reject");
        assert!(wrong_plan.to_string().contains("plan mismatch"));

        // first-period pull mismatch: terms match but the activation did not
        // execute the first charge (amount_pulled_in_period != amount).
        let no_pull = drive_fresh_activation("100", false, |sub, plan| {
            let mut data = subscription_delegation_data(sub, plan, 100, 720);
            // amount_pulled_in_period sits at offset 3+32+32+32+8+8+8 = 131.
            data[131..139].copy_from_slice(&0u64.to_le_bytes());
            data
        })
        .await
        .expect_err("missing first-period charge must reject");
        assert!(no_pull
            .to_string()
            .contains("did not execute the first-period charge"));
    }

    // A broadcast failure on a fresh activation surfaces as a transaction
    // error, not a success receipt.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_surfaces_broadcast_failure() {
        let err = drive_fresh_activation("100", true, |sub, plan| {
            subscription_delegation_data(sub, plan, 100, 720)
        })
        .await
        .expect_err("broadcast failure must reject");
        assert!(err.to_string().to_lowercase().contains("broadcast"));
    }

    // Idempotent re-activation: the delegation is already on-chain (a prior
    // activation landed but the receipt round-trip failed), so the server skips
    // the broadcast and recovers the original creation signature via
    // `getSignaturesForAddress`.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_is_idempotent_when_delegation_already_exists() {
        let rpc = MockRpc::start().await;
        let mut config = make_config();
        config.rpc_url = Some(rpc.url());
        let server = SubscriptionServer::new(config).expect("server");

        let signing_key = SigningKey::from_bytes(&[31u8; 32]);
        let subscriber = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
        let plan_pda = parse_pubkey(server.plan_id(), "plan_id").unwrap();
        let program_id = parse_pubkey(server.program_id(), "program_id").unwrap();
        let (delegation_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);

        // Delegation already present with the correct terms: no broadcast is set
        // up, so if the server tried to broadcast the fixture would reject it.
        rpc.set_account(
            delegation_pda.to_string(),
            subscription_delegation_data(subscriber, plan_pda, 100, 720),
            program_id.to_string(),
        );
        // Newest-first history; the oldest entry is the creation signature.
        rpc.set_signatures(
            delegation_pda.to_string(),
            vec!["RenewSig222".to_string(), "CreationSig111".to_string()],
        );

        let instructions = vec![
            subscription_instruction(program_id, INSTRUCTION_SUBSCRIBE),
            subscription_instruction(program_id, INSTRUCTION_TRANSFER_SUBSCRIPTION),
        ];
        let mut transaction = Transaction::new_unsigned(Message::new_with_blockhash(
            &instructions,
            Some(&subscriber),
            &Hash::default(),
        ));
        transaction.signatures[0] =
            Signature::from(signing_key.sign(&transaction.message_data()).to_bytes());
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&transaction).expect("serialize transaction"));
        let challenge = server.subscription_challenge("100").expect("challenge");
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(encoded),
                signature: None,
            },
        );

        let receipt = server
            .verify_credential(&credential)
            .await
            .expect("idempotent activation receipt");
        let ReceiptKind::Subscription { extensions, .. } = receipt else {
            panic!("expected subscription receipt");
        };
        assert_eq!(
            extensions.activation_signature.as_deref(),
            Some("CreationSig111"),
            "must recover the original creation signature, not a renewal"
        );
    }

    // A fee-sponsored activation: the server co-signs as fee payer, then
    // broadcasts. The subscriber is the non-fee-payer, non-puller signer.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_co_signs_and_settles_a_fee_sponsored_activation() {
        use solana_keychain::MemorySigner;

        let rpc = MockRpc::start().await;
        let fee_sk = ed25519_dalek::SigningKey::from_bytes(&[41u8; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(fee_sk.as_bytes());
        keypair[32..].copy_from_slice(fee_sk.verifying_key().as_bytes());
        let fee_payer = Pubkey::new_from_array(fee_sk.verifying_key().to_bytes());

        let mut config = make_config();
        config.rpc_url = Some(rpc.url());
        config.fee_payer = true;
        config.fee_payer_signer = Some(Arc::new(MemorySigner::from_bytes(&keypair).unwrap()));
        let server = SubscriptionServer::new(config).expect("server");

        let sub_sk = SigningKey::from_bytes(&[42u8; 32]);
        let subscriber = Pubkey::new_from_array(sub_sk.verifying_key().to_bytes());
        let plan_pda = parse_pubkey(server.plan_id(), "plan_id").unwrap();
        let program_id = parse_pubkey(server.program_id(), "program_id").unwrap();
        let (delegation_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);
        rpc.set_account(delegation_pda.to_string(), vec![0], program_id.to_string());

        // Fee payer signs first (account_keys[0]); the subscriber is the second
        // required signer. A subscribe ix references both so both are signers.
        let subscribe = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(subscriber, true)],
            data: vec![INSTRUCTION_SUBSCRIBE],
        };
        let transfer = subscription_instruction(program_id, INSTRUCTION_TRANSFER_SUBSCRIPTION);
        let instructions = vec![subscribe, transfer];
        let mut transaction = Transaction::new_unsigned(Message::new_with_blockhash(
            &instructions,
            Some(&fee_payer),
            &Hash::default(),
        ));
        // Subscriber co-signs their slot; the server fills the fee-payer slot.
        let sub_idx = transaction
            .message
            .account_keys
            .iter()
            .position(|k| *k == subscriber)
            .unwrap();
        transaction.signatures[sub_idx] =
            Signature::from(sub_sk.sign(&transaction.message_data()).to_bytes());

        // The broadcast the fixture expects is the fully-signed message.
        let mut expected = transaction.clone();
        expected.signatures[0] = Signature::from(fee_sk.sign(&expected.message_data()).to_bytes());
        rpc.expect_transaction(
            TransactionExpectation::matching(expected.message.clone())
                .with_account_data_transition(
                    delegation_pda.to_string(),
                    vec![0],
                    subscription_delegation_data(subscriber, plan_pda, 100, 720),
                ),
        );

        let encoded = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&transaction).expect("serialize transaction"));
        let challenge = server.subscription_challenge("100").expect("challenge");
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(encoded),
                signature: None,
            },
        );

        let receipt = server
            .verify_credential(&credential)
            .await
            .expect("fee-sponsored activation receipt");
        assert!(matches!(receipt, ReceiptKind::Subscription { .. }));
        rpc.assert_transaction_consumed();
    }

    // An unknown activation payload type is rejected before any RPC.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_rejects_unknown_payload_type() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let challenge = server.subscription_challenge("100").expect("challenge");
        let err = server
            .verify_credential(&PaymentCredential::new(
                challenge.to_echo(),
                ActivatePayload {
                    payload_type: "carrier-pigeon".into(),
                    transaction: None,
                    signature: None,
                },
            ))
            .await
            .expect_err("unknown payload type must reject");
        assert!(err.to_string().contains("Unsupported payload type"));
    }

    // The challenge pre-fetches a recent blockhash on the configured RPC and
    // embeds it so the client can skip its own round-trip.
    #[tokio::test(flavor = "multi_thread")]
    async fn subscription_challenge_embeds_a_fetched_blockhash() {
        let rpc = MockRpc::start().await;
        let mut config = make_config();
        config.rpc_url = Some(rpc.url());
        let server = SubscriptionServer::new(config).expect("server");
        let challenge = server.subscription_challenge("100").expect("challenge");
        let header = challenge.to_header().unwrap();
        let request_b64 = extract_request_param(&header).expect("request param");
        let bytes = crate::mpp::protocol::core::base64url_decode(&request_b64).unwrap();
        let parsed: SubscriptionRequest = serde_json::from_slice(&bytes).unwrap();
        let md = parsed.method_details.as_ref().unwrap();
        assert_eq!(
            md.get("recentBlockhash").and_then(|v| v.as_str()),
            Some("11111111111111111111111111111111")
        );
    }

    // Idempotent path with an empty signature history: the delegation exists but
    // no creation signature can be recovered, so the receipt omits it rather
    // than failing.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_idempotent_without_history_omits_signature() {
        let rpc = MockRpc::start().await;
        let mut config = make_config();
        config.rpc_url = Some(rpc.url());
        let server = SubscriptionServer::new(config).expect("server");

        let signing_key = SigningKey::from_bytes(&[37u8; 32]);
        let subscriber = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
        let plan_pda = parse_pubkey(server.plan_id(), "plan_id").unwrap();
        let program_id = parse_pubkey(server.program_id(), "program_id").unwrap();
        let (delegation_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);
        rpc.set_account(
            delegation_pda.to_string(),
            subscription_delegation_data(subscriber, plan_pda, 100, 720),
            program_id.to_string(),
        );
        // No signatures seeded → getSignaturesForAddress returns an empty list.

        let instructions = vec![
            subscription_instruction(program_id, INSTRUCTION_SUBSCRIBE),
            subscription_instruction(program_id, INSTRUCTION_TRANSFER_SUBSCRIPTION),
        ];
        let mut transaction = Transaction::new_unsigned(Message::new_with_blockhash(
            &instructions,
            Some(&subscriber),
            &Hash::default(),
        ));
        transaction.signatures[0] =
            Signature::from(signing_key.sign(&transaction.message_data()).to_bytes());
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&transaction).expect("serialize transaction"));
        let challenge = server.subscription_challenge("100").expect("challenge");
        let receipt = server
            .verify_credential(&PaymentCredential::new(
                challenge.to_echo(),
                ActivatePayload {
                    payload_type: "transaction".into(),
                    transaction: Some(encoded),
                    signature: None,
                },
            ))
            .await
            .expect("idempotent activation receipt");
        let ReceiptKind::Subscription { extensions, .. } = receipt else {
            panic!("expected subscription receipt");
        };
        assert!(extensions.activation_signature.is_none());
    }

    // The subscriber is the fee payer's derived pubkey path: fee sponsorship is
    // on, only the signer (no explicit `fee_payer_pubkey`) is set, and the
    // subscriber is still resolved as the non-fee-payer signer.
    #[test]
    fn extract_subscriber_uses_signer_derived_fee_payer_key() {
        use solana_keychain::MemorySigner;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[51u8; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(signing_key.as_bytes());
        keypair[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        let signer: Arc<dyn solana_keychain::SolanaSigner> =
            Arc::new(MemorySigner::from_bytes(&keypair).unwrap());
        let fee_payer = signer.pubkey();

        let mut config = make_config();
        config.fee_payer = true;
        config.fee_payer_signer = Some(signer);
        // No explicit fee_payer_pubkey → the key is derived from the signer.
        let subscriber = Pubkey::new_unique();
        let puller = parse_pubkey(&config.puller, "puller").unwrap();
        let instruction = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![
                AccountMeta::new_readonly(puller, false),
                AccountMeta::new_readonly(subscriber, true),
            ],
            data: Vec::new(),
        };
        let tx = transaction_with_instructions(fee_payer, vec![instruction]);
        assert_eq!(
            extract_subscriber_from_tx(&tx, &SubscriptionRequest::default(), &config).unwrap(),
            subscriber
        );
    }
}
