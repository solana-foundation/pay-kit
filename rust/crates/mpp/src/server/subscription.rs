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
//! use solana_mpp::server::subscription::{SubscriptionConfig, SubscriptionServer};
//! use solana_mpp::protocol::intents::SubscriptionPeriodUnit;
//!
//! let server = SubscriptionServer::new(SubscriptionConfig {
//!     plan_id: "8tWb...".to_string(),
//!     mint: "EPjFW...".to_string(),
//!     token_program: solana_mpp::protocol::solana::programs::TOKEN_PROGRAM.to_string(),
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

use crate::error::Error;
use crate::expires;
use crate::program::subscriptions::{
    find_subscription_pda, parse_pubkey, INSTRUCTION_SUBSCRIBE, INSTRUCTION_TRANSFER_SUBSCRIPTION,
    SUBSCRIPTIONS_PROGRAM_ID,
};
use crate::protocol::core::{
    compute_challenge_id, Base64UrlJson, PaymentChallenge, PaymentCredential, Receipt, ReceiptKind,
};
use crate::protocol::intents::SubscriptionMethodDetails;
use crate::protocol::intents::{
    ActivatePayload, SubscriptionAction, SubscriptionPeriodUnit, SubscriptionReceiptExtensions,
    SubscriptionRequest,
};
use crate::protocol::solana::default_rpc_url;
use crate::server::charge::VerificationError;
use crate::store::{MemoryStore, Store};

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
                status: crate::protocol::core::ReceiptStatus::Success,
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
        for k in keys.iter().skip(1) {
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
    use solana_pubkey::Pubkey;

    fn keypair_base58() -> String {
        // Deterministic pubkey for tests — actual key material is not used.
        Pubkey::new_unique().to_string()
    }

    fn make_config() -> SubscriptionConfig {
        SubscriptionConfig {
            plan_id: keypair_base58(),
            mint: keypair_base58(),
            token_program: crate::protocol::solana::programs::TOKEN_PROGRAM.to_string(),
            puller: keypair_base58(),
            recipient: keypair_base58(),
            challenge_binding_secret: "test-secret".to_string(),
            realm: "test-realm".to_string(),
            ..Default::default()
        }
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
        let bytes = crate::protocol::core::base64url_decode(&request_b64).unwrap();
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
        let cases: Vec<(&str, Box<dyn Fn(&mut SubscriptionConfig)>)> = vec![
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
        let bytes = crate::protocol::core::base64url_decode(request_b64).unwrap();
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
        let bytes = crate::protocol::core::base64url_decode(request_b64).unwrap();
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
    }

    #[test]
    fn decode_activate_payload_accepts_raw_shape() {
        let challenge = make_test_challenge_for_payload();
        let credential = crate::protocol::core::PaymentCredential::new(
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
        let credential = crate::protocol::core::PaymentCredential::new(
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
        let credential = crate::protocol::core::PaymentCredential::new(
            challenge.to_echo(),
            serde_json::json!({"random": "object"}),
        );
        // ActivatePayload has `type` as required; this should not parse.
        assert!(decode_activate_payload(&credential).is_err());
    }

    fn make_test_challenge_for_payload() -> crate::protocol::core::PaymentChallenge {
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
        let credential = crate::protocol::core::PaymentCredential::new(
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
        let credential = crate::protocol::core::PaymentCredential::new(
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
}
