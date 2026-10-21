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
//!     amount_base_units: "10000000".to_string(),
//!     ..Default::default()
//! })?;
//!
//! let challenge = server.subscription_challenge("10000000")?;
//! ```

use std::sync::Arc;

use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;

use crate::mpp::error::Error;
use crate::mpp::expires;
use crate::mpp::program::subscriptions::{
    find_event_authority_pda, find_subscription_authority_pda, find_subscription_pda, parse_pubkey,
    ASSOCIATED_TOKEN_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID,
    INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY, INSTRUCTION_SUBSCRIBE,
    INSTRUCTION_TRANSFER_SUBSCRIPTION, MEMO_PROGRAM_ID, SUBSCRIPTIONS_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
};
use crate::mpp::protocol::core::{
    compute_challenge_id, Base64UrlJson, PaymentChallenge, PaymentCredential, Receipt, ReceiptKind,
};
use crate::mpp::protocol::intents::SubscriptionMethodDetails;
use crate::mpp::protocol::intents::{
    ActivatePayload, SubscriptionAccessPayload, SubscriptionAction, SubscriptionAuthentication,
    SubscriptionPeriodUnit, SubscriptionReceiptExtensions, SubscriptionRequest,
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
    /// Amount charged per period, in base units. REQUIRED — credentials whose
    /// challenged terms differ from this route's are rejected, so a proof for a
    /// cheaper route sharing the Plan cannot unlock this one.
    pub amount_base_units: String,
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
    pub fee_payer_signer: Option<Arc<dyn solana_keychain::TransactionSigner>>,
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
            amount_base_units: String::new(),
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
    /// Transaction message versions accepted and advertised; see `core::tx`.
    accepted_versions: Vec<crate::core::tx::TxVersion>,
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
        match config.amount_base_units.parse::<u64>() {
            Ok(amount) if amount > 0 => {}
            _ => {
                return Err(Error::InvalidConfig(
                    "amount_base_units must be a positive integer".into(),
                ))
            }
        }
        if let Some(subscription_expires) = config.subscription_expires.as_deref() {
            let subscription_expires = time::OffsetDateTime::parse(
                subscription_expires,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|error| {
                Error::InvalidConfig(format!("subscription_expires must be RFC3339: {error}"))
            })?;
            if subscription_expires <= time::OffsetDateTime::now_utc() {
                return Err(Error::InvalidConfig(
                    "subscription_expires must be in the future".into(),
                ));
            }
        }

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

        // Version 0 only until the host opts in with `with_tx_v1`; no RPC call here.
        let accepted_versions = vec![crate::core::tx::TxVersion::V0];
        Ok(SubscriptionServer {
            config,
            program_id,
            challenge_binding_secret,
            realm,
            store,
            rpc_url,
            accepted_versions,
        })
    }

    /// Choose whether version-1 activation transactions are accepted and
    /// advertised. `Auto` probes the `enable_tx_v1` gate once; the default is
    /// version 0 only.
    pub fn with_tx_v1(mut self, mode: crate::core::tx::TxV1Mode) -> Self {
        use solana_rpc_client::rpc_client::RpcClient;
        self.accepted_versions = mode.resolve(&RpcClient::new(self.rpc_url.clone()));
        self
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
        if amount_base_units != self.config.amount_base_units {
            return Err(Error::Other(format!(
                "Amount {amount_base_units} does not match the configured amount {}",
                self.config.amount_base_units
            )));
        }

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
            plan_address: self.config.plan_id.clone(),
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
            subscription_program: Some(self.program_id.clone()),
            network: Some(self.config.network.clone()),
            fee_payer: self.config.fee_payer,
            fee_payer_key,
            recent_blockhash,
            plan_id_numeric: self.config.plan_id_numeric,
            plan_bump: self.config.plan_bump,
            expected_period_hours,
            expected_created_at: self.config.plan_created_at,
            transaction_versions: crate::core::tx::advertised(&self.accepted_versions),
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
        let PreparedActivation {
            request,
            subscriber,
            tx,
            authentication,
        } = match self
            .prepare_credential(credential, time::OffsetDateTime::now_utc())
            .await?
        {
            PreparedCredential::Access { request, access } => {
                return self
                    .verify_access_credential(credential, &request, access)
                    .await;
            }
            PreparedCredential::Activation(activation) => activation,
        };

        // Idempotent retry: if the delegation PDA already exists, a
        // previous broadcast of this same transaction may have landed
        // while the receipt round-trip failed. Accept that only when
        // this exact transaction succeeded on-chain; the subsequent
        // fetch and terms check catch any divergence.
        let program_id = parse_pubkey(&self.program_id, "program_id")
            .map_err(|e| VerificationError::new(e.to_string()))?;
        let plan_pda = parse_pubkey(&self.config.plan_id, "plan_id")
            .map_err(|e| VerificationError::new(e.to_string()))?;
        let (delegation_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);
        let delegation_already_exists = self
            .fetch_subscription_delegation(&delegation_pda)
            .await
            .is_ok();

        let signature = VerifiedSignature::of(&tx)?;
        let key = format!("solana-subscription:consumed:{signature}");
        let binding = serde_json::json!({
            "challengeId": credential.challenge.id,
        });
        let activation_signature = if delegation_already_exists {
            self.ensure_activation_landed(&signature).await?;
            // Already reserved under another challenge: either a
            // recovery of an activation whose binding was never
            // written, or a retry of one already bound. The binder
            // tells them apart, after re-verifying on-chain.
            try_reserve_activation_signature(self.store.as_ref(), &key, binding).await?;
            signature
        } else {
            reserve_activation_signature(self.store.as_ref(), &key, binding).await?;
            match self.broadcast_and_confirm(&tx).await {
                Ok(_) => signature,
                // A transaction that can no longer land needs no
                // replay record; ambiguous outcomes keep theirs.
                Err(BroadcastError::Rejected(error)) => {
                    self.store.delete(&key).await.map_err(|e| {
                        VerificationError::new(format!(
                            "Failed to release activation reservation: {e}"
                        ))
                    })?;
                    return Err(error);
                }
                Err(BroadcastError::Unknown(error)) => return Err(error),
            }
        };
        self.bind_confirmed_activation(
            credential,
            &request,
            subscriber,
            activation_signature,
            authentication.as_ref(),
        )
        .await
    }

    /// The offline half of [`Self::verify_credential`], evaluated at `now`:
    /// challenge binding, request terms, activation payload, bearer proof,
    /// activation scope and the fee-payer co-signature. Nothing here reads
    /// the chain, consumes replay state or broadcasts.
    async fn prepare_credential(
        &self,
        credential: &PaymentCredential,
        now: time::OffsetDateTime,
    ) -> Result<PreparedCredential, VerificationError> {
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

        let method_details = request
            .method_details
            .as_ref()
            .ok_or_else(|| {
                VerificationError::invalid_payload("Subscription request is missing methodDetails")
            })
            .and_then(|value| {
                SubscriptionMethodDetails::from_json(value)
                    .map_err(|error| VerificationError::invalid_payload(error.to_string()))
            })?;
        method_details
            .validate()
            .map_err(|error| VerificationError::invalid_payload(error.to_string()))?;
        if method_details.subscription_program.as_deref() != Some(self.program_id.as_str()) {
            return Err(VerificationError::credential_mismatch(
                "methodDetails.subscriptionProgram does not match this server",
            ));
        }
        if method_details.plan_address != self.config.plan_id {
            return Err(VerificationError::credential_mismatch(
                "methodDetails.planAddress does not match this server",
            ));
        }
        if method_details.network.as_deref() != Some(self.config.network.as_str()) {
            return Err(VerificationError::wrong_network(format!(
                "methodDetails.network does not match this server (expected `{}`)",
                self.config.network
            )));
        }
        // Routes may share a Plan; bind activation and reusable proofs alike
        // to this route's own terms.
        let period_hours = self
            .config
            .period_unit
            .to_period_hours(self.config.period_count)
            .map_err(|error| VerificationError::new(error.to_string()))?;
        if request.amount != self.config.amount_base_units
            || request.period_hours().ok() != Some(period_hours)
        {
            return Err(VerificationError::credential_mismatch(
                "Subscription terms do not match this server",
            ));
        }

        if credential
            .payload
            .get("type")
            .and_then(|value| value.as_str())
            == Some("proof")
        {
            let access: SubscriptionAccessPayload =
                serde_json::from_value(credential.payload.clone()).map_err(|error| {
                    VerificationError::invalid_payload(format!(
                        "Failed to decode proof payload: {error}"
                    ))
                })?;
            return Ok(PreparedCredential::Access { request, access });
        }

        // Challenge expiry limits creation of the durable bearer binding. An
        // already-bound `type="proof"` credential is intentionally handled
        // above so it remains reusable for the active subscription.
        let activation_challenge_expired =
            credential
                .challenge
                .expires
                .as_deref()
                .is_some_and(|value| {
                    time::OffsetDateTime::parse(
                        value,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .map_or(true, |expires| expires <= now)
                });
        if activation_challenge_expired {
            return Err(VerificationError::invalid_payload(
                "Subscription activation challenge has expired",
            ));
        }
        validate_activation_subscription_expiry(request.subscription_expires.as_deref(), now)?;

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

        // ── Validate the activation transaction ──────────────────────────
        match payload_type {
            "transaction" => {
                let tx_b64 = activate.transaction.as_deref().ok_or_else(|| {
                    VerificationError::invalid_payload(
                        "type=\"transaction\" payload missing `transaction` field",
                    )
                })?;
                let mut tx = decode_base64_transaction(tx_b64)?;
                crate::mpp::server::charge::check_network_blockhash(
                    &self.config.network,
                    &tx.message.recent_blockhash().to_string(),
                )?;
                // Envelope: accepted version, no lookup tables, size within the
                // version's limit; then the version-1 header config against the
                // activation compute caps.
                crate::core::tx::check_envelope(&tx, &self.accepted_versions)
                    .map_err(|e| VerificationError::invalid_payload(e.to_string()))?;
                crate::core::tx::check_v1_budget_caps(
                    &tx.message,
                    400_000,
                    if self.config.fee_payer {
                        10_000
                    } else {
                        5_000_000
                    },
                )
                .map_err(|e| VerificationError::invalid_payload(e.to_string()))?;
                let subscriber = extract_subscriber_from_tx(&tx, &request, &self.config)?;
                let program_id = parse_pubkey(&self.program_id, "program_id")
                    .map_err(|e| VerificationError::new(e.to_string()))?;
                let plan_pda = parse_pubkey(&self.config.plan_id, "plan_id")
                    .map_err(|e| VerificationError::new(e.to_string()))?;
                let delegation_pda = find_subscription_pda(&plan_pda, &subscriber, &program_id).0;
                verify_activation_authentication(
                    activate.authentication.as_ref(),
                    &credential.challenge.id,
                    subscriber,
                    &delegation_pda,
                )?;
                validate_activation_scope(
                    &tx,
                    &request,
                    &self.program_id,
                    subscriber,
                    &self.config,
                )?;

                if fee_payer_configured {
                    co_sign_as_fee_payer(&mut tx, self.config.fee_payer_signer.as_ref().unwrap())
                        .await?;
                }
                Ok(PreparedCredential::Activation(PreparedActivation {
                    request,
                    subscriber,
                    tx,
                    authentication: activate.authentication,
                }))
            }
            "signature" => {
                // Push mode (client already broadcast). Not yet supported
                // in v0 — the spec defines it but extracting the
                // subscriber from a fetched transaction requires a
                // versioned-message-aware account_keys reader we don't
                // ship in pay-kit yet.
                Err(VerificationError::invalid_payload(
                    "Push-mode (type=\"signature\") activation is not yet supported by this server. \
                     Use type=\"transaction\" for v0.",
                ))
            }
            other => Err(VerificationError::invalid_payload(format!(
                "Unsupported payload type `{other}` (expected `transaction` or `signature`)"
            ))),
        }
    }

    /// Turn a confirmed activation into the subscription's bearer binding:
    /// read its delegation, check it against this payer, plan and terms, and
    /// rotate the binding to this challenge. The only writer of bindings, for
    /// first activations and recoveries alike.
    async fn bind_confirmed_activation(
        &self,
        credential: &PaymentCredential,
        request: &SubscriptionRequest,
        subscriber: Pubkey,
        activation: VerifiedSignature,
        authentication: Option<&SubscriptionAuthentication>,
    ) -> Result<ReceiptKind, VerificationError> {
        let activation_reference = activation.to_string();
        // ── Derive subscription PDA and read on-chain state ──────────────
        let program_id = parse_pubkey(&self.program_id, "program_id")
            .map_err(|e| VerificationError::new(e.to_string()))?;
        let plan_pda = parse_pubkey(&self.config.plan_id, "plan_id")
            .map_err(|e| VerificationError::new(e.to_string()))?;
        let (subscription_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);

        let delegation = self.fetch_activated_delegation(&subscription_pda).await?;

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
        if delegation.subscriber != subscriber {
            return Err(VerificationError::credential_mismatch(
                "SubscriptionDelegation subscriber does not match the activation signer",
            ));
        }
        // Mint isn't stored on the delegation — the on-chain `Subscribe`
        // ix binds the delegation's terms to the parent Plan's mint, and
        // we already validated `plan_pda` matches the configured plan.
        if delegation.amount_pulled_in_period != expected_amount {
            return Err(VerificationError::new(
                "Activation transaction did not execute the first-period charge",
            ));
        }
        // An existing delegation is only a retry of a paid activation while it
        // is still live; a stale PDA must never stand in for a new charge.
        ensure_live_delegation(
            &delegation,
            expected_amount,
            expected_period_hours,
            request.subscription_expires.as_deref(),
            now_unix_secs(),
        )?;
        self.ensure_current_authority(&subscriber, &delegation)
            .await?;

        let authentication = authentication.ok_or_else(|| {
            VerificationError::invalid_payload(
                "Subscription activation is missing authentication.type=\"proof\"",
            )
        })?;
        let binding_key = subscription_binding_key(&subscription_pda);
        let subscription_id = derive_subscription_id(&subscription_pda, &credential.challenge.id);
        let binding = |landed_slot: u64| {
            serde_json::json!({
                "activationSignature": activation_reference,
                "authentication": authentication,
                "challengeId": credential.challenge.id,
                "landedSlot": landed_slot,
                "periodStartTs": delegation.current_period_start_ts,
                "subscriptionId": subscription_id,
                "subscriptionExpires": request.subscription_expires,
            })
        };
        // Reaching this point proves the activation confirmed and its
        // on-chain delegation matches the challenge. Its binding is written
        // once; a later challenge presenting the same activation gets the
        // binding the first one wrote, never a second one.
        let bound = publish_activation_binding(
            self.store.as_ref(),
            &binding_key,
            &activation,
            ActivationSlots {
                own: || async {
                    self.landed_slot(activation.0).await?.ok_or_else(|| {
                        VerificationError::network_error(
                            "Activation transaction has not been observed landing; retry",
                        )
                    })
                },
                other: |signature: String| async move {
                    match signature.parse::<Signature>() {
                        Ok(signature) => self.landed_slot(signature).await,
                        Err(_) => Ok(None),
                    }
                },
            },
            binding,
        )
        .await?;
        if bound.get("challengeId").and_then(serde_json::Value::as_str)
            != Some(credential.challenge.id.as_str())
        {
            return Err(VerificationError::signature_consumed(
                "Activation is already bound; present the subscription proof for the challenge \
                 that activated it",
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
                reference: activation_reference,
                challenge_id: credential.challenge.id.clone(),
            },
            extensions: SubscriptionReceiptExtensions {
                subscription_id,
                subscription_delegation: subscription_pda.to_string(),
                period_index: 0,
                period_start: format_rfc3339_seconds(period_start_secs),
                period_end: format_rfc3339_seconds(period_end_secs),
                expires_at: request.subscription_expires.clone(),
            },
        };
        Ok(receipt)
    }

    async fn verify_access_credential(
        &self,
        credential: &PaymentCredential,
        request: &SubscriptionRequest,
        access: SubscriptionAccessPayload,
    ) -> Result<ReceiptKind, VerificationError> {
        if access.authentication.challenge_id != credential.challenge.id {
            return Err(VerificationError::credential_mismatch(
                "Subscription proof challengeId does not match the activation challenge",
            ));
        }
        let payer = parse_pubkey(&access.authentication.payer, "authentication.payer")
            .map_err(|error| VerificationError::invalid_payload(error.to_string()))?;
        let program_id = parse_pubkey(&self.program_id, "program_id")
            .map_err(|error| VerificationError::new(error.to_string()))?;
        let plan_pda = parse_pubkey(&self.config.plan_id, "plan_id")
            .map_err(|error| VerificationError::new(error.to_string()))?;
        let expected_delegation = find_subscription_pda(&plan_pda, &payer, &program_id).0;
        if access.subscription_delegation != expected_delegation.to_string() {
            return Err(VerificationError::credential_mismatch(
                "Subscription proof delegation does not match the plan and payer",
            ));
        }
        if !access
            .authentication
            .verify(&access.subscription_delegation)
            .map_err(|error| {
                VerificationError::invalid_payload(format!(
                    "Invalid subscription authentication proof: {error}"
                ))
            })?
        {
            return Err(VerificationError::invalid_payload(
                "Invalid subscription authentication proof",
            ));
        }

        let binding_key = subscription_binding_key(&expected_delegation);
        let binding = self
            .store
            .get(&binding_key)
            .await
            .map_err(|error| {
                VerificationError::new(format!(
                    "Failed to load subscription authentication binding: {error}"
                ))
            })?
            .ok_or_else(|| {
                VerificationError::credential_mismatch(
                    "Subscription has no bound authentication proof",
                )
            })?;
        if binding.get("challengeId").and_then(|value| value.as_str())
            != Some(credential.challenge.id.as_str())
            || binding.get("authentication")
                != Some(
                    &serde_json::to_value(&access.authentication).map_err(|error| {
                        VerificationError::new(format!(
                            "Failed to encode subscription authentication: {error}"
                        ))
                    })?,
                )
        {
            return Err(VerificationError::credential_mismatch(
                "Subscription proof does not match the activation binding",
            ));
        }

        let expected_amount = request.amount.parse::<u64>().map_err(|_| {
            VerificationError::invalid_payload("Subscription amount must be an unsigned integer")
        })?;
        let period_hours = request
            .period_hours()
            .map_err(|error| VerificationError::invalid_payload(error.to_string()))?;
        let now = now_unix_secs();
        let (delegation, period_end) = self
            .active_delegation(
                &payer,
                expected_amount,
                period_hours,
                request.subscription_expires.as_deref(),
                now,
            )
            .await?;

        let anchor = binding
            .get("periodStartTs")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| {
                VerificationError::new("Subscription authentication binding is malformed")
            })?;
        let subscription_id = binding
            .get("subscriptionId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                VerificationError::new("Subscription authentication binding is malformed")
            })?;
        let activation_reference = binding
            .get("activationSignature")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                VerificationError::new("Subscription authentication binding is malformed")
            })?;
        let period_seconds = period_hours as i64 * 3600;
        let elapsed = delegation
            .current_period_start_ts
            .checked_sub(anchor)
            .ok_or_else(|| {
                VerificationError::new("Subscription billing anchor is after the current period")
            })?;
        if elapsed % period_seconds != 0 {
            return Err(VerificationError::new(
                "Subscription billing anchor does not align with the current period",
            ));
        }
        let period_index = u64::try_from(elapsed / period_seconds)
            .map_err(|_| VerificationError::new("Subscription billing period index is invalid"))?;
        Ok(ReceiptKind::Subscription {
            base: Receipt {
                status: crate::mpp::protocol::core::ReceiptStatus::Success,
                method: METHOD_NAME.into(),
                timestamp: format_rfc3339_seconds(now),
                reference: activation_reference.to_string(),
                challenge_id: credential.challenge.id.clone(),
            },
            extensions: SubscriptionReceiptExtensions {
                subscription_id: subscription_id.to_string(),
                subscription_delegation: expected_delegation.to_string(),
                period_index,
                period_start: format_rfc3339_seconds(delegation.current_period_start_ts),
                period_end: format_rfc3339_seconds(period_end),
                expires_at: request.subscription_expires.clone(),
            },
        })
    }

    /// Check on-chain that `subscriber` holds a live, paid subscription to
    /// this server's plan at `amount_base_units` per period: the delegation
    /// exists, its authority is current, the current period is paid, and
    /// neither cancellation nor the configured expiry has taken effect.
    ///
    /// Use this after an identity-only check (such as the legacy
    /// `authenticate` intent) before serving subscription-gated work.
    pub async fn verify_active_subscription(
        &self,
        subscriber: &Pubkey,
        amount_base_units: &str,
    ) -> Result<SubscriptionDelegationView, VerificationError> {
        self.verify_active_subscription_at(subscriber, amount_base_units, now_unix_secs())
            .await
    }

    /// [`Self::verify_active_subscription`] evaluated at `now` (unix seconds).
    async fn verify_active_subscription_at(
        &self,
        subscriber: &Pubkey,
        amount_base_units: &str,
        now: i64,
    ) -> Result<SubscriptionDelegationView, VerificationError> {
        let expected_amount = amount_base_units.parse::<u64>().map_err(|_| {
            VerificationError::invalid_payload("Subscription amount must be an unsigned integer")
        })?;
        let period_hours = self
            .config
            .period_unit
            .to_period_hours(self.config.period_count)
            .map_err(|error| VerificationError::new(error.to_string()))?;
        self.active_delegation(
            subscriber,
            expected_amount,
            period_hours,
            self.config.subscription_expires.as_deref(),
            now,
        )
        .await
        .map(|(delegation, _)| delegation)
    }

    /// Load the subscriber's delegation and require it to be live at `now`.
    /// Returns it with the current period's end.
    async fn active_delegation(
        &self,
        subscriber: &Pubkey,
        expected_amount: u64,
        period_hours: u64,
        subscription_expires: Option<&str>,
        now: i64,
    ) -> Result<(SubscriptionDelegationView, i64), VerificationError> {
        let program_id = parse_pubkey(&self.program_id, "program_id")
            .map_err(|error| VerificationError::new(error.to_string()))?;
        let plan_pda = parse_pubkey(&self.config.plan_id, "plan_id")
            .map_err(|error| VerificationError::new(error.to_string()))?;
        let delegation_pda = find_subscription_pda(&plan_pda, subscriber, &program_id).0;
        let delegation = self.fetch_subscription_delegation(&delegation_pda).await?;
        if delegation.plan_pda != plan_pda || delegation.subscriber != *subscriber {
            return Err(VerificationError::credential_mismatch(
                "SubscriptionDelegation does not match the bound plan and payer",
            ));
        }
        self.ensure_current_authority(subscriber, &delegation)
            .await?;
        if now < delegation.current_period_start_ts {
            return Err(VerificationError::transaction_failed(
                "Subscription is not paid for the current billing period",
            ));
        }
        let period_end = ensure_live_delegation(
            &delegation,
            expected_amount,
            period_hours,
            subscription_expires,
            now,
        )?;
        Ok((delegation, period_end))
    }

    /// Require the subscriber's `SubscriptionAuthority` to exist and be the
    /// generation `delegation` was created under.
    async fn ensure_current_authority(
        &self,
        subscriber: &Pubkey,
        delegation: &SubscriptionDelegationView,
    ) -> Result<(), VerificationError> {
        let program_id = parse_pubkey(&self.program_id, "program_id")
            .map_err(|error| VerificationError::new(error.to_string()))?;
        let mint = parse_pubkey(&self.config.mint, "mint")
            .map_err(|error| VerificationError::new(error.to_string()))?;
        let authority_pda = find_subscription_authority_pda(subscriber, &mint, &program_id).0;
        let authority_init_id = self
            .fetch_subscription_authority_init_id(&authority_pda)
            .await?;
        if authority_init_id != delegation.authority_init_id {
            return Err(VerificationError::credential_mismatch(
                "Subscription authority has been invalidated",
            ));
        }
        Ok(())
    }

    /// Broadcast a signed transaction and wait for `confirmed` (NOT
    /// `finalized`). The 402 caller is blocked on this round-trip, so
    /// every extra slot is a second of UX latency. `confirmed` means
    /// supermajority observed it (~1-2 slots, ~400-800ms); finalisation
    /// happens behind the scenes regardless and the subscription will
    /// still be honoured on the next request.
    // Live-RPC boundary; transaction shape is covered before this call.
    async fn broadcast_and_confirm(
        &self,
        tx: &VersionedTransaction,
    ) -> Result<Signature, BroadcastError> {
        use solana_rpc_client_api::client_error::ErrorKind;
        let rpc_url = self.rpc_url.clone();
        let tx = tx.clone();
        // RpcClient is blocking; offload to a worker thread.
        tokio::task::spawn_blocking(move || {
            let rpc = confirmed_rpc(rpc_url);
            let failed = |e: &dyn std::fmt::Display| {
                VerificationError::transaction_failed(format!("Broadcast failed: {e}"))
            };
            let signature = crate::core::rpc::send_transaction(
                &rpc,
                &tx,
                crate::core::rpc::preflight_config(&rpc),
            )
            .map_err(|e| match e.kind() {
                // The node refused it (preflight or sanitization): never sent.
                ErrorKind::RpcError(
                    solana_rpc_client_api::request::RpcError::RpcResponseError { .. },
                ) => BroadcastError::Rejected(failed(&e)),
                _ => BroadcastError::Unknown(failed(&e)),
            })?;
            let blockhash = *tx.message.recent_blockhash();
            loop {
                match rpc
                    .get_signature_status_with_commitment(&signature, rpc.commitment())
                    .map_err(|e| BroadcastError::Unknown(failed(&e)))?
                {
                    Some(Ok(())) => return Ok(signature),
                    Some(Err(e)) => return Err(BroadcastError::Rejected(failed(&e))),
                    None => {
                        let valid = rpc
                            .is_blockhash_valid(
                                &blockhash,
                                solana_commitment_config::CommitmentConfig::processed(),
                            )
                            .map_err(|e| BroadcastError::Unknown(failed(&e)))?;
                        if !valid {
                            return Err(BroadcastError::Rejected(failed(
                                &"its blockhash expired before it confirmed",
                            )));
                        }
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
        })
        .await
        .map_err(|e| {
            BroadcastError::Unknown(VerificationError::network_error(format!(
                "RPC task join: {e}"
            )))
        })?
    }

    /// Read the delegation a just-confirmed activation created, tolerating
    /// an RPC node that has not caught up to the confirmation yet.
    async fn fetch_activated_delegation(
        &self,
        subscription_pda: &Pubkey,
    ) -> Result<SubscriptionDelegationView, VerificationError> {
        for _ in 1..ACTIVATED_DELEGATION_READ_ATTEMPTS {
            if let Some(delegation) = self
                .try_fetch_subscription_delegation(subscription_pda)
                .await?
            {
                return Ok(delegation);
            }
            tokio::time::sleep(ACTIVATED_DELEGATION_READ_BACKOFF).await;
        }
        self.fetch_subscription_delegation(subscription_pda).await
    }

    async fn fetch_subscription_delegation(
        &self,
        subscription_pda: &Pubkey,
    ) -> Result<SubscriptionDelegationView, VerificationError> {
        self.try_fetch_subscription_delegation(subscription_pda)
            .await?
            .ok_or_else(|| {
                VerificationError::not_found(format!(
                    "SubscriptionDelegation account {subscription_pda} not found"
                ))
            })
    }

    // Live-RPC boundary; ownership and the decoder are covered independently.
    async fn try_fetch_subscription_delegation(
        &self,
        subscription_pda: &Pubkey,
    ) -> Result<Option<SubscriptionDelegationView>, VerificationError> {
        let rpc_url = self.rpc_url.clone();
        let pda = *subscription_pda;
        let expected_owner = parse_pubkey(&self.program_id, "program_id")
            .map_err(|error| VerificationError::new(error.to_string()))?;
        tokio::task::spawn_blocking(move || {
            let rpc = confirmed_rpc(rpc_url);
            let Some(account) = rpc
                .get_account_with_commitment(&pda, rpc.commitment())
                .map_err(|e| {
                    VerificationError::network_error(format!(
                        "SubscriptionDelegation account {pda} lookup failed: {e}"
                    ))
                })?
                .value
            else {
                return Ok(None);
            };
            if account.owner != expected_owner {
                return Err(VerificationError::credential_mismatch(format!(
                    "SubscriptionDelegation owner mismatch: expected {expected_owner}, got {}",
                    account.owner
                )));
            }
            decode_subscription_delegation(&account.data)
                .map(Some)
                .map_err(VerificationError::new)
        })
        .await
        .map_err(|e| VerificationError::network_error(format!("RPC task join: {e}")))?
    }

    // Live-RPC boundary; ownership and the decoder are covered independently.
    async fn fetch_subscription_authority_init_id(
        &self,
        authority_pda: &Pubkey,
    ) -> Result<i64, VerificationError> {
        let rpc_url = self.rpc_url.clone();
        let pda = *authority_pda;
        let expected_owner = parse_pubkey(&self.program_id, "program_id")
            .map_err(|error| VerificationError::new(error.to_string()))?;
        tokio::task::spawn_blocking(move || {
            let rpc = confirmed_rpc(rpc_url);
            let account = rpc.get_account(&pda).map_err(|error| {
                VerificationError::not_found(format!(
                    "SubscriptionAuthority account {pda} not found: {error}"
                ))
            })?;
            if account.owner != expected_owner {
                return Err(VerificationError::credential_mismatch(format!(
                    "SubscriptionAuthority owner mismatch: expected {expected_owner}, got {}",
                    account.owner
                )));
            }
            decode_subscription_authority_init_id(&account.data).map_err(VerificationError::new)
        })
        .await
        .map_err(|error| VerificationError::network_error(format!("RPC task join: {error}")))?
    }

    /// Require `signature` to be a transaction that landed successfully.
    // Live-RPC boundary; covered by the scripted-node activation tests.
    async fn ensure_activation_landed(
        &self,
        signature: &VerifiedSignature,
    ) -> Result<(), VerificationError> {
        let rpc_url = self.rpc_url.clone();
        let signature = signature.0;
        let status = tokio::task::spawn_blocking(move || {
            let rpc = confirmed_rpc(rpc_url);
            rpc.get_signature_status_with_commitment_and_history(&signature, rpc.commitment(), true)
        })
        .await
        .map_err(|e| VerificationError::network_error(format!("RPC task join: {e}")))?
        .map_err(|e| {
            VerificationError::network_error(format!(
                "getSignatureStatuses({signature}) failed: {e}"
            ))
        })?;
        match status {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(VerificationError::transaction_failed(format!(
                "Activation transaction {signature} failed on-chain: {error}"
            ))),
            None => Err(VerificationError::credential_mismatch(
                "SubscriptionDelegation already exists and this activation transaction did not \
                 create it; present the subscription proof instead",
            )),
        }
    }

    /// The slot `signature` landed in successfully, from confirmed status
    /// with history; `None` when the RPC does not have it.
    async fn landed_slot(&self, signature: Signature) -> Result<Option<u64>, VerificationError> {
        let rpc_url = self.rpc_url.clone();
        let statuses = tokio::task::spawn_blocking(move || {
            confirmed_rpc(rpc_url).get_signature_statuses_with_history(&[signature])
        })
        .await
        .map_err(|e| VerificationError::network_error(format!("RPC task join: {e}")))?
        .map_err(|e| VerificationError::network_error(format!("getSignatureStatuses failed: {e}")))?
        .value;
        Ok(statuses
            .into_iter()
            .next()
            .flatten()
            .filter(|status| status.err.is_none())
            .map(|status| status.slot))
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

/// Outcome of a failed activation broadcast.
/// An activation transaction's ID: its first signature, verified against its
/// message by its fee payer's key. Only this, never a raw `signatures[0]`,
/// keys the activation's replay and binding records, so a transaction
/// carrying someone else's landed signature cannot claim their activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedSignature(Signature);

impl VerifiedSignature {
    fn of(tx: &VersionedTransaction) -> Result<Self, VerificationError> {
        let signature = tx.signatures.first().ok_or_else(|| {
            VerificationError::invalid_payload("Activation transaction has no signature slot")
        })?;
        let signer = tx.message.static_account_keys().first().ok_or_else(|| {
            VerificationError::invalid_payload("Activation transaction has no fee payer")
        })?;
        if !signature.verify(signer.as_ref(), &tx.message.serialize()) {
            return Err(VerificationError::invalid_payload(
                "Activation transaction signature does not verify against its message",
            ));
        }
        Ok(Self(*signature))
    }
}

impl std::fmt::Display for VerifiedSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// What [`SubscriptionServer::prepare_credential`] hands to the settlement half.
enum PreparedCredential {
    /// A `type="proof"` access credential; verified against the binding.
    Access {
        request: SubscriptionRequest,
        access: SubscriptionAccessPayload,
    },
    /// An activation whose transaction passed every offline check.
    Activation(PreparedActivation),
}

struct PreparedActivation {
    request: SubscriptionRequest,
    subscriber: Pubkey,
    /// Co-signed by the sponsor when fee sponsorship is configured.
    tx: VersionedTransaction,
    authentication: Option<SubscriptionAuthentication>,
}

/// Conformance hooks (feature `testkit`). Not a payment verifier: nothing
/// here reads the chain, consumes replay state or broadcasts. Use
/// [`SubscriptionServer::verify_credential`] to accept subscriptions.
#[cfg(feature = "testkit")]
pub mod testkit {
    use super::*;

    /// How far [`verify_activation_pre_broadcast`] got.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PreBroadcast {
        /// An activation passed every check
        /// [`SubscriptionServer::verify_credential`] applies before it
        /// reserves the signature and broadcasts.
        Activation,
        /// A `type="proof"` access credential: verifying it needs the
        /// binding a confirmed activation writes, which is not offline.
        AccessProof,
    }

    /// Run the offline half of [`SubscriptionServer::verify_credential`] at
    /// `now` (unix seconds): the challenge binding and expiry, the request
    /// terms, the activation payload and bearer proof, the activation scope,
    /// the fee-payer co-signature and the fee payer's signature over the
    /// message, stopping where the production path first reads the chain.
    pub async fn verify_activation_pre_broadcast(
        server: &SubscriptionServer,
        credential: &PaymentCredential,
        now: i64,
    ) -> Result<PreBroadcast, VerificationError> {
        let now = time::OffsetDateTime::from_unix_timestamp(now)
            .map_err(|error| VerificationError::new(format!("invalid clock: {error}")))?;
        match server.prepare_credential(credential, now).await? {
            PreparedCredential::Access { .. } => Ok(PreBroadcast::AccessProof),
            PreparedCredential::Activation(activation) => {
                VerifiedSignature::of(&activation.tx)?;
                Ok(PreBroadcast::Activation)
            }
        }
    }

    /// [`SubscriptionServer::verify_active_subscription`] at `now` (unix
    /// seconds) instead of the wall clock.
    pub async fn verify_active_subscription_at(
        server: &SubscriptionServer,
        subscriber: &Pubkey,
        amount_base_units: &str,
        now: i64,
    ) -> Result<SubscriptionDelegationView, VerificationError> {
        server
            .verify_active_subscription_at(subscriber, amount_base_units, now)
            .await
    }
}

enum BroadcastError {
    /// The transaction did not and cannot land.
    Rejected(VerificationError),
    /// It may still land; the replay reservation must be kept.
    Unknown(VerificationError),
}

const ACTIVATED_DELEGATION_READ_ATTEMPTS: u32 = 5;
const ACTIVATED_DELEGATION_READ_BACKOFF: std::time::Duration =
    std::time::Duration::from_millis(400);

/// Every activation read uses the commitment the broadcast confirmed at, so
/// state a confirmed activation created is visible to the checks that follow.
fn confirmed_rpc(rpc_url: String) -> solana_rpc_client::rpc_client::RpcClient {
    solana_rpc_client::rpc_client::RpcClient::new_with_commitment(
        rpc_url,
        solana_commitment_config::CommitmentConfig::confirmed(),
    )
}

fn validate_activation_subscription_expiry(
    subscription_expires: Option<&str>,
    now: time::OffsetDateTime,
) -> Result<(), VerificationError> {
    let Some(subscription_expires) = subscription_expires else {
        return Ok(());
    };
    let expires_at = time::OffsetDateTime::parse(
        subscription_expires,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|error| {
        VerificationError::invalid_payload(format!("Invalid subscriptionExpires: {error}"))
    })?;
    if expires_at <= now {
        return Err(VerificationError::transaction_failed(
            "Subscription has expired",
        ));
    }
    Ok(())
}

/// Require `delegation` to be paid for the billing period containing `now`
/// and not cancelled or expired. Returns the current period's end.
fn ensure_live_delegation(
    delegation: &SubscriptionDelegationView,
    expected_amount: u64,
    period_hours: u64,
    subscription_expires: Option<&str>,
    now: i64,
) -> Result<i64, VerificationError> {
    let period_end = delegation
        .current_period_start_ts
        .saturating_add(period_hours as i64 * 3600);
    if delegation.amount_per_period != expected_amount
        || delegation.period_hours != period_hours
        || delegation.amount_pulled_in_period != expected_amount
        || now >= period_end
    {
        return Err(VerificationError::transaction_failed(
            "Subscription is not paid for the current billing period",
        ));
    }
    if delegation.expires_at_ts != 0 && now >= delegation.expires_at_ts {
        return Err(VerificationError::transaction_failed(
            "Subscription cancellation has taken effect",
        ));
    }
    if let Some(expires_at) = subscription_expires {
        let expires_at =
            time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
                .map_err(|error| {
                    VerificationError::invalid_payload(format!(
                        "Invalid subscriptionExpires: {error}"
                    ))
                })?;
        if expires_at.unix_timestamp() <= now {
            return Err(VerificationError::transaction_failed(
                "Subscription has expired",
            ));
        }
    }
    Ok(period_end)
}

#[derive(Debug, PartialEq, Eq)]
enum ActivationReservation {
    /// Reserved for this challenge, now or by an earlier attempt of it.
    Held,
    /// Reserved by a different challenge.
    HeldElsewhere,
}

async fn try_reserve_activation_signature(
    store: &dyn Store,
    key: &str,
    binding: serde_json::Value,
) -> Result<ActivationReservation, VerificationError> {
    let inserted = store
        .put_if_absent(key, binding.clone())
        .await
        .map_err(|error| {
            VerificationError::new(format!("Failed to reserve activation signature: {error}"))
        })?;
    if inserted {
        return Ok(ActivationReservation::Held);
    }

    // Re-broadcasting the same signed transaction is idempotent on Solana.
    // Accept only the original challenge binding so an ambiguous RPC failure
    // can be retried without making the signature reusable by another request.
    let existing = store.get(key).await.map_err(|error| {
        VerificationError::new(format!("Failed to load activation reservation: {error}"))
    })?;
    Ok(if existing == Some(binding) {
        ActivationReservation::Held
    } else {
        ActivationReservation::HeldElsewhere
    })
}

async fn reserve_activation_signature(
    store: &dyn Store,
    key: &str,
    binding: serde_json::Value,
) -> Result<(), VerificationError> {
    match try_reserve_activation_signature(store, key, binding).await? {
        ActivationReservation::Held => Ok(()),
        ActivationReservation::HeldElsewhere => Err(VerificationError::signature_consumed(
            "Activation signature already consumed",
        )),
    }
}

/// Where [`publish_activation_binding`] reads landing slots from: `own` is
/// the confirmed activation being bound, `other` a legacy binding's activation
/// that recorded none (`None` when the RPC no longer has it).
struct ActivationSlots<Own, Other> {
    own: Own,
    other: Other,
}

fn landed_slot_of(binding: &serde_json::Value) -> Option<u64> {
    binding
        .get("landedSlot")
        .and_then(serde_json::Value::as_u64)
}

/// Bind a confirmed activation and return its binding.
///
/// The per-activation record is the claim: `put_if_absent` lets its first
/// writer win, and nothing else is held, so a request cancelled before it
/// leaves nothing behind. Each record carries the slot its activation landed
/// in. The record is then published as the subscription's current binding,
/// only by compare-and-set against the binding just read:
/// - absent, or this activation's own: published, which also repairs a write
///   interrupted between the two steps;
/// - another activation's: replaced only when this one landed in a later
///   slot. Stored slots decide; a legacy binding with none is looked up once,
///   and one the RPC no longer has predates its history window, so it is
///   older. A retry of a retired activation is refused and writes nothing.
async fn publish_activation_binding<Own, OwnFut, Other, OtherFut>(
    store: &dyn Store,
    binding_key: &str,
    activation: &VerifiedSignature,
    slots: ActivationSlots<Own, Other>,
    candidate: impl FnOnce(u64) -> serde_json::Value,
) -> Result<serde_json::Value, VerificationError>
where
    Own: Fn() -> OwnFut,
    OwnFut: std::future::Future<Output = Result<u64, VerificationError>>,
    Other: Fn(String) -> OtherFut,
    OtherFut: std::future::Future<Output = Result<Option<u64>, VerificationError>>,
{
    let store_err = |error: crate::core::store::StoreError| {
        VerificationError::new(format!(
            "Failed to store subscription authentication binding: {error}"
        ))
    };
    let activation_signature = activation.to_string();
    let activation_of = |binding: &serde_json::Value| {
        binding
            .get("activationSignature")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    let activation_key = format!("solana-subscription:activation-binding:{activation_signature}");
    let mut current = store.get(binding_key).await.map_err(store_err)?;
    let recorded = store.get(&activation_key).await.map_err(store_err)?;
    let bound = match recorded {
        Some(record) => record,
        None => {
            // Bound before per-activation records existed: that binding is
            // the record.
            let candidate = match &current {
                Some(binding)
                    if activation_of(binding).as_deref() == Some(&activation_signature) =>
                {
                    binding.clone()
                }
                _ => candidate((slots.own)().await?),
            };
            if store
                .put_if_absent(&activation_key, candidate.clone())
                .await
                .map_err(store_err)?
            {
                candidate
            } else {
                store
                    .get(&activation_key)
                    .await
                    .map_err(store_err)?
                    .ok_or_else(|| {
                        VerificationError::new("Activation binding disappeared; retry")
                    })?
            }
        }
    };
    let already_bound = || {
        VerificationError::signature_consumed(
            "Activation is already bound; present the subscription proof for the challenge \
             that activated it",
        )
    };
    let mut own_slot = landed_slot_of(&bound);
    for _ in 0..PUBLISH_ATTEMPTS {
        match &current {
            Some(binding) if binding == &bound => return Ok(bound),
            Some(binding) => {
                if let Some(other) = activation_of(binding) {
                    if other != activation_signature {
                        let this = match own_slot {
                            Some(slot) => slot,
                            None => {
                                let slot = (slots.own)().await?;
                                own_slot = Some(slot);
                                slot
                            }
                        };
                        let previous = match landed_slot_of(binding) {
                            Some(slot) => Some(slot),
                            None => (slots.other)(other).await?,
                        };
                        if previous.is_some_and(|previous| previous >= this) {
                            return Err(already_bound());
                        }
                    }
                }
            }
            None => {}
        }
        if store
            .put_if_eq(binding_key, current.clone(), bound.clone())
            .await
            .map_err(store_err)?
        {
            return Ok(bound);
        }
        current = store.get(binding_key).await.map_err(store_err)?;
    }
    Err(VerificationError::new(
        "Subscription binding is contended; retry",
    ))
}

/// Compare-and-set rounds one publish makes under contention before asking
/// the client to retry.
const PUBLISH_ATTEMPTS: usize = 8;

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

fn verify_activation_authentication(
    authentication: Option<&SubscriptionAuthentication>,
    challenge_id: &str,
    subscriber: Pubkey,
    subscription_delegation: &Pubkey,
) -> Result<(), VerificationError> {
    let authentication = authentication.ok_or_else(|| {
        VerificationError::invalid_payload(
            "Subscription activation is missing authentication.type=\"proof\"",
        )
    })?;
    if authentication.challenge_id != challenge_id {
        return Err(VerificationError::credential_mismatch(
            "Subscription proof challengeId does not match the activation challenge",
        ));
    }
    if authentication.payer != subscriber.to_string() {
        return Err(VerificationError::credential_mismatch(
            "Subscription proof payer does not match the activation subscriber",
        ));
    }
    if !authentication
        .verify(&subscription_delegation.to_string())
        .map_err(|error| VerificationError::invalid_payload(error.to_string()))?
    {
        return Err(VerificationError::invalid_payload(
            "Invalid subscription authentication proof",
        ));
    }
    Ok(())
}

fn subscription_binding_key(subscription_delegation: &Pubkey) -> String {
    format!("solana-subscription:authentication:{subscription_delegation}")
}

fn derive_subscription_id(subscription_delegation: &Pubkey, challenge_id: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(format!(
        "mpp-subscription-id-v1:{challenge_id}:{subscription_delegation}"
    ));
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..18])
}

/// Base64-decode + bincode-deserialise the activation transaction. The
/// client sends it in standard base64 per the spec.
fn decode_base64_transaction(b64: &str) -> Result<VersionedTransaction, VerificationError> {
    crate::core::tx::decode(b64)
        .map_err(|e| VerificationError::invalid_payload(format!("Tx decode: {e}")))
}

/// Extract the subscriber pubkey from the activation transaction.
///
/// When fee sponsorship is in play, the fee payer (first signer) is the
/// server; the subscriber is the next signer that isn't the puller.
/// Otherwise the subscriber is `account_keys[0]`.
fn extract_subscriber_from_tx(
    tx: &VersionedTransaction,
    _request: &SubscriptionRequest,
    config: &SubscriptionConfig,
) -> Result<Pubkey, VerificationError> {
    let keys = &tx.message.static_account_keys();
    if keys.is_empty() {
        return Err(VerificationError::invalid_payload(
            "VersionedTransaction has no account keys",
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
        let required_signers = tx.message.header().num_required_signatures as usize;
        for k in keys.iter().take(required_signers).skip(1) {
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
    tx: &VersionedTransaction,
    request: &SubscriptionRequest,
    program_id_str: &str,
    subscriber: Pubkey,
    config: &SubscriptionConfig,
) -> Result<(), VerificationError> {
    let program_id = parse_pubkey(program_id_str, "program_id")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let keys = &tx.message.static_account_keys();

    if config.fee_payer {
        let expected_fee_payer = config
            .fee_payer_signer
            .as_ref()
            .map(|signer| signer.pubkey())
            .or_else(|| {
                config
                    .fee_payer_pubkey
                    .as_deref()
                    .and_then(|key| parse_pubkey(key, "fee_payer_key").ok())
            })
            .ok_or_else(|| {
                VerificationError::invalid_payload(
                    "fee_payer=true requires a configured fee-payer pubkey",
                )
            })?;
        if keys.first() != Some(&expected_fee_payer) {
            return Err(VerificationError::invalid_payload(format!(
                "Activation transaction fee payer must be {expected_fee_payer}"
            )));
        }
    }

    let compute_budget_program = parse_pubkey(COMPUTE_BUDGET_PROGRAM_ID, "compute_budget_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let associated_token_program =
        parse_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID, "associated_token_program")
            .map_err(|e| VerificationError::new(e.to_string()))?;
    let memo_program = parse_pubkey(MEMO_PROGRAM_ID, "memo_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let system_program = parse_pubkey(SYSTEM_PROGRAM_ID, "system_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let mint =
        parse_pubkey(&config.mint, "mint").map_err(|e| VerificationError::new(e.to_string()))?;
    let token_program = parse_pubkey(&config.token_program, "token_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let puller = parse_pubkey(&config.puller, "puller")
        .map_err(|e| VerificationError::new(e.to_string()))?;

    let plan_pda = parse_pubkey(&config.plan_id, "plan_id")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let expected_subscription = find_subscription_pda(&plan_pda, &subscriber, &program_id).0;
    let expected_authority = find_subscription_authority_pda(&subscriber, &mint, &program_id).0;
    let sponsor = keys.first().copied().filter(|_| config.fee_payer);

    let mut subscribe_idx: Option<usize> = None;
    let mut transfer_idx: Option<usize> = None;
    let mut ata_idx: Option<usize> = None;
    let mut saw_memo = false;
    let mut saw_compute_limit = false;
    let mut saw_compute_price = false;
    for (i, ix) in tx.message.instructions().iter().enumerate() {
        let prog_idx = ix.program_id_index as usize;
        if prog_idx >= keys.len() {
            return Err(VerificationError::invalid_payload(
                "Activation instruction has an invalid program index",
            ));
        }
        let instruction_program = keys[prog_idx];

        if instruction_program == compute_budget_program {
            match ix.data.as_slice() {
                [2, units @ ..] if units.len() == 4 => {
                    if saw_compute_limit {
                        return Err(VerificationError::invalid_payload(
                            "Activation tx contains multiple compute-unit-limit instructions",
                        ));
                    }
                    saw_compute_limit = true;
                    let units = u32::from_le_bytes(units.try_into().unwrap());
                    if units > 400_000 {
                        return Err(VerificationError::invalid_payload(
                            "Activation compute unit limit exceeds 400000",
                        ));
                    }
                }
                [3, price @ ..] if price.len() == 8 => {
                    if saw_compute_price {
                        return Err(VerificationError::invalid_payload(
                            "Activation tx contains multiple compute-unit-price instructions",
                        ));
                    }
                    saw_compute_price = true;
                    let price = u64::from_le_bytes(price.try_into().unwrap());
                    let max_price = if config.fee_payer { 10_000 } else { 5_000_000 };
                    if price > max_price {
                        return Err(VerificationError::invalid_payload(
                            "Activation compute unit price exceeds cap",
                        ));
                    }
                }
                _ => {
                    return Err(VerificationError::invalid_payload(
                        "Unsupported compute-budget instruction in activation tx",
                    ))
                }
            }
            continue;
        }

        if instruction_program == memo_program {
            if saw_memo || request.external_id.as_deref() != std::str::from_utf8(&ix.data).ok() {
                return Err(VerificationError::invalid_payload(
                    "Activation memo does not match challenge externalId",
                ));
            }
            saw_memo = true;
            continue;
        }

        if instruction_program == associated_token_program {
            if ata_idx.is_some() || ix.data.as_slice() != [1] || ix.accounts.len() != 6 {
                return Err(VerificationError::invalid_payload(
                    "Only one idempotent subscriber ATA creation is allowed in activation tx",
                ));
            }
            let account = |position: usize| -> Option<Pubkey> {
                ix.accounts
                    .get(position)
                    .and_then(|index| keys.get(*index as usize))
                    .copied()
            };
            if account(2) != Some(subscriber)
                || account(3) != Some(mint)
                || account(4) != Some(system_program)
                || account(5) != Some(token_program)
            {
                return Err(VerificationError::invalid_payload(
                    "ATA creation does not match the activation subscriber and mint",
                ));
            }
            ata_idx = Some(i);
            continue;
        }

        if instruction_program != program_id {
            return Err(VerificationError::invalid_payload(format!(
                "Unsupported program {instruction_program} in activation tx"
            )));
        }
        let Some(disc) = ix.data.first().copied() else {
            return Err(VerificationError::invalid_payload(
                "Activation tx contains an empty subscriptions-program instruction",
            ));
        };
        let account = |position: usize| -> Option<Pubkey> {
            ix.accounts
                .get(position)
                .and_then(|index| keys.get(*index as usize))
                .copied()
        };
        if disc == INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY {
            // The authority's init_id is set at its landing slot, which a
            // same-transaction Subscribe cannot pin; clients initialize it
            // in its own transaction.
            return Err(VerificationError::invalid_payload(
                "initialize_subscription_authority is not allowed in an activation tx",
            ));
        } else if disc == INSTRUCTION_SUBSCRIBE {
            if subscribe_idx.is_some() {
                return Err(VerificationError::invalid_payload(
                    "Activation tx contains multiple subscribe instructions",
                ));
            }
            let payer_ok = match ix.accounts.len() {
                8 => true,
                9 => sponsor.is_some() && account(8) == sponsor,
                _ => false,
            };
            if !payer_ok
                || account(0) != Some(subscriber)
                || account(2) != Some(plan_pda)
                || account(3) != Some(expected_subscription)
                || account(4) != Some(expected_authority)
                || account(5) != Some(system_program)
                || account(7) != Some(program_id)
            {
                return Err(VerificationError::invalid_payload(
                    "subscribe accounts do not match the challenged activation",
                ));
            }
            subscribe_idx = Some(i);
        } else if disc == INSTRUCTION_TRANSFER_SUBSCRIPTION {
            if transfer_idx.is_some() {
                return Err(VerificationError::invalid_payload(
                    "Activation tx contains multiple transfer_subscription instructions",
                ));
            }
            if ix.accounts.len() != 10 || ix.data.len() != 73 {
                return Err(VerificationError::invalid_payload(
                    "transfer_subscription does not match the Codama v0.5 schema",
                ));
            }
            let recipient = parse_pubkey(&request.recipient, "recipient")
                .map_err(|e| VerificationError::new(e.to_string()))?;
            let expected_delegator_ata = Pubkey::find_program_address(
                &[subscriber.as_ref(), token_program.as_ref(), mint.as_ref()],
                &associated_token_program,
            )
            .0;
            let expected_receiver_ata = Pubkey::find_program_address(
                &[recipient.as_ref(), token_program.as_ref(), mint.as_ref()],
                &associated_token_program,
            )
            .0;
            let expected_event_authority = find_event_authority_pda(&program_id).0;
            if account(0) != Some(expected_subscription)
                || account(1) != Some(plan_pda)
                || account(2) != Some(expected_authority)
                || account(3) != Some(expected_delegator_ata)
                || account(4) != Some(expected_receiver_ata)
                || account(5) != Some(puller)
                || account(6) != Some(mint)
                || account(7) != Some(token_program)
                || account(8) != Some(expected_event_authority)
                || account(9) != Some(program_id)
            {
                return Err(VerificationError::invalid_payload(
                    "transfer_subscription accounts do not match the challenged activation",
                ));
            }
            let amount = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
            let delegator = Pubkey::new_from_array(ix.data[9..41].try_into().unwrap());
            let transfer_mint = Pubkey::new_from_array(ix.data[41..73].try_into().unwrap());
            let expected_amount = request.amount.parse::<u64>().map_err(|_| {
                VerificationError::invalid_payload("Challenge amount must be a u64")
            })?;
            if amount != expected_amount || delegator != subscriber || transfer_mint != mint {
                return Err(VerificationError::invalid_payload(
                    "transfer_subscription data does not match the challenged activation",
                ));
            }
            transfer_idx = Some(i);
        } else {
            return Err(VerificationError::invalid_payload(format!(
                "Unsupported subscriptions instruction {disc} in activation tx"
            )));
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
    if ata_idx.is_some_and(|idx| idx > subscribe) {
        return Err(VerificationError::invalid_payload(
            "Activation setup instructions must precede subscribe",
        ));
    }
    if request.external_id.is_some() != saw_memo {
        return Err(VerificationError::invalid_payload(
            "Activation transaction memo does not match challenge externalId",
        ));
    }
    // Required signers are exactly the fee payer, the subscriber and the
    // puller; extra slots would be paid for by a sponsor.
    let fee_payer = keys.first().copied().ok_or_else(|| {
        VerificationError::invalid_payload("VersionedTransaction has no account keys")
    })?;
    if !config.fee_payer && fee_payer != subscriber {
        return Err(VerificationError::invalid_payload(
            "Activation transaction fee payer must be the subscriber",
        ));
    }
    let mut expected_signers = vec![fee_payer, subscriber, puller];
    expected_signers.sort();
    expected_signers.dedup();
    let required_signers = tx.message.header().num_required_signatures as usize;
    let mut signers = keys.get(..required_signers).unwrap_or(keys).to_vec();
    signers.sort();
    if signers != expected_signers || tx.signatures.len() != required_signers {
        return Err(VerificationError::invalid_payload(
            "Activation transaction signers must be exactly the fee payer, subscriber and puller",
        ));
    }
    Ok(())
}

/// Sign the transaction's fee-payer slot with the server's fee-payer signer.
/// The client has already signed as the subscriber and (when fee sponsorship is
/// in play) left an empty signature slot at the fee-payer index.
///
/// Routes through `TransactionSigner::sign_transaction`, so a hardware
/// fee-payer signer works. Raw-signing `tx.message_data()` here is what used to
/// restrict activation sponsorship to software keys.
async fn co_sign_as_fee_payer(
    tx: &mut VersionedTransaction,
    signer: &Arc<dyn solana_keychain::TransactionSigner>,
) -> Result<(), VerificationError> {
    let pubkey = signer.pubkey();
    // Keep the payload-shaped diagnostics: both failures are caused by the
    // client's transaction, so neither may read as a server fault. The fee payer
    // is account key zero by construction, and accepting the sponsor at a later
    // index would let a crafted transaction leave its actual fee payer unsigned.
    if tx.message.static_account_keys().first() != Some(&pubkey) {
        return Err(VerificationError::invalid_payload(
            "Fee payer pubkey not present in activation transaction",
        ));
    }
    if tx.signatures.len() != tx.message.header().num_required_signatures as usize {
        return Err(VerificationError::invalid_payload(
            "VersionedTransaction signatures vec is shorter than account_keys",
        ));
    }
    crate::core::signing::cosign_versioned_fee_payer(signer.as_ref(), &pubkey, tx)
        .await
        .map_err(|e| VerificationError::new(format!("Fee-payer signing failed: {e}")))
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
    pub authority_init_id: i64,
    pub amount_per_period: u64,
    pub period_hours: u64,
    pub current_period_start_ts: i64,
    pub amount_pulled_in_period: u64,
    pub expires_at_ts: i64,
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

const SUBSCRIPTION_AUTHORITY_LEN: usize = 106;
const SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET: usize = 98;

fn decode_subscription_authority_init_id(data: &[u8]) -> Result<i64, String> {
    if data.len() != SUBSCRIPTION_AUTHORITY_LEN {
        return Err(format!(
            "Unexpected SubscriptionAuthority length: got {}, expected {SUBSCRIPTION_AUTHORITY_LEN}",
            data.len()
        ));
    }
    if data[0] != 0 {
        return Err(format!(
            "Invalid SubscriptionAuthority discriminator: {}",
            data[0]
        ));
    }
    Ok(i64::from_le_bytes(
        data[SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET..SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET + 8]
            .try_into()
            .expect("8-byte slice"),
    ))
}

fn decode_subscription_delegation(data: &[u8]) -> Result<SubscriptionDelegationView, String> {
    if data.len() != SUBSCRIPTION_DELEGATION_LEN {
        return Err(format!(
            "Unexpected SubscriptionDelegation length: {} bytes (expected {SUBSCRIPTION_DELEGATION_LEN})",
            data.len()
        ));
    }
    if data[0] != 4 || data[1] != 1 {
        return Err(format!(
            "Invalid SubscriptionDelegation discriminator/version: {}/{}",
            data[0], data[1]
        ));
    }
    // header.discriminator(1) + version(1) + bump(1) = 3 bytes before delegator.
    let mut off = 3;
    let subscriber = Pubkey::try_from(&data[off..off + 32]).map_err(|e| e.to_string())?;
    off += 32;
    let plan_pda = Pubkey::try_from(&data[off..off + 32]).map_err(|e| e.to_string())?;
    off += 32;
    off += 32; // payer
    let authority_init_id = i64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    off += 8;
    let amount_per_period = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    off += 8;
    let period_hours = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    off += 8;
    off += 8; // terms.created_at — not used by the verifier
    let amount_pulled_in_period = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    off += 8;
    let current_period_start_ts = i64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    off += 8;
    let expires_at_ts = i64::from_le_bytes(data[off..off + 8].try_into().unwrap());

    Ok(SubscriptionDelegationView {
        subscriber,
        plan_pda,
        authority_init_id,
        amount_per_period,
        period_hours,
        current_period_start_ts,
        amount_pulled_in_period,
        expires_at_ts,
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
#[path = "subscription_activation_tests.rs"]
mod activation_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use solana_instruction::{AccountMeta, Instruction};
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
            amount_base_units: "10000000".to_string(),
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
        let bytes = crate::mpp::protocol::core::base64url_decode(&request_b64).unwrap();
        let parsed: SubscriptionRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.period_unit, SubscriptionPeriodUnit::Day);
        assert_eq!(parsed.period_count, "30");
        let md = parsed.method_details.as_ref().unwrap();
        assert_eq!(md.get("planAddress").unwrap().as_str().unwrap(), plan_id);
    }

    #[test]
    fn rejects_invalid_amount() {
        let server = SubscriptionServer::new(make_config()).unwrap();
        assert!(server.subscription_challenge("not-a-number").is_err());
        assert!(server.subscription_challenge("").is_err());
    }

    #[test]
    fn rejects_each_missing_required_field() {
        type Mutate = Box<dyn Fn(&mut SubscriptionConfig)>;
        let cases: Vec<(&str, Mutate)> = vec![
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

    /// Activation sponsorship must co-sign through `sign_transaction`, never
    /// `sign_message`. This signer implements `TransactionSigner` and fails on
    /// `sign_message`, standing in for a hardware wallet: a Ledger wraps a
    /// `sign_message` payload in an off-chain-message envelope and signs that,
    /// so the raw-signing form this path used to take produced a signature over
    /// the wrong bytes and the cluster rejected the activation at preflight.
    struct TransactionOnlySigner(solana_pubkey::Pubkey);

    #[async_trait::async_trait]
    impl solana_keychain::SolanaSigner for TransactionOnlySigner {
        fn pubkey(&self) -> solana_pubkey::Pubkey {
            self.0
        }
        async fn sign_message(
            &self,
            _message: &[u8],
        ) -> std::result::Result<Signature, solana_keychain::SignerError> {
            Err(solana_keychain::SignerError::Other(
                "a hardware signer cannot raw-sign a transaction message".into(),
            ))
        }
        async fn is_available(&self) -> bool {
            true
        }
    }

    #[async_trait::async_trait]
    impl solana_keychain::TransactionSigner for TransactionOnlySigner {
        async fn sign_transaction(
            &self,
            tx: &mut solana_transaction::versioned::VersionedTransaction,
        ) -> std::result::Result<solana_keychain::SignTransactionResult, solana_keychain::SignerError>
        {
            use solana_keychain::transaction_util::TransactionUtil;
            let signature = Signature::from([9u8; 64]);
            TransactionUtil::add_signature_to_transaction(tx, &self.0, signature)?;
            let signed = (TransactionUtil::serialize_transaction(tx)?, signature);
            Ok(TransactionUtil::classify_signed_transaction(tx, signed))
        }
    }

    #[tokio::test]
    async fn activation_cosign_never_calls_sign_message() {
        let fee_payer = solana_pubkey::Pubkey::new_unique();
        let signer: Arc<dyn solana_keychain::TransactionSigner> =
            Arc::new(TransactionOnlySigner(fee_payer));
        let subscriber = solana_pubkey::Pubkey::new_unique();
        let instruction = solana_system_interface::instruction::transfer(
            &subscriber,
            &solana_pubkey::Pubkey::new_unique(),
            1,
        );
        let mut tx = crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &fee_payer,
            &[instruction],
            solana_hash::Hash::new_unique(),
            None,
        )
        .unwrap();

        co_sign_as_fee_payer(&mut tx, &signer)
            .await
            .expect("co-signing must not reach sign_message");

        assert_eq!(tx.signatures[0], Signature::from([9u8; 64]));
        // The subscriber's own slot is left for the client.
        assert_eq!(tx.signatures[1], Signature::default());
    }

    #[tokio::test]
    async fn activation_cosign_rejects_a_sponsor_that_is_not_the_fee_payer() {
        let sponsor = solana_pubkey::Pubkey::new_unique();
        let signer: Arc<dyn solana_keychain::TransactionSigner> =
            Arc::new(TransactionOnlySigner(sponsor));
        let other_fee_payer = solana_pubkey::Pubkey::new_unique();
        let instruction = solana_system_interface::instruction::transfer(
            &sponsor,
            &solana_pubkey::Pubkey::new_unique(),
            1,
        );
        let mut tx = crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &other_fee_payer,
            &[instruction],
            solana_hash::Hash::new_unique(),
            None,
        )
        .unwrap();

        let err = co_sign_as_fee_payer(&mut tx, &signer).await.unwrap_err();
        assert!(
            err.message.contains("Fee payer pubkey not present"),
            "{}",
            err.message
        );
        assert!(tx.signatures.iter().all(|s| *s == Signature::default()));
    }

    #[test]
    fn activation_rejects_expired_subscription() {
        let err = validate_activation_subscription_expiry(
            Some("2000-01-01T00:00:00Z"),
            time::OffsetDateTime::now_utc(),
        )
        .expect_err("expired subscriptions must not activate");
        assert!(err
            .message
            .to_lowercase()
            .contains("subscription has expired"));
    }

    #[tokio::test]
    async fn activation_signature_reservation_allows_matching_retry() {
        let store = MemoryStore::new();
        let key = "solana-subscription:consumed:test-signature";
        let binding = serde_json::json!({ "challengeId": "challenge-a" });

        reserve_activation_signature(&store, key, binding.clone())
            .await
            .expect("first attempt reserves the signature");
        reserve_activation_signature(&store, key, binding)
            .await
            .expect("the same activation may retry after an ambiguous broadcast failure");

        let err = reserve_activation_signature(
            &store,
            key,
            serde_json::json!({ "challengeId": "challenge-b" }),
        )
        .await
        .expect_err("another challenge must not reuse the signature");
        assert!(err.message.to_lowercase().contains("consumed"));
    }

    const BINDING_KEY: &str = "solana-subscription:authentication:test-delegation";

    fn binding_for(
        activation: &VerifiedSignature,
        challenge: &str,
        landed_slot: Option<u64>,
    ) -> serde_json::Value {
        let mut binding = serde_json::json!({
            "activationSignature": activation.to_string(),
            "challengeId": challenge,
        });
        if let Some(slot) = landed_slot {
            binding["landedSlot"] = slot.into();
        }
        binding
    }

    /// Publish `activation` under `challenge`. `own` is its landing slot as
    /// the RPC reports it and `other` what the RPC reports for a legacy
    /// binding's activation; `None` for either means the RPC must not be asked.
    async fn publish(
        store: &MemoryStore,
        activation: &VerifiedSignature,
        challenge: &str,
        own: Option<u64>,
        other: Option<Option<u64>>,
    ) -> Result<serde_json::Value, VerificationError> {
        let challenge = challenge.to_string();
        publish_activation_binding(
            store,
            BINDING_KEY,
            activation,
            ActivationSlots {
                own: || async move { Ok(own.expect("own slot must not be looked up")) },
                other: |_: String| async move {
                    Ok(other.expect("the previous slot must not be looked up"))
                },
            },
            |slot| binding_for(activation, &challenge, Some(slot)),
        )
        .await
    }

    fn sig(byte: u8) -> VerifiedSignature {
        VerifiedSignature(Signature::from([byte; 64]))
    }

    /// A renewal B replaces A by the slot A's binding stored, with no RPC
    /// history for A; a later retry of A is refused by stored slots alone,
    /// whichever challenge it carries, and writes nothing.
    #[tokio::test]
    async fn a_renewal_replaces_by_stored_slots_and_a_retired_retry_is_refused() {
        let store = MemoryStore::new();
        let (a, b) = (sig(1), sig(2));
        publish(&store, &a, "challenge-a", Some(10), None)
            .await
            .unwrap();
        let b_binding = binding_for(&b, "challenge-b", Some(20));
        let bound = publish(&store, &b, "challenge-b", Some(20), None)
            .await
            .expect("a renewal rotates the binding");
        assert_eq!(bound, b_binding);
        assert_eq!(
            store.get(BINDING_KEY).await.unwrap(),
            Some(b_binding.clone())
        );

        for challenge in ["challenge-a", "fresh"] {
            let error = publish(&store, &a, challenge, None, None)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("already bound"), "{error}");
            assert_eq!(
                store.get(BINDING_KEY).await.unwrap(),
                Some(b_binding.clone())
            );
        }

        // A later attempt for B under another challenge keeps B's first binding.
        let bound = publish(&store, &b, "other", None, None).await.unwrap();
        assert_eq!(bound, b_binding);
    }

    /// A legacy binding records no slot. One the RPC no longer has predates
    /// its history and is replaced; one it knows landed later is kept.
    #[tokio::test]
    async fn a_legacy_binding_is_replaced_only_when_not_known_to_be_later() {
        let (a, b) = (sig(1), sig(2));
        let legacy = binding_for(&a, "challenge-a", None);

        let store = MemoryStore::new();
        store.put(BINDING_KEY, legacy.clone()).await.unwrap();
        let bound = publish(&store, &b, "challenge-b", Some(20), Some(None))
            .await
            .expect("a pruned legacy activation is older");
        assert_eq!(bound, binding_for(&b, "challenge-b", Some(20)));
        assert_eq!(store.get(BINDING_KEY).await.unwrap(), Some(bound));

        let store = MemoryStore::new();
        store.put(BINDING_KEY, legacy.clone()).await.unwrap();
        let error = publish(&store, &b, "challenge-b", Some(20), Some(Some(30)))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("already bound"), "{error}");
        assert_eq!(store.get(BINDING_KEY).await.unwrap(), Some(legacy));
    }

    /// B's renewal racing a retry of the retired A leaves B bound, whichever
    /// runs first. The retry never publishes anything but A's own record.
    #[tokio::test]
    async fn a_renewal_racing_a_retired_retry_leaves_the_renewal() {
        let (a, b) = (sig(1), sig(2));
        let b_binding = binding_for(&b, "challenge-b", Some(20));
        for retry_first in [false, true] {
            let store = MemoryStore::new();
            publish(&store, &a, "challenge-a", Some(10), None)
                .await
                .unwrap();
            let renewal = publish(&store, &b, "challenge-b", Some(20), None);
            let retry = publish(&store, &a, "fresh", None, None);
            let (renewal, retry) = if retry_first {
                let (retry, renewal) = tokio::join!(retry, renewal);
                (renewal, retry)
            } else {
                tokio::join!(renewal, retry)
            };
            assert_eq!(renewal.unwrap(), b_binding);
            assert!(retry.map_or(true, |bound| bound["activationSignature"] == a.to_string()));
            assert_eq!(
                store.get(BINDING_KEY).await.unwrap(),
                Some(b_binding.clone())
            );
        }
    }

    /// The activation record is keyed by a signature that verifies against
    /// the transaction's message; another subscriber's landed signature put in
    /// slot 0 is refused before anything is reserved under it.
    #[tokio::test]
    async fn an_activation_signature_must_verify_against_its_message() {
        use solana_keychain::SolanaSigner;
        let signer = stranger();
        let message = solana_message::VersionedMessage::Legacy(solana_message::Message::new(
            &[],
            Some(&signer.pubkey()),
        ));
        let signature = signer.sign_message(&message.serialize()).await.unwrap();
        let mut tx = VersionedTransaction {
            signatures: vec![signature],
            message,
        };
        assert_eq!(VerifiedSignature::of(&tx).unwrap().0, signature);
        tx.signatures[0] = Signature::from([9u8; 64]);
        let error = VerifiedSignature::of(&tx).unwrap_err();
        assert!(error.to_string().contains("does not verify"), "{error}");
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
    fn rejects_missing_or_invalid_configured_amount() {
        for amount in ["", "0", "-1", "1.5", "abc"] {
            let mut cfg = make_config();
            cfg.amount_base_units = amount.into();
            assert!(SubscriptionServer::new(cfg).is_err(), "amount={amount:?}");
        }
    }

    #[test]
    fn challenge_rejects_an_amount_other_than_the_configured_one() {
        let server = SubscriptionServer::new(make_config()).unwrap();
        assert!(server.subscription_challenge("10000000").is_ok());
        assert!(server.subscription_challenge("9999999").is_err());
        assert!(server.subscription_challenge("10000001").is_err());
    }

    // Two routes sharing realm, secret, mint, recipient, and Plan PDA: a
    // credential (activation or reusable proof) issued for the cheaper route
    // must not verify on the other one.
    #[tokio::test(flavor = "multi_thread")]
    async fn credential_for_a_cheaper_route_sharing_the_plan_is_rejected() {
        let mut cheap_cfg = make_config();
        cheap_cfg.rpc_url = Some("http://127.0.0.1:1".into());
        let cheap = SubscriptionServer::new(cheap_cfg.clone()).unwrap();
        let challenge = cheap.subscription_challenge("10000000").unwrap();

        let mut pricier_amount = cheap_cfg.clone();
        pricier_amount.amount_base_units = "100000000".into();
        let mut longer_period = cheap_cfg.clone();
        longer_period.period_count = 365;
        let mut both = cheap_cfg.clone();
        both.amount_base_units = "100000000".into();
        both.period_count = 365;

        for payload in [
            serde_json::json!({ "type": "proof" }),
            serde_json::json!({ "type": "transaction", "transaction": "AA==" }),
        ] {
            let credential = PaymentCredential::new(challenge.to_echo(), payload.clone());
            for cfg in [&pricier_amount, &longer_period, &both] {
                let other = SubscriptionServer::new(cfg.clone()).unwrap();
                let err = other.verify_credential(&credential).await.unwrap_err();
                assert!(
                    err.message.contains("terms do not match"),
                    "payload={payload} got: {}",
                    err.message
                );
            }
            // Positive control: the issuing route gets past the terms check.
            let err = cheap.verify_credential(&credential).await.unwrap_err();
            assert!(
                !err.message.contains("terms do not match"),
                "{}",
                err.message
            );
        }
    }

    #[test]
    fn week_period_round_trip_in_challenge() {
        let mut cfg = make_config();
        cfg.period_unit = SubscriptionPeriodUnit::Week;
        cfg.period_count = 2;
        cfg.amount_base_units = "5000000".into();
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
        data.push(4); // header.discriminator
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
        assert_eq!(view.authority_init_id, 77);
        assert_eq!(view.amount_per_period, 9_990_000);
        assert_eq!(view.period_hours, 720);
        assert_eq!(view.current_period_start_ts, 1_700_000_000);
        assert_eq!(view.amount_pulled_in_period, 9_990_000);
        assert_eq!(view.expires_at_ts, 0);
    }

    #[test]
    fn account_decoders_reject_wrong_discriminators() {
        let mut delegation = vec![0u8; SUBSCRIPTION_DELEGATION_LEN];
        delegation[0] = 2;
        delegation[1] = 1;
        assert!(decode_subscription_delegation(&delegation).is_err());

        let mut authority = vec![0u8; SUBSCRIPTION_AUTHORITY_LEN];
        authority[0] = 1;
        assert!(decode_subscription_authority_init_id(&authority).is_err());
    }

    #[test]
    fn decode_subscription_delegation_rejects_short_data() {
        let short = vec![0u8; 50];
        assert!(decode_subscription_delegation(&short).is_err());
    }

    #[test]
    fn activation_scope_rejects_extra_instruction_to_another_program() {
        let subscriber = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let subscribe = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(subscriber, true)],
            data: vec![INSTRUCTION_SUBSCRIBE],
        };
        let foreign = Instruction {
            program_id: Pubkey::from_str_const(SYSTEM_PROGRAM_ID),
            accounts: vec![AccountMeta::new(subscriber, true)],
            data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        };
        let transfer = Instruction {
            program_id,
            accounts: vec![AccountMeta::new_readonly(subscriber, false)],
            data: vec![INSTRUCTION_TRANSFER_SUBSCRIPTION],
        };
        let tx = crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &subscriber,
            &[foreign, subscribe, transfer],
            solana_hash::Hash::default(),
            None,
        )
        .unwrap();
        let config = make_config();
        let err = validate_activation_scope(
            &tx,
            &SubscriptionRequest::default(),
            &program_id.to_string(),
            subscriber,
            &config,
        )
        .unwrap_err();
        assert!(err.message.contains("Unsupported program"));
    }

    #[test]
    fn activation_scope_rejects_transfer_to_wrong_recipient_ata() {
        use crate::mpp::program::subscriptions::{
            build_subscribe_ix, build_transfer_subscription_ix, SubscribeAccounts, SubscribeData,
            TransferData, TransferSubscriptionAccounts,
        };

        let subscriber = Pubkey::new_unique();
        let merchant = Pubkey::new_unique();
        let puller = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let attacker = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_program =
            Pubkey::from_str_const(crate::mpp::protocol::solana::programs::TOKEN_PROGRAM);
        let program_id = Pubkey::new_unique();
        let plan_pda = Pubkey::new_unique();
        let subscription_pda = find_subscription_pda(&plan_pda, &subscriber, &program_id).0;
        let authority = find_subscription_authority_pda(&subscriber, &mint, &program_id).0;
        let event_authority = find_event_authority_pda(&program_id).0;
        let associated_token_program = Pubkey::from_str_const(ASSOCIATED_TOKEN_PROGRAM_ID);
        let ata = |owner: &Pubkey| {
            Pubkey::find_program_address(
                &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
                &associated_token_program,
            )
            .0
        };
        let amount = 10_000_000;
        let subscribe = build_subscribe_ix(
            program_id,
            SubscribeAccounts {
                subscriber,
                merchant,
                plan_pda,
                subscription_pda,
                subscription_authority_pda: authority,
                event_authority,
                payer: None,
            },
            &SubscribeData {
                plan_id: 1,
                plan_bump: 1,
                expected_mint: mint,
                expected_amount: amount,
                expected_period_hours: 720,
                expected_created_at: 1,
                expected_subscription_authority_init_id: 1,
            },
        );
        let transfer = build_transfer_subscription_ix(
            program_id,
            TransferSubscriptionAccounts {
                subscription_pda,
                plan_pda,
                subscription_authority: authority,
                delegator_ata: ata(&subscriber),
                receiver_ata: ata(&attacker),
                caller: puller,
                token_mint: mint,
                token_program,
                event_authority,
            },
            &TransferData {
                amount,
                delegator: subscriber,
                mint,
            },
        );
        let tx = crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &subscriber,
            &[subscribe, transfer],
            solana_hash::Hash::default(),
            None,
        )
        .unwrap();
        let config = SubscriptionConfig {
            plan_id: plan_pda.to_string(),
            mint: mint.to_string(),
            token_program: token_program.to_string(),
            puller: puller.to_string(),
            recipient: recipient.to_string(),
            challenge_binding_secret: "test-secret".into(),
            realm: "test-realm".into(),
            amount_base_units: amount.to_string(),
            ..Default::default()
        };
        let request = SubscriptionRequest {
            amount: amount.to_string(),
            recipient: recipient.to_string(),
            ..Default::default()
        };

        let err =
            validate_activation_scope(&tx, &request, &program_id.to_string(), subscriber, &config)
                .unwrap_err();
        assert!(err.message.contains("accounts do not match"));
    }

    #[test]
    fn sponsored_subscriber_must_be_a_required_signer() {
        let fee_payer = Pubkey::new_unique();
        let non_signer = Pubkey::new_unique();
        let instruction = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new_readonly(non_signer, false)],
            data: vec![INSTRUCTION_SUBSCRIBE],
        };
        let tx = crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &fee_payer,
            &[instruction],
            solana_hash::Hash::default(),
            None,
        )
        .unwrap();
        let mut config = make_config();
        config.fee_payer = true;
        config.fee_payer_pubkey = Some(fee_payer.to_string());

        let err =
            extract_subscriber_from_tx(&tx, &SubscriptionRequest::default(), &config).unwrap_err();
        assert!(err.message.contains("Could not identify subscriber"));
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
        let credential = crate::mpp::protocol::core::PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".to_string(),
                transaction: Some("AQAAAA==".to_string()),
                signature: None,
                authentication: None,
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
                authentication: None,
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
                authentication: None,
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
                authentication: None,
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

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_rejects_each_pinned_or_payload_mismatch() {
        fn rebound(
            request: SubscriptionRequest,
            realm: &str,
            method: &str,
            intent: &str,
            expires: Option<&str>,
        ) -> PaymentChallenge {
            PaymentChallenge::with_challenge_binding_secret_full(
                "test-secret",
                realm,
                method,
                intent,
                Base64UrlJson::from_typed(&request).unwrap(),
                expires,
                None,
                None,
                None,
            )
        }

        let server = SubscriptionServer::new(make_config()).unwrap();
        let issued = server.subscription_challenge("10000000").unwrap();
        let request: SubscriptionRequest = issued.request.decode().unwrap();
        let payload = serde_json::json!({"type": "transaction"});
        let cases = [
            rebound(request.clone(), "test-realm", "other", "subscription", None),
            rebound(request.clone(), "test-realm", "solana", "charge", None),
            rebound(
                request.clone(),
                "other-realm",
                "solana",
                "subscription",
                None,
            ),
            {
                let mut value = request.clone();
                value.currency = Pubkey::new_unique().to_string();
                rebound(value, "test-realm", "solana", "subscription", None)
            },
            {
                let mut value = request.clone();
                value.recipient = Pubkey::new_unique().to_string();
                rebound(value, "test-realm", "solana", "subscription", None)
            },
            {
                let mut value = request.clone();
                value.method_details = None;
                rebound(value, "test-realm", "solana", "subscription", None)
            },
            rebound(
                request.clone(),
                "test-realm",
                "solana",
                "subscription",
                Some("1970-01-01T00:00:00Z"),
            ),
        ];
        for challenge in cases {
            let credential = PaymentCredential::new(challenge.to_echo(), payload.clone());
            assert!(server.verify_credential(&credential).await.is_err());
        }

        let malformed_proof =
            PaymentCredential::new(issued.to_echo(), serde_json::json!({"type": "proof"}));
        assert!(server.verify_credential(&malformed_proof).await.is_err());
        let missing_tx = PaymentCredential::new(issued.to_echo(), payload);
        assert!(server.verify_credential(&missing_tx).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn activation_builder_output_passes_complete_scope_validation() {
        use crate::mpp::client::{
            build_subscription_activation_transaction_with_options,
            BuildSubscriptionActivationOptions,
        };
        use crate::mpp::protocol::solana::CredentialPayload;
        use solana_keychain::MemorySigner;
        use solana_keychain::SolanaSigner;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(signing_key.as_bytes());
        keypair[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        let signer = MemorySigner::from_bytes(&keypair).unwrap();
        let config = make_config();
        let details = SubscriptionMethodDetails {
            plan_address: config.plan_id.clone(),
            mint: config.mint.clone(),
            token_program: config.token_program.clone(),
            puller: config.puller.clone(),
            merchant: Some(config.puller.clone()),
            recipient: Some(config.recipient.clone()),
            amount: Some("10000000".into()),
            subscription_program: Some(SUBSCRIPTIONS_PROGRAM_ID.into()),
            recent_blockhash: Some("11111111111111111111111111111111".into()),
            plan_id_numeric: Some(1),
            plan_bump: Some(255),
            expected_period_hours: Some(720),
            expected_created_at: Some(1_700_000_000),
            ..Default::default()
        };
        let payload = build_subscription_activation_transaction_with_options(
            &signer,
            &solana_rpc_client::rpc_client::RpcClient::new_mock("succeeds"),
            &details,
            BuildSubscriptionActivationOptions {
                subscription_authority_init_id: Some(77),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let CredentialPayload::Transaction { transaction } = payload else {
            panic!("expected transaction")
        };
        let tx = decode_base64_transaction(&transaction).unwrap();
        let request = SubscriptionRequest {
            amount: "10000000".into(),
            recipient: config.recipient.clone(),
            ..Default::default()
        };
        validate_activation_scope(
            &tx,
            &request,
            SUBSCRIPTIONS_PROGRAM_ID,
            signer.pubkey(),
            &config,
        )
        .unwrap();
    }

    struct ActivationFixture {
        server: SubscriptionServer,
        signer: solana_keychain::MemorySigner,
        transaction: String,
        delegation: Pubkey,
        rpc_task: tokio::task::JoinHandle<()>,
    }

    impl ActivationFixture {
        async fn activation(
            &self,
            challenge: &crate::mpp::protocol::core::PaymentChallenge,
            signer: &solana_keychain::MemorySigner,
        ) -> (
            PaymentCredential,
            crate::mpp::protocol::intents::subscription::SubscriptionAuthentication,
        ) {
            let authentication = crate::mpp::client::sign_subscription_authentication(
                signer,
                &challenge.id,
                &self.delegation.to_string(),
            )
            .await
            .unwrap();
            let credential = PaymentCredential::new(
                challenge.to_echo(),
                ActivatePayload {
                    payload_type: "transaction".into(),
                    transaction: Some(self.transaction.clone()),
                    signature: None,
                    authentication: Some(authentication.clone()),
                },
            );
            (credential, authentication)
        }

        fn access(
            &self,
            challenge: &crate::mpp::protocol::core::PaymentChallenge,
            authentication: crate::mpp::protocol::intents::subscription::SubscriptionAuthentication,
        ) -> PaymentCredential {
            crate::mpp::client::build_subscription_access_credential(
                challenge,
                self.delegation.to_string(),
                authentication,
            )
        }
    }

    /// A subscription whose on-chain activation has landed: every RPC read
    /// reports it confirmed. `delegation_subscriber` overrides who the
    /// on-chain delegation says it belongs to.
    async fn activation_fixture(delegation_subscriber: Option<Pubkey>) -> ActivationFixture {
        use crate::mpp::client::{
            build_subscription_activation_transaction_with_options,
            BuildSubscriptionActivationOptions,
        };
        use crate::mpp::protocol::solana::CredentialPayload;
        use axum::{routing::post, Json, Router};
        use base64::Engine;
        use solana_keychain::{MemorySigner, SolanaSigner};

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[29u8; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(signing_key.as_bytes());
        keypair[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        let signer = MemorySigner::from_bytes(&keypair).unwrap();
        let subscriber = signer.pubkey();
        let program_id = Pubkey::from_str_const(SUBSCRIPTIONS_PROGRAM_ID);
        let plan = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let puller = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let delegation = find_subscription_pda(&plan, &subscriber, &program_id).0;
        let authority = find_subscription_authority_pda(&subscriber, &mint, &program_id).0;
        let period_start = now_unix_secs() - 60;

        let mut delegation_data = vec![4, 1, 255];
        delegation_data.extend_from_slice(delegation_subscriber.unwrap_or(subscriber).as_ref());
        delegation_data.extend_from_slice(plan.as_ref());
        delegation_data.extend_from_slice(Pubkey::new_unique().as_ref());
        delegation_data.extend_from_slice(&77i64.to_le_bytes());
        delegation_data.extend_from_slice(&10_000_000u64.to_le_bytes());
        delegation_data.extend_from_slice(&720u64.to_le_bytes());
        delegation_data.extend_from_slice(&1_700_000_000i64.to_le_bytes());
        delegation_data.extend_from_slice(&10_000_000u64.to_le_bytes());
        delegation_data.extend_from_slice(&period_start.to_le_bytes());
        delegation_data.extend_from_slice(&0i64.to_le_bytes());
        let mut authority_data = vec![0u8; SUBSCRIPTION_AUTHORITY_LEN];
        authority_data[SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET..]
            .copy_from_slice(&77i64.to_le_bytes());

        let owner = program_id.to_string();
        let delegation_b64 = base64::engine::general_purpose::STANDARD.encode(delegation_data);
        let authority_b64 = base64::engine::general_purpose::STANDARD.encode(authority_data);
        let authority_string = authority.to_string();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<serde_json::Value>| {
                let owner = owner.clone();
                let delegation_b64 = delegation_b64.clone();
                let authority_b64 = authority_b64.clone();
                let authority_string = authority_string.clone();
                async move {
                    let result = match request["method"].as_str().unwrap() {
                        "getLatestBlockhash" => serde_json::json!({
                            "context": {"slot": 1},
                            "value": {"blockhash": "11111111111111111111111111111111", "lastValidBlockHeight": 100}
                        }),
                        "getAccountInfo" => {
                            let address = request["params"][0].as_str().unwrap();
                            let data = if address == authority_string { &authority_b64 } else { &delegation_b64 };
                            serde_json::json!({"context": {"slot": 1}, "value": {
                                "data": [data, "base64"], "executable": false, "lamports": 1,
                                "owner": owner, "rentEpoch": 0, "space": 155
                            }})
                        }
                        "getSignatureStatuses" => serde_json::json!({"context": {"slot": 1}, "value": [{
                            "slot": 1, "confirmations": null, "err": null,
                            "status": {"Ok": null}, "confirmationStatus": "confirmed"
                        }]}),
                        method => panic!("unexpected RPC method {method}"),
                    };
                    Json(serde_json::json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let rpc_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let config = SubscriptionConfig {
            plan_id: plan.to_string(),
            mint: mint.to_string(),
            token_program: crate::mpp::protocol::solana::programs::TOKEN_PROGRAM.into(),
            puller: puller.to_string(),
            recipient: recipient.to_string(),
            rpc_url: Some(rpc_url),
            challenge_binding_secret: "test-secret".into(),
            realm: "test-realm".into(),
            plan_id_numeric: Some(1),
            plan_bump: Some(255),
            plan_created_at: Some(1_700_000_000),
            amount_base_units: "10000000".into(),
            ..Default::default()
        };
        let server = SubscriptionServer::new(config).unwrap();
        let challenge = server.subscription_challenge("10000000").unwrap();
        let request: SubscriptionRequest = challenge.request.decode().unwrap();
        let details =
            SubscriptionMethodDetails::from_json(request.method_details.as_ref().unwrap()).unwrap();
        let transaction = build_subscription_activation_transaction_with_options(
            &signer,
            &solana_rpc_client::rpc_client::RpcClient::new_mock("succeeds"),
            &details,
            BuildSubscriptionActivationOptions {
                subscription_authority_init_id: Some(77),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let CredentialPayload::Transaction { transaction } = transaction else {
            panic!("transaction")
        };
        ActivationFixture {
            server,
            signer,
            transaction,
            delegation,
            rpc_task,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn confirmed_activation_binds_and_reuses_subscription_proof() {
        let fixture = activation_fixture(None).await;
        let challenge = fixture.server.subscription_challenge("10000000").unwrap();
        let (activation, authentication) = fixture.activation(&challenge, &fixture.signer).await;
        assert!(matches!(
            fixture.server.verify_credential(&activation).await.unwrap(),
            ReceiptKind::Subscription { .. }
        ));
        assert!(matches!(
            fixture
                .server
                .verify_credential(&fixture.access(&challenge, authentication))
                .await
                .unwrap(),
            ReceiptKind::Subscription { .. }
        ));
        fixture.rpc_task.abort();
    }

    fn activation_signature(credential: &PaymentCredential) -> String {
        let ActivatePayload {
            transaction: Some(transaction),
            ..
        } = decode_activate_payload(credential).unwrap()
        else {
            panic!("transaction payload");
        };
        decode_base64_transaction(&transaction).unwrap().signatures[0].to_string()
    }

    fn stranger() -> solana_keychain::MemorySigner {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(key.as_bytes());
        keypair[32..].copy_from_slice(key.verifying_key().as_bytes());
        solana_keychain::MemorySigner::from_bytes(&keypair).unwrap()
    }

    /// A confirmed activation, then a crash before anything bound it: the
    /// signature is reserved under the first challenge and no binding exists.
    async fn landed_unbound(
        fixture: &ActivationFixture,
    ) -> (
        crate::mpp::protocol::core::PaymentChallenge,
        crate::mpp::protocol::intents::subscription::SubscriptionAuthentication,
        String,
    ) {
        let first = fixture.server.subscription_challenge("10000000").unwrap();
        let (activation, auth) = fixture.activation(&first, &fixture.signer).await;
        fixture.server.verify_credential(&activation).await.unwrap();
        let signature = activation_signature(&activation);
        let store = fixture.server.store.as_ref();
        store
            .delete(&subscription_binding_key(&fixture.delegation))
            .await
            .unwrap();
        store
            .delete(&format!(
                "solana-subscription:activation-binding:{signature}"
            ))
            .await
            .unwrap();
        (first, auth, signature)
    }

    async fn bound_challenge(fixture: &ActivationFixture) -> Option<String> {
        fixture
            .server
            .store
            .get(&subscription_binding_key(&fixture.delegation))
            .await
            .unwrap()
            .and_then(|binding| binding["challengeId"].as_str().map(str::to_string))
    }

    /// Concurrent recoveries under two fresh challenges bind exactly once:
    /// the first writer's proof works, the other is told to present it.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_recoveries_produce_exactly_one_binding() {
        let fixture = activation_fixture(None).await;
        let (first, first_auth, _) = landed_unbound(&fixture).await;
        let y = fixture.server.subscription_challenge("10000000").unwrap();
        let z = fixture.server.subscription_challenge("10000000").unwrap();
        let (recover_y, y_auth) = fixture.activation(&y, &fixture.signer).await;
        let (recover_z, z_auth) = fixture.activation(&z, &fixture.signer).await;
        let (left, right) = tokio::join!(
            fixture.server.verify_credential(&recover_y),
            fixture.server.verify_credential(&recover_z),
        );
        assert_eq!(
            [left.is_ok(), right.is_ok()]
                .iter()
                .filter(|ok| **ok)
                .count(),
            1
        );
        let loser = left.err().or(right.err()).unwrap();
        assert!(loser.to_string().contains("already bound"), "{loser}");
        let (winner, winner_auth, other, other_auth) =
            if bound_challenge(&fixture).await == Some(y.id.clone()) {
                (&y, y_auth, &z, z_auth)
            } else {
                (&z, z_auth, &y, y_auth)
            };
        fixture
            .server
            .verify_credential(&fixture.access(winner, winner_auth))
            .await
            .unwrap();
        assert!(fixture
            .server
            .verify_credential(&fixture.access(other, other_auth))
            .await
            .is_err());
        assert!(fixture
            .server
            .verify_credential(&fixture.access(&first, first_auth))
            .await
            .is_err());
        fixture.rpc_task.abort();
    }

    /// A recovery cancelled before its write holds nothing, so a fresh
    /// challenge recovers; there is no lease to wait out.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_recovery_cancelled_before_its_write_is_retried() {
        let fixture = activation_fixture(None).await;
        let (_, _, _) = landed_unbound(&fixture).await;
        // A recovery request that never reached the binding write.
        let cancelled = fixture.server.subscription_challenge("10000000").unwrap();
        let (_, _) = fixture.activation(&cancelled, &fixture.signer).await;
        assert_eq!(bound_challenge(&fixture).await, None);

        let fresh = fixture.server.subscription_challenge("10000000").unwrap();
        let (recovery, fresh_auth) = fixture.activation(&fresh, &fixture.signer).await;
        assert!(matches!(
            fixture.server.verify_credential(&recovery).await.unwrap(),
            ReceiptKind::Subscription { .. }
        ));
        fixture
            .server
            .verify_credential(&fixture.access(&fresh, fresh_auth))
            .await
            .unwrap();
        fixture.rpc_task.abort();
    }

    /// A recovery cancelled after its write leaves its proof working. If it
    /// stopped between the activation record and the published binding, the
    /// next attempt republishes that record rather than binding anew.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_recovery_cancelled_after_its_write_keeps_the_proof_path() {
        let fixture = activation_fixture(None).await;
        let (_, _, _) = landed_unbound(&fixture).await;
        let x = fixture.server.subscription_challenge("10000000").unwrap();
        let (recovery, x_auth) = fixture.activation(&x, &fixture.signer).await;
        fixture.server.verify_credential(&recovery).await.unwrap();
        // Its response was lost after the write: the proof works regardless.
        fixture
            .server
            .verify_credential(&fixture.access(&x, x_auth.clone()))
            .await
            .unwrap();

        // Stopped halfway: the record exists, the published binding does not.
        let binding_key = subscription_binding_key(&fixture.delegation);
        fixture.server.store.delete(&binding_key).await.unwrap();
        let fresh = fixture.server.subscription_challenge("10000000").unwrap();
        let (retry, _) = fixture.activation(&fresh, &fixture.signer).await;
        let error = fixture.server.verify_credential(&retry).await.unwrap_err();
        assert!(error.to_string().contains("already bound"), "{error}");
        assert_eq!(bound_challenge(&fixture).await, Some(x.id.clone()));
        fixture
            .server
            .verify_credential(&fixture.access(&x, x_auth))
            .await
            .unwrap();
        fixture.rpc_task.abort();
    }

    /// Failed recoveries consume nothing: any number of them leaves the
    /// activation recoverable.
    #[tokio::test(flavor = "multi_thread")]
    async fn activation_recovery_has_no_retry_limit() {
        let fixture = activation_fixture(None).await;
        landed_unbound(&fixture).await;
        let stranger = stranger();
        for _ in 0..40 {
            let challenge = fixture.server.subscription_challenge("10000000").unwrap();
            let (forged, _) = fixture.activation(&challenge, &stranger).await;
            assert!(fixture.server.verify_credential(&forged).await.is_err());
        }
        assert_eq!(bound_challenge(&fixture).await, None);
        let fresh = fixture.server.subscription_challenge("10000000").unwrap();
        let (recovery, _) = fixture.activation(&fresh, &fixture.signer).await;
        fixture.server.verify_credential(&recovery).await.unwrap();
        assert_eq!(bound_challenge(&fixture).await, Some(fresh.id.clone()));
        fixture.rpc_task.abort();
    }

    /// An unsponsored activation whose slot-0 signature is someone else's
    /// (landed) one is refused before it reserves or binds anything under it.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_activation_carrying_a_foreign_signature_claims_nothing() {
        let fixture = activation_fixture(None).await;
        let challenge = fixture.server.subscription_challenge("10000000").unwrap();
        let mut tx = decode_base64_transaction(&fixture.transaction).unwrap();
        let foreign = Signature::from([7u8; 64]);
        tx.signatures[0] = foreign;
        let authentication = crate::mpp::client::sign_subscription_authentication(
            &fixture.signer,
            &challenge.id,
            &fixture.delegation.to_string(),
        )
        .await
        .unwrap();
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(crate::core::tx::encode(&tx).unwrap()),
                signature: None,
                authentication: Some(authentication),
            },
        );
        let error = fixture
            .server
            .verify_credential(&credential)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not verify"), "{error}");
        let store = fixture.server.store.as_ref();
        for key in [
            format!("solana-subscription:consumed:{foreign}"),
            format!("solana-subscription:activation-binding:{foreign}"),
        ] {
            assert!(store.get(&key).await.unwrap().is_none(), "{key}");
        }
        assert_eq!(bound_challenge(&fixture).await, None);
        fixture.rpc_task.abort();
    }

    /// Recovery re-derives the binding from the on-chain delegation and fails
    /// closed when it belongs to someone else, binding nothing, every time.
    #[tokio::test(flavor = "multi_thread")]
    async fn activation_recovery_refuses_a_delegation_for_another_payer() {
        let fixture = activation_fixture(Some(Pubkey::new_unique())).await;
        let first = fixture.server.subscription_challenge("10000000").unwrap();
        // The first attempt reserved the signature, then failed before binding.
        let (activation, _) = fixture.activation(&first, &fixture.signer).await;
        assert!(fixture.server.verify_credential(&activation).await.is_err());
        let signature = activation_signature(&activation);
        for _ in 0..2 {
            let fresh = fixture.server.subscription_challenge("10000000").unwrap();
            let (recovery, _) = fixture.activation(&fresh, &fixture.signer).await;
            let error = fixture
                .server
                .verify_credential(&recovery)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("subscriber"), "{error}");
        }
        assert_eq!(bound_challenge(&fixture).await, None);
        assert!(fixture
            .server
            .store
            .get(&format!(
                "solana-subscription:activation-binding:{signature}"
            ))
            .await
            .unwrap()
            .is_none());
        fixture.rpc_task.abort();
    }
}
