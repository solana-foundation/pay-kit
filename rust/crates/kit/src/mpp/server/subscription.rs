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
    find_event_authority_pda, find_subscription_authority_pda, find_subscription_pda, parse_pubkey,
    ASSOCIATED_TOKEN_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID, INSTRUCTION_SUBSCRIBE,
    INSTRUCTION_TRANSFER_SUBSCRIPTION, MEMO_PROGRAM_ID, SUBSCRIPTIONS_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
};
use crate::mpp::protocol::core::{
    compute_challenge_id, Base64UrlJson, PaymentChallenge, PaymentCredential, Receipt, ReceiptKind,
};
use crate::mpp::protocol::intents::SubscriptionMethodDetails;
use crate::mpp::protocol::intents::{
    ActivatePayload, SubscriptionAction, SubscriptionPeriodUnit, SubscriptionReceiptExtensions,
    SubscriptionRequest,
};
use crate::mpp::protocol::solana::{default_rpc_url, programs};
use crate::mpp::server::charge::VerificationError;
use crate::mpp::store::Store;

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
    merchant: String,
    program_id: String,
    challenge_binding_secret: String,
    realm: String,
    store: Arc<dyn Store>,
    rpc_url: String,
}

impl SubscriptionServer {
    /// Create a new server handler from config. Validates pubkeys and
    /// period bounds eagerly; misconfigured servers fail at boot, not on
    /// the first challenge.
    pub fn new(config: SubscriptionConfig) -> Result<Self, Error> {
        let merchant = config.puller.clone();
        Self::new_with_merchant(config, merchant)
    }

    /// Create a server whose Plan owner differs from its delegated puller.
    ///
    /// This constructor preserves [`SubscriptionConfig`]'s source-compatible
    /// shape while allowing the challenge and verifier to bind the canonical
    /// `subscribe` merchant account independently from the puller.
    pub fn new_with_merchant(
        config: SubscriptionConfig,
        merchant: impl Into<String>,
    ) -> Result<Self, Error> {
        let merchant = merchant.into();
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
        if config.store.is_none() {
            return Err(Error::InvalidConfig(
                "subscription replay store with atomic put_if_absent is required".into(),
            ));
        }
        if config.fee_payer
            && (config.plan_id_numeric.is_none()
                || config.plan_bump.is_none()
                || config.plan_created_at.is_none())
        {
            return Err(Error::InvalidConfig(
                "fee-sponsored subscription requires plan_id_numeric, plan_bump, and plan_created_at snapshots".into(),
            ));
        }

        // Validate all pubkeys parse.
        parse_pubkey(&config.plan_id, "plan_id")?;
        parse_pubkey(&config.mint, "mint")?;
        parse_pubkey(&config.token_program, "token_program")?;
        parse_pubkey(&config.puller, "puller")?;
        parse_pubkey(&merchant, "merchant")?;
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

        let store = config.store.clone().expect("validated above");

        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&config.network).to_string());

        Ok(SubscriptionServer {
            config,
            merchant,
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
            merchant: Some(self.merchant.clone()),
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
        if !crate::mpp::protocol::core::challenge::constant_time_eq(
            &credential.challenge.id,
            &expected_id,
        ) {
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
        //
        // The `"transaction"` arm claims the replay marker atomically before
        // broadcasting, then owns a reservation that MUST be released on every
        // failure path (inside this arm and in the tail below) until a receipt
        // is produced. The arm hands the claimed key back so the tail can
        // release it on error; the other arms early-return and never claim. The
        // happy path is disarmed explicitly at the end so a real replay stays
        // rejected.
        let (subscriber, activation_signature, claimed_key) = match payload_type {
            "transaction" => {
                let tx_b64 = activate.transaction.as_deref().ok_or_else(|| {
                    VerificationError::invalid_payload(
                        "type=\"transaction\" payload missing `transaction` field",
                    )
                })?;
                let mut tx = decode_base64_transaction(tx_b64)?;
                let subscriber = extract_subscriber_from_tx(&tx, &request, &self.config)?;
                let activation_scope = validate_activation_scope_with_merchant(
                    &tx,
                    &request,
                    &self.program_id,
                    &self.config,
                    &self.merchant,
                    &subscriber,
                )?;

                if let Some(expected_init_id) = activation_scope.expected_init_id {
                    let live_init_id = self
                        .fetch_subscription_authority_init_id(&activation_scope.authority)
                        .await?;
                    if live_init_id != expected_init_id {
                        return Err(VerificationError::credential_mismatch(
                            "Subscribe authority init_id does not match the live authority account",
                        ));
                    }
                }

                if fee_payer_configured {
                    co_sign_as_fee_payer(&mut tx, self.config.fee_payer_signer.as_ref().unwrap())
                        .await?;
                }

                // Replay guard. The activation signature is the transaction's
                // own first signature — the fee payer's (index 0) once the
                // server co-signs, or the subscriber's otherwise — and it is
                // exactly what `sendTransaction` echoes back. The key mirrors
                // the TypeScript port (`solana-subscription:consumed:<sig>`) so
                // a shared store rejects the replay across language runtimes.
                let activation_sig =
                    tx.signatures
                        .first()
                        .map(|s| s.to_string())
                        .ok_or_else(|| {
                            VerificationError::invalid_payload(
                                "Activation transaction has no signature",
                            )
                        })?;
                let consumed_key = format!("solana-subscription:consumed:{activation_sig}");

                // Atomically claim the marker up front, before any RPC
                // broadcast or receipt re-issuance. `put_if_absent` returns
                // `false` when the key already exists, which means a prior (or
                // concurrent) activation already owns this signature — reject
                // the replay. A non-atomic get-then-put would let two
                // concurrent identical activations both pass the check and both
                // issue a server-signed receipt. On a winning claim the caller
                // now owns the reservation and MUST release it on every failure
                // path until a receipt is produced (below); broadcast itself is
                // idempotent on-chain, so the marker's sole job is to prevent
                // re-issuing a receipt for an already-settled activation.
                let claimed = self
                    .store
                    .put_if_absent(&consumed_key, serde_json::json!(true))
                    .await
                    .map_err(|e| VerificationError::network_error(e.to_string()))?;
                if !claimed {
                    return Err(VerificationError::signature_consumed(
                        "Activation signature already consumed",
                    ));
                }
                // We own the reservation now; from here every failure path
                // must release `consumed_key` via `release_on_err`.
                let claimed_key = consumed_key;

                // Idempotent broadcast: if the delegation PDA already exists
                // (a previous activation landed on-chain but the receipt
                // round-trip failed), skip the broadcast — the on-chain
                // `Subscribe` instruction would reject with
                // `AlreadySubscribed` (0x205) and abort the whole tx,
                // burying the actual outcome. The subsequent fetch +
                // terms-check on lines below catches any divergence.
                //
                // Any error between the claim above and the receipt release
                // (parse, PDA fetch, broadcast) must release the marker so a
                // transient RPC failure does not permanently brick this
                // activation signature — `release_on_err` wraps each fallible
                // step to guarantee that.
                let program_id = release_on_err(
                    &*self.store,
                    &claimed_key,
                    parse_pubkey(&self.program_id, "program_id")
                        .map_err(|e| VerificationError::new(e.to_string())),
                )
                .await?;
                let plan_pda = release_on_err(
                    &*self.store,
                    &claimed_key,
                    parse_pubkey(&self.config.plan_id, "plan_id")
                        .map_err(|e| VerificationError::new(e.to_string())),
                )
                .await?;
                let (delegation_pda, _) =
                    find_subscription_pda(&plan_pda, &subscriber, &program_id);
                let delegation_already_exists = self
                    .fetch_subscription_delegation(&delegation_pda)
                    .await
                    .is_ok();

                let sig = if delegation_already_exists {
                    let confirmed = release_on_err(
                        &*self.store,
                        &claimed_key,
                        self.is_signature_confirmed(&activation_sig).await,
                    )
                    .await?;
                    if !confirmed {
                        let err = VerificationError::invalid_payload(
                            "Subscription already exists, but the exact submitted activation signature is not confirmed",
                        );
                        let _ = self.store.delete(&claimed_key).await;
                        return Err(err);
                    }
                    Some(activation_sig)
                } else {
                    Some(
                        release_on_err(
                            &*self.store,
                            &claimed_key,
                            self.broadcast_and_confirm(&tx).await,
                        )
                        .await?
                        .to_string(),
                    )
                };

                (subscriber, sig, claimed_key)
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
        // Still inside the reservation window: any error here (PDA parse,
        // on-chain fetch, terms mismatch) must release the marker so a
        // legitimate client can retry, so every fallible step below is wrapped.
        let program_id = release_on_err(
            &*self.store,
            &claimed_key,
            parse_pubkey(&self.program_id, "program_id")
                .map_err(|e| VerificationError::new(e.to_string())),
        )
        .await?;
        let plan_pda = release_on_err(
            &*self.store,
            &claimed_key,
            parse_pubkey(&self.config.plan_id, "plan_id")
                .map_err(|e| VerificationError::new(e.to_string())),
        )
        .await?;
        let (subscription_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);

        let delegation = release_on_err(
            &*self.store,
            &claimed_key,
            self.fetch_subscription_delegation(&subscription_pda).await,
        )
        .await?;

        // ── Validate snapshotted terms + build the receipt ───────────────
        let receipt = release_on_err(
            &*self.store,
            &claimed_key,
            validate_terms_and_build_receipt(
                &delegation,
                &request,
                &plan_pda,
                &subscription_pda,
                &self.config.plan_id,
                &credential.challenge.id,
                activation_signature,
            ),
        )
        .await?;

        // Happy path: a receipt was produced, so the claim is permanent. Do NOT
        // release — a genuine replay of this activation signature must stay
        // rejected.
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

    async fn is_signature_confirmed(&self, signature: &str) -> Result<bool, VerificationError> {
        use solana_rpc_client::rpc_client::RpcClient;
        let rpc_url = self.rpc_url.clone();
        let signature = signature.parse::<Signature>().map_err(|e| {
            VerificationError::invalid_payload(format!("Invalid activation signature: {e}"))
        })?;
        tokio::task::spawn_blocking(move || {
            let rpc = RpcClient::new(rpc_url);
            rpc.get_signature_status(&signature)
                .map_err(|e| {
                    VerificationError::network_error(format!(
                        "getSignatureStatuses({signature}) failed: {e}"
                    ))
                })
                .map(|status| matches!(status, Some(Ok(()))))
        })
        .await
        .map_err(|e| VerificationError::network_error(format!("RPC task join: {e}")))?
    }

    async fn fetch_subscription_authority_init_id(
        &self,
        authority: &Pubkey,
    ) -> Result<i64, VerificationError> {
        use solana_rpc_client::rpc_client::RpcClient;
        let rpc_url = self.rpc_url.clone();
        let authority = *authority;
        tokio::task::spawn_blocking(move || {
            let account = RpcClient::new(rpc_url)
                .get_account(&authority)
                .map_err(|e| {
                    VerificationError::network_error(format!("getAccount({authority}) failed: {e}"))
                })?;
            if account.data.len() != 106 {
                return Err(VerificationError::invalid_payload(
                    "SubscriptionAuthority account has a non-canonical layout",
                ));
            }
            Ok(i64::from_le_bytes(
                account.data[98..106].try_into().unwrap(),
            ))
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

/// Release-on-failure guard for the activation replay reservation.
///
/// Once the activation signature has been atomically claimed (via
/// `put_if_absent`), every fallible step up to receipt construction must
/// release that claim on error so a transient failure (RPC hiccup, terms
/// mismatch, …) does not permanently brick the activation signature for a
/// legitimate retry. Wrapping each `Result` in this helper deletes the marker
/// at `key` on `Err` and passes `Ok` through untouched. The delete is
/// best-effort: a failed delete cannot make the original error any worse, so it
/// is ignored.
async fn release_on_err<T>(
    store: &dyn Store,
    key: &str,
    result: Result<T, VerificationError>,
) -> Result<T, VerificationError> {
    if result.is_err() {
        let _ = store.delete(key).await;
    }
    result
}

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
#[derive(Debug, Clone, Copy)]
struct ActivationScope {
    authority: Pubkey,
    expected_init_id: Option<i64>,
}

#[cfg(test)]
fn validate_activation_scope(
    tx: &Transaction,
    request: &SubscriptionRequest,
    program_id_str: &str,
    config: &SubscriptionConfig,
    subscriber: &Pubkey,
) -> Result<ActivationScope, VerificationError> {
    validate_activation_scope_with_merchant(
        tx,
        request,
        program_id_str,
        config,
        &config.puller,
        subscriber,
    )
}

fn validate_activation_scope_with_merchant(
    tx: &Transaction,
    request: &SubscriptionRequest,
    program_id_str: &str,
    config: &SubscriptionConfig,
    merchant: &str,
    subscriber: &Pubkey,
) -> Result<ActivationScope, VerificationError> {
    let program_id = parse_pubkey(program_id_str, "program_id")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let keys = &tx.message.account_keys;

    // Strict allowlist of the programs a legitimate activation transaction is
    // permitted to invoke. Anything else is rejected outright — never skipped.
    //
    // The fee-payer co-sign below authorizes EVERY instruction in this message
    // that names the server key as a required signer. If we merely scanned for
    // the subscribe/transfer pair and ignored other instructions, a client
    // could append e.g. a System transfer or an SPL token transfer that spends
    // the server's sponsored fee-payer wallet, and the server would blindly
    // co-sign it. Enforcing an allowlist (not a skip) closes that hole.
    let compute_budget = parse_pubkey(COMPUTE_BUDGET_PROGRAM_ID, "compute_budget_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let ata_program = parse_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID, "associated_token_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let memo_program = parse_pubkey(MEMO_PROGRAM_ID, "memo_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;

    let mint =
        parse_pubkey(&config.mint, "mint").map_err(|e| VerificationError::new(e.to_string()))?;
    let puller = parse_pubkey(&config.puller, "puller")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let merchant =
        parse_pubkey(merchant, "merchant").map_err(|e| VerificationError::new(e.to_string()))?;
    let recipient = parse_pubkey(&config.recipient, "recipient")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let plan = parse_pubkey(&config.plan_id, "plan_id")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let token_program = parse_pubkey(&config.token_program, "token_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let (subscription, _) = find_subscription_pda(&plan, subscriber, &program_id);
    let (authority, _) = find_subscription_authority_pda(subscriber, &mint, &program_id);
    let (event_authority, _) = find_event_authority_pda(&program_id);
    let system_program = parse_pubkey(SYSTEM_PROGRAM_ID, "system_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let amount = request
        .parse_amount()
        .map_err(|e| VerificationError::invalid_payload(e.to_string()))?;
    let period_hours = request
        .period_hours()
        .map_err(|e| VerificationError::invalid_payload(e.to_string()))?;
    let strict = config.fee_payer;
    let plan_id_numeric = config.plan_id_numeric.unwrap_or_default();
    let plan_bump = config.plan_bump.unwrap_or_default();
    let plan_created_at = config.plan_created_at.unwrap_or_default();

    if strict
        && (config.plan_id_numeric.is_none()
            || config.plan_bump.is_none()
            || config.plan_created_at.is_none())
    {
        return Err(VerificationError::invalid_payload(
            "Sponsored subscription requires planIdNumeric, planBump, and planCreatedAt snapshots",
        ));
    }
    if strict && keys.first() != Some(&puller) {
        return Err(VerificationError::invalid_payload(
            "Activation fee payer must be the puller at account index 0",
        ));
    }
    let signer_keys: Vec<Pubkey> = keys
        .iter()
        .enumerate()
        .filter_map(|(i, key)| tx.message.is_signer(i).then_some(*key))
        .collect();
    if strict
        && (signer_keys.len() != 2
            || !signer_keys.contains(&puller)
            || !signer_keys.contains(subscriber))
    {
        return Err(VerificationError::invalid_payload(
            "Activation must require exactly the puller fee payer and subscriber signers",
        ));
    }

    let mut subscribe_idx: Option<usize> = None;
    let mut transfer_idx: Option<usize> = None;
    let mut expected_init_id: Option<i64> = None;
    let mut compute_limit_seen = false;
    let mut compute_price_seen = false;
    for (i, ix) in tx.message.instructions.iter().enumerate() {
        let prog_idx = ix.program_id_index as usize;
        let prog = keys.get(prog_idx).ok_or_else(|| {
            VerificationError::invalid_payload(
                "Activation tx instruction references an out-of-range program id index",
            )
        })?;

        if *prog == program_id {
            let disc = ix.data.first().copied().ok_or_else(|| {
                VerificationError::invalid_payload(
                    "Activation tx subscriptions-program instruction has empty data",
                )
            })?;
            match disc {
                INSTRUCTION_SUBSCRIBE => {
                    if subscribe_idx.is_some() {
                        return Err(VerificationError::invalid_payload(
                            "Activation tx contains multiple subscribe instructions",
                        ));
                    }
                    if strict {
                        expected_init_id = Some(validate_subscribe_instruction(
                            ix,
                            &tx.message,
                            subscriber,
                            merchant,
                            puller,
                            plan,
                            subscription,
                            authority,
                            system_program,
                            event_authority,
                            program_id,
                            mint,
                            amount,
                            period_hours,
                            plan_id_numeric,
                            plan_bump,
                            plan_created_at,
                        )?);
                    }
                    subscribe_idx = Some(i);
                }
                INSTRUCTION_TRANSFER_SUBSCRIPTION => {
                    if transfer_idx.is_some() {
                        return Err(VerificationError::invalid_payload(
                            "Activation tx contains multiple transfer_subscription instructions",
                        ));
                    }
                    if strict {
                        validate_transfer_subscription_instruction(
                            ix,
                            &tx.message,
                            subscriber,
                            puller,
                            plan,
                            subscription,
                            authority,
                            mint,
                            token_program,
                            recipient,
                            event_authority,
                            program_id,
                            amount,
                        )?;
                    }
                    transfer_idx = Some(i);
                }
                other => {
                    return Err(VerificationError::invalid_payload(format!(
                        "Activation tx contains a disallowed subscriptions-program instruction \
                         (discriminator {other}); only subscribe and transfer_subscription are allowed"
                    )));
                }
            }
        } else if *prog == compute_budget {
            validate_compute_budget_instruction(
                ix,
                &mut compute_limit_seen,
                &mut compute_price_seen,
            )?;
            continue;
        } else if *prog == memo_program {
            if strict
                && request.external_id.as_deref().map(str::as_bytes) != Some(ix.data.as_slice())
            {
                return Err(VerificationError::invalid_payload(
                    "Activation memo must exactly match request.externalId",
                ));
            }
            continue;
        } else if *prog == ata_program {
            // The idempotent-ATA bootstrap DOES carry fee-payer fund risk: an
            // ATA `CreateIdempotent` names the funding account (charged the
            // rent) as a required signer, so a blind co-sign would let a client
            // make the sponsored fee payer fund an arbitrary ATA. Validate the
            // instruction the same way the charge verifier does before letting
            // the fee payer co-sign it.
            validate_activation_ata_instruction(ix, &tx.message, config, subscriber)?;
            continue;
        } else {
            return Err(VerificationError::invalid_payload(format!(
                "Activation tx invokes a disallowed program `{prog}`; the fee payer will not \
                 co-sign a transaction outside the subscription activation allowlist"
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
    if !compute_limit_seen {
        return Err(VerificationError::invalid_payload(
            "Activation transaction must contain exactly one SetComputeUnitLimit instruction",
        ));
    }
    let ata_owners: Vec<Pubkey> = tx
        .message
        .instructions
        .iter()
        .filter(|ix| keys.get(ix.program_id_index as usize) == Some(&ata_program))
        .map(|ix| validate_activation_ata_instruction(ix, &tx.message, config, subscriber))
        .collect::<Result<_, _>>()?;
    if strict
        && (ata_owners.len() != 2
            || ata_owners
                .iter()
                .filter(|owner| **owner == *subscriber)
                .count()
                != 1
            || ata_owners
                .iter()
                .filter(|owner| **owner == recipient)
                .count()
                != 1)
    {
        return Err(VerificationError::invalid_payload(
            "Activation must contain exactly one subscriber ATA and one recipient ATA CreateIdempotent instruction",
        ));
    }
    Ok(ActivationScope {
        authority,
        expected_init_id,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_subscribe_instruction(
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    message: &solana_message::Message,
    subscriber: &Pubkey,
    merchant: Pubkey,
    puller: Pubkey,
    plan: Pubkey,
    subscription: Pubkey,
    authority: Pubkey,
    system_program: Pubkey,
    event_authority: Pubkey,
    program_id: Pubkey,
    mint: Pubkey,
    amount: u64,
    period_hours: u64,
    plan_id: u64,
    plan_bump: u8,
    created_at: i64,
) -> Result<i64, VerificationError> {
    let merchant_is_signer = merchant == puller || merchant == *subscriber;
    let expected = [
        (*subscriber, true, true),
        (merchant, merchant_is_signer, merchant_is_signer),
        (plan, false, false),
        (subscription, true, false),
        (authority, false, false),
        (system_program, false, false),
        (event_authority, false, false),
        (program_id, false, false),
        (puller, true, true),
    ];
    validate_instruction_accounts(message, ix, &expected, "subscribe")?;
    if ix.data.len() != 74 || ix.data[0] != INSTRUCTION_SUBSCRIBE {
        return Err(VerificationError::invalid_payload(
            "Non-canonical subscribe instruction data",
        ));
    }
    let u64_at = |at| u64::from_le_bytes(ix.data[at..at + 8].try_into().unwrap());
    let i64_at = |at| i64::from_le_bytes(ix.data[at..at + 8].try_into().unwrap());
    let data_mint = Pubkey::new_from_array(ix.data[10..42].try_into().unwrap());
    if u64_at(1) != plan_id
        || ix.data[9] != plan_bump
        || data_mint != mint
        || u64_at(42) != amount
        || u64_at(50) != period_hours
        || i64_at(58) != created_at
    {
        return Err(VerificationError::credential_mismatch(
            "Subscribe data does not match the challenged plan snapshot",
        ));
    }
    Ok(i64_at(66))
}

#[allow(clippy::too_many_arguments)]
fn validate_transfer_subscription_instruction(
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    message: &solana_message::Message,
    subscriber: &Pubkey,
    puller: Pubkey,
    plan: Pubkey,
    subscription: Pubkey,
    authority: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
    recipient: Pubkey,
    event_authority: Pubkey,
    program_id: Pubkey,
    amount: u64,
) -> Result<(), VerificationError> {
    let ata_program = parse_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID, "associated_token_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let derive_ata = |owner: &Pubkey| {
        Pubkey::find_program_address(
            &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
            &ata_program,
        )
        .0
    };
    let expected = [
        (subscription, true, false),
        (plan, false, false),
        (authority, false, false),
        (derive_ata(subscriber), true, false),
        (derive_ata(&recipient), true, false),
        (puller, true, true),
        (mint, false, false),
        (token_program, false, false),
        (event_authority, false, false),
        (program_id, false, false),
    ];
    validate_instruction_accounts(message, ix, &expected, "transfer_subscription")?;
    if ix.data.len() != 73 || ix.data[0] != INSTRUCTION_TRANSFER_SUBSCRIPTION {
        return Err(VerificationError::invalid_payload(
            "Non-canonical transfer_subscription instruction data",
        ));
    }
    let data_amount = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
    let delegator = Pubkey::new_from_array(ix.data[9..41].try_into().unwrap());
    let data_mint = Pubkey::new_from_array(ix.data[41..73].try_into().unwrap());
    if data_amount != amount || delegator != *subscriber || data_mint != mint {
        return Err(VerificationError::credential_mismatch(
            "Transfer data does not match the challenged subscription",
        ));
    }
    Ok(())
}

fn validate_instruction_accounts(
    message: &solana_message::Message,
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    expected: &[(Pubkey, bool, bool)],
    label: &str,
) -> Result<(), VerificationError> {
    if ix.accounts.len() != expected.len() {
        return Err(VerificationError::invalid_payload(format!(
            "Non-canonical {label} account layout"
        )));
    }
    for (position, ((expected_key, expected_writable, expected_signer), index)) in
        expected.iter().zip(&ix.accounts).enumerate()
    {
        let index = *index as usize;
        let actual = message.account_keys.get(index).ok_or_else(|| {
            VerificationError::invalid_payload(format!("Invalid {label} account index"))
        })?;
        if actual != expected_key {
            return Err(VerificationError::invalid_payload(format!(
                "Non-canonical {label} account layout at position {position}"
            )));
        }
        if message.is_signer(index) != *expected_signer {
            return Err(VerificationError::invalid_payload(format!(
                "Non-canonical {label} signer privilege at position {position}"
            )));
        }
        if is_writable_account_index(message, index) != *expected_writable {
            return Err(VerificationError::invalid_payload(format!(
                "Non-canonical {label} writable privilege at position {position}"
            )));
        }
    }
    Ok(())
}

fn is_writable_account_index(message: &solana_message::Message, index: usize) -> bool {
    let required_signatures = usize::from(message.header.num_required_signatures);
    if index < required_signatures {
        index < required_signatures - usize::from(message.header.num_readonly_signed_accounts)
    } else {
        index
            < message.account_keys.len()
                - usize::from(message.header.num_readonly_unsigned_accounts)
    }
}

/// Validate an Associated-Token-Account `CreateIdempotent` instruction in an
/// activation transaction before the fee payer co-signs it.
///
/// An ATA create names the funding account (which is charged the account's
/// rent) as a required signer. If the server blindly co-signed, a client could
/// make the sponsored fee payer fund the rent for an arbitrary ATA. This
/// mirrors the charge verifier's `validate_create_ata_idempotent_instruction`:
/// require the `CreateIdempotent` discriminator with the canonical 6-account
/// layout, and assert that the funding account is the transaction fee payer,
/// the mint is the plan mint, the token program is the configured one, the
/// owner is one the challenge authorizes (subscriber, recipient, or puller),
/// and that the ATA address re-derives from `(owner, token_program, mint)`.
fn validate_activation_ata_instruction(
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    message: &solana_message::Message,
    config: &SubscriptionConfig,
    subscriber: &Pubkey,
) -> Result<Pubkey, VerificationError> {
    let account_keys = &message.account_keys;
    if ix.data.as_slice() != [1] {
        return Err(VerificationError::invalid_payload(
            "Only idempotent ATA creation is allowed in activation tx",
        ));
    }
    if ix.accounts.len() != 6 {
        return Err(VerificationError::invalid_payload(
            "Unexpected ATA creation account layout in activation tx",
        ));
    }

    let ata_account_key = |slot: usize, label: &str| -> Result<Pubkey, VerificationError> {
        let idx = ix.accounts[slot] as usize;
        account_keys.get(idx).copied().ok_or_else(|| {
            VerificationError::invalid_payload(format!("Invalid {label} account index"))
        })
    };
    let payer = ata_account_key(0, "ATA payer")?;
    let ata = ata_account_key(1, "ATA address")?;
    let owner = ata_account_key(2, "ATA owner")?;
    let mint = ata_account_key(3, "ATA mint")?;
    let system_program = ata_account_key(4, "ATA system program")?;
    let token_program = ata_account_key(5, "ATA token program")?;

    // The funding account (charged the rent) must be the transaction fee payer
    // at index 0 — the slot the server signs as. Anything else means the client
    // is asking the server to fund rent for an account it does not control.
    let expected_payer = account_keys.first().ok_or_else(|| {
        VerificationError::invalid_payload("Activation tx has no fee payer account")
    })?;
    if payer != *expected_payer {
        return Err(VerificationError::invalid_payload(
            "ATA payer must be the transaction fee payer in activation tx",
        ));
    }

    let expected_mint =
        parse_pubkey(&config.mint, "mint").map_err(|e| VerificationError::new(e.to_string()))?;
    if mint != expected_mint {
        return Err(VerificationError::invalid_payload(
            "ATA creation mint does not match the plan mint",
        ));
    }

    // Owner must be one of the parties the challenge authorizes: the subscriber
    // themselves, the primary recipient, or the server puller.
    let recipient = parse_pubkey(&config.recipient, "recipient")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    if owner != *subscriber && owner != recipient {
        return Err(VerificationError::invalid_payload(
            "ATA creation owner is not authorized by the challenge",
        ));
    }

    let system_program_id = parse_pubkey(SYSTEM_PROGRAM_ID, "system_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    if system_program != system_program_id {
        return Err(VerificationError::invalid_payload(
            "ATA creation must reference the System Program",
        ));
    }

    let token_program_str = token_program.to_string();
    if token_program_str != programs::TOKEN_PROGRAM
        && token_program_str != programs::TOKEN_2022_PROGRAM
    {
        return Err(VerificationError::invalid_payload(
            "ATA creation uses an unsupported token program",
        ));
    }
    let expected_token_program = parse_pubkey(&config.token_program, "token_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    if token_program != expected_token_program {
        return Err(VerificationError::invalid_payload(
            "ATA creation token program does not match the configured token program",
        ));
    }

    let ata_program = parse_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID, "associated_token_program")
        .map_err(|e| VerificationError::new(e.to_string()))?;
    let (expected_ata, _) = Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_program,
    );
    if ata != expected_ata {
        return Err(VerificationError::invalid_payload(
            "ATA creation address does not match owner/mint/token program",
        ));
    }

    // Message account privileges are merged globally across instructions. The
    // ATA program receives the owner as readonly, but the subscriber is also a
    // writable signer of `subscribe` and the puller may be the fee payer.
    let owner_is_transaction_signer = owner == *subscriber || owner == *expected_payer;

    validate_instruction_accounts(
        message,
        ix,
        &[
            (payer, true, true),
            (ata, true, false),
            (
                owner,
                owner_is_transaction_signer,
                owner_is_transaction_signer,
            ),
            (mint, false, false),
            (system_program, false, false),
            (token_program, false, false),
        ],
        "ATA CreateIdempotent",
    )?;

    Ok(owner)
}

const MAX_COMPUTE_UNIT_LIMIT: u32 = 200_000;
const MAX_SPONSORED_COMPUTE_UNIT_PRICE_MICROLAMPORTS: u64 = 10_000;

fn validate_compute_budget_instruction(
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    compute_limit_seen: &mut bool,
    compute_price_seen: &mut bool,
) -> Result<(), VerificationError> {
    if !ix.accounts.is_empty() {
        return Err(VerificationError::invalid_payload(
            "Compute budget instruction must not have accounts",
        ));
    }
    match ix.data.as_slice() {
        [2, units @ ..] if units.len() == 4 => {
            if *compute_limit_seen {
                return Err(VerificationError::invalid_payload(
                    "Duplicate compute unit limit instruction",
                ));
            }
            *compute_limit_seen = true;
            let units = u32::from_le_bytes(units.try_into().expect("checked length"));
            if units > MAX_COMPUTE_UNIT_LIMIT {
                return Err(VerificationError::invalid_payload(format!(
                    "Compute unit limit {units} exceeds maximum {MAX_COMPUTE_UNIT_LIMIT}"
                )));
            }
        }
        [3, price @ ..] if price.len() == 8 => {
            if *compute_price_seen {
                return Err(VerificationError::invalid_payload(
                    "Duplicate compute unit price instruction",
                ));
            }
            *compute_price_seen = true;
            let price = u64::from_le_bytes(price.try_into().expect("checked length"));
            if price > MAX_SPONSORED_COMPUTE_UNIT_PRICE_MICROLAMPORTS {
                return Err(VerificationError::invalid_payload(format!(
                    "Compute unit price {price} exceeds maximum {MAX_SPONSORED_COMPUTE_UNIT_PRICE_MICROLAMPORTS}"
                )));
            }
        }
        _ => {
            return Err(VerificationError::invalid_payload(
                "Unsupported or malformed compute budget instruction",
            ));
        }
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
    // The fee payer MUST be account index 0 (Solana's transaction fee-payer
    // slot). Signing wherever the key happens to appear would let a client
    // place the server key at a non-zero index — as the authority/source of an
    // attacker-inserted instruction — and still collect the server's signature.
    // Pinning to index 0 means the server only ever signs as the fee payer.
    let idx = 0usize;
    match tx.message.account_keys.first() {
        Some(k) if *k == pubkey => {}
        Some(_) => {
            return Err(VerificationError::invalid_payload(
                "Fee payer must be the transaction fee-payer (account index 0)",
            ));
        }
        None => {
            return Err(VerificationError::invalid_payload(
                "Activation transaction has no account keys",
            ));
        }
    }
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

/// Validate a fetched `SubscriptionDelegation` against the challenge's
/// snapshotted terms, then build the success receipt.
#[allow(clippy::too_many_arguments)]
fn validate_terms_and_build_receipt(
    delegation: &SubscriptionDelegationView,
    request: &SubscriptionRequest,
    plan_pda: &Pubkey,
    subscription_pda: &Pubkey,
    plan_id: &str,
    challenge_id: &str,
    activation_signature: Option<String>,
) -> Result<ReceiptKind, VerificationError> {
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
    if delegation.plan_pda != *plan_pda {
        return Err(VerificationError::credential_mismatch(format!(
            "SubscriptionDelegation plan mismatch: expected {plan_pda}, got {}",
            delegation.plan_pda
        )));
    }
    if delegation.amount_pulled_in_period != expected_amount {
        return Err(VerificationError::new(
            "Activation transaction did not execute the first-period charge",
        ));
    }

    let period_start_secs = delegation.current_period_start_ts;
    let period_end_secs = period_start_secs.saturating_add(expected_period_hours as i64 * 3600);

    Ok(ReceiptKind::Subscription {
        base: Receipt {
            status: crate::mpp::protocol::core::ReceiptStatus::Success,
            method: METHOD_NAME.into(),
            timestamp: format_rfc3339_seconds(now_unix_secs()),
            reference: subscription_pda.to_string(),
            challenge_id: challenge_id.to_string(),
        },
        extensions: SubscriptionReceiptExtensions {
            subscription_id: subscription_pda.to_string(),
            plan_id: plan_id.to_string(),
            period_index: "0".to_string(),
            period_start_ts: format_rfc3339_seconds(period_start_secs),
            period_end_ts: format_rfc3339_seconds(period_end_secs),
            expires_at: request.subscription_expires.clone(),
            activation_signature,
        },
    })
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
    use crate::mpp::store::MemoryStore;
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
            store: Some(Arc::new(MemoryStore::new())),
            plan_id_numeric: Some(1),
            plan_bump: Some(255),
            plan_created_at: Some(1_700_000_000),
            ..Default::default()
        }
    }

    #[test]
    fn subscription_config_exhaustive_literal_remains_source_compatible() {
        let _config = SubscriptionConfig {
            plan_id: keypair_base58(),
            mint: keypair_base58(),
            decimals: 6,
            token_program: programs::TOKEN_PROGRAM.to_string(),
            puller: keypair_base58(),
            recipient: keypair_base58(),
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: 30,
            subscription_expires: None,
            network: "devnet".to_string(),
            program_id: None,
            rpc_url: None,
            challenge_binding_secret: "test-secret".to_string(),
            realm: "test-realm".to_string(),
            fee_payer: false,
            fee_payer_signer: None,
            fee_payer_pubkey: None,
            store: Some(Arc::new(MemoryStore::new())),
            plan_id_numeric: Some(1),
            plan_bump: Some(255),
            plan_created_at: Some(1_700_000_000),
            description: None,
        };
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
        assert_eq!(md.get("planId").unwrap().as_str().unwrap(), plan_id);
    }

    #[test]
    fn challenge_preserves_plan_owner_when_puller_is_delegated() {
        let config = make_config();
        let merchant = Pubkey::new_unique().to_string();
        assert_ne!(merchant, config.puller);
        let server =
            SubscriptionServer::new_with_merchant(config, merchant.clone()).expect("server");
        let challenge = server.subscription_challenge("10000000").unwrap();
        let request: SubscriptionRequest = challenge.request.decode().unwrap();
        let method_details = request.method_details.expect("method details");
        assert_eq!(
            method_details.get("merchant").and_then(|v| v.as_str()),
            Some(merchant.as_str())
        );
        assert_ne!(
            method_details.get("merchant"),
            method_details.get("puller"),
            "delegated puller must not replace the Plan owner",
        );
    }

    #[test]
    fn rejects_invalid_amount() {
        let server = SubscriptionServer::new(make_config()).unwrap();
        assert!(server.subscription_challenge("not-a-number").is_err());
        assert!(server.subscription_challenge("").is_err());
    }

    #[test]
    fn rejects_each_missing_required_field() {
        let cases: Vec<(&str, fn(&mut SubscriptionConfig))> = vec![
            ("mint", |c| c.mint = String::new()),
            ("token_program", |c| c.token_program = String::new()),
            ("puller", |c| c.puller = String::new()),
            ("recipient", |c| c.recipient = String::new()),
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

    // ── Transaction-building helpers for the static verify checks ───────

    /// Build a legacy `Transaction` over the given account keys and
    /// instructions on the configured subscriptions program. `keys[0]` is
    /// treated as the fee payer / first signer.
    fn build_tx(keys: &[Pubkey], instructions: Vec<(u8, Vec<u8>)>) -> Transaction {
        use solana_hash::Hash;
        use solana_message::compiled_instruction::CompiledInstruction;
        use solana_message::{Message, MessageHeader};

        // Append the subscriptions and compute-budget programs so every
        // otherwise-valid activation fixture carries the canonical explicit
        // 200k limit. Only do so when there are instructions; signer-extraction
        // tests intentionally construct messages with no program keys.
        let program = parse_pubkey(SUBSCRIPTIONS_PROGRAM_ID, "program").unwrap();
        let compute_budget =
            parse_pubkey(COMPUTE_BUDGET_PROGRAM_ID, "compute budget program").unwrap();
        let mut account_keys: Vec<Pubkey> = keys.to_vec();
        let program_idx = account_keys.len() as u8;
        let compute_budget_idx = program_idx + 1;
        if !instructions.is_empty() {
            account_keys.push(program);
            account_keys.push(compute_budget);
        }

        let mut compiled: Vec<CompiledInstruction> = instructions
            .into_iter()
            .map(|(disc, mut extra)| {
                let mut data = vec![disc];
                data.append(&mut extra);
                CompiledInstruction {
                    program_id_index: program_idx,
                    accounts: vec![],
                    data,
                }
            })
            .collect();
        if !compiled.is_empty() {
            compiled.insert(
                0,
                CompiledInstruction {
                    program_id_index: compute_budget_idx,
                    accounts: vec![],
                    data: [vec![2], 200_000u32.to_le_bytes().to_vec()].concat(),
                },
            );
        }

        let readonly_unsigned = (account_keys.len() - keys.len()) as u8;
        let message = Message {
            header: MessageHeader {
                num_required_signatures: keys.len() as u8,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: readonly_unsigned,
            },
            account_keys,
            recent_blockhash: Hash::default(),
            instructions: compiled,
        };
        Transaction {
            signatures: vec![Signature::default(); keys.len()],
            message,
        }
    }

    fn dummy_request() -> SubscriptionRequest {
        SubscriptionRequest {
            amount: "1".into(),
            currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "30".into(),
            recipient: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".into(),
            ..Default::default()
        }
    }

    /// A config for the scope tests. The subscribe/transfer ordering checks are
    /// independent of these values; the ATA-layout checks read `mint`,
    /// `token_program`, `recipient`, and `puller` from here.
    fn scope_config() -> SubscriptionConfig {
        make_config()
    }

    /// A throwaway subscriber for scope tests that do not construct an ATA.
    fn scope_subscriber() -> Pubkey {
        Pubkey::new_unique()
    }

    #[test]
    fn subscribe_validation_keeps_merchant_distinct_from_delegated_puller() {
        use crate::mpp::program::subscriptions::{
            build_subscribe_ix, find_event_authority_pda, find_subscription_authority_pda,
            find_subscription_pda, SubscribeAccounts, SubscribeData,
        };
        use solana_message::Message;

        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let puller = parse_pubkey(&config.puller, "puller").unwrap();
        let merchant = Pubkey::new_unique();
        let plan = parse_pubkey(&config.plan_id, "plan").unwrap();
        let mint = parse_pubkey(&config.mint, "mint").unwrap();
        let program_id = parse_pubkey(SUBSCRIPTIONS_PROGRAM_ID, "program").unwrap();
        let (subscription, _) = find_subscription_pda(&plan, &subscriber, &program_id);
        let (authority, _) = find_subscription_authority_pda(&subscriber, &mint, &program_id);
        let (event_authority, _) = find_event_authority_pda(&program_id);
        let instruction = build_subscribe_ix(
            program_id,
            SubscribeAccounts {
                subscriber,
                merchant,
                plan_pda: plan,
                subscription_pda: subscription,
                subscription_authority_pda: authority,
                event_authority,
                payer: Some(puller),
            },
            &SubscribeData {
                plan_id: config.plan_id_numeric.unwrap(),
                plan_bump: config.plan_bump.unwrap(),
                expected_mint: mint,
                expected_amount: 1,
                expected_period_hours: 720,
                expected_created_at: config.plan_created_at.unwrap(),
                expected_subscription_authority_init_id: 7,
            },
        );
        let message = Message::new(&[instruction], Some(&puller));
        let system_program = parse_pubkey(SYSTEM_PROGRAM_ID, "system").unwrap();

        let init_id = validate_subscribe_instruction(
            &message.instructions[0],
            &message,
            &subscriber,
            merchant,
            puller,
            plan,
            subscription,
            authority,
            system_program,
            event_authority,
            program_id,
            mint,
            1,
            720,
            config.plan_id_numeric.unwrap(),
            config.plan_bump.unwrap(),
            config.plan_created_at.unwrap(),
        )
        .expect("delegated puller layout remains canonical");
        assert_eq!(init_id, 7);
    }

    #[test]
    fn ata_validation_uses_effective_merged_subscriber_privileges() {
        use solana_instruction::{AccountMeta, Instruction};
        use solana_message::Message;

        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let fee_payer = parse_pubkey(&config.puller, "puller").unwrap();
        let mint = parse_pubkey(&config.mint, "mint").unwrap();
        let token_program = parse_pubkey(&config.token_program, "token program").unwrap();
        let ata_program = parse_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID, "ATA program").unwrap();
        let system_program = parse_pubkey(SYSTEM_PROGRAM_ID, "system program").unwrap();
        let (ata, _) = Pubkey::find_program_address(
            &[subscriber.as_ref(), token_program.as_ref(), mint.as_ref()],
            &ata_program,
        );
        let create_ata = Instruction {
            program_id: ata_program,
            accounts: vec![
                AccountMeta::new(fee_payer, true),
                AccountMeta::new(ata, false),
                AccountMeta::new_readonly(subscriber, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(system_program, false),
                AccountMeta::new_readonly(token_program, false),
            ],
            data: vec![1],
        };
        let subscriber_write = Instruction {
            program_id: parse_pubkey(SUBSCRIPTIONS_PROGRAM_ID, "program").unwrap(),
            accounts: vec![AccountMeta::new(subscriber, true)],
            data: vec![INSTRUCTION_SUBSCRIBE],
        };
        let message = Message::new(&[create_ata, subscriber_write], Some(&fee_payer));
        let owner_index = message.instructions[0].accounts[2] as usize;
        assert!(message.is_signer(owner_index));
        assert!(is_writable_account_index(&message, owner_index));
        assert_eq!(
            validate_activation_ata_instruction(
                &message.instructions[0],
                &message,
                &config,
                &subscriber,
            )
            .expect("globally merged owner privileges are canonical"),
            subscriber,
        );
    }

    // ── extract_subscriber_from_tx ──────────────────────────────────────

    #[test]
    fn extract_subscriber_rejects_empty_account_keys() {
        let cfg = make_config();
        let tx = build_tx(&[], vec![]);
        // build_tx appends the program id, so drop it to get a truly empty
        // account_keys vec.
        let mut tx = tx;
        tx.message.account_keys.clear();
        let err = extract_subscriber_from_tx(&tx, &dummy_request(), &cfg).unwrap_err();
        assert!(err.message.contains("no account keys"), "{}", err.message);
    }

    #[test]
    fn extract_subscriber_returns_first_key_no_fee_payer() {
        let cfg = make_config();
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(&[subscriber], vec![]);
        let got = extract_subscriber_from_tx(&tx, &dummy_request(), &cfg).unwrap();
        assert_eq!(got, subscriber);
    }

    #[test]
    fn extract_subscriber_rejects_subscriber_equal_puller() {
        let cfg = make_config();
        let puller = parse_pubkey(&cfg.puller, "puller").unwrap();
        let tx = build_tx(&[puller], vec![]);
        let err = extract_subscriber_from_tx(&tx, &dummy_request(), &cfg).unwrap_err();
        assert!(
            err.message.contains("cannot equal the server puller"),
            "{}",
            err.message
        );
    }

    #[test]
    fn extract_subscriber_finds_subscriber_after_fee_payer() {
        let mut cfg = make_config();
        let fee_payer = Pubkey::new_unique();
        cfg.fee_payer = true;
        cfg.fee_payer_pubkey = Some(fee_payer.to_string());
        let puller = parse_pubkey(&cfg.puller, "puller").unwrap();
        let subscriber = Pubkey::new_unique();
        // account_keys[0] is the fee-payer, then puller, then subscriber.
        let tx = build_tx(&[fee_payer, puller, subscriber], vec![]);
        let got = extract_subscriber_from_tx(&tx, &dummy_request(), &cfg).unwrap();
        assert_eq!(got, subscriber);
    }

    #[test]
    fn extract_subscriber_fee_payer_no_candidate_rejects() {
        let mut cfg = make_config();
        let fee_payer = Pubkey::new_unique();
        cfg.fee_payer = true;
        cfg.fee_payer_pubkey = Some(fee_payer.to_string());
        let puller = parse_pubkey(&cfg.puller, "puller").unwrap();
        // Only fee-payer + puller signers, no subscriber to find.
        let tx = build_tx(&[fee_payer, puller], vec![]);
        let err = extract_subscriber_from_tx(&tx, &dummy_request(), &cfg).unwrap_err();
        assert!(
            err.message.contains("Could not identify subscriber"),
            "{}",
            err.message
        );
    }

    #[test]
    fn extract_subscriber_fee_payer_from_signer_pubkey() {
        use solana_keychain::{MemorySigner, SolanaSigner};
        let mut cfg = make_config();
        cfg.fee_payer = true;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        let signer = MemorySigner::from_bytes(&kp).expect("kp");
        let fee_payer = signer.pubkey();
        cfg.fee_payer_signer = Some(Arc::new(signer));
        // No explicit fee_payer_pubkey — must derive it from the signer.
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(&[fee_payer, subscriber], vec![]);
        let got = extract_subscriber_from_tx(&tx, &dummy_request(), &cfg).unwrap();
        assert_eq!(got, subscriber);
    }

    // ── validate_activation_scope ───────────────────────────────────────

    fn program_id_str() -> String {
        SUBSCRIPTIONS_PROGRAM_ID.to_string()
    }

    #[test]
    fn validate_scope_accepts_subscribe_then_transfer() {
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
            ],
        );
        validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &scope_config(),
            &scope_subscriber(),
        )
        .expect("valid scope");
    }

    #[test]
    fn validate_scope_rejects_missing_subscribe() {
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(
            &[subscriber],
            vec![(INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![])],
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &scope_config(),
            &scope_subscriber(),
        )
        .unwrap_err();
        assert!(err.message.contains("missing subscribe"), "{}", err.message);
    }

    #[test]
    fn validate_scope_rejects_missing_transfer() {
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(&[subscriber], vec![(INSTRUCTION_SUBSCRIBE, vec![])]);
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &scope_config(),
            &scope_subscriber(),
        )
        .unwrap_err();
        assert!(
            err.message.contains("missing transfer_subscription"),
            "{}",
            err.message
        );
    }

    #[test]
    fn validate_scope_rejects_duplicate_subscribe() {
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
            ],
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &scope_config(),
            &scope_subscriber(),
        )
        .unwrap_err();
        assert!(
            err.message.contains("multiple subscribe"),
            "{}",
            err.message
        );
    }

    #[test]
    fn validate_scope_rejects_duplicate_transfer() {
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
            ],
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &scope_config(),
            &scope_subscriber(),
        )
        .unwrap_err();
        assert!(
            err.message.contains("multiple transfer_subscription"),
            "{}",
            err.message
        );
    }

    #[test]
    fn validate_scope_rejects_transfer_before_subscribe() {
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
                (INSTRUCTION_SUBSCRIBE, vec![]),
            ],
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &scope_config(),
            &scope_subscriber(),
        )
        .unwrap_err();
        assert!(err.message.contains("must precede"), "{}", err.message);
    }

    #[test]
    fn validate_scope_rejects_instruction_on_unknown_program() {
        // An instruction on a program outside the activation
        // allowlist must be REJECTED, not skipped. The old behaviour scanned
        // for the subscribe/transfer pair and ignored everything else, so a
        // client could smuggle e.g. a System transfer that spends the
        // sponsored fee payer and the server would still co-sign it.
        use solana_hash::Hash;
        use solana_message::compiled_instruction::CompiledInstruction;
        use solana_message::{Message, MessageHeader};
        let fee_payer = Pubkey::new_unique();
        let attacker_recipient = Pubkey::new_unique();
        let system_program = parse_pubkey(
            crate::mpp::program::subscriptions::SYSTEM_PROGRAM_ID,
            "system",
        )
        .unwrap();
        let sub_program = parse_pubkey(SUBSCRIPTIONS_PROGRAM_ID, "program").unwrap();
        // keys: [fee_payer(0), attacker_recipient(1), system(2), subscriptions(3)]
        let account_keys = vec![fee_payer, attacker_recipient, system_program, sub_program];
        let instructions = vec![
            // Legit subscribe + transfer on the subscriptions program.
            CompiledInstruction {
                program_id_index: 3,
                accounts: vec![],
                data: vec![INSTRUCTION_SUBSCRIBE],
            },
            CompiledInstruction {
                program_id_index: 3,
                accounts: vec![],
                data: vec![INSTRUCTION_TRANSFER_SUBSCRIPTION],
            },
            // Attacker-inserted System transfer draining the fee payer.
            CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: vec![2, 0, 0, 0], // System::Transfer discriminator
            },
        ];
        let message = Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 2,
            },
            account_keys,
            recent_blockhash: Hash::default(),
            instructions,
        };
        let tx = Transaction {
            signatures: vec![Signature::default(); 1],
            message,
        };
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &scope_config(),
            &scope_subscriber(),
        )
        .unwrap_err();
        assert!(
            err.message.contains("disallowed program"),
            "{}",
            err.message
        );
    }

    #[test]
    fn validate_scope_rejects_out_of_range_program_index() {
        // A program-id index past the end of account_keys must be a hard
        // error, not a silent skip (which previously let a crafted subscribe
        // instruction hide behind an out-of-range index).
        use solana_hash::Hash;
        use solana_message::compiled_instruction::CompiledInstruction;
        use solana_message::{Message, MessageHeader};
        let subscriber = Pubkey::new_unique();
        let sub_program = parse_pubkey(SUBSCRIPTIONS_PROGRAM_ID, "program").unwrap();
        let account_keys = vec![subscriber, sub_program];
        let instructions = vec![CompiledInstruction {
            program_id_index: 99,
            accounts: vec![],
            data: vec![INSTRUCTION_SUBSCRIBE],
        }];
        let message = Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys,
            recent_blockhash: Hash::default(),
            instructions,
        };
        let tx = Transaction {
            signatures: vec![Signature::default(); 1],
            message,
        };
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &scope_config(),
            &scope_subscriber(),
        )
        .unwrap_err();
        assert!(err.message.contains("out-of-range"), "{}", err.message);
    }

    #[test]
    fn validate_scope_rejects_unknown_subscriptions_instruction() {
        // An instruction ON the subscriptions program but with a
        // non-subscribe/transfer discriminator (e.g. a delegation revoke or
        // plan mutation) must be rejected.
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
                (
                    crate::mpp::program::subscriptions::INSTRUCTION_REVOKE_DELEGATION,
                    vec![],
                ),
            ],
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &scope_config(),
            &scope_subscriber(),
        )
        .unwrap_err();
        assert!(
            err.message
                .contains("disallowed subscriptions-program instruction"),
            "{}",
            err.message
        );
    }

    /// A per-account override for the ATA `CreateIdempotent` instruction so
    /// negative tests can corrupt exactly one field. `None` fields fall back to
    /// the canonical value derived from `config` + `subscriber`.
    #[derive(Default)]
    struct AtaOverrides {
        payer: Option<Pubkey>,
        owner: Option<Pubkey>,
        mint: Option<Pubkey>,
        token_program: Option<Pubkey>,
        ata: Option<Pubkey>,
        data: Option<Vec<u8>>,
        accounts: Option<Vec<u8>>,
    }

    /// Build a full activation transaction in the exact shape the client
    /// builder emits — compute-budget price/limit, an ATA `CreateIdempotent`,
    /// subscribe, transfer, and a memo — with the ATA instruction fields
    /// controllable via `overrides`. The tx fee payer is `account_keys[0]`.
    fn build_activation_tx_with_ata(
        config: &SubscriptionConfig,
        subscriber: &Pubkey,
        overrides: AtaOverrides,
    ) -> Transaction {
        use solana_hash::Hash;
        use solana_message::compiled_instruction::CompiledInstruction;
        use solana_message::{Message, MessageHeader};

        let fee_payer = Pubkey::new_unique();
        let mint = overrides
            .mint
            .unwrap_or_else(|| parse_pubkey(&config.mint, "mint").unwrap());
        let token_program = overrides
            .token_program
            .unwrap_or_else(|| parse_pubkey(&config.token_program, "token_program").unwrap());
        let owner = overrides.owner.unwrap_or(*subscriber);
        let payer = overrides.payer.unwrap_or(fee_payer);
        let system_program = parse_pubkey(SYSTEM_PROGRAM_ID, "system").unwrap();
        let ata_program = parse_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID, "ata").unwrap();
        // Canonical ATA re-derives from (owner, token_program, mint); a test
        // that wants a bogus ATA address overrides `ata` directly.
        let ata_addr = overrides.ata.unwrap_or_else(|| {
            Pubkey::find_program_address(
                &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
                &ata_program,
            )
            .0
        });

        let cb = parse_pubkey(COMPUTE_BUDGET_PROGRAM_ID, "cb").unwrap();
        let memo = parse_pubkey(MEMO_PROGRAM_ID, "memo").unwrap();
        let sub = parse_pubkey(SUBSCRIPTIONS_PROGRAM_ID, "sub").unwrap();
        // Keep writable non-signers before every readonly non-signer, as the
        // legacy message header requires. The ATA payer is the fee payer at
        // account index 0, not a duplicate readonly copy of that key.
        let account_keys = vec![
            fee_payer,
            ata_addr,
            cb,
            ata_program,
            memo,
            sub,
            payer,
            owner,
            mint,
            system_program,
            token_program,
        ];
        // Default canonical CreateIdempotent layout referencing fee payer,
        // writable ATA, then four readonly program/accounts.
        let ata_accounts = overrides.accounts.unwrap_or_else(|| {
            if payer == fee_payer {
                vec![0, 1, 7, 8, 9, 10]
            } else {
                vec![6, 1, 7, 8, 9, 10]
            }
        });
        let ata_data = overrides.data.unwrap_or_else(|| vec![1]);

        let mk = |prog: u8, accounts: Vec<u8>, data: Vec<u8>| CompiledInstruction {
            program_id_index: prog,
            accounts,
            data,
        };
        let instructions = vec![
            mk(2, vec![], [vec![3], 1u64.to_le_bytes().to_vec()].concat()),
            mk(
                2,
                vec![],
                [vec![2], 200_000u32.to_le_bytes().to_vec()].concat(),
            ),
            mk(3, ata_accounts, ata_data),
            mk(5, vec![], vec![INSTRUCTION_SUBSCRIBE]),
            mk(5, vec![], vec![INSTRUCTION_TRANSFER_SUBSCRIPTION]),
            mk(4, vec![], b"external-id".to_vec()),
        ];
        let message = Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: (account_keys.len() - 2) as u8,
            },
            account_keys,
            recent_blockhash: Hash::default(),
            instructions,
        };
        Transaction {
            signatures: vec![Signature::default(); 1],
            message,
        }
    }

    #[test]
    fn validate_scope_accepts_documented_default_compute_budget() {
        // The exact shape the client builder emits:
        // [compute_budget price, compute_budget limit, create_idempotent_ata,
        //  subscribe, transfer_subscription, memo] must pass, with a canonical
        // ATA that funds from the fee payer and re-derives for the recipient.
        // Its 200k limit is the documented safe sponsored cap and the Rust
        // client's public default.
        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let recipient = parse_pubkey(&config.recipient, "recipient").unwrap();
        let tx = build_activation_tx_with_ata(
            &config,
            &subscriber,
            AtaOverrides {
                owner: Some(recipient),
                ..Default::default()
            },
        );
        validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .expect("valid scope");
    }

    #[test]
    fn validate_scope_requires_exactly_one_compute_unit_limit() {
        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let compute_budget = parse_pubkey(COMPUTE_BUDGET_PROGRAM_ID, "compute budget").unwrap();

        let canonical = || {
            build_tx(
                &[subscriber],
                vec![
                    (INSTRUCTION_SUBSCRIBE, vec![]),
                    (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
                ],
            )
        };
        let mut missing = canonical();
        let missing_keys = missing.message.account_keys.clone();
        missing.message.instructions.retain(|ix| {
            missing_keys.get(ix.program_id_index as usize) != Some(&compute_budget)
                || ix.data.first() != Some(&2)
        });
        let err = validate_activation_scope(
            &missing,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .unwrap_err();
        assert!(
            err.message.contains("exactly one SetComputeUnitLimit"),
            "{}",
            err.message
        );

        let mut duplicate = canonical();
        let limit = duplicate
            .message
            .instructions
            .iter()
            .find(|ix| {
                duplicate
                    .message
                    .account_keys
                    .get(ix.program_id_index as usize)
                    == Some(&compute_budget)
                    && ix.data.first() == Some(&2)
            })
            .cloned()
            .expect("fixture contains compute-unit limit");
        duplicate.message.instructions.push(limit);
        let err = validate_activation_scope(
            &duplicate,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .unwrap_err();
        assert!(err.message.contains("Duplicate"), "{}", err.message);
    }

    #[test]
    fn validate_scope_accepts_ata_owned_by_recipient() {
        // An ATA created for the plan recipient (a split target) is authorized.
        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let recipient = parse_pubkey(&config.recipient, "recipient").unwrap();
        let tx = build_activation_tx_with_ata(
            &config,
            &subscriber,
            AtaOverrides {
                owner: Some(recipient),
                ..Default::default()
            },
        );
        validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .expect("recipient ATA is authorized");
    }

    #[test]
    fn validate_scope_rejects_ata_funded_by_non_fee_payer() {
        // (a) funding account != the fee payer at index 0.
        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let tx = build_activation_tx_with_ata(
            &config,
            &subscriber,
            AtaOverrides {
                payer: Some(Pubkey::new_unique()),
                ..Default::default()
            },
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .unwrap_err();
        assert!(
            err.message
                .contains("ATA payer must be the transaction fee payer"),
            "{}",
            err.message
        );
    }

    #[test]
    fn validate_scope_rejects_ata_wrong_mint() {
        // (b) ATA created for a mint other than the plan mint.
        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let tx = build_activation_tx_with_ata(
            &config,
            &subscriber,
            AtaOverrides {
                mint: Some(Pubkey::new_unique()),
                ..Default::default()
            },
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .unwrap_err();
        assert!(
            err.message
                .contains("ATA creation mint does not match the plan mint"),
            "{}",
            err.message
        );
    }

    #[test]
    fn validate_scope_rejects_ata_wrong_owner() {
        // (c) ATA owner is neither subscriber, recipient, nor puller.
        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let tx = build_activation_tx_with_ata(
            &config,
            &subscriber,
            AtaOverrides {
                owner: Some(Pubkey::new_unique()),
                ..Default::default()
            },
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .unwrap_err();
        assert!(
            err.message
                .contains("ATA creation owner is not authorized by the challenge"),
            "{}",
            err.message
        );
    }

    #[test]
    fn validate_scope_rejects_ata_non_canonical_layout() {
        // (d1) Non-idempotent discriminator (Create = 0) is rejected.
        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let tx = build_activation_tx_with_ata(
            &config,
            &subscriber,
            AtaOverrides {
                data: Some(vec![0]),
                ..Default::default()
            },
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .unwrap_err();
        assert!(
            err.message
                .contains("Only idempotent ATA creation is allowed"),
            "{}",
            err.message
        );

        // (d2) Wrong account count (canonical is 6) is rejected.
        let tx = build_activation_tx_with_ata(
            &config,
            &subscriber,
            AtaOverrides {
                accounts: Some(vec![5, 6, 7, 8, 9]),
                ..Default::default()
            },
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .unwrap_err();
        assert!(
            err.message
                .contains("Unexpected ATA creation account layout"),
            "{}",
            err.message
        );
    }

    #[test]
    fn validate_scope_rejects_ata_wrong_token_program() {
        // (d3) Token program does not match the configured one. Use the other
        // supported token program so it passes the "supported" gate but fails
        // the configured-program equality gate.
        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let other_token_program = parse_pubkey(programs::TOKEN_2022_PROGRAM, "t22").unwrap();
        // Re-derive the ATA against the substituted token program so the only
        // failing check is the token-program mismatch, not the re-derivation.
        let mint = parse_pubkey(&config.mint, "mint").unwrap();
        let ata_program = parse_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID, "ata").unwrap();
        let (ata_addr, _) = Pubkey::find_program_address(
            &[
                subscriber.as_ref(),
                other_token_program.as_ref(),
                mint.as_ref(),
            ],
            &ata_program,
        );
        let tx = build_activation_tx_with_ata(
            &config,
            &subscriber,
            AtaOverrides {
                token_program: Some(other_token_program),
                ata: Some(ata_addr),
                ..Default::default()
            },
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .unwrap_err();
        assert!(
            err.message
                .contains("ATA creation token program does not match the configured token program"),
            "{}",
            err.message
        );
    }

    #[test]
    fn validate_scope_rejects_ata_that_does_not_rederive() {
        // (e) ATA address that does not re-derive from (owner, token, mint).
        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let tx = build_activation_tx_with_ata(
            &config,
            &subscriber,
            AtaOverrides {
                ata: Some(Pubkey::new_unique()),
                ..Default::default()
            },
        );
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .unwrap_err();
        assert!(
            err.message
                .contains("ATA creation address does not match owner/mint/token program"),
            "{}",
            err.message
        );
    }

    #[test]
    fn validate_scope_rejects_ata_privilege_escalation() {
        let config = scope_config();
        let subscriber = Pubkey::new_unique();
        let mut tx = build_activation_tx_with_ata(&config, &subscriber, AtaOverrides::default());
        // Mark every unsigned account readonly, making the ATA account
        // incorrectly readonly even though CreateIdempotent writes it.
        tx.message.header.num_readonly_unsigned_accounts =
            (tx.message.account_keys.len() - 1) as u8;
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            &program_id_str(),
            &config,
            &subscriber,
        )
        .unwrap_err();
        assert!(
            err.message.contains("writable privilege"),
            "{}",
            err.message
        );
    }

    #[test]
    fn compute_budget_rejects_malformed_duplicates_and_expensive_settings() {
        use solana_message::compiled_instruction::CompiledInstruction;

        let instruction = |data: Vec<u8>| CompiledInstruction {
            program_id_index: 0,
            accounts: vec![],
            data,
        };
        let mut limit_seen = false;
        let mut price_seen = false;
        validate_compute_budget_instruction(
            &instruction([vec![2], 200_000u32.to_le_bytes().to_vec()].concat()),
            &mut limit_seen,
            &mut price_seen,
        )
        .expect("maximum compute-unit limit is allowed");

        let err = validate_compute_budget_instruction(
            &instruction([vec![2], 200_001u32.to_le_bytes().to_vec()].concat()),
            &mut false,
            &mut false,
        )
        .unwrap_err();
        assert!(err.message.contains("exceeds maximum"), "{}", err.message);

        let err =
            validate_compute_budget_instruction(&instruction(vec![3]), &mut false, &mut false)
                .unwrap_err();
        assert!(err.message.contains("malformed"), "{}", err.message);

        let err = validate_compute_budget_instruction(
            &instruction([vec![3], 10_001u64.to_le_bytes().to_vec()].concat()),
            &mut false,
            &mut false,
        )
        .unwrap_err();
        assert!(err.message.contains("exceeds maximum"), "{}", err.message);

        let err = validate_compute_budget_instruction(
            &instruction([vec![2], 1u32.to_le_bytes().to_vec()].concat()),
            &mut limit_seen,
            &mut price_seen,
        )
        .unwrap_err();
        assert!(err.message.contains("Duplicate"), "{}", err.message);
    }

    #[test]
    fn validate_scope_rejects_invalid_program_id_string() {
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(&[subscriber], vec![]);
        let err = validate_activation_scope(
            &tx,
            &dummy_request(),
            "not-a-pubkey",
            &scope_config(),
            &scope_subscriber(),
        )
        .unwrap_err();
        assert!(!err.message.is_empty());
    }

    // ── decode_base64_transaction ───────────────────────────────────────

    #[test]
    fn decode_base64_transaction_rejects_bad_base64() {
        let err = decode_base64_transaction("!!!not base64!!!").unwrap_err();
        assert!(err.message.contains("base64 decode"), "{}", err.message);
    }

    #[test]
    fn decode_base64_transaction_rejects_bad_bincode() {
        // Valid base64 but not a bincode-serialised Transaction.
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0xFFu8; 8]);
        let err = decode_base64_transaction(&b64).unwrap_err();
        assert!(err.message.contains("bincode decode"), "{}", err.message);
    }

    #[test]
    fn decode_base64_transaction_round_trips_real_tx() {
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(&[subscriber], vec![(INSTRUCTION_SUBSCRIBE, vec![])]);
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let decoded = decode_base64_transaction(&b64).unwrap();
        assert_eq!(decoded.message.account_keys, tx.message.account_keys);
    }

    // ── co_sign_as_fee_payer ────────────────────────────────────────────

    fn fee_payer_signer_and_key() -> (Arc<dyn solana_keychain::SolanaSigner>, Pubkey) {
        use solana_keychain::{MemorySigner, SolanaSigner};
        let sk = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        let signer = MemorySigner::from_bytes(&kp).expect("kp");
        let pk = signer.pubkey();
        (Arc::new(signer), pk)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn co_sign_fills_fee_payer_slot() {
        let (signer, fee_payer) = fee_payer_signer_and_key();
        let subscriber = Pubkey::new_unique();
        // fee-payer is account_keys[0].
        let mut tx = build_tx(&[fee_payer, subscriber], vec![]);
        assert_eq!(tx.signatures[0], Signature::default());
        co_sign_as_fee_payer(&mut tx, &signer)
            .await
            .expect("co-sign");
        assert_ne!(tx.signatures[0], Signature::default());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn co_sign_rejects_missing_fee_payer_key() {
        let (signer, _fee_payer) = fee_payer_signer_and_key();
        // A tx that does NOT include the fee-payer pubkey in account_keys.
        let other = Pubkey::new_unique();
        let mut tx = build_tx(&[other], vec![]);
        let err = co_sign_as_fee_payer(&mut tx, &signer).await.unwrap_err();
        assert!(err.message.contains("account index 0"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn co_sign_rejects_fee_payer_not_at_index_zero() {
        // The fee-payer key present at a non-zero index (e.g.
        // as the authority of an attacker-inserted instruction) must NOT be
        // co-signed. The old code used `position()` and would sign wherever
        // the key appeared.
        let (signer, fee_payer) = fee_payer_signer_and_key();
        let subscriber = Pubkey::new_unique();
        // subscriber at index 0, fee-payer at index 1.
        let mut tx = build_tx(&[subscriber, fee_payer], vec![]);
        let err = co_sign_as_fee_payer(&mut tx, &signer).await.unwrap_err();
        assert!(err.message.contains("account index 0"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn co_sign_rejects_empty_account_keys() {
        let (signer, _fee_payer) = fee_payer_signer_and_key();
        let mut tx = build_tx(&[Pubkey::new_unique()], vec![]);
        tx.message.account_keys.clear();
        let err = co_sign_as_fee_payer(&mut tx, &signer).await.unwrap_err();
        assert!(err.message.contains("no account keys"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn co_sign_rejects_short_signatures_vec() {
        // Fee payer correctly at index 0, but the signatures vec is empty, so
        // there is no slot 0 to fill.
        let (signer, fee_payer) = fee_payer_signer_and_key();
        let mut tx = build_tx(&[fee_payer], vec![]);
        tx.signatures.clear();
        let err = co_sign_as_fee_payer(&mut tx, &signer).await.unwrap_err();
        assert!(
            err.message.contains("signatures vec is shorter"),
            "{}",
            err.message
        );
    }

    // ── verify_credential pre-RPC error branches ────────────────────────

    /// Build a credential whose challenge is issued by `server` (so HMAC +
    /// pinned fields pass) carrying the given activation payload.
    fn credential_for_server(
        server: &SubscriptionServer,
        payload: ActivatePayload,
    ) -> PaymentCredential {
        let challenge = server
            .subscription_challenge("10000000")
            .expect("challenge");
        PaymentCredential::new(challenge.to_echo(), payload)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_wrong_method() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let challenge = server.subscription_challenge("10000000").unwrap();
        let mut echo = challenge.to_echo();
        // Corrupt the id so it's recomputed to match, but flip the method.
        // Instead: build a fresh challenge with a mismatched method via a
        // server that pins a different method is not possible; directly
        // tamper the echoed method — HMAC will then mismatch first, so we
        // recompute the id to bind the tampered method.
        echo.method = "notsolana".into();
        echo.id = compute_challenge_id(
            &server.challenge_binding_secret,
            &server.realm,
            echo.method.as_str(),
            echo.intent.as_str(),
            echo.request.raw(),
            echo.expires.as_deref(),
            echo.digest.as_deref(),
            echo.opaque.as_ref().map(|o| o.raw()),
        );
        let credential = PaymentCredential::new(
            echo,
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some("AQAAAA==".into()),
                signature: None,
            },
        );
        let err = server.verify_credential(&credential).await.unwrap_err();
        assert!(err.message.contains("does not match"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_wrong_intent() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let challenge = server.subscription_challenge("10000000").unwrap();
        let mut echo = challenge.to_echo();
        echo.intent = "charge".into();
        echo.id = compute_challenge_id(
            &server.challenge_binding_secret,
            &server.realm,
            echo.method.as_str(),
            echo.intent.as_str(),
            echo.request.raw(),
            echo.expires.as_deref(),
            echo.digest.as_deref(),
            echo.opaque.as_ref().map(|o| o.raw()),
        );
        let credential = PaymentCredential::new(
            echo,
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some("AQAAAA==".into()),
                signature: None,
            },
        );
        let err = server.verify_credential(&credential).await.unwrap_err();
        assert!(
            err.message.contains("not a subscription"),
            "{}",
            err.message
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_wrong_realm() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let challenge = server.subscription_challenge("10000000").unwrap();
        let mut echo = challenge.to_echo();
        echo.realm = "other-realm".into();
        echo.id = compute_challenge_id(
            &server.challenge_binding_secret,
            &server.realm,
            echo.method.as_str(),
            echo.intent.as_str(),
            echo.request.raw(),
            echo.expires.as_deref(),
            echo.digest.as_deref(),
            echo.opaque.as_ref().map(|o| o.raw()),
        );
        let credential = PaymentCredential::new(
            echo,
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some("AQAAAA==".into()),
                signature: None,
            },
        );
        let err = server.verify_credential(&credential).await.unwrap_err();
        assert!(err.message.contains("realm"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_mint_mismatch() {
        // Two servers with different mints but the SAME secret + realm, so
        // the HMAC passes but the decoded mint won't match.
        let mut cfg_a = make_config();
        cfg_a.challenge_binding_secret = "shared-secret".into();
        cfg_a.realm = "shared-realm".into();
        let mut cfg_b = cfg_a.clone();
        cfg_b.mint = keypair_base58(); // different mint
        let server_a = SubscriptionServer::new(cfg_a).expect("a");
        let server_b = SubscriptionServer::new(cfg_b).expect("b");
        // Challenge issued by A (its mint), verified by B (different mint).
        let challenge = server_a.subscription_challenge("10000000").unwrap();
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some("AQAAAA==".into()),
                signature: None,
            },
        );
        let err = server_b.verify_credential(&credential).await.unwrap_err();
        assert!(err.message.contains("mint"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_recipient_mismatch() {
        let mut cfg_a = make_config();
        cfg_a.challenge_binding_secret = "shared-secret2".into();
        cfg_a.realm = "shared-realm2".into();
        let mut cfg_b = cfg_a.clone();
        cfg_b.recipient = keypair_base58(); // different recipient, same mint
        let server_a = SubscriptionServer::new(cfg_a).expect("a");
        let server_b = SubscriptionServer::new(cfg_b).expect("b");
        let challenge = server_a.subscription_challenge("10000000").unwrap();
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some("AQAAAA==".into()),
                signature: None,
            },
        );
        let err = server_b.verify_credential(&credential).await.unwrap_err();
        assert!(err.message.contains("recipient"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_unsupported_payload_type() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let credential = credential_for_server(
            &server,
            ActivatePayload {
                payload_type: "wat".into(),
                transaction: None,
                signature: None,
            },
        );
        let err = server.verify_credential(&credential).await.unwrap_err();
        assert!(
            err.message.contains("Unsupported payload type"),
            "{}",
            err.message
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_transaction_missing_transaction_field() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let credential = credential_for_server(
            &server,
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: None, // missing
                signature: None,
            },
        );
        let err = server.verify_credential(&credential).await.unwrap_err();
        assert!(
            err.message.contains("missing `transaction` field"),
            "{}",
            err.message
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_signature_with_fee_sponsorship() {
        // type="signature" combined with fee sponsorship must be rejected
        // before the push-mode branch.
        use solana_keychain::MemorySigner;
        let mut cfg = make_config();
        cfg.fee_payer = true;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        cfg.fee_payer_signer = Some(Arc::new(MemorySigner::from_bytes(&kp).expect("kp")));
        let server = SubscriptionServer::new(cfg).expect("server");
        let credential = credential_for_server(
            &server,
            ActivatePayload {
                payload_type: "signature".into(),
                transaction: None,
                signature: Some("5J8Sig".into()),
            },
        );
        let err = server.verify_credential(&credential).await.unwrap_err();
        assert!(err.message.contains("fee sponsorship"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_transaction_bad_base64() {
        let server = SubscriptionServer::new(make_config()).expect("server");
        let credential = credential_for_server(
            &server,
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some("!!!bad!!!".into()),
                signature: None,
            },
        );
        let err = server.verify_credential(&credential).await.unwrap_err();
        assert!(err.message.contains("base64 decode"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_transaction_empty_account_keys() {
        // A real (decodable) tx whose account_keys are empty exercises the
        // extract_subscriber "no account keys" branch through verify.
        use solana_hash::Hash;
        use solana_message::{Message, MessageHeader};
        let server = SubscriptionServer::new(make_config()).expect("server");
        let tx = Transaction {
            signatures: vec![],
            message: Message {
                header: MessageHeader {
                    num_required_signatures: 0,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 0,
                },
                account_keys: vec![],
                recent_blockhash: Hash::default(),
                instructions: vec![],
            },
        };
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let credential = credential_for_server(
            &server,
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(b64),
                signature: None,
            },
        );
        let err = server.verify_credential(&credential).await.unwrap_err();
        assert!(err.message.contains("no account keys"), "{}", err.message);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rejects_transaction_missing_scope() {
        // A decodable tx with a valid subscriber but no subscribe/transfer
        // instructions reaches validate_activation_scope and fails there.
        let server = SubscriptionServer::new(make_config()).expect("server");
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(&[subscriber], vec![]); // no instructions
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let credential = credential_for_server(
            &server,
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(b64),
                signature: None,
            },
        );
        let err = server.verify_credential(&credential).await.unwrap_err();
        assert!(err.message.contains("missing subscribe"), "{}", err.message);
    }

    // ── validate_terms_and_build_receipt (post-fetch terms check) ───────

    fn make_delegation_view(
        plan_pda: Pubkey,
        amount: u64,
        period_hours: u64,
        pulled: u64,
    ) -> SubscriptionDelegationView {
        SubscriptionDelegationView {
            subscriber: Pubkey::new_unique(),
            plan_pda,
            amount_per_period: amount,
            period_hours,
            current_period_start_ts: 1_700_000_000,
            amount_pulled_in_period: pulled,
        }
    }

    fn terms_request(amount: &str) -> SubscriptionRequest {
        SubscriptionRequest {
            amount: amount.into(),
            currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "30".into(), // 30 days => 720 hours
            recipient: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".into(),
            subscription_expires: Some("2030-01-01T00:00:00Z".into()),
            ..Default::default()
        }
    }

    #[test]
    fn terms_check_success_builds_subscription_receipt() {
        let plan_pda = Pubkey::new_unique();
        let sub_pda = Pubkey::new_unique();
        let delegation = make_delegation_view(plan_pda, 720, 720, 720);
        let receipt = validate_terms_and_build_receipt(
            &delegation,
            &terms_request("720"),
            &plan_pda,
            &sub_pda,
            "PLAN123",
            "chal-id",
            Some("sig123".into()),
        )
        .expect("valid terms");
        match receipt {
            ReceiptKind::Subscription { base, extensions } => {
                assert_eq!(base.reference, sub_pda.to_string());
                assert_eq!(base.challenge_id, "chal-id");
                assert_eq!(extensions.subscription_id, sub_pda.to_string());
                assert_eq!(extensions.plan_id, "PLAN123");
                assert_eq!(extensions.period_index, "0");
                assert_eq!(extensions.activation_signature.as_deref(), Some("sig123"));
                assert_eq!(
                    extensions.expires_at.as_deref(),
                    Some("2030-01-01T00:00:00Z")
                );
                // period_start = 1_700_000_000 (2023-11-14T22:13:20Z);
                // period_end = start + 720h.
                assert_eq!(extensions.period_start_ts, "2023-11-14T22:13:20Z");
            }
            other => panic!("expected Subscription receipt, got {other:?}"),
        }
    }

    #[test]
    fn terms_check_rejects_amount_mismatch() {
        let plan_pda = Pubkey::new_unique();
        let delegation = make_delegation_view(plan_pda, 999, 720, 999);
        let err = validate_terms_and_build_receipt(
            &delegation,
            &terms_request("720"), // expects 720, delegation has 999
            &plan_pda,
            &Pubkey::new_unique(),
            "PLAN",
            "id",
            None,
        )
        .unwrap_err();
        assert!(err.message.contains("amount mismatch"), "{}", err.message);
    }

    #[test]
    fn terms_check_rejects_period_mismatch() {
        let plan_pda = Pubkey::new_unique();
        // amount matches, period_hours (24) != expected 720.
        let delegation = make_delegation_view(plan_pda, 720, 24, 720);
        let err = validate_terms_and_build_receipt(
            &delegation,
            &terms_request("720"),
            &plan_pda,
            &Pubkey::new_unique(),
            "PLAN",
            "id",
            None,
        )
        .unwrap_err();
        assert!(err.message.contains("period mismatch"), "{}", err.message);
    }

    #[test]
    fn terms_check_rejects_plan_mismatch() {
        let expected_plan = Pubkey::new_unique();
        let wrong_plan = Pubkey::new_unique();
        // amount + period match, but delegation.plan_pda differs.
        let delegation = make_delegation_view(wrong_plan, 720, 720, 720);
        let err = validate_terms_and_build_receipt(
            &delegation,
            &terms_request("720"),
            &expected_plan,
            &Pubkey::new_unique(),
            "PLAN",
            "id",
            None,
        )
        .unwrap_err();
        assert!(err.message.contains("plan mismatch"), "{}", err.message);
    }

    #[test]
    fn terms_check_rejects_uncharged_first_period() {
        let plan_pda = Pubkey::new_unique();
        // amount + period + plan match, but nothing was pulled (0 != 720).
        let delegation = make_delegation_view(plan_pda, 720, 720, 0);
        let err = validate_terms_and_build_receipt(
            &delegation,
            &terms_request("720"),
            &plan_pda,
            &Pubkey::new_unique(),
            "PLAN",
            "id",
            None,
        )
        .unwrap_err();
        assert!(
            err.message
                .contains("did not execute the first-period charge"),
            "{}",
            err.message
        );
    }

    #[test]
    fn terms_check_rejects_non_integer_amount() {
        let plan_pda = Pubkey::new_unique();
        let delegation = make_delegation_view(plan_pda, 720, 720, 720);
        let err = validate_terms_and_build_receipt(
            &delegation,
            &terms_request("not-a-number"),
            &plan_pda,
            &Pubkey::new_unique(),
            "PLAN",
            "id",
            None,
        )
        .unwrap_err();
        assert!(
            err.message.contains("not a positive integer"),
            "{}",
            err.message
        );
    }

    #[test]
    fn terms_check_rejects_invalid_period_request() {
        let plan_pda = Pubkey::new_unique();
        let delegation = make_delegation_view(plan_pda, 720, 720, 720);
        // period_count that maps out of [1, 8760] hours (400 days => 9600h).
        let mut req = terms_request("720");
        req.period_count = "400".into();
        let err = validate_terms_and_build_receipt(
            &delegation,
            &req,
            &plan_pda,
            &Pubkey::new_unique(),
            "PLAN",
            "id",
            None,
        )
        .unwrap_err();
        assert!(!err.message.is_empty());
    }

    // ── RPC method error paths (dead endpoint) ──────────────────────────
    //
    // These exercise the RPC round-trip + error `.map_err` closures without
    // a live validator: a server pointed at a closed port fails fast with a
    // connection-refused error, driving the not_found / transaction_failed /
    // network_error branches.

    fn server_with_dead_rpc() -> SubscriptionServer {
        let mut cfg = make_config();
        // Port 1 refuses connections immediately.
        cfg.rpc_url = Some("http://127.0.0.1:1".into());
        SubscriptionServer::new(cfg).expect("server")
    }

    /// Build the 155-byte on-chain `SubscriptionDelegation` account bytes
    /// for the given plan/subscriber/terms, matching the layout the decoder
    /// reads.
    fn encode_delegation_account(
        subscriber: [u8; 32],
        plan_pda: [u8; 32],
        amount: u64,
        period_hours: u64,
        pulled: u64,
        period_start: i64,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(SUBSCRIPTION_DELEGATION_LEN);
        data.push(2); // discriminator
        data.push(1); // version
        data.push(255); // bump
        data.extend_from_slice(&subscriber); // delegator
        data.extend_from_slice(&plan_pda); // delegatee
        data.extend_from_slice(&[3u8; 32]); // payer
        data.extend_from_slice(&77i64.to_le_bytes()); // init_id
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&period_hours.to_le_bytes());
        data.extend_from_slice(&1_780_000_000i64.to_le_bytes()); // created_at
        data.extend_from_slice(&pulled.to_le_bytes());
        data.extend_from_slice(&period_start.to_le_bytes());
        data.extend_from_slice(&0i64.to_le_bytes()); // expires_at
        data
    }

    /// Spawn a one-shot HTTP server that answers a single JSON-RPC
    /// `getAccountInfo` request with the given account bytes, then returns
    /// the `http://127.0.0.1:<port>` URL to point an RpcClient at.
    fn spawn_mock_getaccount_rpc(account_data: Vec<u8>, owner: Pubkey) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let data_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &account_data);
        let owner_str = owner.to_string();
        std::thread::spawn(move || {
            // Serve several requests (verify makes multiple RPC round-trips:
            // idempotency fetch, signature lookup, terms fetch).
            for _ in 0..12 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let body = format!(
                    "{{\"jsonrpc\":\"2.0\",\"result\":{{\"context\":{{\"slot\":1,\"apiVersion\":\"2.0.0\"}},\"value\":{{\"data\":[\"{data_b64}\",\"base64\"],\"executable\":false,\"lamports\":1000000,\"owner\":\"{owner_str}\",\"rentEpoch\":0,\"space\":{}}}}},\"id\":1}}",
                    account_data.len()
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        url
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fetch_subscription_delegation_decodes_account_from_rpc() {
        let mut cfg = make_config();
        let plan_pda = parse_pubkey(&cfg.plan_id, "plan").unwrap();
        let subscriber = Pubkey::new_unique();
        let program = parse_pubkey(SUBSCRIPTIONS_PROGRAM_ID, "prog").unwrap();
        let account = encode_delegation_account(
            subscriber.to_bytes(),
            plan_pda.to_bytes(),
            720,
            720,
            720,
            1_700_000_000,
        );
        let url = spawn_mock_getaccount_rpc(account, program);
        cfg.rpc_url = Some(url);
        let server = SubscriptionServer::new(cfg).expect("server");
        let pda = Pubkey::new_unique();
        let view = server
            .fetch_subscription_delegation(&pda)
            .await
            .expect("mock RPC returns a decodable delegation");
        assert_eq!(view.amount_per_period, 720);
        assert_eq!(view.period_hours, 720);
        assert_eq!(view.plan_pda, plan_pda);
        assert_eq!(view.current_period_start_ts, 1_700_000_000);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn existing_delegation_does_not_prove_never_broadcast_activation_signature() {
        // Point the server at a mock RPC that always returns a valid
        // delegation account. verify_credential then: extracts the
        // subscriber, validates scope, sees the delegation already exists
        // (idempotent branch — skips broadcast), fetches it again, checks
        // the terms, and builds the success receipt. Exercises the RPC
        // success path end-to-end without a live validator.
        let mut cfg = make_config();
        let plan_pda = parse_pubkey(&cfg.plan_id, "plan").unwrap();
        let program = parse_pubkey(SUBSCRIPTIONS_PROGRAM_ID, "prog").unwrap();
        // The delegation's amount/period must match the challenge terms:
        // amount = 720 base units, Day * 30 => 720 period hours.
        let subscriber = Pubkey::new_unique();
        let account = encode_delegation_account(
            subscriber.to_bytes(),
            plan_pda.to_bytes(),
            720,
            720,
            720,
            1_700_000_000,
        );
        let url = spawn_mock_getaccount_rpc(account, program);
        cfg.rpc_url = Some(url);
        let server = SubscriptionServer::new(cfg).expect("server");

        // Build an activation tx with a valid subscriber + subscribe/transfer
        // scope, and issue a challenge for amount "720" so terms match.
        let tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
            ],
        );
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let challenge = server.subscription_challenge("720").expect("challenge");
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(b64),
                signature: None,
            },
        );

        let err = server
            .verify_credential(&credential)
            .await
            .expect_err("an unrelated existing delegation must not prove this signature landed");
        assert!(
            err.message.contains("getSignatureStatuses")
                || err.message.contains("exact submitted activation signature"),
            "{}",
            err.message
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fetch_subscription_delegation_errors_on_dead_rpc() {
        let server = server_with_dead_rpc();
        let pda = Pubkey::new_unique();
        let err = server
            .fetch_subscription_delegation(&pda)
            .await
            .expect_err("dead RPC must error");
        assert!(!err.message.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn exact_signature_confirmation_errors_on_dead_rpc() {
        let server = server_with_dead_rpc();
        let signature = Signature::new_unique().to_string();
        let err = server
            .is_signature_confirmed(&signature)
            .await
            .expect_err("dead RPC must error");
        assert!(!err.message.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn broadcast_and_confirm_errors_on_dead_rpc() {
        let server = server_with_dead_rpc();
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
            ],
        );
        let err = server
            .broadcast_and_confirm(&tx)
            .await
            .expect_err("dead RPC must error");
        assert!(!err.message.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_with_fee_sponsorship_cosigns_then_hits_rpc() {
        // A fee-payer-configured server drives verify_credential through the
        // co_sign_as_fee_payer branch before the (dead) RPC broadcast.
        use solana_keychain::{MemorySigner, SolanaSigner};
        let mut cfg = make_config();
        cfg.rpc_url = Some("http://127.0.0.1:1".into());
        cfg.fee_payer = true;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        let signer = MemorySigner::from_bytes(&kp).expect("kp");
        let fee_payer = signer.pubkey();
        cfg.fee_payer_signer = Some(Arc::new(signer));
        let server = SubscriptionServer::new(cfg).expect("server");

        // Build an activation tx: fee-payer at index 0, subscriber next,
        // carrying subscribe + transfer instructions so scope validation
        // passes and co-signing has a slot to fill.
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(
            &[fee_payer, subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
            ],
        );
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let credential = credential_for_server(
            &server,
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(b64),
                signature: None,
            },
        );
        let err = server
            .verify_credential(&credential)
            .await
            .expect_err("dead RPC after co-sign must error");
        assert!(!err.message.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_hits_rpc_and_errors_on_dead_endpoint() {
        // Drive the full verify path through instruction-scope validation
        // up to the broadcast, which fails against the dead RPC. Covers the
        // settlement branch of verify_credential (subscriber extraction +
        // scope check + broadcast attempt).
        let server = server_with_dead_rpc();
        let subscriber = Pubkey::new_unique();
        let tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
            ],
        );
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let credential = credential_for_server(
            &server,
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(b64),
                signature: None,
            },
        );
        let err = server
            .verify_credential(&credential)
            .await
            .expect_err("dead RPC must surface an error");
        assert!(!err.message.is_empty());
    }

    // ── format_rfc3339_seconds edge branches ────────────────────────────

    #[test]
    fn format_rfc3339_handles_jan_feb_and_pre_epoch() {
        // A date in January exercises the `mp >= 10` month remap and the
        // `mo <= 2` year adjustment.
        // 2021-01-31T00:00:00Z = 1612051200
        assert_eq!(
            format_rfc3339_seconds(1_612_051_200),
            "2021-01-31T00:00:00Z"
        );
        // A February date.
        // 2020-02-29T23:59:59Z = 1583020799 (leap day)
        assert_eq!(
            format_rfc3339_seconds(1_583_020_799),
            "2020-02-29T23:59:59Z"
        );
        // A pre-epoch (negative) timestamp exercises the `z < 0` era branch.
        // 1969-12-31T00:00:00Z = -86400
        assert_eq!(format_rfc3339_seconds(-86_400), "1969-12-31T00:00:00Z");
    }

    // ── Activation replay marker ────────────────────────────────────────
    //
    // A duplicate activation credential must be rejected up front — before
    // any RPC broadcast or receipt re-issuance — once the first activation
    // has landed. The marker is keyed by the activation signature with the
    // same key shape the TypeScript port writes
    // (`solana-subscription:consumed:<sig>`), so a shared store rejects the
    // replay across the two language runtimes.

    /// Per-method request counters for the stateful mock below, so a test
    /// can assert that a rejected replay performs zero RPC work.
    #[derive(Default)]
    struct RpcCounters {
        get_account: usize,
        send: usize,
        get_signatures: usize,
    }

    /// Spawn a stateful, counting JSON-RPC mock for the activation happy
    /// path. `getAccountInfo` returns account-not-found on its first call
    /// (so `verify_credential` sees the delegation does not yet exist and
    /// broadcasts) and the encoded delegation on every later call (so the
    /// post-broadcast terms fetch succeeds). `sendTransaction` echoes the
    /// submitted transaction's own first signature — matching what a real
    /// node returns — and every method bumps a shared counter.
    fn spawn_counting_activation_rpc(
        account_data: Vec<u8>,
        owner: Pubkey,
    ) -> (String, Arc<std::sync::Mutex<RpcCounters>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let data_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &account_data);
        let owner_str = owner.to_string();
        let account_len = account_data.len();
        let counters = Arc::new(std::sync::Mutex::new(RpcCounters::default()));
        let thread_counters = counters.clone();
        std::thread::spawn(move || {
            for _ in 0..64 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let body_start = buf[..n]
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(0);
                let req: serde_json::Value =
                    serde_json::from_slice(&buf[body_start..n]).unwrap_or(serde_json::Value::Null);
                let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
                let params = req
                    .get("params")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                let result = {
                    let mut c = thread_counters.lock().unwrap();
                    match method {
                        "getLatestBlockhash" => serde_json::json!({
                            "context": {"slot": 1},
                            "value": {"blockhash": "11111111111111111111111111111111", "lastValidBlockHeight": 1000},
                        }),
                        "getAccountInfo" => {
                            c.get_account += 1;
                            if c.get_account == 1 {
                                // First fetch: idempotency probe — not found.
                                serde_json::json!({"context": {"slot": 1}, "value": serde_json::Value::Null})
                            } else {
                                serde_json::json!({
                                    "context": {"slot": 1},
                                    "value": {
                                        "data": [data_b64, "base64"],
                                        "executable": false,
                                        "lamports": 1_000_000u64,
                                        "owner": owner_str,
                                        "rentEpoch": 0,
                                        "space": account_len,
                                    },
                                })
                            }
                        }
                        "sendTransaction" => {
                            c.send += 1;
                            let sig = params
                                .get(0)
                                .and_then(|p| p.as_str())
                                .and_then(|encoded| {
                                    let bytes = base64::Engine::decode(
                                        &base64::engine::general_purpose::STANDARD,
                                        encoded,
                                    )
                                    .ok()?;
                                    let tx: solana_transaction::versioned::VersionedTransaction =
                                        bincode::deserialize(&bytes).ok()?;
                                    Some(tx.signatures.first()?.to_string())
                                })
                                .unwrap_or_default();
                            serde_json::Value::String(sig)
                        }
                        "getSignatureStatuses" => serde_json::json!({
                            "context": {"slot": 1},
                            "value": [{
                                "slot": 1,
                                "confirmations": serde_json::Value::Null,
                                "status": {"Ok": serde_json::Value::Null},
                                "err": serde_json::Value::Null,
                                "confirmationStatus": "finalized",
                            }],
                        }),
                        "getSignaturesForAddress" => {
                            c.get_signatures += 1;
                            serde_json::json!([])
                        }
                        _ => serde_json::Value::Null,
                    }
                };

                let body =
                    serde_json::json!({"jsonrpc": "2.0", "result": result, "id": id}).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        (url, counters)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_credential_rejects_replayed_activation_and_writes_ts_keyed_marker() {
        // Drive one activation through the full verify path against the
        // stateful counting mock: it broadcasts, confirms, fetches the
        // delegation, and issues a receipt. The replay store must then carry
        // `solana-subscription:consumed:<sig>` so a second, identical
        // credential is rejected before any further broadcast/receipt work.
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let mut cfg = make_config();
        cfg.store = Some(store.clone());
        let plan_pda = parse_pubkey(&cfg.plan_id, "plan").unwrap();
        let program = parse_pubkey(SUBSCRIPTIONS_PROGRAM_ID, "prog").unwrap();
        let subscriber = Pubkey::new_unique();
        let account = encode_delegation_account(
            subscriber.to_bytes(),
            plan_pda.to_bytes(),
            720,
            720,
            720,
            1_700_000_000,
        );
        let (url, counters) = spawn_counting_activation_rpc(account, program);
        cfg.rpc_url = Some(url);
        let server = SubscriptionServer::new(cfg).expect("server");

        // Build a client-signed activation tx with a distinctive first
        // signature so the marker key is deterministic and easy to assert.
        let mut tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
            ],
        );
        tx.signatures[0] = Signature::from([7u8; 64]);
        let expected_sig = tx.signatures[0].to_string();
        let expected_key = format!("solana-subscription:consumed:{expected_sig}");
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let challenge = server.subscription_challenge("720").expect("challenge");
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(b64),
                signature: None,
            },
        );

        // First activation: succeeds, broadcasts exactly once.
        server
            .verify_credential(&credential)
            .await
            .expect("first activation succeeds");
        {
            let c = counters.lock().unwrap();
            assert_eq!(c.send, 1, "first activation broadcasts exactly once");
        }

        // The consumed marker must be written under the TS-compatible key so
        // a shared cross-language store rejects the replay.
        assert_eq!(
            store.get(&expected_key).await.unwrap(),
            Some(serde_json::json!(true)),
            "activation marker must be keyed as solana-subscription:consumed:<sig>",
        );

        let send_before_replay = counters.lock().unwrap().send;
        let get_account_before_replay = counters.lock().unwrap().get_account;

        // Second, identical credential: rejected up front as a replay.
        let err = server
            .verify_credential(&credential)
            .await
            .expect_err("replayed activation must be rejected");
        assert_eq!(
            err.code,
            Some("signature-consumed"),
            "replay must surface a signature-consumed error, got: {err:?}",
        );

        // The replay performed no further RPC work: no second broadcast and
        // no additional account fetch / receipt re-issuance.
        let c = counters.lock().unwrap();
        assert_eq!(
            c.send, send_before_replay,
            "replay must not broadcast a second transaction",
        );
        assert_eq!(
            c.get_account, get_account_before_replay,
            "replay must be rejected before any RPC account fetch",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_identical_activations_admit_exactly_one() {
        // The core TOCTOU gate. Two concurrent activation verifications with
        // the SAME activation signature race through one shared store. The
        // atomic `put_if_absent` claim admits exactly one — the other is
        // rejected as `signature-consumed`. The winner runs the full happy
        // path against the counting mock and keeps its marker (it never fails,
        // so it never releases), so the loser observes the claim no matter how
        // the two tasks interleave.
        //
        // Against the OLD non-atomic get-then-put, both verifications would
        // pass the get() check before either wrote the marker and BOTH would
        // broadcast + issue a receipt — zero `signature-consumed`, so this test
        // fails. It passes only with the atomic claim.
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let mut cfg = make_config();
        cfg.store = Some(store.clone());
        let plan_pda = parse_pubkey(&cfg.plan_id, "plan").unwrap();
        let program = parse_pubkey(SUBSCRIPTIONS_PROGRAM_ID, "prog").unwrap();
        let subscriber = Pubkey::new_unique();
        let account = encode_delegation_account(
            subscriber.to_bytes(),
            plan_pda.to_bytes(),
            720,
            720,
            720,
            1_700_000_000,
        );
        let (url, counters) = spawn_counting_activation_rpc(account, program);
        cfg.rpc_url = Some(url);
        let server = Arc::new(SubscriptionServer::new(cfg).expect("server"));

        let mut tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
            ],
        );
        tx.signatures[0] = Signature::from([9u8; 64]);
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let challenge = server.subscription_challenge("720").expect("challenge");
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(b64),
                signature: None,
            },
        );

        let s1 = server.clone();
        let s2 = server.clone();
        let c1 = credential.clone();
        let c2 = credential.clone();
        let h1 = tokio::spawn(async move { s1.verify_credential(&c1).await });
        let h2 = tokio::spawn(async move { s2.verify_credential(&c2).await });
        let r1 = h1.await.expect("task 1 joins");
        let r2 = h2.await.expect("task 2 joins");

        let ok_count = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
        let consumed_count = [&r1, &r2]
            .iter()
            .filter(|r| matches!(r, Err(e) if e.code == Some("signature-consumed")))
            .count();
        assert_eq!(
            ok_count, 1,
            "exactly one activation must succeed, got r1={r1:?} r2={r2:?}",
        );
        assert_eq!(
            consumed_count, 1,
            "the loser must be rejected as signature-consumed, got r1={r1:?} r2={r2:?}",
        );

        // Exactly one broadcast reached the chain — the second activation was
        // rejected before it could re-settle.
        assert_eq!(
            counters.lock().unwrap().send,
            1,
            "only the winning activation may broadcast",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn broadcast_failure_releases_claim_for_retry() {
        // Release-on-failure. The claim is taken atomically up front, but a
        // broadcast failure afterwards must delete the marker so a legitimate
        // client can retry — otherwise a transient RPC error would permanently
        // brick the activation signature. The dead RPC makes broadcast fail
        // after the claim; the retry must NOT be rejected as consumed.
        //
        // Against the OLD get-then-put, the marker was only written AFTER a
        // successful broadcast, so a failed broadcast left no marker and this
        // assertion was vacuous. With the atomic upfront claim it is load-
        // bearing: the marker exists after the claim and MUST be released on
        // the broadcast error path.
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let mut cfg = make_config();
        cfg.store = Some(store.clone());
        // Port 1 refuses connections immediately, so broadcast_and_confirm
        // errors after the claim.
        cfg.rpc_url = Some("http://127.0.0.1:1".into());
        let server = SubscriptionServer::new(cfg).expect("server");

        let subscriber = Pubkey::new_unique();
        let mut tx = build_tx(
            &[subscriber],
            vec![
                (INSTRUCTION_SUBSCRIBE, vec![]),
                (INSTRUCTION_TRANSFER_SUBSCRIPTION, vec![]),
            ],
        );
        tx.signatures[0] = Signature::from([5u8; 64]);
        let sig = tx.signatures[0].to_string();
        let consumed_key = format!("solana-subscription:consumed:{sig}");
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let credential = credential_for_server(
            &server,
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(b64),
                signature: None,
            },
        );

        // First attempt: broadcast fails against the dead RPC.
        let err = server
            .verify_credential(&credential)
            .await
            .expect_err("dead RPC must fail the broadcast");
        assert_ne!(
            err.code,
            Some("signature-consumed"),
            "the first attempt is a broadcast failure, not a replay: {err:?}",
        );

        // The claim must have been released so the signature is not bricked.
        assert_eq!(
            store.get(&consumed_key).await.unwrap(),
            None,
            "a broadcast failure must release the activation claim for retry",
        );

        // Retry: still fails on the dead RPC, but MUST NOT be rejected as a
        // replay — proving the marker was released rather than kept.
        let err = server
            .verify_credential(&credential)
            .await
            .expect_err("retry still hits the dead RPC");
        assert_ne!(
            err.code,
            Some("signature-consumed"),
            "a retry after a released claim must not be rejected as consumed: {err:?}",
        );
    }
}
