//! Resource-server handler for the SVM `batch-settlement` scheme.
//!
//! The client deposits once into an escrow payment channel, then signs a
//! cumulative Ed25519 voucher per request. This server verifies each voucher
//! offchain, serves immediately, and redeems the accumulated vouchers onchain
//! later, in batches — so no request ever waits on a Solana transaction.
//!
//! # Roles
//!
//! This server self-facilitates: it holds the `feePayer` signer and talks to
//! the chain directly, the same shape as [`crate::x402::server::upto`]. That
//! one key is the transaction fee payer, the channel `rent_payer`, and the
//! zero-share channel `payee` — a lifecycle authority that can always seal and
//! reclaim an abandoned channel, but can never advance the settled watermark,
//! because only the client-controlled `payerAuthorizer` signs vouchers.
//!
//! # Request lifecycle (the `authorization` flow)
//!
//! 1. [`X402BatchSettlement::verify_payment`] runs before the resource handler
//!    and is read-only: it checks the voucher and reserves the channel.
//! 2. [`X402BatchSettlement::settle_payment`] durably commits the watermark and
//!    broadcasts any deposit transaction.
//! 3. The route handler runs only after that commitment succeeds. This prevents
//!    a successful handler execution from being replayed with the same voucher.
//!
//! Redemption is out of band: [`X402BatchSettlement::claim`] advances the
//! onchain watermark from stored vouchers and [`X402BatchSettlement::settle`]
//! pays the claimed delta to `payTo`.
//!
//! See `specs/schemes/batch-settlement/scheme_batch_settlement_svm.md`.

use dashmap::DashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

use crate::core::payment_channels as pc;
use crate::core::payment_channels::generated::accounts::Channel;
use crate::core::settlement::packing::{pack, ChannelInstructionGroup};
use crate::core::store::{
    BatchReservation, ChannelState, ChannelStore, MemoryChannelStore, PendingSetup,
    CHANNEL_STATE_SCHEMA_VERSION, CHARGE_RESERVATION_LEASE,
};

use crate::x402::error::Error;
use crate::x402::protocol::schemes::batch_settlement::{
    check_channel_config, check_no_cooperative_close, check_token_program, check_voucher,
    check_withdraw_delay, derive_channel_id, errors as codes, setup_form_from_transaction,
    BatchChannelConfig, BatchError, BatchExtra, BatchPayload, BatchPaymentPayload,
    BatchRequiredEnvelope, BatchRequirements, BatchSettlementExtra, BatchSettlementResponse,
    ChannelStateSnapshot, SetupForm, TransactionExpectations, VoucherState,
    BATCH_SETTLEMENT_SCHEME, MAX_CLAIMS_PER_BATCH, MIN_WITHDRAW_DELAY_SECONDS, VOUCHER_EXPIRES_AT,
};
use crate::x402::protocol::schemes::exact::{
    caip2_network_for_cluster, default_rpc_url, default_token_program_for_currency, ResourceInfo,
};
use crate::x402::server::upto::cosign_operator_fee_payer;
use crate::x402::{PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, X402_VERSION_V2};

/// `ChannelStatus::Open` discriminant in the generated client.
const CHANNEL_STATUS_OPEN: u8 = 0;

/// `ChannelStatus::Closing` discriminant.
const CHANNEL_STATUS_CLOSING: u8 = 2;

/// `ChannelStatus::Distributed` discriminant.
const CHANNEL_STATUS_DISTRIBUTED: u8 = 3;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn batch_err(code: &'static str, detail: impl Into<String>) -> Error {
    BatchError::new(code, detail).into()
}

/// Fetch and decode a channel account with the blocking RPC client. Factored out
/// of [`X402BatchSettlement::lookup_channel`] so the reconcile path can run it on
/// a blocking thread (via `spawn_blocking`) instead of stalling an async worker:
/// the sync `RpcClient` call otherwise blocks a Tokio runtime thread for a full
/// RPC round-trip on every stale-snapshot refresh, which under load serializes
/// unrelated paid requests and collapses gateway throughput.
fn rpc_lookup_channel(rpc: &RpcClient, channel_id: &Pubkey) -> Result<Option<Channel>, Error> {
    let account = rpc
        .get_account_with_commitment(channel_id, rpc.commitment())
        .map_err(|e| Error::Rpc(format!("channel account fetch failed: {e}")))?
        .value;
    account
        .map(|account| {
            Channel::from_bytes(&account.data)
                .map_err(|e| Error::Other(format!("channel decode failed: {e}")))
        })
        .transpose()
}

/// Simulate, broadcast, and confirm a co-signed deposit/top-up with the
/// blocking RPC client. Factored out of
/// [`X402BatchSettlement::broadcast_client_transaction`] so it can run on a
/// blocking thread (via `spawn_blocking`): `simulate_transaction` and
/// `send_and_confirm_transaction` otherwise block a Tokio runtime thread for
/// the full round trip — for `send_and_confirm_transaction`, the entire
/// confirm-poll loop — which under concurrent channel opens starves the
/// runtime, collapsing provisioning throughput and, via client-side timeouts
/// and retries, amplifying `sendTransaction`/`getSignatureStatuses` volume.
fn broadcast_and_confirm_deposit(
    rpc: &RpcClient,
    tx: &VersionedTransaction,
) -> Result<String, Error> {
    let signature = *tx
        .signatures
        .first()
        .ok_or_else(|| Error::Other("transaction has no signature slot".into()))?;
    if matches!(rpc.get_signature_status(&signature), Ok(Some(Ok(())))) {
        return Ok(signature.to_string());
    }
    // Simulate the exact bytes before they reach the network. The static
    // policy has already bounded what the sponsor is authorizing; this
    // catches the rest — an unfunded payer, a frozen or wrong-owner token
    // account, a settlement path that would not be usable later — while
    // rejecting is still free.
    let simulation = rpc
        .simulate_transaction(tx)
        .map_err(|e| batch_err(codes::INVALID_SETTLEMENT_SIMULATION, e.to_string()))?;
    if let Some(err) = simulation.value.err {
        return Err(batch_err(
            codes::INVALID_SETTLEMENT_SIMULATION,
            format!("simulation failed: {err:?}"),
        ));
    }
    match rpc.send_and_confirm_transaction(tx) {
        Ok(confirmed) => Ok(confirmed.to_string()),
        Err(error) => {
            if matches!(rpc.get_signature_status(&signature), Ok(Some(Ok(())))) {
                Ok(signature.to_string())
            } else {
                Err(Error::Rpc(format!("broadcast failed: {error}")))
            }
        }
    }
}

/// Server configuration for the SVM `batch-settlement` scheme.
#[derive(Clone)]
pub struct BatchConfig {
    /// Base58 final payment receiver — the sole distribution recipient, at
    /// 10,000 bps. Normally a cold wallet, distinct from the fee payer.
    pub pay_to: String,
    /// Currency symbol (`"USDC"`) or mint address.
    pub currency: String,
    /// Token decimals.
    pub decimals: u8,
    /// Token program override; derived from `currency` when absent.
    pub token_program: Option<String>,
    /// Solana cluster: `mainnet-beta`, `devnet`, or `localnet`.
    pub cluster: String,
    /// RPC URL override (defaults per cluster).
    pub rpc_url: Option<String>,
    /// Resource identifier for the 402 challenge.
    pub resource: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// HTTP completion window in seconds.
    pub max_timeout_seconds: u64,
    /// Forced-close grace period in seconds. Must be within
    /// `900..=2592000` and at least `max_timeout_seconds`.
    pub withdraw_delay: u32,
    /// Seller-defined payment reference pinned into the setup transaction's
    /// Memo. When absent the client supplies a random hex nonce instead.
    pub memo: Option<String>,
    /// Base58 server key advertised as `extra.receiverAuthorizer`.
    ///
    /// Advertised only. This server never signs a `CloseAuthorization` and
    /// rejects any it receives — see [`check_no_cooperative_close`].
    pub receiver_authorizer: Option<String>,
    /// Signer that co-signs client setup transactions as fee payer, holds the
    /// channel `rent_payer` and zero-share `payee` seats, and signs redemption
    /// transactions.
    pub fee_payer_signer: Arc<dyn SolanaSigner>,
    /// Channel program id override (defaults to the canonical deployment).
    pub program_id: Option<String>,
    /// How long a confirmed onchain channel snapshot is trusted before this
    /// server re-fetches it, in seconds.
    ///
    /// The scheme requires the channel to be confirmed `Open` before a voucher
    /// is accepted, and allows a fresh snapshot to stand in for a per-request
    /// fetch. `0` re-fetches on every request. The window is safe well past the
    /// default because a forced close cannot seal until its grace period —
    /// at least 900 seconds — has run.
    pub channel_snapshot_max_age_seconds: u64,
}

impl BatchConfig {
    /// Minimal configuration with USDC defaults and the minimum conformant
    /// forced-close grace period.
    pub fn new(
        pay_to: impl Into<String>,
        cluster: impl Into<String>,
        fee_payer_signer: Arc<dyn SolanaSigner>,
    ) -> Self {
        Self {
            pay_to: pay_to.into(),
            currency: "USDC".to_string(),
            decimals: 6,
            token_program: None,
            cluster: cluster.into(),
            rpc_url: None,
            resource: String::new(),
            description: None,
            max_timeout_seconds: 300,
            withdraw_delay: MIN_WITHDRAW_DELAY_SECONDS,
            memo: None,
            receiver_authorizer: None,
            fee_payer_signer,
            program_id: None,
            channel_snapshot_max_age_seconds: 30,
        }
    }
}

/// Per-channel, process-local serialization guard.
///
/// The spec requires the server to serialize all paid-request and close
/// processing per channel. The guard is held from `verify_payment` through
/// `settle_payment`, so a second request on the same channel cannot read the
/// watermark, serve, and commit in between.
///
/// A multi-replica deployment must route a channel to one replica until its
/// verified outcome settles; a future store reservation can remove that
/// deployment constraint.
#[derive(Clone, Default)]
struct InFlight(Arc<DashSet<String>>);

impl InFlight {
    fn acquire(&self, channel_id: &str) -> Result<ChannelGuard, Error> {
        // Sharded set, not a global Mutex<HashSet>: this guard is acquired and
        // released on every paid request, so a single mutex here serializes all
        // gateway traffic and caps throughput at ~1/critical-section regardless
        // of concurrency. DashSet shards the contention away.
        if !self.0.insert(channel_id.to_string()) {
            return Err(batch_err(
                codes::DUPLICATE_SETTLEMENT,
                format!("channel {channel_id} already has a request in flight"),
            ));
        }
        Ok(ChannelGuard {
            in_flight: self.clone(),
            channel_id: channel_id.to_string(),
        })
    }
}

/// Releases its channel's in-flight slot when dropped — including on the error
/// and panic paths, so a failed handler never wedges a channel.
#[derive(Debug)]
struct ChannelGuard {
    in_flight: InFlight,
    channel_id: String,
}

impl std::fmt::Debug for InFlight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InFlight")
    }
}

impl Drop for ChannelGuard {
    fn drop(&mut self) {
        self.in_flight.0.remove(&self.channel_id);
    }
}

/// The durable identity of one payment authorization.
///
/// `id` is the scheme's `("access", channelId, maxClaimableAmount)` cache key,
/// so a retry resolves to the same authorization whichever payload variant
/// carries the voucher. `fingerprint` binds that id to this exact request.
#[derive(Clone, Debug)]
struct Authorization {
    id: String,
    fingerprint: String,
}

/// What the caller must do with a verified `batch-settlement` request.
///
/// Returned by [`X402BatchSettlement::verify_and_reserve_payment`], which
/// reserves the authorization durably *before* the resource handler runs.
#[derive(Debug)]
pub enum BatchAccess {
    /// Reserved for this request: run the handler exactly once, then
    /// [`X402BatchSettlement::release_authorization`] on failure, or
    /// [`X402BatchSettlement::mark_handler_succeeded`] followed by
    /// [`X402BatchSettlement::finish_commit`] on success.
    Serve(BatchOutcome),
    /// An earlier attempt's handler already succeeded but its commitment did
    /// not finish. Call [`X402BatchSettlement::finish_commit`] and return its
    /// response; the handler MUST NOT run again.
    Resume(BatchOutcome),
    /// Already committed: return this stored response, and do not run the
    /// handler.
    Replay(BatchSettlementResponse),
    /// Another in-flight request owns this authorization. Answer `409` with
    /// [`codes::DUPLICATE_SETTLEMENT`]; the client may retry shortly.
    InProgress,
    /// A payment-control operation (a `refund`): bypass the handler and call
    /// [`X402BatchSettlement::settle_payment`].
    Control(BatchOutcome),
}

/// A verified payment, carried from [`X402BatchSettlement::verify_payment`] to
/// [`X402BatchSettlement::settle_payment`].
///
/// Not `Clone`: it owns its channel's in-flight guard, released on drop.
#[derive(Debug)]
pub struct BatchOutcome {
    /// Whether the gate should run the protected handler.
    ///
    /// `false` for a `refund`: a channel close is a payment-control operation,
    /// not a paid request, so the application handler must be bypassed.
    pub serve: bool,
    /// Whether this is an idempotent retry of an already-accepted voucher.
    ///
    /// The caller MUST return its cached response for
    /// `("access", channelId, maxClaimableAmount)` and MUST NOT run the
    /// resource handler again — the request was already paid for and served.
    pub replay: bool,
    /// The derived channel PDA (base58).
    pub channel_id: String,
    /// The channel payer (base58).
    pub payer: String,
    /// What this request charges, in atomic units.
    pub charged_amount: u64,
    payload: BatchPayload,
    requirements: BatchRequirements,
    max_claimable: u64,
    /// The channel payer's signature over a carried setup transaction, which
    /// identifies it uniquely across retries.
    deposit_signature: Option<String>,
    /// The authorization this request pays with. `None` for a `refund`, which
    /// pays for nothing and reserves nothing.
    authorization: Option<Authorization>,
    _guard: ChannelGuard,
}

impl BatchOutcome {
    /// The payload this outcome verified.
    pub fn payload(&self) -> &BatchPayload {
        &self.payload
    }
}

/// Server-side handler for the SVM x402 `batch-settlement` scheme.
#[derive(Clone)]
pub struct X402BatchSettlement {
    rpc: Arc<RpcClient>,
    config: BatchConfig,
    fee_payer: Pubkey,
    store: Arc<dyn ChannelStore>,
    in_flight: InFlight,
}

impl X402BatchSettlement {
    /// Build a handler backed by an in-memory channel store.
    ///
    /// The store holds the only record of what a client has been charged, so a
    /// durable store is required in production — see [`Self::with_store`].
    pub fn new(config: BatchConfig) -> Result<Self, Error> {
        Self::with_store(config, Arc::new(MemoryChannelStore::new()))
    }

    /// Build a handler over a caller-provided (durable) channel store.
    ///
    /// The in-flight reservation is process-local, so multi-replica callers
    /// must consistently route each channel to one instance until settlement.
    pub fn with_store(config: BatchConfig, store: Arc<dyn ChannelStore>) -> Result<Self, Error> {
        if config.pay_to.is_empty() {
            return Err(Error::Other("pay_to is required".into()));
        }
        Pubkey::from_str(&config.pay_to)
            .map_err(|e| Error::Other(format!("invalid payTo pubkey: {e}")))?;
        crate::x402::exact::try_resolve_stablecoin_mint(&config.currency, Some(&config.cluster))?;
        check_withdraw_delay(config.withdraw_delay, config.max_timeout_seconds)
            .map_err(|e| Error::Other(e.to_string()))?;
        let fee_payer = config.fee_payer_signer.pubkey();
        if pc::pubkey_string(&fee_payer) == config.pay_to {
            // Not fatal onchain, but it collapses the cold-wallet separation the
            // scheme is built around, so surface it at construction.
            tracing::warn!(
                "batch-settlement payTo equals the fee payer; proceeds are not isolated"
            );
        }
        if let Some(authorizer) = &config.receiver_authorizer {
            Pubkey::from_str(authorizer)
                .map_err(|e| Error::Other(format!("invalid receiverAuthorizer: {e}")))?;
        }
        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&config.cluster).to_string());
        Ok(Self {
            rpc: Arc::new(RpcClient::new(rpc_url)),
            config,
            fee_payer,
            store,
            in_flight: InFlight::default(),
        })
    }

    /// The advertised `extra.feePayer` (base58).
    pub fn fee_payer(&self) -> String {
        pc::pubkey_string(&self.fee_payer)
    }

    /// The channel store backing this handler, for redemption workers.
    pub fn store(&self) -> &Arc<dyn ChannelStore> {
        &self.store
    }

    fn program_id(&self) -> Result<Pubkey, Error> {
        match &self.config.program_id {
            Some(v) => {
                Pubkey::from_str(v).map_err(|e| Error::Other(format!("invalid programId: {e}")))
            }
            None => Ok(pc::default_program_id()),
        }
    }

    fn mint(&self) -> Result<Pubkey, Error> {
        let mint = crate::x402::exact::try_resolve_stablecoin_mint(
            &self.config.currency,
            Some(&self.config.cluster),
        )?
        .ok_or_else(|| Error::Other("batch-settlement requires an SPL token".into()))?;
        Pubkey::from_str(mint).map_err(|e| Error::Other(format!("invalid mint: {e}")))
    }

    fn token_program(&self) -> Result<Pubkey, Error> {
        let declared = self.config.token_program.clone().unwrap_or_else(|| {
            default_token_program_for_currency(&self.config.currency, Some(&self.config.cluster))
                .to_string()
        });
        Ok(check_token_program(&declared)?)
    }

    fn network(&self) -> String {
        caip2_network_for_cluster(&self.config.cluster).to_string()
    }

    // ── Challenge ──

    /// Build the `batch-settlement` requirement. Pure: no RPC.
    pub fn requirements(&self, amount: &str) -> Result<BatchRequirements, Error> {
        let base_units = crate::x402::server::exact::parse_units(amount, self.config.decimals)?;
        Ok(BatchRequirements {
            scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
            network: self.network(),
            amount: base_units,
            asset: pc::pubkey_string(&self.mint()?),
            pay_to: self.config.pay_to.clone(),
            max_timeout_seconds: self.config.max_timeout_seconds,
            extra: BatchExtra {
                // Omitted: the scheme already resolves to the protocol-default
                // `authorization` flow.
                payment_flow: None,
                fee_payer: self.fee_payer(),
                receiver_authorizer: self.config.receiver_authorizer.clone(),
                withdraw_delay: self.config.withdraw_delay,
                token_program: pc::pubkey_string(&self.token_program()?),
                memo: self.config.memo.clone(),
                recent_blockhash: None,
                recent_slot: None,
                channel_state: None,
                voucher_state: None,
            },
        })
    }

    /// Build the full 402 challenge.
    ///
    /// One `getLatestBlockhash` supplies both hints: its response context
    /// carries the slot, which the client uses as `channelConfig.openSlot`. Both
    /// are construction conveniences — a client may ignore them and fetch its
    /// own, and neither is part of the signed voucher.
    ///
    /// `resource` names the URL being paid for. x402 v2 requires one, so a
    /// server that cannot know it at construction — a gate serving many routes
    /// — passes the routed request's URL here instead.
    pub fn challenge(
        &self,
        amount: &str,
        resource: Option<&str>,
    ) -> Result<BatchRequiredEnvelope, Error> {
        let mut requirement = self.requirements(amount)?;
        let hint =
            crate::core::blockhash::fetch_blockhash_with_slot(&self.rpc, self.rpc.commitment())
                .map_err(|e| Error::Rpc(format!("failed to fetch recent blockhash: {e}")))?;
        requirement.extra.recent_blockhash = Some(hint.blockhash);
        requirement.extra.recent_slot = Some(hint.slot);
        Ok(self.envelope(requirement, None, resource))
    }

    /// Build a corrective 402 telling the client where the server's watermark
    /// actually is, after a cumulative-amount mismatch.
    ///
    /// The snapshot carries a `voucherState` proof: the signature the client
    /// itself produced at `signedMaxClaimable`. Without it the client would have
    /// to take the server's word for how much it has been charged, and a server
    /// could walk the cumulative base up arbitrarily. When the server holds no
    /// voucher yet, the proof is omitted and the client resynchronizes from
    /// onchain state instead.
    pub async fn corrective_challenge(
        &self,
        amount: &str,
        channel_id: &str,
        resource: Option<&str>,
    ) -> Result<BatchRequiredEnvelope, Error> {
        // No blockhash or slot hint: this answers a client that already has a
        // channel and will retry with a plain `voucher`, which needs neither.
        // Keeping the error path RPC-free means a degraded RPC cannot turn a
        // recoverable mismatch into an unrecoverable failure — and a client that
        // does need to top up may fetch its own, as the scheme allows.
        let mut requirement = self.requirements(amount)?;
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| batch_err(codes::INVALID_CHANNEL_STATE, "unknown channel"))?;
        requirement.extra.voucher_state =
            state
                .highest_voucher_signature
                .as_ref()
                .map(|signature| VoucherState {
                    signed_max_claimable: state.cumulative.to_string(),
                    expires_at: state
                        .highest_voucher_expires_at
                        .unwrap_or(VOUCHER_EXPIRES_AT),
                    signature: signature.clone(),
                });
        requirement.extra.channel_state = Some(Self::snapshot(&state));
        Ok(self.envelope(
            requirement,
            Some(codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH.to_string()),
            resource,
        ))
    }

    fn envelope(
        &self,
        requirement: BatchRequirements,
        error: Option<String>,
        resource: Option<&str>,
    ) -> BatchRequiredEnvelope {
        // The configured resource wins when set, so a single-route server keeps
        // its declared identifier; otherwise the routed request supplies it.
        let url = (!self.config.resource.is_empty())
            .then(|| self.config.resource.clone())
            .or_else(|| resource.map(str::to_string));
        BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: url.map(|url| ResourceInfo {
                url,
                description: self.config.description.clone(),
                mime_type: None,
            }),
            accepts: vec![requirement],
            error,
        }
    }

    /// `(header-name, base64-value)` for the 402 challenge.
    pub fn payment_required_header(
        &self,
        amount: &str,
        resource: Option<&str>,
    ) -> Result<(String, String), Error> {
        Ok((
            PAYMENT_REQUIRED_HEADER.to_string(),
            encode_json(&self.challenge(amount, resource)?)?,
        ))
    }

    /// `(header-name, base64-value)` for the `PAYMENT-RESPONSE` result.
    pub fn settlement_header(
        &self,
        response: &BatchSettlementResponse,
    ) -> Result<(String, String), Error> {
        Ok((PAYMENT_RESPONSE_HEADER.to_string(), encode_json(response)?))
    }

    /// Decode a `PAYMENT-SIGNATURE` header into a `batch-settlement` payload.
    pub fn parse_payment(&self, header: &str) -> Result<BatchPaymentPayload, Error> {
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, header)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        let envelope: BatchPaymentPayload = serde_json::from_slice(&decoded)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        if envelope.accepted.scheme != BATCH_SETTLEMENT_SCHEME {
            return Err(Error::InvalidPayloadType(envelope.accepted.scheme));
        }
        Ok(envelope)
    }

    /// Build the 402 to answer a failed verification with.
    ///
    /// A cumulative-amount mismatch gets the corrective challenge, carrying the
    /// server's snapshot and the voucher proof the client needs to resynchronize
    /// and retry. Every challenge carries a machine-readable error code.
    pub async fn challenge_for_failure(
        &self,
        header: &str,
        amount: &str,
        error: &Error,
        resource: Option<&str>,
    ) -> Result<(String, String), Error> {
        let is_mismatch =
            crate::x402::protocol::schemes::batch_settlement::classify(&error.to_string())
                == codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH;
        if is_mismatch {
            if let Some(channel_id) = self.channel_id_for_header(header) {
                if let Ok(envelope) = self
                    .corrective_challenge(amount, &channel_id, resource)
                    .await
                {
                    return Ok((PAYMENT_REQUIRED_HEADER.to_string(), encode_json(&envelope)?));
                }
            }
        }
        let mut envelope = self.challenge(amount, resource)?;
        envelope.error = Some(
            crate::x402::protocol::schemes::batch_settlement::classify(&error.to_string())
                .to_string(),
        );
        Ok((PAYMENT_REQUIRED_HEADER.to_string(), encode_json(&envelope)?))
    }

    fn channel_id_for_header(&self, header: &str) -> Option<String> {
        let envelope = self.parse_payment(header).ok()?;
        let program_id = self.program_id().ok()?;
        let channel = derive_channel_id(
            envelope.payload.channel_config(),
            &envelope.accepted.extra.fee_payer,
            &program_id,
        )
        .ok()?;
        Some(pc::pubkey_string(&channel))
    }

    // ── Verify (before the resource handler) ──

    /// Verify a payment for a route priced at `amount`, without mutating state.
    ///
    /// On success the returned [`BatchOutcome`] holds the channel's in-flight
    /// guard. Hand it to [`Self::settle_payment`] before serving the resource,
    /// which atomically commits the voucher watermark before access is granted.
    ///
    /// A cumulative-amount mismatch fails with
    /// `invalid_batch_settlement_svm_cumulative_amount_mismatch`; answer it with
    /// [`Self::corrective_challenge`] so the client can resynchronize.
    pub async fn verify_payment(&self, header: &str, amount: &str) -> Result<BatchOutcome, Error> {
        let envelope = self.parse_payment(header)?;
        if envelope.x402_version != X402_VERSION_V2 {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                "batch-settlement requires x402 version 2",
            ));
        }
        let requirements = self.requirements(amount)?;
        let payload = envelope.payload;
        let config = payload.channel_config().clone();

        check_channel_config(&config, &requirements)?;
        check_no_cooperative_close(&payload)?;
        self.check_accepted_matches(&envelope.accepted, &requirements)?;

        let program_id = self.program_id()?;
        let channel_id = derive_channel_id(&config, &requirements.extra.fee_payer, &program_id)?;
        let channel_b58 = pc::pubkey_string(&channel_id);
        let guard = self.in_flight.acquire(&channel_b58)?;

        let charge = requirements.amount()?;

        match &payload {
            BatchPayload::Refund { transaction, .. } => {
                self.verify_refund(transaction, &config, &requirements, &channel_id)?;
                // A refund only needs the current watermark; read it out without
                // cloning the record.
                let max_claimable = Arc::new(Mutex::new(0u64));
                let out = Arc::clone(&max_claimable);
                self.store
                    .read_channel(
                        &channel_b58,
                        Box::new(move |state| {
                            if let Some(state) = state {
                                *out.lock().unwrap_or_else(|e| e.into_inner()) = state.cumulative;
                            }
                            Ok(())
                        }),
                    )
                    .await
                    .map_err(|e| Error::Other(format!("store error: {e}")))?;
                let max_claimable = *max_claimable.lock().unwrap_or_else(|e| e.into_inner());
                Ok(BatchOutcome {
                    serve: false,
                    replay: false,
                    channel_id: channel_b58,
                    payer: config.payer.clone(),
                    charged_amount: 0,
                    payload,
                    requirements,
                    max_claimable,
                    deposit_signature: None,
                    authorization: None,
                    _guard: guard,
                })
            }
            BatchPayload::Voucher { voucher, .. } => {
                // Hot path: extract only the scalar fields the checks need,
                // borrowing the record under the read guard. The growing
                // `committed_deliveries` Vec and the `extra` map are never
                // cloned here.
                let fields: Arc<Mutex<Option<(bool, bool, u64, Option<String>, u64, String)>>> =
                    Arc::new(Mutex::new(None));
                let out = Arc::clone(&fields);
                self.store
                    .read_channel(
                        &channel_b58,
                        Box::new(move |state| {
                            if let Some(state) = state {
                                *out.lock().unwrap_or_else(|e| e.into_inner()) = Some((
                                    state.sealed,
                                    state.close_requested_at.is_some(),
                                    state.cumulative,
                                    state.highest_voucher_signature.clone(),
                                    state.deposit,
                                    state.payer.clone(),
                                ));
                            }
                            Ok(())
                        }),
                    )
                    .await
                    .map_err(|e| Error::Other(format!("store error: {e}")))?;
                let (
                    sealed,
                    close_requested,
                    cumulative,
                    highest_voucher_signature,
                    deposit,
                    payer,
                ) = fields
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                    .ok_or_else(|| {
                        batch_err(
                            codes::INVALID_CHANNEL_STATE,
                            format!("no channel {channel_b58}; open one with a deposit payload"),
                        )
                    })?;
                self.check_channel_open(sealed, close_requested)?;
                let max_claimable = check_voucher(voucher, &config, &channel_id)?;
                let replay = self.check_watermark(
                    cumulative,
                    highest_voucher_signature.as_deref(),
                    voucher,
                    max_claimable,
                    charge,
                )?;
                self.check_deposit_cap(max_claimable, deposit)?;
                let authorization =
                    authorization_for(&channel_b58, voucher, max_claimable, &requirements);
                Ok(BatchOutcome {
                    serve: !replay,
                    replay,
                    channel_id: channel_b58,
                    payer,
                    charged_amount: if replay { 0 } else { charge },
                    payload,
                    requirements,
                    max_claimable,
                    deposit_signature: None,
                    authorization: Some(authorization),
                    _guard: guard,
                })
            }
            BatchPayload::Deposit {
                voucher, deposit, ..
            } => {
                let stored = self
                    .store
                    .get_channel(&channel_b58)
                    .await
                    .map_err(|e| Error::Other(format!("store error: {e}")))?;
                let max_claimable = check_voucher(voucher, &config, &channel_id)?;
                let deposit_amount = deposit.amount()?;
                let form = setup_form_from_transaction(&deposit.transaction, &program_id)?;
                if let Some(state) = &stored {
                    self.check_channel_open(state.sealed, state.close_requested_at.is_some())?;
                }
                let prior = stored.as_ref();
                let replay = match prior {
                    Some(state) => self.check_watermark(
                        state.cumulative,
                        state.highest_voucher_signature.as_deref(),
                        voucher,
                        max_claimable,
                        charge,
                    )?,
                    None => {
                        if max_claimable != charge {
                            return Err(batch_err(
                                codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                                format!(
                                    "first voucher must authorize exactly {charge}, got {max_claimable}"
                                ),
                            ));
                        }
                        false
                    }
                };
                let mint = self.mint()?;
                let token_program = self.token_program()?;
                let receiver = pc::parse_pubkey(&requirements.pay_to)?;
                self.check_mint_owner(&mint, &token_program)?;
                let payer = pc::parse_pubkey(&config.payer)?;
                self.check_settlement_accounts(&mint, &token_program, &receiver, &payer)?;
                let expectations = TransactionExpectations {
                    program_id: &program_id,
                    fee_payer: &self.fee_payer,
                    config: &config,
                    channel_id: &channel_id,
                    token_program: &token_program,
                    receiver: &receiver,
                    memo: self.config.memo.as_deref(),
                };
                // An `open` whose transaction already landed must not be
                // re-validated against the open-slot window: by the time the
                // client retries, its `openSlot` can be well behind the current
                // slot, and a fresh window check would reject the very channel
                // the payer has already escrowed into. A landed `open` is
                // recognized by the confirmed channel, or by the pending-setup
                // record this server wrote before broadcasting.
                let carried_signature =
                    payer_signature(&pc::decode_transaction(&deposit.transaction)?);
                let retrying = stored
                    .as_ref()
                    .and_then(|s| s.pending_setup.as_ref())
                    .is_some_and(|setup| {
                        Some(setup.payer_signature.as_str()) == carried_signature.as_deref()
                    })
                    || self.lookup_channel(&channel_id)?.is_some();
                let recent_slot = (matches!(form, SetupForm::Open) && !retrying)
                    .then(|| {
                        crate::core::blockhash::fetch_blockhash_with_slot(
                            &self.rpc,
                            self.rpc.commitment(),
                        )
                        .ok()
                        .map(|hint| hint.slot)
                    })
                    .flatten();
                let validated =
                    crate::x402::protocol::schemes::batch_settlement::validate_setup_transaction(
                        &deposit.transaction,
                        form,
                        &expectations,
                        deposit_amount,
                        recent_slot,
                    )?;
                let deposit_signature = payer_signature(&validated.transaction);
                let deposit_after = Self::deposit_ceiling(
                    stored.as_ref(),
                    deposit_amount,
                    deposit_signature.as_deref(),
                )?;
                self.check_deposit_cap(max_claimable, deposit_after)?;
                let authorization =
                    authorization_for(&channel_b58, voucher, max_claimable, &requirements);
                Ok(BatchOutcome {
                    serve: !replay,
                    replay,
                    channel_id: channel_b58,
                    payer: config.payer.clone(),
                    charged_amount: if replay { 0 } else { charge },
                    payload,
                    requirements,
                    max_claimable,
                    deposit_signature,
                    authorization: Some(authorization),
                    _guard: guard,
                })
            }
        }
    }

    /// The client must echo back the requirements it is answering, so a payload
    /// built against a different price or asset cannot be replayed onto this
    /// route.
    fn check_accepted_matches(
        &self,
        accepted: &BatchRequirements,
        requirements: &BatchRequirements,
    ) -> Result<(), Error> {
        let mismatched = accepted.network != requirements.network
            || accepted.amount != requirements.amount
            || accepted.asset != requirements.asset
            || accepted.pay_to != requirements.pay_to
            || accepted.max_timeout_seconds != requirements.max_timeout_seconds
            || accepted.extra.payment_flow != requirements.extra.payment_flow
            || accepted.extra.fee_payer != requirements.extra.fee_payer
            || accepted.extra.receiver_authorizer != requirements.extra.receiver_authorizer
            || accepted.extra.withdraw_delay != requirements.extra.withdraw_delay
            || accepted.extra.token_program != requirements.extra.token_program
            || accepted.extra.memo != requirements.extra.memo;
        if mismatched {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                "paymentPayload.accepted does not match the route's paymentRequirements",
            ));
        }
        Ok(())
    }

    fn check_channel_open(&self, sealed: bool, close_requested: bool) -> Result<(), Error> {
        if sealed {
            return Err(batch_err(codes::INVALID_CLOSE_STATE, "channel is sealed"));
        }
        // Once a payer-forced close has been broadcast the redemption window is
        // bounded by the grace period, so no further charge may be accepted.
        if close_requested {
            return Err(batch_err(
                codes::INVALID_CLOSE_STATE,
                "channel close is pending; open a new channel",
            ));
        }
        Ok(())
    }

    /// Apply the fixed-price watermark rule, returning whether this is an
    /// idempotent replay.
    ///
    /// A fresh voucher must advance the cumulative by exactly one request's
    /// price. An exact repeat of the highest accepted voucher — same amount and
    /// same signature — is a retry of a request that was already paid for and
    /// served. Anything else is stale or a fork, and must not be served.
    fn check_watermark(
        &self,
        cumulative: u64,
        highest_voucher_signature: Option<&str>,
        voucher: &crate::x402::protocol::schemes::batch_settlement::BatchVoucher,
        max_claimable: u64,
        charge: u64,
    ) -> Result<bool, Error> {
        if max_claimable == cumulative
            && highest_voucher_signature == Some(voucher.signature.as_str())
        {
            return Ok(true);
        }
        let expected = cumulative
            .checked_add(charge)
            .ok_or_else(|| batch_err(codes::INVALID_CHANNEL_STATE, "cumulative amount overflow"))?;
        if max_claimable != expected {
            return Err(batch_err(
                codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                format!(
                    "voucher authorizes {max_claimable}, expected {expected} \
                     (charged {cumulative} + amount {charge})"
                ),
            ));
        }
        Ok(false)
    }

    /// The deposit ceiling a request may authorize against, once its carried
    /// setup transaction confirms.
    ///
    /// A retry must not add the same escrow twice. The first attempt may have
    /// broadcast, confirmed, and recorded the deposit before failing later
    /// (a store error while committing the voucher, say), and re-adding it
    /// would leave the request permanently unsatisfiable: the ceiling would
    /// exceed what the chain will ever hold, so the confirmed-state check
    /// could never pass and the escrowed funds would be stranded. The payer's
    /// signature identifies the transaction across attempts.
    fn deposit_ceiling(
        stored: Option<&ChannelState>,
        deposit_amount: u64,
        deposit_signature: Option<&str>,
    ) -> Result<u64, Error> {
        let Some(state) = stored else {
            // No channel yet: the `open` is the whole escrow.
            return Ok(deposit_amount);
        };
        if deposit_signature.is_some_and(|signature| {
            state
                .processed_topup_signatures
                .iter()
                .any(|s| s == signature)
        }) {
            return Ok(state.deposit);
        }
        state
            .deposit
            .checked_add(deposit_amount)
            .ok_or_else(|| batch_err(codes::INVALID_CHANNEL_STATE, "deposit overflow"))
    }

    fn check_deposit_cap(&self, max_claimable: u64, deposit: u64) -> Result<(), Error> {
        if max_claimable > deposit {
            return Err(batch_err(
                codes::INVALID_CUMULATIVE_EXCEEDS_DEPOSIT,
                format!("voucher authorizes {max_claimable} over a deposit of {deposit}"),
            ));
        }
        Ok(())
    }

    /// Confirm the advertised token program really owns the mint.
    ///
    /// The ATA derivations in the setup transaction depend on it, so a token
    /// program that disagrees with the chain would have the sponsor validate
    /// accounts the program will never touch.
    fn check_mint_owner(&self, mint: &Pubkey, token_program: &Pubkey) -> Result<(), Error> {
        let account = self
            .rpc
            .get_account(mint)
            .map_err(|e| Error::Rpc(format!("mint fetch failed: {e}")))?;
        if pc::from_address(&account.owner) != *token_program {
            return Err(batch_err(
                codes::INVALID_TOKEN_PROGRAM,
                format!(
                    "tokenProgram {} does not own mint {}",
                    pc::pubkey_string(token_program),
                    pc::pubkey_string(mint)
                ),
            ));
        }
        Ok(())
    }

    /// Ensure a channel can later distribute its settled funds before the
    /// sponsor co-signs the escrow transaction.
    ///
    /// Each destination must be a live token account for this mint, owned by
    /// the role that will receive the payout: an uninitialized, frozen,
    /// wrong-mint or wrong-owner account would fail `distribute` only after the
    /// escrow is already locked and the request already served.
    fn check_settlement_accounts(
        &self,
        mint: &Pubkey,
        token_program: &Pubkey,
        receiver: &Pubkey,
        payer: &Pubkey,
    ) -> Result<(), Error> {
        for (role, owner) in [
            ("payee", self.fee_payer),
            ("treasury", pc::treasury_owner()),
            ("receiver", *receiver),
            // The payer's return ATA is a settlement destination too: a close
            // pays `deposit - settled` back through it, so an unusable one
            // would strand the remainder of an escrow this server sponsored.
            ("payer", *payer),
        ] {
            let (ata, _) = pc::find_associated_token_address(&owner, mint, token_program);
            let reject = |detail: String| {
                Err(batch_err(
                    codes::INVALID_SETUP_TRANSACTION,
                    format!("{role} settlement ATA {ata} {detail}"),
                ))
            };
            let account = self.rpc.get_account(&ata).map_err(|e| {
                batch_err(
                    codes::INVALID_SETUP_TRANSACTION,
                    format!("{role} settlement ATA {ata} is unavailable: {e}"),
                )
            })?;
            if pc::from_address(&account.owner) != *token_program {
                return reject("is not owned by the declared token program".to_string());
            }
            let Some(decoded) = decode_token_account(&account.data) else {
                return reject("is not an initialized token account".to_string());
            };
            if decoded.mint != *mint {
                return reject(format!(
                    "holds mint {} rather than {}",
                    pc::pubkey_string(&decoded.mint),
                    pc::pubkey_string(mint)
                ));
            }
            if decoded.owner != owner {
                return reject(format!(
                    "is owned by {} rather than {}",
                    pc::pubkey_string(&decoded.owner),
                    pc::pubkey_string(&owner)
                ));
            }
            if decoded.state == TOKEN_ACCOUNT_FROZEN {
                return reject("is frozen".to_string());
            }
            if let Some(extension) = decoded.unsupported_extension {
                return reject(format!(
                    "carries token account extension {extension}, which this server \
                     will not settle through"
                ));
            }
            if decoded.state != TOKEN_ACCOUNT_INITIALIZED {
                return reject(format!("is in account state {}", decoded.state));
            }
        }
        Ok(())
    }

    fn verify_refund(
        &self,
        transaction: &str,
        config: &BatchChannelConfig,
        requirements: &BatchRequirements,
        channel_id: &Pubkey,
    ) -> Result<(), Error> {
        let program_id = self.program_id()?;
        let token_program = self.token_program()?;
        let receiver = pc::parse_pubkey(&requirements.pay_to)?;
        let expectations = TransactionExpectations {
            program_id: &program_id,
            fee_payer: &self.fee_payer,
            config,
            channel_id,
            token_program: &token_program,
            receiver: &receiver,
            memo: self.config.memo.as_deref(),
        };
        crate::x402::protocol::schemes::batch_settlement::validate_request_close_transaction(
            transaction,
            &expectations,
        )?;
        // The close pays out through these accounts once the grace period
        // ends; an unusable one would leave the escrow unrecoverable.
        let payer = pc::parse_pubkey(&config.payer)?;
        self.check_settlement_accounts(&self.mint()?, &token_program, &receiver, &payer)?;
        // The channel must still be closeable. `Closing` is accepted so a
        // retried refund is idempotent rather than a second transition.
        let channel = self.fetch_channel(channel_id)?;
        if channel.status != CHANNEL_STATUS_OPEN && channel.status != CHANNEL_STATUS_CLOSING {
            return Err(batch_err(
                codes::INVALID_CLOSE_STATE,
                format!("channel status {} cannot be closed", channel.status),
            ));
        }
        Ok(())
    }

    // ── Reserve (before the resource handler) ──

    /// Verify a payment and durably reserve its authorization before the
    /// resource handler runs.
    ///
    /// This is the entry point a gate should use. The returned [`BatchAccess`]
    /// says whether to run the handler, resume an unfinished commitment, or
    /// answer with a stored response — so one authorization has exactly one
    /// outcome even across a crash:
    ///
    /// - a handler failure is released with [`Self::release_authorization`] and
    ///   the client may retry the same voucher;
    /// - a handler success is recorded with [`Self::mark_handler_succeeded`]
    ///   before [`Self::finish_commit`] charges it, so a crash in between can
    ///   only ever finish the charge, never re-run the handler;
    /// - a retry after a lost response replays the stored result.
    ///
    /// The reservation is store-backed, so it holds across replicas; the
    /// process-local in-flight guard remains only as a fast path.
    pub async fn verify_and_reserve_payment(
        &self,
        header: &str,
        amount: &str,
    ) -> Result<BatchAccess, Error> {
        let outcome = match self.verify_payment(header, amount).await {
            Ok(outcome) => outcome,
            Err(error) => {
                // A channel the chain knows and this server does not. Rebuild
                // the record and verify again rather than refuse a funded,
                // open channel.
                if !self.recover_channel(header, amount).await? {
                    return Err(error);
                }
                self.verify_payment(header, amount).await?
            }
        };
        let Some(authorization) = outcome.authorization.clone() else {
            return Ok(BatchAccess::Control(outcome));
        };
        // Only now, holding a payload this channel's own signer authorized, is
        // an RPC worth spending: reconciling first would let any well-formed
        // header pull an account fetch out of the operator, on the one path
        // this scheme otherwise keeps free of RPC entirely.
        //
        // Verification read the pre-reconciliation snapshot, which is safe in
        // one direction only — a deposit ceiling can grow but never shrink, so
        // a stale one is conservative — while a channel that is closing or gone
        // is refused by the reconciliation itself.
        self.reconcile_channel(&outcome.channel_id).await?;
        // The watermark already stands at this voucher, so the request it pays
        // for was charged and served. Answer it as a replay even if the cached
        // record has since aged out — never as a fresh serve.
        if outcome.replay {
            return Ok(BatchAccess::Replay(self.replay_response(&outcome).await?));
        }
        match self.reserve(&outcome, &authorization).await? {
            BatchReservation::Reserved => Ok(BatchAccess::Serve(outcome)),
            BatchReservation::HandlerSucceeded => Ok(BatchAccess::Resume(outcome)),
            BatchReservation::Committed => {
                Ok(BatchAccess::Replay(self.replay_response(&outcome).await?))
            }
            BatchReservation::InProgress => Ok(BatchAccess::InProgress),
            BatchReservation::Conflict => Err(batch_err(
                codes::DUPLICATE_SETTLEMENT,
                format!(
                    "authorization {} is held by a different request",
                    authorization.id
                ),
            )),
            // A reservation that never reported an outcome may have served its
            // request already, so this voucher can never be served again. The
            // channel is stuck at this cumulative and the client's recovery is
            // a new one, which is worth an operator's attention.
            BatchReservation::Abandoned => {
                tracing::error!(
                    channel = %outcome.channel_id,
                    authorization = %authorization.id,
                    "authorization was abandoned mid-request; refusing to serve it twice"
                );
                Err(batch_err(
                    codes::INVALID_CHANNEL_STATE,
                    format!(
                        "authorization {} was abandoned while it may have been served; \
                         open a new channel",
                        authorization.id
                    ),
                ))
            }
        }
    }

    /// Atomically reserve this request's authorization, creating the channel
    /// record when an initial deposit is opening the channel.
    async fn reserve(
        &self,
        outcome: &BatchOutcome,
        authorization: &Authorization,
    ) -> Result<BatchReservation, Error> {
        let Authorization { id, fingerprint } = authorization.clone();
        let charge = outcome.charged_amount;
        let now = now_unix() as i64;
        // The reservation has to outlive the request it guards: reclaiming it
        // while a slow handler is still running would let a retry run that
        // handler alongside it. The route's advertised completion window is
        // that bound, with the charge lease as the floor.
        let lease = CHARGE_RESERVATION_LEASE.max(std::time::Duration::from_secs(
            self.config.max_timeout_seconds,
        ));
        let setup = outcome.deposit_signature.clone().map(|payer_signature| {
            let (deposit, opens_channel) = match &outcome.payload {
                BatchPayload::Deposit { deposit, .. } => (
                    deposit.amount().unwrap_or_default(),
                    !matches!(
                        setup_form_from_transaction(
                            &deposit.transaction,
                            &pc::default_program_id()
                        ),
                        Ok(SetupForm::TopUp)
                    ),
                ),
                _ => (0, false),
            };
            PendingSetup {
                payer_signature,
                deposit,
                opens_channel,
                expires_at: now.saturating_add(lease.as_secs() as i64),
            }
        });
        let seed = matches!(outcome.payload, BatchPayload::Deposit { .. })
            .then(|| self.seed_state(&outcome.channel_id, outcome.payload.channel_config()));
        let reservation = Arc::new(Mutex::new(BatchReservation::InProgress));
        let out = Arc::clone(&reservation);
        // In-place reservation: the record is mutated behind the store's shard
        // guard with no clone. When no record exists yet, only an initial
        // deposit may create one (via `seed`); a plain voucher on an unknown
        // channel is refused by the store's missing-channel error. The
        // reservation outcome is carried out through `out`.
        self.store
            .mutate_channel(
                &outcome.channel_id,
                seed,
                Box::new(move |state| {
                    if let Some(setup) = setup {
                        match &state.pending_setup {
                            // Another setup transaction is already in flight for
                            // this channel; one of them would be credited twice.
                            Some(current) if current.payer_signature != setup.payer_signature => {
                                return Err(crate::core::store::StoreError::Internal(format!(
                                    "channel {} already has a pending setup transaction",
                                    state.channel_id
                                )))
                            }
                            _ => state.pending_setup = Some(setup),
                        }
                    }
                    *out.lock().unwrap_or_else(|e| e.into_inner()) =
                        state.reserve_authorization(&id, &fingerprint, charge, lease, now);
                    Ok(())
                }),
            )
            .await
            .map_err(|e| batch_err(codes::INVALID_CHANNEL_STATE, format!("store error: {e}")))?;
        let reserved = reservation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        Ok(reserved)
    }

    /// Record that the resource handler succeeded, before the charge is
    /// committed.
    ///
    /// This is the crash boundary: past it, a retry can only finish the charge.
    pub async fn mark_handler_succeeded(&self, outcome: &BatchOutcome) -> Result<(), Error> {
        let Authorization { id, fingerprint } = self.authorization_of(outcome)?;
        self.store
            .mutate_channel(
                &outcome.channel_id,
                None,
                Box::new(move |state| {
                    state.mark_authorization_handler_succeeded(&id, &fingerprint)?;
                    Ok(())
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        Ok(())
    }

    /// Release an authorization whose handler failed, so the client can retry
    /// the same voucher.
    ///
    /// Nothing is charged and no setup transaction is broadcast. A record that
    /// existed only to hold an opening deposit is removed with it.
    pub async fn release_authorization(&self, outcome: BatchOutcome) -> Result<(), Error> {
        let Authorization { id, fingerprint } = self.authorization_of(&outcome)?;
        let deposit_signature = outcome.deposit_signature.clone();
        let state = self
            .store
            .update_channel(
                &outcome.channel_id,
                Box::new(move |current| {
                    let mut state = current.ok_or_else(|| {
                        crate::core::store::StoreError::Internal("channel not found".into())
                    })?;
                    state.release_authorization(&id, &fingerprint)?;
                    // Only this request's own setup transaction is dropped: a
                    // plain voucher must not discard a deposit another replica
                    // is holding for the same channel.
                    if state
                        .pending_setup
                        .as_ref()
                        .map(|setup| &setup.payer_signature)
                        == deposit_signature.as_ref()
                    {
                        state.pending_setup = None;
                    }
                    Ok(state)
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        // A record holding no escrow, no watermark and no other authorization
        // was created by this request alone; leaving it behind would make a
        // later voucher look like it had a channel.
        if state.deposit == 0
            && state.cumulative == 0
            && state.pending_deliveries.is_empty()
            && state.committed_deliveries.is_empty()
        {
            self.store
                .delete_channel(&outcome.channel_id)
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?;
        }
        Ok(())
    }

    /// Finish committing an authorization whose handler succeeded: broadcast
    /// any carried setup transaction, advance the voucher watermark, and store
    /// the response returned for it.
    ///
    /// Safe to call again after a failure. The watermark advance, the committed
    /// record and the stored response are one store transition, so a retry
    /// either finds the commitment done or redoes all of it.
    pub async fn finish_commit(
        &self,
        outcome: &BatchOutcome,
    ) -> Result<BatchSettlementResponse, Error> {
        let Authorization { id, fingerprint } = self.authorization_of(outcome)?;
        let voucher = voucher_of(&outcome.payload)
            .ok_or_else(|| batch_err(codes::INVALID_PAYLOAD_TYPE, "payload carries no voucher"))?
            .clone();

        // The escrow is broadcast only now, after the handler succeeded: the
        // scheme puts the deposit transaction in the post-handler settle.
        let (transaction, amount, confirmed) = match &outcome.payload {
            BatchPayload::Deposit { deposit, .. } => {
                let signature = self
                    .broadcast_client_transaction(&deposit.transaction)
                    .await?;
                let channel = self.fetch_channel(&pc::parse_pubkey(&outcome.channel_id)?)?;
                self.check_channel_bindings(
                    &channel,
                    outcome.payload.channel_config(),
                    &outcome.requirements.pay_to,
                    // The escrow must cover what this voucher authorizes: that
                    // is what the program enforces at `settle`, and it stays
                    // true when a retry re-confirms a deposit that landed.
                    outcome.max_claimable,
                )?;
                (signature, deposit.amount.clone(), Some(channel))
            }
            _ => (String::new(), String::new(), None),
        };

        let payer = outcome.payer.clone();
        let network = outcome.requirements.network.clone();
        let commitment_id = voucher.commitment_id();
        let charged = outcome.charged_amount;
        let max_claimable = outcome.max_claimable;
        let deposit_signature = outcome.deposit_signature.clone();
        let rent_payer = self.fee_payer();
        let now = now_unix() as i64;
        let committed = Arc::new(Mutex::new(None));
        let out = Arc::clone(&committed);
        self.store
            .mutate_channel(
                &outcome.channel_id,
                None,
                Box::new(move |state| {
                    if let Some(channel) = &confirmed {
                        // A top-up only ever raises the ceiling; never let a
                        // stale read lower a deposit the chain has confirmed.
                        state.deposit = state.deposit.max(channel.deposit);
                        state.settled_on_chain =
                            state.settled_on_chain.max(channel.settlement.settled);
                        state.open_slot = Some(channel.open_slot);
                        state.rent_payer = rent_payer;
                        state.onchain_checked_at = now.max(0) as u64;
                        state.pending_setup = None;
                        // Marks this escrow as applied, so a retry re-uses the
                        // confirmed deposit rather than adding it again.
                        if let Some(signature) = deposit_signature {
                            if !state.processed_topup_signatures.contains(&signature) {
                                state.processed_topup_signatures.push(signature);
                            }
                        }
                    }
                    state.last_activity_at = now.max(0) as u64;
                    state.commit_authorization(
                        &id,
                        &fingerprint,
                        max_claimable,
                        &voucher.signature,
                        voucher.expires_at,
                        now,
                        |state| {
                            let response = accepted_response(
                                &payer,
                                &network,
                                commitment_id,
                                transaction,
                                amount,
                                charged,
                                state,
                            );
                            let value = serde_json::to_value(&response).ok();
                            *out.lock().unwrap_or_else(|e| e.into_inner()) = Some(response);
                            value
                        },
                    )?;
                    Ok(())
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;

        let response = committed.lock().unwrap_or_else(|e| e.into_inner()).clone();
        match response {
            Some(response) => Ok(response),
            // The transition found the authorization already committed, so the
            // response stored on its record is the authoritative one.
            None => self.replay_response(outcome).await,
        }
    }

    fn authorization_of(&self, outcome: &BatchOutcome) -> Result<Authorization, Error> {
        outcome.authorization.clone().ok_or_else(|| {
            batch_err(
                codes::INVALID_PAYLOAD_TYPE,
                "payload reserves no authorization",
            )
        })
    }

    /// Rebuild a channel record from confirmed onchain state when this server
    /// has none, and report whether it created one.
    ///
    /// A server that lost its store — or a replica reading one that never held
    /// this channel — would otherwise refuse every voucher for a channel that
    /// is open and funded, leaving the payer's escrow to be recovered through a
    /// forced close. The chain carries every immutable binding plus the settled
    /// watermark, and that watermark is the most this server can honestly claim
    /// to have charged: any voucher above it is unclaimable without the
    /// signature that vanished with the store, so starting from it forfeits
    /// nothing that was not already lost.
    ///
    /// The client's own voucher signature is checked before any RPC, so a
    /// payload nobody signed cannot make this server read accounts. What the
    /// rebuilt record cannot know is which requests were already served below
    /// that watermark; a store loss is outside what the scheme's serve-once
    /// guarantee can cover, and the corrective 402 that follows carries no
    /// voucher proof, so the client resynchronizes from onchain state instead.
    async fn recover_channel(&self, header: &str, amount: &str) -> Result<bool, Error> {
        let Ok(envelope) = self.parse_payment(header) else {
            return Ok(false);
        };
        // Only a steady-state voucher recovers: a deposit carries the `open`
        // that would create the channel, and a refund reads the chain anyway.
        let BatchPayload::Voucher {
            channel_config,
            voucher,
        } = &envelope.payload
        else {
            return Ok(false);
        };
        let requirements = self.requirements(amount)?;
        let program_id = self.program_id()?;
        let Ok(channel_id) =
            derive_channel_id(channel_config, &requirements.extra.fee_payer, &program_id)
        else {
            return Ok(false);
        };
        let channel_b58 = pc::pubkey_string(&channel_id);
        if self
            .store
            .get_channel(&channel_b58)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .is_some()
        {
            return Ok(false);
        }
        if check_voucher(voucher, channel_config, &channel_id).is_err() {
            return Ok(false);
        }
        let Some(channel) = self.lookup_channel(&channel_id)? else {
            return Ok(false);
        };
        // The deposit cap is left to verification, which reports it with the
        // code the client acts on.
        self.check_channel_bindings(&channel, channel_config, &requirements.pay_to, 0)?;
        if channel.closure_started_at != 0 {
            return Err(batch_err(
                codes::INVALID_CLOSE_STATE,
                format!("channel {channel_b58} is closing onchain"),
            ));
        }
        let settled = channel.settlement.settled;
        let deposit = channel.deposit;
        let open_slot = channel.open_slot;
        let now = now_unix();
        let mut seed = self.seed_state(&channel_b58, channel_config);
        seed.deposit = deposit;
        seed.cumulative = settled;
        seed.spent_amount = settled;
        seed.settled_on_chain = settled;
        seed.open_slot = Some(open_slot);
        seed.onchain_checked_at = now;
        self.store
            .update_channel(
                &channel_b58,
                Box::new(move |current| {
                    // Another replica may have rebuilt it first; its record is
                    // no less authoritative than this one.
                    Ok(current.unwrap_or(seed))
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        tracing::info!(
            channel = %channel_b58,
            settled,
            deposit,
            "rebuilt an unknown channel record from confirmed onchain state"
        );
        Ok(true)
    }

    /// Refresh a channel record from confirmed onchain state before it
    /// authorizes anything.
    ///
    /// The scheme requires the server to confirm the channel is still `Open`
    /// before accepting a voucher, and allows a fresh snapshot to stand in for
    /// a per-request fetch. A payer can force a close at any time; serving past
    /// the grace period that follows is unbacked work.
    async fn reconcile_channel(&self, channel_b58: &str) -> Result<(), Error> {
        // Hot path: only the last-checked timestamp decides whether a refresh
        // is due, so read that one field without cloning the whole record.
        let checked_at: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
        let out = Arc::clone(&checked_at);
        self.store
            .read_channel(
                channel_b58,
                Box::new(move |state| {
                    *out.lock().unwrap_or_else(|e| e.into_inner()) =
                        state.map(|s| s.onchain_checked_at);
                    Ok(())
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        let Some(onchain_checked_at) = *checked_at.lock().unwrap_or_else(|e| e.into_inner()) else {
            // Nothing to reconcile: an unknown channel is refused by
            // verification, and a deposit confirms its own channel.
            return Ok(());
        };
        let now = now_unix();
        let age = now.saturating_sub(onchain_checked_at);
        if age < self.config.channel_snapshot_max_age_seconds {
            return Ok(());
        }
        let channel_id = pc::parse_pubkey(channel_b58)?;
        // Run the blocking RPC on a blocking thread so a stale-snapshot refresh
        // never stalls the async worker serving other paid requests.
        let rpc = Arc::clone(&self.rpc);
        let fetched = tokio::task::spawn_blocking(move || rpc_lookup_channel(&rpc, &channel_id))
            .await
            .map_err(|e| Error::Other(format!("channel reconcile task failed: {e}")))?;
        let onchain = match fetched {
            Ok(onchain) => onchain,
            Err(e) => {
                // A degraded RPC must not reject every paid request, but it also
                // must not let the snapshot rot: past half the forced-close
                // grace period, a close started right after the last check
                // would leave too little time to claim.
                let stale_limit = u64::from(self.config.withdraw_delay) / 2;
                if onchain_checked_at > 0 && age < stale_limit {
                    tracing::warn!(channel = %channel_b58, error = %e, age, "serving on a stale channel snapshot");
                    return Ok(());
                }
                return Err(e);
            }
        };
        let closed_at = match onchain {
            // Confirmed absent: reclaimed, or never opened. Either way no
            // voucher against it can ever be redeemed.
            None => {
                return Err(batch_err(
                    codes::INVALID_CHANNEL_STATE,
                    format!("channel {channel_b58} no longer exists onchain"),
                ))
            }
            Some(channel) => {
                let closed_at = (channel.status != CHANNEL_STATUS_OPEN
                    || channel.closure_started_at != 0)
                    .then(|| {
                        u64::try_from(channel.closure_started_at)
                            .unwrap_or(now)
                            .max(1)
                    });
                let deposit = channel.deposit;
                let settled = channel.settlement.settled;
                let sealed = channel.status != CHANNEL_STATUS_OPEN
                    && channel.status != CHANNEL_STATUS_CLOSING;
                self.store
                    .update_channel(
                        channel_b58,
                        Box::new(move |current| {
                            let mut state = current.ok_or_else(|| {
                                crate::core::store::StoreError::Internal("channel not found".into())
                            })?;
                            state.deposit = state.deposit.max(deposit);
                            state.settled_on_chain = state.settled_on_chain.max(settled);
                            state.sealed = state.sealed || sealed;
                            if let Some(closed_at) = closed_at {
                                state.close_requested_at =
                                    Some(state.close_requested_at.unwrap_or(closed_at));
                            }
                            state.onchain_checked_at = now;
                            Ok(state)
                        }),
                    )
                    .await
                    .map_err(|e| Error::Other(format!("store error: {e}")))?;
                closed_at
            }
        };
        if closed_at.is_some() {
            return Err(batch_err(
                codes::INVALID_CLOSE_STATE,
                format!("channel {channel_b58} is closing or closed onchain"),
            ));
        }
        Ok(())
    }

    // ── Commit ──

    /// Commit a verified payment.
    ///
    /// A `refund` initiates the channel close. A `voucher` or `deposit` is
    /// charged through [`Self::finish_commit`], which the caller MUST NOT reach
    /// before its resource handler has succeeded.
    pub async fn settle_payment(
        &self,
        outcome: BatchOutcome,
    ) -> Result<BatchSettlementResponse, Error> {
        let network = outcome.requirements.network.clone();
        match &outcome.payload {
            BatchPayload::Refund { transaction, .. } => {
                let channel_id = pc::parse_pubkey(&outcome.channel_id)?;
                let mut channel = self.fetch_channel(&channel_id)?;
                self.upsert_channel(&outcome, &channel).await?;
                let signature = if channel.status == CHANNEL_STATUS_OPEN {
                    let state = self
                        .store
                        .get_channel(&outcome.channel_id)
                        .await
                        .map_err(|e| Error::Other(format!("store error: {e}")))?;
                    if state.is_some_and(|state| state.cumulative > channel.settlement.settled) {
                        self.claim(std::slice::from_ref(&outcome.channel_id))
                            .await?;
                    }
                    self.broadcast_client_transaction(transaction).await?
                } else if channel.status == CHANNEL_STATUS_CLOSING {
                    String::new()
                } else {
                    return Err(batch_err(
                        codes::INVALID_CLOSE_STATE,
                        "channel cannot be closed",
                    ));
                };
                channel = self.fetch_channel(&channel_id)?;
                if channel.status != CHANNEL_STATUS_CLOSING {
                    return Err(batch_err(
                        codes::INVALID_CLOSE_STATE,
                        "request_close did not move the channel to Closing",
                    ));
                }
                let state = self.record_close(&outcome, &channel).await?;
                Ok(BatchSettlementResponse {
                    success: true,
                    error_reason: None,
                    payer: Some(outcome.payer.clone()),
                    transaction: signature,
                    network,
                    // The grace period may still be running: nothing has moved
                    // back to the payer yet, and claiming otherwise would be a
                    // lie the client could act on.
                    amount: String::new(),
                    extra: Some(BatchSettlementExtra {
                        commitment_id: None,
                        charged_amount: None,
                        channel_state: Some(Self::snapshot(&state)),
                    }),
                })
            }
            BatchPayload::Voucher { .. } | BatchPayload::Deposit { .. } => {
                self.finish_commit(&outcome).await
            }
        }
    }

    /// Rebuild the accepted response for an idempotent voucher retry.
    ///
    /// Used when no response was stored for the authorization — a record that
    /// predates response storage, or one whose stored response has aged out.
    /// The charge it reports is this route's fixed price, which is what the
    /// original response carried.
    pub async fn replay_response(
        &self,
        outcome: &BatchOutcome,
    ) -> Result<BatchSettlementResponse, Error> {
        let state = self
            .store
            .get_channel(&outcome.channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| batch_err(codes::INVALID_CHANNEL_STATE, "channel vanished"))?;
        let stored = outcome
            .authorization
            .as_ref()
            .and_then(|authorization| state.committed_authorization(&authorization.id))
            .and_then(|committed| committed.settlement_response.clone())
            .and_then(|value| serde_json::from_value(value).ok());
        if let Some(response) = stored {
            return Ok(response);
        }
        Ok(accepted_response(
            &outcome.payer,
            &outcome.requirements.network,
            format!("{}:{}", outcome.channel_id, outcome.max_claimable),
            String::new(),
            String::new(),
            outcome.requirements.amount()?,
            &state,
        ))
    }

    /// Co-sign a client-supplied transaction as fee payer and broadcast it.
    ///
    /// The transaction was already statically validated during verification, so
    /// this only adds the sponsor signature. A rejection is not authoritative on
    /// its own: a retry of a transaction whose first submission landed dies at
    /// preflight with "already processed", so the confirmed signature status
    /// decides.
    async fn broadcast_client_transaction(&self, transaction_b64: &str) -> Result<String, Error> {
        let mut tx = pc::decode_transaction(transaction_b64)?;
        cosign_operator_fee_payer(
            self.config.fee_payer_signer.as_ref(),
            &self.fee_payer,
            &mut tx,
        )
        .await?;
        let rpc = Arc::clone(&self.rpc);
        tokio::task::spawn_blocking(move || broadcast_and_confirm_deposit(&rpc, &tx))
            .await
            .map_err(|e| Error::Other(format!("broadcast join error: {e}")))?
    }

    /// Re-read the confirmed channel and bind every immutable field to the
    /// payload and requirements before reporting settlement success.
    /// Bind every immutable field of an onchain channel to the payload and
    /// requirements that claim it.
    ///
    /// `min_deposit` is the escrow the caller needs the channel to already
    /// hold; pass `0` to check only the bindings.
    fn check_channel_bindings(
        &self,
        channel: &Channel,
        config: &BatchChannelConfig,
        pay_to: &str,
        min_deposit: u64,
    ) -> Result<(), Error> {
        let expect = |ok: bool, what: &str| -> Result<(), Error> {
            if ok {
                Ok(())
            } else {
                Err(batch_err(
                    codes::INVALID_CHANNEL_STATE,
                    format!("confirmed channel {what} does not match the payload"),
                ))
            }
        };
        expect(channel.status == CHANNEL_STATUS_OPEN, "status")?;
        // The escrow must cover what this voucher authorizes. That — not the
        // arithmetic ceiling computed before broadcast — is the property the
        // program enforces at `settle`, and it is the one that stays true when
        // a retry re-confirms a deposit that already landed.
        expect(channel.deposit >= min_deposit, "deposit")?;
        expect(
            pc::pubkey_string(&pc::from_address(&channel.payer)) == config.payer,
            "payer",
        )?;
        expect(pc::from_address(&channel.payee) == self.fee_payer, "payee")?;
        expect(
            pc::from_address(&channel.rent_payer) == self.fee_payer,
            "rent_payer",
        )?;
        expect(
            pc::pubkey_string(&pc::from_address(&channel.authorized_signer))
                == config.payer_authorizer,
            "authorized_signer",
        )?;
        expect(
            pc::pubkey_string(&pc::from_address(&channel.mint)) == config.token,
            "mint",
        )?;
        expect(
            channel.grace_period == config.withdraw_delay,
            "grace_period",
        )?;
        expect(channel.open_slot == config.open_slot, "open_slot")?;
        // The distribution is only committed as a hash, so it is checked by
        // rebuilding the single-recipient preimage the scheme requires.
        let receiver = pc::parse_pubkey(pay_to)?;
        let expected_hash = pc::distribution_hash(&pc::sole_recipient(&receiver));
        expect(channel.distribution_hash == expected_hash, "distribution")?;
        Ok(())
    }

    /// Refresh the channel record from confirmed onchain state, creating it if
    /// this is the first confirmation.
    async fn upsert_channel(&self, outcome: &BatchOutcome, channel: &Channel) -> Result<(), Error> {
        let deposit = channel.deposit;
        let settled = channel.settlement.settled;
        let seed = self.seed_state(&outcome.channel_id, outcome.payload.channel_config());
        let deposit_signature = outcome.deposit_signature.clone();
        self.store
            .update_channel(
                &outcome.channel_id,
                Box::new(move |current| {
                    let mut state = current.unwrap_or(seed);
                    // A top-up only ever raises the ceiling; never let a stale
                    // read lower a deposit the chain has already confirmed.
                    state.deposit = state.deposit.max(deposit);
                    state.settled_on_chain = state.settled_on_chain.max(settled);
                    state.last_activity_at = now_unix();
                    // Marks this escrow as applied, so a retry of the same
                    // transaction re-uses the confirmed deposit rather than
                    // adding it a second time.
                    if let Some(signature) = deposit_signature {
                        if !state.processed_topup_signatures.contains(&signature) {
                            state.processed_topup_signatures.push(signature);
                        }
                    }
                    Ok(state)
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        Ok(())
    }

    /// A fresh channel record for this request's channel, holding no escrow and
    /// no accepted voucher.
    fn seed_state(&self, channel_id: &str, config: &BatchChannelConfig) -> ChannelState {
        ChannelState {
            channel_id: channel_id.to_string(),
            authorized_signer: config.payer_authorizer.clone(),
            deposit: 0,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            open_slot: Some(config.open_slot),
            payer: config.payer.clone(),
            rent_payer: self.fee_payer(),
            opening_challenge_id: String::new(),
            authentication: None,
            voucher_signer: "client".to_string(),
            idle_timeout_seconds: None,
            last_activity_at: now_unix(),
            spent_amount: 0,
            settled_on_chain: 0,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
            pending_setup: None,
            onchain_checked_at: 0,
            lifecycle: None,
            schema_version: CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        }
    }

    async fn record_close(
        &self,
        outcome: &BatchOutcome,
        channel: &Channel,
    ) -> Result<ChannelState, Error> {
        let closed_at = u64::try_from(channel.closure_started_at).unwrap_or_else(|_| now_unix());
        self.store
            .update_channel(
                &outcome.channel_id,
                Box::new(move |current| {
                    let mut state = current.ok_or_else(|| {
                        crate::core::store::StoreError::Internal("channel not found".into())
                    })?;
                    state.close_requested_at = Some(closed_at);
                    state.last_activity_at = now_unix();
                    Ok(state)
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))
    }

    pub(crate) fn snapshot(state: &ChannelState) -> ChannelStateSnapshot {
        ChannelStateSnapshot {
            channel_id: state.channel_id.clone(),
            balance: state.deposit.to_string(),
            total_claimed: state.settled_on_chain.to_string(),
            withdraw_requested_at: state.close_requested_at.unwrap_or(0) as i64,
            charged_cumulative_amount: Some(state.cumulative.to_string()),
        }
    }

    /// Read a channel account, separating confirmed absence from a transient
    /// RPC or decode failure.
    ///
    /// `Ok(None)` is a confirmed absence, which is terminal. Everything else —
    /// an unreachable RPC, an undecodable account — is an error and never an
    /// absence: a durable record must not be dropped for a condition that can
    /// clear, because it holds the only copy of this server's charge watermark.
    fn lookup_channel(&self, channel_id: &Pubkey) -> Result<Option<Channel>, Error> {
        rpc_lookup_channel(&self.rpc, channel_id)
    }

    fn fetch_channel(&self, channel_id: &Pubkey) -> Result<Channel, Error> {
        self.lookup_channel(channel_id)?.ok_or_else(|| {
            batch_err(
                codes::INVALID_CHANNEL_STATE,
                format!("channel {} does not exist", pc::pubkey_string(channel_id)),
            )
        })
    }

    // ── Redemption (out of band) ──

    /// Advance the onchain `settled` watermark from each channel's stored
    /// voucher, packing up to [`MAX_CLAIMS_PER_BATCH`] channels per transaction.
    ///
    /// Every channel is processed or the call fails — a batch is never silently
    /// truncated, because a dropped channel is unclaimed value the server would
    /// forfeit if the payer force-closed.
    ///
    /// Returns the confirmed transaction signatures.
    pub async fn claim(&self, channel_ids: &[String]) -> Result<Vec<String>, Error> {
        let program_id = self.program_id()?;
        let mut groups = Vec::with_capacity(channel_ids.len());
        for channel_id in channel_ids {
            let mut state = self
                .store
                .get_channel(channel_id)
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?
                .ok_or_else(|| {
                    batch_err(
                        codes::INVALID_CHANNEL_STATE,
                        format!("unknown channel {channel_id}"),
                    )
                })?;
            let channel = pc::parse_pubkey(channel_id)?;
            let Some(onchain) = self.lookup_for_lifecycle(channel_id, &channel).await? else {
                continue;
            };
            if onchain.status != CHANNEL_STATUS_OPEN || onchain.closure_started_at != 0 {
                continue;
            }
            let settled_on_chain = onchain.settlement.settled;
            state.settled_on_chain = state.settled_on_chain.max(settled_on_chain);
            self.store
                .update_channel(
                    channel_id,
                    Box::new(move |current| {
                        let mut current = current.ok_or_else(|| {
                            crate::core::store::StoreError::Internal("channel not found".into())
                        })?;
                        current.settled_on_chain = current.settled_on_chain.max(settled_on_chain);
                        Ok(current)
                    }),
                )
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?;
            let Some(signature) = state.highest_voucher_signature.clone() else {
                continue;
            };
            // `settle` requires a strictly increasing watermark, so a channel
            // already claimed at this amount would only fail onchain.
            if state.cumulative <= state.settled_on_chain {
                continue;
            }
            let authorized_signer = pc::parse_pubkey(&state.authorized_signer)?;
            let signature_bytes = decode_signature(&signature)?;
            let expires_at = state
                .highest_voucher_expires_at
                .unwrap_or(VOUCHER_EXPIRES_AT);
            // Emits the Ed25519 precompile instruction immediately followed by
            // the program `settle` that reads it back from the instructions
            // sysvar; the pair must stay adjacent, so they are packed together.
            let instructions = pc::build_settle_instructions(
                &channel,
                &authorized_signer,
                &signature_bytes,
                state.cumulative,
                expires_at,
                &program_id,
            )?;
            groups.push(ChannelInstructionGroup {
                channel_id: channel_id.clone(),
                instructions,
            });
        }
        self.submit_groups(groups, MAX_CLAIMS_PER_BATCH).await
    }

    /// Pay each channel's newly claimed delta to `payTo` via program
    /// `distribute`. The channel stays open.
    pub async fn settle(&self, channel_ids: &[String]) -> Result<Vec<String>, Error> {
        let program_id = self.program_id()?;
        let mint = self.mint()?;
        let token_program = self.token_program()?;
        let receiver = pc::parse_pubkey(&self.config.pay_to)?;
        let mut groups = Vec::with_capacity(channel_ids.len());
        for channel_id in channel_ids {
            let channel = pc::parse_pubkey(channel_id)?;
            let Some(onchain) = self.lookup_for_lifecycle(channel_id, &channel).await? else {
                continue;
            };
            // A close freezes the distributable watermark. Never pack a
            // closing or terminal channel into a distribute batch: one
            // program-level rejection would otherwise fail every neighbour in
            // the atomic transaction.
            if onchain.status != CHANNEL_STATUS_OPEN || onchain.closure_started_at != 0 {
                continue;
            }
            if onchain.settlement.settled <= onchain.settlement.payout_watermark {
                continue;
            }
            let instruction = pc::build_distribute_instruction(
                &channel,
                &pc::from_address(&onchain.payer),
                &self.fee_payer,
                &self.fee_payer,
                &pc::treasury_owner(),
                &mint,
                &pc::sole_recipient(&receiver),
                &token_program,
                &program_id,
            );
            groups.push(ChannelInstructionGroup {
                channel_id: channel_id.clone(),
                instructions: vec![instruction],
            });
        }
        self.submit_groups(groups, MAX_CLAIMS_PER_BATCH).await
    }

    /// The onchain channel a lifecycle step should act on, or `None` when there
    /// is nothing left to act on.
    ///
    /// A confirmed absence is terminal: the account has been reclaimed (or
    /// never existed), so its durable record is dropped and the work queue
    /// drains. A transient RPC or decode failure is not absence and propagates
    /// instead — that record holds the only copy of this server's charge
    /// watermark.
    async fn lookup_for_lifecycle(
        &self,
        channel_id: &str,
        channel: &Pubkey,
    ) -> Result<Option<Channel>, Error> {
        if let Some(onchain) = self.lookup_channel(channel)? {
            return Ok(Some(onchain));
        }
        // A channel being opened has a record before it has a PDA: its setup
        // transaction is only broadcast once the handler has succeeded. Absence
        // is expected there, and dropping the record would take the
        // authorization with it — losing a charge that was served but not yet
        // committed, or freeing one whose handler already ran to be served a
        // second time.
        let in_flight = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .is_some_and(|state| state.has_in_flight_authorization());
        if in_flight {
            tracing::debug!(
                channel = %channel_id,
                "channel is not onchain yet; keeping its in-flight record"
            );
            return Ok(None);
        }
        tracing::info!(
            channel = %channel_id,
            "channel account is gone onchain; dropping its record"
        );
        self.store
            .delete_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        Ok(None)
    }

    async fn submit_groups(
        &self,
        groups: Vec<ChannelInstructionGroup>,
        max_per_tx: usize,
    ) -> Result<Vec<String>, Error> {
        if groups.is_empty() {
            return Ok(vec![]);
        }
        let batches = pack(groups, &self.fee_payer, max_per_tx);
        let mut signatures = Vec::with_capacity(batches.len());
        for batch in batches {
            let instructions: Vec<_> = batch
                .into_iter()
                .flat_map(|group| group.instructions)
                .collect();
            let blockhash = self
                .rpc
                .get_latest_blockhash()
                .map_err(|e| Error::Rpc(format!("blockhash fetch failed: {e}")))?;
            let message = Message::new_with_blockhash(
                &instructions,
                Some(&pc::to_address(&self.fee_payer)),
                &blockhash,
            );
            let mut tx = Transaction::new_unsigned(message);
            self.config
                .fee_payer_signer
                .sign_transaction(&mut tx)
                .await
                .map_err(|e| Error::Other(format!("fee payer signing failed: {e}")))?;
            let signature = self
                .rpc
                .send_and_confirm_transaction(&VersionedTransaction::from(tx))
                .map_err(|e| Error::Rpc(format!("settlement broadcast failed: {e}")))?;
            signatures.push(signature.to_string());
        }
        Ok(signatures)
    }

    /// Finalize channels whose payer-forced close has run out its grace period.
    ///
    /// After `closure_started_at + grace_period`, `seal` is permissionless. The
    /// sealed `distribute` that follows pays any settled delta to `payTo`,
    /// returns `deposit - settled` to the payer, and closes the escrow token
    /// account. Both run in one transaction per channel.
    ///
    /// Channels that are not yet due are skipped, and a channel another crank
    /// already advanced is treated as success — the terminal onchain state is
    /// what matters, not which worker got there.
    ///
    /// Claim before this runs: a voucher still unclaimed when the watermark
    /// freezes is value the server forfeits to the payer.
    pub async fn finalize_close(&self, channel_ids: &[String]) -> Result<Vec<String>, Error> {
        let program_id = self.program_id()?;
        let mint = self.mint()?;
        let token_program = self.token_program()?;
        let receiver = pc::parse_pubkey(&self.config.pay_to)?;
        let now = now_unix() as i64;
        let mut groups = Vec::new();
        for channel_id in channel_ids {
            let channel = pc::parse_pubkey(channel_id)?;
            let Some(onchain) = self.lookup_for_lifecycle(channel_id, &channel).await? else {
                continue;
            };
            if onchain.status != CHANNEL_STATUS_CLOSING {
                continue;
            }
            let due = onchain
                .closure_started_at
                .saturating_add(i64::from(onchain.grace_period));
            if now < due {
                continue;
            }
            groups.push(ChannelInstructionGroup {
                channel_id: channel_id.clone(),
                instructions: vec![
                    pc::build_seal_instruction(&channel, &program_id),
                    pc::build_distribute_instruction(
                        &channel,
                        &pc::from_address(&onchain.payer),
                        &self.fee_payer,
                        &self.fee_payer,
                        &pc::treasury_owner(),
                        &mint,
                        &pc::sole_recipient(&receiver),
                        &token_program,
                        &program_id,
                    ),
                ],
            });
        }
        // One channel per transaction: a seal/distribute pair is far larger
        // than a claim, and a single failure must not strand its neighbours.
        let finalized: Vec<_> = groups
            .iter()
            .map(|group| group.channel_id.clone())
            .collect();
        let signatures = self.submit_groups(groups, 1).await?;
        for channel_id in finalized {
            self.store
                .update_channel(
                    &channel_id,
                    Box::new(|current| {
                        let mut state = current.ok_or_else(|| {
                            crate::core::store::StoreError::Internal("channel not found".into())
                        })?;
                        state.sealed = true;
                        state.last_activity_at = now_unix();
                        Ok(state)
                    }),
                )
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?;
        }
        Ok(signatures)
    }

    /// Recover the PDA rent this server fronted for `Distributed` channels.
    ///
    /// Permissionless, and gated by the program on
    /// `clock.slot > open_slot + OPEN_SLOT_WINDOW`. Rent always returns to the
    /// recorded `rent_payer`, so an abandoned channel can never permanently
    /// lock what the sponsor put up.
    pub async fn reclaim(&self, channel_ids: &[String]) -> Result<Vec<String>, Error> {
        let program_id = self.program_id()?;
        let slot = self
            .rpc
            .get_slot()
            .map_err(|e| Error::Rpc(format!("slot fetch failed: {e}")))?;
        let mut groups = Vec::new();
        for channel_id in channel_ids {
            let channel = pc::parse_pubkey(channel_id)?;
            // A reclaimed channel's account is already gone. Its record is
            // dropped, but only on a confirmed absence — a transient RPC or
            // decode failure leaves the channel for the next sweep.
            let onchain = match self.lookup_for_lifecycle(channel_id, &channel).await {
                Ok(Some(onchain)) => onchain,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(channel = %channel_id, error = %e, "skipping reclaim");
                    continue;
                }
            };
            if onchain.status != CHANNEL_STATUS_DISTRIBUTED
                || slot <= onchain.open_slot.saturating_add(pc::OPEN_SLOT_WINDOW)
            {
                continue;
            }
            groups.push(ChannelInstructionGroup {
                channel_id: channel_id.clone(),
                instructions: vec![pc::build_reclaim_instruction(
                    &channel,
                    &self.fee_payer,
                    &program_id,
                )],
            });
        }
        let reclaimed: Vec<_> = groups
            .iter()
            .map(|group| group.channel_id.clone())
            .collect();
        let signatures = self.submit_groups(groups, pc::MAX_RECLAIMS_PER_TX).await?;
        for channel_id in reclaimed {
            self.store
                .delete_channel(&channel_id)
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?;
        }
        Ok(signatures)
    }

    /// Discover every channel whose rent this server sponsored.
    ///
    /// Local state can be lost; the chain cannot. This rebuilds the lifecycle
    /// work queue by filtering on `Channel.rent_payer`, then rederives each
    /// account's PDA before accepting it — a `getProgramAccounts` filter result
    /// is never trusted on its own.
    ///
    /// It does not recover the server's charge watermark or unclaimed voucher;
    /// those exist only in the store. If they are lost the server must not
    /// invent a charge — the conservative action is to close at the current
    /// onchain `settled` and return the remainder to the payer.
    pub fn discover_sponsored_channels(&self) -> Result<Vec<(Pubkey, Channel)>, Error> {
        use solana_rpc_client_api::config::{
            RpcAccountInfoConfig, RpcProgramAccountsConfig, UiAccountEncoding,
        };
        use solana_rpc_client_api::filter::{Memcmp, RpcFilterType};
        use solana_rpc_client_api::request::RpcRequest;
        use solana_rpc_client_api::response::RpcKeyedAccount;

        let program_id = self.program_id()?;
        let config = RpcProgramAccountsConfig {
            filters: Some(vec![
                RpcFilterType::DataSize(pc::CHANNEL_ACCOUNT_SIZE as u64),
                RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                    pc::CHANNEL_RENT_PAYER_OFFSET,
                    self.fee_payer.to_bytes().to_vec(),
                )),
            ]),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                ..Default::default()
            },
            ..Default::default()
        };
        let params = serde_json::json!([program_id.to_string(), config]);
        let keyed: Vec<RpcKeyedAccount> = self
            .rpc
            .send(RpcRequest::GetProgramAccounts, params)
            .map_err(|e| Error::Rpc(format!("getProgramAccounts failed: {e}")))?;

        let mut found = Vec::new();
        for entry in keyed {
            let Ok(address) = Pubkey::from_str(&entry.pubkey) else {
                continue;
            };
            let Some(data) = entry.account.data.decode() else {
                continue;
            };
            let Ok(channel) = Channel::from_bytes(&data) else {
                continue;
            };
            let (derived, _) = pc::find_channel_pda(
                &pc::from_address(&channel.payer),
                &pc::from_address(&channel.payee),
                &pc::from_address(&channel.mint),
                &pc::from_address(&channel.authorized_signer),
                channel.salt,
                channel.open_slot,
                &program_id,
            );
            if derived == address {
                found.push((address, channel));
            }
        }
        Ok(found)
    }
}

/// The channel payer's base58 signature over a setup transaction.
///
/// Slot 0 is the sponsor's and is still empty before co-signing, so the payer's
/// slot is what identifies a client-supplied transaction across retries. The
/// payer signs the compiled message, which commits to the blockhash and every
/// instruction, so the signature is unique to this exact transaction.
fn payer_signature(transaction: &VersionedTransaction) -> Option<String> {
    let signature = transaction.signatures.get(1)?;
    Some(signature.to_string())
}

/// Base length of an SPL token account. Token-2022 appends its extensions
/// after the same fixed layout, so one decoder covers both programs.
const TOKEN_ACCOUNT_LEN: usize = 165;

/// `AccountState::Initialized`, at offset 108.
const TOKEN_ACCOUNT_INITIALIZED: u8 = 1;

/// `AccountState::Frozen`: the account cannot receive or send.
const TOKEN_ACCOUNT_FROZEN: u8 = 2;

/// `AccountType::Account`, the discriminant a Token-2022 account carries at
/// offset 165 before its extensions.
const TOKEN_ACCOUNT_TYPE: u8 = 2;

/// `ExtensionType::ImmutableOwner`.
///
/// The only account extension a settlement destination may carry. It is inert
/// — it fixes the owner, nothing else — and every associated token account has
/// it, so requiring its absence would reject ordinary ATAs.
const EXTENSION_IMMUTABLE_OWNER: u16 = 7;

/// The fields of an SPL token account this server cares about.
struct TokenAccount {
    mint: Pubkey,
    owner: Pubkey,
    state: u8,
    /// An account extension this server will not settle through, if any.
    unsupported_extension: Option<u16>,
}

/// Decode a token account, or `None` when the data is too short to be one —
/// which is what an uninitialized (or non-token) account looks like.
///
/// Token-2022 appends a type byte and a TLV extension list after the same
/// 165-byte base. Those extensions are not cosmetic: one can withhold part of a
/// transfer, require a memo to precede it, block it from a CPI, or move the
/// balance out of the classic ledger entirely — so an account carrying one is
/// reported rather than silently accepted as a payout destination.
fn decode_token_account(data: &[u8]) -> Option<TokenAccount> {
    if data.len() < TOKEN_ACCOUNT_LEN {
        return None;
    }
    Some(TokenAccount {
        mint: Pubkey::try_from(&data[0..32]).ok()?,
        owner: Pubkey::try_from(&data[32..64]).ok()?,
        state: data[108],
        unsupported_extension: unsupported_account_extension(data),
    })
}

/// The first account extension outside the allowlist, if the account has one.
///
/// A malformed or truncated TLV is reported as unsupported rather than skipped:
/// this decides whether to accept an escrow, so anything it cannot read is
/// something it should not settle through.
fn unsupported_account_extension(data: &[u8]) -> Option<u16> {
    // A classic SPL Token account is exactly the base length and has no
    // extension list at all.
    if data.len() == TOKEN_ACCOUNT_LEN {
        return None;
    }
    if data[TOKEN_ACCOUNT_LEN] != TOKEN_ACCOUNT_TYPE {
        return Some(u16::from(data[TOKEN_ACCOUNT_LEN]));
    }
    let mut cursor = TOKEN_ACCOUNT_LEN + 1;
    while cursor < data.len() {
        // A run of zero padding is the end of the list, not an extension.
        if data[cursor..].iter().all(|byte| *byte == 0) {
            return None;
        }
        let Some(header) = data.get(cursor..cursor + 4) else {
            return Some(u16::MAX);
        };
        let extension = u16::from_le_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if extension != EXTENSION_IMMUTABLE_OWNER {
            return Some(extension);
        }
        let Some(next) = cursor.checked_add(4).and_then(|c| c.checked_add(length)) else {
            return Some(u16::MAX);
        };
        if next > data.len() {
            return Some(u16::MAX);
        }
        cursor = next;
    }
    None
}

/// The voucher a payload authorizes with, if any.
fn voucher_of(
    payload: &BatchPayload,
) -> Option<&crate::x402::protocol::schemes::batch_settlement::BatchVoucher> {
    match payload {
        BatchPayload::Voucher { voucher, .. } | BatchPayload::Deposit { voucher, .. } => {
            Some(voucher)
        }
        BatchPayload::Refund { voucher, .. } => voucher.as_ref(),
    }
}

/// The `PAYMENT-RESPONSE` for an accepted authorization.
fn accepted_response(
    payer: &str,
    network: &str,
    commitment_id: String,
    transaction: String,
    amount: String,
    charged_amount: u64,
    state: &ChannelState,
) -> BatchSettlementResponse {
    BatchSettlementResponse {
        success: true,
        error_reason: None,
        payer: Some(payer.to_string()),
        transaction,
        network: network.to_string(),
        amount,
        extra: Some(BatchSettlementExtra {
            commitment_id: Some(commitment_id),
            charged_amount: Some(charged_amount.to_string()),
            channel_state: Some(X402BatchSettlement::snapshot(state)),
        }),
    }
}

/// The authorization a voucher pays with.
fn authorization_for(
    channel_id: &str,
    voucher: &crate::x402::protocol::schemes::batch_settlement::BatchVoucher,
    max_claimable: u64,
    requirements: &BatchRequirements,
) -> Authorization {
    Authorization {
        id: format!("access:{channel_id}:{max_claimable}"),
        fingerprint: request_fingerprint(&voucher.signature, requirements),
    }
}

/// Digest binding an authorization to the request that reserved it.
///
/// The voucher signature identifies what is being paid for; the requirements
/// pin the price, asset, and sponsor it was signed against, so a payload built
/// for another route cannot resume this one's reservation. The payload variant
/// is deliberately excluded: the scheme requires a retry that switches from
/// `deposit` to `voucher` to resolve to the same authorization (§Phase 5).
fn request_fingerprint(voucher_signature: &str, requirements: &BatchRequirements) -> String {
    use sha2::{Digest, Sha256};
    let max_timeout = requirements.max_timeout_seconds.to_string();
    let withdraw_delay = requirements.extra.withdraw_delay.to_string();
    let mut hasher = Sha256::new();
    for field in [
        voucher_signature,
        requirements.scheme.as_str(),
        requirements.network.as_str(),
        requirements.amount.as_str(),
        requirements.asset.as_str(),
        requirements.pay_to.as_str(),
        max_timeout.as_str(),
        requirements.extra.payment_flow.as_deref().unwrap_or(""),
        requirements.extra.fee_payer.as_str(),
        requirements
            .extra
            .receiver_authorizer
            .as_deref()
            .unwrap_or(""),
        withdraw_delay.as_str(),
        requirements.extra.token_program.as_str(),
        requirements.extra.memo.as_deref().unwrap_or(""),
    ] {
        // Length-prefixed: a `memo` is seller-supplied UTF-8, and an unprefixed
        // concatenation would let it impersonate the fields after it.
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    bs58::encode(hasher.finalize()).into_string()
}

fn decode_signature(signature_b58: &str) -> Result<[u8; 64], Error> {
    let bytes = bs58::decode(signature_b58)
        .into_vec()
        .map_err(|e| Error::Other(format!("invalid voucher signature: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::Other("voucher signature is not 64 bytes".into()))
}

fn encode_json<T: serde::Serialize>(value: &T) -> Result<String, Error> {
    let json = serde_json::to_string(value)
        .map_err(|e| Error::Other(format!("serialization failed: {e}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        json.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::protocol::schemes::batch_settlement::{
        BatchDeposit, BatchVoucher, MAX_WITHDRAW_DELAY_SECONDS,
    };
    use crate::x402::protocol::schemes::exact::programs;
    use async_trait::async_trait;
    use ed25519_dalek::{Signer as _, SigningKey};
    use solana_keychain::{SignTransactionResult, SignerError};
    use solana_signature::Signature;

    const PAY_TO: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";

    struct TestSigner {
        key: SigningKey,
        pubkey: Pubkey,
    }

    impl TestSigner {
        fn new(seed: u8) -> Self {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let pubkey = Pubkey::from(key.verifying_key().to_bytes());
            Self { key, pubkey }
        }
    }

    #[async_trait]
    impl SolanaSigner for TestSigner {
        fn pubkey(&self) -> Pubkey {
            self.pubkey
        }
        async fn sign_transaction(
            &self,
            _tx: &mut Transaction,
        ) -> Result<SignTransactionResult, SignerError> {
            Err(SignerError::Other("unused in these tests".to_string()))
        }
        async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
            Ok(Signature::from(self.key.sign(message).to_bytes()))
        }
        async fn is_available(&self) -> bool {
            true
        }
    }

    fn handler(store: Arc<dyn ChannelStore>) -> (X402BatchSettlement, Pubkey) {
        let signer = TestSigner::new(21);
        let fee_payer = signer.pubkey();
        let mut config = BatchConfig::new(PAY_TO, "localnet", Arc::new(signer));
        config.withdraw_delay = 3600;
        config.memo = Some("invoice-1".to_string());
        (
            X402BatchSettlement::with_store(config, store).expect("valid config"),
            fee_payer,
        )
    }

    /// A client keypair, its channel config against `fee_payer`, and the derived
    /// channel PDA.
    fn client(
        fee_payer: &Pubkey,
        requirements: &BatchRequirements,
    ) -> (SigningKey, BatchChannelConfig, Pubkey) {
        let key = SigningKey::from_bytes(&[22u8; 32]);
        let payer = pc::pubkey_string(&Pubkey::from(key.verifying_key().to_bytes()));
        let config = BatchChannelConfig {
            payer: payer.clone(),
            payer_authorizer: payer,
            receiver: requirements.pay_to.clone(),
            receiver_authorizer: None,
            token: requirements.asset.clone(),
            withdraw_delay: requirements.extra.withdraw_delay,
            salt: "42".to_string(),
            open_slot: 341_000_000,
        };
        let channel = derive_channel_id(
            &config,
            &pc::pubkey_string(fee_payer),
            &pc::default_program_id(),
        )
        .expect("derivable");
        (key, config, channel)
    }

    fn voucher(key: &SigningKey, channel: &Pubkey, max_claimable: u64) -> BatchVoucher {
        let message =
            pc::voucher_message_bytes(channel, max_claimable, VOUCHER_EXPIRES_AT).unwrap();
        BatchVoucher {
            channel_id: pc::pubkey_string(channel),
            max_claimable_amount: max_claimable.to_string(),
            expires_at: VOUCHER_EXPIRES_AT,
            signature: bs58::encode(key.sign(&message).to_bytes()).into_string(),
        }
    }

    fn header(requirements: &BatchRequirements, payload: BatchPayload) -> String {
        let envelope = BatchPaymentPayload {
            x402_version: X402_VERSION_V2,
            accepted: requirements.clone(),
            payload,
        };
        encode_json(&envelope).unwrap()
    }

    fn seeded(
        channel: &Pubkey,
        config: &BatchChannelConfig,
        deposit: u64,
        cumulative: u64,
    ) -> ChannelState {
        ChannelState {
            channel_id: pc::pubkey_string(channel),
            authorized_signer: config.payer_authorizer.clone(),
            deposit,
            cumulative,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            open_slot: Some(config.open_slot),
            payer: config.payer.clone(),
            rent_payer: String::new(),
            opening_challenge_id: String::new(),
            authentication: None,
            voucher_signer: "client".to_string(),
            idle_timeout_seconds: None,
            last_activity_at: 0,
            spent_amount: 0,
            settled_on_chain: 0,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
            pending_setup: None,
            // Fresh enough that the reservation path trusts it instead of
            // reaching for an RPC these tests do not have.
            onchain_checked_at: now_unix(),
            lifecycle: None,
            schema_version: CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        }
    }

    /// A deposit that confirmed on a first attempt must not be counted again
    /// when the request is retried.
    ///
    /// The first attempt can broadcast, confirm, and record the escrow and
    /// still fail afterwards — a store error while committing the voucher, say.
    /// If the retry re-added the same amount, the ceiling would exceed anything
    /// the chain will ever hold, the confirmed-state check could never pass,
    /// and the client's escrow would be stranded with its voucher permanently
    /// uncommittable.
    #[test]
    fn a_confirmed_deposit_is_not_counted_twice_on_retry() {
        let (_, fee_payer) = handler(Arc::new(MemoryChannelStore::new()));
        let requirements = BatchRequirements {
            scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
            network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
            amount: "1000".to_string(),
            asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            pay_to: PAY_TO.to_string(),
            max_timeout_seconds: 300,
            extra: BatchExtra {
                payment_flow: None,
                fee_payer: pc::pubkey_string(&fee_payer),
                receiver_authorizer: None,
                withdraw_delay: 3600,
                token_program: programs::TOKEN_PROGRAM.to_string(),
                memo: None,
                recent_blockhash: None,
                recent_slot: None,
                channel_state: None,
                voucher_state: None,
            },
        };
        let (_, config, channel) = client(&fee_payer, &requirements);
        let signature = "5xTopUpSignature";

        // Before the top-up is applied, its amount raises the ceiling.
        let state = seeded(&channel, &config, 5_000, 0);
        assert_eq!(
            X402BatchSettlement::deposit_ceiling(Some(&state), 3_000, Some(signature)).unwrap(),
            8_000
        );

        // After it confirms, the stored deposit already includes it, so the
        // ceiling is the confirmed deposit — not the confirmed deposit plus the
        // same top-up a second time.
        let mut applied = seeded(&channel, &config, 8_000, 0);
        applied
            .processed_topup_signatures
            .push(signature.to_string());
        assert_eq!(
            X402BatchSettlement::deposit_ceiling(Some(&applied), 3_000, Some(signature)).unwrap(),
            8_000
        );

        // A different top-up against the same channel still adds.
        assert_eq!(
            X402BatchSettlement::deposit_ceiling(Some(&applied), 3_000, Some("otherSignature"))
                .unwrap(),
            11_000
        );

        // A first deposit has no stored channel: the open is the whole escrow.
        assert_eq!(
            X402BatchSettlement::deposit_ceiling(None, 3_000, Some(signature)).unwrap(),
            3_000
        );
    }

    #[test]
    fn requirements_advertise_the_scheme_wire_contract() {
        let (handler, fee_payer) = handler(Arc::new(MemoryChannelStore::new()));
        let requirements = handler.requirements("0.001").expect("requirements build");
        assert_eq!(requirements.scheme, BATCH_SETTLEMENT_SCHEME);
        assert_eq!(requirements.amount, "1000");
        assert_eq!(requirements.pay_to, PAY_TO);
        assert_eq!(requirements.extra.fee_payer, pc::pubkey_string(&fee_payer));
        assert_eq!(requirements.extra.withdraw_delay, 3600);
        assert_eq!(requirements.extra.token_program, programs::TOKEN_PROGRAM);
        assert_eq!(requirements.extra.memo.as_deref(), Some("invoice-1"));
        // The flow is the protocol default, so it stays off the wire, and the
        // program id is never negotiated through `extra`.
        let json = serde_json::to_value(&requirements).unwrap();
        assert!(json["extra"].get("paymentFlow").is_none());
        assert!(json["extra"].get("channelProgram").is_none());
    }

    #[tokio::test]
    async fn withdraw_delay_outside_the_conformance_range_is_refused_at_verify() {
        let (mut handler, _) = handler(Arc::new(MemoryChannelStore::new()));
        handler.config.withdraw_delay = MAX_WITHDRAW_DELAY_SECONDS + 1;
        let requirements = handler.requirements("0.001").unwrap();
        // The challenge is still constructible, but a payment against it fails
        // closed rather than opening a channel the client cannot escape.
        let (key, config, channel) = client(&handler.fee_payer, &requirements);
        let payload = BatchPayload::Voucher {
            channel_config: config,
            voucher: voucher(&key, &channel, 1000),
        };
        let header = header(&requirements, payload);
        let err = handler.verify_payment(&header, "0.001").await.unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_WITHDRAW_DELAY_OUT_OF_RANGE
        );
    }

    #[tokio::test]
    async fn a_voucher_for_an_unknown_channel_is_refused() {
        let (handler, fee_payer) = handler(Arc::new(MemoryChannelStore::new()));
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        let payload = BatchPayload::Voucher {
            channel_config: config,
            voucher: voucher(&key, &channel, 1000),
        };
        let err = handler
            .verify_payment(&header(&requirements, payload), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CHANNEL_STATE
        );
    }

    #[tokio::test]
    async fn fixed_pricing_binds_the_next_voucher_and_the_deposit_ceiling() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        store
            .put_channel(
                &pc::pubkey_string(&channel),
                seeded(&channel, &config, 5_000, 2_000),
            )
            .await
            .unwrap();

        let payload = |max: u64| BatchPayload::Voucher {
            channel_config: config.clone(),
            voucher: voucher(&key, &channel, max),
        };

        // Exactly one price above the watermark is the only fresh voucher the
        // server accepts.
        let outcome = handler
            .verify_payment(&header(&requirements, payload(3_000)), "0.001")
            .await
            .expect("a correctly-stepped voucher verifies");
        assert!(outcome.serve);
        assert!(!outcome.replay);
        assert_eq!(outcome.charged_amount, 1_000);
        drop(outcome);

        // A larger step would let the client buy one request and authorize two.
        let err = handler
            .verify_payment(&header(&requirements, payload(4_000)), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH
        );

        // A stale voucher must not replay a past request into a fresh serve.
        let err = handler
            .verify_payment(&header(&requirements, payload(2_000)), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH
        );

        // And nothing may authorize beyond what is actually escrowed.
        let reseeded = seeded(&channel, &config, 3_500, 3_000);
        store
            .update_channel(
                &pc::pubkey_string(&channel),
                Box::new(move |_| Ok(reseeded)),
            )
            .await
            .unwrap();
        let err = handler
            .verify_payment(&header(&requirements, payload(4_000)), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CUMULATIVE_EXCEEDS_DEPOSIT
        );
    }

    #[tokio::test]
    async fn an_exact_repeat_is_a_replay_rather_than_a_second_serve() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        let repeated = voucher(&key, &channel, 3_000);
        let mut state = seeded(&channel, &config, 5_000, 3_000);
        state.highest_voucher_signature = Some(repeated.signature.clone());
        state.highest_voucher_expires_at = Some(VOUCHER_EXPIRES_AT);
        store
            .put_channel(&pc::pubkey_string(&channel), state)
            .await
            .unwrap();

        let payload = BatchPayload::Voucher {
            channel_config: config,
            voucher: repeated,
        };
        let outcome = handler
            .verify_payment(&header(&requirements, payload), "0.001")
            .await
            .expect("an exact repeat verifies");
        // The request was already paid for: it must not be charged or served
        // again.
        assert!(outcome.replay);
        assert!(!outcome.serve);
        assert_eq!(outcome.charged_amount, 0);
    }

    /// A channel seeded with `deposit`, and a closure that builds the paid
    /// request for one step above the current watermark.
    async fn paid_channel(
        store: &Arc<MemoryChannelStore>,
        handler: &X402BatchSettlement,
        fee_payer: &Pubkey,
        cumulative: u64,
    ) -> (BatchRequirements, String) {
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(fee_payer, &requirements);
        store
            .put_channel(
                &pc::pubkey_string(&channel),
                seeded(&channel, &config, 5_000, cumulative),
            )
            .await
            .unwrap();
        let payload = BatchPayload::Voucher {
            channel_config: config,
            voucher: voucher(&key, &channel, cumulative + 1_000),
        };
        let request = header(&requirements, payload);
        (requirements, request)
    }

    /// A handler failure charges nothing and leaves the same voucher usable.
    #[tokio::test]
    async fn a_failed_handler_releases_its_authorization_for_retry() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let (_, request) = paid_channel(&store, &handler, &fee_payer, 2_000).await;

        let BatchAccess::Serve(outcome) = handler
            .verify_and_reserve_payment(&request, "0.001")
            .await
            .expect("a correctly-stepped voucher reserves")
        else {
            panic!("a fresh authorization must be served");
        };
        let channel_id = outcome.channel_id.clone();
        handler
            .release_authorization(outcome)
            .await
            .expect("a failed handler releases");

        let state = store.get_channel(&channel_id).await.unwrap().unwrap();
        assert_eq!(state.cumulative, 2_000, "a released request is not charged");
        assert!(state.pending_deliveries.is_empty());

        // The same voucher is reservable again, which is the retry the client
        // is entitled to after a 500.
        assert!(matches!(
            handler
                .verify_and_reserve_payment(&request, "0.001")
                .await
                .expect("the same voucher verifies again"),
            BatchAccess::Serve(_)
        ));
    }

    /// A served request is charged exactly once, and a retry after a lost
    /// response gets the original result instead of a second execution.
    #[tokio::test]
    async fn a_served_handler_is_charged_once_and_then_replays() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let (_, request) = paid_channel(&store, &handler, &fee_payer, 2_000).await;

        let BatchAccess::Serve(outcome) = handler
            .verify_and_reserve_payment(&request, "0.001")
            .await
            .unwrap()
        else {
            panic!("a fresh authorization must be served");
        };
        let channel_id = outcome.channel_id.clone();
        handler.mark_handler_succeeded(&outcome).await.unwrap();
        let settled = handler.finish_commit(&outcome).await.expect("commits");
        // The outcome holds the channel's in-flight slot until it drops.
        drop(outcome);
        let charged = |response: &BatchSettlementResponse| {
            response
                .extra
                .as_ref()
                .and_then(|extra| extra.charged_amount.clone())
        };
        assert_eq!(charged(&settled).as_deref(), Some("1000"));

        let state = store.get_channel(&channel_id).await.unwrap().unwrap();
        assert_eq!(state.cumulative, 3_000);

        // The retry is answered from the stored response, not by serving again.
        let BatchAccess::Replay(replayed) = handler
            .verify_and_reserve_payment(&request, "0.001")
            .await
            .expect("the same voucher verifies")
        else {
            panic!("a committed authorization must replay");
        };
        assert_eq!(charged(&replayed), charged(&settled));
        assert_eq!(
            store
                .get_channel(&channel_id)
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            3_000,
            "a replay must not charge again"
        );
    }

    /// A served request is still charged when the success marker could not be
    /// written. The marker makes "the handler ran" survive a crash; committing
    /// needs the reservation, not the marker, so losing it must not turn a
    /// served request into a free one.
    #[tokio::test]
    async fn a_served_request_is_charged_even_without_its_marker() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let (_, request) = paid_channel(&store, &handler, &fee_payer, 2_000).await;

        let BatchAccess::Serve(outcome) = handler
            .verify_and_reserve_payment(&request, "0.001")
            .await
            .unwrap()
        else {
            panic!("a fresh authorization must be served");
        };
        let channel_id = outcome.channel_id.clone();
        // The marker write failed, so the reservation is still unmarked.
        let settled = handler
            .finish_commit(&outcome)
            .await
            .expect("an unmarked reservation still commits");
        drop(outcome);
        assert!(settled.success);
        assert_eq!(
            store
                .get_channel(&channel_id)
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            3_000,
            "the served request is charged exactly once"
        );

        // And the retry is answered as a replay, not refused: an unmarked
        // reservation that was charged anyway leaves nothing stranded.
        assert!(matches!(
            handler
                .verify_and_reserve_payment(&request, "0.001")
                .await
                .expect("the same voucher verifies"),
            BatchAccess::Replay(_)
        ));
    }

    /// The crash boundary. Once the handler has succeeded, a retry may only
    /// finish the charge — it must never run the handler a second time.
    #[tokio::test]
    async fn a_crash_after_serving_can_only_finish_the_charge() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let (_, request) = paid_channel(&store, &handler, &fee_payer, 2_000).await;

        let BatchAccess::Serve(outcome) = handler
            .verify_and_reserve_payment(&request, "0.001")
            .await
            .unwrap()
        else {
            panic!("a fresh authorization must be served");
        };
        let channel_id = outcome.channel_id.clone();
        handler.mark_handler_succeeded(&outcome).await.unwrap();
        // The commit never ran: drop the outcome as a crashed process would.
        drop(outcome);

        let BatchAccess::Resume(outcome) = handler
            .verify_and_reserve_payment(&request, "0.001")
            .await
            .expect("the same voucher verifies")
        else {
            panic!("a served authorization must resume, not serve");
        };
        let settled = handler.finish_commit(&outcome).await.expect("commits");
        assert!(settled.success);
        assert_eq!(
            store
                .get_channel(&channel_id)
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            3_000,
            "the resumed commit charges exactly one request"
        );
    }

    /// The reservation is store-backed, so a second replica presenting the same
    /// authorization is turned away instead of serving it in parallel — the
    /// process-local guard is only a fast path.
    #[tokio::test]
    async fn a_live_reservation_turns_away_a_second_replica() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let (_, request) = paid_channel(&store, &handler, &fee_payer, 2_000).await;

        let BatchAccess::Serve(outcome) = handler
            .verify_and_reserve_payment(&request, "0.001")
            .await
            .unwrap()
        else {
            panic!("a fresh authorization must be served");
        };
        // Release the in-process guard while leaving the durable reservation
        // live: the shape another replica sees.
        drop(outcome);

        assert!(matches!(
            handler
                .verify_and_reserve_payment(&request, "0.001")
                .await
                .expect("verification itself succeeds"),
            BatchAccess::InProgress
        ));
    }

    /// Every immutable field of a recovered channel is bound to the payload
    /// that claims it. A channel this server did not sponsor, or one carrying
    /// a distribution that pays someone else, must not become a usable record.
    #[test]
    fn recovering_a_channel_binds_it_to_the_payload_that_claims_it() {
        use crate::core::payment_channels::generated::types::SettlementWatermarks;

        let (handler, fee_payer) = handler(Arc::new(MemoryChannelStore::new()));
        let requirements = handler.requirements("0.001").unwrap();
        let (_, config, _) = client(&fee_payer, &requirements);
        let receiver = pc::parse_pubkey(&requirements.pay_to).unwrap();
        let onchain = |mutate: &dyn Fn(&mut Channel)| {
            let mut channel = Channel {
                discriminator: 0,
                version: 1,
                bump: 0,
                status: CHANNEL_STATUS_OPEN,
                salt: config.salt.parse().unwrap(),
                deposit: 5_000,
                settlement: SettlementWatermarks {
                    settled: 2_000,
                    payout_watermark: 0,
                },
                closure_started_at: 0,
                payer_withdrawn_at: 0,
                grace_period: config.withdraw_delay,
                distribution_hash: pc::distribution_hash(&pc::sole_recipient(&receiver)),
                payer: pc::to_address(&pc::parse_pubkey(&config.payer).unwrap()),
                payee: pc::to_address(&fee_payer),
                authorized_signer: pc::to_address(
                    &pc::parse_pubkey(&config.payer_authorizer).unwrap(),
                ),
                mint: pc::to_address(&pc::parse_pubkey(&config.token).unwrap()),
                rent_payer: pc::to_address(&fee_payer),
                open_slot: config.open_slot,
            };
            mutate(&mut channel);
            channel
        };
        let check = |channel: &Channel, min_deposit: u64| {
            handler.check_channel_bindings(channel, &config, &requirements.pay_to, min_deposit)
        };

        check(&onchain(&|_| {}), 0).expect("a matching channel recovers");

        // A channel whose rent this server never fronted is not its channel to
        // charge against, and neither is one it is not the payee of.
        let stranger = pc::to_address(&Pubkey::from([9u8; 32]));
        type Mutation<'a> = (&'a str, &'a dyn Fn(&mut Channel));
        let cases: [Mutation; 9] = [
            ("payee", &|c: &mut Channel| c.payee = stranger),
            ("rent_payer", &|c: &mut Channel| c.rent_payer = stranger),
            ("payer", &|c: &mut Channel| c.payer = stranger),
            ("authorized_signer", &|c: &mut Channel| {
                c.authorized_signer = stranger
            }),
            ("mint", &|c: &mut Channel| c.mint = stranger),
            ("grace_period", &|c: &mut Channel| c.grace_period += 1),
            ("open_slot", &|c: &mut Channel| c.open_slot += 1),
            // The payout destination is only committed as a hash, so a channel
            // that would pay someone else must be caught by rebuilding it.
            ("distribution", &|c: &mut Channel| {
                c.distribution_hash = [7u8; 32]
            }),
            ("status", &|c: &mut Channel| {
                c.status = CHANNEL_STATUS_CLOSING
            }),
        ];
        for (what, mutate) in cases {
            let err = check(&onchain(mutate), 0)
                .err()
                .unwrap_or_else(|| panic!("{what} must not bind"));
            assert_eq!(
                crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
                codes::INVALID_CHANNEL_STATE,
                "{what}"
            );
        }

        // `salt` is deliberately absent: it is a PDA seed, so an account at the
        // address the caller derived can only have been opened with it.

        // And the escrow must cover what the caller needs it to.
        check(&onchain(&|_| {}), 5_000).expect("a deposit that exactly covers passes");
        check(&onchain(&|_| {}), 5_001).expect_err("an escrow short of the need is refused");
    }

    /// Settlement accounts are decoded, not just probed for existence: a
    /// frozen, wrong-mint or uninitialized ATA fails `distribute` only after
    /// the escrow is locked and the request served.
    #[test]
    fn settlement_account_decoding_rejects_unusable_token_accounts() {
        let mint = Pubkey::from([3u8; 32]);
        let owner = Pubkey::from([4u8; 32]);
        let account = |state: u8, len: usize| {
            let mut data = vec![0u8; len];
            if len >= 64 {
                data[0..32].copy_from_slice(&mint.to_bytes());
                data[32..64].copy_from_slice(&owner.to_bytes());
            }
            if len > 108 {
                data[108] = state;
            }
            data
        };

        let live = decode_token_account(&account(TOKEN_ACCOUNT_INITIALIZED, TOKEN_ACCOUNT_LEN))
            .expect("an initialized token account decodes");
        assert_eq!(live.mint, mint);
        assert_eq!(live.owner, owner);
        assert_eq!(live.state, TOKEN_ACCOUNT_INITIALIZED);

        // Token-2022 appends extensions after the same base layout.
        assert!(decode_token_account(&account(TOKEN_ACCOUNT_INITIALIZED, 300)).is_some());

        // A frozen account is decodable but unusable, and the caller rejects it
        // on the state byte.
        assert_eq!(
            decode_token_account(&account(TOKEN_ACCOUNT_FROZEN, TOKEN_ACCOUNT_LEN))
                .expect("a frozen account still decodes")
                .state,
            TOKEN_ACCOUNT_FROZEN
        );

        // An uninitialized (or non-token) account is too short to be one.
        assert!(decode_token_account(&account(0, 0)).is_none());
        assert!(decode_token_account(&account(0, TOKEN_ACCOUNT_LEN - 1)).is_none());

        // A Token-2022 account carries a type byte and a TLV extension list.
        // `ImmutableOwner` is inert and every ATA has it, so it passes; a
        // padded tail is the end of the list, not an extension.
        let extended = |extensions: &[(u16, &[u8])]| {
            let mut data = account(TOKEN_ACCOUNT_INITIALIZED, TOKEN_ACCOUNT_LEN);
            data.push(TOKEN_ACCOUNT_TYPE);
            for (kind, value) in extensions {
                data.extend_from_slice(&kind.to_le_bytes());
                data.extend_from_slice(&(value.len() as u16).to_le_bytes());
                data.extend_from_slice(value);
            }
            data
        };
        assert!(decode_token_account(&extended(&[]))
            .unwrap()
            .unsupported_extension
            .is_none());
        assert!(
            decode_token_account(&extended(&[(EXTENSION_IMMUTABLE_OWNER, &[])]))
                .unwrap()
                .unsupported_extension
                .is_none()
        );

        // Everything else changes what a payout means: withholding part of a
        // transfer, requiring a memo before it, blocking it from a CPI, or
        // moving the balance out of the classic ledger.
        for unsupported in [
            2u16, // TransferFeeAmount
            5,    // ConfidentialTransferAccount
            8,    // MemoTransfer
            11,   // CpiGuard
            13,   // NonTransferableAccount
            15,   // TransferHookAccount
            27,   // PausableAccount
        ] {
            assert_eq!(
                decode_token_account(&extended(&[(unsupported, &[0u8; 8])]))
                    .unwrap()
                    .unsupported_extension,
                Some(unsupported),
                "extension {unsupported} must be refused"
            );
        }
        // Including one hiding behind an allowed extension.
        assert_eq!(
            decode_token_account(&extended(&[
                (EXTENSION_IMMUTABLE_OWNER, &[]),
                (8, &[0u8; 8]),
            ]))
            .unwrap()
            .unsupported_extension,
            Some(8)
        );
        // A truncated TLV is refused rather than skipped.
        let mut truncated = extended(&[]);
        truncated.extend_from_slice(&[7u8, 0]);
        assert!(decode_token_account(&truncated)
            .unwrap()
            .unsupported_extension
            .is_some());
    }

    #[tokio::test]
    async fn a_channel_admits_one_request_at_a_time() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        store
            .put_channel(
                &pc::pubkey_string(&channel),
                seeded(&channel, &config, 5_000, 0),
            )
            .await
            .unwrap();
        let payload = || BatchPayload::Voucher {
            channel_config: config.clone(),
            voucher: voucher(&key, &channel, 1_000),
        };

        let first = handler
            .verify_payment(&header(&requirements, payload()), "0.001")
            .await
            .expect("first request verifies");
        // Without serialization two concurrent requests could both read the
        // watermark, both serve, and only one commit.
        let err = handler
            .verify_payment(&header(&requirements, payload()), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::DUPLICATE_SETTLEMENT
        );

        // Dropping the outcome releases the channel, including on the error and
        // panic paths.
        drop(first);
        handler
            .verify_payment(&header(&requirements, payload()), "0.001")
            .await
            .expect("the channel is free again");
    }

    #[tokio::test]
    async fn a_payload_built_for_other_requirements_is_refused() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        store
            .put_channel(
                &pc::pubkey_string(&channel),
                seeded(&channel, &config, 5_000, 0),
            )
            .await
            .unwrap();

        // A payload whose `accepted` names a cheaper price than the route: the
        // client must not be able to pay one route's price for another's.
        let mut cheaper = requirements.clone();
        cheaper.amount = "1".to_string();
        let payload = BatchPayload::Voucher {
            channel_config: config,
            voucher: voucher(&key, &channel, 1),
        };
        let err = handler
            .verify_payment(&header(&cheaper, payload), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CHANNEL_STATE
        );
    }

    #[tokio::test]
    async fn a_refund_carrying_a_cooperative_hint_is_refused() {
        let (handler, fee_payer) = handler(Arc::new(MemoryChannelStore::new()));
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        let payload = BatchPayload::Refund {
            channel_config: config,
            transaction: "b64".to_string(),
            voucher: Some(voucher(&key, &channel, 1_000)),
            close_authorization: None,
        };
        let err = handler
            .verify_payment(&header(&requirements, payload), "0.001")
            .await
            .unwrap_err();
        // A receiver-authorizer key in an untrusted request is not a trust
        // anchor, so the shortcut is refused rather than silently ignored.
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CLOSE_AUTHORIZATION
        );
    }

    #[test]
    fn payment_headers_must_name_this_scheme() {
        let (handler, _) = handler(Arc::new(MemoryChannelStore::new()));
        let mut requirements = handler.requirements("0.001").unwrap();
        requirements.scheme = "exact".to_string();
        let payload = BatchPayload::Deposit {
            channel_config: BatchChannelConfig {
                payer: PAY_TO.to_string(),
                payer_authorizer: PAY_TO.to_string(),
                receiver: PAY_TO.to_string(),
                receiver_authorizer: None,
                token: requirements.asset.clone(),
                withdraw_delay: 3600,
                salt: "1".to_string(),
                open_slot: 1,
            },
            voucher: BatchVoucher {
                channel_id: PAY_TO.to_string(),
                max_claimable_amount: "1".to_string(),
                expires_at: 0,
                signature: "sig".to_string(),
            },
            deposit: BatchDeposit {
                amount: "1".to_string(),
                transaction: "b64".to_string(),
            },
        };
        let err = handler
            .parse_payment(&header(&requirements, payload))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidPayloadType(scheme) if scheme == "exact"));
    }

    #[test]
    fn settlement_headers_round_trip_the_payment_response() {
        let (handler, _) = handler(Arc::new(MemoryChannelStore::new()));
        let response = BatchSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some(PAY_TO.to_string()),
            transaction: String::new(),
            network: handler.network(),
            amount: String::new(),
            extra: Some(BatchSettlementExtra {
                commitment_id: Some("chan:5000".to_string()),
                charged_amount: Some("1000".to_string()),
                channel_state: None,
            }),
        };
        let (name, value) = handler.settlement_header(&response).unwrap();
        assert_eq!(name, PAYMENT_RESPONSE_HEADER);
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).unwrap();
        let back: BatchSettlementResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(back.success);
        assert_eq!(
            back.extra.unwrap().commitment_id.as_deref(),
            Some("chan:5000")
        );
    }

    #[tokio::test]
    async fn a_corrective_challenge_proves_what_it_claims_to_have_charged() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        let held = voucher(&key, &channel, 3_000);
        let mut state = seeded(&channel, &config, 5_000, 3_000);
        state.highest_voucher_signature = Some(held.signature.clone());
        state.highest_voucher_expires_at = Some(VOUCHER_EXPIRES_AT);
        store
            .put_channel(&pc::pubkey_string(&channel), state)
            .await
            .unwrap();

        let envelope = handler
            .corrective_challenge("0.001", &pc::pubkey_string(&channel), None)
            .await
            .expect("corrective challenge builds");
        assert_eq!(
            envelope.error.as_deref(),
            Some(codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH)
        );
        let extra = &envelope.accepts[0].extra;
        let snapshot = extra.channel_state.as_ref().expect("snapshot present");
        assert_eq!(snapshot.charged_cumulative_amount.as_deref(), Some("3000"));
        // The proof is the client's own signature at that amount, so the client
        // can verify the server is not inflating the base it will sign from.
        let proof = extra.voucher_state.as_ref().expect("proof present");
        assert_eq!(proof.signed_max_claimable, "3000");
        assert_eq!(proof.signature, held.signature);
        crate::x402::protocol::schemes::batch_settlement::check_corrective_voucher_state(
            proof,
            &pc::pubkey_string(&channel),
            &config.payer_authorizer,
            3_000,
        )
        .expect("the client accepts the proof");
    }
}
