//! Server-side session intent — challenge issuance, voucher verification,
//! and channel lifecycle management.
//!
//! # Overview
//!
//! 1. Server calls [`SessionServer::build_challenge_request`] to produce the
//!    `SessionRequest` embedded in a 402 challenge.
//! 2. Client responds with `SessionAction::Open` — server calls
//!    [`SessionServer::process_open`] to record the channel.
//! 3. For each subsequent API call the client attaches `SessionAction::Voucher`
//!    — server calls [`SessionServer::verify_voucher`] to validate and advance
//!    the settled watermark atomically.
//! 4. At session end the client (or server) triggers close. The server calls
//!    [`SessionServer::seal_params`] to get the parameters needed to
//!    submit on-chain seal + distribute transactions.
//!
//! Open credentials are fully validated before a pending intent is durably
//! persisted, then broadcast, confirmed, and activated. Pending channels cannot
//! authorize service. Lifecycle workers can resume a stored intent after a
//! crash without a new client request. Top-ups likewise require confirmation.
//!
//! Replayed `open` payloads for an existing channel are idempotent: they
//! never reset the voucher watermark or any other channel state.
//!
//! A charge (voucher, `use`, metered delivery) is admitted only on a confirmed
//! read of the channel account at most [`CHANNEL_SNAPSHOT_MAX_AGE_SECONDS`]
//! old, re-read as needed. A read showing a forced close sets
//! `close_requested_at` and makes the channel's lifecycle due at once; the host
//! must then settle it with [`SessionServer::seal_params`] before the grace
//! period ends.

use solana_pubkey::Pubkey;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::core::session::VoucherAcceptance;
use crate::core::store::{ObservedLifecycle, OnchainObservation};
use crate::core::tx::{TxV1Mode, TxVersion};
use crate::mpp::error::{Error, Result};
use crate::mpp::program::payment_channels;
use crate::mpp::protocol::core::{Receipt, ReceiptKind};
use crate::mpp::protocol::intents::session::{
    resolve_idle_timeout_seconds, validate_idle_timeout_options, ClosePayload, CommitPayload,
    CommitReceipt, CommitStatus, MeteringDirective, OpenPayload, SessionMethodDetails,
    SessionReceiptExtensions, SessionReceiptIntent, SessionRequest, SessionSplit, SignedVoucher,
    TopUpPayload, UsePayload, VoucherData, VoucherPayload, VoucherSignatureType,
};
use crate::mpp::protocol::solana::default_token_program_for_currency;
use crate::mpp::store::{
    ChannelLifecycle, ChannelState, ChannelStore, CommittedDelivery, PendingDelivery, StoreError,
    CHANNEL_STATE_SCHEMA_VERSION,
};

#[path = "session_binding.rs"]
mod binding;
pub use binding::{channel_binding, SessionConfigSnapshot};

// ── Configuration ──

/// Verified outer challenge facts required while opening a session.
#[derive(Debug, Clone, Copy)]
pub struct SessionOpenContext<'a> {
    /// ID of the challenge echoed by the opening credential.
    pub challenge_id: &'a str,
    /// Standard challenge expiry from the `expires` auth-param.
    pub expires: Option<&'a str>,
    /// The challenged `methodDetails.recentBlockhash` (base58). The open
    /// transaction's compiled message MUST use exactly this blockhash.
    pub recent_blockhash: &'a str,
    /// The challenged `methodDetails.recentSlot`. The payload's `openSlot`
    /// MUST be no later than it and within [`payment_channels::OPEN_SLOT_WINDOW`].
    pub recent_slot: u64,
}

impl SessionOpenContext<'_> {
    fn ensure_not_expired(self) -> Result<()> {
        let Some(expires) = self.expires else {
            return Ok(());
        };
        let expiry = OffsetDateTime::parse(expires, &Rfc3339)
            .map_err(|_| Error::ChallengeExpired(expires.to_string()))?;
        if expiry <= OffsetDateTime::now_utc() {
            return Err(Error::ChallengeExpired(expires.to_string()));
        }
        Ok(())
    }
}

/// A payment split committed at channel open; distributed at close.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Split {
    pub recipient: Pubkey,
    /// Share in basis points.
    pub bps: u16,
}

/// Who signs the channel's vouchers.
pub use crate::mpp::protocol::intents::session::SessionVoucherSigner as VoucherSigner;

impl VoucherSigner {
    /// Resolve the authorized voucher signer for the selected mode.
    pub fn authorized_signer(self, operator: Pubkey, client: Pubkey) -> Pubkey {
        match self {
            Self::Operator => operator,
            Self::Client => client,
        }
    }
}

/// Result of accepting a channel-open action.
#[derive(Debug, Clone)]
pub struct OpenAcceptance {
    /// Persisted channel state after processing the open.
    pub state: ChannelState,
    /// Whether the channel already existed and the open was an idempotent replay.
    pub replay: bool,
    /// Confirmed transaction signature after any server fee-payer co-signing.
    pub transaction_signature: String,
}

const OPERATOR_VOUCHER_ERROR: &str =
    "a voucher does not authenticate an operator-signed session; present the session bearer proof (use)";
const OPEN_INTENT_KEY: &str = "mppSessionOpenIntent";
const OPEN_TERMINAL_KEY: &str = "mppSessionOpenTerminal";
const OPEN_TERMINAL_ERROR: &str = "session open expired without funding; request a new channel";
const OPENED_ELSEWHERE_ERROR: &str =
    "channel was opened outside this server's ledger and cannot be adopted; open a new channel";

/// Index of the channel PDA among the `open` instruction's accounts.
const OPEN_CHANNEL_ACCOUNT: usize = 5;

/// Longest a confirmed read of a channel account admits new charges on it.
///
/// The payer can start a forced close at any time; the server learns of it at
/// most this long later and must still settle inside the grace period. It is
/// further capped at half the configured grace period.
pub const CHANNEL_SNAPSHOT_MAX_AGE_SECONDS: u64 = 30;

/// An open credential that passed the credential checks.
struct ValidatedOpen {
    deposit: u64,
    effective_idle_timeout: u32,
    params: payment_channels::OpenChannelParams,
}

/// Outcome of broadcasting a verified open.
enum OpenSubmission {
    /// The open is confirmed on-chain, with its settled watermark.
    Landed { signature: String, settled: u64 },
    /// A fresh open whose transaction had already landed before this
    /// server's first broadcast: another ledger owns the channel.
    OpenedElsewhere,
}

/// Whether an open has been retired after finalized expiry reconciliation.
/// This is a local tombstone, not an on-chain seal. Keep the row and open a
/// different channel; lifecycle workers must not submit transactions for it.
pub fn session_open_is_terminal(state: &ChannelState) -> bool {
    state.extra.contains_key(OPEN_TERMINAL_KEY)
}

/// A cluster slot observed before this ledger's first broadcast of an open.
/// Only a landing after it proves this ledger opened the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdoptionFloor {
    Slot(u64),
    /// Nothing recorded bounds the first broadcast; the open is never adopted.
    Unproven,
}

impl AdoptionFloor {
    fn slot(self) -> Result<u64> {
        match self {
            Self::Slot(slot) => Ok(slot),
            Self::Unproven => Err(Error::Other(
                "pending open has no recorded broadcast floor and cannot be adopted".into(),
            )),
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(from = "StoredOpenIntent", into = "StoredOpenIntent")]
struct OpenIntent {
    version: u32,
    payload: OpenPayload,
    challenge_id: String,
    recent_blockhash: String,
    recent_slot: u64,
    /// Positive finalized observation, persisted before any server broadcast.
    finalized_valid_at: Option<u64>,
    /// Fully signed transaction ID (the sponsor signature for sponsored opens).
    transaction_signature: Option<String>,
    adoption_floor: AdoptionFloor,
}

/// The persisted form of [`OpenIntent`].
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOpenIntent {
    version: u32,
    payload: OpenPayload,
    challenge_id: String,
    recent_blockhash: String,
    recent_slot: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finalized_valid_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adoption_floor: Option<u64>,
}

impl From<StoredOpenIntent> for OpenIntent {
    fn from(stored: StoredOpenIntent) -> Self {
        // Rows written before floors were recorded still persisted their
        // finalized observation before broadcasting: a finalized slot is at or
        // below the cluster slot at that moment, so it is a coarser floor.
        let adoption_floor = stored
            .adoption_floor
            .or(stored.finalized_valid_at)
            .map_or(AdoptionFloor::Unproven, AdoptionFloor::Slot);
        Self {
            version: stored.version,
            payload: stored.payload,
            challenge_id: stored.challenge_id,
            recent_blockhash: stored.recent_blockhash,
            recent_slot: stored.recent_slot,
            finalized_valid_at: stored.finalized_valid_at,
            transaction_signature: stored.transaction_signature,
            adoption_floor,
        }
    }
}

/// Whether a stored intent is `expected`, compared in its loaded form so a row
/// written by an older release matches its own migrated intent.
fn same_open_intent(stored: &serde_json::Value, expected: &serde_json::Value) -> bool {
    serde_json::from_value::<OpenIntent>(stored.clone())
        .ok()
        .and_then(|intent| serde_json::to_value(intent).ok())
        .is_some_and(|stored| &stored == expected)
}

impl From<OpenIntent> for StoredOpenIntent {
    fn from(intent: OpenIntent) -> Self {
        Self {
            version: intent.version,
            payload: intent.payload,
            challenge_id: intent.challenge_id,
            recent_blockhash: intent.recent_blockhash,
            recent_slot: intent.recent_slot,
            finalized_valid_at: intent.finalized_valid_at,
            transaction_signature: intent.transaction_signature,
            adoption_floor: match intent.adoption_floor {
                AdoptionFloor::Slot(slot) => Some(slot),
                AdoptionFloor::Unproven => None,
            },
        }
    }
}

/// Result of accepting a channel top-up action.
#[derive(Debug, Clone)]
pub struct TopUpAcceptance {
    /// Persisted channel state after processing the top-up.
    pub state: ChannelState,
    /// Whether this exact confirmed transaction had already been credited.
    pub replay: bool,
    /// Confirmed transaction signature after any server fee-payer co-signing.
    pub transaction_signature: String,
}

/// Result of accepting an operator-signed use action.
#[derive(Debug, Clone)]
pub struct UseAcceptance {
    /// Operator-signed cumulative voucher covering the use.
    pub voucher: SignedVoucher,
    /// Whether the idempotency key had already been processed.
    pub replay: bool,
}

/// A `use` proof that matched the proof bound at open. Only
/// [`SessionServer::authenticate_use`] produces one, and
/// [`SessionServer::charge_operator_request`] takes nothing else, so a metered
/// operator charge is never made for a request that did not authenticate
/// (draft-solana-session-00 §Debit Processing step 1). It carries the
/// request's `(challengeId, idempotencyKey)`, so the charge it authorizes is
/// recorded under them and a retry of the same request is not charged twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUse {
    channel_id: String,
    authentication: String,
    challenge_id: String,
    idempotency_key: String,
}

impl AuthenticatedUse {
    /// The authenticated channel.
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    /// The request's idempotency key.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}

/// A metered charge on an operator-signed session.
#[derive(Debug, Clone)]
pub struct OperatorCharge {
    /// Operator-signed cumulative voucher persisted for the request.
    pub voucher: SignedVoucher,
    /// Accepted cumulative before this call's charge.
    pub previous_cumulative: u64,
    /// Accepted cumulative after it.
    pub cumulative: u64,
    /// What this call charged: the request's new total less what it had
    /// already been charged. Zero on a replay.
    pub charged: u64,
    /// The request's total charged so far.
    pub request_total: u64,
    /// Whether the request had already been charged up to the total asked:
    /// the voucher is the one recorded then, and nothing was charged now.
    pub replay: bool,
}

/// Attempts [`SessionServer::charge_operator_request`] makes before
/// reporting that concurrent charges kept moving the watermark.
const OPERATOR_CHARGE_ATTEMPTS: usize = 8;

/// Most requests a channel remembers for idempotent replay, most recently
/// charged first. A long-lived channel serves far more requests than any
/// host retries, so the record is bounded; a retry of a request older than
/// this is charged as a new one.
pub const MAX_PROCESSED_USES: usize = 256;
#[derive(Clone)]
pub struct SessionConfig {
    /// Operator public key (base58). Shown to clients in the challenge.
    pub operator: String,

    /// Primary payment recipient (base58).
    pub recipient: String,

    /// Optional splits routed to specific recipients at close.
    pub splits: Vec<Split>,

    /// Price per unit of service (base units).
    pub amount: u64,

    /// Suggested initial channel deposit.
    pub suggested_deposit: Option<u64>,

    /// Minimum accepted initial channel deposit.
    ///
    /// Required when [`fee_payer_signer`](Self::fee_payer_signer) is set: a
    /// sponsored open makes the sponsor fund the channel and escrow rent, so
    /// the refundable deposit is what it costs a client to make the sponsor
    /// lock that SOL. A sponsored server without one refuses to issue
    /// challenges or accept opens.
    pub minimum_deposit: Option<u64>,

    /// Currency identifier accepted in configuration (e.g., "USDC" or a mint).
    /// Challenges always normalize this to a concrete SPL mint address.
    pub currency: String,

    /// Token decimals (0 through 9; default 6 for USDC).
    pub decimals: u8,

    /// Solana network: "mainnet", "devnet", "localnet".
    pub network: String,

    /// Payment-channel program ID. `None` defaults to the canonical program.
    pub channel_program: Option<Pubkey>,

    /// Channel ABI version. `None` retains the V1 deployment.
    pub channel_version: Option<u8>,

    /// Immutable V2 lifecycle callbacks; never submitted as top-level instructions.
    pub channel_hooks: Option<crate::core::payment_channels_v2::ChannelHooks>,

    /// SPL token program override.
    pub token_program: Option<Pubkey>,

    /// Minimum voucher increment (base units). 0 = no minimum.
    pub min_voucher_delta: u64,

    /// Voucher signing authority, independent of transaction submission mode.
    pub voucher_signer: VoucherSigner,

    /// Ed25519 key used to issue vouchers in operator mode.
    pub operator_signing_key: Option<ed25519_dalek::SigningKey>,

    /// Optional operator signer that sponsors session transaction fees and
    /// channel-account rent. When set, challenges advertise `feePayer: true`
    /// and clients leave this signer's fee-payer slot empty for the server to
    /// co-sign after validating the transaction. Requires
    /// [`minimum_deposit`](Self::minimum_deposit).
    pub fee_payer_signer: Option<std::sync::Arc<dyn solana_keychain::TransactionSigner>>,

    /// Inactivity thresholds offered for a new channel.
    pub idle_timeout_options_seconds: Option<Vec<u32>>,

    /// Server-selected inactivity threshold in seconds.
    pub idle_timeout_seconds: u32,

    /// Forced-close grace period (seconds) used as the voucher settlement
    /// window: a non-zero voucher expiry MUST outlast this window so the
    /// operator can still redeem the voucher on-chain after the asynchronous
    /// forced-close delay. Mirrors the channel's on-chain grace period.
    pub grace_period_seconds: u32,

    /// Solana RPC URL for on-chain open-transaction verification.
    ///
    /// Required by open and top-up processing. Missing RPC configuration is a
    /// hard error; funding is never inferred from payload claims.
    pub rpc_url: Option<String>,
}

impl std::fmt::Debug for SessionConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionConfig")
            .field("operator", &self.operator)
            .field("recipient", &self.recipient)
            .field("splits", &self.splits)
            .field("amount", &self.amount)
            .field("suggested_deposit", &self.suggested_deposit)
            .field("minimum_deposit", &self.minimum_deposit)
            .field("currency", &self.currency)
            .field("decimals", &self.decimals)
            .field("network", &self.network)
            .field("channel_program", &self.channel_program)
            .field("token_program", &self.token_program)
            .field("min_voucher_delta", &self.min_voucher_delta)
            .field("voucher_signer", &self.voucher_signer)
            .field("operator_signing_key", &self.operator_signing_key.is_some())
            .field(
                "fee_payer_signer",
                &self.fee_payer_signer.as_ref().map(|signer| signer.pubkey()),
            )
            .field(
                "idle_timeout_options_seconds",
                &self.idle_timeout_options_seconds,
            )
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .field("grace_period_seconds", &self.grace_period_seconds)
            .field("rpc_url", &self.rpc_url.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl SessionConfig {
    /// Validate the advertised program and ABI together before serving or recovering.
    pub fn channel_deployment(&self) -> Result<crate::core::payment_channels_v2::Deployment> {
        crate::mpp::program::channel_deployment::resolve_for_network(
            self.channel_program
                .unwrap_or_else(payment_channels::default_program_id),
            self.channel_version,
            self.channel_hooks.as_ref(),
            &self.network,
        )
    }

    /// A sponsor fronts the rent of every channel it opens, so it must name
    /// the deposit floor that buys that rent rather than accept any non-zero
    /// deposit.
    fn check_sponsored_deposit_floor(&self) -> Result<()> {
        if self.fee_payer_signer.is_some() && self.minimum_deposit.is_none() {
            return Err(Error::InvalidConfig(
                "sponsored sessions (fee_payer_signer) require minimum_deposit: the sponsor \
                 funds each channel's rent"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            operator: String::new(),
            recipient: String::new(),
            splits: vec![],
            amount: 1,
            suggested_deposit: Some(10_000_000),
            minimum_deposit: None,
            currency: "USDC".to_string(),
            decimals: 6,
            network: "mainnet".to_string(),
            channel_program: None,
            channel_version: None,
            channel_hooks: None,
            token_program: None,
            min_voucher_delta: 0,
            voucher_signer: VoucherSigner::Client,
            operator_signing_key: None,
            fee_payer_signer: None,
            idle_timeout_options_seconds: None,
            idle_timeout_seconds: 300,
            grace_period_seconds: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            rpc_url: None,
        }
    }
}

// ── Parameters returned to the caller for on-chain settlement ──

/// Parameters needed to submit a seal + distribute transaction pair.
#[derive(Debug, Clone)]
pub struct SealParams {
    /// On-chain channel address.
    pub channel_id: Pubkey,

    /// Public key authorized to sign vouchers for this channel.
    pub authorized_signer: Option<Pubkey>,

    /// Original channel payer.
    pub payer: Option<Pubkey>,

    /// Rent payer recorded at open; the program refunds rent to exactly this
    /// account at distribution.
    pub rent_payer: Option<Pubkey>,

    /// SPL mint locked by the channel.
    pub mint: Option<Pubkey>,

    /// Payment-channels program ID.
    pub program_id: Pubkey,

    /// Persisted ABI selection and immutable callback configuration.
    pub channel_version: Option<u8>,
    pub channel_hooks: Option<crate::core::payment_channels_v2::ChannelHooks>,

    /// The settled watermark to commit on-chain.
    pub settled: u64,

    /// Signature for the highest accepted voucher.
    pub voucher_signature: Option<String>,

    /// Expiry timestamp for the highest accepted voucher.
    pub voucher_expires_at: Option<i64>,

    /// Primary recipient.
    pub recipient: Pubkey,

    /// Splits for the distribute instruction.
    pub splits: Vec<Split>,

    /// 32-byte distribution hash committed at channel open time.
    pub distribution_hash: [u8; 32],
}

impl SealParams {
    /// Build the on-chain settle+seal instructions for this channel, signed
    /// by `operator` (fee-payer + payee authority). Shared by the settlement
    /// worker and on-chain tests so the close path is constructed one way. A
    /// voucher signature is included only when value was actually settled.
    pub fn settle_instructions(
        &self,
        operator: &Pubkey,
    ) -> Result<Vec<solana_instruction::Instruction>> {
        crate::mpp::program::channel_deployment::resolve(
            self.program_id,
            self.channel_version,
            self.channel_hooks.as_ref(),
        )?;
        let authorized_signer = self
            .authorized_signer
            .ok_or_else(|| Error::Other("seal missing authorized_signer".to_string()))?;
        let (signature, expires_at): (Option<[u8; 64]>, i64) =
            match (&self.voucher_signature, self.settled) {
                (Some(b58), settled) if settled > 0 => {
                    let bytes: [u8; 64] = bs58::decode(b58)
                        .into_vec()
                        .map_err(|e| Error::Other(format!("invalid voucher signature: {e}")))?
                        .try_into()
                        .map_err(|_| {
                            Error::Other("voucher signature is not 64 bytes".to_string())
                        })?;
                    // The signed voucher message commits to its expiry, so a
                    // missing one can't be defaulted to 0 — that builds bytes the
                    // signature won't match, failing on-chain verification.
                    let expires_at = self.voucher_expires_at.ok_or_else(|| {
                        Error::Other("voucher signature present but expiry is missing".to_string())
                    })?;
                    (Some(bytes), expires_at)
                }
                _ => (None, 0),
            };
        payment_channels::build_settle_and_seal_instructions(
            operator,
            &self.channel_id,
            &authorized_signer,
            signature.as_ref(),
            self.settled,
            expires_at,
            &self.program_id,
        )
        .map_err(|e| Error::Other(format!("settle instructions: {e}")))
    }

    /// Build distribution with the original mandatory callbacks, including
    /// terminal distributions whose actual payer refund is zero. The rent
    /// payer is the one recorded at open, never inferred from a signer.
    pub fn distribute_instruction(
        &self,
        treasury: &Pubkey,
        token_program: &Pubkey,
    ) -> Result<solana_instruction::Instruction> {
        let deployment = crate::mpp::program::channel_deployment::resolve(
            self.program_id,
            self.channel_version,
            self.channel_hooks.as_ref(),
        )?;
        let payer = self
            .payer
            .ok_or_else(|| Error::Other("distribution missing payer".into()))?;
        let mint = self
            .mint
            .ok_or_else(|| Error::Other("distribution missing mint".into()))?;
        let rent_payer = &self
            .rent_payer
            .ok_or_else(|| Error::Other("distribution missing rent payer".into()))?;
        let recipients = self
            .splits
            .iter()
            .map(|split| payment_channels::Distribution {
                recipient: split.recipient,
                bps: split.bps,
            })
            .collect::<Vec<_>>();
        if deployment.version == 2 {
            Ok(
                crate::core::payment_channels_v2::build_distribute_instruction(
                    &self.channel_id,
                    &payer,
                    rent_payer,
                    &self.recipient,
                    treasury,
                    &mint,
                    &recipients,
                    token_program,
                    &self.program_id,
                    &self.channel_hooks.clone().unwrap_or_default(),
                )?,
            )
        } else {
            Ok(payment_channels::build_distribute_instruction(
                &self.channel_id,
                &payer,
                rent_payer,
                &self.recipient,
                treasury,
                &mint,
                &recipients,
                token_program,
                &self.program_id,
            ))
        }
    }
}

/// Request to reserve a metered delivery for client-side ack/commit.
#[derive(Debug, Clone)]
pub struct DeliveryRequest {
    /// Channel/session ID that will pay for the delivery.
    pub session_id: String,

    /// Amount owed for this delivery in base units.
    pub amount: u64,

    /// Optional idempotency key. If omitted, the server derives one from the
    /// session id and next delivery sequence.
    pub delivery_id: Option<String>,

    /// Optional commit endpoint hint surfaced to the client.
    pub commit_url: Option<String>,

    /// Optional opaque proof surfaced to the client.
    pub proof: Option<String>,

    /// Optional directive expiry. Defaults to the voucher default expiry.
    pub expires_at: Option<i64>,
}

impl DeliveryRequest {
    pub fn new(session_id: impl Into<String>, amount: u64) -> Self {
        Self {
            session_id: session_id.into(),
            amount,
            delivery_id: None,
            commit_url: None,
            proof: None,
            expires_at: None,
        }
    }
}

// ── Server ──

/// Server-side session manager.
///
/// Generic over the channel store to support in-memory testing and
/// production persistence backends.
pub struct SessionServer<S: ChannelStore> {
    config: SessionConfig,
    store: binding::BoundStore<S>,
    /// Transaction message versions accepted for `open` / `topUp` and
    /// advertised in the challenge; see `core::tx`.
    accepted_versions: Vec<TxVersion>,
    blockhash_cache: Option<crate::core::blockhash::BlockhashCache>,
    #[cfg(feature = "server")]
    tx_pipeline: tokio::sync::OnceCell<crate::core::tx_pipeline::TxPipeline>,
}

impl<S: ChannelStore> SessionServer<S> {
    pub fn new(config: SessionConfig, store: S) -> Self {
        // Version 0 only until the host opts in with `with_tx_v1`; no RPC call here.
        let accepted_versions = vec![TxVersion::V0];
        // V2 recovery must never reconstruct deployment policy from a new
        // process's defaults. Reuse the existing immutable policy snapshot.
        let deployment_binding = (config.channel_version.unwrap_or(1) != 1)
            .then(|| binding::Binding::new(serde_json::Value::Null, &config));
        Self {
            config,
            store: binding::BoundStore {
                inner: store,
                binding: deployment_binding,
            },
            accepted_versions,
            blockhash_cache: None,
            #[cfg(feature = "server")]
            tx_pipeline: tokio::sync::OnceCell::new(),
        }
    }

    /// Scope every channel operation to an immutable host policy identity and
    /// the current public configuration snapshot. Legacy channels are excluded.
    pub fn with_channel_binding(mut self, policy: serde_json::Value) -> Self {
        self.store.binding = Some(binding::Binding::new(policy, &self.config));
        self
    }

    /// Check scope and activation before a host uses raw channel-store state.
    /// Call this inside atomic host mutations, not only before starting them.
    pub fn require_channel_binding(&self, state: &ChannelState) -> Result<()> {
        binding::require_binding(state, &self.store.binding, false)
    }

    fn resolve_versions(config: &SessionConfig, mode: TxV1Mode) -> Vec<TxVersion> {
        match (&config.rpc_url, mode) {
            // No RPC means no funding verification and no gate to probe.
            (None, TxV1Mode::Auto) => vec![TxVersion::V0],
            (Some(url), mode) => {
                mode.resolve(&solana_rpc_client::rpc_client::RpcClient::new(url.clone()))
            }
            (None, mode) => {
                mode.resolve(&solana_rpc_client::rpc_client::RpcClient::new(String::new()))
            }
        }
    }

    /// Choose whether version-1 `open` / `topUp` transactions are accepted and
    /// advertised. `Auto` probes the `enable_tx_v1` gate once; the default is
    /// version 0 only.
    pub fn with_tx_v1(mut self, mode: TxV1Mode) -> Self {
        self.accepted_versions = Self::resolve_versions(&self.config, mode);
        self
    }

    /// Share the host's recent-blockhash cache with challenge issuance, so
    /// the challenge's `recentBlockhash`/`recentSlot` come from one cached
    /// `getLatestBlockhash` instead of a blocking RPC round-trip per 402.
    pub fn with_blockhash_cache(mut self, cache: crate::core::blockhash::BlockhashCache) -> Self {
        self.blockhash_cache = Some(cache);
        self
    }

    /// Use a host-owned transaction pipeline for session open and top-up.
    /// Sharing this across gate instances preserves one RPC connection pool
    /// and one confirmation/read-back batcher process-wide.
    #[cfg(feature = "server")]
    pub fn with_tx_pipeline(self, pipeline: crate::core::tx_pipeline::TxPipeline) -> Self {
        let _ = self.tx_pipeline.set(pipeline);
        self
    }

    /// Return the lazily initialized pipeline used by this session server.
    /// Hosts can reuse the clone for settlement and reconciliation so every
    /// lifecycle phase shares the same RPC pool and confirmation tracker.
    #[cfg(feature = "server")]
    pub async fn transaction_pipeline(&self) -> Result<crate::core::tx_pipeline::TxPipeline> {
        let rpc_url = self.config.rpc_url.as_ref().ok_or_else(|| {
            Error::Other(
                "session transaction verification requires an RPC client; funding verification cannot be skipped"
                    .to_string(),
            )
        })?;
        Ok(self
            .tx_pipeline
            .get_or_init(|| async {
                crate::core::tx_pipeline::TxPipeline::new(
                    rpc_url.clone(),
                    crate::core::tx_pipeline::TxPipelineConfig::default(),
                )
            })
            .await
            .clone())
    }

    /// Build the exact `SessionRequest` embedded in a new-channel 402
    /// challenge.
    ///
    /// Fails loudly (retryable) rather than issuing a challenge without
    /// `recentBlockhash`/`recentSlot`: both are REQUIRED for a new-channel
    /// challenge — the client derives the channel PDA from `recentSlot` and
    /// MUST use the challenged blockhash — so a silent omission would surface
    /// as a non-retryable payment failure at open time.
    pub fn build_challenge_request(&self) -> Result<SessionRequest> {
        self.config.channel_deployment()?;
        self.config.check_sponsored_deposit_floor()?;
        if self.config.decimals > 9 {
            return Err(Error::InvalidConfig(
                "session token decimals must be between 0 and 9".to_string(),
            ));
        }
        let currency = expected_payment_channel_mint(&self.config)?.to_string();
        let hint = self.challenge_open_transaction_context()?;
        let channel_program = self
            .config
            .channel_program
            .unwrap_or_else(payment_channels::default_program_id);
        let fee_payer_key = self
            .config
            .fee_payer_signer
            .as_ref()
            .map(|signer| signer.pubkey().to_string());
        Ok(SessionRequest {
            amount: self.config.amount.to_string(),
            currency,
            recipient: self.config.recipient.clone(),
            description: None,
            external_id: None,
            minimum_deposit: self.config.minimum_deposit.map(|value| value.to_string()),
            suggested_deposit: self.config.suggested_deposit.map(|value| value.to_string()),
            unit_type: None,
            method_details: SessionMethodDetails {
                network: self.config.network.clone(),
                channel_program: payment_channels::pubkey_string(&channel_program),
                channel_version: self.config.channel_version,
                channel_hooks: self.config.channel_hooks.clone(),
                channel_id: None,
                recent_blockhash: Some(hint.blockhash),
                recent_slot: Some(hint.slot),
                decimals: Some(self.config.decimals),
                token_program: self
                    .config
                    .token_program
                    .map(|key| payment_channels::pubkey_string(&key)),
                fee_payer: fee_payer_key.as_ref().map(|_| true),
                fee_payer_key,
                voucher_signer: Some(self.config.voucher_signer),
                operator: (self.config.voucher_signer == VoucherSigner::Operator)
                    .then(|| self.config.operator.clone()),
                min_voucher_delta: (self.config.min_voucher_delta > 0)
                    .then(|| self.config.min_voucher_delta.to_string()),
                ttl_seconds: None,
                idle_timeout_options_seconds: self.config.idle_timeout_options_seconds.clone(),
                idle_timeout_seconds: None,
                grace_period_seconds: Some(self.config.grace_period_seconds),
                distribution_splits: self
                    .config
                    .splits
                    .iter()
                    .map(|split| SessionSplit {
                        recipient: payment_channels::pubkey_string(&split.recipient),
                        share_bps: split.bps,
                    })
                    .collect(),
                transaction_versions: crate::core::tx::advertised(&self.accepted_versions),
            },
        })
    }

    /// Fetch the open-transaction context (`recentBlockhash` + `recentSlot`)
    /// for a new-channel challenge.
    ///
    /// Prefers the shared cache (refreshed out of band) to avoid a blocking
    /// RPC round-trip per challenge; falls back to one direct
    /// `getLatestBlockhash` call, whose response carries both the blockhash
    /// and the context slot.
    fn challenge_open_transaction_context(
        &self,
    ) -> Result<crate::core::blockhash::CachedBlockhash> {
        if let Some(cached) = self.blockhash_cache.as_ref().and_then(|cache| cache.get()) {
            return Ok(cached);
        }
        #[cfg(feature = "server")]
        if let Some(ref rpc_url) = self.config.rpc_url {
            let rpc = confirmed_rpc_client(rpc_url);
            return crate::core::blockhash::fetch_blockhash_with_slot(&rpc, rpc.commitment())
                .map_err(|e| {
                    Error::Rpc(format!(
                        "failed to fetch recentBlockhash/recentSlot for session challenge: {e}"
                    ))
                });
        }
        Err(Error::Other(
            "session challenge requires recentBlockhash/recentSlot; configure a blockhash cache \
             or an rpc_url"
                .to_string(),
        ))
    }

    /// Build and validate payment-channel open parameters from an `open` payload.
    ///
    /// This verifies the client-provided payer/payee/mint/salt/deposit/channel
    /// fields against the session challenge and returns the exact on-chain open
    /// params expected by the payment-channels program.
    pub fn payment_channel_open_params(
        &self,
        payload: &OpenPayload,
    ) -> Result<payment_channels::OpenChannelParams> {
        self.config.channel_deployment()?;
        self.config.check_sponsored_deposit_floor()?;
        let payer = parse_pubkey_field(&payload.payer, "payer")?;
        let payee = parse_pubkey_field(&payload.payee, "payee")?;
        let mint = parse_pubkey_field(&payload.mint, "mint")?;
        let authorized_signer = parse_pubkey_field(&payload.authorized_signer, "authorizedSigner")?;
        if !authorized_signer.is_on_curve() {
            return Err(Error::Other(
                "payment-channel authorizedSigner must be an on-curve Ed25519 public key"
                    .to_string(),
            ));
        }
        let salt = payload.salt;
        let grace_period = payload.grace_period_seconds;
        let open_slot = payload.open_slot;
        let deposit = payload.deposit_amount()?;
        let token_program = match self.config.token_program {
            Some(program) => program,
            None => parse_pubkey_field(
                default_token_program_for_currency(
                    &self.config.currency,
                    Some(self.config.network.as_str()),
                ),
                "token program",
            )?,
        };
        let program_id = self
            .config
            .channel_program
            .unwrap_or_else(payment_channels::default_program_id);
        let expected_payee = parse_pubkey_field(&self.config.recipient, "recipient")?;
        let expected_mint = expected_payment_channel_mint(&self.config)?;
        if self.config.voucher_signer == VoucherSigner::Operator {
            let operator = parse_required_operator(&self.config.operator)?;
            if authorized_signer != operator {
                return Err(Error::Other(
                    "operator voucher signing requires authorizedSigner to match the operator"
                        .to_string(),
                ));
            }
        }

        if payee != expected_payee {
            return Err(Error::Other(
                "payment-channel open payee does not match challenge recipient".to_string(),
            ));
        }
        if mint != expected_mint {
            return Err(Error::Other(
                "payment-channel open mint does not match challenge currency".to_string(),
            ));
        }
        if grace_period != self.config.grace_period_seconds {
            return Err(Error::Other(
                "payment-channel open gracePeriodSeconds does not match challenge".to_string(),
            ));
        }
        if self
            .config
            .minimum_deposit
            .is_some_and(|minimum| deposit < minimum)
        {
            return Err(Error::Other(
                "payment-channel open depositAmount is below minimumDeposit".to_string(),
            ));
        }

        let payload_splits: Vec<Split> = payload
            .distribution_splits
            .iter()
            .map(|split| {
                Ok(Split {
                    recipient: parse_pubkey_field(&split.recipient, "distribution recipient")?,
                    bps: split.share_bps,
                })
            })
            .collect::<Result<_>>()?;
        if payload_splits != self.config.splits {
            return Err(Error::Other(
                "payment-channel open distributionSplits do not match challenge".to_string(),
            ));
        }

        let recipients = self
            .config
            .splits
            .iter()
            .map(|split| payment_channels::Distribution {
                recipient: split.recipient,
                bps: split.bps,
            })
            .collect();
        let rent_payer = self
            .config
            .fee_payer_signer
            .as_ref()
            .map(|signer| signer.pubkey())
            .unwrap_or(payer);
        reject_sponsor_as_payer(&self.config, &payer)?;
        let params = payment_channels::OpenChannelParams {
            payer,
            rent_payer,
            payee,
            mint,
            authorized_signer,
            salt,
            open_slot,
            deposit,
            grace_period,
            recipients,
            token_program,
            program_id,
        };

        let expected_channel = payment_channels::derive_channel_addresses(&params).channel;
        let channel = parse_pubkey_field(&payload.channel_id, "channelId")?;
        if channel != expected_channel {
            return Err(Error::Other(
                "payment-channel open channelId does not match derived channel PDA".to_string(),
            ));
        }

        Ok(params)
    }

    /// Build the exact payment-channel open instruction expected for a payload.
    pub fn payment_channel_open_instruction(
        &self,
        payload: &OpenPayload,
    ) -> Result<solana_instruction::Instruction> {
        // The transaction verifier binds every open-instruction account to
        // these payload and challenge values before the channel is persisted.
        let params = self.payment_channel_open_params(payload)?;
        if self.config.channel_deployment()?.version == 2 {
            Ok(crate::core::payment_channels_v2::build_open_instruction(
                &params,
                &self.config.channel_hooks.clone().unwrap_or_default(),
            )?)
        } else {
            Ok(payment_channels::build_open_instruction(&params))
        }
    }

    /// Process an `open` action: persist the channel state.
    ///
    /// Accepts payment-channel opens and operated-voucher delegated-token opens.
    /// Returns the stored `ChannelState`.
    ///
    /// Requires `config.rpc_url`. Validates before persisting a pending intent,
    /// then confirms the transaction and matching on-chain state before
    /// activation. A failed or interrupted submission leaves a recoverable
    /// pending record, never an authorized channel.
    ///
    /// Replayed opens are idempotent: when a channel already exists for the
    /// session id with the same authorized signer, the existing state is
    /// returned unchanged — the voucher watermark is never reset. Opens for an
    /// existing channel are rejected when the channel is sealed or when the
    /// payload's authorized signer differs from the stored one.
    pub async fn process_open(
        &self,
        payload: &OpenPayload,
        context: SessionOpenContext<'_>,
    ) -> Result<ChannelState> {
        Ok(self
            .process_open_with_outcome(payload, context)
            .await?
            .state)
    }

    /// Process an `open` action and report whether it created channel state.
    pub async fn process_open_with_outcome(
        &self,
        payload: &OpenPayload,
        context: SessionOpenContext<'_>,
    ) -> Result<OpenAcceptance> {
        self.process_open_inner(payload, context).await
    }

    /// Resume a validated, durably stored intent without a new client request.
    ///
    /// This trusted lifecycle operation ignores original challenge expiry but
    /// reverifies the transaction and exact chain parameters. It cannot adopt
    /// an on-chain channel without its existing pending intent.
    pub async fn resume_pending_open(&self, channel_id: &str) -> Result<OpenAcceptance> {
        let state = self
            .store
            .inner
            .get_channel(channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Other("pending open not found".into()))?;
        binding::require_binding(&state, &self.store.binding, true)?;
        if !state
            .pending_setup
            .as_ref()
            .is_some_and(|setup| setup.opens_channel)
        {
            return Err(Error::Other("channel has no pending open".into()));
        }
        let intent: OpenIntent = serde_json::from_value(
            state
                .extra
                .get(OPEN_INTENT_KEY)
                .ok_or_else(|| Error::Other("pending open intent missing".into()))?
                .clone(),
        )
        .map_err(|_| Error::Other("invalid pending open intent".into()))?;
        if !matches!(intent.version, 1 | 2) || intent.payload.session_id() != channel_id {
            return Err(Error::Other("pending open intent identity mismatch".into()));
        }
        #[cfg(feature = "server")]
        if intent.version == 2 {
            if let Some(valid_at) = intent.finalized_valid_at {
                let pipeline = self.transaction_pipeline().await?;
                let (valid, invalid_at) = pipeline
                    .finalized_blockhash_validity(&intent.recent_blockhash, Some(valid_at))
                    .await
                    .map_err(|error| Error::Rpc(format!("open expiry reconciliation: {error}")))?;
                if !valid && invalid_at > valid_at {
                    let params = self.payment_channel_open_params(&intent.payload)?;
                    let prepared = prepare_open_transaction(
                        &intent.payload,
                        &params,
                        &intent.recent_blockhash,
                        self.config.fee_payer_signer.as_deref(),
                        &self.accepted_versions,
                        &self.config,
                    )
                    .await?;
                    let signature = prepared
                        .0
                        .signatures
                        .first()
                        .copied()
                        .ok_or_else(|| Error::Other("open signature missing".into()))?;
                    if intent.transaction_signature.as_deref()
                        != Some(signature.to_string().as_str())
                    {
                        return Err(Error::Other(
                            "open reconciliation signature mismatch".into(),
                        ));
                    }
                    let address = payment_channels::derive_channel_addresses(&params).channel;
                    if pipeline
                        .finalized_unfunded(address, signature, invalid_at)
                        .await
                        .map_err(|error| {
                            Error::Rpc(format!("open funding reconciliation: {error}"))
                        })?
                    {
                        let expected = state.clone();
                        self.store
                            .inner
                            .update_channel(
                                channel_id,
                                Box::new(move |current| {
                                    let mut current = current.ok_or_else(|| {
                                        StoreError::Internal("open intent disappeared".into())
                                    })?;
                                    // Fence the entire state, not merely its channel ID: a
                                    // concurrent activation or mutation invalidates this proof.
                                    let encode = |state: &ChannelState| {
                                        serde_json::to_value(state).map_err(|error| {
                                            StoreError::Internal(error.to_string())
                                        })
                                    };
                                    if encode(&current)? != encode(&expected)? {
                                        return Err(StoreError::Internal(
                                            "open changed before retirement".into(),
                                        ));
                                    }
                                    current.extra.insert(
                                        OPEN_TERMINAL_KEY.into(),
                                        serde_json::json!({
                                            "version": 1, "finalizedInvalidAt": invalid_at,
                                        }),
                                    );
                                    current.pending_setup = None;
                                    current.lifecycle = None;
                                    Ok(current)
                                }),
                            )
                            .await
                            .map_err(store_err)?;
                        return Err(Error::Other(OPEN_TERMINAL_ERROR.into()));
                    }
                }
            }
        }
        self.process_open_inner(
            &intent.payload,
            SessionOpenContext {
                challenge_id: &intent.challenge_id,
                expires: None,
                recent_blockhash: &intent.recent_blockhash,
                recent_slot: intent.recent_slot,
            },
        )
        .await
    }

    /// The credential half of `process_open`'s checks, before it reads the
    /// store: the challenge expiry, the deposit and idle-timeout selection,
    /// the open parameters against the challenge
    /// ([`Self::payment_channel_open_params`]), the `openSlot` window against
    /// the challenged `recentSlot`, and the voucher-signer mode and bearer
    /// proof. [`Self::prepare_open`] is the transaction half; the conformance
    /// hook ([`testkit::verify_open_pre_broadcast`]) runs both.
    fn validate_open_request(
        &self,
        payload: &OpenPayload,
        context: SessionOpenContext<'_>,
    ) -> Result<ValidatedOpen> {
        context.ensure_not_expired()?;
        let session_id = payload.session_id();
        let deposit = payload.deposit_amount()?;
        let effective_idle_timeout = resolve_idle_timeout_seconds(
            self.config.idle_timeout_seconds,
            self.config.idle_timeout_options_seconds.as_deref(),
            payload.idle_timeout_seconds,
        )?;
        if let Some(options) = self.config.idle_timeout_options_seconds.as_deref() {
            validate_idle_timeout_options(options)?;
        }

        if deposit == 0 {
            return Err(Error::Other(
                "Deposit must be greater than zero".to_string(),
            ));
        }

        let params = self.payment_channel_open_params(payload)?;

        // Bind the open to the specific challenge that authorized it: the
        // client takes `openSlot` from the challenged `recentSlot` (an earlier
        // slot is allowed, a later one never is), so a payload outside this
        // window was not built against this challenge.
        if payload.open_slot > context.recent_slot {
            return Err(Error::Other(format!(
                "open openSlot {} is ahead of the challenged recentSlot {}",
                payload.open_slot, context.recent_slot
            )));
        }
        if context.recent_slot - payload.open_slot > payment_channels::OPEN_SLOT_WINDOW {
            return Err(Error::Other(format!(
                "open openSlot {} is outside the {}-slot freshness window of the challenged \
                 recentSlot {}",
                payload.open_slot,
                payment_channels::OPEN_SLOT_WINDOW,
                context.recent_slot
            )));
        }

        if self.config.voucher_signer == VoucherSigner::Operator {
            let operator = parse_required_operator(&self.config.operator)?;
            let authorized_signer =
                parse_pubkey_field(&payload.authorized_signer, "authorizedSigner")?;
            if authorized_signer != operator {
                return Err(Error::Other(
                    "operator voucher signing requires authorizedSigner to match the operator"
                        .to_string(),
                ));
            }
            let authentication = payload.authentication.as_ref().ok_or_else(|| {
                Error::Other("operator voucher signing requires authentication".to_string())
            })?;
            if authentication.challenge_id != context.challenge_id {
                return Err(Error::Other(
                    "session authentication challengeId does not match the opening challenge"
                        .to_string(),
                ));
            }
            if authentication.payer != payload.payer {
                return Err(Error::Other(
                    "session authentication payer does not match the channel payer".to_string(),
                ));
            }
            if !authentication.verify(session_id)? {
                return Err(Error::Other(
                    "invalid session authentication signature".to_string(),
                ));
            }
        } else if payload.authentication.is_some() {
            return Err(Error::Other(
                "authentication is only valid when voucherSigner is operator".to_string(),
            ));
        }

        Ok(ValidatedOpen {
            deposit,
            effective_idle_timeout,
            params,
        })
    }

    /// The transaction half of `process_open`'s checks
    /// (`prepare_open_transaction`): accepted version and budget, the
    /// challenged blockhash, the fee payer, exactly the declared open
    /// instruction with matching privileges, and the client's signatures.
    /// Co-signs a sponsored open; never broadcasts.
    async fn prepare_open(
        &self,
        payload: &OpenPayload,
        params: &payment_channels::OpenChannelParams,
        context: SessionOpenContext<'_>,
    ) -> Result<(solana_transaction::versioned::VersionedTransaction, String)> {
        prepare_open_transaction(
            payload,
            params,
            context.recent_blockhash,
            self.config.fee_payer_signer.as_deref(),
            &self.accepted_versions,
            &self.config,
        )
        .await
    }

    async fn process_open_inner(
        &self,
        payload: &OpenPayload,
        context: SessionOpenContext<'_>,
    ) -> Result<OpenAcceptance> {
        let ValidatedOpen {
            deposit,
            effective_idle_timeout,
            params,
        } = self.validate_open_request(payload, context)?;
        let session_id = payload.session_id();

        let existing = self
            .store
            .inner
            .get_channel(session_id)
            .await
            .map_err(store_err)?;
        if let Some(existing) = &existing {
            binding::require_binding(existing, &self.store.binding, true)?;
        }
        let fresh_open = existing.is_none();
        // Activating a reservation (fresh or still pending) adopts a channel
        // into this ledger and needs proof this ledger opened it.
        let activating = existing.as_ref().is_none_or(|state| {
            state
                .pending_setup
                .as_ref()
                .is_some_and(|setup| setup.opens_channel)
        });
        #[cfg(feature = "server")]
        let pipeline = self.transaction_pipeline().await?;
        #[cfg(not(feature = "server"))]
        let pipeline = ();
        let prepared = self.prepare_open(payload, &params, context).await?;
        // A fresh open's own broadcast lands after this observed slot; one that
        // landed at or before it was opened elsewhere and has no ledger here.
        #[cfg(feature = "server")]
        let observed_floor = if fresh_open {
            Some(validate_open_slot(&pipeline, params.open_slot).await?)
        } else {
            None
        };
        #[cfg(not(feature = "server"))]
        let observed_floor: Option<u64> = None;

        let authentication = payload
            .authentication
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| Error::Other(format!("serialize authentication: {error}")))?;
        let now_ms = now_unix_secs().saturating_mul(1_000) as u64;

        let mut fresh_state = ChannelState {
            channel_id: session_id.to_string(),
            authorized_signer: payload.authorized_signer.clone(),
            deposit: 0,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            final_cumulative: None,
            // Persisted so the channel PDA can be re-derived and the reclaim
            // gate evaluated later.
            open_slot: Some(payload.open_slot),
            payer: payload.payer.clone(),
            rent_payer: params.rent_payer.to_string(),
            opening_challenge_id: context.challenge_id.to_string(),
            authentication,
            voucher_signer: match self.config.voucher_signer {
                VoucherSigner::Client => "client",
                VoucherSigner::Operator => "operator",
            }
            .to_string(),
            idle_timeout_seconds: Some(effective_idle_timeout),
            last_activity_at: now_ms,
            spent_amount: 0,
            settled_on_chain: 0,
            distributed_on_chain: 0,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: Default::default(),
            pending_setup: None,
            onchain_checked_at: 0,
            lifecycle: Some(ChannelLifecycle {
                owner: self.config.operator.clone(),
                close_after: now_ms.saturating_add(u64::from(effective_idle_timeout) * 1_000),
            }),
            schema_version: CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        };
        fresh_state.pending_setup = Some(crate::mpp::store::PendingSetup {
            payer_signature: prepared.1.clone(),
            deposit,
            opens_channel: true,
            // Reconcile instead of evicting on challenge expiry: funding may
            // have landed immediately before the process lost its response.
            expires_at: i64::MAX,
        });
        let stored_intent = existing
            .as_ref()
            .and_then(|state| state.extra.get(OPEN_INTENT_KEY))
            .map(|value| serde_json::from_value::<OpenIntent>(value.clone()))
            .transpose()
            .map_err(|_| Error::Other("invalid pending open intent".into()))?;
        let finalized_valid_at = stored_intent
            .as_ref()
            .and_then(|intent| intent.finalized_valid_at);
        let adoption_floor = match &stored_intent {
            Some(intent) if !fresh_open => intent.adoption_floor,
            _ => observed_floor.map_or(AdoptionFloor::Unproven, AdoptionFloor::Slot),
        };
        let activation_floor = if activating {
            Some(adoption_floor.slot()?)
        } else {
            None
        };
        #[cfg(feature = "server")]
        let finalized_valid_at = if fresh_open {
            // Confirmed challenge hashes can be newer than the finalized bank.
            // Lack of a positive observation is not a submission failure, but it
            // permanently excludes this attempt from expiry-based retirement.
            match pipeline
                .finalized_blockhash_validity(context.recent_blockhash, None)
                .await
            {
                Ok((true, slot)) => Some(slot),
                _ => None,
            }
        } else {
            finalized_valid_at
        };
        let intent = serde_json::to_value(OpenIntent {
            version: stored_intent.as_ref().map_or(2, |intent| intent.version),
            payload: payload.clone(),
            challenge_id: context.challenge_id.to_string(),
            recent_blockhash: context.recent_blockhash.to_string(),
            recent_slot: context.recent_slot,
            finalized_valid_at,
            transaction_signature: if stored_intent
                .as_ref()
                .is_some_and(|intent| intent.version == 1)
            {
                None
            } else {
                prepared.0.signatures.first().map(ToString::to_string)
            },
            adoption_floor,
        })
        .map_err(|error| Error::Other(format!("serialize open intent: {error}")))?;
        fresh_state
            .extra
            .insert(OPEN_INTENT_KEY.into(), intent.clone());
        if let Some(binding) = &self.store.binding {
            binding.insert(&mut fresh_state)?;
        }

        // Reserve only after validating the payer's actual signed transaction.
        // Replays cannot replace the intent/binding or reset accounting. The
        // durable write must complete before any funding broadcast.
        let session_id_owned = session_id.to_string();
        let authorized_signer = payload.authorized_signer.clone();
        let payer = payload.payer.clone();
        let rent_payer = params.rent_payer.to_string();
        let opening_challenge_id = context.challenge_id.to_string();
        let authentication = payload.authentication.clone();
        let replay = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let replay_out = std::sync::Arc::clone(&replay);
        let expected_binding = self.store.binding.clone();
        let expected_intent = intent.clone();
        self
            .store.inner
            .update_channel(
                session_id,
                Box::new(move |state_opt| match state_opt {
                    Some(existing) => {
                        binding::require_binding(&existing, &expected_binding, true)
                            .map_err(|error| StoreError::Internal(error.to_string()))?;
                        if existing.extra.get(OPEN_INTENT_KEY).is_some_and(|stored| !same_open_intent(stored, &expected_intent)) {
                            return Err(StoreError::Internal("open intent does not match stored state".into()));
                        }
                        if existing.sealed {
                            return Err(StoreError::Internal(format!(
                                "Channel {session_id_owned} is already sealed"
                            )));
                        }
                        if existing.authorized_signer != authorized_signer {
                            return Err(StoreError::Internal(format!(
                                "Channel {session_id_owned} already exists with a different authorized signer"
                            )));
                        }
                        if existing.payer != payer
                            || existing.rent_payer != rent_payer
                            || existing.opening_challenge_id != opening_challenge_id
                            || existing.authentication
                                != authentication
                                    .as_ref()
                                    .map(serde_json::to_string)
                                    .transpose()
                                    .map_err(|error| StoreError::Internal(error.to_string()))?
                        {
                            return Err(StoreError::Internal(format!(
                                "Channel {session_id_owned} open replay does not match stored state"
                            )));
                        }
                        // Idempotent replay: keep existing state untouched.
                        replay_out.store(existing.pending_setup.is_none(), std::sync::atomic::Ordering::Relaxed);
                        Ok(existing)
                    }
                    None => Ok(fresh_state),
                }),
            )
            .await
            .map_err(store_err)?;

        let opened = submit_and_fetch_open(
            prepared.0,
            &params,
            &pipeline,
            fresh_open,
            activation_floor,
            &self.config,
        )
        .await;
        let (transaction_signature, onchain_settled) =
            match opened? {
                OpenSubmission::Landed { signature, settled } => (signature, settled),
                OpenSubmission::OpenedElsewhere => {
                    // Retire the reservation so no retry can activate it.
                    let expected_intent = intent.clone();
                    self.store
                        .inner
                        .update_channel(
                            session_id,
                            Box::new(move |state| {
                                let mut state = state.ok_or_else(|| {
                                    StoreError::Internal("open intent disappeared".into())
                                })?;
                                if !state.extra.get(OPEN_INTENT_KEY).is_some_and(|stored| {
                                    same_open_intent(stored, &expected_intent)
                                }) {
                                    return Err(StoreError::Internal(
                                        "open intent changed before retirement".into(),
                                    ));
                                }
                                state.extra.insert(
                                    OPEN_TERMINAL_KEY.into(),
                                    serde_json::json!({ "version": 1, "openedElsewhere": true }),
                                );
                                state.pending_setup = None;
                                state.lifecycle = None;
                                Ok(state)
                            }),
                        )
                        .await
                        .map_err(store_err)?;
                    return Err(Error::Other(OPENED_ELSEWHERE_ERROR.into()));
                }
            };
        let expected_binding = self.store.binding.clone();
        let state = self
            .store
            .inner
            .update_channel(
                session_id,
                Box::new(move |state| {
                    let mut state = state
                        .ok_or_else(|| StoreError::Internal("open intent disappeared".into()))?;
                    binding::require_binding(&state, &expected_binding, true)
                        .map_err(|error| StoreError::Internal(error.to_string()))?;
                    if state
                        .extra
                        .get(OPEN_INTENT_KEY)
                        .is_some_and(|stored| !same_open_intent(stored, &intent))
                    {
                        return Err(StoreError::Internal(
                            "open intent changed before activation".into(),
                        ));
                    }
                    if state
                        .pending_setup
                        .as_ref()
                        .is_some_and(|setup| setup.opens_channel)
                    {
                        state.deposit = deposit;
                        state.pending_setup = None;
                    }
                    // An open adopted from chain may already carry settled
                    // vouchers; never accept one at or below that watermark.
                    state.cumulative = state.cumulative.max(onchain_settled);
                    state.spent_amount = state.spent_amount.max(onchain_settled);
                    state.settled_on_chain = state.settled_on_chain.max(onchain_settled);
                    // The confirmed read above found the channel open.
                    state.record_onchain_observation(
                        OnchainObservation {
                            slot: None,
                            lifecycle: ObservedLifecycle::Open,
                        },
                        now_unix_secs().max(0) as u64,
                    );
                    Ok(state)
                }),
            )
            .await
            .map_err(store_err)?;
        let replay = replay.load(std::sync::atomic::Ordering::Relaxed);
        Ok(OpenAcceptance {
            state,
            replay,
            transaction_signature,
        })
    }

    /// Build the required receipt for a successful session action.
    pub fn receipt(
        &self,
        state: &ChannelState,
        challenge_id: impl Into<String>,
    ) -> Result<ReceiptKind> {
        self.receipt_with_close_fields(state, challenge_id, None, None)
    }

    /// Build a successful close receipt with optional settlement details.
    pub fn close_receipt(
        &self,
        state: &ChannelState,
        challenge_id: impl Into<String>,
        tx_hash: Option<String>,
        refunded: Option<u64>,
    ) -> Result<ReceiptKind> {
        self.receipt_with_close_fields(state, challenge_id, tx_hash, refunded)
    }

    fn receipt_with_close_fields(
        &self,
        state: &ChannelState,
        challenge_id: impl Into<String>,
        tx_hash: Option<String>,
        refunded: Option<u64>,
    ) -> Result<ReceiptKind> {
        let idle_timeout_seconds = state.idle_timeout_seconds.ok_or_else(|| {
            Error::Other(format!(
                "channel {} is missing its negotiated idle timeout",
                state.channel_id
            ))
        })?;
        Ok(ReceiptKind::Session {
            base: Receipt::success("solana", state.channel_id.clone(), challenge_id),
            extensions: SessionReceiptExtensions {
                intent: SessionReceiptIntent::Session,
                accepted_cumulative: state.cumulative,
                spent: state.spent_amount,
                idle_timeout_seconds,
                tx_hash,
                refunded,
            },
        })
    }

    /// Verify a voucher, advance the watermark, and return the acceptance
    /// outcome (post-acceptance cumulative, the amount newly charged, and
    /// whether this was an idempotent replay).
    ///
    /// Rejects vouchers that:
    /// - Belong to an unknown channel
    /// - Have a non-increasing cumulative (unless exact idempotent replay)
    /// - Exceed the deposit cap
    /// - Have an invalid signature
    /// - Are below the minimum voucher delta
    /// - Are submitted after a close has been requested
    ///
    /// An exact idempotent replay of the latest voucher is accepted as a
    /// no-charge no-op: the returned [`VoucherAcceptance`] has `charged == 0`
    /// and `replay == true` so callers do not treat it as a fresh paid serve.
    ///
    /// Uses atomic read-modify-write to prevent double-spend under concurrent requests.
    pub async fn verify_voucher(&self, payload: &VoucherPayload) -> Result<VoucherAcceptance> {
        self.verify_voucher_priced(payload, self.config.amount, true, |_| Ok(()))
            .await
    }

    /// Verify a voucher authorizing one request, checking a host
    /// lease/capacity precondition inside the atomic watermark-and-service-debit
    /// mutation.
    ///
    /// The guard sees the current record on every committing mutation. It must
    /// be nonblocking and free of side effects; retries must recheck the lease.
    ///
    /// A successful return always charged the request: an exact replay of the
    /// highest voucher is rejected rather than returned as a no-charge
    /// acceptance, so a caller that forwards the request on `Ok` (for example
    /// across replicas sharing the store) can never serve it twice for one
    /// payment.
    pub async fn verify_voucher_with_guard(
        &self,
        payload: &VoucherPayload,
        guard: impl Fn(&ChannelState) -> Result<()> + Send + Sync + 'static,
    ) -> Result<VoucherAcceptance> {
        self.verify_voucher_priced(payload, self.config.amount, false, guard)
            .await
    }

    /// Verify a voucher paying for one request priced at `amount` base units.
    ///
    /// `amount` is the price the client was challenged with — the
    /// authenticated `SessionRequest.amount` echoed by the credential — and
    /// replaces [`SessionConfig::amount`] for both the availability check and
    /// the debit, in the same atomic transition. Hosts that override the
    /// challenge price per route must use this instead of
    /// [`verify_voucher`](Self::verify_voucher). A zero amount is rejected.
    ///
    /// Each accepted voucher authorizes exactly one request: an exact replay
    /// of the highest voucher is rejected rather than accepted as a no-charge
    /// no-op, and no state changes.
    pub async fn verify_voucher_for_amount(
        &self,
        payload: &VoucherPayload,
        amount: u64,
    ) -> Result<VoucherAcceptance> {
        if amount == 0 {
            return Err(Error::Other(
                "session voucher request amount must be positive".to_string(),
            ));
        }
        self.verify_voucher_priced(payload, amount, false, |_| Ok(()))
            .await
    }

    async fn verify_voucher_priced(
        &self,
        payload: &VoucherPayload,
        amount: u64,
        allow_replay: bool,
        guard: impl Fn(&ChannelState) -> Result<()> + Send + Sync + 'static,
    ) -> Result<VoucherAcceptance> {
        let voucher = &payload.voucher;
        // draft-solana-session-00: "In operator mode, vouchers are
        // operator-generated settlement artifacts and MUST NOT authenticate
        // the caller." Operator-signed vouchers are public settlement data, so
        // presenting one proves nothing; the caller authenticates with `use`.
        if self.config.voucher_signer == VoucherSigner::Operator {
            return Err(Error::Other(OPERATOR_VOUCHER_ERROR.to_string()));
        }
        // The top-level channelId is the routing key; it must never diverge
        // from the signed voucher's inner channelId (spec: servers MUST
        // reject the action when the two differ).
        if payload.channel_id != voucher.data.channel_id {
            return Err(Error::Other(
                "voucher action channelId does not match the signed voucher's channelId"
                    .to_string(),
            ));
        }
        let state = self
            .store
            .get_channel(&voucher.data.channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| {
                Error::Other(format!("Channel {} not found", voucher.data.channel_id))
            })?;
        if state.voucher_signer == "operator" {
            return Err(Error::Other(OPERATOR_VOUCHER_ERROR.to_string()));
        }
        if voucher.signer != state.authorized_signer {
            return Err(Error::Other(
                "voucher signer does not match the channel authorized signer".to_string(),
            ));
        }
        let new_cumulative: u64 = voucher
            .data
            .cumulative_amount
            .parse()
            .map_err(|_| Error::Other("Invalid cumulative in voucher".to_string()))?;
        self.refresh_channel_snapshot(&voucher.data.channel_id)
            .await?;
        let max_age = self.snapshot_max_age();

        // Wire-agnostic acceptance (signature + monotonicity + deposit cap +
        // min-delta + idempotent replay + atomic advance) lives in core so the
        // x402 `batch-settlement` scheme shares it. The settlement window is the
        // channel's forced-close grace period: a non-zero voucher expiry must
        // outlast it so the operator can still redeem on-chain after the async
        // forced-close delay.
        let owner = self.config.operator.clone();
        let acceptance = crate::core::session::accept_voucher_with_commit(
            &self.store,
            &voucher.data.channel_id,
            new_cumulative,
            voucher.data.expires_at.unwrap_or(0),
            &voucher.signature,
            now_unix_secs(),
            self.config.min_voucher_delta,
            self.config.grace_period_seconds as i64,
            // Reject a voucher whose newly authorized credit
            // (`acceptedCumulative - spentAmount`) can't cover this action's
            // price, before the watermark advances — matches the
            // TypeScript/Python session servers' availability gate.
            amount,
            move |state, replay| {
                require_fresh_snapshot(state, max_age)?;
                if replay && !allow_replay {
                    return Err(StoreError::Internal(
                        "voucher was already accepted; sign a new voucher for this request".into(),
                    ));
                }
                guard(state).map_err(|error| StoreError::Internal(error.to_string()))?;
                let debit = if replay { 0 } else { amount };
                state.spent_amount = state
                    .spent_amount
                    .checked_add(debit)
                    .ok_or_else(|| StoreError::Internal("session spent amount overflow".into()))?;
                let now_ms = now_unix_secs().saturating_mul(1_000) as u64;
                state.last_activity_at = now_ms;
                state.lifecycle = state.idle_timeout_seconds.map(|seconds| ChannelLifecycle {
                    owner: owner.clone(),
                    close_after: now_ms.saturating_add(u64::from(seconds) * 1_000),
                });
                Ok(())
            },
        )
        .await
        .map_err(Error::from)?;
        Ok(acceptance)
    }

    /// Meter one operator-signed request exactly once.
    pub async fn process_use(
        &self,
        payload: &UsePayload,
        challenge_id: &str,
        idempotency_key: &str,
    ) -> Result<UseAcceptance> {
        use ed25519_dalek::Signer;

        if idempotency_key.is_empty() {
            return Err(Error::Other(
                "operator-signed use requires an Idempotency-Key".to_string(),
            ));
        }
        if self.config.voucher_signer != VoucherSigner::Operator {
            return Err(Error::Other(
                "use is only valid for operator-signed sessions".to_string(),
            ));
        }
        let signing_key =
            self.config.operator_signing_key.clone().ok_or_else(|| {
                Error::Other("operator signing key is required for use".to_string())
            })?;
        let signer = bs58::encode(signing_key.verifying_key().as_bytes()).into_string();
        if signer != self.config.operator {
            return Err(Error::Other(
                "operator signing key does not match configured operator".to_string(),
            ));
        }
        let authentication = serde_json::to_string(&payload.authentication)
            .map_err(|error| Error::Other(format!("serialize authentication: {error}")))?;
        let channel_id = payload.channel_id.clone();
        let channel_id_for_update = channel_id.clone();
        let proof = payload.authentication.clone();
        let challenge_id = challenge_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        let price = self.config.amount;
        let lifecycle_owner = self.config.operator.clone();
        self.refresh_channel_snapshot(&channel_id).await?;
        let max_age = self.snapshot_max_age();
        let result = std::sync::Arc::new(std::sync::Mutex::new(None));
        let result_out = std::sync::Arc::clone(&result);
        self.store
            .update_channel(
                &channel_id,
                Box::new(move |state_opt| {
                    let mut state = state_opt.ok_or_else(|| {
                        StoreError::Internal(format!("Channel {channel_id_for_update} not found"))
                    })?;
                    if state.sealed || state.close_requested_at.is_some() {
                        return Err(StoreError::Internal(
                            "Channel is closed or close is pending".to_string(),
                        ));
                    }
                    check_use_binding(&state, &proof, &authentication)?;
                    if let Some(replay) = state
                        .processed_uses
                        .iter()
                        .find(|entry| entry.idempotency_key == idempotency_key)
                    {
                        let voucher = SignedVoucher {
                            data: VoucherData {
                                channel_id: state.channel_id.clone(),
                                cumulative_amount: replay.cumulative.to_string(),
                                expires_at: None,
                            },
                            signer: signer.clone(),
                            signature: replay.voucher_signature.clone(),
                            signature_type: VoucherSignatureType::Ed25519,
                        };
                        *result_out.lock().unwrap() = Some(UseAcceptance {
                            voucher,
                            replay: true,
                        });
                        return Ok(state);
                    }
                    require_fresh_snapshot(&state, max_age)?;
                    let cumulative = state.cumulative.checked_add(price).ok_or_else(|| {
                        StoreError::Internal("session cumulative overflow".to_string())
                    })?;
                    if cumulative > state.deposit {
                        return Err(StoreError::Internal(
                            "insufficient channel availability".to_string(),
                        ));
                    }
                    let data = VoucherData {
                        channel_id: state.channel_id.clone(),
                        cumulative_amount: cumulative.to_string(),
                        expires_at: None,
                    };
                    let signature = bs58::encode(
                        signing_key
                            .sign(
                                &data
                                    .message_bytes()
                                    .map_err(|error| StoreError::Internal(error.to_string()))?,
                            )
                            .to_bytes(),
                    )
                    .into_string();
                    state.cumulative = cumulative;
                    state.spent_amount =
                        state.spent_amount.checked_add(price).ok_or_else(|| {
                            StoreError::Internal("session spent amount overflow".to_string())
                        })?;
                    state.highest_voucher_signature = Some(signature.clone());
                    state.highest_voucher_expires_at = Some(0);
                    let now_ms = now_unix_secs().saturating_mul(1_000) as u64;
                    state.last_activity_at = now_ms;
                    state.lifecycle = state.idle_timeout_seconds.map(|seconds| ChannelLifecycle {
                        owner: lifecycle_owner.clone(),
                        close_after: now_ms.saturating_add(u64::from(seconds) * 1_000),
                    });
                    record_use(
                        &mut state.processed_uses,
                        crate::core::store::ProcessedUse {
                            challenge_id: challenge_id.clone(),
                            idempotency_key: idempotency_key.clone(),
                            cumulative,
                            voucher_signature: signature.clone(),
                            amount: Some(price),
                        },
                    );
                    let voucher = SignedVoucher {
                        data,
                        signer: signer.clone(),
                        signature,
                        signature_type: VoucherSignatureType::Ed25519,
                    };
                    *result_out.lock().unwrap() = Some(UseAcceptance {
                        voucher,
                        replay: false,
                    });
                    Ok(state)
                }),
            )
            .await
            .map_err(store_err)?;
        let acceptance = result
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Error::Other("use did not produce a voucher".to_string()))?;
        Ok(acceptance)
    }

    /// Authenticate a request under an operator-signed session with its
    /// `use` proof, without charging it.
    ///
    /// Hosts whose price is known only after serving authenticate here,
    /// serve, then charge the metered amount with
    /// [`charge_operator_request`](Self::charge_operator_request). Hosts with a
    /// fixed price per request use [`process_use`](Self::process_use).
    ///
    /// Nothing is reserved between the two calls: concurrent requests on one
    /// channel all authenticate against the same remaining deposit, and a
    /// charge that no longer fits is refused after the response was served.
    /// A host that must not serve unpaid work reserves capacity itself
    /// before delivery (MPP-11052eb7e8), for example by bounding each
    /// request's cost and the requests in flight per channel.
    ///
    /// `challenge_id` and `idempotency_key` identify the request; the charge
    /// is recorded under them (MPP-b18b8c42af).
    pub async fn authenticate_use(
        &self,
        payload: &UsePayload,
        challenge_id: &str,
        idempotency_key: &str,
    ) -> Result<AuthenticatedUse> {
        if idempotency_key.is_empty() {
            return Err(Error::Other(
                "operator-signed use requires an Idempotency-Key".to_string(),
            ));
        }
        if self.config.voucher_signer != VoucherSigner::Operator {
            return Err(Error::Other(
                "use is only valid for operator-signed sessions".to_string(),
            ));
        }
        let authentication = serde_json::to_string(&payload.authentication)
            .map_err(|error| Error::Other(format!("serialize authentication: {error}")))?;
        let state = self
            .store
            .get_channel(&payload.channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Other(format!("Channel {} not found", payload.channel_id)))?;
        if state.sealed || state.close_requested_at.is_some() {
            return Err(Error::Other(
                "Channel is closed or close is pending".to_string(),
            ));
        }
        check_use_binding(&state, &payload.authentication, &authentication).map_err(store_err)?;
        self.refresh_channel_snapshot(&payload.channel_id).await?;
        Ok(AuthenticatedUse {
            channel_id: payload.channel_id.clone(),
            authentication,
            challenge_id: challenge_id.to_string(),
            idempotency_key: idempotency_key.to_string(),
        })
    }

    /// Charge an authenticated request on an operator-signed session up to
    /// `request_total`, the request's metered cost so far
    /// (draft-solana-session-00 §Debit Processing step 5): sign the voucher
    /// for `acceptedCumulative` plus what the request has not yet been
    /// charged, and persist it, the new `acceptedCumulative` and
    /// `spentAmount` in one store update.
    ///
    /// A request is metered as it is served, so a stream charges it again
    /// and again with a growing total. Each charge pays only the difference
    /// from what the request was already charged, recorded under its
    /// `(challengeId, idempotencyKey)` in the same update: one record per
    /// request, updated in place. A retry (a lost response, an ambiguous
    /// store result) asking for a total already reached returns the recorded
    /// voucher with `replay: true` and charges nothing (MPP-670a939f90,
    /// MPP-b18b8c42af). The key used for another challenge is refused.
    ///
    /// `signer` is the operator key; it signs before the update so it may be
    /// remote. The update commits only if the watermark and the request's
    /// record are still the ones the voucher was signed from, the channel is
    /// still open and bound to the same proof, the voucher stays within the
    /// deposit, and `guard` accepts the record. A concurrent charge that
    /// moved either, or a store write that lost its compare-and-set to one,
    /// is retried from the new state, up to a bound; `guard` runs again on
    /// every attempt, so it must be nonblocking and free of side effects.
    ///
    /// The channel remembers the last [`MAX_PROCESSED_USES`] requests; a
    /// retry of an older one is not recognised and is charged as a new
    /// request.
    ///
    /// A zero `request_total` is rejected: unused reserved capacity MUST NOT
    /// advance the voucher.
    pub async fn charge_operator_request(
        &self,
        authenticated: &AuthenticatedUse,
        signer: &dyn solana_keychain::SolanaSigner,
        request_total: u64,
        guard: impl Fn(&ChannelState) -> Result<()> + Send + Sync + 'static,
    ) -> Result<OperatorCharge> {
        if request_total == 0 {
            return Err(Error::Other(
                "operator charge amount must be positive".to_string(),
            ));
        }
        if self.config.voucher_signer != VoucherSigner::Operator {
            return Err(Error::Other(
                "operator charges are only valid for operator-signed sessions".to_string(),
            ));
        }
        let operator = signer.pubkey().to_string();
        if operator != self.config.operator {
            return Err(Error::Other(
                "operator signer does not match configured operator".to_string(),
            ));
        }
        let guard = std::sync::Arc::new(guard);
        let channel_id = authenticated.channel_id.clone();
        self.refresh_channel_snapshot(&channel_id).await?;
        let max_age = self.snapshot_max_age();
        for _ in 0..OPERATOR_CHARGE_ATTEMPTS {
            let state = self
                .store
                .get_channel(&channel_id)
                .await
                .map_err(store_err)?
                .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;
            if state.sealed || state.close_requested_at.is_some() {
                return Err(Error::Other(
                    "Channel is closed or close is pending".to_string(),
                ));
            }
            check_bound_authentication(&state, &authenticated.authentication).map_err(store_err)?;
            let recorded = recorded_use(&state, authenticated).map_err(store_err)?;
            let charged_before = recorded.as_ref().map_or(0, |entry| entry.request_total);
            if let Some(entry) = recorded
                .as_ref()
                .filter(|entry| entry.request_total >= request_total)
            {
                return Ok(replayed_charge(&channel_id, &operator, entry));
            }
            let delta = request_total - charged_before;
            let base = state.cumulative;
            let cumulative = base
                .checked_add(delta)
                .ok_or_else(|| Error::Other("session cumulative overflow".to_string()))?;
            if cumulative > state.deposit {
                return Err(Error::Other(
                    "insufficient channel availability".to_string(),
                ));
            }
            let data = VoucherData {
                channel_id: channel_id.clone(),
                cumulative_amount: cumulative.to_string(),
                expires_at: None,
            };
            let signature = signer
                .sign_message(&data.message_bytes()?)
                .await
                .map_err(|error| {
                    Error::Other(format!("operator voucher signing failed: {error}"))
                })?;
            let signature = bs58::encode(<[u8; 64]>::from(signature)).into_string();

            let moved = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let replayed = std::sync::Arc::new(std::sync::Mutex::new(None));
            let commit = {
                let moved = std::sync::Arc::clone(&moved);
                let replayed = std::sync::Arc::clone(&replayed);
                let guard = std::sync::Arc::clone(&guard);
                let authenticated = authenticated.clone();
                let signature = signature.clone();
                let lifecycle_owner = self.config.operator.clone();
                move |state_opt: Option<ChannelState>| {
                    let mut state = state_opt
                        .ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?;
                    if state.sealed || state.close_requested_at.is_some() {
                        return Err(StoreError::Internal(
                            "Channel is closed or close is pending".to_string(),
                        ));
                    }
                    check_bound_authentication(&state, &authenticated.authentication)?;
                    require_fresh_snapshot(&state, max_age)?;
                    let recorded = recorded_use(&state, &authenticated)?;
                    // A retry of this request reached the total since the
                    // read: answer with its record and write nothing new.
                    if let Some(entry) = recorded
                        .as_ref()
                        .filter(|entry| entry.request_total >= request_total)
                    {
                        *replayed.lock().unwrap() = Some(entry.clone());
                        return Ok(state);
                    }
                    if state.cumulative != base
                        || recorded.as_ref().map_or(0, |entry| entry.request_total)
                            != charged_before
                    {
                        moved.store(true, std::sync::atomic::Ordering::Relaxed);
                        return Err(StoreError::Internal(
                            "operator charge watermark moved".to_string(),
                        ));
                    }
                    if cumulative > state.deposit {
                        return Err(StoreError::Internal(
                            "insufficient channel availability".to_string(),
                        ));
                    }
                    guard(&state).map_err(|error| StoreError::Internal(error.to_string()))?;
                    state.cumulative = cumulative;
                    state.spent_amount =
                        state.spent_amount.checked_add(delta).ok_or_else(|| {
                            StoreError::Internal("session spent amount overflow".to_string())
                        })?;
                    state.highest_voucher_signature = Some(signature.clone());
                    state.highest_voucher_expires_at = Some(0);
                    let now_ms = now_unix_secs().saturating_mul(1_000) as u64;
                    state.last_activity_at = now_ms;
                    state.lifecycle = state.idle_timeout_seconds.map(|seconds| ChannelLifecycle {
                        owner: lifecycle_owner.clone(),
                        close_after: now_ms.saturating_add(u64::from(seconds) * 1_000),
                    });
                    record_use(
                        &mut state.processed_uses,
                        crate::core::store::ProcessedUse {
                            challenge_id: authenticated.challenge_id.clone(),
                            idempotency_key: authenticated.idempotency_key.clone(),
                            cumulative,
                            voucher_signature: signature.clone(),
                            amount: Some(request_total),
                        },
                    );
                    Ok(state)
                }
            };
            match self
                .store
                .update_channel(&channel_id, Box::new(commit))
                .await
            {
                Ok(_) => {
                    if let Some(entry) = replayed.lock().unwrap().take() {
                        return Ok(replayed_charge(&channel_id, &operator, &entry));
                    }
                    return Ok(OperatorCharge {
                        voucher: SignedVoucher {
                            data,
                            signer: operator,
                            signature,
                            signature_type: VoucherSignatureType::Ed25519,
                        },
                        previous_cumulative: base,
                        cumulative,
                        charged: delta,
                        request_total,
                        replay: false,
                    });
                }
                Err(_) if moved.load(std::sync::atomic::Ordering::Relaxed) => continue,
                // Every check passed but the write lost a race (the Redis
                // store's compare-and-set): retry from whatever landed, which
                // the next read classifies, replay included.
                Err(_) if self.watermark_moved(&channel_id, base).await? => continue,
                Err(error) => return Err(store_err(error)),
            }
        }
        Err(Error::Other(format!(
            "channel {channel_id} kept advancing concurrently; retry the request"
        )))
    }

    /// Whether the channel's watermark is no longer `base`.
    async fn watermark_moved(&self, channel_id: &str, base: u64) -> Result<bool> {
        Ok(self
            .store
            .get_channel(channel_id)
            .await
            .map_err(store_err)?
            .is_some_and(|state| state.cumulative != base))
    }

    /// Longest a confirmed channel read admits charges on that channel.
    fn snapshot_max_age(&self) -> u64 {
        CHANNEL_SNAPSHOT_MAX_AGE_SECONDS.min(u64::from(self.config.grace_period_seconds) / 2)
    }

    /// Re-read the channel account once half of
    /// [`Self::snapshot_max_age`] has passed since the record's last
    /// confirmed read, so a forced close started onchain fences the record
    /// before it admits another charge.
    ///
    /// A due read that fails or finds no account refuses the charge. A read
    /// showing the channel closing or closed records the close (no further
    /// charges), makes the channel's lifecycle due now so the host settles it
    /// inside the grace period, and refuses the charge.
    async fn refresh_channel_snapshot(&self, channel_id: &str) -> Result<()> {
        let now = now_unix_secs().max(0) as u64;
        let max_age = self.snapshot_max_age();
        let due = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let due_out = std::sync::Arc::clone(&due);
        let observed_slot = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let observed_slot_out = std::sync::Arc::clone(&observed_slot);
        self.store
            .read_channel(
                channel_id,
                Box::new(move |state| {
                    if let Some(state) = state {
                        observed_slot_out.store(
                            state.onchain_observed_slot(),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    let stale = state.is_some_and(|state| {
                        !state.sealed
                            && state.close_requested_at.is_none()
                            && !state
                                .pending_setup
                                .as_ref()
                                .is_some_and(|setup| setup.opens_channel)
                            && now
                                .saturating_sub(state.onchain_observed_at())
                                .saturating_mul(2)
                                >= max_age
                    });
                    due_out.store(stale, std::sync::atomic::Ordering::Relaxed);
                    Ok(())
                }),
            )
            .await
            .map_err(store_err)?;
        if !due.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        // A lagging node may still show a closing channel as open: read from
        // a bank at least as recent as the one last recorded, and record the
        // answering slot so an older view can never renew the window.
        let min_slot = observed_slot.load(std::sync::atomic::Ordering::Relaxed);
        let (read, slot) = self
            .read_channel_lifecycle(channel_id, now, min_slot)
            .await?;
        let (lifecycle, settled) =
            read.ok_or_else(|| Error::Other(format!("Channel {channel_id} not found onchain")))?;
        let owner = self.config.operator.clone();
        self.store
            .mutate_channel(
                channel_id,
                None,
                Box::new(move |state| {
                    state.settled_on_chain = state.settled_on_chain.max(settled);
                    let outcome = state.record_onchain_observation(
                        OnchainObservation {
                            slot: Some(slot),
                            lifecycle,
                        },
                        now,
                    );
                    if let crate::core::store::ObservationOutcome::Behind { recorded } = outcome {
                        return Err(StoreError::Internal(format!(
                            "channel read at slot {slot} is behind the recorded slot {recorded}"
                        )));
                    }
                    if lifecycle != ObservedLifecycle::Open {
                        let now_ms = now.saturating_mul(1_000);
                        let close_after = state
                            .lifecycle
                            .as_ref()
                            .map_or(now_ms, |current| current.close_after.min(now_ms));
                        state.lifecycle = Some(ChannelLifecycle { owner, close_after });
                    }
                    Ok(())
                }),
            )
            .await
            .map_err(store_err)?;
        match lifecycle {
            ObservedLifecycle::Open => Ok(()),
            ObservedLifecycle::Closing { started_at } => Err(Error::Other(format!(
                "Channel close is pending — channel {channel_id} has been closing onchain \
                 since {started_at}; no further charges accepted"
            ))),
            ObservedLifecycle::Terminal { .. } => Err(Error::Other(format!(
                "Channel {channel_id} is already sealed onchain"
            ))),
        }
    }

    /// The lifecycle and settled watermark of the channel account (`None`
    /// when it does not exist), read at confirmed commitment from a bank at
    /// or after `min_slot`, with the slot that answered.
    #[cfg(feature = "server")]
    async fn read_channel_lifecycle(
        &self,
        channel_id: &str,
        now: u64,
        min_slot: u64,
    ) -> Result<(Option<(ObservedLifecycle, u64)>, u64)> {
        if self.config.rpc_url.is_none() {
            return Err(Error::Other(format!(
                "channel {channel_id} needs a confirmed onchain read before it accepts charges, \
                 and no RPC is configured"
            )));
        }
        let pipeline = self.transaction_pipeline().await?;
        let deployment = self.config.channel_deployment()?;
        let (data, slot) = pipeline
            .read_confirmed_owned_account_data_at(
                parse_pubkey(channel_id)?,
                min_slot,
                deployment.program_id,
            )
            .await
            .map_err(|error| Error::Rpc(format!("channel account read failed: {error}")))?;
        let read = data
            .map(|data| {
                let channel = deployment.decode_channel(&data)?.channel;
                Ok::<_, Error>((
                    ObservedLifecycle::of_channel(channel.status, channel.closure_started_at, now),
                    channel.settlement.settled,
                ))
            })
            .transpose()?;
        Ok((read, slot))
    }

    #[cfg(not(feature = "server"))]
    async fn read_channel_lifecycle(
        &self,
        _channel_id: &str,
        _now: u64,
        _min_slot: u64,
    ) -> Result<(Option<(ObservedLifecycle, u64)>, u64)> {
        Err(Error::Other(
            "session channel reads require the `server` feature".to_string(),
        ))
    }

    /// Process a `topup` action: atomically update the channel's deposit cap.
    ///
    /// The additional amount must be positive and must not overflow the
    /// channel deposit. Top-ups are rejected once the channel is
    /// sealed or a close has been requested.
    ///
    /// The top-up transaction is decoded, broadcast, confirmed, and checked
    /// against the resulting channel account before the deposit is raised.
    /// Missing RPC configuration is a hard error.
    pub async fn process_topup(&self, payload: &TopUpPayload) -> Result<ChannelState> {
        Ok(self.process_topup_with_outcome(payload).await?.state)
    }

    /// The request half of a top-up: a positive `additionalAmount` for a
    /// known channel that is still `Open` (no close requested, not sealed).
    async fn topup_channel(&self, payload: &TopUpPayload) -> Result<(u64, ChannelState)> {
        let additional_amount: u64 = payload
            .additional_amount
            .parse()
            .map_err(|_| Error::Other("invalid additionalAmount".to_string()))?;
        if additional_amount == 0 {
            return Err(Error::Other(
                "additionalAmount must be positive".to_string(),
            ));
        }
        let existing = self
            .store
            .get_channel(&payload.channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Other(format!("Channel {} not found", payload.channel_id)))?;
        if existing.sealed || existing.close_requested_at.is_some() {
            return Err(Error::Other(
                "Channel is closed or close is pending".to_string(),
            ));
        }
        Ok((additional_amount, existing))
    }

    /// Process a `topup` action and return its post-co-sign transaction ID.
    pub async fn process_topup_with_outcome(
        &self,
        payload: &TopUpPayload,
    ) -> Result<TopUpAcceptance> {
        let (additional_amount, existing) = self.topup_channel(payload).await?;
        // The transaction id is the fee-payer signature. In sponsored mode
        // that slot is intentionally empty in the submitted payload, so only
        // the server can derive the stable dedupe key after validation and
        // co-signing. A replay may therefore reach RPC again; the confirmed
        // signature status makes that path idempotent before this mutator
        // credits the deposit.
        #[cfg(feature = "server")]
        let pipeline = self.transaction_pipeline().await?;
        #[cfg(feature = "server")]
        let topup_signature = verify_submit_and_fetch_topup(
            payload,
            &existing,
            &self.config,
            &pipeline,
            &self.accepted_versions,
        )
        .await?;
        #[cfg(not(feature = "server"))]
        let topup_signature = verify_submit_and_fetch_topup(
            payload,
            &existing,
            &self.config,
            &(),
            &self.accepted_versions,
        )
        .await?;

        let cid = payload.channel_id.clone();
        let lifecycle_owner = self.config.operator.clone();
        let replay = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let replay_out = std::sync::Arc::clone(&replay);
        let transaction_signature = topup_signature.clone();
        let state = self
            .store
            .update_channel(
                &payload.channel_id,
                Box::new(move |state_opt| {
                    let mut state = state_opt
                        .ok_or_else(|| StoreError::Internal(format!("Channel {cid} not found")))?;
                    // Signature dedupe must live inside the atomic mutator:
                    // two in-flight submissions of the same signed top-up
                    // both confirm the same landed transaction, so only the
                    // first check-and-record may credit the deposit.
                    if state.processed_topup_signatures.contains(&topup_signature) {
                        replay_out.store(true, std::sync::atomic::Ordering::Relaxed);
                        return Ok(state);
                    }
                    if state.sealed {
                        return Err(StoreError::Internal(
                            "Channel is already sealed".to_string(),
                        ));
                    }
                    if state.close_requested_at.is_some() {
                        return Err(StoreError::Internal(
                            "Channel close is pending — no further top-ups accepted".to_string(),
                        ));
                    }
                    let new_deposit =
                        state
                            .deposit
                            .checked_add(additional_amount)
                            .ok_or_else(|| {
                                StoreError::Internal("top-up deposit overflow".to_string())
                            })?;
                    let now_ms = now_unix_secs().saturating_mul(1_000) as u64;
                    state.lifecycle = state.idle_timeout_seconds.map(|seconds| ChannelLifecycle {
                        owner: lifecycle_owner.clone(),
                        close_after: now_ms.saturating_add(u64::from(seconds) * 1_000),
                    });
                    state.deposit = new_deposit;
                    state.last_activity_at = now_ms;
                    state
                        .processed_topup_signatures
                        .push(topup_signature.clone());
                    Ok(state)
                }),
            )
            .await
            .map_err(store_err)?;
        Ok(TopUpAcceptance {
            state,
            replay: replay.load(std::sync::atomic::Ordering::Relaxed),
            transaction_signature,
        })
    }

    /// Reserve capacity for a delivered message/response and return the
    /// metering directive the client must commit after processing it.
    pub async fn begin_delivery(&self, request: DeliveryRequest) -> Result<MeteringDirective> {
        if request.amount == 0 {
            return Err(Error::Other(
                "Delivery amount must be greater than zero".to_string(),
            ));
        }

        let session_id = request.session_id.clone();
        let amount = request.amount;
        // Same wire currency (the mint) the session challenge carries.
        let currency = expected_payment_channel_mint(&self.config)?.to_string();
        let commit_url = request.commit_url.clone();
        let proof = request.proof.clone();
        let requested_delivery_id = request.delivery_id.clone();
        let expires_at = request
            .expires_at
            .unwrap_or(crate::mpp::protocol::intents::session::DEFAULT_SESSION_EXPIRES_AT);
        let directive_out = std::sync::Arc::new(std::sync::Mutex::new(None));
        self.refresh_channel_snapshot(&session_id).await?;
        let max_age = self.snapshot_max_age();

        self.store
            .update_channel(
                &session_id,
                Box::new({
                    let session_id = session_id.clone();
                    let directive_out = std::sync::Arc::clone(&directive_out);
                    move |state_opt| {
                        let mut state = state_opt.ok_or_else(|| {
                            StoreError::Internal(format!("Channel {session_id} not found"))
                        })?;
                        if state.sealed {
                            return Err(StoreError::Internal(
                                "Channel is already sealed".to_string(),
                            ));
                        }
                        if state.close_requested_at.is_some() {
                            return Err(StoreError::Internal(
                                "Channel close is pending — no further deliveries accepted"
                                    .to_string(),
                            ));
                        }
                        require_fresh_snapshot(&state, max_age)?;
                        let reserved = state
                            .pending_deliveries
                            .iter()
                            .try_fold(state.cumulative, |total, delivery| {
                                total.checked_add(delivery.amount)
                            })
                            .and_then(|total| total.checked_add(amount));
                        if reserved.is_none_or(|reserved| reserved > state.deposit) {
                            return Err(StoreError::Internal(format!(
                                "Delivery amount {amount} exceeds available deposit"
                            )));
                        }

                        let sequence = state.next_delivery_sequence + 1;
                        let delivery_id = requested_delivery_id
                            .clone()
                            .unwrap_or_else(|| format!("{session_id}:{sequence}"));
                        if state
                            .pending_deliveries
                            .iter()
                            .any(|delivery| delivery.delivery_id == delivery_id)
                            || state
                                .committed_deliveries
                                .iter()
                                .any(|delivery| delivery.delivery_id == delivery_id)
                        {
                            return Err(StoreError::Internal(format!(
                                "Delivery {delivery_id} already exists"
                            )));
                        }

                        state.next_delivery_sequence = sequence;
                        state.pending_deliveries.push(PendingDelivery {
                            delivery_id: delivery_id.clone(),
                            amount,
                            sequence,
                            expires_at,
                            // A metered delivery is bound by its own
                            // `deliveryId` and committed by the client's
                            // voucher, so it carries no request digest and no
                            // handler stage.
                            request_fingerprint: None,
                            handler_succeeded: false,
                        });

                        *directive_out.lock().unwrap() = Some(MeteringDirective {
                            delivery_id,
                            session_id,
                            amount: amount.to_string(),
                            currency,
                            sequence,
                            expires_at,
                            commit_url,
                            proof,
                        });

                        Ok(state)
                    }
                }),
            )
            .await
            .map_err(store_err)?;

        let directive = directive_out.lock().unwrap().clone();
        directive.ok_or_else(|| {
            Error::Other("Delivery reservation did not produce directive".to_string())
        })
    }

    /// Record the final usage of a reserved delivery, at most its reserved
    /// amount, before the client commits it.
    ///
    /// The commit must then pay exactly `amount`; without a recorded usage it
    /// must pay the full reservation. A usage of `0` releases the reservation.
    pub async fn record_delivery_usage(
        &self,
        channel_id: &str,
        delivery_id: &str,
        amount: u64,
    ) -> Result<()> {
        let delivery_id = delivery_id.to_string();
        self.store
            .update_channel(
                channel_id,
                Box::new(move |state_opt| {
                    let mut state = state_opt
                        .ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?;
                    let index = state
                        .pending_deliveries
                        .iter()
                        .position(|delivery| delivery.delivery_id == delivery_id)
                        .ok_or_else(|| {
                            StoreError::Internal(format!("Delivery {delivery_id} not found"))
                        })?;
                    let reserved = state.pending_deliveries[index].amount;
                    if amount > reserved {
                        return Err(StoreError::Internal(format!(
                            "Usage {amount} exceeds reserved amount {reserved}"
                        )));
                    }
                    if amount == 0 {
                        state.pending_deliveries.remove(index);
                    } else {
                        state.pending_deliveries[index].amount = amount;
                    }
                    Ok(state)
                }),
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    /// Commit a reserved delivery by verifying the attached voucher and
    /// advancing the settled watermark.
    pub async fn process_commit(&self, payload: &CommitPayload) -> Result<CommitReceipt> {
        let channel_id = payload.voucher.data.channel_id.clone();
        let new_cumulative: u64 = payload
            .voucher
            .data
            .cumulative_amount
            .parse()
            .map_err(|_| Error::Other("Invalid cumulative in commit voucher".to_string()))?;

        let state = self
            .store
            .get_channel(&channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;

        if let Some(committed) = state
            .committed_deliveries
            .iter()
            .find(|delivery| delivery.delivery_id == payload.delivery_id)
        {
            if committed.cumulative == new_cumulative
                && committed.voucher_signature == payload.voucher.signature
            {
                verify_signature(
                    &payload.voucher,
                    &state.authorized_signer,
                    self.config.grace_period_seconds as i64,
                )?;
                return Ok(CommitReceipt {
                    delivery_id: payload.delivery_id.clone(),
                    session_id: channel_id,
                    amount: committed.amount.to_string(),
                    cumulative: committed.cumulative.to_string(),
                    status: CommitStatus::Replayed,
                });
            }
            return Err(Error::Other(format!(
                "Delivery {} was already committed with different voucher",
                payload.delivery_id
            )));
        }

        let pending = state
            .pending_deliveries
            .iter()
            .find(|delivery| delivery.delivery_id == payload.delivery_id)
            .cloned()
            .ok_or_else(|| Error::Other(format!("Delivery {} not found", payload.delivery_id)))?;
        let now = unix_now_i64();
        if pending.expires_at <= now {
            return Err(Error::Other(format!(
                "Delivery {} has expired",
                payload.delivery_id
            )));
        }
        if new_cumulative <= state.cumulative {
            return Err(Error::Other(format!(
                "Commit cumulative {new_cumulative} must exceed watermark {}",
                state.cumulative
            )));
        }
        if new_cumulative > state.deposit {
            return Err(Error::Other(format!(
                "Commit cumulative {new_cumulative} exceeds deposit {}",
                state.deposit
            )));
        }
        verify_signature(
            &payload.voucher,
            &state.authorized_signer,
            self.config.grace_period_seconds as i64,
        )?;

        let delivery_id = payload.delivery_id.clone();
        let signature = payload.voucher.signature.clone();
        let expires_at = payload.voucher.data.expires_at.unwrap_or(0);
        let lifecycle_owner = self.config.operator.clone();
        let commit_outcome = std::sync::Arc::new(std::sync::Mutex::new(None));
        let _new_state = self
            .store
            .update_channel(
                &channel_id,
                Box::new({
                    let channel_id = channel_id.clone();
                    let commit_outcome = std::sync::Arc::clone(&commit_outcome);
                    move |state_opt| {
                        let mut state = state_opt.ok_or_else(|| {
                            StoreError::Internal(format!("Channel {channel_id} not found"))
                        })?;
                        if state.sealed {
                            return Err(StoreError::Internal(
                                "Channel is already sealed".to_string(),
                            ));
                        }
                        // A delivery reserved before close was requested may
                        // still commit until the finalizer fixes the sealed
                        // amount (`freeze_watermark_at`); refusing it earlier
                        // would strand a charge that was already served.
                        if let Some(fence) = state.final_cumulative {
                            return Err(StoreError::Internal(format!(
                                "Channel close is pending — final watermark is fixed at {fence}"
                            )));
                        }
                        if let Some(committed) = state
                            .committed_deliveries
                            .iter()
                            .find(|delivery| delivery.delivery_id == delivery_id)
                        {
                            if committed.cumulative == new_cumulative
                                && committed.voucher_signature == signature
                            {
                                *commit_outcome.lock().unwrap() = Some((
                                    committed.amount,
                                    committed.cumulative,
                                    CommitStatus::Replayed,
                                ));
                                return Ok(state);
                            }
                            return Err(StoreError::Internal(format!(
                                "Delivery {delivery_id} was already committed with different voucher"
                            )));
                        }
                        let pending_index = state
                            .pending_deliveries
                            .iter()
                            .position(|delivery| delivery.delivery_id == delivery_id)
                            .ok_or_else(|| {
                                StoreError::Internal(format!("Delivery {delivery_id} not found"))
                            })?;
                        let pending = state.pending_deliveries[pending_index].clone();
                        if pending.expires_at <= now {
                            return Err(StoreError::Internal(format!(
                                "Delivery {delivery_id} has expired"
                            )));
                        }
                        if new_cumulative <= state.cumulative {
                            return Err(StoreError::Internal(format!(
                                "Commit cumulative {new_cumulative} must exceed watermark {}",
                                state.cumulative
                            )));
                        }
                        if new_cumulative > state.deposit {
                            return Err(StoreError::Internal(format!(
                                "Commit cumulative {new_cumulative} exceeds deposit {}",
                                state.deposit
                            )));
                        }
                        // The client signs the amount; only the server decides
                        // how much was delivered (see `record_delivery_usage`).
                        let actual_amount = new_cumulative - state.cumulative;
                        if actual_amount != pending.amount {
                            return Err(StoreError::Internal(format!(
                                "Commit amount {actual_amount} does not match delivery amount {}",
                                pending.amount
                            )));
                        }

                        state.pending_deliveries.remove(pending_index);
                        state.cumulative = new_cumulative;
                        state.spent_amount =
                            state.spent_amount.checked_add(actual_amount).ok_or_else(|| {
                                StoreError::Internal(
                                    "session spent amount overflow".to_string(),
                                )
                            })?;
                        state.highest_voucher_signature = Some(signature.clone());
                        state.highest_voucher_expires_at = Some(expires_at);
                        // A committed delivery is channel activity: refresh the
                        // idle-close deadline like the voucher/use/top-up paths,
                        // or the host's lifecycle worker closes a channel that is
                        // actively paying through the metered-delivery flow.
                        let now_ms = now_unix_secs().saturating_mul(1_000) as u64;
                        state.last_activity_at = now_ms;
                        state.lifecycle =
                            state.idle_timeout_seconds.map(|seconds| ChannelLifecycle {
                                owner: lifecycle_owner.clone(),
                                close_after: now_ms.saturating_add(u64::from(seconds) * 1_000),
                            });
                        state.committed_deliveries.push_back(CommittedDelivery {
                            delivery_id: delivery_id.clone(),
                            amount: actual_amount,
                            cumulative: new_cumulative,
                            voucher_signature: signature,
                            // A commit replay is answered by rebuilding the
                            // receipt from this record, so there is no stored
                            // response and no retention clock to run.
                            request_fingerprint: None,
                            settlement_response: None,
                            cached_response: None,
                            retain_until: 0,
                        });
                        *commit_outcome.lock().unwrap() =
                            Some((actual_amount, new_cumulative, CommitStatus::Committed));
                        Ok(state)
                    }
                }),
            )
            .await
            .map_err(store_err)?;

        let (amount, cumulative, status) = commit_outcome
            .lock()
            .unwrap()
            .ok_or_else(|| Error::Other("Commit did not produce a receipt".to_string()))?;
        Ok(CommitReceipt {
            delivery_id: payload.delivery_id.clone(),
            session_id: channel_id,
            amount: amount.to_string(),
            cumulative: cumulative.to_string(),
            status,
        })
    }

    /// Process a `close` action: atomically set close-pending, accept a final
    /// voucher if provided, and return the parameters needed for on-chain settlement.
    pub async fn process_close(&self, payload: &ClosePayload) -> Result<SealParams> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let voucher_opt = payload.voucher.clone();
        // Same routing-key invariant as the voucher action: a final voucher
        // nested in a close must be bound to the channel being closed.
        if let Some(ref voucher) = voucher_opt {
            if voucher.data.channel_id != payload.channel_id {
                return Err(Error::Other(
                    "close voucher channelId does not match the close channelId".to_string(),
                ));
            }
        }
        let authentication_opt = payload.authentication.clone();
        let settlement_window = self.config.grace_period_seconds as i64;

        self.store
            .update_channel(
                &payload.channel_id,
                Box::new(move |state_opt| {
                    let state = state_opt.ok_or_else(|| {
                        StoreError::Internal("Channel not found".to_string())
                    })?;
                    if state.sealed {
                        return Err(StoreError::Internal(
                            "Channel is already sealed".to_string(),
                        ));
                    }
                    if state.close_requested_at.is_some() {
                        return Err(StoreError::Internal("Close already requested".to_string()));
                    }
                    // Reservations that were (or may have been) delivered
                    // can't be committed once close is pending, so the final
                    // voucher must pay for them; see `owed_at_close`.
                    let live_pending = state
                        .pending_deliveries
                        .iter()
                        .filter(|delivery| delivery.owed_at_close(now as i64))
                        .try_fold(0u64, |total, delivery| total.checked_add(delivery.amount))
                        .ok_or_else(|| {
                            StoreError::Internal("pending delivery total overflow".to_string())
                        })?;

                    // A close that presents authentication against a record
                    // with no proof binding (and no operator marker) is an
                    // operator-signed session whose record predates — or was
                    // stripped of — the binding fields. Without this, the
                    // wiped row falls through to the client branch below and
                    // reports a misleading error.
                    if authentication_opt.is_some()
                        && state.voucher_signer != "operator"
                        && state.opening_challenge_id.is_empty()
                        && state.authentication.is_none()
                    {
                        return Err(StoreError::Internal(
                            "session channel predates proof binding; \
                             the lifecycle worker will close it"
                                .to_string(),
                        ));
                    }
                    if state.voucher_signer == "operator" {
                        if voucher_opt.is_some() {
                            return Err(StoreError::Internal(
                                "operator close must not include a voucher".to_string(),
                            ));
                        }
                        let authentication = authentication_opt.as_ref().ok_or_else(|| {
                            StoreError::Internal(
                                "operator close requires the proof bound at open".to_string(),
                            )
                        })?;
                        if state.opening_challenge_id.is_empty()
                            && state.authentication.is_none()
                        {
                            return Err(StoreError::Internal(
                                "session channel predates proof binding; \
                                 the lifecycle worker will close it"
                                    .to_string(),
                            ));
                        }
                        let encoded = serde_json::to_string(authentication)
                            .map_err(|error| StoreError::Internal(error.to_string()))?;
                        if state.authentication.as_deref() != Some(encoded.as_str())
                            || authentication.challenge_id != state.opening_challenge_id
                            || authentication.payer != state.payer
                            || !authentication
                                .verify(&state.channel_id)
                                .map_err(|error| StoreError::Internal(error.to_string()))?
                        {
                            return Err(StoreError::Internal(
                                "close authentication does not match the proof bound at open"
                                    .to_string(),
                            ));
                        }
                    } else {
                        if authentication_opt.is_some() {
                            return Err(StoreError::Internal(
                                "client close must not include authentication".to_string(),
                            ));
                        }
                        if voucher_opt.is_none() {
                            return Err(StoreError::Internal(
                                "client close requires a final voucher".to_string(),
                            ));
                        }
                    }

                    let (new_cumulative, new_sig, new_expires_at) =
                        if let Some(ref voucher) = voucher_opt {
                        let cumulative: u64 = voucher
                            .data
                            .cumulative_amount
                            .parse()
                            .map_err(|_| StoreError::Internal("Invalid cumulative".to_string()))?;
                        if cumulative <= state.cumulative {
                            // Idempotent replay check
                            if cumulative == state.cumulative
                                && state.highest_voucher_signature.as_deref()
                                    == Some(voucher.signature.as_str())
                            {
                                // Recheck expiry/window even on idempotent replay: a close
                                // must not be recorded against a voucher that no longer
                                // outlasts the settlement window, or the async settle can be
                                // rejected on-chain after close-pending is set.
                                verify_signature(voucher, &state.authorized_signer, settlement_window)
                                    .map_err(|e| StoreError::Internal(e.to_string()))?;
                                (
                                    state.cumulative,
                                    state.highest_voucher_signature.clone(),
                                    state.highest_voucher_expires_at.or(Some(voucher.data.expires_at.unwrap_or(0))),
                                )
                            } else {
                                return Err(StoreError::Internal(format!(
                                    "Final voucher cumulative {cumulative} must exceed watermark {}",
                                    state.cumulative
                                )));
                            }
                        } else {
                            if cumulative > state.deposit {
                                return Err(StoreError::Internal(
                                    "Final voucher exceeds deposit".to_string(),
                                ));
                            }
                            verify_signature(voucher, &state.authorized_signer, settlement_window)
                                .map_err(|e| StoreError::Internal(e.to_string()))?;
                            (
                                cumulative,
                                Some(voucher.signature.clone()),
                                Some(voucher.data.expires_at.unwrap_or(0)),
                            )
                        }
                    } else {
                        (
                            state.cumulative,
                            state.highest_voucher_signature.clone(),
                            state.highest_voucher_expires_at,
                        )
                    };

                    let mut state = state;
                    if live_pending > 0 {
                        let required = state.cumulative.saturating_add(live_pending);
                        if voucher_opt.is_none() || new_cumulative < required {
                            return Err(StoreError::Internal(format!(
                                "Channel has {live_pending} in uncommitted deliveries; \
                                 the final voucher must reach cumulative {required}"
                            )));
                        }
                        state.spent_amount =
                            state.spent_amount.checked_add(live_pending).ok_or_else(|| {
                                StoreError::Internal("session spent amount overflow".to_string())
                            })?;
                        state
                            .pending_deliveries
                            .retain(|delivery| !delivery.owed_at_close(now as i64));
                    }

                    // The client's final voucher is the sealed amount.
                    Ok(ChannelState {
                        cumulative: new_cumulative,
                        highest_voucher_signature: new_sig,
                        highest_voucher_expires_at: new_expires_at,
                        close_requested_at: Some(now),
                        final_cumulative: Some(new_cumulative),
                        ..state
                    })
                }),
            )
            .await
            .map_err(store_err)?;

        self.seal_params(&payload.channel_id).await
    }

    /// Return seal parameters for a channel ready for on-chain settlement.
    pub async fn seal_params(&self, channel_id: &str) -> Result<SealParams> {
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;
        // The program rejects a voucher above the escrow; never hand one out.
        if state.cumulative > state.deposit {
            return Err(Error::Other(format!(
                "Channel {channel_id} cumulative {} exceeds deposit {}",
                state.cumulative, state.deposit
            )));
        }

        let channel_pubkey = parse_pubkey(channel_id)?;
        let recipient_pubkey = parse_pubkey(&self.config.recipient)?;
        let authorized_signer = parse_pubkey(&state.authorized_signer).ok();
        let payer = parse_pubkey(&state.payer).ok();
        let rent_payer = parse_pubkey(&state.rent_payer).ok();
        let mint = expected_payment_channel_mint(&self.config).ok();
        let program_id = self
            .config
            .channel_program
            .unwrap_or_else(payment_channels::default_program_id);

        let splits_with_pubkeys: Vec<payment_channels::Distribution> = self
            .config
            .splits
            .iter()
            .map(|s| payment_channels::Distribution {
                recipient: s.recipient,
                bps: s.bps,
            })
            .collect();

        let distribution_hash = payment_channels::distribution_hash(&splits_with_pubkeys);

        Ok(SealParams {
            channel_id: channel_pubkey,
            authorized_signer,
            payer,
            rent_payer,
            mint,
            program_id,
            channel_version: self.config.channel_version,
            channel_hooks: self.config.channel_hooks.clone(),
            settled: state.cumulative,
            voucher_signature: state.highest_voucher_signature,
            voucher_expires_at: state.highest_voucher_expires_at,
            recipient: recipient_pubkey,
            splits: self.config.splits.clone(),
            distribution_hash,
        })
    }

    /// Mark a channel as sealed (call after the on-chain seal tx confirms).
    pub async fn mark_sealed(&self, channel_id: &str) -> Result<()> {
        self.store.mark_sealed(channel_id).await.map_err(store_err)
    }
}

// ── Helpers ──

fn store_err(e: StoreError) -> Error {
    Error::Other(e.to_string())
}

/// Refuse a charge on a record whose last confirmed onchain read is older
/// than `max_age` seconds: only a fresh read can rule out a forced close.
/// Checked inside every admitting mutation, after
/// [`SessionServer::refresh_channel_snapshot`].
fn require_fresh_snapshot(
    state: &ChannelState,
    max_age: u64,
) -> std::result::Result<(), StoreError> {
    let now = now_unix_secs().max(0) as u64;
    if now.saturating_sub(state.onchain_observed_at()) > max_age {
        return Err(StoreError::Internal(format!(
            "channel {} has no confirmed onchain read in the last {max_age}s",
            state.channel_id
        )));
    }
    Ok(())
}

/// The checks a `use` proof must pass against the channel record: the
/// channel is operator-signed and bound at open to exactly this proof, which
/// was issued for the opening challenge by the payer and verifies over the
/// channel id.
fn check_use_binding(
    state: &ChannelState,
    proof: &crate::mpp::protocol::intents::session::SessionAuthentication,
    authentication: &str,
) -> std::result::Result<(), StoreError> {
    // A record with no binding at all is not a mismatch: it either predates
    // proof binding or was rewritten by a pre-binding writer (the 2026-08-01
    // wipe). Name it so the client knows re-opening — not retrying the proof
    // — is the fix.
    if state.opening_challenge_id.is_empty() && state.authentication.is_none() {
        return Err(StoreError::Internal(
            "session channel predates proof binding; open a new session".to_string(),
        ));
    }
    if state.voucher_signer != "operator"
        || state.authentication.as_deref() != Some(authentication)
        || proof.challenge_id != state.opening_challenge_id
        || proof.payer != state.payer
        || !proof
            .verify(&state.channel_id)
            .map_err(|error| StoreError::Internal(error.to_string()))?
    {
        return Err(StoreError::Internal(
            "use authentication does not match the proof bound at open".to_string(),
        ));
    }
    Ok(())
}

/// The record is an operator channel bound to `authentication` at open. The
/// proof itself was verified by [`SessionServer::authenticate_use`].
fn check_bound_authentication(
    state: &ChannelState,
    authentication: &str,
) -> std::result::Result<(), StoreError> {
    if state.voucher_signer != "operator" || state.authentication.as_deref() != Some(authentication)
    {
        return Err(StoreError::Internal(
            "use authentication does not match the proof bound at open".to_string(),
        ));
    }
    Ok(())
}

/// What a request has been charged so far: its recorded total, and the
/// voucher persisted with it.
#[derive(Debug, Clone)]
struct RecordedUse {
    request_total: u64,
    cumulative: u64,
    voucher_signature: String,
}

/// The record of `authenticated`'s request, if the channel holds one. The
/// key names one request: one recorded for another challenge, or without a
/// total (written before totals were kept), is refused rather than advanced.
fn recorded_use(
    state: &ChannelState,
    authenticated: &AuthenticatedUse,
) -> std::result::Result<Option<RecordedUse>, StoreError> {
    let Some(entry) = state
        .processed_uses
        .iter()
        .find(|entry| entry.idempotency_key == authenticated.idempotency_key)
    else {
        return Ok(None);
    };
    match entry.amount {
        Some(request_total) if entry.challenge_id == authenticated.challenge_id => {
            Ok(Some(RecordedUse {
                request_total,
                cumulative: entry.cumulative,
                voucher_signature: entry.voucher_signature.clone(),
            }))
        }
        _ => Err(StoreError::Internal(
            "Idempotency-Key was already used for a different request".to_string(),
        )),
    }
}

/// Record `entry` as its request's latest charge: replace the request's
/// earlier record, so a request is one entry however often it is charged,
/// and keep only the [`MAX_PROCESSED_USES`] most recently charged requests.
fn record_use(
    processed_uses: &mut Vec<crate::core::store::ProcessedUse>,
    entry: crate::core::store::ProcessedUse,
) {
    processed_uses.retain(|recorded| recorded.idempotency_key != entry.idempotency_key);
    processed_uses.push(entry);
    let excess = processed_uses.len().saturating_sub(MAX_PROCESSED_USES);
    processed_uses.drain(..excess);
}

/// The answer to a retry of a request already charged up to `entry`:
/// the recorded voucher, and nothing charged now.
fn replayed_charge(channel_id: &str, operator: &str, entry: &RecordedUse) -> OperatorCharge {
    OperatorCharge {
        voucher: SignedVoucher {
            data: VoucherData {
                channel_id: channel_id.to_string(),
                cumulative_amount: entry.cumulative.to_string(),
                expires_at: None,
            },
            signer: operator.to_string(),
            signature: entry.voucher_signature.clone(),
            signature_type: VoucherSignatureType::Ed25519,
        },
        previous_cumulative: entry.cumulative,
        cumulative: entry.cumulative,
        charged: 0,
        request_total: entry.request_total,
        replay: true,
    }
}

fn unix_now_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(feature = "server")]
fn confirmed_rpc_client(rpc_url: &str) -> solana_rpc_client::rpc_client::RpcClient {
    solana_rpc_client::rpc_client::RpcClient::new_with_commitment(
        rpc_url.to_string(),
        solana_commitment_config::CommitmentConfig::confirmed(),
    )
}

/// A sponsored server co-signs as fee payer and rent payer. If the channel
/// payer were the same key, that one signature would also authorize the
/// deposit out of the sponsor's own token account, so the roles must differ.
fn reject_sponsor_as_payer(config: &SessionConfig, payer: &Pubkey) -> Result<()> {
    if config
        .fee_payer_signer
        .as_ref()
        .is_some_and(|signer| signer.pubkey() == *payer)
    {
        return Err(Error::Other(
            "payment-channel payer must differ from the sponsored fee payer".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "server")]
async fn prepare_open_transaction(
    payload: &OpenPayload,
    params: &payment_channels::OpenChannelParams,
    challenged_blockhash: &str,
    fee_payer_signer: Option<&dyn solana_keychain::TransactionSigner>,
    accepted_versions: &[TxVersion],
    config: &SessionConfig,
) -> Result<(solana_transaction::versioned::VersionedTransaction, String)> {
    let mut tx = payment_channels::decode_transaction(&payload.transaction)?;
    // Envelope: accepted version, no address lookup tables, size within the
    // version's limit; then the version-1 header config against the same caps
    // the ComputeBudget prefix gets on version 0.
    crate::core::tx::check_envelope_without_legacy(&tx, accepted_versions)?;
    crate::core::tx::check_v1_budget_caps(
        &tx.message,
        crate::mpp::server::charge::MAX_COMPUTE_UNIT_LIMIT,
        if fee_payer_signer.is_some() {
            crate::mpp::server::charge::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED
        } else {
            crate::mpp::server::charge::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS
        },
    )?;
    let price_cap = if fee_payer_signer.is_some() {
        crate::mpp::server::charge::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED
    } else {
        crate::mpp::server::charge::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS
    };
    if let Some(declared) = crate::core::tx::check_v0_budget_caps(
        &tx.message,
        crate::mpp::server::charge::MAX_COMPUTE_UNIT_LIMIT,
        price_cap,
    )? {
        crate::core::tx::require_budget_prefix(&tx.message, &declared)?;
    }
    // The compiled message must use the challenged `recentBlockhash`: it
    // proves the transaction was built for this challenge, not replayed from
    // an older one the server never authorized.
    if tx.message.recent_blockhash().to_string() != challenged_blockhash {
        return Err(Error::Other(
            "open transaction does not use the challenged recentBlockhash".to_string(),
        ));
    }
    let keys = tx.message.static_account_keys();
    if keys.first() != Some(&params.rent_payer) {
        return Err(Error::Other(
            "open transaction fee payer does not match the challenge policy".to_string(),
        ));
    }
    let expected = if config.channel_deployment()?.version == 2 {
        crate::core::payment_channels_v2::build_open_instruction(
            params,
            &config.channel_hooks.clone().unwrap_or_default(),
        )?
    } else {
        payment_channels::build_open_instruction(params)
    };
    let compute_budget = parse_pubkey("ComputeBudget111111111111111111111111111111")?;
    let mut found_open = false;
    for ix in tx.message.instructions() {
        let program = keys.get(ix.program_id_index as usize).ok_or_else(|| {
            Error::Other("open instruction program index out of range".to_string())
        })?;
        // Validated as a whole by `check_v0_budget_caps` above.
        if *program == compute_budget {
            continue;
        }
        if found_open || *program != expected.program_id || ix.data.first() != expected.data.first()
        {
            return Err(Error::Other(
                "open transaction contains an unexpected instruction".to_string(),
            ));
        }
        // The open the credential declares, decoded from the transaction:
        // its arguments, then its accounts (the channel PDA first, which the
        // declared channelId must name).
        if ix.data != expected.data {
            return Err(Error::Other(
                "open instruction arguments do not match the credential".to_string(),
            ));
        }
        let accounts = ix
            .accounts
            .iter()
            .map(|index| {
                keys.get(*index as usize)
                    .copied()
                    .ok_or_else(|| Error::Other("open account index out of range".to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        let expected_accounts = expected
            .accounts
            .iter()
            .map(|account| account.pubkey)
            .collect::<Vec<_>>();
        if accounts.get(OPEN_CHANNEL_ACCOUNT) != expected_accounts.get(OPEN_CHANNEL_ACCOUNT) {
            return Err(Error::Other(
                "open transaction channel account does not match the derived channel PDA"
                    .to_string(),
            ));
        }
        if accounts != expected_accounts {
            return Err(Error::Other(
                "open transaction accounts do not match the declared channel".to_string(),
            ));
        }
        found_open = true;
    }
    if !found_open {
        return Err(Error::Other(
            "open transaction does not contain the expected open instruction".to_string(),
        ));
    }
    // Privileges after the instruction allowlist, so an unexpected
    // instruction is reported as one rather than by the accounts it adds.
    verify_channel_privileges(&tx, &expected, params.rent_payer)?;

    verify_client_transaction_signatures(&tx, fee_payer_signer.map(|signer| signer.pubkey()))?;
    if let Some(signer) = fee_payer_signer {
        payment_channels::cosign_fee_payer(signer, &params.rent_payer, &mut tx).await?;
    }
    let payer_index = tx
        .message
        .static_account_keys()
        .iter()
        .position(|key| key == &params.payer)
        .ok_or_else(|| Error::Other("open payer is missing from transaction".into()))?;
    let payer_signature = tx
        .signatures
        .get(payer_index)
        .ok_or_else(|| Error::Other("open payer signature is missing".into()))?
        .to_string();
    Ok((tx, payer_signature))
}

/// Conformance hooks (feature `testkit`). Not a payment verifier: nothing
/// here binds the challenge id, stores the channel, co-signs or broadcasts.
/// Use [`SessionServer`] to accept payments.
#[cfg(all(feature = "server", feature = "testkit"))]
pub mod testkit {
    use super::*;

    /// The offline checks [`SessionServer`] applies to a client-paid `open`
    /// before it broadcasts: the open parameters the payload declares,
    /// against the server's configuration (`payment_channel_open_params`),
    /// then the transaction (`prepare_open_transaction`: accepted message
    /// version, size, compute budget, the challenged blockhash, fee payer,
    /// the expected open instruction and the client's signatures).
    pub async fn verify_open_transaction_pre_broadcast<S: ChannelStore>(
        server: &SessionServer<S>,
        open: &OpenPayload,
        challenged_blockhash: &str,
    ) -> Result<()> {
        let params = server.payment_channel_open_params(open)?;
        prepare_open_transaction(
            open,
            &params,
            challenged_blockhash,
            None,
            &server.accepted_versions,
            &server.config,
        )
        .await
        .map(|_| ())
    }

    /// Every check [`SessionServer::process_open`] makes on an `open`
    /// credential before it persists the open intent or broadcasts, in its
    /// order: the credential (`validate_open_request`: challenge expiry,
    /// deposit and idle-timeout selection, the open parameters against the
    /// challenge, the `openSlot` window against `context.recent_slot`, the
    /// voucher-signer mode and bearer proof), then the decoded transaction
    /// (`prepare_open`, co-signed in memory when the server sponsors fees).
    /// The window against the live cluster slot needs RPC and is not part
    /// of it.
    pub async fn verify_open_pre_broadcast<S: ChannelStore>(
        server: &SessionServer<S>,
        open: &OpenPayload,
        context: SessionOpenContext<'_>,
    ) -> Result<()> {
        let validated = server.validate_open_request(open, context)?;
        server
            .prepare_open(open, &validated.params, context)
            .await
            .map(|_| ())
    }

    /// Every check [`SessionServer::process_topup`] makes on a `topUp`
    /// credential before it broadcasts: a positive `additionalAmount` for a
    /// stored channel that is still `Open`, then the decoded transaction
    /// (`prepare_topup_transaction`, co-signed in memory when the channel's
    /// rent payer is the configured sponsor).
    pub async fn verify_topup_pre_broadcast<S: ChannelStore>(
        server: &SessionServer<S>,
        topup: &TopUpPayload,
    ) -> Result<()> {
        let (_, state) = server.topup_channel(topup).await?;
        prepare_topup_transaction(topup, &state, &server.config, &server.accepted_versions)
            .await
            .map(|_| ())
    }
}

#[cfg(feature = "server")]
async fn submit_and_fetch_open(
    tx: solana_transaction::versioned::VersionedTransaction,
    params: &payment_channels::OpenChannelParams,
    pipeline: &crate::core::tx_pipeline::TxPipeline,
    fresh_open: bool,
    activation_floor: Option<u64>,
    config: &SessionConfig,
) -> Result<OpenSubmission> {
    let signature = *tx.signatures.first().ok_or_else(|| {
        Error::Other("open transaction is missing its fee-payer signature".into())
    })?;
    let transaction_signature = signature.to_string();
    // With no active ledger row, a channel is adopted only on proof that this
    // ledger's own broadcast landed it: its signature confirmed after the slot
    // recorded before that broadcast. Anything else may be a channel opened by
    // another endpoint sharing the challenge secret, or by a lost ledger, and
    // adopting it would start an independent watermark against escrow another
    // ledger already spends.
    let landed_here = |landed: u64, floor: u64| {
        if landed <= floor {
            Err(OpenSubmission::OpenedElsewhere)
        } else {
            Ok(())
        }
    };

    let existing = if fresh_open {
        None
    } else {
        fetch_and_match_open_channel(pipeline, params, None, config)
            .await
            .ok()
    };
    if let Some(settled) = existing {
        // The channel account already matches this exact open (a resubmit —
        // e.g. the client never saw the first response). Never rebroadcast an
        // open that has nothing left to do: it would burn a sponsor fee on
        // every duplicate open request, not just the first.
        match activation_floor {
            None => {
                return Ok(OpenSubmission::Landed {
                    signature: transaction_signature,
                    settled,
                })
            }
            Some(floor) => {
                let landed = pipeline
                    .landed_slot(signature)
                    .await
                    .map_err(|error| Error::Rpc(format!("open ownership check failed: {error}")))?
                    .ok_or_else(|| {
                        Error::Rpc(format!(
                            "open {transaction_signature} has not been observed landing; \
                             channel ownership is unproven"
                        ))
                    })?;
                if let Err(elsewhere) = landed_here(landed, floor) {
                    return Ok(elsewhere);
                }
                return Ok(OpenSubmission::Landed {
                    signature: transaction_signature,
                    settled,
                });
            }
        }
    }
    // A broadcast rejection is not authoritative: a retry of an open whose
    // first submission landed (response lost, or the store write after it
    // failed) dies at preflight with "already processed", and the pipeline
    // still reports that signature's confirmed landing.
    let submission = submit_client_transaction(pipeline, tx, config).await;
    let min_context_slot = submission.as_ref().ok().map(|confirmed| confirmed.slot);
    if let (Some(floor), Ok(landed)) = (activation_floor, &submission) {
        if let Err(elsewhere) = landed_here(landed.slot, floor) {
            return Ok(elsewhere);
        }
    }
    let confirmed = fetch_and_match_open_channel(pipeline, params, min_context_slot, config).await;
    let settled = match (submission, confirmed) {
        (Ok(_), confirmed) => confirmed,
        // An active row's channel account is authoritative for this exact open.
        (Err(_), Ok(settled)) if activation_floor.is_none() => Ok(settled),
        (Err(error), _) => Err(Error::Rpc(format!("open submission failed: {error}"))),
    }?;
    Ok(OpenSubmission::Landed {
        signature: transaction_signature,
        settled,
    })
}

/// Broadcast a validated client `open` or `topUp` and await confirmation.
/// One the configured sponsor pays the fee for is simulated first: it is
/// charged for a transaction that fails on-chain, and the offline checks
/// cannot show that the payer holds the tokens it moves.
#[cfg(feature = "server")]
async fn submit_client_transaction(
    pipeline: &crate::core::tx_pipeline::TxPipeline,
    tx: solana_transaction::versioned::VersionedTransaction,
    config: &SessionConfig,
) -> std::result::Result<
    crate::core::tx_pipeline::ConfirmedTransaction,
    crate::core::tx_pipeline::TxPipelineError,
> {
    let sponsor = config
        .fee_payer_signer
        .as_ref()
        .map(|signer| signer.pubkey());
    if sponsor.is_some() && tx.message.static_account_keys().first() == sponsor.as_ref() {
        let simulated = pipeline.simulate(tx).await?;
        pipeline.submit_simulated(&simulated).await
    } else {
        pipeline.submit_verified(&tx).await
    }
}

#[cfg(feature = "server")]
async fn validate_open_slot(
    pipeline: &crate::core::tx_pipeline::TxPipeline,
    open_slot: u64,
) -> Result<u64> {
    let current_slot = pipeline
        .current_slot()
        .await
        .map_err(|error| Error::Rpc(format!("session open slot validation failed: {error}")))?;
    if open_slot > current_slot {
        return Err(Error::Other(format!(
            "open openSlot {open_slot} is ahead of the current cluster slot {current_slot}"
        )));
    }
    if current_slot - open_slot > payment_channels::OPEN_SLOT_WINDOW {
        return Err(Error::Other(format!(
            "open openSlot {open_slot} is outside the {}-slot freshness window of the current cluster slot {current_slot}",
            payment_channels::OPEN_SLOT_WINDOW
        )));
    }
    Ok(current_slot)
}

#[cfg(feature = "server")]
async fn fetch_and_match_open_channel(
    pipeline: &crate::core::tx_pipeline::TxPipeline,
    params: &payment_channels::OpenChannelParams,
    min_context_slot: Option<u64>,
    config: &SessionConfig,
) -> Result<u64> {
    let channel_address = payment_channels::derive_channel_addresses(params).channel;
    let account_data = pipeline
        .read_owned_account_data(channel_address, min_context_slot, params.program_id)
        .await
        .map_err(|error| Error::Rpc(format!("fetch confirmed channel failed: {error}")))?
        .ok_or_else(|| Error::Rpc("confirmed channel account not found".to_string()))?;
    let decoded = config.channel_deployment()?.decode_channel(&account_data)?;
    if decoded.guard != 0 || decoded.hooks != config.channel_hooks.clone().unwrap_or_default() {
        return Err(Error::Other(
            "confirmed channel hooks do not match challenge".into(),
        ));
    }
    let channel = decoded.channel;
    if channel.status != 0
        || channel.deposit != params.deposit
        || channel.salt != params.salt
        || channel.open_slot != params.open_slot
        || channel.grace_period != params.grace_period
        || payment_channels::from_address(&channel.payer) != params.payer
        || payment_channels::from_address(&channel.rent_payer) != params.rent_payer
        || payment_channels::from_address(&channel.payee) != params.payee
        || payment_channels::from_address(&channel.mint) != params.mint
        || payment_channels::from_address(&channel.authorized_signer) != params.authorized_signer
        || channel.distribution_hash != payment_channels::distribution_hash(&params.recipients)
    {
        return Err(Error::Other(
            "confirmed channel state does not match the verified open transaction".to_string(),
        ));
    }
    Ok(channel.settlement.settled)
}

/// A top-up transaction that passed every offline check, co-signed when the
/// channel's rent payer is the configured sponsor.
#[cfg(feature = "server")]
struct PreparedTopUp {
    tx: solana_transaction::versioned::VersionedTransaction,
    amount: u64,
    channel: Pubkey,
    program_id: Pubkey,
    deployment: crate::core::payment_channels_v2::Deployment,
}

/// The offline checks on a client's `topUp` transaction: accepted message
/// version and budget, the fee payer the channel's recorded rent payer
/// implies, exactly one top-up instruction for this channel, mint, token
/// program and `additionalAmount`, matching privileges and the client's
/// signatures. Co-signs a sponsored top-up; never broadcasts.
#[cfg(feature = "server")]
async fn prepare_topup_transaction(
    payload: &TopUpPayload,
    state: &ChannelState,
    config: &SessionConfig,
    accepted_versions: &[TxVersion],
) -> Result<PreparedTopUp> {
    let amount = payload
        .additional_amount
        .parse::<u64>()
        .map_err(|_| Error::Other("invalid additionalAmount".to_string()))?;
    let payer = parse_pubkey_field(&state.payer, "payer")?;
    reject_sponsor_as_payer(config, &payer)?;
    let channel = parse_pubkey_field(&payload.channel_id, "channelId")?;
    let mint = expected_payment_channel_mint(config)?;
    let token_program = match config.token_program {
        Some(program) => program,
        None => parse_pubkey_field(
            default_token_program_for_currency(&config.currency, Some(config.network.as_str())),
            "token program",
        )?,
    };
    let program_id = config
        .channel_program
        .unwrap_or_else(payment_channels::default_program_id);
    let deployment = config.channel_deployment()?;
    let expected = if deployment.version == 2 {
        crate::core::payment_channels_v2::build_top_up_instruction(
            &payer,
            &channel,
            &mint,
            amount,
            &token_program,
            &program_id,
            &config.channel_hooks.clone().unwrap_or_default(),
        )?
    } else {
        payment_channels::build_top_up_instruction(
            &payer,
            &channel,
            &mint,
            amount,
            &token_program,
            &program_id,
        )
    };
    let mut tx = payment_channels::decode_transaction(&payload.transaction)?;
    // Envelope: accepted version, no address lookup tables, size within the
    // version's limit; then the version-1 header config against the same caps
    // the ComputeBudget prefix gets on version 0.
    crate::core::tx::check_envelope_without_legacy(&tx, accepted_versions)?;
    crate::core::tx::check_v1_budget_caps(
        &tx.message,
        crate::mpp::server::charge::MAX_COMPUTE_UNIT_LIMIT,
        if config.fee_payer_signer.is_some() {
            crate::mpp::server::charge::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED
        } else {
            crate::mpp::server::charge::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS
        },
    )?;
    let keys = tx.message.static_account_keys();
    let stored_rent_payer = parse_pubkey_field(&state.rent_payer, "stored rentPayer")?;
    let fee_payer_signer = match config.fee_payer_signer.as_deref() {
        Some(signer) if signer.pubkey() == stored_rent_payer => Some(signer),
        Some(_) if stored_rent_payer == payer => None,
        Some(_) => {
            return Err(Error::Other(
                "configured session fee payer does not match the channel rentPayer".into(),
            ));
        }
        None if stored_rent_payer == payer => None,
        None => {
            return Err(Error::Other(
                "sponsored session top-up requires the channel fee-payer signer".into(),
            ));
        }
    };
    let expected_fee_payer = fee_payer_signer
        .map(|signer| signer.pubkey())
        .unwrap_or(payer);
    if keys.first() != Some(&expected_fee_payer) {
        return Err(Error::Other(
            "top-up transaction fee payer does not match the challenge policy".to_string(),
        ));
    }
    if let Some(declared) = crate::core::tx::check_v0_budget_caps(
        &tx.message,
        crate::mpp::server::charge::MAX_COMPUTE_UNIT_LIMIT,
        if fee_payer_signer.is_some() {
            crate::mpp::server::charge::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED
        } else {
            crate::mpp::server::charge::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS
        },
    )? {
        crate::core::tx::require_budget_prefix(&tx.message, &declared)?;
    }
    let compute_budget = parse_pubkey("ComputeBudget111111111111111111111111111111")?;
    let mut found = false;
    for ix in tx.message.instructions() {
        let program = keys
            .get(ix.program_id_index as usize)
            .ok_or_else(|| Error::Other("top-up program index out of range".to_string()))?;
        // Validated as a whole by `check_v0_budget_caps` above.
        if *program == compute_budget {
            continue;
        }
        let accounts = ix
            .accounts
            .iter()
            .map(|index| {
                keys.get(*index as usize)
                    .copied()
                    .ok_or_else(|| Error::Other("top-up account index out of range".to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        let expected_accounts = expected
            .accounts
            .iter()
            .map(|account| account.pubkey)
            .collect::<Vec<_>>();
        if found || *program != expected.program_id || ix.data.first() != expected.data.first() {
            return Err(Error::Other(
                "top-up transaction contains an unexpected instruction".to_string(),
            ));
        }
        if accounts != expected_accounts {
            return Err(Error::Other(
                "top-up transaction accounts do not match the stored channel".to_string(),
            ));
        }
        if ix.data != expected.data {
            return Err(Error::Other(
                "top-up transaction amount does not match additionalAmount".to_string(),
            ));
        }
        found = true;
    }
    if !found {
        return Err(Error::Other("top-up instruction not found".to_string()));
    }
    verify_channel_privileges(&tx, &expected, expected_fee_payer)?;
    verify_client_transaction_signatures(&tx, fee_payer_signer.map(|signer| signer.pubkey()))?;
    if let Some(signer) = fee_payer_signer {
        payment_channels::cosign_fee_payer(signer, &expected_fee_payer, &mut tx).await?;
    }
    Ok(PreparedTopUp {
        tx,
        amount,
        channel,
        program_id,
        deployment,
    })
}

#[cfg(feature = "server")]
async fn verify_submit_and_fetch_topup(
    payload: &TopUpPayload,
    state: &ChannelState,
    config: &SessionConfig,
    pipeline: &crate::core::tx_pipeline::TxPipeline,
    accepted_versions: &[TxVersion],
) -> Result<String> {
    let PreparedTopUp {
        tx,
        amount,
        channel,
        program_id,
        deployment,
    } = prepare_topup_transaction(payload, state, config, accepted_versions).await?;
    let signature = tx
        .signatures
        .first()
        .ok_or_else(|| Error::Other("top-up transaction is missing a signature".to_string()))?
        .to_string();
    if state.processed_topup_signatures.contains(&signature) {
        return Ok(signature);
    }
    // `submit_verified` already asks the shared confirmation tracker whether
    // THIS signature specifically reached confirmed commitment
    // (`TxPipeline::confirm`, via `getSignatureStatuses`) before reporting an
    // error — a send failure alone is never authoritative there (see its own
    // doc comment). So `Err` here means this exact transaction did not
    // confirm, full stop: falling through to a generic "does the channel's
    // aggregate on-chain deposit meet `state.deposit + amount`" check would
    // let a *different*, concurrently-landed top-up satisfy an unrelated
    // request's minimum, since every concurrent top-up in this window reads
    // the same stale `state.deposit` baseline. That request would then
    // return `Ok(signature)` for a signature that never landed, and the
    // atomic mutator in `process_topup_with_outcome` credits
    // `additionalAmount` once per distinct signature — stacking N credits in
    // the store for one real on-chain deposit.
    let confirmed = submit_client_transaction(pipeline, tx, config)
        .await
        .map_err(|error| Error::Rpc(format!("top-up submission failed: {error}")))?;
    // A confirmed signature can still be forked out, and the aggregate
    // deposit read below can be met by another top-up on the surviving fork.
    // Credit only a signature that finalized, against finalized state.
    let finalized = pipeline
        .confirm_finalized(confirmed.signature)
        .await
        .map_err(|error| Error::Rpc(format!("top-up finalization failed: {error}")))?;
    let account_data = pipeline
        .read_finalized_owned_account_data(channel, finalized.slot, program_id)
        .await
        .map_err(|error| Error::Rpc(format!("fetch topped-up channel failed: {error}")))?
        .ok_or_else(|| Error::Rpc("finalized topped-up channel account not found".to_string()))?;
    let decoded = deployment.decode_channel(&account_data)?;
    if decoded.guard != 0 || decoded.hooks != config.channel_hooks.clone().unwrap_or_default() {
        return Err(Error::Other(
            "topped-up channel hooks do not match stored policy".into(),
        ));
    }
    let channel_state = decoded.channel;
    let minimum = state
        .deposit
        .checked_add(amount)
        .ok_or_else(|| Error::Other("top-up deposit overflow".to_string()))?;
    if channel_state.status != 0 || channel_state.deposit < minimum {
        return Err(Error::Other(
            "confirmed channel state does not reflect the submitted top-up".to_string(),
        ));
    }
    Ok(signature)
}

#[cfg(not(feature = "server"))]
async fn verify_submit_and_fetch_topup(
    _payload: &TopUpPayload,
    _state: &ChannelState,
    _config: &SessionConfig,
    _pipeline: &(),
    _accepted_versions: &[TxVersion],
) -> Result<String> {
    Err(Error::Other(
        "session top-up verification requires the `server` feature".to_string(),
    ))
}

#[cfg(not(feature = "server"))]
async fn prepare_open_transaction(
    _payload: &OpenPayload,
    _params: &payment_channels::OpenChannelParams,
    _challenged_blockhash: &str,
    _fee_payer_signer: Option<&dyn solana_keychain::TransactionSigner>,
    _accepted_versions: &[TxVersion],
    _config: &SessionConfig,
) -> Result<(solana_transaction::versioned::VersionedTransaction, String)> {
    Err(Error::Other(
        "session open verification requires the `server` feature".to_string(),
    ))
}

#[cfg(not(feature = "server"))]
async fn submit_and_fetch_open(
    _tx: solana_transaction::versioned::VersionedTransaction,
    _params: &payment_channels::OpenChannelParams,
    _pipeline: &(),
    _fresh_open: bool,
    _activation_floor: Option<u64>,
    _config: &SessionConfig,
) -> Result<OpenSubmission> {
    Err(Error::Other(
        "session open verification requires the `server` feature".to_string(),
    ))
}

/// Compare transaction-wide privileges to the union of the committed account
/// metas. Duplicate account keys legitimately merge privileges in Solana.
#[cfg(feature = "server")]
fn verify_channel_privileges(
    tx: &solana_transaction::versioned::VersionedTransaction,
    expected: &solana_instruction::Instruction,
    fee_payer: Pubkey,
) -> Result<()> {
    let header = tx.message.header();
    let keys = tx.message.static_account_keys();
    let required = usize::from(header.num_required_signatures);
    let writable_signed = required.saturating_sub(usize::from(header.num_readonly_signed_accounts));
    let writable_unsigned_end = keys
        .len()
        .saturating_sub(usize::from(header.num_readonly_unsigned_accounts));
    for (index, key) in keys.iter().enumerate() {
        let signer = index < required;
        let writable = if signer {
            index < writable_signed
        } else {
            index < writable_unsigned_end
        };
        let expected_signer = *key == fee_payer
            || expected
                .accounts
                .iter()
                .any(|meta| meta.pubkey == *key && meta.is_signer);
        let expected_writable = *key == fee_payer
            || expected
                .accounts
                .iter()
                .any(|meta| meta.pubkey == *key && meta.is_writable);
        if signer != expected_signer || writable != expected_writable {
            return Err(Error::Other(
                "channel transaction account privileges do not match committed policy".into(),
            ));
        }
    }
    Ok(())
}

fn verify_client_transaction_signatures(
    tx: &solana_transaction::versioned::VersionedTransaction,
    server_fee_payer: Option<Pubkey>,
) -> Result<()> {
    crate::core::tx::require_presigned(tx, server_fee_payer.as_ref())
        .map_err(|error| Error::Other(format!("session transaction: {error}")))
}

fn parse_pubkey(s: &str) -> Result<Pubkey> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| Error::Other(format!("Invalid pubkey {s}: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Other(format!("Pubkey {s} is not 32 bytes")))?;
    Ok(Pubkey::from(arr))
}

fn parse_pubkey_field(value: &str, field: &str) -> Result<Pubkey> {
    parse_pubkey(value).map_err(|e| Error::Other(format!("invalid payment-channel {field}: {e}")))
}

/// Parse the configured operator pubkey used for operator-signed vouchers.
fn parse_required_operator(operator: &str) -> Result<Pubkey> {
    if operator.trim().is_empty() {
        return Err(Error::Other(
            "payment-channel open requires a configured operator signer".to_string(),
        ));
    }
    parse_pubkey_field(operator, "operator")
}

fn expected_payment_channel_mint(config: &SessionConfig) -> Result<Pubkey> {
    let mint = crate::mpp::protocol::solana::try_resolve_stablecoin_mint(
        &config.currency,
        Some(config.network.as_str()),
    )?
    .ok_or_else(|| Error::Other("payment-channel sessions require an SPL token".to_string()))?;
    parse_pubkey_field(mint, "currency")
}

/// Current Unix time in seconds.
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Verify an Ed25519 voucher signature against the authorized signer.
///
/// Delegates to [`crate::core::voucher::verify_voucher_signature`] — the
/// shared implementation also used by the x402 `batch-settlement` scheme.
///
/// `settlement_window` is the channel's forced-close grace period (seconds): a
/// non-zero voucher expiry must outlast it so the voucher can still settle
/// on-chain after the async forced-close delay (`0` expiry = never expires).
fn verify_signature(
    voucher: &SignedVoucher,
    authorized_signer: &str,
    settlement_window: i64,
) -> Result<()> {
    if voucher.signer != authorized_signer {
        return Err(Error::Other(
            "voucher signer does not match the channel authorized signer".to_string(),
        ));
    }
    let cumulative: u64 = voucher
        .data
        .cumulative_amount
        .parse()
        .map_err(|_| Error::Other("Invalid cumulative in voucher".to_string()))?;
    crate::core::voucher::verify_voucher_signature(
        &voucher.data.channel_id,
        cumulative,
        voucher.data.expires_at.unwrap_or(0),
        &voucher.signature,
        authorized_signer,
        now_unix_secs(),
        settlement_window,
    )
    .map_err(Into::into)
}

/// Compute the payment-channel distribution hash for explicit recipients.
///
/// The primary payee receives the implicit remainder and is not part of the
/// hashed preimage unless it is explicitly listed in `splits`.
pub fn compute_distribution_hash(_recipient: &Pubkey, splits: &[(Pubkey, u16)]) -> [u8; 32] {
    let recipients = splits
        .iter()
        .map(|(recipient, bps)| payment_channels::Distribution {
            recipient: *recipient,
            bps: *bps,
        })
        .collect::<Vec<_>>();
    payment_channels::distribution_hash(&recipients)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpp::client::session::ActiveSession;
    use crate::mpp::protocol::intents::session::{
        SessionAuthentication, SessionSplit, VoucherSignatureType,
    };
    use crate::mpp::protocol::solana::{mints, programs};
    use crate::mpp::store::MemoryChannelStore;
    use solana_keychain::MemorySigner;
    use solana_signature::Signature;
    use std::str::FromStr;

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn signer(seed: u8) -> Box<dyn solana_keychain::TransactionSigner> {
        let key = key(seed);
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(key.as_bytes());
        bytes[32..].copy_from_slice(key.verifying_key().as_bytes());
        Box::new(MemorySigner::from_bytes(&bytes).unwrap())
    }

    fn shared_signer(seed: u8) -> std::sync::Arc<dyn solana_keychain::TransactionSigner> {
        std::sync::Arc::from(signer(seed))
    }

    fn signer_address(seed: u8) -> String {
        bs58::encode(key(seed).verifying_key().as_bytes()).into_string()
    }

    #[cfg(feature = "server")]
    #[test]
    fn session_rpc_uses_confirmed_commitment() {
        assert_eq!(
            confirmed_rpc_client("http://127.0.0.1:1").commitment(),
            solana_commitment_config::CommitmentConfig::confirmed()
        );
    }

    /// The `recentSlot` every test challenge advertises; matches the
    /// `open_slot` used by `valid_open`/`signed_open`.
    const CHALLENGED_SLOT: u64 = 42;

    /// The `recentBlockhash` every test challenge advertises; `signed_open`
    /// builds its transaction with the same hash so full-path opens verify.
    fn test_blockhash() -> solana_hash::Hash {
        solana_hash::Hash::new_from_array([7; 32])
    }

    fn config(voucher_signer: VoucherSigner) -> SessionConfig {
        let operator_key = key(9);
        SessionConfig {
            operator: bs58::encode(operator_key.verifying_key().as_bytes()).into_string(),
            recipient: Pubkey::new_unique().to_string(),
            amount: 25,
            suggested_deposit: Some(1_000),
            minimum_deposit: Some(100),
            network: "mainnet".into(),
            voucher_signer,
            operator_signing_key: (voucher_signer == VoucherSigner::Operator)
                .then_some(operator_key),
            idle_timeout_options_seconds: Some(vec![60, 300]),
            idle_timeout_seconds: 300,
            ..SessionConfig::default()
        }
    }

    // A sponsor funds each channel's rent; without a deposit floor a 1-unit
    // deposit buys that rent, so a sponsored server must name the floor.
    #[test]
    fn sponsored_sessions_require_a_minimum_deposit() {
        let mut cfg = config(VoucherSigner::Client);
        cfg.fee_payer_signer = Some(shared_signer(8));
        cfg.minimum_deposit = None;
        let server = SessionServer::new(cfg.clone(), MemoryChannelStore::new());
        let challenge = server.build_challenge_request().unwrap_err().to_string();
        assert!(challenge.contains("minimum_deposit"), "{challenge}");
        let open = valid_open(&server);
        let open = server.payment_channel_open_params(&open).unwrap_err();
        assert!(open.to_string().contains("minimum_deposit"), "{open}");

        // Positive controls: a sponsored server with a floor, and an
        // unsponsored one without, both get past the check.
        cfg.minimum_deposit = Some(100);
        let server = SessionServer::new(cfg, MemoryChannelStore::new());
        let open = valid_open(&server);
        server.payment_channel_open_params(&open).unwrap();
        let mut unsponsored = config(VoucherSigner::Client);
        unsponsored.minimum_deposit = None;
        let server = SessionServer::new(unsponsored, MemoryChannelStore::new());
        let open = valid_open(&server);
        server.payment_channel_open_params(&open).unwrap();
    }

    #[test]
    fn v2_network_is_checked_for_raw_config_and_challenges_before_rpc() {
        let mut config = config(VoucherSigner::Client);
        config.channel_program =
            Some(Pubkey::from_str("CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ").unwrap());
        config.channel_version = Some(2);
        for network in ["mainnet", "", "testnet", "mainnet-beta"] {
            config.network = network.into();
            let expected = config.channel_deployment().unwrap_err().to_string();
            let server = SessionServer::new(config.clone(), MemoryChannelStore::new());
            assert_eq!(
                server.build_challenge_request().unwrap_err().to_string(),
                expected
            );
        }
        for network in ["devnet", "localnet"] {
            config.network = network.into();
            assert_eq!(config.channel_deployment().unwrap().version, 2);
        }
    }

    #[test]
    fn usdtest_mainnet_challenge_is_rejected_before_rpc() {
        let mut config = config(VoucherSigner::Client);
        config.currency = "USDtest".to_string();
        let server = SessionServer::new(config, MemoryChannelStore::new());

        let error = server.build_challenge_request().unwrap_err();
        assert!(error.to_string().contains("USDtest is devnet-only"));
    }

    fn state(channel_id: String, authorized_signer: String) -> ChannelState {
        let mut state = ChannelState {
            channel_id,
            authorized_signer,
            deposit: 1_000,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            final_cumulative: None,
            open_slot: Some(42),
            payer: Pubkey::new_unique().to_string(),
            rent_payer: Pubkey::new_unique().to_string(),
            opening_challenge_id: "opening".into(),
            authentication: None,
            voucher_signer: "client".into(),
            idle_timeout_seconds: Some(60),
            last_activity_at: 1,
            spent_amount: 0,
            settled_on_chain: 0,
            distributed_on_chain: 0,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: Default::default(),
            pending_setup: None,
            onchain_checked_at: 0,
            lifecycle: None,
            schema_version: CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        };
        state.record_onchain_observation(
            OnchainObservation {
                slot: None,
                lifecycle: ObservedLifecycle::Open,
            },
            now_unix_secs() as u64,
        );
        state
    }

    async fn client_server() -> (SessionServer<MemoryChannelStore>, ActiveSession, String) {
        let channel = Pubkey::new_unique();
        let channel_id = channel.to_string();
        let session = ActiveSession::new(channel, signer(1));
        let store = MemoryChannelStore::new();
        store
            .put_channel(&channel_id, state(channel_id.clone(), signer_address(1)))
            .await
            .unwrap();
        (
            SessionServer::new(config(VoucherSigner::Client), store),
            session,
            channel_id,
        )
    }

    fn valid_open(server: &SessionServer<MemoryChannelStore>) -> OpenPayload {
        let payer = Pubkey::new_unique();
        let payee = Pubkey::from_str(&server.config.recipient).unwrap();
        let mint = Pubkey::from_str(mints::USDC_MAINNET).unwrap();
        let authorized_signer = match server.config.voucher_signer {
            VoucherSigner::Client => signer_address(1).parse().unwrap(),
            VoucherSigner::Operator => Pubkey::from_str(&server.config.operator).unwrap(),
        };
        let rent_payer = server
            .config
            .fee_payer_signer
            .as_ref()
            .map(|signer| signer.pubkey())
            .unwrap_or(payer);
        let params = payment_channels::OpenChannelParams {
            payer,
            rent_payer,
            payee,
            mint,
            authorized_signer,
            salt: 7,
            open_slot: 42,
            deposit: 1_000,
            grace_period: server.config.grace_period_seconds,
            recipients: vec![],
            token_program: Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap(),
            program_id: payment_channels::default_program_id(),
        };
        OpenPayload::payment_channel(
            payment_channels::derive_channel_addresses(&params)
                .channel
                .to_string(),
            "1000".into(),
            payer.to_string(),
            payee.to_string(),
            mint.to_string(),
            7,
            server.config.grace_period_seconds,
            42,
            authorized_signer.to_string(),
            "transaction".into(),
        )
    }

    #[cfg(feature = "server")]
    async fn rpc_for_channel(
        channel: payment_channels::generated::generated::accounts::Channel,
        current_slot: u64,
    ) -> (
        String,
        tokio::task::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        rpc_for_channel_with_options(channel, current_slot, LandedStatus::Finalized).await
    }

    /// Like [`rpc_for_channel`], but `landed_with_error` makes
    /// `getSignatureStatuses` report every landed signature as failed
    /// on-chain (`confirm`'s fast, non-timeout failure path), simulating a
    /// submission whose execution genuinely fails — as opposed to one whose
    /// response is merely lost. Account reads
    /// (`getAccountInfo`/`getMultipleAccounts`) still return the fixed
    /// `channel` state regardless, matching a real cluster where the account
    /// reflects whatever *other* transaction landed.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum LandedStatus {
        Finalized,
        Failed,
        /// Fails simulation (e.g. the payer cannot fund it) and would fail
        /// on-chain if sent.
        Unexecutable,
        /// Confirmed but never finalized (e.g. on a fork that is abandoned).
        ConfirmedOnly,
    }

    async fn rpc_for_channel_with_options(
        channel: payment_channels::generated::generated::accounts::Channel,
        current_slot: u64,
        landed_status: LandedStatus,
    ) -> (
        String,
        tokio::task::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        rpc_for_landed_channel(channel, current_slot, landed_status, []).await
    }

    /// Like [`rpc_for_channel_with_options`], with `prelanded` signatures
    /// already landed at their slots (a cluster that saw an earlier broadcast).
    async fn rpc_for_landed_channel<const N: usize>(
        channel: payment_channels::generated::generated::accounts::Channel,
        current_slot: u64,
        landed_status: LandedStatus,
        prelanded: [(String, u64); N],
    ) -> (
        String,
        tokio::task::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use base64::Engine;
        use serde_json::{json, Value};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let account_data = borsh::to_vec(&channel).unwrap();
        // The cluster advances past every landing, so a transaction always
        // lands after the slot getSlot reported before its broadcast.
        let slot = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(current_slot));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        // Mainnet-faithful duplicate handling: a signature lands exactly once,
        // so a repeated `sendTransaction` is rejected at preflight the way a
        // real RPC rejects it, and `getSignatureStatuses` reports only
        // signatures that actually landed.
        let landed: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>> =
            std::sync::Arc::new(std::sync::Mutex::new(prelanded.into_iter().collect()));
        let send_tx_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let send_tx_count_srv = std::sync::Arc::clone(&send_tx_count);
        let handle = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let account_data = account_data.clone();
                let landed = std::sync::Arc::clone(&landed);
                let slot = std::sync::Arc::clone(&slot);
                let send_tx_count = std::sync::Arc::clone(&send_tx_count_srv);
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let body_start = loop {
                        let mut chunk = [0_u8; 4096];
                        let read = stream.read(&mut chunk).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&chunk[..read]);
                        if let Some(index) =
                            bytes.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            break index + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&bytes[..body_start]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::trim)
                                .and_then(|value| value.parse::<usize>().ok())
                        })
                        .unwrap();
                    while bytes.len() < body_start + content_length {
                        let mut chunk = [0_u8; 4096];
                        let read = stream.read(&mut chunk).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&chunk[..read]);
                    }
                    let request: Value =
                        serde_json::from_slice(&bytes[body_start..body_start + content_length])
                            .unwrap();
                    let result = match request["method"].as_str().unwrap_or_default() {
                        "isBlockhashValid" => {
                            assert_eq!(request["params"][1]["commitment"], "finalized");
                            Ok(json!({"context": {"slot": 42}, "value": true}))
                        }
                        "getSlot" => Ok(json!(slot.load(std::sync::atomic::Ordering::SeqCst))),
                        "simulateTransaction" => {
                            assert_eq!(request["params"][1]["commitment"], "confirmed");
                            assert_eq!(request["params"][1]["replaceRecentBlockhash"], false);
                            let signature = payment_channels::decode_transaction(
                                request["params"][0].as_str().unwrap(),
                            )
                            .unwrap()
                            .signatures[0]
                                .to_string();
                            let err = if landed.lock().unwrap().contains_key(&signature) {
                                json!("AlreadyProcessed")
                            } else if landed_status == LandedStatus::Unexecutable {
                                json!({"InstructionError": [1, {"Custom": 1}]})
                            } else {
                                Value::Null
                            };
                            Ok(json!({
                                "context": { "slot": slot.load(std::sync::atomic::Ordering::SeqCst) },
                                "value": { "err": err, "logs": [], "accounts": null, "unitsConsumed": 0 }
                            }))
                        }
                        "sendTransaction" => {
                            send_tx_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let signature = payment_channels::decode_transaction(
                                request["params"][0].as_str().unwrap(),
                            )
                            .unwrap()
                            .signatures[0]
                                .to_string();
                            let mut landed = landed.lock().unwrap();
                            if landed.contains_key(&signature) {
                                Err(json!({
                                    "code": -32002,
                                    "message": "Transaction simulation failed: This transaction has already been processed",
                                    "data": {
                                        "accounts": null,
                                        "err": "AlreadyProcessed",
                                        "logs": [],
                                        "unitsConsumed": 0
                                    }
                                }))
                            } else {
                                let at = slot.fetch_add(2, std::sync::atomic::Ordering::SeqCst) + 1;
                                landed.insert(signature.clone(), at);
                                Ok(json!(signature))
                            }
                        }
                        "getSignatureStatuses" => {
                            let statuses = request["params"][0]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|signature| {
                                    if let Some(landed_slot) = landed
                                        .lock()
                                        .unwrap()
                                        .get(signature.as_str().unwrap())
                                        .copied()
                                    {
                                        if matches!(
                                            landed_status,
                                            LandedStatus::Failed | LandedStatus::Unexecutable
                                        ) {
                                            // A signature the RPC saw land, but
                                            // whose execution failed on-chain
                                            // (e.g. insufficient fee-payer
                                            // funds) — the confirmation
                                            // tracker's fast (non-timeout)
                                            // failure path.
                                            json!({
                                                "slot": landed_slot,
                                                "confirmations": null,
                                                "err": "AlreadyProcessed",
                                                "confirmationStatus": "finalized",
                                                "status": { "Err": "AlreadyProcessed" }
                                            })
                                        } else if landed_status == LandedStatus::ConfirmedOnly {
                                            json!({
                                                "slot": landed_slot,
                                                "confirmations": 1,
                                                "err": null,
                                                "confirmationStatus": "confirmed",
                                                "status": { "Ok": null }
                                            })
                                        } else {
                                            json!({
                                                "slot": landed_slot,
                                                "confirmations": null,
                                                "err": null,
                                                "confirmationStatus": "finalized",
                                                "status": { "Ok": null }
                                            })
                                        }
                                    } else {
                                        Value::Null
                                    }
                                })
                                .collect::<Vec<_>>();
                            Ok(json!({
                                "context": { "slot": slot.load(std::sync::atomic::Ordering::SeqCst) },
                                "value": statuses
                            }))
                        }
                        "getAccountInfo" => Ok(json!({
                            "context": { "slot": slot.load(std::sync::atomic::Ordering::SeqCst) },
                            "value": {
                                "data": [
                                    base64::engine::general_purpose::STANDARD.encode(account_data),
                                    "base64"
                                ],
                                "executable": false,
                                "lamports": 1,
                                "owner": payment_channels::PAYMENT_CHANNELS_PROGRAM_ID,
                                "rentEpoch": 0,
                                "space": 256
                            }
                        })),
                        "getMultipleAccounts" => {
                            let account = json!({
                                "data": [
                                    base64::engine::general_purpose::STANDARD.encode(account_data),
                                    "base64"
                                ],
                                "executable": false,
                                "lamports": 1,
                                "owner": payment_channels::PAYMENT_CHANNELS_PROGRAM_ID,
                                "rentEpoch": 0,
                                "space": 256
                            });
                            let values = request["params"][0]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|_| account.clone())
                                .collect::<Vec<_>>();
                            Ok(json!({
                                "context": { "slot": slot.load(std::sync::atomic::Ordering::SeqCst) },
                                "value": values
                            }))
                        }
                        method => panic!("unexpected RPC method {method}"),
                    };
                    let body = serde_json::to_vec(&match result {
                        Ok(result) => json!({
                            "jsonrpc": "2.0",
                            "id": request["id"].clone(),
                            "result": result
                        }),
                        Err(error) => json!({
                            "jsonrpc": "2.0",
                            "id": request["id"].clone(),
                            "error": error
                        }),
                    })
                    .unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                });
            }
        });
        (url, handle, send_tx_count)
    }

    #[cfg(feature = "server")]
    async fn signed_open(
        server: &SessionServer<MemoryChannelStore>,
        payer_seed: u8,
    ) -> (OpenPayload, payment_channels::OpenChannelParams) {
        let payer = signer(payer_seed);
        let payee = Pubkey::from_str(&server.config.recipient).unwrap();
        let mint = Pubkey::from_str(mints::USDC_MAINNET).unwrap();
        let authorized_signer = match server.config.voucher_signer {
            VoucherSigner::Client => signer_address(1).parse().unwrap(),
            VoucherSigner::Operator => server.config.operator.parse().unwrap(),
        };
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
        let program_id = payment_channels::default_program_id();
        let fee_payer = server
            .config
            .fee_payer_signer
            .as_ref()
            .map(|signer| signer.pubkey())
            .unwrap_or_else(|| payer.pubkey());
        let params = payment_channels::OpenChannelParams {
            payer: payer.pubkey(),
            rent_payer: fee_payer,
            payee,
            mint,
            authorized_signer,
            salt: 7,
            open_slot: 42,
            deposit: 1_000,
            grace_period: server.config.grace_period_seconds,
            recipients: vec![],
            token_program,
            program_id,
        };
        let tx = payment_channels::build_open_payment_channel_tx(
            payer.as_ref(),
            &payee,
            &mint,
            &authorized_signer,
            7,
            42,
            1_000,
            server.config.grace_period_seconds,
            vec![],
            &token_program,
            &program_id,
            &fee_payer,
            test_blockhash(),
        )
        .await
        .unwrap();
        (
            OpenPayload::payment_channel(
                tx.channel_id.to_string(),
                "1000".into(),
                payer.pubkey().to_string(),
                payee.to_string(),
                mint.to_string(),
                7,
                server.config.grace_period_seconds,
                42,
                authorized_signer.to_string(),
                tx.transaction,
            ),
            params,
        )
    }

    #[test]
    fn challenge_and_open_params_use_the_exact_contract() {
        let split = Split {
            recipient: Pubkey::new_unique(),
            bps: 250,
        };
        let mut cfg = config(VoucherSigner::Client);
        cfg.splits.push(split.clone());
        cfg.min_voucher_delta = 5;
        let cache = crate::core::blockhash::BlockhashCache::new();
        cache.set(test_blockhash().to_string(), 314, CHALLENGED_SLOT);
        let server = SessionServer::new(cfg, MemoryChannelStore::new()).with_blockhash_cache(cache);
        let request = server.build_challenge_request().unwrap();
        assert_eq!(request.amount, "25");
        assert_eq!(request.currency, mints::USDC_MAINNET);
        assert_eq!(request.method_details.decimals, Some(6));
        assert_eq!(request.minimum_deposit.as_deref(), Some("100"));
        assert_eq!(request.method_details.channel_id, None);
        // Both open-transaction context fields come from the one cached
        // `getLatestBlockhash` entry — never from a per-challenge RPC call.
        let challenged_blockhash = test_blockhash().to_string();
        assert_eq!(
            request.method_details.recent_blockhash.as_deref(),
            Some(challenged_blockhash.as_str())
        );
        assert_eq!(request.method_details.recent_slot, Some(CHALLENGED_SLOT));
        assert_eq!(
            request.method_details.min_voucher_delta.as_deref(),
            Some("5")
        );
        assert_eq!(request.method_details.distribution_splits[0].share_bps, 250);

        let mut open = valid_open(&server);
        open.distribution_splits = vec![SessionSplit {
            recipient: split.recipient.to_string(),
            share_bps: split.bps,
        }];
        let params = server.payment_channel_open_params(&open).unwrap();
        assert_eq!(params.deposit, 1_000);
        assert_eq!(params.open_slot, 42);
        assert_eq!(
            server
                .payment_channel_open_instruction(&open)
                .unwrap()
                .program_id,
            params.program_id
        );

        let mut invalid = open.clone();
        invalid.payee = Pubkey::new_unique().to_string();
        assert!(server.payment_channel_open_params(&invalid).is_err());
        invalid = open.clone();
        invalid.mint = Pubkey::new_unique().to_string();
        assert!(server.payment_channel_open_params(&invalid).is_err());
        invalid = open.clone();
        invalid.grace_period_seconds += 1;
        assert!(server.payment_channel_open_params(&invalid).is_err());
        invalid = open.clone();
        invalid.deposit_amount = "1".into();
        assert!(server.payment_channel_open_params(&invalid).is_err());
        invalid = open.clone();
        invalid.channel_id = Pubkey::new_unique().to_string();
        assert!(server.payment_channel_open_params(&invalid).is_err());
        invalid = open.clone();
        invalid.authorized_signer = open.channel_id.clone();
        let err = server.payment_channel_open_params(&invalid).unwrap_err();
        assert!(err.to_string().contains("on-curve"));
        invalid = open;
        invalid.distribution_splits.clear();
        assert!(server.payment_channel_open_params(&invalid).is_err());
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn sponsored_open_rejects_explicit_budgets_above_policy() {
        use crate::core::tx::{ComputeBudget, TxVersion};
        use crate::mpp::client::session::{
            build_open_payment_channel_transaction, BuildOpenPaymentChannelTransactionParams,
            PaymentChannelOpenOptions,
        };

        let mut cfg = config(VoucherSigner::Client);
        cfg.fee_payer_signer = Some(shared_signer(8));
        let cache = crate::core::blockhash::BlockhashCache::new();
        cache.set(test_blockhash().to_string(), 314, CHALLENGED_SLOT);
        let server = SessionServer::new(cfg, MemoryChannelStore::new()).with_blockhash_cache(cache);
        let payer = signer(6);
        for version in [TxVersion::V0, TxVersion::V1] {
            for budget in [
                ComputeBudget::new(600_000, 0),
                ComputeBudget::new(200_000, 10_001),
            ] {
                let mut request = server.build_challenge_request().unwrap();
                request.method_details.transaction_versions = Some(vec![version]);
                let (mut open, params) = signed_open(&server, 6).await;
                open.transaction = build_open_payment_channel_transaction(
                    BuildOpenPaymentChannelTransactionParams {
                        request: &request,
                        signer: payer.as_ref(),
                        authorized_signer: params.authorized_signer,
                        fee_payer: None,
                        recent_blockhash: None,
                        options: PaymentChannelOpenOptions {
                            compute_budget: Some(budget),
                            salt: Some(params.salt),
                            ..Default::default()
                        },
                    },
                )
                .await
                .unwrap()
                .transaction;
                let error = prepare_open_transaction(
                    &open,
                    &params,
                    &test_blockhash().to_string(),
                    server.config.fee_payer_signer.as_deref(),
                    &[version],
                    &server.config,
                )
                .await
                .unwrap_err()
                .to_string();
                assert!(error.contains("exceeds maximum"), "{error}");
            }
        }
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn sponsored_open_advertises_cosigns_and_persists_rent_payer() {
        use payment_channels::generated::generated::types::SettlementWatermarks;

        let sponsor = shared_signer(8);
        let mut cfg = config(VoucherSigner::Client);
        cfg.fee_payer_signer = Some(std::sync::Arc::clone(&sponsor));
        let cache = crate::core::blockhash::BlockhashCache::new();
        cache.set(test_blockhash().to_string(), 314, CHALLENGED_SLOT);
        let mut server =
            SessionServer::new(cfg, MemoryChannelStore::new()).with_blockhash_cache(cache);
        let request = server.build_challenge_request().unwrap();
        let sponsor_key = sponsor.pubkey().to_string();
        assert_eq!(request.method_details.fee_payer, Some(true));
        assert_eq!(
            request.method_details.fee_payer_key.as_deref(),
            Some(sponsor_key.as_str())
        );

        let (open, params) = signed_open(&server, 6).await;
        assert_eq!(params.rent_payer, sponsor.pubkey());
        let submitted = payment_channels::decode_transaction(&open.transaction).unwrap();
        assert_eq!(submitted.signatures[0], Signature::default());
        verify_client_transaction_signatures(&submitted, Some(sponsor.pubkey())).unwrap();

        let channel = payment_channels::generated::generated::accounts::Channel {
            discriminator: 1,
            version: 1,
            bump: 1,
            status: 0,
            salt: params.salt,
            deposit: params.deposit,
            settlement: SettlementWatermarks {
                settled: 0,
                payout_watermark: 0,
            },
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: params.grace_period,
            distribution_hash: payment_channels::distribution_hash(&params.recipients),
            payer: payment_channels::to_address(&params.payer),
            payee: payment_channels::to_address(&params.payee),
            authorized_signer: payment_channels::to_address(&params.authorized_signer),
            mint: payment_channels::to_address(&params.mint),
            rent_payer: payment_channels::to_address(&params.rent_payer),
            open_slot: params.open_slot,
        };
        let (url, rpc, _send_tx_count) = rpc_for_channel(channel, 43).await;
        server.config.rpc_url = Some(url);
        let challenged_blockhash = test_blockhash().to_string();
        let acceptance = server
            .process_open_with_outcome(
                &open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: &challenged_blockhash,
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .unwrap();
        assert_ne!(
            acceptance.transaction_signature,
            Signature::default().to_string()
        );
        assert_eq!(acceptance.state.rent_payer, sponsor.pubkey().to_string());

        let mut tampered = submitted;
        tampered.signatures[1] = Signature::default();
        let mut invalid_open = open;
        invalid_open.transaction = crate::core::tx::encode(&tampered).unwrap();
        let error = server
            .process_open(
                &invalid_open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: &challenged_blockhash,
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("invalid client transaction signature"));
        rpc.abort();
    }

    // The sponsor pays the fee of a sponsored open even when it fails
    // on-chain (an empty payer token account), so one that fails simulation
    // never reaches the network.
    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn sponsored_open_that_fails_simulation_is_never_broadcast() {
        use payment_channels::generated::generated::types::SettlementWatermarks;

        for (status, lands) in [
            (LandedStatus::Unexecutable, false),
            (LandedStatus::Finalized, true),
        ] {
            let sponsor = shared_signer(8);
            let mut cfg = config(VoucherSigner::Client);
            cfg.fee_payer_signer = Some(std::sync::Arc::clone(&sponsor));
            let mut server = SessionServer::new(cfg, MemoryChannelStore::new());
            let (open, params) = signed_open(&server, 6).await;
            let channel = payment_channels::generated::generated::accounts::Channel {
                discriminator: 1,
                version: 1,
                bump: 1,
                status: 0,
                salt: params.salt,
                deposit: params.deposit,
                settlement: SettlementWatermarks {
                    settled: 0,
                    payout_watermark: 0,
                },
                closure_started_at: 0,
                payer_withdrawn_at: 0,
                grace_period: params.grace_period,
                distribution_hash: payment_channels::distribution_hash(&params.recipients),
                payer: payment_channels::to_address(&params.payer),
                payee: payment_channels::to_address(&params.payee),
                authorized_signer: payment_channels::to_address(&params.authorized_signer),
                mint: payment_channels::to_address(&params.mint),
                rent_payer: payment_channels::to_address(&params.rent_payer),
                open_slot: params.open_slot,
            };
            let (url, rpc, sends) = rpc_for_channel_with_options(channel, 43, status).await;
            server.config.rpc_url = Some(url);
            let blockhash = test_blockhash().to_string();
            let result = server
                .process_open(
                    &open,
                    SessionOpenContext {
                        challenge_id: "opening",
                        expires: None,
                        recent_blockhash: &blockhash,
                        recent_slot: CHALLENGED_SLOT,
                    },
                )
                .await;
            if lands {
                result.unwrap();
            } else {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("failed simulation"), "{error}");
            }
            assert_eq!(
                sends.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(lands)
            );
            rpc.abort();
        }
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn sponsored_open_rejects_payer_aliasing_the_fee_payer() {
        let sponsor = shared_signer(8);
        let mut cfg = config(VoucherSigner::Client);
        cfg.fee_payer_signer = Some(std::sync::Arc::clone(&sponsor));
        let server = SessionServer::new(cfg, MemoryChannelStore::new());

        // Seed 8 is the sponsor: the open would draw the deposit from the
        // sponsor's token account under the sponsor's co-signature alone.
        let (aliased, _) = signed_open(&server, 8).await;
        assert_eq!(aliased.payer, sponsor.pubkey().to_string());
        let error = server.payment_channel_open_params(&aliased).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must differ from the sponsored fee payer"),
            "{error}"
        );
        assert!(server.payment_channel_open_instruction(&aliased).is_err());

        let (distinct, _) = signed_open(&server, 6).await;
        let params = server.payment_channel_open_params(&distinct).unwrap();
        assert_eq!(params.rent_payer, sponsor.pubkey());
        assert_ne!(params.payer, params.rent_payer);
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn sponsored_topup_rejects_stored_payer_aliasing_the_fee_payer() {
        let (mut server, _session, channel_id) = client_server().await;
        let sponsor = shared_signer(8);
        server.config.fee_payer_signer = Some(std::sync::Arc::clone(&sponsor));
        server.config.rpc_url = Some("http://127.0.0.1:1".into());
        let sponsor_key = sponsor.pubkey().to_string();
        server
            .store
            .update_channel(
                &channel_id,
                Box::new(move |state| {
                    let mut state = state.unwrap();
                    state.payer = sponsor_key.clone();
                    state.rent_payer = sponsor_key;
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let payload = TopUpPayload {
            channel_id: channel_id.clone(),
            additional_amount: "100".into(),
            transaction: String::new(),
        };
        let error = server
            .process_topup_with_outcome(&payload)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must differ from the sponsored fee payer"),
            "{error}"
        );

        // Positive control: a distinct stored payer passes the role check and
        // fails later, on the (empty) transaction itself.
        let payer = signer(5).pubkey().to_string();
        server
            .store
            .update_channel(
                &channel_id,
                Box::new(move |state| {
                    let mut state = state.unwrap();
                    state.payer = payer;
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let error = server
            .process_topup_with_outcome(&payload)
            .await
            .unwrap_err();
        assert!(
            !error.to_string().contains("sponsored fee payer"),
            "{error}"
        );
    }

    /// Re-sign `open` as a sponsored V0 transaction carrying `instructions`.
    #[cfg(feature = "server")]
    async fn sponsored_open_with(
        mut open: OpenPayload,
        params: &payment_channels::OpenChannelParams,
        instructions: &[solana_instruction::Instruction],
    ) -> OpenPayload {
        use solana_message::{v0, VersionedMessage};
        let message =
            v0::Message::try_compile(&params.rent_payer, instructions, &[], test_blockhash())
                .unwrap();
        let mut tx = solana_transaction::versioned::VersionedTransaction {
            signatures: vec![
                Signature::default();
                usize::from(message.header.num_required_signatures)
            ],
            message: VersionedMessage::V0(message),
        };
        crate::core::signing::sign_versioned_transaction_slot(signer(6).as_ref(), &mut tx)
            .await
            .unwrap();
        open.transaction = crate::core::tx::encode(&tx).unwrap();
        open
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn sponsored_open_requires_a_canonical_compute_budget_prefix() {
        use crate::core::tx::{unit_limit_instruction, unit_price_instruction};
        let mut cfg = config(VoucherSigner::Client);
        cfg.fee_payer_signer = Some(shared_signer(8));
        let server = SessionServer::new(cfg, MemoryChannelStore::new());
        let (open, params) = signed_open(&server, 6).await;
        let ix = payment_channels::build_open_instruction(&params);
        let prepare = |open: OpenPayload| {
            let server = &server;
            let params = &params;
            async move {
                prepare_open_transaction(
                    &open,
                    params,
                    &test_blockhash().to_string(),
                    server.config.fee_payer_signer.as_deref(),
                    &server.accepted_versions,
                    &server.config,
                )
                .await
            }
        };

        let canonical = sponsored_open_with(
            open.clone(),
            &params,
            &[
                unit_limit_instruction(200_000),
                unit_price_instruction(10),
                ix.clone(),
            ],
        )
        .await;
        assert!(prepare(canonical).await.is_ok());

        for (layout, expected) in [
            (
                vec![
                    unit_limit_instruction(100_000),
                    unit_limit_instruction(200_000),
                    ix.clone(),
                ],
                "duplicate",
            ),
            (vec![ix.clone(), unit_price_instruction(10)], "lead"),
            (
                vec![
                    unit_price_instruction(10),
                    unit_limit_instruction(200_000),
                    ix.clone(),
                ],
                "precede",
            ),
        ] {
            let malformed = sponsored_open_with(open.clone(), &params, &layout).await;
            let error = prepare(malformed).await.unwrap_err().to_string();
            assert!(error.contains(expected), "{expected}: {error}");
        }
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn sponsored_v1_open_rejects_client_elevated_signer_privileges() {
        use crate::core::signing::sign_versioned_transaction_slot;
        use solana_message::{v0, VersionedMessage};
        use solana_transaction::versioned::VersionedTransaction;

        let sponsor = shared_signer(8);
        let mut cfg = config(VoucherSigner::Client);
        cfg.fee_payer_signer = Some(std::sync::Arc::clone(&sponsor));
        let server = SessionServer::new(cfg, MemoryChannelStore::new());
        let (canonical, params) = signed_open(&server, 6).await;
        let challenged = test_blockhash().to_string();

        // The canonical sponsored open is accepted and co-signed.
        let accepted = prepare_open_transaction(
            &canonical,
            &params,
            &challenged,
            server.config.fee_payer_signer.as_deref(),
            &server.accepted_versions,
            &server.config,
        )
        .await
        .unwrap();
        assert_eq!(accepted.0.message.header().num_required_signatures, 2);

        // Same program, data and account keys, but the client-controlled
        // authorized signer is promoted to an extra (sponsor-paid) signer.
        let mut elevated = payment_channels::build_open_instruction(&params);
        let meta = elevated
            .accounts
            .iter_mut()
            .find(|meta| meta.pubkey == params.authorized_signer)
            .unwrap();
        assert!(!meta.is_signer);
        meta.is_signer = true;
        let message =
            v0::Message::try_compile(&params.rent_payer, &[elevated], &[], test_blockhash())
                .unwrap();
        let mut tx = VersionedTransaction {
            signatures: vec![
                Signature::default();
                usize::from(message.header.num_required_signatures)
            ],
            message: VersionedMessage::V0(message),
        };
        sign_versioned_transaction_slot(signer(6).as_ref(), &mut tx)
            .await
            .unwrap();
        sign_versioned_transaction_slot(signer(1).as_ref(), &mut tx)
            .await
            .unwrap();
        assert_eq!(tx.message.header().num_required_signatures, 3);
        let mut malicious = canonical;
        malicious.transaction = crate::core::tx::encode(&tx).unwrap();
        let error = prepare_open_transaction(
            &malicious,
            &params,
            &challenged,
            server.config.fee_payer_signer.as_deref(),
            &server.accepted_versions,
            &server.config,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("privileges"), "{error}");
    }

    #[test]
    fn challenge_fails_without_open_transaction_context() {
        // A new-channel challenge REQUIRES recentBlockhash/recentSlot, so a
        // server with neither a blockhash cache nor an rpc_url must fail the
        // challenge (retryable) instead of degrading to a hint-less 402 the
        // client cannot open against.
        let server = SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new());
        let err = server.build_challenge_request().unwrap_err();
        assert!(err.to_string().contains("recentBlockhash"));
    }

    #[test]
    fn challenge_rejects_native_sol_and_out_of_range_decimals() {
        let cache = crate::core::blockhash::BlockhashCache::new();
        cache.set(test_blockhash().to_string(), 314, CHALLENGED_SLOT);

        let mut native = config(VoucherSigner::Client);
        native.currency = "SOL".to_string();
        let server = SessionServer::new(native, MemoryChannelStore::new())
            .with_blockhash_cache(cache.clone());
        assert!(server
            .build_challenge_request()
            .unwrap_err()
            .to_string()
            .contains("SPL token"));

        let mut invalid_decimals = config(VoucherSigner::Client);
        invalid_decimals.decimals = 10;
        let server = SessionServer::new(invalid_decimals, MemoryChannelStore::new())
            .with_blockhash_cache(cache);
        assert!(server
            .build_challenge_request()
            .unwrap_err()
            .to_string()
            .contains("between 0 and 9"));
    }

    #[test]
    fn session_receipt_uses_channel_accounting_and_idle_timeout() {
        let server = SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new());
        let mut channel = state("channel-1".to_string(), signer_address(1));
        channel.cumulative = 125;
        channel.spent_amount = 100;
        channel.idle_timeout_seconds = Some(300);

        let receipt = server
            .close_receipt(
                &channel,
                "challenge-1",
                Some("settlement-signature".to_string()),
                Some(25),
            )
            .unwrap();
        assert_eq!(receipt.base().reference, "channel-1");
        let extensions = receipt.session_extensions().unwrap();
        assert_eq!(extensions.intent, SessionReceiptIntent::Session);
        assert_eq!(extensions.accepted_cumulative, 125);
        assert_eq!(extensions.spent, 100);
        assert_eq!(extensions.idle_timeout_seconds, 300);
        assert_eq!(extensions.tx_hash.as_deref(), Some("settlement-signature"));
        assert_eq!(extensions.refunded, Some(25));
    }

    #[tokio::test]
    async fn open_enforces_expiry_authentication_and_rpc_verification() {
        let client = SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new());
        let open = valid_open(&client);
        let expired = client
            .process_open(
                &open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: Some("2000-01-01T00:00:00Z"),
                    recent_blockhash: "hash",
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .unwrap_err();
        assert!(expired.to_string().contains("expired"));
        let missing_rpc = client
            .process_open(
                &open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: "hash",
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .unwrap_err();
        assert!(missing_rpc.to_string().contains("RPC client"));

        // The open is bound to the challenged `recentSlot`: an `openSlot`
        // ahead of it, or stale beyond OPEN_SLOT_WINDOW, was not built
        // against this challenge.
        let ahead = client
            .process_open(
                &open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: "hash",
                    recent_slot: 41,
                },
            )
            .await
            .unwrap_err();
        assert!(ahead
            .to_string()
            .contains("ahead of the challenged recentSlot"));
        let stale = client
            .process_open(
                &open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: "hash",
                    recent_slot: 42 + payment_channels::OPEN_SLOT_WINDOW + 1,
                },
            )
            .await
            .unwrap_err();
        assert!(stale.to_string().contains("freshness window"));

        let operator =
            SessionServer::new(config(VoucherSigner::Operator), MemoryChannelStore::new());
        let mut operated = valid_open(&operator);
        let payer_key = key(2);
        operated.payer = signer_address(2);
        operated.authentication =
            Some(SessionAuthentication::sign("wrong", &operated.channel_id, &payer_key).unwrap());
        assert!(operator
            .process_open(
                &operated,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: "hash",
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .is_err());
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn bound_pending_open_recovers_without_client_or_current_policy() {
        use payment_channels::generated::generated::types::SettlementWatermarks;
        use serde_json::json;

        let policy = json!({"deployment": "a", "version": 1});
        let cfg = config(VoucherSigner::Client);
        let mut server = SessionServer::new(cfg.clone(), MemoryChannelStore::new())
            .with_channel_binding(policy.clone());
        let (open, params) = signed_open(&server, 4).await;
        let channel = payment_channels::generated::generated::accounts::Channel {
            discriminator: 1,
            version: 1,
            bump: 1,
            status: 0,
            salt: params.salt,
            deposit: params.deposit,
            settlement: SettlementWatermarks {
                settled: 0,
                payout_watermark: 0,
            },
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: params.grace_period,
            distribution_hash: payment_channels::distribution_hash(&params.recipients),
            payer: payment_channels::to_address(&params.payer),
            payee: payment_channels::to_address(&params.payee),
            authorized_signer: payment_channels::to_address(&params.authorized_signer),
            mint: payment_channels::to_address(&params.mint),
            rent_payer: payment_channels::to_address(&params.rent_payer),
            open_slot: params.open_slot,
        };
        // Funding confirms, but the account read-back fails to match. This is
        // the same durable boundary as losing the process before activation.
        let mut bad_readback = channel.clone();
        bad_readback.deposit += 1;
        let (url, rpc, sends) = rpc_for_channel(bad_readback, params.open_slot).await;
        server.config.rpc_url = Some(url);
        let blockhash = test_blockhash().to_string();
        let context = SessionOpenContext {
            challenge_id: "opening",
            expires: None,
            recent_blockhash: &blockhash,
            recent_slot: CHALLENGED_SLOT,
        };
        let mut malformed = open.clone();
        malformed.transaction = "invalid".into();
        assert!(server.process_open(&malformed, context).await.is_err());
        assert!(server
            .store
            .inner
            .get_channel(&open.channel_id)
            .await
            .unwrap()
            .is_none());
        assert!(server.process_open(&open, context).await.is_err());
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
        let pending = server
            .store
            .inner
            .get_channel(&open.channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.deposit, 0);
        assert!(pending.pending_setup.is_some());
        assert_eq!(pending.extra[OPEN_INTENT_KEY]["version"], 2);
        assert_eq!(pending.extra[OPEN_INTENT_KEY]["finalized_valid_at"], 42);
        assert!(pending.extra[OPEN_INTENT_KEY]["transaction_signature"].is_string());
        assert!(server.require_channel_binding(&pending).is_err());
        assert!(server.seal_params(&open.channel_id).await.is_err());
        rpc.abort();

        // Round-trip the durable row into a fresh store/server, after today's
        // deployment has changed and the original slot window has expired.
        let recovered: ChannelState =
            serde_json::from_str(&serde_json::to_string(&pending).unwrap()).unwrap();
        let store = MemoryChannelStore::new();
        store
            .put_channel(&open.channel_id, recovered.clone())
            .await
            .unwrap();
        let snapshot = SessionConfigSnapshot::from_channel(&recovered)
            .unwrap()
            .unwrap();
        let mut changed = cfg.clone();
        changed.recipient = Pubkey::new_unique().to_string();
        changed.amount += 100;
        snapshot.apply_to(&mut changed).unwrap();
        assert_eq!(changed.recipient, cfg.recipient);
        assert_eq!(changed.amount, cfg.amount);
        // The cluster still reports the original broadcast's landing.
        let signature = pending.extra[OPEN_INTENT_KEY]["transaction_signature"]
            .as_str()
            .unwrap()
            .to_string();
        let (url, rpc, sends) = rpc_for_landed_channel(
            channel,
            params.open_slot + 10_000,
            LandedStatus::Finalized,
            [(signature, params.open_slot + 1)],
        )
        .await;
        changed.rpc_url = Some(url);
        let mut restarted = SessionServer::new(changed, store)
            .with_channel_binding(json!({"deployment": "b", "version": 1}));
        assert!(restarted
            .resume_pending_open(&open.channel_id)
            .await
            .is_err());
        restarted = restarted.with_channel_binding(policy.clone());
        let accepted = restarted
            .resume_pending_open(&open.channel_id)
            .await
            .unwrap();
        assert_eq!(accepted.state.deposit, params.deposit);
        assert!(accepted.state.pending_setup.is_none());
        assert_eq!(channel_binding(&accepted.state).unwrap(), Some(policy));
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(restarted.resume_pending_open("unknown").await.is_err());
        // A retry is a no-op and cannot reset the accounting watermark.
        restarted
            .store
            .update_channel(
                &open.channel_id,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.cumulative = 100;
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let replay = restarted
            .process_open_with_outcome(&open, context)
            .await
            .unwrap();
        assert!(replay.replay);
        assert_eq!(replay.state.cumulative, 100);
        rpc.abort();
    }

    #[cfg(feature = "server")]
    async fn pending_before_broadcast(
        server: &SessionServer<MemoryChannelStore>,
        open: &OpenPayload,
    ) -> ChannelState {
        let params = server.payment_channel_open_params(open).unwrap();
        let blockhash = test_blockhash().to_string();
        let prepared = prepare_open_transaction(
            open,
            &params,
            &blockhash,
            server.config.fee_payer_signer.as_deref(),
            &server.accepted_versions,
            &server.config,
        )
        .await
        .unwrap();
        let mut pending = state(
            open.session_id().to_string(),
            open.authorized_signer.clone(),
        );
        pending.deposit = 0;
        pending.payer = open.payer.clone();
        pending.rent_payer = params.rent_payer.to_string();
        pending.open_slot = Some(open.open_slot);
        pending.opening_challenge_id = "opening".into();
        pending.pending_setup = Some(crate::mpp::store::PendingSetup {
            payer_signature: prepared.1,
            deposit: params.deposit,
            opens_channel: true,
            expires_at: i64::MAX,
        });
        pending.extra.insert(
            OPEN_INTENT_KEY.into(),
            serde_json::to_value(OpenIntent {
                version: 2,
                payload: open.clone(),
                challenge_id: "opening".into(),
                recent_blockhash: blockhash,
                recent_slot: CHALLENGED_SLOT,
                finalized_valid_at: Some(42),
                transaction_signature: Some(prepared.0.signatures[0].to_string()),
                adoption_floor: AdoptionFloor::Slot(CHALLENGED_SLOT),
            })
            .unwrap(),
        );
        server
            .store
            .binding
            .as_ref()
            .unwrap()
            .insert(&mut pending)
            .unwrap();
        pending
    }

    #[cfg(feature = "server")]
    async fn expiry_rpc(
        valid: bool,
        account: serde_json::Value,
        status: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        expiry_rpc_with_delayed_read(valid, account, status, None).await
    }

    #[cfg(feature = "server")]
    async fn expiry_rpc_with_delayed_read(
        valid: bool,
        account: serde_json::Value,
        status: serde_json::Value,
        delayed_read: Option<(
            serde_json::Value,
            std::sync::Arc<tokio::sync::Notify>,
            std::sync::Arc<tokio::sync::Notify>,
        )>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{routing::post, Json, Router};
        use serde_json::json;
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<serde_json::Value>| {
                let account = account.clone();
                let status = status.clone();
                let delayed_read = delayed_read.clone();
                async move {
                    let result = match request["method"].as_str().unwrap() {
                        "getMultipleAccounts" if delayed_read.is_some() => {
                            let (account, entered, release) = delayed_read.unwrap();
                            entered.notify_one();
                            release.notified().await;
                            json!({"context":{"slot":43}, "value":[account]})
                        }
                        "isBlockhashValid" => {
                            assert_eq!(request["params"][1]["commitment"], "finalized");
                            json!({"context": {"slot": 500}, "value": valid})
                        }
                        "getAccountInfo" => {
                            assert_eq!(request["params"][1]["commitment"], "finalized");
                            assert_eq!(request["params"][1]["minContextSlot"], 500);
                            json!({"context": {"slot": 500}, "value": account})
                        }
                        "getSignatureStatuses" => {
                            assert_eq!(request["params"][1]["searchTransactionHistory"], true);
                            json!({"context": {"slot": 500}, "value": [status]})
                        }
                        // Conservative attempts can still attempt their original
                        // transaction; force an immediate RPC failure, not a timeout.
                        _ => {
                            return Json(json!({"jsonrpc":"2.0", "id":request["id"],
                        "error":{"code":-32000, "message":"unavailable"}}))
                        }
                    };
                    Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, task)
    }

    #[cfg(feature = "server")]
    fn channel_for_params(
        params: &payment_channels::OpenChannelParams,
    ) -> payment_channels::generated::generated::accounts::Channel {
        payment_channels::generated::generated::accounts::Channel {
            discriminator: 1,
            version: 1,
            bump: 1,
            status: 0,
            salt: params.salt,
            deposit: params.deposit,
            settlement: payment_channels::generated::generated::types::SettlementWatermarks {
                settled: 0,
                payout_watermark: 0,
            },
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: params.grace_period,
            distribution_hash: payment_channels::distribution_hash(&params.recipients),
            payer: payment_channels::to_address(&params.payer),
            payee: payment_channels::to_address(&params.payee),
            authorized_signer: payment_channels::to_address(&params.authorized_signer),
            mint: payment_channels::to_address(&params.mint),
            rent_payer: payment_channels::to_address(&params.rent_payer),
            open_slot: params.open_slot,
        }
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn delayed_concurrent_activation_cannot_revive_terminal_open() {
        use base64::Engine;
        use serde_json::json;
        use std::sync::Arc;
        let mut server =
            SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new())
                .with_channel_binding(json!({"version":1}));
        let (open, params) = signed_open(&server, 4).await;
        let pending = pending_before_broadcast(&server, &open).await;
        server
            .store
            .inner
            .put_channel(&open.channel_id, pending)
            .await
            .unwrap();
        let account = json!({
            "data":[base64::engine::general_purpose::STANDARD.encode(
                borsh::to_vec(&channel_for_params(&params)).unwrap()), "base64"],
            "executable":false, "lamports":1,
            "owner":payment_channels::PAYMENT_CHANNELS_PROGRAM_ID, "rentEpoch":0,
        });
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let (url, rpc) = expiry_rpc_with_delayed_read(
            false,
            json!(null),
            json!(null),
            Some((account, entered.clone(), release.clone())),
        )
        .await;
        server.config.rpc_url = Some(url);
        let server = Arc::new(server);
        let task_server = server.clone();
        let task_open = open.clone();
        let task = tokio::spawn(async move {
            let blockhash = test_blockhash().to_string();
            task_server
                .process_open(
                    &task_open,
                    SessionOpenContext {
                        challenge_id: "opening",
                        expires: None,
                        recent_blockhash: &blockhash,
                        recent_slot: CHALLENGED_SLOT,
                    },
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        assert!(server
            .resume_pending_open(&open.channel_id)
            .await
            .unwrap_err()
            .to_string()
            .contains("request a new channel"));
        release.notify_one();
        // The delayed activation never proves ownership (the open's signature
        // never landed) and cannot revive the retired row either way.
        let error = task.await.unwrap().unwrap_err().to_string();
        assert!(
            error.contains("request a new channel") || error.contains("ownership is unproven"),
            "{error}"
        );
        let terminal = server
            .store
            .inner
            .get_channel(&open.channel_id)
            .await
            .unwrap()
            .unwrap();
        assert!(session_open_is_terminal(&terminal));
        assert_eq!(terminal.deposit, 0);
        rpc.abort();
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn expired_prebroadcast_open_becomes_guarded_tombstone_and_new_channel_is_allowed() {
        use serde_json::json;
        let (url, rpc) = expiry_rpc(false, json!(null), json!(null)).await;
        let mut cfg = config(VoucherSigner::Client);
        cfg.rpc_url = Some(url);
        let policy = json!({"deployment": "original", "version": 1});
        let server =
            SessionServer::new(cfg, MemoryChannelStore::new()).with_channel_binding(policy.clone());
        let (open, _) = signed_open(&server, 4).await;
        let pending = pending_before_broadcast(&server, &open).await;
        server
            .store
            .inner
            .put_channel(&open.channel_id, pending.clone())
            .await
            .unwrap();
        assert!(server
            .resume_pending_open(&open.channel_id)
            .await
            .unwrap_err()
            .to_string()
            .contains("request a new channel"));
        let terminal = server
            .store
            .inner
            .get_channel(&open.channel_id)
            .await
            .unwrap()
            .unwrap();
        assert!(session_open_is_terminal(&terminal));
        assert!(terminal.pending_setup.is_none());
        assert!(terminal.lifecycle.is_none());
        assert!(!terminal.sealed);
        assert_eq!(
            terminal.extra[OPEN_INTENT_KEY],
            pending.extra[OPEN_INTENT_KEY]
        );
        assert_eq!(channel_binding(&terminal).unwrap(), Some(policy.clone()));
        assert_eq!(
            SessionConfigSnapshot::from_channel(&terminal).unwrap(),
            SessionConfigSnapshot::from_channel(&pending).unwrap()
        );
        assert_eq!(terminal.payer, pending.payer);
        assert_eq!(terminal.rent_payer, pending.rent_payer);
        assert_eq!(terminal.open_slot, pending.open_slot);
        assert!(server.require_channel_binding(&terminal).is_err());
        assert!(server.seal_params(&open.channel_id).await.is_err());
        // This is the same guard the delayed activation closure executes.
        assert!(binding::require_binding(&terminal, &server.store.binding, true).is_err());
        assert!(server
            .store
            .update_channel(
                &open.channel_id,
                Box::new(|mut state| {
                    state.as_mut().unwrap().deposit = 10;
                    Ok(state.unwrap())
                })
            )
            .await
            .is_err());
        let blockhash = test_blockhash().to_string();
        assert!(server
            .process_open(
                &open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: &blockhash,
                    recent_slot: CHALLENGED_SLOT,
                }
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("request a new channel"));
        assert!(server
            .resume_pending_open(&open.channel_id)
            .await
            .unwrap_err()
            .to_string()
            .contains("request a new channel"));
        // A distinct salt/channel can complete the normal open API while the
        // original tombstone remains in this same store.
        let (new_open, params) = signed_open(&server, 5).await;
        assert_ne!(new_open.channel_id, open.channel_id);
        let (url, new_rpc, _) =
            rpc_for_channel(channel_for_params(&params), params.open_slot).await;
        let mut cfg = server.config.clone();
        cfg.rpc_url = Some(url);
        let new_server = SessionServer::new(cfg, server.store.inner).with_channel_binding(policy);
        let accepted = new_server
            .process_open(
                &new_open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: &blockhash,
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .unwrap();
        assert_eq!(accepted.deposit, params.deposit);
        assert_eq!(
            new_server.store.inner.list_channels().await.unwrap().len(),
            2
        );
        new_rpc.abort();
        rpc.abort();
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn funded_uncertain_and_legacy_opens_are_never_retired() {
        use serde_json::json;
        let success = json!({"slot": 499, "confirmations": null, "err": null,
            "confirmationStatus":"finalized", "status":{"Ok":null}});
        let nonfinal = json!({"slot": 499, "confirmations": 1, "err":"AlreadyProcessed",
            "confirmationStatus":"confirmed", "status":{"Err":"AlreadyProcessed"}});
        for (valid, account, status, legacy) in [
            (false, json!({"conflicting":"account"}), json!(null), false),
            (false, json!(null), success, false),
            (false, json!(null), nonfinal, false),
            (true, json!(null), json!(null), false),
            (false, json!(null), json!(null), true),
        ] {
            let (url, rpc) = expiry_rpc(valid, account, status).await;
            let mut cfg = config(VoucherSigner::Client);
            cfg.rpc_url = Some(url.clone());
            let pipeline = crate::core::tx_pipeline::TxPipeline::new(
                url,
                crate::core::tx_pipeline::TxPipelineConfig {
                    submission_max_attempts: 1,
                    confirmation_timeout: std::time::Duration::from_millis(10),
                    account_read_retries: 0,
                    ..Default::default()
                },
            );
            let server = SessionServer::new(cfg, MemoryChannelStore::new())
                .with_channel_binding(json!({"version":1}))
                .with_tx_pipeline(pipeline);
            let (open, _) = signed_open(&server, 4).await;
            let mut pending = pending_before_broadcast(&server, &open).await;
            if legacy {
                let intent = pending
                    .extra
                    .get_mut(OPEN_INTENT_KEY)
                    .unwrap()
                    .as_object_mut()
                    .unwrap();
                intent.insert("version".into(), json!(1));
                intent.remove("finalized_valid_at");
                intent.remove("transaction_signature");
            }
            server
                .store
                .inner
                .put_channel(&open.channel_id, pending.clone())
                .await
                .unwrap();
            assert!(server.resume_pending_open(&open.channel_id).await.is_err());
            let retained = server
                .store
                .inner
                .get_channel(&open.channel_id)
                .await
                .unwrap()
                .unwrap();
            assert!(!session_open_is_terminal(&retained));
            assert_eq!(
                serde_json::to_value(retained).unwrap(),
                serde_json::to_value(pending).unwrap()
            );
            rpc.abort();
        }
    }

    #[tokio::test]
    async fn bound_store_isolates_legacy_policy_and_snapshot_on_every_mutation() {
        use serde_json::json;
        let (mut server, mut session, channel_id) = client_server().await;
        let legacy = server
            .store
            .inner
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        server = server.with_channel_binding(json!({"deployment": "a", "version": 1}));
        assert!(server.require_channel_binding(&legacy).is_err());
        let mut bound = legacy.clone();
        server
            .store
            .binding
            .as_ref()
            .unwrap()
            .insert(&mut bound)
            .unwrap();
        server
            .store
            .inner
            .update_channel(&channel_id, Box::new(move |_| Ok(bound)))
            .await
            .unwrap();
        let voucher = session.sign_increment(100).await.unwrap();
        let payload = VoucherPayload {
            channel_id: channel_id.clone(),
            voucher,
        };
        let snapshot = server
            .store
            .inner
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        server = server.with_channel_binding(json!({"deployment": "b", "version": 1}));
        assert!(server.verify_voucher(&payload).await.is_err());
        assert!(server.seal_params(&channel_id).await.is_err());
        assert!(server
            .store
            .update_channel(&channel_id, Box::new(|state| Ok(state.unwrap())))
            .await
            .is_err());
        server.store.binding = None;
        assert!(server.require_channel_binding(&snapshot).is_err());
        assert!(server.verify_voucher(&payload).await.is_err());
        assert!(server.store.mark_sealed(&channel_id).await.is_err());
        server = server.with_channel_binding(json!({"deployment": "a", "version": 1}));
        server.config.amount += 1;
        server = server.with_channel_binding(json!({"deployment": "a", "version": 1}));
        assert!(server.require_channel_binding(&snapshot).is_err());
        let stored = server
            .store
            .inner
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.cumulative, 0);
        assert!(!stored.sealed);
    }

    #[tokio::test]
    async fn guarded_voucher_failure_rolls_back_watermark_and_debit_and_rechecks_replay() {
        let (server, mut session, channel_id) = client_server().await;
        let voucher = session.sign_increment(100).await.unwrap();
        let payload = VoucherPayload {
            channel_id: channel_id.clone(),
            voucher,
        };
        for reason in ["expired lease", "replaced lease", "close claimed"] {
            let error = server
                .verify_voucher_with_guard(&payload, move |state| {
                    assert_eq!(state.cumulative, 0);
                    assert_eq!(state.spent_amount, 0);
                    Err(Error::Other(reason.into()))
                })
                .await
                .unwrap_err();
            assert!(error.to_string().contains(reason));
            let state = server
                .store
                .inner
                .get_channel(&channel_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!((state.cumulative, state.spent_amount), (0, 0));
        }
        server
            .verify_voucher_with_guard(&payload, |_| Ok(()))
            .await
            .unwrap();
        let state = server
            .store
            .inner
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((state.cumulative, state.spent_amount), (100, 25));
        assert!(server
            .verify_voucher_with_guard(&payload, |_| {
                Err(Error::Other("lease expired before replay".into()))
            })
            .await
            .is_err());
        // An exact replay authorizes nothing: it is refused, not returned as a
        // no-charge success a delegating host would forward.
        let error = server
            .verify_voucher_with_guard(&payload, |_| Ok(()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("already accepted"), "{error}");
        let state = server
            .store
            .inner
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((state.cumulative, state.spent_amount), (100, 25));
        // The unguarded verifier still reports the replay idempotently.
        assert!(server.verify_voucher(&payload).await.unwrap().replay);
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn confirmed_open_is_persisted_and_replays_without_reset() {
        use payment_channels::generated::generated::types::SettlementWatermarks;

        let mut server =
            SessionServer::new(config(VoucherSigner::Operator), MemoryChannelStore::new());
        let (mut open, params) = signed_open(&server, 4).await;
        open.authentication =
            Some(SessionAuthentication::sign("opening", &open.channel_id, &key(4)).unwrap());
        let channel = payment_channels::generated::generated::accounts::Channel {
            discriminator: 1,
            version: 1,
            bump: 1,
            status: 0,
            salt: params.salt,
            deposit: params.deposit,
            settlement: SettlementWatermarks {
                settled: 0,
                payout_watermark: 0,
            },
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: params.grace_period,
            distribution_hash: payment_channels::distribution_hash(&params.recipients),
            payer: payment_channels::to_address(&params.payer),
            payee: payment_channels::to_address(&params.payee),
            authorized_signer: payment_channels::to_address(&params.authorized_signer),
            mint: payment_channels::to_address(&params.mint),
            rent_payer: payment_channels::to_address(&params.rent_payer),
            open_slot: params.open_slot,
        };
        let (future_url, future_rpc, _send_tx_count) =
            rpc_for_channel(channel.clone(), params.open_slot - 1).await;
        let mut future_server =
            SessionServer::new(server.config.clone(), MemoryChannelStore::new());
        future_server.config.rpc_url = Some(future_url);
        let challenged_blockhash = test_blockhash().to_string();
        let future = future_server
            .process_open(
                &open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: &challenged_blockhash,
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .unwrap_err();
        assert!(future
            .to_string()
            .contains("ahead of the current cluster slot"));
        future_rpc.abort();

        let stale_slot = params.open_slot + payment_channels::OPEN_SLOT_WINDOW + 1;
        let (stale_url, stale_rpc, _send_tx_count) =
            rpc_for_channel(channel.clone(), stale_slot).await;
        let mut stale_server = SessionServer::new(server.config.clone(), MemoryChannelStore::new());
        stale_server.config.rpc_url = Some(stale_url);
        let stale = stale_server
            .process_open(
                &open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: &challenged_blockhash,
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .unwrap_err();
        assert!(stale.to_string().contains("current cluster slot"));
        stale_rpc.abort();

        let (url, rpc, send_tx_count) = rpc_for_channel(channel, 43).await;
        server.config.rpc_url = Some(url);
        // A transaction built against some other blockhash was not built for
        // this challenge — rejected before broadcast.
        let wrong_blockhash = solana_hash::Hash::new_unique().to_string();
        let mismatch = server
            .process_open(
                &open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: &wrong_blockhash,
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .unwrap_err();
        assert!(mismatch.to_string().contains("challenged recentBlockhash"));
        let context = SessionOpenContext {
            challenge_id: "opening",
            expires: None,
            recent_blockhash: &challenged_blockhash,
            recent_slot: CHALLENGED_SLOT,
        };
        let accepted = server
            .process_open_with_outcome(&open, context)
            .await
            .unwrap();
        assert!(!accepted.replay);
        assert_eq!(accepted.state.opening_challenge_id, "opening");
        assert_eq!(accepted.state.idle_timeout_seconds, Some(300));
        assert_eq!(
            send_tx_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the fresh open must broadcast exactly once"
        );
        let replay = server
            .process_open_with_outcome(&open, context)
            .await
            .unwrap();
        assert!(replay.replay);
        assert_eq!(
            send_tx_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a replayed open against an already-confirmed channel must not rebroadcast \
             (and so must not burn a sponsor fee on the duplicate open)"
        );

        server.store.mark_sealed(&open.channel_id).await.unwrap();
        assert!(server.process_open(&open, context).await.is_err());
        rpc.abort();
    }

    /// The hardest retry: the first submission's broadcast landed but the
    /// store write after it was lost, so no state exists for the replay
    /// branch and the retry's re-broadcast dies at preflight with
    /// "already processed". The confirmed channel account matching the
    /// verified open params is the only signal left — it must be accepted.
    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn open_landed_outside_this_ledger_is_never_adopted() {
        use payment_channels::generated::generated::types::SettlementWatermarks;

        let mut server =
            SessionServer::new(config(VoucherSigner::Operator), MemoryChannelStore::new());
        let (mut open, params) = signed_open(&server, 6).await;
        open.authentication =
            Some(SessionAuthentication::sign("opening", &open.channel_id, &key(6)).unwrap());
        let channel = payment_channels::generated::generated::accounts::Channel {
            discriminator: 1,
            version: 1,
            bump: 1,
            status: 0,
            salt: params.salt,
            deposit: params.deposit,
            settlement: SettlementWatermarks {
                settled: 0,
                payout_watermark: 0,
            },
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: params.grace_period,
            distribution_hash: payment_channels::distribution_hash(&params.recipients),
            payer: payment_channels::to_address(&params.payer),
            payee: payment_channels::to_address(&params.payee),
            authorized_signer: payment_channels::to_address(&params.authorized_signer),
            mint: payment_channels::to_address(&params.mint),
            rent_payer: payment_channels::to_address(&params.rent_payer),
            open_slot: params.open_slot,
        };
        let (url, rpc, _send_tx_count) = rpc_for_channel(channel, 43).await;
        server.config.rpc_url = Some(url);
        let challenged_blockhash = test_blockhash().to_string();
        let context = SessionOpenContext {
            challenge_id: "opening",
            expires: None,
            recent_blockhash: &challenged_blockhash,
            recent_slot: CHALLENGED_SLOT,
        };
        let first = server
            .process_open_with_outcome(&open, context)
            .await
            .unwrap();
        assert!(!first.replay);

        // The ledger that broadcast the open retries it idempotently.
        let replayed = server
            .process_open_with_outcome(&open, context)
            .await
            .unwrap();
        assert!(replayed.replay);
        assert_eq!(replayed.state.deposit, 1_000);

        // The same signed open presented to a ledger that never saw it (a
        // second endpoint sharing the challenge secret, or a wiped store)
        // must not start an independent watermark against the same escrow.
        let fresh = SessionServer::new(server.config.clone(), MemoryChannelStore::new());
        let error = fresh
            .process_open_with_outcome(&open, context)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cannot be adopted"), "{error}");
        let retired = fresh
            .store
            .inner
            .get_channel(&open.channel_id)
            .await
            .unwrap()
            .unwrap();
        assert!(session_open_is_terminal(&retired));
        assert!(retired.pending_setup.is_none());
        assert_eq!(retired.deposit, 0);
        // A retry stays refused rather than activating the reservation.
        assert!(fresh
            .process_open_with_outcome(&open, context)
            .await
            .is_err());
        let proof = open.authentication.clone().unwrap();
        assert!(fresh
            .process_use(
                &UsePayload {
                    channel_id: open.channel_id.clone(),
                    authentication: proof,
                },
                "use",
                "key",
            )
            .await
            .is_err());
        rpc.abort();
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn pending_open_is_adopted_only_when_it_landed_after_its_recorded_floor() {
        use serde_json::json;
        for (landed_at, adopted) in [
            (CHALLENGED_SLOT - 2, false),
            (CHALLENGED_SLOT, false),
            (CHALLENGED_SLOT + 1, true),
        ] {
            let mut server =
                SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new())
                    .with_channel_binding(json!({"version": 1}));
            let (open, params) = signed_open(&server, 4).await;
            // A reservation left by an attempt whose confirmation and account
            // read both failed; its floor was recorded before that broadcast.
            let pending = pending_before_broadcast(&server, &open).await;
            let signature = pending.extra[OPEN_INTENT_KEY]["transaction_signature"]
                .as_str()
                .unwrap()
                .to_string();
            server
                .store
                .inner
                .put_channel(&open.channel_id, pending)
                .await
                .unwrap();
            let (url, rpc, sends) = rpc_for_landed_channel(
                channel_for_params(&params),
                CHALLENGED_SLOT + 10,
                LandedStatus::Finalized,
                [(signature, landed_at)],
            )
            .await;
            server.config.rpc_url = Some(url);
            let blockhash = test_blockhash().to_string();
            let context = SessionOpenContext {
                challenge_id: "opening",
                expires: None,
                recent_blockhash: &blockhash,
                recent_slot: CHALLENGED_SLOT,
            };
            let outcome = server.process_open_with_outcome(&open, context).await;
            let state = server
                .store
                .inner
                .get_channel(&open.channel_id)
                .await
                .unwrap()
                .unwrap();
            if adopted {
                assert_eq!(outcome.unwrap().state.deposit, params.deposit);
            } else {
                let error = outcome.unwrap_err().to_string();
                assert!(error.contains("cannot be adopted"), "{error}");
                assert!(session_open_is_terminal(&state));
                assert_eq!(state.deposit, 0);
            }
            assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
            rpc.abort();
        }
    }

    /// A pending open written before floors were recorded loads its floor
    /// from the finalized observation it persisted before broadcasting, and is
    /// resumed only when it landed after that; with neither recorded it is
    /// never adopted.
    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn legacy_pending_open_derives_its_floor_from_its_finalized_observation() {
        use serde_json::json;
        const FINALIZED: u64 = CHALLENGED_SLOT - 2;
        for (landed_at, finalized, adopted) in [
            (FINALIZED, Some(FINALIZED), false),
            (FINALIZED + 1, Some(FINALIZED), true),
            (CHALLENGED_SLOT + 1, None, false),
        ] {
            let mut server =
                SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new())
                    .with_channel_binding(json!({"version": 1}));
            let (open, params) = signed_open(&server, 4).await;
            let mut pending = pending_before_broadcast(&server, &open).await;
            let intent = pending
                .extra
                .get_mut(OPEN_INTENT_KEY)
                .unwrap()
                .as_object_mut()
                .unwrap();
            intent.remove("adoption_floor");
            match finalized {
                Some(slot) => intent.insert("finalized_valid_at".into(), json!(slot)),
                None => intent.remove("finalized_valid_at"),
            };
            let signature = intent["transaction_signature"]
                .as_str()
                .unwrap()
                .to_string();
            let loaded: OpenIntent =
                serde_json::from_value(pending.extra[OPEN_INTENT_KEY].clone()).unwrap();
            assert_eq!(
                loaded.adoption_floor,
                finalized.map_or(AdoptionFloor::Unproven, AdoptionFloor::Slot)
            );
            server
                .store
                .inner
                .put_channel(&open.channel_id, pending.clone())
                .await
                .unwrap();
            let (url, rpc, sends) = rpc_for_landed_channel(
                channel_for_params(&params),
                CHALLENGED_SLOT + 10,
                LandedStatus::Finalized,
                [(signature, landed_at)],
            )
            .await;
            server.config.rpc_url = Some(url);
            let blockhash = test_blockhash().to_string();
            let context = SessionOpenContext {
                challenge_id: "opening",
                expires: None,
                recent_blockhash: &blockhash,
                recent_slot: CHALLENGED_SLOT,
            };
            let outcome = server.process_open_with_outcome(&open, context).await;
            let state = server
                .store
                .inner
                .get_channel(&open.channel_id)
                .await
                .unwrap()
                .unwrap();
            match (adopted, finalized) {
                (true, _) => {
                    assert_eq!(outcome.unwrap().state.deposit, params.deposit);
                    assert!(state.pending_setup.is_none());
                }
                // Landed at or before the floor: opened elsewhere, retired.
                (false, Some(_)) => {
                    let error = outcome.unwrap_err().to_string();
                    assert!(error.contains("cannot be adopted"), "{error}");
                    assert!(session_open_is_terminal(&state));
                    assert_eq!(state.deposit, 0);
                }
                // Nothing bounds the first broadcast: refused, row untouched.
                (false, None) => {
                    let error = outcome.unwrap_err().to_string();
                    assert!(error.contains("no recorded broadcast floor"), "{error}");
                    assert_eq!(
                        serde_json::to_value(&state).unwrap(),
                        serde_json::to_value(&pending).unwrap()
                    );
                }
            }
            assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
            rpc.abort();
        }
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn failed_fresh_open_never_adopts_a_matching_channel() {
        let mut server =
            SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new());
        let (open, params) = signed_open(&server, 4).await;
        // This open's own transaction fails on-chain, yet a matching channel
        // account exists: it was opened by some other transaction.
        let (url, rpc, _) =
            rpc_for_channel_with_options(channel_for_params(&params), 43, LandedStatus::Failed)
                .await;
        server.config.rpc_url = Some(url);
        let blockhash = test_blockhash().to_string();
        let context = SessionOpenContext {
            challenge_id: "opening",
            expires: None,
            recent_blockhash: &blockhash,
            recent_slot: CHALLENGED_SLOT,
        };
        for _ in 0..2 {
            assert!(server.process_open(&open, context).await.is_err());
            let state = server
                .store
                .inner
                .get_channel(&open.channel_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(state.deposit, 0);
            assert!(state.pending_setup.is_some());
        }
        rpc.abort();
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn open_never_accepts_vouchers_at_or_below_the_onchain_settlement() {
        let mut server =
            SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new());
        let (open, params) = signed_open(&server, 6).await;
        // The confirmed channel already carries a settled watermark (e.g. the
        // ledger row was rebuilt after vouchers were redeemed).
        let mut channel = channel_for_params(&params);
        channel.settlement.settled = 300;
        let (url, rpc, _) = rpc_for_channel(channel, 43).await;
        server.config.rpc_url = Some(url);
        let challenged_blockhash = test_blockhash().to_string();
        let context = SessionOpenContext {
            challenge_id: "opening",
            expires: None,
            recent_blockhash: &challenged_blockhash,
            recent_slot: CHALLENGED_SLOT,
        };
        let opened = server
            .process_open_with_outcome(&open, context)
            .await
            .unwrap();
        assert_eq!(opened.state.cumulative, 300);
        assert_eq!(opened.state.settled_on_chain, 300);
        assert_eq!(opened.state.spent_amount, 300);

        let channel_pubkey = Pubkey::from_str(&open.channel_id).unwrap();
        let mut session = ActiveSession::new(channel_pubkey, signer(1));
        let settled_voucher = session.sign_increment(300).await.unwrap();
        assert!(server
            .verify_voucher(&VoucherPayload {
                channel_id: open.channel_id.clone(),
                voucher: settled_voucher,
            })
            .await
            .is_err());
        let next = session.sign_increment(50).await.unwrap();
        let accepted = server
            .verify_voucher(&VoucherPayload {
                channel_id: open.channel_id.clone(),
                voucher: next,
            })
            .await
            .unwrap();
        assert_eq!(accepted.charged, 50);
        rpc.abort();
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn sponsored_topup_with_zero_compute_unit_limit_is_rejected_before_cosigning() {
        use payment_channels::generated::generated::types::SettlementWatermarks;

        let (mut server, _session, channel_id) = client_server().await;
        let payer = signer(5);
        let sponsor = shared_signer(8);
        server.config.fee_payer_signer = Some(std::sync::Arc::clone(&sponsor));
        server
            .store
            .update_channel(
                &channel_id,
                Box::new({
                    let payer = payer.pubkey().to_string();
                    let rent_payer = sponsor.pubkey().to_string();
                    move |state| {
                        let mut state = state.unwrap();
                        state.payer = payer;
                        state.rent_payer = rent_payer;
                        Ok(state)
                    }
                }),
            )
            .await
            .unwrap();
        let channel = Pubkey::from_str(&channel_id).unwrap();
        let mint = Pubkey::from_str(mints::USDC_MAINNET).unwrap();
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
        let program_id = payment_channels::default_program_id();
        let ix = payment_channels::build_top_up_instruction(
            &payer.pubkey(),
            &channel,
            &mint,
            100,
            &token_program,
            &program_id,
        );
        let mut tx = crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &sponsor.pubkey(),
            &[crate::core::tx::unit_limit_instruction(0), ix],
            solana_hash::Hash::new_unique(),
            None,
        )
        .unwrap();
        crate::core::signing::sign_versioned_transaction_slot(payer.as_ref(), &mut tx)
            .await
            .unwrap();
        assert_eq!(tx.signatures[0], Signature::default());
        let transaction = crate::core::tx::encode(&tx).unwrap();
        let account = payment_channels::generated::generated::accounts::Channel {
            discriminator: 1,
            version: 1,
            bump: 1,
            status: 0,
            salt: 7,
            deposit: 1_100,
            settlement: SettlementWatermarks {
                settled: 0,
                payout_watermark: 0,
            },
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: server.config.grace_period_seconds,
            distribution_hash: [0; 32],
            payer: payment_channels::to_address(&payer.pubkey()),
            payee: payment_channels::to_address(
                &Pubkey::from_str(&server.config.recipient).unwrap(),
            ),
            authorized_signer: payment_channels::to_address(&signer(1).pubkey()),
            mint: payment_channels::to_address(&mint),
            rent_payer: payment_channels::to_address(&sponsor.pubkey()),
            open_slot: 42,
        };
        let (url, rpc, send_tx_count) = rpc_for_channel(account, 43).await;
        server.config.rpc_url = Some(url);
        let payload = TopUpPayload {
            channel_id: channel_id.clone(),
            additional_amount: "100".into(),
            transaction,
        };
        let error = server
            .process_topup_with_outcome(&payload)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("must be positive"), "{error}");
        assert_eq!(send_tx_count.load(std::sync::atomic::Ordering::SeqCst), 0);
        let stored = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.deposit, 1_000);
        rpc.abort();
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn confirmed_sponsored_topup_adds_only_the_declared_amount() {
        use payment_channels::generated::generated::types::SettlementWatermarks;

        let (mut server, _session, channel_id) = client_server().await;
        let payer = signer(5);
        let sponsor = shared_signer(8);
        server.config.fee_payer_signer = Some(std::sync::Arc::clone(&sponsor));
        server
            .store
            .update_channel(
                &channel_id,
                Box::new({
                    let payer = payer.pubkey().to_string();
                    let rent_payer = sponsor.pubkey().to_string();
                    move |state| {
                        let mut state = state.unwrap();
                        state.payer = payer;
                        state.rent_payer = rent_payer;
                        Ok(state)
                    }
                }),
            )
            .await
            .unwrap();
        let channel = Pubkey::from_str(&channel_id).unwrap();
        let mint = Pubkey::from_str(mints::USDC_MAINNET).unwrap();
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
        let program_id = payment_channels::default_program_id();
        let ix = payment_channels::build_top_up_instruction(
            &payer.pubkey(),
            &channel,
            &mint,
            100,
            &token_program,
            &program_id,
        );
        let mut tx = crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &sponsor.pubkey(),
            &[ix],
            solana_hash::Hash::new_unique(),
            None,
        )
        .unwrap();
        crate::core::signing::sign_versioned_transaction_slot(payer.as_ref(), &mut tx)
            .await
            .unwrap();
        assert_eq!(tx.signatures[0], Signature::default());
        let transaction = crate::core::tx::encode(&tx).unwrap();
        let account = payment_channels::generated::generated::accounts::Channel {
            discriminator: 1,
            version: 1,
            bump: 1,
            status: 0,
            salt: 7,
            deposit: 1_100,
            settlement: SettlementWatermarks {
                settled: 0,
                payout_watermark: 0,
            },
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: server.config.grace_period_seconds,
            distribution_hash: [0; 32],
            payer: payment_channels::to_address(&payer.pubkey()),
            payee: payment_channels::to_address(
                &Pubkey::from_str(&server.config.recipient).unwrap(),
            ),
            authorized_signer: payment_channels::to_address(&signer(1).pubkey()),
            mint: payment_channels::to_address(&mint),
            rent_payer: payment_channels::to_address(&sponsor.pubkey()),
            open_slot: 42,
        };
        let (url, rpc, _send_tx_count) = rpc_for_channel(account, 43).await;
        server.config.rpc_url = Some(url);
        let payload = TopUpPayload {
            channel_id: channel_id.clone(),
            additional_amount: "100".into(),
            transaction,
        };
        let updated = server.process_topup_with_outcome(&payload).await.unwrap();
        assert_eq!(updated.state.deposit, 1_100);
        assert!(updated.state.lifecycle.is_some());
        assert!(!updated.replay);
        assert_ne!(
            updated.transaction_signature,
            Signature::default().to_string()
        );

        // A plain retry replays from the recorded signature without
        // re-broadcasting — no second credit.
        let replayed = server.process_topup_with_outcome(&payload).await.unwrap();
        assert_eq!(replayed.state.deposit, 1_100);
        assert!(replayed.replay);

        // Broadcast landed but the credit was lost (crash between confirm
        // and store write): the retry's re-broadcast dies at preflight, the
        // landed-signature status check rescues it, and the mutator credits
        // exactly once.
        server
            .store
            .update_channel(
                &channel_id,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.deposit = 1_000;
                    state.processed_topup_signatures.clear();
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let redriven = server.process_topup(&payload).await.unwrap();
        assert_eq!(redriven.deposit, 1_100);
        let stored = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.deposit, 1_100);
        assert_eq!(stored.processed_topup_signatures.len(), 1);
        rpc.abort();
    }

    // A sponsored top-up the payer cannot fund fails simulation and is never
    // broadcast at the sponsor's expense.
    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn sponsored_topup_that_fails_simulation_is_never_broadcast() {
        use payment_channels::generated::generated::types::SettlementWatermarks;

        for (status, lands) in [
            (LandedStatus::Unexecutable, false),
            (LandedStatus::Finalized, true),
        ] {
            let (mut server, _session, channel_id) = client_server().await;
            let payer = signer(5);
            let sponsor = shared_signer(8);
            server.config.fee_payer_signer = Some(std::sync::Arc::clone(&sponsor));
            server
                .store
                .update_channel(
                    &channel_id,
                    Box::new({
                        let payer = payer.pubkey().to_string();
                        let rent_payer = sponsor.pubkey().to_string();
                        move |state| {
                            let mut state = state.unwrap();
                            state.payer = payer;
                            state.rent_payer = rent_payer;
                            Ok(state)
                        }
                    }),
                )
                .await
                .unwrap();
            let channel = Pubkey::from_str(&channel_id).unwrap();
            let mint = Pubkey::from_str(mints::USDC_MAINNET).unwrap();
            let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
            let program_id = payment_channels::default_program_id();
            let ix = payment_channels::build_top_up_instruction(
                &payer.pubkey(),
                &channel,
                &mint,
                100,
                &token_program,
                &program_id,
            );
            let mut tx = crate::core::tx::build_unsigned_unchecked(
                crate::core::tx::TxVersion::V0,
                &sponsor.pubkey(),
                &[ix],
                solana_hash::Hash::new_unique(),
                None,
            )
            .unwrap();
            crate::core::signing::sign_versioned_transaction_slot(payer.as_ref(), &mut tx)
                .await
                .unwrap();
            let transaction = crate::core::tx::encode(&tx).unwrap();
            // The on-chain account already reflects deposit=1_100 — as if a
            // *different* concurrent top-up already landed — even though THIS
            // request's own transaction is about to be reported as failed.
            let account = payment_channels::generated::generated::accounts::Channel {
                discriminator: 1,
                version: 1,
                bump: 1,
                status: 0,
                salt: 7,
                deposit: 1_100,
                settlement: SettlementWatermarks {
                    settled: 0,
                    payout_watermark: 0,
                },
                closure_started_at: 0,
                payer_withdrawn_at: 0,
                grace_period: server.config.grace_period_seconds,
                distribution_hash: [0; 32],
                payer: payment_channels::to_address(&payer.pubkey()),
                payee: payment_channels::to_address(
                    &Pubkey::from_str(&server.config.recipient).unwrap(),
                ),
                authorized_signer: payment_channels::to_address(&signer(1).pubkey()),
                mint: payment_channels::to_address(&mint),
                rent_payer: payment_channels::to_address(&sponsor.pubkey()),
                open_slot: 42,
            };
            let (url, rpc, sends) = rpc_for_channel_with_options(account, 43, status).await;
            server.config.rpc_url = Some(url);
            let payload = TopUpPayload {
                channel_id: channel_id.clone(),
                additional_amount: "100".into(),
                transaction,
            };
            let result = server.process_topup_with_outcome(&payload).await;
            if lands {
                result.unwrap();
            } else {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("failed simulation"), "{error}");
            }
            assert_eq!(
                sends.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(lands)
            );
            rpc.abort();
        }
    }

    /// Regression: a top-up whose own transaction fails on-chain must not be
    /// credited just because the channel's *aggregate* on-chain deposit
    /// happens to already meet `state.deposit + amount` — that aggregate can
    /// be satisfied by a wholly different, concurrently-landed top-up reading
    /// the same stale `state.deposit` baseline. Crediting on that basis lets
    /// N concurrent (but individually failed) top-up requests each add their
    /// own `additionalAmount` to the store — since each carries a distinct
    /// signature, the mutator's replay-by-signature dedupe never catches
    /// it — inflating the stored deposit far past what actually escrowed
    /// on-chain.
    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn topup_whose_own_transaction_fails_is_not_credited_from_the_aggregate_deposit() {
        use payment_channels::generated::generated::types::SettlementWatermarks;

        let (mut server, _session, channel_id) = client_server().await;
        let payer = signer(5);
        let sponsor = shared_signer(8);
        server.config.fee_payer_signer = Some(std::sync::Arc::clone(&sponsor));
        server
            .store
            .update_channel(
                &channel_id,
                Box::new({
                    let payer = payer.pubkey().to_string();
                    let rent_payer = sponsor.pubkey().to_string();
                    move |state| {
                        let mut state = state.unwrap();
                        state.payer = payer;
                        state.rent_payer = rent_payer;
                        Ok(state)
                    }
                }),
            )
            .await
            .unwrap();
        let channel = Pubkey::from_str(&channel_id).unwrap();
        let mint = Pubkey::from_str(mints::USDC_MAINNET).unwrap();
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
        let program_id = payment_channels::default_program_id();
        let ix = payment_channels::build_top_up_instruction(
            &payer.pubkey(),
            &channel,
            &mint,
            100,
            &token_program,
            &program_id,
        );
        let mut tx = crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &sponsor.pubkey(),
            &[ix],
            solana_hash::Hash::new_unique(),
            None,
        )
        .unwrap();
        crate::core::signing::sign_versioned_transaction_slot(payer.as_ref(), &mut tx)
            .await
            .unwrap();
        let transaction = crate::core::tx::encode(&tx).unwrap();
        // The on-chain account already reflects deposit=1_100 — as if a
        // *different* concurrent top-up already landed — even though THIS
        // request's own transaction is about to be reported as failed.
        let account = payment_channels::generated::generated::accounts::Channel {
            discriminator: 1,
            version: 1,
            bump: 1,
            status: 0,
            salt: 7,
            deposit: 1_100,
            settlement: SettlementWatermarks {
                settled: 0,
                payout_watermark: 0,
            },
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: server.config.grace_period_seconds,
            distribution_hash: [0; 32],
            payer: payment_channels::to_address(&payer.pubkey()),
            payee: payment_channels::to_address(
                &Pubkey::from_str(&server.config.recipient).unwrap(),
            ),
            authorized_signer: payment_channels::to_address(&signer(1).pubkey()),
            mint: payment_channels::to_address(&mint),
            rent_payer: payment_channels::to_address(&sponsor.pubkey()),
            open_slot: 42,
        };
        let (url, rpc, _send_tx_count) =
            rpc_for_channel_with_options(account, 43, LandedStatus::Failed).await;
        server.config.rpc_url = Some(url);
        let payload = TopUpPayload {
            channel_id: channel_id.clone(),
            additional_amount: "100".into(),
            transaction,
        };

        let result = server.process_topup_with_outcome(&payload).await;
        assert!(
            result.is_err(),
            "a top-up whose own transaction failed on-chain must not report success \
             just because the channel's aggregate deposit already meets the minimum"
        );

        let stored = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.deposit, 1_000,
            "no credit may be applied for a transaction that never confirmed"
        );
        assert!(stored.processed_topup_signatures.is_empty());
        rpc.abort();
    }

    async fn stored<S: ChannelStore>(server: &SessionServer<S>, channel_id: &str) -> ChannelState {
        server.store.get_channel(channel_id).await.unwrap().unwrap()
    }

    fn voucher_payload(voucher: SignedVoucher) -> VoucherPayload {
        VoucherPayload {
            channel_id: voucher.data.channel_id.clone(),
            voucher,
        }
    }

    #[tokio::test]
    async fn priced_voucher_must_cover_the_challenged_amount() {
        let (mut server, session, channel_id) = client_server().await;
        // Static unit price; the request was challenged at 100.
        server.config.amount = 1;
        let under = session.prepare_increment(1).await.unwrap();
        let error = server
            .verify_voucher_for_amount(&voucher_payload(under), 100)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("availability"), "{error}");
        let off_by_one = session.prepare_increment(99).await.unwrap();
        assert!(server
            .verify_voucher_for_amount(&voucher_payload(off_by_one), 100)
            .await
            .is_err());
        let state = stored(&server, &channel_id).await;
        assert_eq!((state.cumulative, state.spent_amount), (0, 0));
        assert!(state.highest_voucher_signature.is_none());

        let exact = session.prepare_increment(100).await.unwrap();
        let accepted = server
            .verify_voucher_for_amount(&voucher_payload(exact), 100)
            .await
            .unwrap();
        assert_eq!((accepted.cumulative, accepted.charged), (100, 100));
        let state = stored(&server, &channel_id).await;
        assert_eq!((state.cumulative, state.spent_amount), (100, 100));
    }

    #[tokio::test]
    async fn priced_voucher_debits_the_challenged_amount_not_the_unit_price() {
        let (mut server, mut session, channel_id) = client_server().await;
        server.config.amount = 1;
        let first = session.sign_increment(300).await.unwrap();
        server
            .verify_voucher_for_amount(&voucher_payload(first), 250)
            .await
            .unwrap();
        assert_eq!(stored(&server, &channel_id).await.spent_amount, 250);
        // 50 of prepaid credit remains; the next 250 request needs +200 more.
        let short = session.prepare_increment(199).await.unwrap();
        assert!(server
            .verify_voucher_for_amount(&voucher_payload(short), 250)
            .await
            .is_err());
        let enough = session.prepare_increment(200).await.unwrap();
        server
            .verify_voucher_for_amount(&voucher_payload(enough), 250)
            .await
            .unwrap();
        let state = stored(&server, &channel_id).await;
        assert_eq!((state.cumulative, state.spent_amount), (500, 500));
    }

    #[tokio::test]
    async fn priced_voucher_exact_replay_is_rejected_without_state_change() {
        let (server, mut session, channel_id) = client_server().await;
        let payload = voucher_payload(session.sign_increment(25).await.unwrap());
        let accepted = server
            .verify_voucher_for_amount(&payload, 25)
            .await
            .unwrap();
        assert!(!accepted.replay);
        let before = stored(&server, &channel_id).await;
        let error = server
            .verify_voucher_for_amount(&payload, 25)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("already accepted"), "{error}");
        let after = stored(&server, &channel_id).await;
        assert_eq!(
            (after.cumulative, after.spent_amount, after.last_activity_at),
            (25, 25, before.last_activity_at)
        );
        // The next request is paid with a fresh voucher.
        let next = voucher_payload(session.sign_increment(25).await.unwrap());
        let accepted = server.verify_voucher_for_amount(&next, 25).await.unwrap();
        assert_eq!((accepted.cumulative, accepted.charged), (50, 25));
        assert_eq!(stored(&server, &channel_id).await.spent_amount, 50);
        // The idempotent unpriced path keeps its replay semantics.
        assert!(server.verify_voucher(&next).await.unwrap().replay);
    }

    #[tokio::test]
    async fn unit_priced_config_cannot_settle_a_route_challenged_higher() {
        let (mut server, mut session, channel_id) = client_server().await;
        server.config.amount = 1;
        server
            .store
            .update_channel(
                &channel_id,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.deposit = 1_000_000;
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let route_price = 500_000;

        let plus_one = voucher_payload(session.prepare_increment(1).await.unwrap());
        assert!(server
            .verify_voucher_for_amount(&plus_one, route_price)
            .await
            .is_err());
        assert_eq!(server.seal_params(&channel_id).await.unwrap().settled, 0);

        let paid = voucher_payload(session.sign_increment(route_price).await.unwrap());
        server
            .verify_voucher_for_amount(&paid, route_price)
            .await
            .unwrap();
        let state = stored(&server, &channel_id).await;
        assert_eq!(state.spent_amount, route_price);
        assert_eq!(
            server.seal_params(&channel_id).await.unwrap().settled,
            route_price
        );
    }

    #[tokio::test]
    async fn metered_commit_above_deposit_is_rejected() {
        let (server, mut session, channel_id) = client_server().await;
        server
            .verify_voucher(&voucher_payload(session.sign_voucher(100).await.unwrap()))
            .await
            .unwrap();
        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 900))
            .await
            .unwrap();
        server
            .verify_voucher(&voucher_payload(session.sign_voucher(200).await.unwrap()))
            .await
            .unwrap();

        for over in [1_001, 1_100] {
            let error = server
                .process_commit(&CommitPayload {
                    delivery_id: directive.delivery_id.clone(),
                    voucher: session.prepare_voucher(over).await.unwrap(),
                })
                .await
                .unwrap_err();
            assert!(error.to_string().contains("exceeds deposit"), "{error}");
        }
        let state = stored(&server, &channel_id).await;
        assert_eq!(state.cumulative, 200);
        assert_eq!(state.pending_deliveries.len(), 1);
        assert_eq!(server.seal_params(&channel_id).await.unwrap().settled, 200);

        // Committing up to the escrow cap still works.
        server
            .record_delivery_usage(&channel_id, &directive.delivery_id, 800)
            .await
            .unwrap();
        let receipt = server
            .process_commit(&CommitPayload {
                delivery_id: directive.delivery_id,
                voucher: session.prepare_voucher(1_000).await.unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(
            (receipt.amount.as_str(), receipt.cumulative.as_str()),
            ("800", "1000")
        );
        assert_eq!(
            server.seal_params(&channel_id).await.unwrap().settled,
            1_000
        );
    }

    #[tokio::test]
    async fn delivery_reservation_overflow_is_rejected() {
        let (server, _session, channel_id) = client_server().await;
        server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 600))
            .await
            .unwrap();
        for amount in [u64::MAX, u64::MAX - 599, 401] {
            assert!(server
                .begin_delivery(DeliveryRequest::new(channel_id.clone(), amount))
                .await
                .is_err());
        }
        server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 400))
            .await
            .unwrap();
        assert_eq!(
            stored(&server, &channel_id).await.pending_deliveries.len(),
            2
        );
    }

    #[tokio::test]
    async fn seal_params_refuses_a_watermark_above_deposit() {
        let (server, _session, channel_id) = client_server().await;
        server
            .store
            .update_channel(
                &channel_id,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.cumulative = state.deposit + 1;
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        assert!(server.seal_params(&channel_id).await.is_err());
    }

    fn action_voucher(action: crate::mpp::SessionAction) -> VoucherPayload {
        match action {
            crate::mpp::SessionAction::Voucher(payload) => payload,
            other => panic!("expected voucher action, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn out_of_order_vouchers_from_advancing_signer_overstate_the_watermark() {
        // The hazard: signing advances the client watermark before delivery,
        // so the server only sees the higher voucher as fresh.
        let (server, mut session, channel_id) = client_server().await;
        let low = action_voucher(session.voucher_action(25).await.unwrap());
        let high = action_voucher(session.voucher_action(25).await.unwrap());
        server.verify_voucher_for_amount(&high, 25).await.unwrap();
        assert!(server.verify_voucher_for_amount(&low, 25).await.is_err());
        let state = stored(&server, &channel_id).await;
        // The rejected request is not debited.
        assert_eq!((state.cumulative, state.spent_amount), (50, 25));
    }

    #[tokio::test]
    async fn concurrent_prepared_vouchers_never_settle_a_rejected_request() {
        let (server, mut session, channel_id) = client_server().await;
        let (first, second) = tokio::join!(
            session.prepare_voucher_action(25),
            session.prepare_voucher_action(25)
        );
        let (first, second) = (
            action_voucher(first.unwrap()),
            action_voucher(second.unwrap()),
        );
        assert_eq!(first.voucher.data.cumulative_amount, "25");
        assert_eq!(first.voucher.signature, second.voucher.signature);

        // Whichever lands first is served; the other is rejected and costs
        // nothing, so the watermark always equals what was served.
        server.verify_voucher_for_amount(&second, 25).await.unwrap();
        assert!(server.verify_voucher_for_amount(&first, 25).await.is_err());
        let state = stored(&server, &channel_id).await;
        assert_eq!((state.cumulative, state.spent_amount), (25, 25));
        assert_eq!(server.seal_params(&channel_id).await.unwrap().settled, 25);

        // The client records only the accepted voucher, then retries.
        session.record_voucher(&second.voucher).unwrap();
        let retry = action_voucher(session.prepare_voucher_action(25).await.unwrap());
        assert_eq!(retry.voucher.data.cumulative_amount, "50");
        server.verify_voucher_for_amount(&retry, 25).await.unwrap();
        session.record_voucher(&retry.voucher).unwrap();
        let state = stored(&server, &channel_id).await;
        assert_eq!((state.cumulative, state.spent_amount), (50, 50));
    }

    fn close_with(voucher: SignedVoucher) -> ClosePayload {
        ClosePayload {
            channel_id: voucher.data.channel_id.clone(),
            authentication: None,
            voucher: Some(voucher),
        }
    }

    #[tokio::test]
    async fn close_cannot_discard_a_live_metered_delivery() {
        let (server, session, channel_id) = client_server().await;
        let mut request = DeliveryRequest::new(channel_id.clone(), 100);
        request.delivery_id = Some("delivery-100".to_string());
        let directive = server.begin_delivery(request).await.unwrap();

        for short in [1, 99] {
            let error = server
                .process_close(&close_with(session.prepare_increment(short).await.unwrap()))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("uncommitted"), "{error}");
        }
        let state = stored(&server, &channel_id).await;
        assert!(state.close_requested_at.is_none());
        assert_eq!(state.pending_deliveries.len(), 1);

        // Committing the delivery first leaves an ordinary close.
        server
            .process_commit(&CommitPayload {
                delivery_id: directive.delivery_id,
                voucher: session.prepare_increment(100).await.unwrap(),
            })
            .await
            .unwrap();
        let seal = server
            .process_close(&close_with(session.prepare_voucher(101).await.unwrap()))
            .await
            .unwrap();
        assert_eq!(seal.settled, 101);
    }

    #[tokio::test]
    async fn close_voucher_covering_a_live_delivery_settles_it() {
        let (server, session, channel_id) = client_server().await;
        server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 100))
            .await
            .unwrap();
        let seal = server
            .process_close(&close_with(session.prepare_increment(100).await.unwrap()))
            .await
            .unwrap();
        assert_eq!(seal.settled, 100);
        let state = stored(&server, &channel_id).await;
        assert!(state.pending_deliveries.is_empty());
        assert_eq!(state.spent_amount, 100);
    }

    #[tokio::test]
    async fn expired_metered_delivery_is_still_owed_at_close() {
        let (server, session, channel_id) = client_server().await;
        let mut request = DeliveryRequest::new(channel_id.clone(), 100);
        request.expires_at = Some(1);
        server.begin_delivery(request).await.unwrap();

        // The directive was handed out, so the response may have been sent:
        // an expired commit window does not let the close drop the charge.
        let error = server
            .process_close(&close_with(session.prepare_increment(1).await.unwrap()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("uncommitted"), "{error}");
        assert!(stored(&server, &channel_id)
            .await
            .close_requested_at
            .is_none());

        let seal = server
            .process_close(&close_with(session.prepare_increment(100).await.unwrap()))
            .await
            .unwrap();
        assert_eq!(seal.settled, 100);
        let state = stored(&server, &channel_id).await;
        assert!(state.pending_deliveries.is_empty());
        assert_eq!(state.spent_amount, 100);
    }

    #[tokio::test]
    async fn released_expired_delivery_does_not_block_close() {
        let (server, session, channel_id) = client_server().await;
        let mut request = DeliveryRequest::new(channel_id.clone(), 100);
        request.expires_at = Some(1);
        let directive = server.begin_delivery(request).await.unwrap();
        // The host knows the handler failed before sending anything.
        server
            .record_delivery_usage(&channel_id, &directive.delivery_id, 0)
            .await
            .unwrap();
        let seal = server
            .process_close(&close_with(session.prepare_increment(1).await.unwrap()))
            .await
            .unwrap();
        assert_eq!(seal.settled, 1);
    }

    #[tokio::test]
    async fn metered_commit_must_pay_the_full_reservation() {
        let (server, session, channel_id) = client_server().await;
        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 100))
            .await
            .unwrap();
        for wrong in [1, 99, 101] {
            let error = server
                .process_commit(&CommitPayload {
                    delivery_id: directive.delivery_id.clone(),
                    voucher: session.prepare_increment(wrong).await.unwrap(),
                })
                .await
                .unwrap_err();
            assert!(error.to_string().contains("does not match"), "{error}");
        }
        let state = stored(&server, &channel_id).await;
        assert_eq!((state.cumulative, state.spent_amount), (0, 0));
        assert_eq!(state.pending_deliveries.len(), 1);

        let receipt = server
            .process_commit(&CommitPayload {
                delivery_id: directive.delivery_id,
                voucher: session.prepare_increment(100).await.unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(receipt.amount, "100");
        assert_eq!(server.seal_params(&channel_id).await.unwrap().settled, 100);
    }

    #[tokio::test]
    async fn server_recorded_usage_sets_the_commit_amount() {
        let (server, session, channel_id) = client_server().await;
        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 100))
            .await
            .unwrap();
        assert!(server
            .record_delivery_usage(&channel_id, &directive.delivery_id, 101)
            .await
            .is_err());
        assert!(server
            .record_delivery_usage(&channel_id, "unknown", 10)
            .await
            .is_err());
        server
            .record_delivery_usage(&channel_id, &directive.delivery_id, 64)
            .await
            .unwrap();
        assert!(server
            .process_commit(&CommitPayload {
                delivery_id: directive.delivery_id.clone(),
                voucher: session.prepare_increment(1).await.unwrap(),
            })
            .await
            .is_err());
        let receipt = server
            .process_commit(&CommitPayload {
                delivery_id: directive.delivery_id,
                voucher: session.prepare_increment(64).await.unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(
            (receipt.amount.as_str(), receipt.cumulative.as_str()),
            ("64", "64")
        );
        assert_eq!(stored(&server, &channel_id).await.spent_amount, 64);

        let unused = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 50))
            .await
            .unwrap();
        server
            .record_delivery_usage(&channel_id, &unused.delivery_id, 0)
            .await
            .unwrap();
        assert!(stored(&server, &channel_id)
            .await
            .pending_deliveries
            .is_empty());
    }

    #[tokio::test]
    async fn priced_voucher_rejects_a_zero_amount() {
        let (server, session, channel_id) = client_server().await;
        let voucher = session.prepare_increment(25).await.unwrap();
        assert!(server
            .verify_voucher_for_amount(&voucher_payload(voucher), 0)
            .await
            .is_err());
        assert_eq!(stored(&server, &channel_id).await.cumulative, 0);
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn confirmed_but_unfinalized_topup_is_not_credited() {
        use payment_channels::generated::generated::types::SettlementWatermarks;

        let (mut server, _session, channel_id) = client_server().await;
        let payer = signer(5);
        let sponsor = shared_signer(8);
        server.config.fee_payer_signer = Some(std::sync::Arc::clone(&sponsor));
        server
            .store
            .update_channel(
                &channel_id,
                Box::new({
                    let payer = payer.pubkey().to_string();
                    let rent_payer = sponsor.pubkey().to_string();
                    move |state| {
                        let mut state = state.unwrap();
                        state.payer = payer;
                        state.rent_payer = rent_payer;
                        Ok(state)
                    }
                }),
            )
            .await
            .unwrap();
        let channel = Pubkey::from_str(&channel_id).unwrap();
        let mint = Pubkey::from_str(mints::USDC_MAINNET).unwrap();
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
        let program_id = payment_channels::default_program_id();
        let ix = payment_channels::build_top_up_instruction(
            &payer.pubkey(),
            &channel,
            &mint,
            100,
            &token_program,
            &program_id,
        );
        let mut tx = crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &sponsor.pubkey(),
            &[ix],
            solana_hash::Hash::new_unique(),
            None,
        )
        .unwrap();
        crate::core::signing::sign_versioned_transaction_slot(payer.as_ref(), &mut tx)
            .await
            .unwrap();
        let transaction = crate::core::tx::encode(&tx).unwrap();
        // The confirmed account already reflects deposit=1_100.
        let account = payment_channels::generated::generated::accounts::Channel {
            discriminator: 1,
            version: 1,
            bump: 1,
            status: 0,
            salt: 7,
            deposit: 1_100,
            settlement: SettlementWatermarks {
                settled: 0,
                payout_watermark: 0,
            },
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: server.config.grace_period_seconds,
            distribution_hash: [0; 32],
            payer: payment_channels::to_address(&payer.pubkey()),
            payee: payment_channels::to_address(
                &Pubkey::from_str(&server.config.recipient).unwrap(),
            ),
            authorized_signer: payment_channels::to_address(&signer(1).pubkey()),
            mint: payment_channels::to_address(&mint),
            rent_payer: payment_channels::to_address(&sponsor.pubkey()),
            open_slot: 42,
        };
        let (url, rpc, _send_tx_count) =
            rpc_for_channel_with_options(account, 43, LandedStatus::ConfirmedOnly).await;
        server.config.rpc_url = Some(url.clone());
        let server = server.with_tx_pipeline(crate::core::tx_pipeline::TxPipeline::new(
            url,
            crate::core::tx_pipeline::TxPipelineConfig {
                confirmation_poll_interval: std::time::Duration::from_millis(20),
                confirmation_timeout: std::time::Duration::from_millis(300),
                ..Default::default()
            },
        ));
        let payload = TopUpPayload {
            channel_id: channel_id.clone(),
            additional_amount: "100".into(),
            transaction,
        };

        // The signature confirmed and the aggregate deposit already shows
        // +100, but the signature never finalizes: it may sit on a fork that
        // is abandoned while another top-up lands on the surviving one.
        let result = server.process_topup_with_outcome(&payload).await;
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.to_string().contains("finalization")),
            "a top-up must not be credited before its own signature finalizes"
        );

        let stored = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.deposit, 1_000,
            "no credit may be applied for a transaction that never confirmed"
        );
        assert!(stored.processed_topup_signatures.is_empty());
        rpc.abort();
    }

    #[tokio::test]
    async fn vouchers_advance_refresh_lifecycle_and_replay_once() {
        let (server, mut session, channel_id) = client_server().await;
        let voucher = session.sign_increment(100).await.unwrap();
        let accepted = server
            .verify_voucher(&VoucherPayload {
                channel_id: voucher.data.channel_id.clone(),
                voucher: voucher.clone(),
            })
            .await
            .unwrap();
        assert_eq!(accepted.charged, 100);
        assert!(!accepted.replay);
        let replay = server
            .verify_voucher(&VoucherPayload {
                channel_id: voucher.data.channel_id.clone(),
                voucher: voucher.clone(),
            })
            .await
            .unwrap();
        assert_eq!(replay.charged, 0);
        assert!(replay.replay);
        let stored = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.lifecycle.is_some());
        assert!(stored.last_activity_at > 1);
        // spent_amount debits the fixed per-action price (config.amount == 25
        // here), not the voucher's own 100-unit cumulative jump — and the
        // replay must not double-debit it.
        assert_eq!(stored.spent_amount, 25);

        // The top-level routing key must match the signed voucher's inner
        // channelId — a divergent pair is rejected before any state lookup.
        let mismatch = server
            .verify_voucher(&VoucherPayload {
                channel_id: Pubkey::new_unique().to_string(),
                voucher: voucher.clone(),
            })
            .await;
        assert!(mismatch
            .unwrap_err()
            .to_string()
            .contains("does not match the signed voucher"));

        let mut wrong = voucher;
        wrong.signer = Pubkey::new_unique().to_string();
        assert!(server
            .verify_voucher(&VoucherPayload {
                channel_id: wrong.data.channel_id.clone(),
                voucher: wrong,
            })
            .await
            .is_err());
        let unknown_channel = Pubkey::new_unique().to_string();
        assert!(server
            .verify_voucher(&VoucherPayload {
                channel_id: unknown_channel.clone(),
                voucher: SignedVoucher {
                    data: VoucherData {
                        channel_id: unknown_channel,
                        cumulative_amount: "1".into(),
                        expires_at: None,
                    },
                    signer: signer_address(1),
                    signature: "bad".into(),
                    signature_type: VoucherSignatureType::Ed25519,
                },
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn voucher_below_action_price_is_rejected_and_not_replayable() {
        let (server, mut session, channel_id) = client_server().await;
        // Serve one action at the fixed price (config.amount == 25): the
        // watermark and spent_amount both advance to 25, so the channel's
        // available credit (cumulative - spent) is now 0.
        let first = session.sign_increment(25).await.unwrap();
        let accepted = server
            .verify_voucher(&VoucherPayload {
                channel_id: first.data.channel_id.clone(),
                voucher: first,
            })
            .await
            .unwrap();
        assert_eq!(accepted.charged, 25);

        // A delta-1 voucher (min_voucher_delta is 0, so monotonicity alone
        // admits it) authorizes only 1 new unit — it cannot cover the 25-unit
        // action price. The server must reject it, not serve at full price and
        // settle only the +1 cumulative.
        let underfunded = session.sign_increment(1).await.unwrap();
        let rejected = server
            .verify_voucher(&VoucherPayload {
                channel_id: underfunded.data.channel_id.clone(),
                voucher: underfunded.clone(),
            })
            .await;
        assert!(rejected
            .unwrap_err()
            .to_string()
            .contains("insufficient authorized voucher availability"));

        // The rejection advanced neither the watermark, the highest-voucher
        // signature, nor spent — so a retry of that same under-funded voucher is
        // not mistaken for an already-paid replay and served for free.
        let after_reject = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_reject.cumulative, 25);
        assert_eq!(after_reject.spent_amount, 25);
        let retry = server
            .verify_voucher(&VoucherPayload {
                channel_id: underfunded.data.channel_id.clone(),
                voucher: underfunded,
            })
            .await;
        assert!(retry
            .unwrap_err()
            .to_string()
            .contains("insufficient authorized voucher availability"));

        // A voucher that authorizes a full action's worth of new credit serves
        // and debits normally: the gate only blocks the under-funded case.
        let funded = session.sign_increment(24).await.unwrap(); // 26 -> 50
        let served = server
            .verify_voucher(&VoucherPayload {
                channel_id: funded.data.channel_id.clone(),
                voucher: funded,
            })
            .await
            .unwrap();
        assert_eq!(served.charged, 25);
        let after = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.cumulative, 50);
        assert_eq!(after.spent_amount, 50);
    }

    /// A channel account as the program stores it, at `status` with a forced
    /// close started at `closure_started_at` (`0`: none).
    fn channel_account(
        state: &ChannelState,
        status: u8,
        closure_started_at: i64,
        settled: u64,
    ) -> payment_channels::generated::generated::accounts::Channel {
        let key = |value: &str| payment_channels::to_address(&Pubkey::from_str(value).unwrap());
        payment_channels::generated::generated::accounts::Channel {
            discriminator: 1,
            version: 1,
            bump: 1,
            status,
            salt: 7,
            deposit: state.deposit,
            settlement: payment_channels::generated::generated::types::SettlementWatermarks {
                settled,
                payout_watermark: 0,
            },
            closure_started_at,
            payer_withdrawn_at: 0,
            grace_period: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            distribution_hash: [0; 32],
            payer: key(&state.payer),
            payee: payment_channels::to_address(&Pubkey::new_unique()),
            authorized_signer: key(&state.authorized_signer),
            mint: payment_channels::to_address(&Pubkey::new_unique()),
            rent_payer: key(&state.rent_payer),
            open_slot: 42,
        }
    }

    /// `stored`, last confirmed onchain long ago.
    fn stale(mut stored: ChannelState) -> ChannelState {
        stored.record_onchain_observation(
            OnchainObservation {
                slot: None,
                lifecycle: ObservedLifecycle::Open,
            },
            1,
        );
        stored
    }

    /// A client-signed channel whose snapshot is stale, served by a fixture
    /// RPC holding its account at `status` / `closure_started_at`.
    #[cfg(feature = "server")]
    async fn client_channel_onchain(
        status: u8,
        closure_started_at: i64,
    ) -> (
        SessionServer<MemoryChannelStore>,
        ActiveSession,
        String,
        tokio::task::JoinHandle<()>,
    ) {
        let channel = Pubkey::new_unique();
        let channel_id = channel.to_string();
        let stored = stale(state(channel_id.clone(), signer_address(1)));
        let account = channel_account(&stored, status, closure_started_at, 0);
        let (url, rpc, _) = rpc_for_channel(account, 43).await;
        let mut cfg = config(VoucherSigner::Client);
        cfg.rpc_url = Some(url);
        (
            seeded_server(cfg, stored).await,
            ActiveSession::new(channel, signer(1)),
            channel_id,
            rpc,
        )
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn a_forced_close_started_onchain_stops_vouchers_and_makes_the_close_due() {
        let started_at = now_unix_secs() - 10;
        let (server, mut session, channel_id, rpc) = client_channel_onchain(2, started_at).await;
        let voucher = session.sign_increment(100).await.unwrap();
        let error = server
            .verify_voucher(&voucher_payload(voucher))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("closing onchain"), "{error}");

        let after = stored(&server, &channel_id).await;
        assert_eq!(after.cumulative, 0);
        assert_eq!(after.spent_amount, 0);
        assert_eq!(after.close_requested_at, Some(started_at as u64));
        let due = after
            .lifecycle
            .expect("closing channel is scheduled")
            .close_after;
        assert!(due <= now_unix_secs() as u64 * 1_000);

        // The record alone now refuses every further voucher.
        rpc.abort();
        let next = session.sign_increment(100).await.unwrap();
        let error = server
            .verify_voucher_for_amount(&voucher_payload(next), 25)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("close is pending"), "{error}");
        assert!(server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 10))
            .await
            .is_err());
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn an_open_channel_read_renews_the_snapshot_and_admits_the_voucher() {
        let (server, mut session, channel_id, rpc) = client_channel_onchain(0, 0).await;
        let voucher = session.sign_increment(100).await.unwrap();
        let accepted = server
            .verify_voucher(&voucher_payload(voucher))
            .await
            .unwrap();
        assert_eq!(accepted.charged, 100);
        let after = stored(&server, &channel_id).await;
        assert!(after.close_requested_at.is_none());
        assert!(now_unix_secs() as u64 - after.onchain_observed_at() <= 1);

        // Inside the window the snapshot stands in for a read.
        rpc.abort();
        let next = session.sign_increment(100).await.unwrap();
        assert_eq!(
            server
                .verify_voucher(&voucher_payload(next))
                .await
                .unwrap()
                .charged,
            100
        );
        assert!(server
            .begin_delivery(DeliveryRequest::new(channel_id, 10))
            .await
            .is_ok());
    }

    /// A lagging RPC node can still show a channel open after the payer
    /// started closing it: a read from a bank older than the recorded one
    /// never renews the charge window.
    #[cfg(feature = "server")]
    #[tokio::test]
    async fn a_read_behind_the_recorded_slot_never_renews_the_snapshot() {
        let channel = Pubkey::new_unique();
        let channel_id = channel.to_string();
        let mut record = state(channel_id.clone(), signer_address(1));
        record.record_onchain_observation(
            OnchainObservation {
                slot: Some(100),
                lifecycle: ObservedLifecycle::Open,
            },
            1,
        );
        let account = channel_account(&record, 0, 0, 0);
        // The node answers from slot 43, behind the recorded 100.
        let (url, _rpc, _) = rpc_for_channel(account, 43).await;
        let mut cfg = config(VoucherSigner::Client);
        cfg.rpc_url = Some(url);
        let server = seeded_server(cfg, record).await;
        let mut session = ActiveSession::new(channel, signer(1));
        let voucher = session.sign_increment(100).await.unwrap();
        assert!(server
            .verify_voucher(&voucher_payload(voucher))
            .await
            .is_err());
        let after = stored(&server, &channel_id).await;
        assert_eq!(after.cumulative, 0);
        assert_eq!(after.onchain_observed_at(), 1, "the window was not renewed");
        assert_eq!(after.onchain_observed_slot(), 100);
    }

    #[tokio::test]
    async fn a_stale_snapshot_without_a_read_refuses_every_charge() {
        let channel = Pubkey::new_unique();
        let channel_id = channel.to_string();
        let server = seeded_server(
            config(VoucherSigner::Client),
            stale(state(channel_id.clone(), signer_address(1))),
        )
        .await;
        let mut session = ActiveSession::new(channel, signer(1));
        let voucher = session.sign_increment(100).await.unwrap();
        assert!(server
            .verify_voucher(&voucher_payload(voucher))
            .await
            .is_err());
        assert!(server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 10))
            .await
            .is_err());
        let after = stored(&server, &channel_id).await;
        assert_eq!(after.cumulative, 0);
        assert!(after.pending_deliveries.is_empty());

        let cfg = config(VoucherSigner::Operator);
        let channel_id = Pubkey::new_unique().to_string();
        let proof = SessionAuthentication::sign("opening", &channel_id, &key(3)).unwrap();
        let mut bound = stale(state(channel_id.clone(), cfg.operator.clone()));
        bound.payer = proof.payer.clone();
        bound.authentication = Some(serde_json::to_string(&proof).unwrap());
        bound.voucher_signer = "operator".into();
        let server = seeded_server(cfg, bound).await;
        let payload = UsePayload {
            channel_id: channel_id.clone(),
            authentication: proof,
        };
        assert!(server
            .process_use(&payload, "use-1", "request-1")
            .await
            .is_err());
        assert!(server
            .authenticate_use(&payload, "use-1", "request-1")
            .await
            .is_err());
        assert_eq!(stored(&server, &channel_id).await.cumulative, 0);
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn operator_use_stops_once_the_channel_is_closing_onchain() {
        let cfg = config(VoucherSigner::Operator);
        let channel_id = Pubkey::new_unique().to_string();
        let proof = SessionAuthentication::sign("opening", &channel_id, &key(3)).unwrap();
        let mut bound = stale(state(channel_id.clone(), cfg.operator.clone()));
        bound.payer = proof.payer.clone();
        bound.authentication = Some(serde_json::to_string(&proof).unwrap());
        bound.voucher_signer = "operator".into();
        let account = channel_account(&bound, 2, now_unix_secs() - 5, 0);
        let (url, rpc, _) = rpc_for_channel(account, 43).await;
        let mut cfg = cfg;
        cfg.rpc_url = Some(url);
        let server = seeded_server(cfg, bound).await;
        let payload = UsePayload {
            channel_id: channel_id.clone(),
            authentication: proof,
        };
        let error = server
            .process_use(&payload, "use-1", "request-1")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("closing onchain"), "{error}");
        assert!(server
            .authenticate_use(&payload, "use-2", "request-2")
            .await
            .is_err());
        let after = stored(&server, &channel_id).await;
        assert_eq!(after.cumulative, 0);
        assert!(after.close_requested_at.is_some());
        rpc.abort();
    }

    #[test]
    fn admission_requires_a_snapshot_inside_the_window() {
        let fresh = state(Pubkey::new_unique().to_string(), signer_address(1));
        assert!(require_fresh_snapshot(&fresh, 30).is_ok());
        assert!(require_fresh_snapshot(&stale(fresh), 30).is_err());
    }

    #[test]
    fn channel_status_maps_to_the_observed_lifecycle() {
        assert_eq!(
            ObservedLifecycle::of_channel(0, 0, 9),
            ObservedLifecycle::Open
        );
        assert_eq!(
            ObservedLifecycle::of_channel(2, 5, 9),
            ObservedLifecycle::Closing { started_at: 5 }
        );
        assert_eq!(
            ObservedLifecycle::of_channel(1, 0, 9),
            ObservedLifecycle::Terminal {
                started_at: Some(1)
            }
        );
        assert_eq!(
            ObservedLifecycle::of_channel(3, 0, 9),
            ObservedLifecycle::Terminal {
                started_at: Some(1)
            }
        );
    }

    #[tokio::test]
    async fn deliveries_commit_partially_and_are_idempotent() {
        let (server, mut session, channel_id) = client_server().await;
        let mut request = DeliveryRequest::new(channel_id.clone(), 125);
        request.delivery_id = Some("delivery-1".into());
        request.commit_url = Some("/commit".into());
        request.proof = Some("proof".into());
        let directive = server.begin_delivery(request).await.unwrap();
        assert_eq!(directive.amount_base_units().unwrap(), 125);
        assert_eq!(directive.sequence, 1);
        let duplicate = DeliveryRequest {
            session_id: channel_id.clone(),
            amount: 1,
            delivery_id: Some("delivery-1".into()),
            commit_url: None,
            proof: None,
            expires_at: None,
        };
        assert!(server.begin_delivery(duplicate).await.is_err());

        server
            .record_delivery_usage(&channel_id, &directive.delivery_id, 75)
            .await
            .unwrap();
        let payload = CommitPayload {
            delivery_id: directive.delivery_id,
            voucher: session.sign_increment(75).await.unwrap(),
        };
        let receipt = server.process_commit(&payload).await.unwrap();
        assert_eq!(receipt.amount, "75");
        assert_eq!(receipt.status, CommitStatus::Committed);
        assert_eq!(
            server.process_commit(&payload).await.unwrap().status,
            CommitStatus::Replayed
        );
        assert!(server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 0))
            .await
            .is_err());
        assert!(server
            .begin_delivery(DeliveryRequest::new(channel_id, 1_000))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn reserved_delivery_commits_after_close_request_until_watermark_is_frozen() {
        let (server, mut session, channel_id) = client_server().await;
        let first = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 100))
            .await
            .unwrap();
        let second = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 50))
            .await
            .unwrap();
        // An idle-close worker claims the close while both deliveries are live.
        server
            .store
            .update_channel(
                &channel_id,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    assert!(state.has_blocking_authorization(unix_now_i64()));
                    state.close_requested_at = Some(1);
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        assert!(server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 1))
            .await
            .unwrap_err()
            .to_string()
            .contains("close is pending"));

        // The served delivery's charge still lands in the watermark.
        let receipt = server
            .process_commit(&CommitPayload {
                delivery_id: first.delivery_id,
                voucher: session.sign_increment(100).await.unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(receipt.status, CommitStatus::Committed);
        assert_eq!(receipt.cumulative, "100");

        // Once the finalizer fixes the sealed amount, later commits are refused.
        server
            .store
            .update_channel(
                &channel_id,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    let cumulative = state.cumulative;
                    state.freeze_watermark_at(cumulative);
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let fenced = server
            .process_commit(&CommitPayload {
                delivery_id: second.delivery_id,
                voucher: session.sign_increment(50).await.unwrap(),
            })
            .await
            .unwrap_err();
        assert!(fenced
            .to_string()
            .contains("final watermark is fixed at 100"));
        let stored = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.cumulative, 100);
    }

    #[tokio::test]
    async fn client_close_fences_commits_at_the_final_voucher() {
        let (server, mut session, channel_id) = client_server().await;
        let pending = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 50))
            .await
            .unwrap();
        let params = server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: None,
                voucher: Some(session.sign_increment(100).await.unwrap()),
            })
            .await
            .unwrap();
        assert_eq!(params.settled, 100);
        let stored = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.final_cumulative, Some(100));
        // The final voucher already paid for the live delivery, so it cannot
        // commit on top of the sealed amount.
        assert!(stored.pending_deliveries.is_empty());
        assert!(server
            .process_commit(&CommitPayload {
                delivery_id: pending.delivery_id,
                voucher: session.sign_increment(50).await.unwrap(),
            })
            .await
            .is_err());
        let stored = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.cumulative, 100);
    }

    #[tokio::test]
    async fn commits_refresh_activity_and_lifecycle() {
        let (server, mut session, channel_id) = client_server().await;
        // Age the channel: stale activity watermark and an idle-close deadline
        // already in the past, as if no voucher had arrived since open.
        server
            .store
            .update_channel(
                &channel_id,
                Box::new(|state_opt| {
                    let mut state = state_opt.unwrap();
                    state.last_activity_at = 1;
                    if let Some(lifecycle) = state.lifecycle.as_mut() {
                        lifecycle.close_after = 1;
                    }
                    Ok(state)
                }),
            )
            .await
            .unwrap();

        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 50))
            .await
            .unwrap();
        let payload = CommitPayload {
            delivery_id: directive.delivery_id,
            voucher: session.sign_increment(50).await.unwrap(),
        };
        let receipt = server.process_commit(&payload).await.unwrap();
        assert_eq!(receipt.status, CommitStatus::Committed);

        let stored = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.last_activity_at > 1);
        // A committed delivery debits spent_amount by the delivered amount,
        // matching the operator `use` and client `voucher` paths.
        assert_eq!(stored.spent_amount, 50);
        let lifecycle = stored
            .lifecycle
            .expect("commit must re-arm the idle-close deadline");
        assert!(lifecycle.close_after > 1);

        // The idempotent replay is not fresh activity: it must not advance the
        // watermark past what the committed path recorded, and must not
        // double-debit spent_amount.
        let before_replay = stored.last_activity_at;
        assert_eq!(
            server.process_commit(&payload).await.unwrap().status,
            CommitStatus::Replayed
        );
        let after_replay = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_replay.last_activity_at, before_replay);
        assert_eq!(after_replay.spent_amount, 50);
    }

    #[tokio::test]
    async fn operator_use_and_close_require_the_opening_proof() {
        let cfg = config(VoucherSigner::Operator);
        let channel_id = Pubkey::new_unique().to_string();
        let payer = key(3);
        let proof = SessionAuthentication::sign("opening", &channel_id, &payer).unwrap();
        let mut stored = state(channel_id.clone(), cfg.operator.clone());
        stored.payer = proof.payer.clone();
        stored.authentication = Some(serde_json::to_string(&proof).unwrap());
        stored.voucher_signer = "operator".into();
        let store = MemoryChannelStore::new();
        store.put_channel(&channel_id, stored).await.unwrap();
        let server = SessionServer::new(cfg, store);
        let payload = UsePayload {
            channel_id: channel_id.clone(),
            authentication: proof.clone(),
        };
        let first = server
            .process_use(&payload, "use-1", "request-1")
            .await
            .unwrap();
        assert_eq!(first.voucher.data.cumulative_amount, "25");
        assert!(!first.replay);
        let replay = server
            .process_use(&payload, "use-2", "request-1")
            .await
            .unwrap();
        assert_eq!(replay.voucher.data.cumulative_amount, "25");
        assert!(replay.replay);
        assert!(server.process_use(&payload, "use-3", "").await.is_err());

        let params = server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: Some(proof),
                voucher: None,
            })
            .await
            .unwrap();
        assert_eq!(params.channel_id.to_string(), channel_id);
        assert!(server
            .process_close(&ClosePayload {
                channel_id,
                authentication: None,
                voucher: None,
            })
            .await
            .is_err());
    }

    /// draft-solana-session-00 §Action "voucher": "In operator mode,
    /// vouchers are operator-generated settlement artifacts and MUST NOT
    /// authenticate the caller." A valid operator-signed voucher (public
    /// settlement data) presented as a voucher action is refused, and the
    /// watermark does not move.
    #[tokio::test]
    async fn operator_session_refuses_a_voucher_action() {
        use ed25519_dalek::Signer;
        let cfg = config(VoucherSigner::Operator);
        let channel = Pubkey::new_unique().to_string();
        let mut operated = state(channel.clone(), cfg.operator.clone());
        operated.voucher_signer = "operator".into();
        let server = seeded_server(cfg, operated).await;
        let data = VoucherData {
            channel_id: channel.clone(),
            cumulative_amount: "25".into(),
            expires_at: None,
        };
        let signature = key(9).sign(&data.message_bytes().unwrap());
        let voucher = SignedVoucher {
            data,
            signer: server.config.operator.clone(),
            signature: bs58::encode(signature.to_bytes()).into_string(),
            signature_type: VoucherSignatureType::Ed25519,
        };
        let payload = VoucherPayload {
            channel_id: channel.clone(),
            voucher,
        };
        for result in [
            server.verify_voucher(&payload).await,
            server.verify_voucher_for_amount(&payload, 25).await,
        ] {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("does not authenticate an operator-signed session"));
        }
        assert_eq!(stored(&server, &channel).await.cumulative, 0);
    }

    /// An operator-signed channel bound at open to `proof`, plus the
    /// operator's signer (`key(9)`, the `config` operator).
    async fn operator_channel() -> (
        std::sync::Arc<SessionServer<MemoryChannelStore>>,
        UsePayload,
        MemorySigner,
    ) {
        let cfg = config(VoucherSigner::Operator);
        let channel_id = Pubkey::new_unique().to_string();
        let proof = SessionAuthentication::sign("opening", &channel_id, &key(3)).unwrap();
        let mut bound = state(channel_id.clone(), cfg.operator.clone());
        bound.payer = proof.payer.clone();
        bound.authentication = Some(serde_json::to_string(&proof).unwrap());
        bound.voucher_signer = "operator".into();
        let server = std::sync::Arc::new(seeded_server(cfg, bound).await);
        let payload = UsePayload {
            channel_id,
            authentication: proof,
        };
        (server, payload, memory_signer(9))
    }

    fn memory_signer(seed: u8) -> MemorySigner {
        let key = key(seed);
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(key.as_bytes());
        bytes[32..].copy_from_slice(key.verifying_key().as_bytes());
        MemorySigner::from_bytes(&bytes).unwrap()
    }

    /// draft-solana-session-00 §Debit Processing step 5: "For `operator`,
    /// sign a voucher for `acceptedCumulative + cost` and atomically persist
    /// that voucher, the new `acceptedCumulative`, and `spentAmount += cost`."
    /// The cost here is metered after serving, not the challenged price.
    #[tokio::test]
    async fn operator_charge_signs_and_persists_the_metered_amount() {
        let (server, payload, operator) = operator_channel().await;
        let first_request = authenticate(&server, &payload, "request-1").await;
        assert_eq!(stored(&server, &payload.channel_id).await.cumulative, 0);

        let first = server
            .charge_operator_request(&first_request, &operator, 7, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(
            (first.previous_cumulative, first.cumulative, first.replay),
            (0, 7, false)
        );
        let second_request = authenticate(&server, &payload, "request-2").await;
        let second = server
            .charge_operator_request(&second_request, &operator, 40, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!((second.previous_cumulative, second.cumulative), (7, 47));

        let record = stored(&server, &payload.channel_id).await;
        assert_eq!(record.cumulative, 47);
        assert_eq!(record.spent_amount, 47);
        assert_eq!(
            record.highest_voucher_signature.as_deref(),
            Some(second.voucher.signature.as_str())
        );
        assert_eq!(second.voucher.data.cumulative_amount, "47");
        assert_eq!(second.voucher.signer, server.config.operator);
        // The persisted voucher is the operator's settlement artifact: it
        // verifies under the channel's authorized signer.
        verify_signature(&second.voucher, &record.authorized_signer, 0).unwrap();
    }

    /// Only a `use` proof bound at open authenticates a metered request, and
    /// only on an operator-signed session.
    #[tokio::test]
    async fn operator_charge_requires_the_opening_proof() {
        let (server, payload, _) = operator_channel().await;
        let other = UsePayload {
            channel_id: payload.channel_id.clone(),
            authentication: SessionAuthentication::sign("opening", &payload.channel_id, &key(4))
                .unwrap(),
        };
        assert!(server
            .authenticate_use(&other, "opening", "request-1")
            .await
            .unwrap_err()
            .to_string()
            .contains("does not match the proof bound at open"));

        let client = SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new());
        assert!(client
            .authenticate_use(&payload, "opening", "request-1")
            .await
            .unwrap_err()
            .to_string()
            .contains("only valid for operator-signed sessions"));
        assert!(server
            .authenticate_use(&payload, "opening", "")
            .await
            .unwrap_err()
            .to_string()
            .contains("requires an Idempotency-Key"));
    }

    /// Nothing advances the watermark for a zero amount, a charge beyond the
    /// deposit, a signer other than the operator, a guard that refuses, or a
    /// channel whose close is pending.
    #[tokio::test]
    async fn refused_operator_charges_leave_the_watermark() {
        let (server, payload, operator) = operator_channel().await;
        let authenticated = authenticate(&server, &payload, "request-1").await;
        let refusals = [
            server
                .charge_operator_request(&authenticated, &operator, 0, |_| Ok(()))
                .await,
            server
                .charge_operator_request(&authenticated, &operator, 1_001, |_| Ok(()))
                .await,
            server
                .charge_operator_request(&authenticated, &memory_signer(5), 5, |_| Ok(()))
                .await,
            server
                .charge_operator_request(&authenticated, &operator, 5, |_| {
                    Err(Error::Other("lease expired".into()))
                })
                .await,
        ];
        for (refusal, expected) in refusals.into_iter().zip([
            "must be positive",
            "insufficient channel availability",
            "does not match configured operator",
            "lease expired",
        ]) {
            let message = refusal.unwrap_err().to_string();
            assert!(message.contains(expected), "{message}");
        }

        server
            .store
            .update_channel(
                &payload.channel_id,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.close_requested_at = Some(1);
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        assert!(server
            .charge_operator_request(&authenticated, &operator, 5, |_| Ok(()))
            .await
            .unwrap_err()
            .to_string()
            .contains("close is pending"));
        let record = stored(&server, &payload.channel_id).await;
        assert_eq!((record.cumulative, record.spent_amount), (0, 0));
    }

    /// Concurrent charges each sign from the watermark they read and commit
    /// only if it has not moved, so every charge lands once and none is lost
    /// or double-counted. Multi-threaded, so the charges really interleave:
    /// without the watermark fence or the retry this fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_operator_charges_each_land_once() {
        let (server, payload, operator) = operator_channel().await;
        let operator = std::sync::Arc::new(operator);
        let charges = (1..=6_u64).map(|amount| {
            let server = std::sync::Arc::clone(&server);
            let payload = payload.clone();
            let operator = std::sync::Arc::clone(&operator);
            tokio::spawn(async move {
                let request = format!("request-{amount}");
                let authenticated = authenticate(&server, &payload, &request).await;
                server
                    .charge_operator_request(&authenticated, operator.as_ref(), amount, |_| Ok(()))
                    .await
            })
        });
        let mut landed: Vec<(u64, u64)> = Vec::new();
        for charge in charges.collect::<Vec<_>>() {
            let charge = charge.await.unwrap().unwrap();
            landed.push((charge.previous_cumulative, charge.cumulative));
        }
        landed.sort();
        // The charges chain end to end: each starts where another ended.
        assert_eq!(landed.first().unwrap().0, 0);
        assert!(landed.windows(2).all(|pair| pair[0].1 == pair[1].0));
        let record = stored(&server, &payload.channel_id).await;
        assert_eq!(record.cumulative, 21);
        assert_eq!(record.spent_amount, 21);
    }

    /// A stream charges one authenticated request again and again, so every
    /// charge, not only the authentication, needs a fresh channel read.
    #[tokio::test]
    async fn every_operator_charge_needs_a_fresh_channel_read() {
        let (server, payload, operator) = operator_channel().await;
        let request = authenticate(&server, &payload, "request-1").await;
        let first = server
            .charge_operator_request(&request, &operator, 7, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(first.cumulative, 7);

        server
            .store
            .update_channel(
                &payload.channel_id,
                Box::new(|state| Ok(stale(state.unwrap()))),
            )
            .await
            .unwrap();
        let error = server
            .charge_operator_request(&request, &operator, 20, |_| Ok(()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("onchain"), "{error}");
        assert_eq!(stored(&server, &payload.channel_id).await.cumulative, 7);
    }

    async fn authenticate(
        server: &SessionServer<impl ChannelStore>,
        payload: &UsePayload,
        idempotency_key: &str,
    ) -> AuthenticatedUse {
        server
            .authenticate_use(payload, "opening", idempotency_key)
            .await
            .unwrap()
    }

    /// draft-solana-session-00 §Concurrency and Idempotency: "Replaying an
    /// already processed request MAY return the cached receipt and MUST NOT
    /// change channel state", and servers "MUST NOT increment spentAmount
    /// twice for a duplicate idempotent request". A request is charged up to
    /// its running total: each charge pays only the difference, a retry at or
    /// below the total reached is answered from the record, and the request
    /// stays one record however often it is charged.
    #[tokio::test]
    async fn a_request_is_charged_up_to_its_running_total() {
        let (server, payload, operator) = operator_channel().await;
        let request = authenticate(&server, &payload, "request-1").await;
        let first = server
            .charge_operator_request(&request, &operator, 7, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(
            (first.charged, first.cumulative, first.replay),
            (7, 7, false)
        );

        // The retry after a lost response authenticates again, as a fresh
        // request would, and charges nothing.
        let retry = authenticate(&server, &payload, "request-1").await;
        let replay = server
            .charge_operator_request(&retry, &operator, 7, |_| Ok(()))
            .await
            .unwrap();
        assert!(replay.replay);
        assert_eq!((replay.charged, replay.cumulative), (0, 7));
        assert_eq!(replay.voucher.signature, first.voucher.signature);

        // The stream goes on: only the difference is charged.
        let more = server
            .charge_operator_request(&request, &operator, 10, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(
            (more.previous_cumulative, more.charged, more.cumulative),
            (7, 3, 10)
        );
        // A stale retry of an earlier step is answered with the latest.
        let stale = server
            .charge_operator_request(&retry, &operator, 7, |_| Ok(()))
            .await
            .unwrap();
        assert!(stale.replay);
        assert_eq!((stale.request_total, stale.cumulative), (10, 10));

        let record = stored(&server, &payload.channel_id).await;
        assert_eq!((record.cumulative, record.spent_amount), (10, 10));
        assert_eq!(record.processed_uses.len(), 1, "one record per request");

        // The key names one request: reused under another challenge it is
        // refused, not answered with this request's charge.
        let other = server
            .authenticate_use(&payload, "another-challenge", "request-1")
            .await
            .unwrap();
        let reused = server
            .charge_operator_request(&other, &operator, 12, |_| Ok(()))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            reused.contains("already used for a different request"),
            "{reused}"
        );
        let record = stored(&server, &payload.channel_id).await;
        assert_eq!((record.cumulative, record.spent_amount), (10, 10));
    }

    /// A channel remembers the most recently charged requests, not every
    /// request it ever served.
    #[tokio::test]
    async fn the_request_record_is_bounded() {
        let (server, payload, operator) = operator_channel().await;
        for i in 0..MAX_PROCESSED_USES + 10 {
            let request = authenticate(&server, &payload, &format!("request-{i}")).await;
            for total in 1..=2 {
                server
                    .charge_operator_request(&request, &operator, total, |_| Ok(()))
                    .await
                    .unwrap();
            }
        }
        let record = stored(&server, &payload.channel_id).await;
        assert_eq!(record.processed_uses.len(), MAX_PROCESSED_USES);
        assert_eq!(
            record.processed_uses.last().unwrap().idempotency_key,
            format!("request-{}", MAX_PROCESSED_USES + 9)
        );
        assert!(record
            .processed_uses
            .iter()
            .all(|entry| entry.idempotency_key != "request-0"));
        assert_eq!(record.spent_amount, 2 * (MAX_PROCESSED_USES as u64 + 10));
    }

    /// A store whose next update loses its compare-and-set the way the Redis
    /// store's does: another writer's update lands between the read and the
    /// write, and the write reports a concurrent update.
    struct LosingStore {
        inner: MemoryChannelStore,
        /// The update that lands first, applied on the next `update_channel`.
        rival: std::sync::Mutex<Option<ChannelUpdater>>,
    }

    type ChannelUpdater = Box<
        dyn FnOnce(Option<ChannelState>) -> std::result::Result<ChannelState, StoreError> + Send,
    >;
    type StoreFuture<'a, T> = std::pin::Pin<
        Box<dyn std::future::Future<Output = std::result::Result<T, StoreError>> + Send + 'a>,
    >;

    impl ChannelStore for LosingStore {
        fn list_channels(&self) -> StoreFuture<'_, Vec<ChannelState>> {
            self.inner.list_channels()
        }
        fn list_channel_ids(&self) -> StoreFuture<'_, Vec<String>> {
            self.inner.list_channel_ids()
        }
        fn get_channel(&self, channel_id: &str) -> StoreFuture<'_, Option<ChannelState>> {
            self.inner.get_channel(channel_id)
        }
        fn put_channel(&self, channel_id: &str, state: ChannelState) -> StoreFuture<'_, ()> {
            self.inner.put_channel(channel_id, state)
        }
        fn delete_channel(&self, channel_id: &str) -> StoreFuture<'_, ()> {
            self.inner.delete_channel(channel_id)
        }
        fn delete_channel_if(
            &self,
            channel_id: &str,
            approve: crate::core::store::ChannelPredicate,
        ) -> StoreFuture<'_, bool> {
            self.inner.delete_channel_if(channel_id, approve)
        }
        fn update_channel(
            &self,
            channel_id: &str,
            updater: ChannelUpdater,
        ) -> StoreFuture<'_, ChannelState> {
            let channel_id = channel_id.to_string();
            let rival = self.rival.lock().unwrap().take();
            Box::pin(async move {
                let Some(rival) = rival else {
                    return self.inner.update_channel(&channel_id, updater).await;
                };
                let read = self.inner.get_channel(&channel_id).await?;
                updater(read)?;
                self.inner.update_channel(&channel_id, rival).await?;
                Err(StoreError::Internal(
                    "Concurrent channel update; retry the request".to_string(),
                ))
            })
        }
        fn read_channel(
            &self,
            channel_id: &str,
            reader: Box<
                dyn FnOnce(Option<&ChannelState>) -> std::result::Result<(), StoreError> + Send,
            >,
        ) -> StoreFuture<'_, ()> {
            self.inner.read_channel(channel_id, reader)
        }
        fn mutate_channel(
            &self,
            channel_id: &str,
            seed: Option<ChannelState>,
            mutator: Box<
                dyn FnOnce(&mut ChannelState) -> std::result::Result<(), StoreError> + Send,
            >,
        ) -> StoreFuture<'_, ()> {
            self.inner.mutate_channel(channel_id, seed, mutator)
        }
        fn touch_channel_lifecycle(
            &self,
            channel_id: &str,
            lifecycle: ChannelLifecycle,
        ) -> StoreFuture<'_, ChannelState> {
            self.inner.touch_channel_lifecycle(channel_id, lifecycle)
        }
        fn advance_cumulative(
            &self,
            channel_id: &str,
            expected: u64,
            new: u64,
        ) -> StoreFuture<'_, bool> {
            self.inner.advance_cumulative(channel_id, expected, new)
        }
        fn update_deposit(&self, channel_id: &str, new_deposit: u64) -> StoreFuture<'_, ()> {
            self.inner.update_deposit(channel_id, new_deposit)
        }
        fn mark_sealed(&self, channel_id: &str) -> StoreFuture<'_, ()> {
            self.inner.mark_sealed(channel_id)
        }
        fn mark_finalized(&self, channel_id: &str) -> StoreFuture<'_, ()> {
            self.inner.mark_finalized(channel_id)
        }
    }

    /// A charge whose write loses the compare-and-set to another charge is
    /// retried from the watermark that landed, not reported as an error.
    #[tokio::test]
    async fn a_charge_that_loses_its_write_retries_from_the_new_watermark() {
        let (seeded, payload, operator) = operator_channel().await;
        let channel = stored(&seeded, &payload.channel_id).await;
        let store = std::sync::Arc::new(LosingStore {
            inner: MemoryChannelStore::new(),
            rival: std::sync::Mutex::new(None),
        });
        store
            .put_channel(&payload.channel_id, channel)
            .await
            .unwrap();
        let server = SessionServer::new(config(VoucherSigner::Operator), store.clone());
        let request = authenticate(&server, &payload, "request-1").await;
        *store.rival.lock().unwrap() = Some(Box::new(|state| {
            let mut state = state.unwrap();
            state.cumulative += 5;
            state.spent_amount += 5;
            Ok(state)
        }));

        let charge = server
            .charge_operator_request(&request, &operator, 7, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!((charge.previous_cumulative, charge.cumulative), (5, 12));
        let record = stored(&server, &payload.channel_id).await;
        assert_eq!((record.cumulative, record.spent_amount), (12, 12));
    }

    /// The open transaction checks name what disagrees: an argument, the
    /// channel account, or an instruction outside the open.
    #[cfg(feature = "server")]
    #[tokio::test]
    async fn channel_transaction_errors_name_the_disagreeing_part() {
        let server = SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new());
        let open = valid_open(&server);
        let params = server.payment_channel_open_params(&open).unwrap();
        let blockhash = solana_hash::Hash::new_from_array([7; 32]);
        let check = |instructions: Vec<solana_instruction::Instruction>| {
            let message = solana_message::v0::Message::try_compile(
                &params.rent_payer,
                &instructions,
                &[],
                blockhash,
            )
            .unwrap();
            let tx = solana_transaction::versioned::VersionedTransaction {
                signatures: vec![
                    Signature::default();
                    usize::from(message.header.num_required_signatures)
                ],
                message: solana_message::VersionedMessage::V0(message),
            };
            let mut open = open.clone();
            open.transaction = crate::core::tx::encode(&tx).unwrap();
            let server = &server;
            let params = params.clone();
            async move {
                server
                    .prepare_open(
                        &open,
                        &params,
                        SessionOpenContext {
                            challenge_id: "opening",
                            expires: None,
                            recent_blockhash: &blockhash.to_string(),
                            recent_slot: params.open_slot,
                        },
                    )
                    .await
                    .unwrap_err()
                    .to_string()
            }
        };
        let honest = payment_channels::build_open_instruction(&params);
        let mut argument = honest.clone();
        argument.data[9] ^= 1;
        assert!(check(vec![argument])
            .await
            .contains("open instruction arguments do not match the credential"));
        let mut channel = honest.clone();
        channel.accounts[OPEN_CHANNEL_ACCOUNT].pubkey = Pubkey::new_unique();
        assert!(check(vec![channel])
            .await
            .contains("channel account does not match the derived channel PDA"));
        let memo = solana_instruction::Instruction {
            program_id: payment_channels::memo_program_id(),
            accounts: vec![solana_instruction::AccountMeta::new(
                Pubkey::new_unique(),
                false,
            )],
            data: b"x".to_vec(),
        };
        assert!(check(vec![honest, memo])
            .await
            .contains("open transaction contains an unexpected instruction"));
    }

    #[tokio::test]
    async fn wiped_or_pre_binding_rows_report_a_distinct_error() {
        let cfg = config(VoucherSigner::Operator);
        let channel_id = Pubkey::new_unique().to_string();
        let payer = key(3);
        let proof = SessionAuthentication::sign("opening", &channel_id, &payer).unwrap();
        // A record rewritten by a pre-binding writer: the three binding
        // fields decode to their serde defaults, indistinguishable from a
        // record that predates proof binding.
        let mut stored = state(channel_id.clone(), cfg.operator.clone());
        stored.payer = proof.payer.clone();
        stored.opening_challenge_id = String::new();
        stored.authentication = None;
        stored.voucher_signer = String::new();
        let store = MemoryChannelStore::new();
        store.put_channel(&channel_id, stored).await.unwrap();
        let server = SessionServer::new(cfg, store);

        let use_err = server
            .process_use(
                &UsePayload {
                    channel_id: channel_id.clone(),
                    authentication: proof.clone(),
                },
                "use-1",
                "request-1",
            )
            .await
            .unwrap_err();
        assert!(
            use_err.to_string().contains("predates proof binding"),
            "got: {use_err}"
        );

        let close_err = server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: Some(proof.clone()),
                voucher: None,
            })
            .await
            .unwrap_err();
        assert!(
            close_err.to_string().contains("predates proof binding"),
            "got: {close_err}"
        );

        // Same split when the operator marker survived but the binding did
        // not (a pre-binding record written after voucher_signer existed).
        let channel_id_2 = Pubkey::new_unique().to_string();
        let mut stored = state(channel_id_2.clone(), server.config.operator.clone());
        stored.payer = proof.payer.clone();
        stored.opening_challenge_id = String::new();
        stored.authentication = None;
        stored.voucher_signer = "operator".into();
        server
            .store
            .put_channel(&channel_id_2, stored)
            .await
            .unwrap();
        let close_err = server
            .process_close(&ClosePayload {
                channel_id: channel_id_2,
                authentication: Some(proof),
                voucher: None,
            })
            .await
            .unwrap_err();
        assert!(
            close_err.to_string().contains("predates proof binding"),
            "got: {close_err}"
        );
    }

    #[tokio::test]
    async fn close_distributes_rent_to_the_rent_payer_recorded_at_open() {
        let (server, mut session, channel_id) = client_server().await;
        let operator = Pubkey::from_str(&server.config.operator).unwrap();
        let client_payer = Pubkey::new_unique();
        server
            .store
            .update_channel(
                &channel_id,
                Box::new(move |state| {
                    let mut state = state.unwrap();
                    // Client-funded open: the payer funded the channel rent.
                    state.payer = client_payer.to_string();
                    state.rent_payer = client_payer.to_string();
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let params = server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: None,
                voucher: Some(session.sign_increment(100).await.unwrap()),
            })
            .await
            .unwrap();
        assert_eq!(params.rent_payer, Some(client_payer));
        let treasury = Pubkey::new_unique();
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
        let ix = params
            .distribute_instruction(&treasury, &token_program)
            .unwrap();
        // Accounts: channel, payer, rent_payer, …
        assert_eq!(ix.accounts[2].pubkey, client_payer);
        assert!(ix.accounts.iter().all(|meta| meta.pubkey != operator));

        let mut missing = params;
        missing.rent_payer = None;
        assert!(missing
            .distribute_instruction(&treasury, &token_program)
            .unwrap_err()
            .to_string()
            .contains("rent payer"));
    }

    #[tokio::test]
    async fn client_close_seal_and_store_lifecycle_are_consistent() {
        let (server, mut session, channel_id) = client_server().await;
        let voucher = session.sign_increment(100).await.unwrap();
        // Routing-key invariant on close: a final voucher signed for another
        // channel must be rejected before any state transition.
        let foreign = server
            .process_close(&ClosePayload {
                channel_id: Pubkey::new_unique().to_string(),
                authentication: None,
                voucher: Some(voucher.clone()),
            })
            .await;
        assert!(foreign
            .unwrap_err()
            .to_string()
            .contains("does not match the close channelId"));
        let params = server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: None,
                voucher: Some(voucher),
            })
            .await
            .unwrap();
        assert_eq!(params.settled, 100);
        assert_eq!(
            params
                .settle_instructions(&Pubkey::from_str(&server.config.operator).unwrap())
                .unwrap()
                .len(),
            2
        );
        assert!(server
            .process_topup(&TopUpPayload {
                channel_id: channel_id.clone(),
                additional_amount: "1".into(),
                transaction: "tx".into(),
            })
            .await
            .is_err());
        server.mark_sealed(&channel_id).await.unwrap();
        assert!(
            server
                .store
                .get_channel(&channel_id)
                .await
                .unwrap()
                .unwrap()
                .sealed
        );
        assert!(server.seal_params("missing").await.is_err());
        assert!(server.mark_sealed("missing").await.is_err());
    }

    async fn seeded_server(
        cfg: SessionConfig,
        stored: ChannelState,
    ) -> SessionServer<MemoryChannelStore> {
        let store = MemoryChannelStore::new();
        store
            .put_channel(&stored.channel_id.clone(), stored)
            .await
            .unwrap();
        SessionServer::new(cfg, store)
    }

    fn unsigned_voucher(channel_id: &str, cumulative: &str) -> SignedVoucher {
        SignedVoucher {
            data: VoucherData {
                channel_id: channel_id.into(),
                cumulative_amount: cumulative.into(),
                expires_at: None,
            },
            signer: signer_address(1),
            signature: "invalid".into(),
            signature_type: VoucherSignatureType::Ed25519,
        }
    }

    #[tokio::test]
    async fn use_delivery_commit_and_close_error_paths_fail_closed() {
        let channel_id = Pubkey::new_unique().to_string();
        let payer = key(3);
        let proof = SessionAuthentication::sign("opening", &channel_id, &payer).unwrap();
        let use_payload = UsePayload {
            channel_id: channel_id.clone(),
            authentication: proof.clone(),
        };

        let client = seeded_server(
            config(VoucherSigner::Client),
            state(channel_id.clone(), signer_address(1)),
        )
        .await;
        assert!(client
            .process_use(&use_payload, "use", "key")
            .await
            .is_err());

        let mut cfg = config(VoucherSigner::Operator);
        cfg.operator_signing_key = None;
        assert!(seeded_server(
            cfg,
            state(channel_id.clone(), config(VoucherSigner::Operator).operator),
        )
        .await
        .process_use(&use_payload, "use", "key")
        .await
        .is_err());
        let mut cfg = config(VoucherSigner::Operator);
        cfg.operator = Pubkey::new_unique().to_string();
        assert!(
            seeded_server(cfg, state(channel_id.clone(), signer_address(9)))
                .await
                .process_use(&use_payload, "use", "key")
                .await
                .is_err()
        );
        assert!(
            SessionServer::new(config(VoucherSigner::Operator), MemoryChannelStore::new(),)
                .process_use(&use_payload, "use", "key")
                .await
                .is_err()
        );

        let cfg = config(VoucherSigner::Operator);
        let mut stored = state(channel_id.clone(), cfg.operator.clone());
        stored.payer = proof.payer.clone();
        stored.authentication = Some(serde_json::to_string(&proof).unwrap());
        stored.voucher_signer = "operator".into();
        stored.sealed = true;
        assert!(seeded_server(cfg.clone(), stored)
            .await
            .process_use(&use_payload, "use", "key")
            .await
            .is_err());
        let mut stored = state(channel_id.clone(), cfg.operator.clone());
        stored.payer = proof.payer.clone();
        stored.authentication = Some(serde_json::to_string(&proof).unwrap());
        stored.voucher_signer = "operator".into();
        stored.deposit = 1;
        assert!(seeded_server(cfg, stored)
            .await
            .process_use(&use_payload, "use", "key")
            .await
            .is_err());

        let mut sealed = state(channel_id.clone(), signer_address(1));
        sealed.sealed = true;
        assert!(seeded_server(config(VoucherSigner::Client), sealed)
            .await
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 1))
            .await
            .is_err());
        let mut closing = state(channel_id.clone(), signer_address(1));
        closing.close_requested_at = Some(1);
        assert!(seeded_server(config(VoucherSigner::Client), closing)
            .await
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 1))
            .await
            .is_err());

        let commit = CommitPayload {
            delivery_id: "missing".into(),
            voucher: unsigned_voucher(&channel_id, "bad"),
        };
        assert!(client.process_commit(&commit).await.is_err());
        let commit = CommitPayload {
            delivery_id: "missing".into(),
            voucher: unsigned_voucher(&channel_id, "1"),
        };
        assert!(client.process_commit(&commit).await.is_err());

        let mut expired = state(channel_id.clone(), signer_address(1));
        expired.pending_deliveries.push(PendingDelivery {
            delivery_id: "expired".into(),
            amount: 10,
            sequence: 1,
            expires_at: 1,
            request_fingerprint: None,
            handler_succeeded: false,
        });
        let expired_server = seeded_server(config(VoucherSigner::Client), expired).await;
        assert!(expired_server
            .process_commit(&CommitPayload {
                delivery_id: "expired".into(),
                voucher: unsigned_voucher(&channel_id, "1"),
            })
            .await
            .is_err());

        let mut closed = state(channel_id.clone(), signer_address(1));
        closed.sealed = true;
        let closed_server = seeded_server(config(VoucherSigner::Client), closed).await;
        assert!(closed_server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: None,
                voucher: Some(unsigned_voucher(&channel_id, "1")),
            })
            .await
            .is_err());
        assert!(client
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: Some(proof),
                voucher: None,
            })
            .await
            .is_err());
        assert!(client
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: None,
                voucher: None,
            })
            .await
            .is_err());
        assert!(client
            .process_close(&ClosePayload {
                channel_id,
                authentication: None,
                voucher: Some(unsigned_voucher("bad", "not-a-number")),
            })
            .await
            .is_err());
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn open_and_close_reject_every_invalid_binding() {
        let client = SessionServer::new(config(VoucherSigner::Client), MemoryChannelStore::new());
        let open = valid_open(&client);
        assert!(client
            .process_open(
                &open,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: Some("not-a-date"),
                    recent_blockhash: "hash",
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .is_err());
        let mut invalid = open.clone();
        invalid.idle_timeout_seconds = Some(99);
        assert!(client
            .process_open(
                &invalid,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: "hash",
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .is_err());
        invalid = open.clone();
        invalid.deposit_amount = "0".into();
        assert!(client
            .process_open(
                &invalid,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: "hash",
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .is_err());
        invalid = open;
        invalid.authentication =
            Some(SessionAuthentication::sign("opening", &invalid.channel_id, &key(2)).unwrap());
        assert!(client
            .process_open(
                &invalid,
                SessionOpenContext {
                    challenge_id: "opening",
                    expires: None,
                    recent_blockhash: "hash",
                    recent_slot: CHALLENGED_SLOT,
                },
            )
            .await
            .is_err());

        let operator =
            SessionServer::new(config(VoucherSigner::Operator), MemoryChannelStore::new());
        let (mut operated, _) = signed_open(&operator, 4).await;
        let challenged_blockhash = test_blockhash().to_string();
        let context = SessionOpenContext {
            challenge_id: "opening",
            expires: None,
            recent_blockhash: &challenged_blockhash,
            recent_slot: CHALLENGED_SLOT,
        };
        assert!(operator.process_open(&operated, context).await.is_err());
        operated.authentication =
            Some(SessionAuthentication::sign("other", &operated.channel_id, &key(4)).unwrap());
        assert!(operator.process_open(&operated, context).await.is_err());
        operated.authentication =
            Some(SessionAuthentication::sign("opening", &operated.channel_id, &key(5)).unwrap());
        assert!(operator.process_open(&operated, context).await.is_err());
        let mut bad_signature =
            SessionAuthentication::sign("opening", &operated.channel_id, &key(4)).unwrap();
        bad_signature.signature = bs58::encode([0_u8; 64]).into_string();
        operated.authentication = Some(bad_signature);
        assert!(operator.process_open(&operated, context).await.is_err());

        let channel_id = Pubkey::new_unique().to_string();
        let payer = key(3);
        let proof = SessionAuthentication::sign("opening", &channel_id, &payer).unwrap();
        let cfg = config(VoucherSigner::Operator);
        let mut operated_state = state(channel_id.clone(), cfg.operator.clone());
        operated_state.payer = proof.payer.clone();
        operated_state.authentication = Some(serde_json::to_string(&proof).unwrap());
        operated_state.voucher_signer = "operator".into();
        let operated_server = seeded_server(cfg, operated_state.clone()).await;
        assert!(operated_server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: Some(proof.clone()),
                voucher: Some(unsigned_voucher(&channel_id, "1")),
            })
            .await
            .is_err());
        assert!(operated_server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: None,
                voucher: None,
            })
            .await
            .is_err());
        let wrong = SessionAuthentication::sign("wrong", &channel_id, &payer).unwrap();
        assert!(operated_server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: Some(wrong),
                voucher: None,
            })
            .await
            .is_err());

        let session_signer = signer(1);
        let mut active = ActiveSession::new(Pubkey::from_str(&channel_id).unwrap(), session_signer);
        let mut stale_state = state(channel_id.clone(), signer_address(1));
        stale_state.cumulative = 100;
        stale_state.highest_voucher_signature = Some("different".into());
        let stale_server = seeded_server(config(VoucherSigner::Client), stale_state).await;
        assert!(stale_server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: None,
                voucher: Some(active.sign_increment(100).await.unwrap()),
            })
            .await
            .is_err());
        let mut low_deposit = state(channel_id.clone(), signer_address(1));
        low_deposit.deposit = 1;
        let low_server = seeded_server(config(VoucherSigner::Client), low_deposit).await;
        assert!(low_server
            .process_close(&ClosePayload {
                channel_id: channel_id.clone(),
                authentication: None,
                voucher: Some(active.sign_increment(1).await.unwrap()),
            })
            .await
            .is_err());
        assert!(seeded_server(
            config(VoucherSigner::Client),
            state(channel_id.clone(), signer_address(1)),
        )
        .await
        .process_close(&ClosePayload {
            channel_id,
            authentication: None,
            voucher: Some(unsigned_voucher("bad", "1")),
        })
        .await
        .is_err());
    }

    #[test]
    fn helpers_reject_invalid_values_and_hash_deterministically() {
        let operator = Pubkey::new_unique();
        let client = Pubkey::new_unique();
        assert_eq!(
            VoucherSigner::Operator.authorized_signer(operator, client),
            operator
        );
        assert_eq!(
            VoucherSigner::Client.authorized_signer(operator, client),
            client
        );
        assert!(parse_pubkey("invalid").is_err());
        assert!(parse_required_operator("").is_err());
        let recipient = Pubkey::new_unique();
        let split = Pubkey::new_unique();
        assert_eq!(
            compute_distribution_hash(&recipient, &[]),
            compute_distribution_hash(&split, &[])
        );
        assert_ne!(
            compute_distribution_hash(&recipient, &[]),
            compute_distribution_hash(&recipient, &[(split, 10)])
        );

        let base = SealParams {
            channel_id: Pubkey::new_unique(),
            authorized_signer: None,
            payer: None,
            rent_payer: None,
            mint: None,
            program_id: payment_channels::default_program_id(),
            channel_version: None,
            channel_hooks: None,
            settled: 1,
            voucher_signature: None,
            voucher_expires_at: None,
            recipient,
            splits: vec![],
            distribution_hash: [0; 32],
        };
        assert!(base.settle_instructions(&operator).is_err());
        let mut invalid = base;
        invalid.authorized_signer = Some(client);
        invalid.voucher_signature = Some("invalid".into());
        assert!(invalid.settle_instructions(&operator).is_err());
        invalid.voucher_signature = Some(bs58::encode([0_u8; 63]).into_string());
        assert!(invalid.settle_instructions(&operator).is_err());
        invalid.voucher_signature = Some(bs58::encode([0_u8; 64]).into_string());
        assert!(invalid.settle_instructions(&operator).is_err());
    }
}
