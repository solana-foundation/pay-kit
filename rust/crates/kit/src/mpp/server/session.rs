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
//! Open and top-up credentials are accepted only after their submitted
//! transactions are decoded, bound to the challenge and persisted channel,
//! broadcast, confirmed, and checked against the resulting on-chain state.
//!
//! Replayed `open` payloads for an existing channel are idempotent: they
//! never reset the voucher watermark or any other channel state.

use solana_pubkey::Pubkey;
use solana_signature::Signature;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::core::session::VoucherAcceptance;
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// co-sign after validating the transaction.
    pub fee_payer_signer: Option<std::sync::Arc<dyn solana_keychain::SolanaSigner>>,

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

    /// SPL mint locked by the channel.
    pub mint: Option<Pubkey>,

    /// Payment-channels program ID.
    pub program_id: Pubkey,

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
    store: S,
    blockhash_cache: Option<crate::core::blockhash::BlockhashCache>,
    #[cfg(feature = "server")]
    tx_pipeline: tokio::sync::OnceCell<crate::core::tx_pipeline::TxPipeline>,
}

impl<S: ChannelStore> SessionServer<S> {
    pub fn new(config: SessionConfig, store: S) -> Self {
        Self {
            config,
            store,
            blockhash_cache: None,
            #[cfg(feature = "server")]
            tx_pipeline: tokio::sync::OnceCell::new(),
        }
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
        Ok(payment_channels::build_open_instruction(&params))
    }

    /// Process an `open` action: persist the channel state.
    ///
    /// Accepts payment-channel opens and operated-voucher delegated-token opens.
    /// Returns the stored `ChannelState`.
    ///
    /// When `config.rpc_url` is set, confirms the open transaction on-chain at
    /// confirmed commitment before persisting — rejects the open if the tx is
    /// unknown or failed. Leave `rpc_url` as `None` in unit tests.
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

    async fn process_open_inner(
        &self,
        payload: &OpenPayload,
        context: SessionOpenContext<'_>,
    ) -> Result<OpenAcceptance> {
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

        let fresh_open = self
            .store
            .get_channel(session_id)
            .await
            .map_err(store_err)?
            .is_none();
        #[cfg(feature = "server")]
        let pipeline = self.transaction_pipeline().await?;
        #[cfg(feature = "server")]
        let transaction_signature = verify_submit_and_fetch_open(
            payload,
            &params,
            context.recent_blockhash,
            &pipeline,
            fresh_open,
            self.config.fee_payer_signer.as_deref(),
        )
        .await?;
        #[cfg(not(feature = "server"))]
        let transaction_signature = verify_submit_and_fetch_open(
            payload,
            &params,
            context.recent_blockhash,
            &(),
            fresh_open,
            self.config.fee_payer_signer.as_deref(),
        )
        .await?;

        let authentication = payload
            .authentication
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| Error::Other(format!("serialize authentication: {error}")))?;
        let now_ms = now_unix_secs().saturating_mul(1_000) as u64;

        let fresh_state = ChannelState {
            channel_id: session_id.to_string(),
            authorized_signer: payload.authorized_signer.clone(),
            deposit,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
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
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
            lifecycle: Some(ChannelLifecycle {
                owner: self.config.operator.clone(),
                close_after: now_ms.saturating_add(u64::from(effective_idle_timeout) * 1_000),
            }),
            schema_version: CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        };

        // Atomic check-and-insert: a replayed open re-passes all checks above
        // (the referenced tx is genuinely confirmed), so it MUST NOT overwrite
        // existing state — that would reset the voucher watermark and erase
        // accepted vouchers before close.
        let session_id_owned = session_id.to_string();
        let authorized_signer = payload.authorized_signer.clone();
        let payer = payload.payer.clone();
        let rent_payer = params.rent_payer.to_string();
        let opening_challenge_id = context.challenge_id.to_string();
        let authentication = payload.authentication.clone();
        let replay = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let replay_out = std::sync::Arc::clone(&replay);
        let state = self
            .store
            .update_channel(
                session_id,
                Box::new(move |state_opt| match state_opt {
                    Some(existing) => {
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
                        replay_out.store(true, std::sync::atomic::Ordering::Relaxed);
                        Ok(existing)
                    }
                    None => Ok(fresh_state),
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
        let voucher = &payload.voucher;
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

        // Wire-agnostic acceptance (signature + monotonicity + deposit cap +
        // min-delta + idempotent replay + atomic advance) lives in core so the
        // x402 `batch-settlement` scheme shares it. The settlement window is the
        // channel's forced-close grace period: a non-zero voucher expiry must
        // outlast it so the operator can still redeem on-chain after the async
        // forced-close delay.
        let acceptance = crate::core::session::accept_voucher(
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
            // fixed price, before the watermark advances — matches the
            // TypeScript/Python session servers' availability gate.
            self.config.amount,
        )
        .await
        .map_err(Error::from)?;
        let now_ms = now_unix_secs().saturating_mul(1_000) as u64;
        let owner = self.config.operator.clone();
        // Debit the fixed per-action price, not the voucher's own cumulative
        // jump: the client may pre-fund a voucher for more than one action's
        // worth of `cumulativeAmount`, and `spentAmount` tracks delivered
        // service (draft-solana-session-00 `spentAmount += cost`), not the
        // authorized credit line. This matches `process_use`'s debit and the
        // TypeScript/Python session servers. 0 on an idempotent replay, since
        // no additional service is delivered.
        let debit = if acceptance.replay {
            0
        } else {
            self.config.amount
        };
        self.store
            .update_channel(
                &voucher.data.channel_id,
                Box::new(move |state_opt| {
                    let mut state = state_opt.ok_or_else(|| {
                        StoreError::Internal(
                            "Channel disappeared after voucher acceptance".to_string(),
                        )
                    })?;
                    state.spent_amount =
                        state.spent_amount.checked_add(debit).ok_or_else(|| {
                            StoreError::Internal("session spent amount overflow".to_string())
                        })?;
                    state.last_activity_at = now_ms;
                    state.lifecycle = state.idle_timeout_seconds.map(|seconds| ChannelLifecycle {
                        owner,
                        close_after: now_ms.saturating_add(u64::from(seconds) * 1_000),
                    });
                    Ok(state)
                }),
            )
            .await
            .map_err(store_err)?;
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
                    // A record with no binding at all is not a mismatch: it
                    // either predates proof binding or was rewritten by a
                    // pre-binding writer (the 2026-08-01 wipe). Name it so the
                    // client knows re-opening — not retrying the proof — is
                    // the fix.
                    if state.opening_challenge_id.is_empty() && state.authentication.is_none() {
                        return Err(StoreError::Internal(
                            "session channel predates proof binding; open a new session"
                                .to_string(),
                        ));
                    }
                    if state.voucher_signer != "operator"
                        || state.authentication.as_deref() != Some(authentication.as_str())
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
                    state.processed_uses.push(crate::core::store::ProcessedUse {
                        challenge_id: challenge_id.clone(),
                        idempotency_key: idempotency_key.clone(),
                        cumulative,
                        voucher_signature: signature.clone(),
                    });
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

    /// Process a `topup` action and return its post-co-sign transaction ID.
    pub async fn process_topup_with_outcome(
        &self,
        payload: &TopUpPayload,
    ) -> Result<TopUpAcceptance> {
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
        // The transaction id is the fee-payer signature. In sponsored mode
        // that slot is intentionally empty in the submitted payload, so only
        // the server can derive the stable dedupe key after validation and
        // co-signing. A replay may therefore reach RPC again; the confirmed
        // signature status makes that path idempotent before this mutator
        // credits the deposit.
        #[cfg(feature = "server")]
        let pipeline = self.transaction_pipeline().await?;
        #[cfg(feature = "server")]
        let topup_signature =
            verify_submit_and_fetch_topup(payload, &existing, &self.config, &pipeline).await?;
        #[cfg(not(feature = "server"))]
        let topup_signature =
            verify_submit_and_fetch_topup(payload, &existing, &self.config, &()).await?;

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
        let currency = self.config.currency.clone();
        let commit_url = request.commit_url.clone();
        let proof = request.proof.clone();
        let requested_delivery_id = request.delivery_id.clone();
        let expires_at = request
            .expires_at
            .unwrap_or(crate::mpp::protocol::intents::session::DEFAULT_SESSION_EXPIRES_AT);
        let directive_out = std::sync::Arc::new(std::sync::Mutex::new(None));

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
                        let pending_total = state
                            .pending_deliveries
                            .iter()
                            .map(|delivery| delivery.amount)
                            .sum::<u64>();
                        if state.cumulative + pending_total + amount > state.deposit {
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
                        if state.close_requested_at.is_some() {
                            return Err(StoreError::Internal(
                                "Channel close is pending — no further commits accepted"
                                    .to_string(),
                            ));
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
                        let actual_amount = new_cumulative - state.cumulative;
                        if actual_amount > pending.amount {
                            return Err(StoreError::Internal(format!(
                                "Commit amount {actual_amount} exceeds reserved amount {}",
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
                        state.committed_deliveries.push(CommittedDelivery {
                            delivery_id: delivery_id.clone(),
                            amount: actual_amount,
                            cumulative: new_cumulative,
                            voucher_signature: signature,
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

                    Ok(ChannelState {
                        cumulative: new_cumulative,
                        highest_voucher_signature: new_sig,
                        highest_voucher_expires_at: new_expires_at,
                        close_requested_at: Some(now),
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

        let channel_pubkey = parse_pubkey(channel_id)?;
        let recipient_pubkey = parse_pubkey(&self.config.recipient)?;
        let authorized_signer = parse_pubkey(&state.authorized_signer).ok();
        let payer = parse_pubkey(&state.payer).ok();
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
            mint,
            program_id,
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

#[cfg(feature = "server")]
async fn verify_submit_and_fetch_open(
    payload: &OpenPayload,
    params: &payment_channels::OpenChannelParams,
    challenged_blockhash: &str,
    pipeline: &crate::core::tx_pipeline::TxPipeline,
    fresh_open: bool,
    fee_payer_signer: Option<&dyn solana_keychain::SolanaSigner>,
) -> Result<String> {
    let mut tx = payment_channels::decode_transaction(&payload.transaction)?;
    if tx
        .message
        .address_table_lookups()
        .is_some_and(|lookups| !lookups.is_empty())
    {
        return Err(Error::Other(
            "open transaction must not use address lookup tables".to_string(),
        ));
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
    let expected = payment_channels::build_open_instruction(params);
    let compute_budget = parse_pubkey("ComputeBudget111111111111111111111111111111")?;
    let mut found_open = false;
    for ix in tx.message.instructions() {
        let program = keys.get(ix.program_id_index as usize).ok_or_else(|| {
            Error::Other("open instruction program index out of range".to_string())
        })?;
        if *program == compute_budget {
            crate::mpp::server::charge::validate_compute_budget_instruction(
                ix,
                fee_payer_signer.is_some(),
            )
            .map_err(|error| Error::Other(error.to_string()))?;
            continue;
        }
        if found_open || *program != expected.program_id || ix.data != expected.data {
            return Err(Error::Other(
                "open transaction contains an unexpected instruction".to_string(),
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

    verify_client_transaction_signatures(&tx, fee_payer_signer.map(|signer| signer.pubkey()))?;
    if let Some(signer) = fee_payer_signer {
        payment_channels::cosign_fee_payer(signer, &params.rent_payer, &mut tx).await?;
    }
    let transaction_signature = tx
        .signatures
        .first()
        .ok_or_else(|| Error::Other("open transaction is missing its fee-payer signature".into()))?
        .to_string();

    if fresh_open {
        let current_slot = pipeline
            .current_slot()
            .await
            .map_err(|error| Error::Rpc(format!("session open slot validation failed: {error}")))?;
        if params.open_slot > current_slot {
            return Err(Error::Other(format!(
                "open openSlot {} is ahead of the current cluster slot {current_slot}",
                params.open_slot
            )));
        }
        if current_slot - params.open_slot > payment_channels::OPEN_SLOT_WINDOW {
            return Err(Error::Other(format!(
                "open openSlot {} is outside the {}-slot freshness window of the current cluster slot {current_slot}",
                params.open_slot,
                payment_channels::OPEN_SLOT_WINDOW
            )));
        }
    } else if fetch_and_match_open_channel(pipeline, params, None)
        .await
        .is_ok()
    {
        // This open already exists in the store (a resubmit — e.g. the
        // client never saw the first response), and the channel account
        // confirmed on-chain already matches this exact open. Return the
        // already-landed signature instead of resubmitting: co-signing and
        // rebroadcasting an open that has nothing left to do would burn a
        // sponsor fee on every duplicate open request, not just the first.
        return Ok(transaction_signature);
    }
    // A broadcast rejection is not authoritative: a retry of an open whose
    // first submission landed (response lost, or the store write after it
    // failed) dies at preflight with "already processed". The confirmed
    // channel account is — it matches the verified open params only if this
    // exact open succeeded, so a match is treated as success regardless of
    // what the broadcast said.
    let submission = pipeline.submit_verified(&tx).await;
    let min_context_slot = submission.as_ref().ok().map(|confirmed| confirmed.slot);
    let confirmed = fetch_and_match_open_channel(pipeline, params, min_context_slot).await;
    match (submission, confirmed) {
        (Ok(_), confirmed) => confirmed,
        (Err(_), Ok(())) => Ok(()),
        (Err(error), Err(_)) => Err(Error::Rpc(format!("open submission failed: {error}"))),
    }?;
    Ok(transaction_signature)
}

#[cfg(feature = "server")]
async fn fetch_and_match_open_channel(
    pipeline: &crate::core::tx_pipeline::TxPipeline,
    params: &payment_channels::OpenChannelParams,
    min_context_slot: Option<u64>,
) -> Result<()> {
    let channel_address = payment_channels::derive_channel_addresses(params).channel;
    let account_data = pipeline
        .read_account_data(channel_address, min_context_slot)
        .await
        .map_err(|error| Error::Rpc(format!("fetch confirmed channel failed: {error}")))?
        .ok_or_else(|| Error::Rpc("confirmed channel account not found".to_string()))?;
    let channel =
        payment_channels::generated::generated::accounts::Channel::from_bytes(&account_data)
            .map_err(|error| Error::Other(format!("decode confirmed channel: {error}")))?;
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
    Ok(())
}

#[cfg(feature = "server")]
async fn verify_submit_and_fetch_topup(
    payload: &TopUpPayload,
    state: &ChannelState,
    config: &SessionConfig,
    pipeline: &crate::core::tx_pipeline::TxPipeline,
) -> Result<String> {
    let amount = payload
        .additional_amount
        .parse::<u64>()
        .map_err(|_| Error::Other("invalid additionalAmount".to_string()))?;
    let payer = parse_pubkey_field(&state.payer, "payer")?;
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
    let expected = payment_channels::build_top_up_instruction(
        &payer,
        &channel,
        &mint,
        amount,
        &token_program,
        &program_id,
    );
    let mut tx = payment_channels::decode_transaction(&payload.transaction)?;
    if tx
        .message
        .address_table_lookups()
        .is_some_and(|lookups| !lookups.is_empty())
    {
        return Err(Error::Other(
            "top-up transaction must not use address lookup tables".to_string(),
        ));
    }
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
    let compute_budget = parse_pubkey("ComputeBudget111111111111111111111111111111")?;
    let mut found = false;
    for ix in tx.message.instructions() {
        let program = keys
            .get(ix.program_id_index as usize)
            .ok_or_else(|| Error::Other("top-up program index out of range".to_string()))?;
        if *program == compute_budget {
            crate::mpp::server::charge::validate_compute_budget_instruction(
                ix,
                fee_payer_signer.is_some(),
            )
            .map_err(|error| Error::Other(error.to_string()))?;
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
        if found
            || *program != expected.program_id
            || ix.data != expected.data
            || accounts != expected_accounts
        {
            return Err(Error::Other(
                "top-up transaction does not match channel and additionalAmount".to_string(),
            ));
        }
        found = true;
    }
    if !found {
        return Err(Error::Other("top-up instruction not found".to_string()));
    }
    verify_client_transaction_signatures(&tx, fee_payer_signer.map(|signer| signer.pubkey()))?;
    if let Some(signer) = fee_payer_signer {
        payment_channels::cosign_fee_payer(signer, &expected_fee_payer, &mut tx).await?;
    }
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
    let confirmed = pipeline
        .submit_verified(&tx)
        .await
        .map_err(|error| Error::Rpc(format!("top-up submission failed: {error}")))?;
    let account_data = pipeline
        .read_account_data(channel, Some(confirmed.slot))
        .await
        .map_err(|error| Error::Rpc(format!("fetch topped-up channel failed: {error}")))?
        .ok_or_else(|| Error::Rpc("confirmed topped-up channel account not found".to_string()))?;
    let channel_state =
        payment_channels::generated::generated::accounts::Channel::from_bytes(&account_data)
            .map_err(|error| Error::Other(format!("decode topped-up channel: {error}")))?;
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
) -> Result<String> {
    Err(Error::Other(
        "session top-up verification requires the `server` feature".to_string(),
    ))
}

#[cfg(not(feature = "server"))]
async fn verify_submit_and_fetch_open(
    _payload: &OpenPayload,
    _params: &payment_channels::OpenChannelParams,
    _challenged_blockhash: &str,
    _pipeline: &(),
    _fresh_open: bool,
    _fee_payer_signer: Option<&dyn solana_keychain::SolanaSigner>,
) -> Result<String> {
    Err(Error::Other(
        "session open verification requires the `server` feature".to_string(),
    ))
}

fn verify_client_transaction_signatures(
    tx: &solana_transaction::versioned::VersionedTransaction,
    server_fee_payer: Option<Pubkey>,
) -> Result<()> {
    let required = usize::from(tx.message.header().num_required_signatures);
    let keys = tx.message.static_account_keys();
    if tx.signatures.len() != required || keys.len() < required {
        return Err(Error::Other(
            "session transaction signature slots do not match its required signers".into(),
        ));
    }
    let message = tx.message.serialize();
    for (index, (signature, key)) in tx.signatures.iter().zip(keys).take(required).enumerate() {
        if server_fee_payer == Some(*key) {
            if index != 0 || *signature != Signature::default() {
                return Err(Error::Other(
                    "session fee-payer signature slot must be empty before server co-signing"
                        .into(),
                ));
            }
            continue;
        }
        if !signature.verify(key.as_ref(), &message) {
            return Err(Error::Other(format!(
                "invalid client transaction signature for required signer {key}"
            )));
        }
    }
    Ok(())
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
    use std::str::FromStr;

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn signer(seed: u8) -> Box<dyn solana_keychain::SolanaSigner> {
        let key = key(seed);
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(key.as_bytes());
        bytes[32..].copy_from_slice(key.verifying_key().as_bytes());
        Box::new(MemorySigner::from_bytes(&bytes).unwrap())
    }

    fn shared_signer(seed: u8) -> std::sync::Arc<dyn solana_keychain::SolanaSigner> {
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

    #[test]
    fn usdtest_mainnet_challenge_is_rejected_before_rpc() {
        let mut config = config(VoucherSigner::Client);
        config.currency = "USDtest".to_string();
        let server = SessionServer::new(config, MemoryChannelStore::new());

        let error = server.build_challenge_request().unwrap_err();
        assert!(error.to_string().contains("USDtest is devnet-only"));
    }

    fn state(channel_id: String, authorized_signer: String) -> ChannelState {
        ChannelState {
            channel_id,
            authorized_signer,
            deposit: 1_000,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
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
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
            lifecycle: None,
            schema_version: CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        }
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
        rpc_for_channel_with_options(channel, current_slot, false).await
    }

    /// Like [`rpc_for_channel`], but `landed_with_error` makes
    /// `getSignatureStatuses` report every landed signature as failed
    /// on-chain (`confirm`'s fast, non-timeout failure path), simulating a
    /// submission whose execution genuinely fails — as opposed to one whose
    /// response is merely lost. Account reads
    /// (`getAccountInfo`/`getMultipleAccounts`) still return the fixed
    /// `channel` state regardless, matching a real cluster where the account
    /// reflects whatever *other* transaction landed.
    async fn rpc_for_channel_with_options(
        channel: payment_channels::generated::generated::accounts::Channel,
        current_slot: u64,
        landed_with_error: bool,
    ) -> (
        String,
        tokio::task::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use base64::Engine;
        use serde_json::{json, Value};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let account_data = borsh::to_vec(&channel).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        // Mainnet-faithful duplicate handling: a signature lands exactly once,
        // so a repeated `sendTransaction` is rejected at preflight the way a
        // real RPC rejects it, and `getSignatureStatuses` reports only
        // signatures that actually landed.
        let landed: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>> =
            std::sync::Arc::default();
        let send_tx_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let send_tx_count_srv = std::sync::Arc::clone(&send_tx_count);
        let handle = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let account_data = account_data.clone();
                let landed = std::sync::Arc::clone(&landed);
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
                        "getSlot" => Ok(json!(current_slot)),
                        "sendTransaction" => {
                            send_tx_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let signature = payment_channels::decode_transaction(
                                request["params"][0].as_str().unwrap(),
                            )
                            .unwrap()
                            .signatures[0]
                                .to_string();
                            if !landed.lock().unwrap().insert(signature.clone()) {
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
                                Ok(json!(signature))
                            }
                        }
                        "getSignatureStatuses" => {
                            let statuses = request["params"][0]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|signature| {
                                    if landed.lock().unwrap().contains(signature.as_str().unwrap())
                                    {
                                        if landed_with_error {
                                            // A signature the RPC saw land, but
                                            // whose execution failed on-chain
                                            // (e.g. insufficient fee-payer
                                            // funds) — the confirmation
                                            // tracker's fast (non-timeout)
                                            // failure path.
                                            json!({
                                                "slot": 43,
                                                "confirmations": null,
                                                "err": "AlreadyProcessed",
                                                "confirmationStatus": "finalized",
                                                "status": { "Err": "AlreadyProcessed" }
                                            })
                                        } else {
                                            json!({
                                                "slot": 43,
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
                                "context": { "slot": 43 },
                                "value": statuses
                            }))
                        }
                        "getAccountInfo" => Ok(json!({
                            "context": { "slot": 43 },
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
                                "context": { "slot": 43 },
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
    async fn sponsored_open_advertises_cosigns_and_persists_rent_payer() {
        use base64::Engine;
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
        invalid_open.transaction = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&tampered).unwrap());
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
    async fn retried_open_survives_preflight_rejection_without_stored_state() {
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

        // Same signed transaction against the same RPC (which now rejects the
        // duplicate at preflight), but an empty store: the retry must still
        // succeed and re-create the channel state.
        let fresh = SessionServer::new(server.config.clone(), MemoryChannelStore::new());
        let retried = fresh
            .process_open_with_outcome(&open, context)
            .await
            .unwrap();
        assert!(!retried.replay);
        assert_eq!(retried.state.deposit, 1_000);
        assert_eq!(retried.state.opening_challenge_id, "opening");
        rpc.abort();
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn confirmed_sponsored_topup_adds_only_the_declared_amount() {
        use base64::Engine;
        use payment_channels::generated::generated::types::SettlementWatermarks;
        use solana_message::Message;
        use solana_transaction::Transaction;

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
        let message = Message::new_with_blockhash(
            &[ix],
            Some(&sponsor.pubkey()),
            &solana_hash::Hash::new_unique(),
        );
        let mut tx = Transaction::new_unsigned(message);
        payer.sign_transaction(&mut tx).await.unwrap();
        assert_eq!(tx.signatures[0], Signature::default());
        let transaction =
            base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&tx).unwrap());
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
        use base64::Engine;
        use payment_channels::generated::generated::types::SettlementWatermarks;
        use solana_message::Message;
        use solana_transaction::Transaction;

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
        let message = Message::new_with_blockhash(
            &[ix],
            Some(&sponsor.pubkey()),
            &solana_hash::Hash::new_unique(),
        );
        let mut tx = Transaction::new_unsigned(message);
        payer.sign_transaction(&mut tx).await.unwrap();
        let transaction =
            base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&tx).unwrap());
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
            rpc_for_channel_with_options(account, 43, /* landed_with_error */ true).await;
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
            mint: None,
            program_id: payment_channels::default_program_id(),
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
