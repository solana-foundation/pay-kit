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
//! # Note on on-chain verification
//!
//! When `SessionConfig::rpc_url` is set, `process_open` (push mode) and
//! `process_topup` confirm the provided transaction signature and bind the
//! persisted state to the resulting on-chain Channel account. Without an RPC,
//! those operations fail closed off localnet.
//!
//! Replayed `open` payloads for an existing channel are idempotent: they
//! never reset the voucher watermark or any other channel state.

use solana_pubkey::Pubkey;

use crate::core::session::VoucherAcceptance;
use crate::mpp::error::{Error, Result};
use crate::mpp::program::payment_channels;
use crate::mpp::protocol::intents::session::{
    ClosePayload, CommitPayload, CommitReceipt, CommitStatus, MeteringDirective, OpenPayload,
    SessionMode, SessionPullVoucherStrategy, SessionRequest, SessionSplit, SignedVoucher,
    TopUpPayload, VoucherPayload,
};
use crate::mpp::protocol::solana::{default_token_program_for_currency, resolve_stablecoin_mint};
use crate::mpp::store::{
    ChannelState, ChannelStore, CommittedDelivery, PendingDelivery, SessionStoreDurability,
    StoreError,
};

// ── Configuration ──

/// A payment split committed at channel open; distributed at close.
#[derive(Debug, Clone)]
pub struct Split {
    pub recipient: Pubkey,
    /// Share in basis points.
    pub bps: u16,
}

/// Who signs the channel's vouchers — the settlement authority model.
///
/// The simpler successor to the removed `multi_delegator` path. Both settle
/// through the same batched worker; the difference is only who holds the
/// channel's `authorized_signer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SettlementAuthority {
    /// Client's ephemeral key signs each voucher (classic MPP push). Default —
    /// preserves existing behavior.
    #[default]
    ClientVoucher,
    /// Operator is the channel `authorized_signer` and signs settlement (the
    /// x402 `upto` model). Usage metered server-side; one settlement at close.
    Delegated,
}

impl SettlementAuthority {
    /// The channel `authorized_signer` to open with under this mode: the
    /// operator (Delegated) or the client's own ephemeral key (ClientVoucher).
    pub fn authorized_signer(self, operator: Pubkey, client: Pubkey) -> Pubkey {
        match self {
            Self::Delegated => operator,
            Self::ClientVoucher => client,
        }
    }
}

/// Server configuration for the session intent.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Operator public key (base58). Shown to clients in the challenge.
    pub operator: String,

    /// Primary payment recipient (base58).
    pub recipient: String,

    /// Optional splits routed to specific recipients at close.
    pub splits: Vec<Split>,

    /// Maximum cap the server will offer per session (base units).
    /// Clients may request a lower cap but not a higher one.
    pub max_cap: u64,

    /// Currency identifier (e.g., "USDC", mint address).
    pub currency: String,

    /// Token decimals (default 6 for USDC).
    pub decimals: u8,

    /// Solana network: "mainnet", "devnet", "localnet".
    pub network: String,

    /// Payment-channel program ID. `None` defaults to the canonical program.
    pub program_id: Option<Pubkey>,

    /// Minimum voucher increment (base units). 0 = no minimum.
    pub min_voucher_delta: u64,

    /// Forced-close grace period (seconds) used as the voucher settlement
    /// window: a non-zero voucher expiry MUST outlast this window so the
    /// operator can still redeem the voucher on-chain after the asynchronous
    /// forced-close delay. Mirrors the channel's on-chain grace period.
    pub grace_period_seconds: u32,

    /// Session modes this server accepts.
    ///
    /// Advertised to clients in the 402 challenge. An empty list or
    /// `[Push]` means only the payment-channel push mode is supported.
    pub modes: Vec<SessionMode>,

    /// Voucher authority used for pull sessions.
    ///
    /// Required when `modes` includes [`SessionMode::Pull`].
    pub pull_voucher_strategy: Option<SessionPullVoucherStrategy>,

    /// Solana RPC URL for on-chain open-transaction verification.
    ///
    /// Required for payment-channel opens and top-ups outside localnet. Those
    /// paths bind the confirmed transaction to its Channel account before
    /// persisting any state.
    pub rpc_url: Option<String>,

    /// Explicit development escape hatch for a process-local channel store
    /// outside localnet. Production deployments should always leave this off.
    pub allow_unsafe_ephemeral_store_off_localnet: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            operator: String::new(),
            recipient: String::new(),
            splits: vec![],
            max_cap: 10_000_000, // 10 USDC
            currency: "USDC".to_string(),
            decimals: 6,
            network: "mainnet".to_string(),
            program_id: None,
            min_voucher_delta: 0,
            grace_period_seconds: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            modes: vec![SessionMode::Push],
            pull_voucher_strategy: None,
            rpc_url: None,
            allow_unsafe_ephemeral_store_off_localnet: false,
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
}

impl<S: ChannelStore> SessionServer<S> {
    pub fn new(config: SessionConfig, store: S) -> Self {
        Self { config, store }
    }

    /// Build the `SessionRequest` to embed in a 402 challenge.
    ///
    /// `cap` is the maximum this session will allow; clamped to `config.max_cap`.
    ///
    /// When `config.rpc_url` is set (and the `server` feature is enabled), the
    /// current slot is pre-fetched and advertised as `recentSlot` (analogous to
    /// `recentBlockhash`) — the slot clients MUST use as the program's
    /// `openSlot` for PDA derivation and `open` (the program only accepts a
    /// recent slot, and clients never fetch their own). Best-effort, mirroring
    /// the subscription challenge's blockhash pre-fetch: if the RPC is down the
    /// challenge still goes out and the client surfaces a clear "challenge
    /// missing recentSlot" error at open time.
    pub fn build_challenge_request(&self, cap: u64) -> SessionRequest {
        let effective_cap = cap.min(self.config.max_cap);
        SessionRequest {
            cap: effective_cap.to_string(),
            currency: self.config.currency.clone(),
            decimals: Some(self.config.decimals),
            network: Some(self.config.network.clone()),
            operator: self.config.operator.clone(),
            recipient: self.config.recipient.clone(),
            splits: self
                .config
                .splits
                .iter()
                .map(|s| SessionSplit {
                    recipient: bs58::encode(s.recipient.as_ref()).into_string(),
                    bps: s.bps,
                })
                .collect(),
            program_id: self
                .config
                .program_id
                .map(|p| bs58::encode(p.as_ref()).into_string()),
            description: None,
            external_id: None,
            min_voucher_delta: if self.config.min_voucher_delta > 0 {
                Some(self.config.min_voucher_delta.to_string())
            } else {
                None
            },
            // Omit if only Push — clients assume Push when modes is absent.
            modes: if self.config.modes == [SessionMode::Push] {
                vec![]
            } else {
                self.config.modes.clone()
            },
            pull_voucher_strategy: if self.config.modes.contains(&SessionMode::Pull) {
                self.config.pull_voucher_strategy.clone()
            } else {
                None
            },
            recent_blockhash: None,
            recent_slot: self.challenge_recent_slot(),
        }
    }

    /// Best-effort pre-fetch of the current slot for the challenge's
    /// `recentSlot` (see [`Self::build_challenge_request`]). `None` when no
    /// `rpc_url` is configured, when the fetch fails, or without the `server`
    /// feature.
    fn challenge_recent_slot(&self) -> Option<u64> {
        #[cfg(feature = "server")]
        if let Some(ref rpc_url) = self.config.rpc_url {
            use solana_rpc_client::rpc_client::RpcClient;
            return RpcClient::new(rpc_url.clone())
                .get_slot()
                .map_err(|e| {
                    tracing::warn!(%e, "recentSlot pre-fetch failed; challenge omits it");
                    e
                })
                .ok();
        }
        None
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
        let payer = parse_payload_pubkey(payload.payer.as_deref(), "payer")?;
        let payee = parse_payload_pubkey(payload.payee.as_deref(), "payee")?;
        let mint = parse_payload_pubkey(payload.mint.as_deref(), "mint")?;
        let authorized_signer = parse_pubkey_field(&payload.authorized_signer, "authorizedSigner")?;
        let salt = payload
            .salt
            .ok_or_else(|| Error::Other("payment-channel open missing salt".to_string()))?;
        let grace_period = payload
            .grace_period
            .ok_or_else(|| Error::Other("payment-channel open missing gracePeriod".to_string()))?;
        // The payload's recentSlot is the program's openSlot — a channel-PDA
        // seed since the epoch-addressed program update — so the server cannot
        // re-derive (and thus verify) the channel address without it.
        let open_slot = payload
            .recent_slot
            .ok_or_else(|| Error::Other("payment-channel open missing recentSlot".to_string()))?;
        let deposit = payload.deposit_amount()?;
        let token_program = parse_pubkey_field(
            default_token_program_for_currency(
                &self.config.currency,
                Some(self.config.network.as_str()),
            ),
            "token program",
        )?;
        let program_id = self
            .config
            .program_id
            .unwrap_or_else(payment_channels::default_program_id);
        let expected_payee = parse_pubkey_field(&self.config.recipient, "recipient")?;
        let expected_mint = expected_payment_channel_mint(&self.config)?;
        // The configured operator IS the expected rentPayer (slot 1): the
        // operator / fee-payer pubkey that funds the channel PDA + escrow-ATA
        // rent while gasless. It is a security boundary, so it is REQUIRED — a
        // missing/empty operator must hard-fail rather than silently skip the
        // rentPayer pin. rentPayer is pinned to it below (slot-1 == operator).
        let operator = parse_required_operator(&self.config.operator)?;

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

        let recipients = self
            .config
            .splits
            .iter()
            .map(|split| payment_channels::Distribution {
                recipient: split.recipient,
                bps: split.bps,
            })
            .collect();
        let params = payment_channels::OpenChannelParams {
            payer,
            rent_payer: operator,
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
        let channel = parse_payload_pubkey(payload.channel_id.as_deref(), "channelId")?;
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
        // rentPayer is pinned to the operator inside `payment_channel_open_params`.
        let params = self.payment_channel_open_params(payload)?;
        Ok(payment_channels::build_open_instruction(&params))
    }

    /// Process an `open` action: persist the channel state.
    ///
    /// Accepts payment-channel opens and operated-voucher delegated-token opens.
    /// Returns the stored `ChannelState`.
    ///
    /// When `config.rpc_url` is set, confirms the open transaction is finalized
    /// on-chain before persisting — rejects the open if the tx is unknown or
    /// failed. Leave `rpc_url` as `None` in unit tests.
    ///
    /// Replayed opens are idempotent: when a channel already exists for the
    /// session id with the same authorized signer, the existing state is
    /// returned unchanged — the voucher watermark is never reset. Opens for an
    /// existing channel are rejected when the channel is sealed or when the
    /// payload's authorized signer differs from the stored one.
    pub async fn process_open(&self, payload: &OpenPayload) -> Result<ChannelState> {
        self.require_production_session_safety()?;
        let supports_mode = if self.config.modes.is_empty() {
            payload.mode == SessionMode::Push
        } else {
            self.config.modes.contains(&payload.mode)
        };
        if !supports_mode {
            return Err(Error::Other(format!(
                "Session mode {:?} is not supported by this challenge",
                payload.mode
            )));
        }

        let session_id = payload.session_id()?;
        let deposit = payload.deposit_amount()?;

        if deposit == 0 {
            return Err(Error::Other(
                "Deposit must be greater than zero".to_string(),
            ));
        }

        if deposit > self.config.max_cap {
            return Err(Error::Other(format!(
                "Deposit {deposit} exceeds max cap {}",
                self.config.max_cap
            )));
        }

        // Confirm the signature and bind every persisted payment-channel fact
        // to the authoritative on-chain account.
        //
        // Any transaction-backed open is a payment-channel open, including
        // clientVoucher pull mode, and must bind the same authoritative state.
        let mut bound_deposit = deposit;
        let mut bound_payer = payload.owner.clone().or_else(|| payload.payer.clone());
        let mut open_slot = payload.recent_slot;
        let mut bound_salt = payload.salt;
        let payment_channel_backed =
            payload.mode == SessionMode::Push || payload.transaction.is_some();
        if payment_channel_backed {
            match self.config.rpc_url.as_deref() {
                Some(rpc_url) => {
                    let params = self.payment_channel_open_params(payload)?;
                    let bound_signature = bound_client_open_signature(payload)?;
                    let confirmed_slot = verify_transaction_signature(bound_signature, rpc_url, VerifiedTx::Open)
                        .map_err(|e| {
                            tracing::warn!(signature = %payload.signature, %e, "open tx verification failed");
                            e
                        })?;
                    let channel_pda = parse_pubkey_field(session_id, "channelId")?;
                    let channel = fetch_channel_account(
                        rpc_url,
                        &channel_pda,
                        &params.program_id,
                        confirmed_slot,
                    )?;
                    if channel.status != CHANNEL_STATUS_OPEN {
                        return Err(Error::Other(format!(
                            "channel {session_id} is not open on-chain (status {})",
                            channel.status
                        )));
                    }
                    if payment_channels::from_address(&channel.mint) != params.mint {
                        return Err(Error::Other("on-chain channel mint mismatch".to_string()));
                    }
                    if payment_channels::from_address(&channel.payee) != params.payee {
                        return Err(Error::Other("on-chain channel payee mismatch".to_string()));
                    }
                    if payment_channels::from_address(&channel.authorized_signer)
                        != params.authorized_signer
                    {
                        return Err(Error::Other(
                            "on-chain channel authorized_signer mismatch".to_string(),
                        ));
                    }
                    if payment_channels::from_address(&channel.payer) != params.payer {
                        return Err(Error::Other("on-chain channel payer mismatch".to_string()));
                    }
                    if payment_channels::from_address(&channel.rent_payer) != params.rent_payer {
                        return Err(Error::Other(
                            "on-chain channel rent_payer mismatch".to_string(),
                        ));
                    }
                    if channel.settlement.settled != 0 || channel.settlement.payout_watermark != 0 {
                        return Err(Error::Other(
                            "channel has nonzero settlement watermarks".to_string(),
                        ));
                    }
                    if channel.grace_period != self.config.grace_period_seconds {
                        return Err(Error::Other(format!(
                            "on-chain channel grace_period {} != expected {}",
                            channel.grace_period, self.config.grace_period_seconds
                        )));
                    }
                    let expected_distribution: Vec<payment_channels::Distribution> = self
                        .config
                        .splits
                        .iter()
                        .map(|split| payment_channels::Distribution {
                            recipient: split.recipient,
                            bps: split.bps,
                        })
                        .collect();
                    if channel.distribution_hash
                        != payment_channels::distribution_hash(&expected_distribution)
                    {
                        return Err(Error::Other(
                            "on-chain channel distribution_hash does not match session splits"
                                .to_string(),
                        ));
                    }
                    let authoritative_params = payment_channels::OpenChannelParams {
                        payer: payment_channels::from_address(&channel.payer),
                        rent_payer: payment_channels::from_address(&channel.rent_payer),
                        payee: payment_channels::from_address(&channel.payee),
                        mint: payment_channels::from_address(&channel.mint),
                        authorized_signer: payment_channels::from_address(
                            &channel.authorized_signer,
                        ),
                        salt: channel.salt,
                        deposit: channel.deposit,
                        grace_period: channel.grace_period,
                        open_slot: channel.open_slot,
                        recipients: expected_distribution,
                        token_program: params.token_program,
                        program_id: params.program_id,
                    };
                    let authoritative_channel =
                        payment_channels::derive_channel_addresses(&authoritative_params).channel;
                    if authoritative_channel != channel_pda {
                        return Err(Error::Other(
                            "channel account does not match PDA derived from authoritative state"
                                .to_string(),
                        ));
                    }
                    if channel.deposit == 0 {
                        return Err(Error::Other("on-chain channel deposit is zero".to_string()));
                    }
                    if channel.deposit > self.config.max_cap {
                        return Err(Error::Other(format!(
                            "on-chain channel deposit {} exceeds max cap {}",
                            channel.deposit, self.config.max_cap
                        )));
                    }
                    bound_deposit = channel.deposit;
                    bound_payer = Some(payment_channels::pubkey_string(&params.payer));
                    open_slot = Some(channel.open_slot);
                    bound_salt = Some(channel.salt);
                }
                None if self.config.network != "localnet" => {
                    return Err(Error::Other(
                        "payment-channel push open requires an rpc_url to bind the on-chain channel off localnet"
                            .to_string(),
                    ));
                }
                None => {}
            }
        }

        let fresh_state = ChannelState {
            channel_id: session_id.to_string(),
            authorized_signer: payload.authorized_signer.clone(),
            deposit: bound_deposit,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            // Persisted so the channel PDA can be re-derived and the reclaim
            // gate evaluated later (the payload's `recentSlot` is the
            // program's openSlot). `None` for opens that don't carry it
            // (pull/legacy payloads).
            open_slot,
            salt: bound_salt,
            open_signature: None,
            operator: bound_payer,
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
        };

        // Atomic check-and-insert: a replayed open re-passes all checks above
        // (the referenced tx is genuinely confirmed), so it MUST NOT overwrite
        // existing state — that would reset the voucher watermark and erase
        // accepted vouchers before close.
        let session_id_owned = session_id.to_string();
        let authorized_signer = payload.authorized_signer.clone();
        self.store
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
                        // Idempotent replay: keep existing state untouched.
                        Ok(existing)
                    }
                    None => Ok(fresh_state),
                }),
            )
            .await
            .map_err(store_err)
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
        self.require_production_session_safety()?;
        let voucher = &payload.voucher;
        let new_cumulative: u64 = voucher
            .data
            .cumulative
            .parse()
            .map_err(|_| Error::Other("Invalid cumulative in voucher".to_string()))?;

        // Wire-agnostic acceptance (signature + monotonicity + deposit cap +
        // min-delta + idempotent replay + atomic advance) lives in core so the
        // x402 `batch-settlement` scheme shares it. The settlement window is the
        // channel's forced-close grace period: a non-zero voucher expiry must
        // outlast it so the operator can still redeem on-chain after the async
        // forced-close delay.
        crate::core::session::accept_voucher(
            &self.store,
            &voucher.data.channel_id,
            new_cumulative,
            voucher.data.expires_at,
            &voucher.signature,
            now_unix_secs(),
            self.config.min_voucher_delta,
            self.config.grace_period_seconds as i64,
        )
        .await
        .map_err(Into::into)
    }

    /// Process a `topup` action: atomically update the channel's deposit cap.
    ///
    /// The new deposit must be greater than the current deposit and must not
    /// exceed the configured max cap. Top-ups are rejected once the channel is
    /// sealed or a close has been requested.
    ///
    /// When `config.rpc_url` is set, confirms the top-up transaction is
    /// finalized on-chain before raising the deposit — rejects the top-up if
    /// the tx is unknown or failed. When `rpc_url` is `None`, the provided
    /// signature and deposit amount are trusted as-is; only use that mode in
    /// unit tests or when the caller verifies the transaction out of band.
    pub async fn process_topup(&self, payload: &TopUpPayload) -> Result<ChannelState> {
        self.require_production_session_safety()?;
        let new_deposit: u64 = payload
            .new_deposit
            .parse()
            .map_err(|_| Error::Other("Invalid new_deposit".to_string()))?;
        if self.config.rpc_url.is_none() && self.config.network != "localnet" {
            return Err(Error::Other(
                "payment-channel top-up requires an rpc_url to bind the on-chain channel off localnet"
                    .to_string(),
            ));
        }
        let existing = self
            .store
            .get_channel(&payload.channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Other(format!("Channel {} not found", payload.channel_id)))?;
        let topup_delta = new_deposit.checked_sub(existing.deposit).ok_or_else(|| {
            Error::Other(format!(
                "New deposit {new_deposit} must exceed current deposit {}",
                existing.deposit
            ))
        })?;

        match self.config.rpc_url.as_deref() {
            Some(rpc_url) => {
                let confirmed_slot = verify_transaction_signature(&payload.signature, rpc_url, VerifiedTx::TopUp)
                    .map_err(|e| {
                        tracing::warn!(signature = %payload.signature, %e, "top-up tx verification failed");
                        e
                    })?;
                let channel_pda = parse_pubkey_field(&payload.channel_id, "channelId")?;
                let program_id = self
                    .config
                    .program_id
                    .unwrap_or_else(payment_channels::default_program_id);
                if self.config.network != "localnet" {
                    verify_top_up_transaction(
                        rpc_url,
                        &payload.signature,
                        &payload.channel_id,
                        &program_id,
                        topup_delta,
                    )?;
                }
                let channel =
                    fetch_channel_account(rpc_url, &channel_pda, &program_id, confirmed_slot)?;
                if channel.status != CHANNEL_STATUS_OPEN {
                    return Err(Error::Other(format!(
                        "channel {} is not open on-chain (status {})",
                        payload.channel_id, channel.status
                    )));
                }
                if payment_channels::from_address(&channel.mint)
                    != expected_payment_channel_mint(&self.config)?
                {
                    return Err(Error::Other("on-chain channel mint mismatch".to_string()));
                }
                if payment_channels::from_address(&channel.payee)
                    != parse_pubkey_field(&self.config.recipient, "recipient")?
                {
                    return Err(Error::Other("on-chain channel payee mismatch".to_string()));
                }
                if payment_channels::pubkey_string(&payment_channels::from_address(
                    &channel.rent_payer,
                )) != self.config.operator
                {
                    return Err(Error::Other(
                        "on-chain channel rent_payer mismatch".to_string(),
                    ));
                }
                if payment_channels::pubkey_string(&payment_channels::from_address(
                    &channel.authorized_signer,
                )) != existing.authorized_signer
                {
                    return Err(Error::Other(
                        "on-chain channel authorized_signer does not match stored channel"
                            .to_string(),
                    ));
                }
                let stored_payer = existing
                    .operator
                    .as_deref()
                    .ok_or_else(|| Error::Other("stored channel payer is missing".to_string()))?;
                if payment_channels::pubkey_string(&payment_channels::from_address(&channel.payer))
                    != stored_payer
                {
                    return Err(Error::Other(
                        "on-chain channel payer does not match stored channel".to_string(),
                    ));
                }
                if channel.deposit != new_deposit {
                    return Err(Error::Other(format!(
                        "on-chain channel deposit {} != asserted new_deposit {new_deposit}",
                        channel.deposit
                    )));
                }
            }
            None if self.config.network != "localnet" => {
                return Err(Error::Other(
                    "payment-channel top-up requires an rpc_url to bind the on-chain channel off localnet"
                        .to_string(),
                ));
            }
            None => {}
        }

        let max_cap = self.config.max_cap;
        let cid = payload.channel_id.clone();
        self.store
            .update_channel(
                &payload.channel_id,
                Box::new(move |state_opt| {
                    let state = state_opt
                        .ok_or_else(|| StoreError::Internal(format!("Channel {cid} not found")))?;
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
                    if new_deposit <= state.deposit {
                        return Err(StoreError::Internal(format!(
                            "New deposit {new_deposit} must exceed current deposit {}",
                            state.deposit
                        )));
                    }
                    if new_deposit > max_cap {
                        return Err(StoreError::Internal(format!(
                            "New deposit {new_deposit} exceeds max cap {max_cap}"
                        )));
                    }
                    Ok(ChannelState {
                        deposit: new_deposit,
                        ..state
                    })
                }),
            )
            .await
            .map_err(store_err)
    }

    fn require_production_session_safety(&self) -> Result<()> {
        if self.config.network != "localnet"
            && self.store.session_store_durability() != SessionStoreDurability::DurableShared
            && !self.config.allow_unsafe_ephemeral_store_off_localnet
        {
            let message = if self.store.session_store_durability()
                == SessionStoreDurability::Ephemeral
            {
                "ephemeral session store is unsafe off localnet; inject a durable shared ChannelStore"
            } else {
                "session store must explicitly declare durable shared capability off localnet; inject a durable shared ChannelStore"
            };
            return Err(Error::Other(message.to_string()));
        }
        Ok(())
    }

    /// Reserve capacity for a delivered message/response and return the
    /// metering directive the client must commit after processing it.
    pub async fn begin_delivery(&self, request: DeliveryRequest) -> Result<MeteringDirective> {
        self.require_production_session_safety()?;
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
                        let pending_total =
                            state
                                .pending_deliveries
                                .iter()
                                .try_fold(0u64, |sum, delivery| {
                                    sum.checked_add(delivery.amount).ok_or_else(|| {
                                        StoreError::Internal(
                                            "Pending delivery total overflow".to_string(),
                                        )
                                    })
                                })?;
                        let reserved = state
                            .cumulative
                            .checked_add(pending_total)
                            .and_then(|value| value.checked_add(amount))
                            .ok_or_else(|| {
                                StoreError::Internal("Delivery capacity overflow".to_string())
                            })?;
                        if reserved > state.deposit {
                            return Err(StoreError::Internal(format!(
                                "Delivery amount {amount} exceeds available deposit"
                            )));
                        }

                        let sequence =
                            state.next_delivery_sequence.checked_add(1).ok_or_else(|| {
                                StoreError::Internal("Delivery sequence overflow".to_string())
                            })?;
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
        self.require_production_session_safety()?;
        let channel_id = payload.voucher.data.channel_id.clone();
        let new_cumulative: u64 = payload
            .voucher
            .data
            .cumulative
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
        let expires_at = payload.voucher.data.expires_at;
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
                        state.highest_voucher_signature = Some(signature.clone());
                        state.highest_voucher_expires_at = Some(expires_at);
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
        self.require_production_session_safety()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let voucher_opt = payload.voucher.clone();
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

                    let (new_cumulative, new_sig, new_expires_at) =
                        if let Some(ref voucher) = voucher_opt {
                        let cumulative: u64 = voucher
                            .data
                            .cumulative
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
                                    state.highest_voucher_expires_at.or(Some(voucher.data.expires_at)),
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
                                Some(voucher.data.expires_at),
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
        self.require_production_session_safety()?;
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;

        let channel_pubkey = parse_pubkey(channel_id)?;
        let recipient_pubkey = parse_pubkey(&self.config.recipient)?;
        let authorized_signer = parse_pubkey(&state.authorized_signer).ok();
        let payer = state
            .operator
            .as_deref()
            .and_then(|payer| parse_pubkey(payer).ok());
        let mint = expected_payment_channel_mint(&self.config).ok();
        let program_id = self
            .config
            .program_id
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
        self.require_production_session_safety()?;
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

/// Which transaction a signature check is verifying — names the tx in
/// error messages. The spellings are mirrored by the TypeScript port's
/// error strings; add variants rather than passing free-form labels.
#[cfg(feature = "server")]
#[derive(Clone, Copy, Debug)]
enum VerifiedTx {
    Open,
    TopUp,
}

#[cfg(feature = "server")]
fn bound_client_open_signature(payload: &OpenPayload) -> Result<&str> {
    let transaction = payload
        .transaction
        .as_deref()
        .ok_or_else(|| Error::Other("payment-channel open missing transaction".to_string()))?;
    let decoded = payment_channels::decode_transaction(transaction)?;
    let transaction_signature = decoded.signatures.first().ok_or_else(|| {
        Error::Other("open transaction has no fee-payer signature slot".to_string())
    })?;
    if *transaction_signature == solana_signature::Signature::default() {
        return Err(Error::Other(
            "Rust session server does not broadcast partially signed opens; broadcast the completed transaction and provide its signature"
                .to_string(),
        ));
    }
    let transaction_signature = transaction_signature.to_string();
    if payload.signature != transaction_signature {
        return Err(Error::Other(format!(
            "open payload signature {} does not match transaction signature {transaction_signature}",
            payload.signature
        )));
    }
    Ok(&payload.signature)
}

#[cfg(feature = "server")]
impl std::fmt::Display for VerifiedTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::TopUp => "top-up",
        })
    }
}

/// Confirm that `sig_str` is a finalized, successful transaction on-chain.
///
/// `tx` names the transaction in error messages (see [`VerifiedTx`]).
/// Uses the blocking `RpcClient` — consistent with the rest of this module.
/// Returns an error if the signature is malformed, the tx was rejected, or
/// the tx is not found (not yet processed or doesn't exist).
#[cfg(feature = "server")]
fn verify_transaction_signature(sig_str: &str, rpc_url: &str, tx: VerifiedTx) -> Result<u64> {
    use solana_rpc_client::rpc_client::RpcClient;
    use solana_signature::Signature;
    use std::str::FromStr;

    let sig = Signature::from_str(sig_str)
        .map_err(|e| Error::Other(format!("invalid {tx} tx signature '{sig_str}': {e}")))?;

    let rpc = RpcClient::new(rpc_url.to_string());

    let response = rpc
        .get_signature_statuses_with_history(&[sig])
        .map_err(|e| Error::Other(format!("RPC error verifying {tx} tx: {e}")))?
        .value
        .into_iter()
        .next()
        .flatten()
        .ok_or_else(|| {
            Error::Other(format!(
                "{tx} tx '{sig_str}' not found — not yet confirmed or does not exist"
            ))
        })?;
    if let Some(error) = response.err {
        return Err(Error::Other(format!(
            "{tx} tx was rejected on-chain: {error:?}"
        )));
    }
    let level = response
        .confirmation_status
        .ok_or_else(|| Error::Other(format!("{tx} tx '{sig_str}' has no confirmation status")))?;
    if !matches!(
        level,
        solana_transaction_status_client_types::TransactionConfirmationStatus::Confirmed
            | solana_transaction_status_client_types::TransactionConfirmationStatus::Finalized
    ) {
        return Err(Error::Other(format!(
            "{tx} tx '{sig_str}' is only processed"
        )));
    }
    Ok(response.slot)
}

#[cfg(feature = "server")]
const CHANNEL_STATUS_OPEN: u8 = 0;

#[cfg(feature = "server")]
fn fetch_channel_account(
    rpc_url: &str,
    channel_id: &Pubkey,
    program_id: &Pubkey,
    min_context_slot: u64,
) -> Result<payment_channels::generated::accounts::Channel> {
    use solana_rpc_client::rpc_client::RpcClient;
    use solana_rpc_client_api::config::RpcAccountInfoConfig;

    let response = RpcClient::new(rpc_url.to_string())
        .get_ui_account_with_config(
            channel_id,
            RpcAccountInfoConfig {
                commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
                min_context_slot: Some(min_context_slot),
                ..RpcAccountInfoConfig::default()
            },
        )
        .map_err(|e| Error::Other(format!("channel account fetch failed: {e}")))?;
    let account = response
        .value
        .ok_or_else(|| Error::Other("channel account not found".to_string()))?;
    let owner = parse_pubkey(&account.owner)?;
    let data = account
        .data
        .decode()
        .ok_or_else(|| Error::Other("channel account data is undecodable".to_string()))?;
    if owner != *program_id {
        return Err(Error::Other(format!(
            "channel is owned by {} instead of payment-channels program {program_id}",
            owner
        )));
    }
    if data.len() != 256 {
        return Err(Error::Other(format!(
            "channel account has invalid length {}",
            data.len()
        )));
    }
    let channel = payment_channels::generated::accounts::Channel::from_bytes(&data)
        .map_err(|e| Error::Other(format!("channel decode failed: {e}")))?;
    if channel.discriminator != 1 {
        return Err(Error::Other(format!(
            "channel has invalid discriminator {}",
            channel.discriminator
        )));
    }
    if channel.version != 1 {
        return Err(Error::Other(format!(
            "channel has unsupported version {}",
            channel.version
        )));
    }
    Ok(channel)
}

#[cfg(feature = "server")]
fn verify_top_up_transaction(
    rpc_url: &str,
    signature: &str,
    channel_id: &str,
    program_id: &Pubkey,
    expected_delta: u64,
) -> Result<()> {
    use solana_rpc_client::rpc_client::RpcClient;
    use solana_signature::Signature;
    use solana_transaction_status_client_types::UiTransactionEncoding;
    use std::str::FromStr;

    let signature = Signature::from_str(signature)
        .map_err(|e| Error::Other(format!("invalid top-up signature: {e}")))?;
    let transaction = RpcClient::new(rpc_url.to_string())
        .get_transaction(&signature, UiTransactionEncoding::JsonParsed)
        .map_err(|e| Error::Other(format!("fetch top-up transaction: {e}")))?;
    if transaction
        .transaction
        .meta
        .as_ref()
        .and_then(|meta| meta.err.as_ref())
        .is_some()
    {
        return Err(Error::Other(
            "top-up transaction failed on-chain".to_string(),
        ));
    }
    let value = serde_json::to_value(&transaction)
        .map_err(|e| Error::Other(format!("serialize top-up transaction: {e}")))?;
    let instructions = value
        .pointer("/transaction/transaction/message/instructions")
        .and_then(|value| value.as_array())
        .ok_or_else(|| Error::Other("top-up transaction has no parsed instructions".to_string()))?;
    let mut matches = 0usize;
    let mut total = 0u64;
    for instruction in instructions {
        if instruction
            .get("programId")
            .and_then(|value| value.as_str())
            != Some(&program_id.to_string())
        {
            continue;
        }
        let Some(data) = instruction.get("data").and_then(|value| value.as_str()) else {
            continue;
        };
        let decoded = bs58::decode(data)
            .into_vec()
            .map_err(|e| Error::Other(format!("invalid top-up instruction data: {e}")))?;
        if decoded.first().copied() != Some(3) {
            continue;
        }
        let accounts = instruction
            .get("accounts")
            .and_then(|value| value.as_array())
            .ok_or_else(|| Error::Other("top-up instruction has invalid accounts".to_string()))?;
        if accounts.get(1).and_then(|value| value.as_str()) != Some(channel_id) {
            continue;
        }
        let amount_bytes: [u8; 8] = decoded
            .get(1..9)
            .ok_or_else(|| Error::Other("top-up instruction has invalid length".to_string()))?
            .try_into()
            .map_err(|_| Error::Other("top-up instruction has invalid length".to_string()))?;
        if decoded.len() != 9 {
            return Err(Error::Other(
                "top-up instruction has trailing data".to_string(),
            ));
        }
        total = total
            .checked_add(u64::from_le_bytes(amount_bytes))
            .ok_or_else(|| Error::Other("top-up instruction amount overflow".to_string()))?;
        matches += 1;
    }
    if matches != 1 {
        return Err(Error::Other(format!(
            "expected exactly one top-up instruction, found {matches}"
        )));
    }
    if total != expected_delta {
        return Err(Error::Other(format!(
            "top-up amount {total} != expected delta {expected_delta}"
        )));
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

fn parse_payload_pubkey(value: Option<&str>, field: &str) -> Result<Pubkey> {
    let value =
        value.ok_or_else(|| Error::Other(format!("payment-channel open missing {field}")))?;
    parse_pubkey_field(value, field)
}

fn parse_pubkey_field(value: &str, field: &str) -> Result<Pubkey> {
    parse_pubkey(value).map_err(|e| Error::Other(format!("invalid payment-channel {field}: {e}")))
}

/// Parse the configured operator pubkey, which is the expected `rentPayer`
/// (slot 1) of the open: the operator / fee payer that funds the channel rent
/// while gasless. The rentPayer slot is a security boundary, so the operator is
/// REQUIRED — an empty/missing value hard-fails rather than letting the
/// rentPayer pin be skipped.
fn parse_required_operator(operator: &str) -> Result<Pubkey> {
    if operator.trim().is_empty() {
        return Err(Error::Other(
            "payment-channel open requires a configured operator (the expected rentPayer)"
                .to_string(),
        ));
    }
    parse_pubkey_field(operator, "operator")
}

fn expected_payment_channel_mint(config: &SessionConfig) -> Result<Pubkey> {
    let mint = resolve_stablecoin_mint(&config.currency, Some(config.network.as_str()))
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
    let cumulative: u64 = voucher
        .data
        .cumulative
        .parse()
        .map_err(|_| Error::Other("Invalid cumulative in voucher".to_string()))?;
    crate::core::voucher::verify_voucher_signature(
        &voucher.data.channel_id,
        cumulative,
        voucher.data.expires_at,
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
    use crate::mpp::protocol::intents::session::{
        ClosePayload, CommitPayload, CommitStatus, OpenPayload, SessionMode,
        SessionPullVoucherStrategy, VoucherData, VoucherPayload,
    };
    use crate::mpp::store::MemoryChannelStore;

    struct TestStore {
        durability: SessionStoreDurability,
    }

    impl TestStore {
        fn new(durability: SessionStoreDurability) -> Self {
            Self { durability }
        }
    }

    impl ChannelStore for TestStore {
        fn session_store_durability(&self) -> SessionStoreDurability {
            self.durability
        }

        fn get_channel(
            &self,
            _channel_id: &str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::result::Result<Option<ChannelState>, StoreError>,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async { Err(StoreError::Internal("test store was used".to_string())) })
        }

        fn put_channel(
            &self,
            _channel_id: &str,
            _state: ChannelState,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::result::Result<(), StoreError>> + Send + '_>,
        > {
            Box::pin(async { Err(StoreError::Internal("test store was used".to_string())) })
        }

        fn update_channel(
            &self,
            _channel_id: &str,
            _updater: Box<
                dyn FnOnce(Option<ChannelState>) -> std::result::Result<ChannelState, StoreError>
                    + Send,
            >,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::result::Result<ChannelState, StoreError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Err(StoreError::Internal("test store was used".to_string())) })
        }

        fn advance_cumulative(
            &self,
            _channel_id: &str,
            _expected: u64,
            _new: u64,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::result::Result<bool, StoreError>> + Send + '_,
            >,
        > {
            Box::pin(async { Err(StoreError::Internal("test store was used".to_string())) })
        }

        fn update_deposit(
            &self,
            _channel_id: &str,
            _new_deposit: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::result::Result<(), StoreError>> + Send + '_>,
        > {
            Box::pin(async { Err(StoreError::Internal("test store was used".to_string())) })
        }

        fn mark_sealed(
            &self,
            _channel_id: &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::result::Result<(), StoreError>> + Send + '_>,
        > {
            Box::pin(async { Err(StoreError::Internal("test store was used".to_string())) })
        }
    }

    const RECIPIENT: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";

    fn make_server() -> SessionServer<MemoryChannelStore> {
        SessionServer::new(
            SessionConfig {
                operator: RECIPIENT.to_string(),
                recipient: RECIPIENT.to_string(),
                splits: vec![],
                max_cap: 10_000_000,
                currency: "USDC".to_string(),
                decimals: 6,
                network: "localnet".to_string(),
                program_id: None,
                min_voucher_delta: 0,
                grace_period_seconds: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
                modes: vec![SessionMode::Push],
                pull_voucher_strategy: None,
                rpc_url: None,
                allow_unsafe_ephemeral_store_off_localnet: false,
            },
            MemoryChannelStore::new(),
        )
    }

    fn make_server_with_min_delta(min_delta: u64) -> SessionServer<MemoryChannelStore> {
        SessionServer::new(
            SessionConfig {
                operator: RECIPIENT.to_string(),
                recipient: RECIPIENT.to_string(),
                splits: vec![],
                max_cap: 10_000_000,
                currency: "USDC".to_string(),
                decimals: 6,
                network: "localnet".to_string(),
                program_id: None,
                min_voucher_delta: min_delta,
                grace_period_seconds: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
                modes: vec![SessionMode::Push],
                pull_voucher_strategy: None,
                rpc_url: None,
                allow_unsafe_ephemeral_store_off_localnet: false,
            },
            MemoryChannelStore::new(),
        )
    }

    fn open_payload(channel_id: &str, deposit: u64, signer: &str) -> OpenPayload {
        OpenPayload::push(
            channel_id.to_string(),
            deposit.to_string(),
            signer.to_string(),
            "dummy_tx_sig".to_string(),
        )
    }

    // ── E2E helpers ──────────────────────────────────────────────────────────

    /// Build a deterministic MemorySigner + ActiveSession from a fixed seed.
    /// Returns (session, authorized_signer_b58, channel_id_b58).
    #[cfg(feature = "client")]
    fn make_e2e_session() -> (
        crate::mpp::client::session::ActiveSession,
        String, // authorized_signer
        String, // channel_id (base58)
        Pubkey, // channel Pubkey
    ) {
        use solana_keychain::MemorySigner;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(vk.as_bytes());
        let signer: Box<dyn solana_keychain::SolanaSigner> =
            Box::new(MemorySigner::from_bytes(&kp).expect("valid keypair"));
        let auth_signer = bs58::encode(vk.as_bytes()).into_string();
        let channel = Pubkey::new_unique();
        let chan_str = bs58::encode(channel.as_ref()).into_string();
        let session = crate::mpp::client::session::ActiveSession::new(channel, signer);
        (session, auth_signer, chan_str, channel)
    }

    // ── process_open ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn process_open_stores_state() {
        let server = make_server();
        let state = server
            .process_open(&open_payload("chan1", 1_000_000, "signer1"))
            .await
            .unwrap();
        assert_eq!(state.deposit, 1_000_000);
        assert_eq!(state.cumulative, 0);
        assert!(!state.sealed);
        assert_eq!(state.authorized_signer, "signer1");
    }

    #[tokio::test]
    async fn process_open_zero_deposit_rejected() {
        let server = make_server();
        assert!(server
            .process_open(&open_payload("chan1", 0, "signer1"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_open_exceeds_cap_rejected() {
        let server = make_server();
        assert!(server
            .process_open(&open_payload("chan1", 20_000_000, "signer1"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_open_rejects_unadvertised_pull_mode() {
        let server = make_server();
        let payload = OpenPayload::payment_channel_with_mode(
            SessionMode::Pull,
            "chan1".to_string(),
            "1000000".to_string(),
            "payer".to_string(),
            RECIPIENT.to_string(),
            "mint".to_string(),
            1,
            900,
            314,
            "signer1".to_string(),
            "pending".to_string(),
        );

        let err = server.process_open(&payload).await.unwrap_err();
        assert!(err.to_string().contains("not supported"));
    }

    #[tokio::test]
    async fn process_open_accepts_advertised_pull_client_voucher_channel() {
        let server = SessionServer::new(
            SessionConfig {
                modes: vec![SessionMode::Pull],
                pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let payload = OpenPayload::payment_channel_with_mode(
            SessionMode::Pull,
            "chan1".to_string(),
            "1000000".to_string(),
            "payer".to_string(),
            RECIPIENT.to_string(),
            "mint".to_string(),
            1,
            900,
            314,
            "signer1".to_string(),
            "pending".to_string(),
        );

        let state = server.process_open(&payload).await.unwrap();
        assert_eq!(state.channel_id, "chan1");
        assert_eq!(state.deposit, 1_000_000);
    }

    #[test]
    fn payment_channel_open_params_validate_challenge_fields() {
        use crate::mpp::protocol::solana::{mints, programs};
        use std::str::FromStr;

        let payer = Pubkey::new_unique();
        let authorized_signer = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).expect("valid recipient");
        let mint = Pubkey::from_str(mints::USDC_MAINNET).expect("valid USDC mint");
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).expect("valid token program");
        let server = SessionServer::new(
            SessionConfig {
                splits: vec![Split {
                    recipient: split_recipient,
                    bps: 10,
                }],
                modes: vec![SessionMode::Pull],
                pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let expected = payment_channels::OpenChannelParams {
            payer,
            // rentPayer is pinned to the operator (config operator == RECIPIENT).
            rent_payer: recipient,
            payee: recipient,
            mint,
            authorized_signer,
            salt: 77,
            open_slot: 4_242,
            deposit: 1_000_000,
            grace_period: 900,
            recipients: vec![payment_channels::Distribution {
                recipient: split_recipient,
                bps: 10,
            }],
            token_program,
            program_id: payment_channels::default_program_id(),
        };
        let channel = payment_channels::derive_channel_addresses(&expected).channel;
        let payload = OpenPayload::payment_channel_with_mode(
            SessionMode::Pull,
            payment_channels::pubkey_string(&channel),
            expected.deposit.to_string(),
            payment_channels::pubkey_string(&payer),
            RECIPIENT.to_string(),
            mints::USDC_MAINNET.to_string(),
            expected.salt,
            expected.grace_period,
            expected.open_slot,
            payment_channels::pubkey_string(&authorized_signer),
            "pending".to_string(),
        );

        let params = server.payment_channel_open_params(&payload).unwrap();
        assert_eq!(params.payer, expected.payer);
        assert_eq!(params.payee, expected.payee);
        assert_eq!(params.mint, expected.mint);
        assert_eq!(params.authorized_signer, expected.authorized_signer);
        assert_eq!(params.recipients, expected.recipients);
        assert_eq!(
            server
                .payment_channel_open_instruction(&payload)
                .unwrap()
                .program_id,
            payment_channels::to_address(&expected.program_id)
        );

        let mut wrong_payee = payload.clone();
        wrong_payee.payee = Some(payment_channels::pubkey_string(&Pubkey::new_unique()));
        let err = server
            .payment_channel_open_params(&wrong_payee)
            .unwrap_err();
        assert!(err.to_string().contains("payee does not match"));

        let mut wrong_mint = payload.clone();
        wrong_mint.mint = Some(payment_channels::pubkey_string(&Pubkey::new_unique()));
        let err = server.payment_channel_open_params(&wrong_mint).unwrap_err();
        assert!(err.to_string().contains("mint does not match"));

        let mut missing_payer = payload.clone();
        missing_payer.payer = None;
        let err = server
            .payment_channel_open_params(&missing_payer)
            .unwrap_err();
        assert!(err.to_string().contains("missing payer"));

        let mut missing_salt = payload.clone();
        missing_salt.salt = None;
        let err = server
            .payment_channel_open_params(&missing_salt)
            .unwrap_err();
        assert!(err.to_string().contains("missing salt"));

        let mut missing_grace_period = payload.clone();
        missing_grace_period.grace_period = None;
        let err = server
            .payment_channel_open_params(&missing_grace_period)
            .unwrap_err();
        assert!(err.to_string().contains("missing gracePeriod"));

        let mut missing_recent_slot = payload.clone();
        missing_recent_slot.recent_slot = None;
        let err = server
            .payment_channel_open_params(&missing_recent_slot)
            .unwrap_err();
        assert!(err.to_string().contains("missing recentSlot"));

        // A different recentSlot derives a different (per-incarnation) PDA, so
        // the payload's channelId no longer matches.
        let mut wrong_recent_slot = payload.clone();
        wrong_recent_slot.recent_slot = Some(expected.open_slot + 1);
        let err = server
            .payment_channel_open_params(&wrong_recent_slot)
            .unwrap_err();
        assert!(err.to_string().contains("channelId does not match"));

        let mut invalid_authorized_signer = payload.clone();
        invalid_authorized_signer.authorized_signer = "not-a-pubkey".to_string();
        let err = server
            .payment_channel_open_params(&invalid_authorized_signer)
            .unwrap_err();
        assert!(err.to_string().contains("authorizedSigner"));

        let sol_server = SessionServer::new(
            SessionConfig {
                currency: "SOL".to_string(),
                modes: vec![SessionMode::Pull],
                pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let err = sol_server
            .payment_channel_open_params(&payload)
            .unwrap_err();
        assert!(err.to_string().contains("SPL token"));

        let mut wrong_channel = payload.clone();
        wrong_channel.channel_id = Some(payment_channels::pubkey_string(&Pubkey::new_unique()));
        let err = server
            .payment_channel_open_params(&wrong_channel)
            .unwrap_err();
        assert!(err.to_string().contains("channelId does not match"));

        // FIX C: the operator (expected rentPayer / slot 1) is REQUIRED. An
        // empty operator must hard-fail rather than silently skipping the
        // rentPayer pin.
        let no_operator_server = SessionServer::new(
            SessionConfig {
                operator: String::new(),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let err = no_operator_server
            .payment_channel_open_params(&payload)
            .unwrap_err();
        assert!(err.to_string().contains("requires a configured operator"));
    }

    #[test]
    fn payment_channel_open_params_resolves_token_2022_stablecoin_symbols() {
        use crate::mpp::protocol::solana::{mints, programs};
        use std::str::FromStr;

        let payer = Pubkey::new_unique();
        let authorized_signer = Pubkey::new_unique();
        let payee = Pubkey::from_str(RECIPIENT).expect("valid recipient");
        let mint = Pubkey::from_str(mints::PYUSD_DEVNET).expect("valid PYUSD mint");
        let token_program =
            Pubkey::from_str(programs::TOKEN_2022_PROGRAM).expect("valid token-2022 program");
        let server = SessionServer::new(
            SessionConfig {
                currency: "PYUSD".to_string(),
                network: "devnet".to_string(),
                modes: vec![SessionMode::Pull],
                pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let expected = payment_channels::OpenChannelParams {
            payer,
            // rentPayer is pinned to the operator (config operator == RECIPIENT == payee).
            rent_payer: payee,
            payee,
            mint,
            authorized_signer,
            salt: 88,
            open_slot: 4_243,
            deposit: 1_000_000,
            grace_period: 901,
            recipients: vec![],
            token_program,
            program_id: payment_channels::default_program_id(),
        };
        let channel = payment_channels::derive_channel_addresses(&expected).channel;
        let payload = OpenPayload::payment_channel_with_mode(
            SessionMode::Pull,
            payment_channels::pubkey_string(&channel),
            expected.deposit.to_string(),
            payment_channels::pubkey_string(&payer),
            RECIPIENT.to_string(),
            mints::PYUSD_DEVNET.to_string(),
            expected.salt,
            expected.grace_period,
            expected.open_slot,
            payment_channels::pubkey_string(&authorized_signer),
            "pending".to_string(),
        );

        let params = server.payment_channel_open_params(&payload).unwrap();
        assert_eq!(params.mint, mint);
        assert_eq!(params.token_program, token_program);
        assert_eq!(params.grace_period, 901);
    }

    #[tokio::test]
    async fn process_open_exactly_at_cap_accepted() {
        let server = make_server();
        let state = server
            .process_open(&open_payload("chan1", 10_000_000, "s"))
            .await
            .unwrap();
        assert_eq!(state.deposit, 10_000_000);
    }

    #[tokio::test]
    async fn process_open_replay_does_not_reset_watermark() {
        let server = make_server();
        let payload = open_payload("chan1", 1_000_000, "signer1");
        server.process_open(&payload).await.unwrap();

        // Simulate accepted vouchers advancing the watermark.
        server
            .store
            .update_channel(
                "chan1",
                Box::new(|state_opt| {
                    let state = state_opt.unwrap();
                    Ok(ChannelState {
                        cumulative: 750_000,
                        highest_voucher_signature: Some("voucher_sig".to_string()),
                        highest_voucher_expires_at: Some(i64::MAX),
                        ..state
                    })
                }),
            )
            .await
            .unwrap();

        // Replayed open (re-passes all open checks) must not mutate state.
        let state = server.process_open(&payload).await.unwrap();
        assert_eq!(state.cumulative, 750_000);
        assert_eq!(
            state.highest_voucher_signature.as_deref(),
            Some("voucher_sig")
        );

        let stored = server.store.get_channel("chan1").await.unwrap().unwrap();
        assert_eq!(stored.cumulative, 750_000);
        assert_eq!(
            stored.highest_voucher_signature.as_deref(),
            Some("voucher_sig")
        );
        assert_eq!(stored.deposit, 1_000_000);
    }

    #[tokio::test]
    async fn process_open_existing_channel_mismatched_signer_rejected() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 1_000_000, "signer1"))
            .await
            .unwrap();

        let err = server
            .process_open(&open_payload("chan1", 1_000_000, "signer2"))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("different authorized signer"),
            "Expected mismatched signer error, got: {err}"
        );
    }

    #[tokio::test]
    async fn process_open_on_sealed_channel_rejected() {
        let server = make_server();
        let payload = open_payload("chan1", 1_000_000, "signer1");
        server.process_open(&payload).await.unwrap();
        server.mark_sealed("chan1").await.unwrap();

        let err = server.process_open(&payload).await.unwrap_err();
        assert!(
            err.to_string().contains("sealed"),
            "Expected sealed error, got: {err}"
        );
    }

    // ── metered deliveries ──────────────────────────────────────────────────

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn begin_delivery_reserves_capacity() {
        let server = make_server();
        let (_session, authorized_signer, channel_id, _channel) = make_e2e_session();
        server
            .process_open(&open_payload(&channel_id, 1_000, &authorized_signer))
            .await
            .unwrap();

        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 100))
            .await
            .unwrap();
        assert_eq!(directive.session_id, channel_id);
        assert_eq!(directive.amount, "100");
        assert_eq!(directive.sequence, 1);

        let state = server
            .store
            .get_channel(&directive.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.pending_deliveries.len(), 1);
        assert_eq!(
            state.pending_deliveries[0].delivery_id,
            directive.delivery_id
        );

        let err = server
            .begin_delivery(DeliveryRequest::new(directive.session_id, 901))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds available deposit"));
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn process_commit_accepts_delivery_and_replays_idempotently() {
        let server = make_server();
        let (mut session, authorized_signer, channel_id, _channel) = make_e2e_session();
        server
            .process_open(&open_payload(&channel_id, 1_000, &authorized_signer))
            .await
            .unwrap();
        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 125))
            .await
            .unwrap();
        let voucher = session.sign_increment(125).await.unwrap();
        let payload = CommitPayload {
            delivery_id: directive.delivery_id.clone(),
            voucher,
        };

        let receipt = server.process_commit(&payload).await.unwrap();
        assert_eq!(receipt.delivery_id, directive.delivery_id);
        assert_eq!(receipt.amount, "125");
        assert_eq!(receipt.cumulative, "125");
        assert_eq!(receipt.status, CommitStatus::Committed);

        let replay = server.process_commit(&payload).await.unwrap();
        assert_eq!(replay.status, CommitStatus::Replayed);

        let state = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.pending_deliveries.len(), 0);
        assert_eq!(state.committed_deliveries.len(), 1);
        assert_eq!(state.cumulative, 125);
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn process_commit_accepts_partial_stream_usage() {
        let server = make_server();
        let (mut session, authorized_signer, channel_id, _channel) = make_e2e_session();
        server
            .process_open(&open_payload(&channel_id, 1_000, &authorized_signer))
            .await
            .unwrap();
        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id, 125))
            .await
            .unwrap();
        let voucher = session.sign_increment(75).await.unwrap();
        let payload = CommitPayload {
            delivery_id: directive.delivery_id.clone(),
            voucher,
        };

        let receipt = server.process_commit(&payload).await.unwrap();
        assert_eq!(receipt.delivery_id, directive.delivery_id);
        assert_eq!(receipt.amount, "75");
        assert_eq!(receipt.cumulative, "75");
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn process_commit_rejects_over_reserved_cumulative() {
        let server = make_server();
        let (mut session, authorized_signer, channel_id, _channel) = make_e2e_session();
        server
            .process_open(&open_payload(&channel_id, 1_000, &authorized_signer))
            .await
            .unwrap();
        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id, 125))
            .await
            .unwrap();
        let voucher = session.sign_increment(200).await.unwrap();
        let payload = CommitPayload {
            delivery_id: directive.delivery_id,
            voucher,
        };

        let err = server.process_commit(&payload).await.unwrap_err();
        assert!(err.to_string().contains("exceeds reserved amount"));
    }

    // ── build_challenge_request ───────────────────────────────────────────────

    #[test]
    fn build_challenge_request_clamps_cap() {
        let server = make_server();
        let req = server.build_challenge_request(50_000_000);
        assert_eq!(req.cap, "10000000");
    }

    #[test]
    fn build_challenge_request_below_cap() {
        let server = make_server();
        let req = server.build_challenge_request(5_000_000);
        assert_eq!(req.cap, "5000000");
    }

    #[test]
    fn build_challenge_request_includes_fields() {
        let server = make_server();
        let req = server.build_challenge_request(1_000_000);
        assert_eq!(req.operator, RECIPIENT);
        assert_eq!(req.recipient, RECIPIENT);
        assert_eq!(req.currency, "USDC");
        assert_eq!(req.decimals, Some(6));
        assert_eq!(req.network.as_deref(), Some("localnet"));
        assert!(req.splits.is_empty());
    }

    #[test]
    fn build_challenge_request_with_splits() {
        let split_pk = Pubkey::new_unique();
        let config = SessionConfig {
            operator: RECIPIENT.to_string(),
            recipient: RECIPIENT.to_string(),
            splits: vec![Split {
                recipient: split_pk,
                bps: 1_000,
            }],
            max_cap: 10_000_000,
            currency: "USDC".to_string(),
            decimals: 6,
            network: "mainnet".to_string(),
            program_id: None,
            min_voucher_delta: 0,
            grace_period_seconds: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            modes: vec![SessionMode::Push],
            pull_voucher_strategy: None,
            rpc_url: None,
            allow_unsafe_ephemeral_store_off_localnet: false,
        };
        let server = SessionServer::new(config, MemoryChannelStore::new());
        let req = server.build_challenge_request(5_000_000);
        assert_eq!(req.splits.len(), 1);
        assert_eq!(req.splits[0].bps, 1_000);
    }

    #[test]
    fn build_challenge_request_min_voucher_delta() {
        let config = SessionConfig {
            operator: RECIPIENT.to_string(),
            recipient: RECIPIENT.to_string(),
            splits: vec![],
            max_cap: 10_000_000,
            currency: "USDC".to_string(),
            decimals: 6,
            network: "localnet".to_string(),
            program_id: None,
            min_voucher_delta: 500,
            grace_period_seconds: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            modes: vec![SessionMode::Push],
            pull_voucher_strategy: None,
            rpc_url: None,
            allow_unsafe_ephemeral_store_off_localnet: false,
        };
        let server = SessionServer::new(config, MemoryChannelStore::new());
        let req = server.build_challenge_request(5_000_000);
        assert_eq!(req.min_voucher_delta.as_deref(), Some("500"));
    }

    #[test]
    fn build_challenge_request_omits_modes_when_push_only() {
        let server = make_server(); // modes: [Push]
        let req = server.build_challenge_request(1_000_000);
        assert!(req.modes.is_empty(), "Push-only should omit modes field");
    }

    #[test]
    fn build_challenge_request_includes_modes_when_pull_supported() {
        let config = SessionConfig {
            operator: RECIPIENT.to_string(),
            recipient: RECIPIENT.to_string(),
            splits: vec![],
            max_cap: 10_000_000,
            currency: "USDC".to_string(),
            decimals: 6,
            network: "localnet".to_string(),
            program_id: None,
            min_voucher_delta: 0,
            grace_period_seconds: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            modes: vec![SessionMode::Push, SessionMode::Pull],
            pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
            rpc_url: None,
            allow_unsafe_ephemeral_store_off_localnet: false,
        };
        let server = SessionServer::new(config, MemoryChannelStore::new());
        let req = server.build_challenge_request(1_000_000);
        assert_eq!(req.modes.len(), 2);
        assert!(req.modes.contains(&SessionMode::Push));
        assert!(req.modes.contains(&SessionMode::Pull));
        assert_eq!(
            req.pull_voucher_strategy,
            Some(SessionPullVoucherStrategy::ClientVoucher)
        );
    }

    // ── verify_voucher ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn verify_voucher_unknown_channel() {
        let server = make_server();
        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "unknown".to_string(),
                cumulative: "100".to_string(),
                expires_at: i64::MAX,
                nonce: Some(1),
            },
            signature: "AAAA".to_string(),
        };
        let err = server.verify_voucher(&VoucherPayload { voucher }).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("not found"));
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn verify_voucher_valid_end_to_end() {
        let server = make_server();
        let (mut session, auth_signer, chan_str, _) = make_e2e_session();
        server
            .process_open(&open_payload(&chan_str, 5_000_000, &auth_signer))
            .await
            .unwrap();

        let voucher = session.sign_increment(1_000_000).await.unwrap();
        let result = server.verify_voucher(&VoucherPayload { voucher }).await;
        let accepted = result.unwrap();
        assert_eq!(accepted.cumulative, 1_000_000);
        assert_eq!(accepted.charged, 1_000_000);
        assert!(!accepted.replay);
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn verify_voucher_advances_watermark() {
        let server = make_server();
        let (mut session, auth_signer, chan_str, _) = make_e2e_session();
        server
            .process_open(&open_payload(&chan_str, 5_000_000, &auth_signer))
            .await
            .unwrap();

        // First voucher succeeds: a fresh charge, not a replay.
        let v1 = session.sign_increment(500_000).await.unwrap();
        let first = server
            .verify_voucher(&VoucherPayload {
                voucher: v1.clone(),
            })
            .await
            .unwrap();
        assert_eq!(first.cumulative, 500_000);
        assert_eq!(first.charged, 500_000);
        assert!(!first.replay);

        // Idempotent replay of exact same voucher (same cumulative + same
        // signature) succeeds as a no-charge no-op — never a fresh paid serve.
        let v1_replay = v1.clone();
        let replay = server
            .verify_voucher(&VoucherPayload { voucher: v1_replay })
            .await
            .unwrap();
        assert_eq!(
            replay.cumulative, 500_000,
            "Idempotent replay should return same cumulative"
        );
        assert_eq!(replay.charged, 0, "replay must not charge again");
        assert!(replay.replay, "replay must be flagged");

        // Next voucher with higher cumulative succeeds and charges the delta.
        let v2 = session.sign_increment(500_000).await.unwrap();
        let result = server.verify_voucher(&VoucherPayload { voucher: v2 }).await;
        let advanced = result.unwrap();
        assert_eq!(advanced.cumulative, 1_000_000);
        assert_eq!(advanced.charged, 500_000);
        assert!(!advanced.replay);
    }

    #[tokio::test]
    async fn verify_voucher_stale_cumulative_rejected() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 5_000_000, "signer1"))
            .await
            .unwrap();

        // Manually advance watermark via store
        server
            .store
            .advance_cumulative("chan1", 0, 500_000)
            .await
            .unwrap();

        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "100".to_string(), // below watermark
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        let err = server.verify_voucher(&VoucherPayload { voucher }).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("watermark"));
    }

    #[tokio::test]
    async fn verify_voucher_exceeds_deposit_rejected() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 1_000_000, "signer1"))
            .await
            .unwrap();

        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "2000000".to_string(), // > deposit
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        let err = server.verify_voucher(&VoucherPayload { voucher }).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("deposit"));
    }

    #[tokio::test]
    async fn verify_voucher_bad_cumulative_format_rejected() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 1_000_000, "signer1"))
            .await
            .unwrap();

        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "not_a_number".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        assert!(server
            .verify_voucher(&VoucherPayload { voucher })
            .await
            .is_err());
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn verify_voucher_bad_signature_rejected() {
        let server = make_server();
        let (mut session, auth_signer, chan_str, _) = make_e2e_session();
        server
            .process_open(&open_payload(&chan_str, 5_000_000, &auth_signer))
            .await
            .unwrap();

        let mut voucher = session.sign_increment(1_000_000).await.unwrap();
        // Tamper with the signature
        voucher.signature = bs58::encode([0u8; 64]).into_string();

        assert!(server
            .verify_voucher(&VoucherPayload { voucher })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn verify_voucher_on_sealed_channel_rejected() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 1_000_000, "signer1"))
            .await
            .unwrap();
        server.mark_sealed("chan1").await.unwrap();

        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "500000".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        let err = server.verify_voucher(&VoucherPayload { voucher }).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("sealed"));
    }

    // ── process_topup ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn process_topup_valid() {
        let server = make_server();
        let chan = "chan1";
        server
            .process_open(&open_payload(chan, 1_000_000, "s"))
            .await
            .unwrap();

        let state = server
            .process_topup(&TopUpPayload {
                channel_id: chan.to_string(),
                new_deposit: "5000000".to_string(),
                signature: "topup_sig".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(state.deposit, 5_000_000);
    }

    #[tokio::test]
    async fn process_topup_lower_deposit_rejected() {
        let server = make_server();
        let chan = "chan1";
        server
            .process_open(&open_payload(chan, 3_000_000, "s"))
            .await
            .unwrap();

        assert!(server
            .process_topup(&TopUpPayload {
                channel_id: chan.to_string(),
                new_deposit: "2000000".to_string(),
                signature: "sig".to_string(),
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_topup_exceeds_cap_rejected() {
        let server = make_server();
        let chan = "chan1";
        server
            .process_open(&open_payload(chan, 1_000_000, "s"))
            .await
            .unwrap();

        assert!(server
            .process_topup(&TopUpPayload {
                channel_id: chan.to_string(),
                new_deposit: "20000000".to_string(), // > max_cap
                signature: "sig".to_string(),
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_topup_bad_amount_format_rejected() {
        let server = make_server();
        let chan = "chan1";
        server
            .process_open(&open_payload(chan, 1_000_000, "s"))
            .await
            .unwrap();

        assert!(server
            .process_topup(&TopUpPayload {
                channel_id: chan.to_string(),
                new_deposit: "not_a_number".to_string(),
                signature: "sig".to_string(),
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_topup_unknown_channel_rejected() {
        let server = make_server();
        assert!(server
            .process_topup(&TopUpPayload {
                channel_id: "ghost".to_string(),
                new_deposit: "5000000".to_string(),
                signature: "sig".to_string(),
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_topup_close_pending_rejected() {
        let server = make_server();
        let chan = bs58::encode(Pubkey::new_unique().as_ref()).into_string();
        server
            .process_open(&open_payload(&chan, 1_000_000, "s"))
            .await
            .unwrap();
        server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap();

        let err = server
            .process_topup(&TopUpPayload {
                channel_id: chan,
                new_deposit: "5000000".to_string(),
                signature: "sig".to_string(),
            })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("close is pending"),
            "Expected close-pending error, got: {err}"
        );
    }

    #[tokio::test]
    async fn process_topup_sealed_rejected() {
        let server = make_server();
        let chan = "chan1";
        server
            .process_open(&open_payload(chan, 1_000_000, "s"))
            .await
            .unwrap();
        server.mark_sealed(chan).await.unwrap();

        let err = server
            .process_topup(&TopUpPayload {
                channel_id: chan.to_string(),
                new_deposit: "5000000".to_string(),
                signature: "sig".to_string(),
            })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("sealed"),
            "Expected sealed error, got: {err}"
        );
    }

    #[cfg(feature = "server")]
    struct SessionAccountRpc {
        url: String,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(feature = "server")]
    impl SessionAccountRpc {
        fn start(account_data: Vec<u8>, owner: Pubkey) -> Self {
            use base64::Engine as _;
            use std::io::{Read, Write};
            use std::sync::atomic::Ordering;

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let thread_stop = stop.clone();
            let data = base64::engine::general_purpose::STANDARD.encode(account_data);
            let owner = payment_channels::pubkey_string(&owner);
            let thread = std::thread::spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(value) => value,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                            continue;
                        }
                        Err(_) => break,
                    };
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(read) => {
                                request.extend_from_slice(&buf[..read]);
                                if let Some(header_end) =
                                    request.windows(4).position(|w| w == b"\r\n\r\n")
                                {
                                    let headers = String::from_utf8_lossy(&request[..header_end]);
                                    let length = headers
                                        .lines()
                                        .find_map(|line| {
                                            line.to_ascii_lowercase()
                                                .strip_prefix("content-length:")
                                                .and_then(|value| {
                                                    value.trim().parse::<usize>().ok()
                                                })
                                        })
                                        .unwrap_or(0);
                                    if request.len() >= header_end + 4 + length {
                                        break;
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let body_start = request
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|i| i + 4);
                    let request_json: serde_json::Value = body_start
                        .and_then(|start| serde_json::from_slice(&request[start..]).ok())
                        .unwrap_or_default();
                    let id = request_json
                        .get("id")
                        .cloned()
                        .unwrap_or(serde_json::Value::from(1));
                    let result = match request_json.get("method").and_then(|value| value.as_str()) {
                        Some("getSignatureStatuses") => serde_json::json!({
                            "context": {"slot": 1},
                            "value": [{
                                "slot": 1,
                                "confirmations": null,
                                "status": {"Ok": null},
                                "err": null,
                                "confirmationStatus": "finalized"
                            }]
                        }),
                        Some("getAccountInfo") => serde_json::json!({
                            "context": {"slot": 1},
                            "value": {
                                "data": [data, "base64"],
                                "executable": false,
                                "lamports": 1,
                                "owner": owner,
                                "rentEpoch": 0,
                                "space": 0
                            }
                        }),
                        _ => serde_json::json!({
                            "context": {"slot": 1},
                            "value": [{
                                "slot": 1,
                                "confirmations": null,
                                "status": {"Ok": null},
                                "err": null,
                                "confirmationStatus": "finalized"
                            }]
                        }),
                    };
                    let response =
                        serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result})
                            .to_string();
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.len()
                    );
                    let _ = stream.write_all(headers.as_bytes());
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            Self {
                url: format!("http://{address}"),
                stop,
                thread: Some(thread),
            }
        }
    }

    #[cfg(feature = "server")]
    impl Drop for SessionAccountRpc {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;
            self.stop.store(true, Ordering::Relaxed);
            let _ = std::net::TcpStream::connect(self.url.trim_start_matches("http://"));
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[cfg(feature = "server")]
    fn encoded_channel(
        status: u8,
        deposit: u64,
        payer: Pubkey,
        payee: Pubkey,
        signer: Pubkey,
        mint: Pubkey,
    ) -> Vec<u8> {
        use crate::generated::payment_channels::generated::accounts::Channel;
        use crate::generated::payment_channels::generated::types::SettlementWatermarks;

        borsh::to_vec(&Channel {
            discriminator: 1,
            version: 1,
            bump: 255,
            status,
            salt: 7,
            deposit,
            settlement: SettlementWatermarks {
                settled: 0,
                payout_watermark: 0,
            },
            closure_started_at: 0,
            payer_withdrawn_at: 0,
            grace_period: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            distribution_hash: payment_channels::distribution_hash(&[]),
            payer: payment_channels::to_address(&payer),
            payee: payment_channels::to_address(&payee),
            authorized_signer: payment_channels::to_address(&signer),
            mint: payment_channels::to_address(&mint),
            rent_payer: payment_channels::to_address(&payee),
            open_slot: 42,
        })
        .unwrap()
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_open_binds_authoritative_channel_account() {
        let base = make_server();
        let payer = Pubkey::new_unique();
        let payee = parse_pubkey(&base.config.recipient).unwrap();
        let signer = Pubkey::new_unique();
        let mint = expected_payment_channel_mint(&base.config).unwrap();
        let params = payment_channels::OpenChannelParams {
            payer,
            rent_payer: payee,
            payee,
            mint,
            authorized_signer: signer,
            salt: 7,
            deposit: 1_000,
            grace_period: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            open_slot: 42,
            recipients: vec![],
            token_program: parse_pubkey(default_token_program_for_currency(
                "USDC",
                Some("localnet"),
            ))
            .unwrap(),
            program_id: payment_channels::default_program_id(),
        };
        let channel_id = payment_channels::derive_channel_addresses(&params).channel;
        let rpc = SessionAccountRpc::start(
            encoded_channel(CHANNEL_STATUS_OPEN, 4_000, payer, payee, signer, mint),
            params.program_id,
        );
        let server = SessionServer::new(
            SessionConfig {
                rpc_url: Some(rpc.url.clone()),
                modes: vec![SessionMode::Pull],
                ..base.config
            },
            MemoryChannelStore::new(),
        );
        let mut payload = OpenPayload::payment_channel(
            payment_channels::pubkey_string(&channel_id),
            "1000".to_string(),
            payment_channels::pubkey_string(&payer),
            payment_channels::pubkey_string(&payee),
            payment_channels::pubkey_string(&mint),
            7,
            payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            42,
            payment_channels::pubkey_string(&signer),
            bs58::encode([9u8; 64]).into_string(),
        );
        payload.mode = SessionMode::Pull;
        let mut transaction = solana_transaction::Transaction::new_unsigned(
            solana_message::Message::new(&[], Some(&payer)),
        );
        transaction.signatures[0] = solana_signature::Signature::from([9u8; 64]);
        let transaction = solana_transaction::versioned::VersionedTransaction::from(transaction);
        payload.transaction = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            bincode::serialize(&transaction).unwrap(),
        ));
        let state = server.process_open(&payload).await.unwrap();
        assert_eq!(state.deposit, 4_000);
        assert_eq!(state.salt, Some(7));
        assert_eq!(
            state.operator.as_deref(),
            Some(payment_channels::pubkey_string(&payer).as_str())
        );
    }

    #[cfg(feature = "server")]
    fn transaction_bound_open_payload(
        transaction_signature: solana_signature::Signature,
        claimed_signature: String,
    ) -> OpenPayload {
        let payer = Pubkey::new_unique();
        let mut transaction = solana_transaction::Transaction::new_unsigned(
            solana_message::Message::new(&[], Some(&payer)),
        );
        transaction.signatures[0] = transaction_signature;
        let transaction = solana_transaction::versioned::VersionedTransaction::from(transaction);
        let mut payload = open_payload("channel", 1_000, "signer");
        payload.signature = claimed_signature;
        payload.transaction = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            bincode::serialize(&transaction).unwrap(),
        ));
        payload
    }

    #[cfg(feature = "server")]
    #[test]
    fn open_transaction_signature_binding_rejects_placeholder_and_mismatch() {
        let placeholder = transaction_bound_open_payload(
            solana_signature::Signature::default(),
            solana_signature::Signature::default().to_string(),
        );
        assert!(bound_client_open_signature(&placeholder)
            .unwrap_err()
            .to_string()
            .contains("does not broadcast partially signed opens"));

        let transaction_signature = solana_signature::Signature::from([9u8; 64]);
        let mismatched = transaction_bound_open_payload(
            transaction_signature,
            solana_signature::Signature::from([8u8; 64]).to_string(),
        );
        assert!(bound_client_open_signature(&mismatched)
            .unwrap_err()
            .to_string()
            .contains("does not match transaction signature"));
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_topup_rejects_resulting_deposit_mismatch() {
        let base = make_server();
        let channel = Pubkey::new_unique();
        let channel_id = payment_channels::pubkey_string(&channel);
        let payer = Pubkey::new_unique();
        let payee = parse_pubkey(&base.config.recipient).unwrap();
        let signer = Pubkey::new_unique();
        let mint = expected_payment_channel_mint(&base.config).unwrap();
        let program_id = payment_channels::default_program_id();
        let rpc = SessionAccountRpc::start(
            encoded_channel(CHANNEL_STATUS_OPEN, 2_000, payer, payee, signer, mint),
            program_id,
        );
        let server = SessionServer::new(
            SessionConfig {
                rpc_url: Some(rpc.url.clone()),
                ..base.config
            },
            MemoryChannelStore::new(),
        );
        let mut stored = ChannelState {
            channel_id: channel_id.clone(),
            authorized_signer: payment_channels::pubkey_string(&Pubkey::new_unique()),
            deposit: 1_000,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            open_slot: Some(42),
            salt: Some(7),
            open_signature: None,
            operator: Some(payment_channels::pubkey_string(&payer)),
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
        };
        server
            .store
            .put_channel(&channel_id, stored.clone())
            .await
            .unwrap();

        let identity_error = server
            .process_topup(&TopUpPayload {
                channel_id: channel_id.clone(),
                new_deposit: "2000".to_string(),
                signature: bs58::encode([10u8; 64]).into_string(),
            })
            .await
            .unwrap_err();
        assert!(identity_error
            .to_string()
            .contains("authorized_signer does not match stored channel"));

        stored.authorized_signer = payment_channels::pubkey_string(&signer);
        server.store.put_channel(&channel_id, stored).await.unwrap();

        let error = server
            .process_topup(&TopUpPayload {
                channel_id: channel_id.clone(),
                new_deposit: "3000".to_string(),
                signature: bs58::encode([10u8; 64]).into_string(),
            })
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("on-chain channel deposit 2000 != asserted new_deposit 3000"));
        assert_eq!(
            server
                .store
                .get_channel(&channel_id)
                .await
                .unwrap()
                .unwrap()
                .deposit,
            1_000
        );
    }

    #[cfg(feature = "server")]
    #[test]
    fn channel_account_rejects_invalid_discriminator_version_and_length() {
        let base = make_server();
        let payer = Pubkey::new_unique();
        let payee = parse_pubkey(&base.config.recipient).unwrap();
        let signer = Pubkey::new_unique();
        let mint = expected_payment_channel_mint(&base.config).unwrap();
        let program = payment_channels::default_program_id();
        let channel = Pubkey::new_unique();
        let valid = encoded_channel(CHANNEL_STATUS_OPEN, 1_000, payer, payee, signer, mint);
        let mut bad_discriminator = valid.clone();
        bad_discriminator[0] = 9;
        let mut bad_version = valid.clone();
        bad_version[1] = 9;
        for data in [
            bad_discriminator,
            bad_version,
            valid[..valid.len() - 1].to_vec(),
        ] {
            let rpc = SessionAccountRpc::start(data, program);
            assert!(fetch_channel_account(&rpc.url, &channel, &program, 1).is_err());
        }
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_open_rejects_spent_or_economically_mismatched_channel_state() {
        use crate::generated::payment_channels::generated::accounts::Channel;

        let base = make_server();
        let payer = Pubkey::new_unique();
        let payee = parse_pubkey(&base.config.recipient).unwrap();
        let signer = Pubkey::new_unique();
        let mint = expected_payment_channel_mint(&base.config).unwrap();
        let program_id = payment_channels::default_program_id();
        let params = payment_channels::OpenChannelParams {
            payer,
            rent_payer: payee,
            payee,
            mint,
            authorized_signer: signer,
            salt: 7,
            deposit: 1_000,
            grace_period: payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            open_slot: 42,
            recipients: vec![],
            token_program: parse_pubkey(default_token_program_for_currency(
                "USDC",
                Some("localnet"),
            ))
            .unwrap(),
            program_id,
        };
        let channel_id = payment_channels::derive_channel_addresses(&params).channel;
        let payload = OpenPayload::payment_channel(
            payment_channels::pubkey_string(&channel_id),
            "1000".to_string(),
            payment_channels::pubkey_string(&payer),
            payment_channels::pubkey_string(&payee),
            payment_channels::pubkey_string(&mint),
            7,
            payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
            42,
            payment_channels::pubkey_string(&signer),
            bs58::encode([9u8; 64]).into_string(),
        );

        type ChannelMutation = Box<dyn Fn(&mut Channel)>;
        let cases: Vec<(&str, ChannelMutation)> = vec![
            (
                "settled",
                Box::new(|channel| channel.settlement.settled = 1),
            ),
            (
                "payout watermark",
                Box::new(|channel| channel.settlement.payout_watermark = 1),
            ),
            (
                "grace period",
                Box::new(|channel| channel.grace_period += 1),
            ),
            (
                "distribution hash",
                Box::new(|channel| channel.distribution_hash[0] ^= 0xff),
            ),
            ("salt", Box::new(|channel| channel.salt += 1)),
            ("open slot", Box::new(|channel| channel.open_slot += 1)),
        ];
        for (name, mutate) in cases {
            let mut channel = Channel::from_bytes(&encoded_channel(
                CHANNEL_STATUS_OPEN,
                1_000,
                payer,
                payee,
                signer,
                mint,
            ))
            .unwrap();
            mutate(&mut channel);
            let rpc = SessionAccountRpc::start(borsh::to_vec(&channel).unwrap(), program_id);
            let server = SessionServer::new(
                SessionConfig {
                    rpc_url: Some(rpc.url.clone()),
                    ..base.config.clone()
                },
                MemoryChannelStore::new(),
            );
            let error = server.process_open(&payload).await.unwrap_err();
            assert!(!error.to_string().is_empty(), "{name} was accepted");
        }
    }

    #[tokio::test]
    async fn begin_delivery_rejects_capacity_and_sequence_overflow() {
        let server = make_server();
        server
            .store
            .put_channel(
                "overflow",
                ChannelState {
                    channel_id: "overflow".to_string(),
                    authorized_signer: "signer".to_string(),
                    deposit: u64::MAX,
                    cumulative: 0,
                    sealed: false,
                    highest_voucher_signature: None,
                    highest_voucher_expires_at: None,
                    close_requested_at: None,
                    open_slot: None,
                    salt: None,
                    open_signature: None,
                    operator: None,
                    next_delivery_sequence: 0,
                    pending_deliveries: vec![
                        PendingDelivery {
                            delivery_id: "a".to_string(),
                            amount: u64::MAX,
                            sequence: 1,
                            expires_at: i64::MAX,
                        },
                        PendingDelivery {
                            delivery_id: "b".to_string(),
                            amount: 1,
                            sequence: 2,
                            expires_at: i64::MAX,
                        },
                    ],
                    committed_deliveries: vec![],
                },
            )
            .await
            .unwrap();
        let error = server
            .begin_delivery(DeliveryRequest {
                session_id: "overflow".to_string(),
                amount: 1,
                delivery_id: None,
                commit_url: None,
                proof: None,
                expires_at: None,
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("overflow"));

        server
            .store
            .update_channel(
                "overflow",
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.pending_deliveries.clear();
                    state.next_delivery_sequence = u64::MAX;
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let error = server
            .begin_delivery(DeliveryRequest {
                session_id: "overflow".to_string(),
                amount: 1,
                delivery_id: None,
                commit_url: None,
                proof: None,
                expires_at: None,
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("sequence overflow"));
    }

    #[tokio::test]
    async fn process_open_without_rpc_fails_closed_off_localnet() {
        let server = SessionServer::new(
            SessionConfig {
                network: "devnet".to_string(),
                allow_unsafe_ephemeral_store_off_localnet: true,
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let error = server
            .process_open(&open_payload("chan1", 1_000, "signer1"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("requires an rpc_url"));
    }

    #[tokio::test]
    async fn process_open_rejects_ephemeral_store_off_localnet() {
        let server = SessionServer::new(
            SessionConfig {
                network: "devnet".to_string(),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let error = server
            .process_open(&open_payload("chan1", 1_000, "signer1"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("ephemeral session store"));
    }

    #[tokio::test]
    async fn process_open_rejects_unmarked_store_off_localnet() {
        let server = SessionServer::new(
            SessionConfig {
                network: "devnet".to_string(),
                ..make_server().config
            },
            TestStore::new(SessionStoreDurability::Unknown),
        );
        let error = server
            .process_open(&open_payload("chan1", 1_000, "signer1"))
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("explicitly declare durable shared"));
    }

    #[tokio::test]
    async fn state_operations_reject_ephemeral_store_off_localnet() {
        let server = SessionServer::new(
            SessionConfig {
                network: "devnet".to_string(),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let error = server
            .begin_delivery(DeliveryRequest::new("preloaded", 1))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("ephemeral session store"));
        let error = server.mark_sealed("preloaded").await.unwrap_err();
        assert!(error.to_string().contains("ephemeral session store"));
    }

    #[tokio::test]
    async fn process_open_accepts_marked_durable_store_before_rpc_gate() {
        let server = SessionServer::new(
            SessionConfig {
                network: "devnet".to_string(),
                ..make_server().config
            },
            TestStore::new(SessionStoreDurability::DurableShared),
        );
        let error = server
            .process_open(&open_payload("chan1", 1_000, "signer1"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("requires an rpc_url"));
    }

    #[tokio::test]
    async fn process_topup_without_rpc_fails_closed_off_localnet() {
        let server = SessionServer::new(
            SessionConfig {
                network: "mainnet".to_string(),
                allow_unsafe_ephemeral_store_off_localnet: true,
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let error = server
            .process_topup(&TopUpPayload {
                channel_id: "chan1".to_string(),
                new_deposit: "3000".to_string(),
                signature: "sig".to_string(),
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("requires an rpc_url"));
    }

    // ── process_close ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn process_close_no_voucher() {
        let server = make_server();
        let chan = bs58::encode(Pubkey::new_unique().as_ref()).into_string();
        server
            .process_open(&open_payload(&chan, 5_000_000, "s"))
            .await
            .unwrap();

        let params = server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap();
        assert_eq!(params.settled, 0);
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn process_close_with_voucher() {
        let server = make_server();
        let (mut session, auth_signer, chan_str, _) = make_e2e_session();
        server
            .process_open(&open_payload(&chan_str, 5_000_000, &auth_signer))
            .await
            .unwrap();

        // Consume 500k first
        let v1 = session.sign_increment(500_000).await.unwrap();
        server
            .verify_voucher(&VoucherPayload { voucher: v1 })
            .await
            .unwrap();

        // Close with a final 200k voucher
        let final_voucher = session.sign_increment(200_000).await.unwrap();
        let params = server
            .process_close(&ClosePayload {
                channel_id: chan_str,
                voucher: Some(final_voucher),
            })
            .await
            .unwrap();
        assert_eq!(params.settled, 700_000);
    }

    #[tokio::test]
    async fn process_close_unknown_channel_rejected() {
        let server = make_server();
        let err = server
            .process_close(&ClosePayload {
                channel_id: bs58::encode(Pubkey::new_unique().as_ref()).into_string(),
                voucher: None,
            })
            .await;
        assert!(err.is_err());
    }

    // ── seal_params ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn seal_params_correct() {
        let server = make_server();
        let channel = Pubkey::new_unique();
        let chan_str = bs58::encode(channel.as_ref()).into_string();
        server
            .process_open(&open_payload(&chan_str, 5_000_000, "s"))
            .await
            .unwrap();

        let params = server.seal_params(&chan_str).await.unwrap();
        assert_eq!(params.channel_id, channel);
        assert_eq!(params.settled, 0);
        assert_eq!(
            params.mint,
            Some(expected_payment_channel_mint(&server.config).unwrap())
        );
        assert!(params.splits.is_empty());
        // Hash with no splits should be deterministic
        let recipient = parse_pubkey(RECIPIENT).unwrap();
        let expected_hash = compute_distribution_hash(&recipient, &[]);
        assert_eq!(params.distribution_hash, expected_hash);
    }

    #[tokio::test]
    async fn seal_params_unknown_channel_rejected() {
        let server = make_server();
        let err = server
            .seal_params(&bs58::encode(Pubkey::new_unique().as_ref()).into_string())
            .await;
        assert!(err.is_err());
    }

    // ── mark_sealed ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mark_sealed_sets_flag() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 1_000_000, "s"))
            .await
            .unwrap();
        server.mark_sealed("chan1").await.unwrap();

        let state = server.store.get_channel("chan1").await.unwrap().unwrap();
        assert!(state.sealed);
    }

    #[tokio::test]
    async fn mark_sealed_unknown_channel_errors() {
        let server = make_server();
        assert!(server.mark_sealed("ghost").await.is_err());
    }

    // ── distribution_hash ─────────────────────────────────────────────────────

    #[test]
    fn distribution_hash_deterministic() {
        let r = Pubkey::new_unique();
        let s1 = Pubkey::new_unique();
        let h1 = compute_distribution_hash(&r, &[(s1, 5_000)]);
        let h2 = compute_distribution_hash(&r, &[(s1, 5_000)]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn distribution_hash_empty_splits() {
        let r = Pubkey::new_unique();
        let h = compute_distribution_hash(&r, &[]);
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn distribution_hash_changes_with_amount() {
        let r = Pubkey::new_unique();
        let s = Pubkey::new_unique();
        assert_ne!(
            compute_distribution_hash(&r, &[(s, 100)]),
            compute_distribution_hash(&r, &[(s, 200)]),
        );
    }

    #[test]
    fn distribution_hash_empty_splits_ignores_implicit_payee() {
        let r1 = Pubkey::new_unique();
        let r2 = Pubkey::new_unique();
        assert_eq!(
            compute_distribution_hash(&r1, &[]),
            compute_distribution_hash(&r2, &[]),
        );
    }

    #[test]
    fn distribution_hash_changes_with_split_recipient() {
        let r = Pubkey::new_unique();
        let s1 = Pubkey::new_unique();
        let s2 = Pubkey::new_unique();
        assert_ne!(
            compute_distribution_hash(&r, &[(s1, 100)]),
            compute_distribution_hash(&r, &[(s2, 100)]),
        );
    }

    // ── parse_pubkey helper ───────────────────────────────────────────────────

    #[test]
    fn parse_pubkey_valid() {
        let pk = Pubkey::new_unique();
        let s = bs58::encode(pk.as_ref()).into_string();
        assert_eq!(parse_pubkey(&s).unwrap(), pk);
    }

    #[test]
    fn parse_pubkey_invalid_base58() {
        assert!(parse_pubkey("not!!valid").is_err());
    }

    #[test]
    fn parse_pubkey_wrong_length() {
        // Valid base58 but only 10 bytes
        let s = bs58::encode(&[1u8; 10]).into_string();
        assert!(parse_pubkey(&s).is_err());
    }

    // ── verify_voucher: idempotent replay ────────────────────────────────────

    #[tokio::test]
    async fn verify_voucher_idempotent_replay() {
        let server = make_server();
        // Manually set up a channel with a known highest_voucher_signature
        use crate::mpp::store::ChannelState;
        server
            .store
            .put_channel(
                "chan1",
                ChannelState {
                    channel_id: "chan1".to_string(),
                    authorized_signer: "signer1".to_string(),
                    deposit: 5_000_000,
                    cumulative: 1_000_000,
                    sealed: false,
                    highest_voucher_signature: Some("replay_sig".to_string()),
                    highest_voucher_expires_at: None,
                    close_requested_at: None,
                    open_slot: None,
                    salt: None,
                    open_signature: None,
                    operator: None,
                    next_delivery_sequence: 0,
                    pending_deliveries: vec![],
                    committed_deliveries: vec![],
                },
            )
            .await
            .unwrap();

        // A voucher with same cumulative AND same signature is idempotent replay
        // (signature verify will fail since it's fake, but let's test the path up to sig verify)
        // We just need to confirm it does NOT fail with "must exceed watermark"
        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "1000000".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "replay_sig".to_string(),
        };
        let err = server
            .verify_voucher(&VoucherPayload { voucher })
            .await
            .unwrap_err();
        // Should fail at signature verification, not watermark check
        let msg = err.to_string();
        assert!(!msg.contains("watermark"), "Expected sig error, got: {msg}");
        // The error is from crypto validation (bad encoding, wrong length, bad key, etc.)
        // Any error other than "watermark" means idempotent replay path was taken correctly
        assert!(
            msg.contains("signature")
                || msg.contains("encoding")
                || msg.contains("Invalid")
                || msg.contains("bytes")
                || msg.contains("key")
                || msg.contains("channelId"),
            "Expected signature-related error, got: {msg}"
        );
    }

    // ── verify_voucher: min_delta enforcement ────────────────────────────────

    #[tokio::test]
    async fn verify_voucher_min_delta_enforced() {
        let server = make_server_with_min_delta(500_000);
        server
            .process_open(&open_payload("chan1", 5_000_000, "signer1"))
            .await
            .unwrap();

        // delta = 100_000, min = 500_000 → should be rejected
        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "100000".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        let err = server
            .verify_voucher(&VoucherPayload { voucher })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "Expected min delta error, got: {err}"
        );
    }

    // ── verify_voucher: close-pending rejection ──────────────────────────────

    #[tokio::test]
    async fn verify_voucher_close_pending_rejected() {
        let server = make_server();
        let chan = bs58::encode(Pubkey::new_unique().as_ref()).into_string();
        server
            .process_open(&open_payload(&chan, 5_000_000, "s"))
            .await
            .unwrap();

        // Close the channel first
        server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap();

        // Now try to submit a voucher — should be rejected
        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: chan.clone(),
                cumulative: "100000".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        let err = server
            .verify_voucher(&VoucherPayload { voucher })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("close is pending"),
            "Expected close-pending error, got: {err}"
        );
    }

    // ── process_close: sets close_requested_at ───────────────────────────────

    #[tokio::test]
    async fn process_close_sets_close_pending() {
        let server = make_server();
        let chan = bs58::encode(Pubkey::new_unique().as_ref()).into_string();
        server
            .process_open(&open_payload(&chan, 5_000_000, "s"))
            .await
            .unwrap();

        server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap();

        let state = server.store.get_channel(&chan).await.unwrap().unwrap();
        assert!(
            state.close_requested_at.is_some(),
            "Expected close_requested_at to be set"
        );
    }

    // ── process_close: prevents double-close ─────────────────────────────────

    #[tokio::test]
    async fn process_close_prevents_double_close() {
        let server = make_server();
        let chan = bs58::encode(Pubkey::new_unique().as_ref()).into_string();
        server
            .process_open(&open_payload(&chan, 5_000_000, "s"))
            .await
            .unwrap();

        // First close succeeds
        server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap();

        // Second close should fail
        let err = server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Close already requested")
                || err.to_string().contains("close"),
            "Expected double-close error, got: {err}"
        );
    }
}
