//! Client-side session intent implementation.
//!
//! Tracks an open payment channel and signs cumulative vouchers for each
//! API call. Vouchers are Ed25519-signed over the on-chain Borsh voucher
//! layout used by the payment-channels program.
//!
//! # Example
//!
//! ```ignore
//! use crate::mpp::client::session::ActiveSession;
//!
//! // Obtain a signer (e.g. MemorySigner, hardware wallet, cloud KMS):
//! let signer: Box<dyn solana_keychain::SolanaSigner> = ...;
//! let channel_id = /* Pubkey of the opened on-chain channel */;
//!
//! let mut session = ActiveSession::new(channel_id, signer);
//!
//! // Before each API call, sign a voucher incremented by the request price:
//! let voucher = session.sign_increment(50_000).await?; // +0.05 USDC
//! // Attach voucher to Authorization header via SessionAction::Voucher
//! ```

use std::str::FromStr;

use solana_hash::Hash;
use solana_keychain::{SolanaSigner, TransactionSigner};
use solana_pubkey::Pubkey;

use crate::mpp::error::{Error, Result};
use crate::mpp::program::payment_channels::{
    build_open_payment_channel_tx_with_options, derive_channel_addresses, random_salt,
    Distribution, OpenChannelParams, OpenTxOptions, PaymentChannelOpenTransaction,
};
use crate::mpp::protocol::intents::session::{
    ClosePayload, OpenPayload, SessionAction, SessionAuthentication, SessionRequest,
    SessionVoucherSigner, SignedVoucher, TopUpPayload, VoucherData, VoucherPayload,
    VoucherSignatureType, DEFAULT_SESSION_EXPIRES_AT,
};
use crate::mpp::protocol::solana::default_token_program_for_currency;

/// Default payment-channel close grace period (seconds). Re-exported from
/// `solana-pay-core` to preserve this crate's public path.
pub use crate::mpp::program::payment_channels::DEFAULT_GRACE_PERIOD_SECONDS;

/// Default voucher expiry: 2100-01-01T00:00:00Z.
///
/// This stays below JavaScript's max safe integer so JSON intermediaries do not
/// round it before the credential is decoded.
pub const DEFAULT_VOUCHER_EXPIRES_AT: i64 = DEFAULT_SESSION_EXPIRES_AT;

/// Tracks the client-side state of an active payment session.
///
/// Holds a `SolanaSigner` session key and advances the cumulative watermark
/// with each signed voucher. The signer may be a local memory signer, a
/// hardware wallet, or any cloud KMS — all are supported through the trait.
pub struct ActiveSession {
    /// On-chain channel address.
    pub channel_id: Pubkey,

    /// Cumulative amount authorized so far (base units).
    pub cumulative: u64,

    /// Unix timestamp at which newly signed vouchers expire.
    expires_at: i64,

    /// Session signing key.
    signer: Box<dyn SolanaSigner>,
}

impl ActiveSession {
    /// Create a new session tracker.
    ///
    /// `channel_id` is the on-chain channel address obtained after opening.
    /// `signer` is the session key — its public key becomes the `authorizedSigner`
    /// passed to the server in the `open` action.
    pub fn new(channel_id: Pubkey, signer: Box<dyn SolanaSigner>) -> Self {
        Self {
            channel_id,
            cumulative: 0,
            expires_at: DEFAULT_VOUCHER_EXPIRES_AT,
            signer,
        }
    }

    /// Create a new session tracker with an explicit voucher expiry.
    pub fn new_with_expiry(
        channel_id: Pubkey,
        signer: Box<dyn SolanaSigner>,
        expires_at: i64,
    ) -> Self {
        Self {
            channel_id,
            cumulative: 0,
            expires_at,
            signer,
        }
    }

    /// Update the expiry timestamp used for subsequent vouchers.
    pub fn set_expires_at(&mut self, expires_at: i64) {
        self.expires_at = expires_at;
    }

    /// The authorized signer public key (base58), for the `open` action payload.
    pub fn authorized_signer(&self) -> String {
        bs58::encode(self.signer.pubkey().as_ref()).into_string()
    }

    /// Channel ID as base58.
    pub fn channel_id_str(&self) -> String {
        bs58::encode(self.channel_id.as_ref()).into_string()
    }

    /// Sign a voucher with an absolute cumulative amount.
    ///
    /// `cumulative` MUST be strictly greater than the current watermark.
    pub async fn sign_voucher(&mut self, cumulative: u64) -> Result<SignedVoucher> {
        let voucher = self.prepare_voucher(cumulative).await?;
        self.record_voucher(&voucher)?;
        Ok(voucher)
    }

    /// Prepare a signed voucher without advancing the local watermark.
    ///
    /// This is useful for ack/commit transports: if sending the commit fails,
    /// the client can retry the same cumulative amount without its local state
    /// drifting ahead of the server.
    pub async fn prepare_voucher(&self, cumulative: u64) -> Result<SignedVoucher> {
        if cumulative <= self.cumulative {
            return Err(Error::Other(format!(
                "Voucher cumulative {cumulative} must exceed current watermark {}",
                self.cumulative
            )));
        }

        let data = VoucherData {
            channel_id: self.channel_id_str(),
            cumulative_amount: cumulative.to_string(),
            expires_at: Some(self.expires_at),
        };

        let bytes = data.message_bytes()?;
        let sig = self
            .signer
            .sign_message(&bytes)
            .await
            .map_err(|e| Error::Other(format!("Signing failed: {e}")))?;
        let sig_b58 = bs58::encode(sig.as_ref()).into_string();

        Ok(SignedVoucher {
            data,
            signer: self.authorized_signer(),
            signature: sig_b58,
            signature_type: VoucherSignatureType::Ed25519,
        })
    }

    /// Prepare a signed voucher adding `amount` without advancing the watermark.
    pub async fn prepare_increment(&self, amount: u64) -> Result<SignedVoucher> {
        self.prepare_voucher(self.incremented(amount)?).await
    }

    fn incremented(&self, amount: u64) -> Result<u64> {
        self.cumulative.checked_add(amount).ok_or_else(|| {
            Error::Other(format!(
                "voucher increment {amount} overflows the cumulative {}",
                self.cumulative
            ))
        })
    }

    /// Record a prepared voucher as accepted by the server.
    pub fn record_voucher(&mut self, voucher: &SignedVoucher) -> Result<()> {
        let cumulative = voucher
            .data
            .cumulative_amount
            .parse::<u64>()
            .map_err(|_| Error::Other("invalid voucher cumulative".to_string()))?;
        if cumulative <= self.cumulative {
            return Err(Error::Other(format!(
                "Voucher cumulative {cumulative} must exceed current watermark {}",
                self.cumulative
            )));
        }
        self.cumulative = cumulative;
        Ok(())
    }

    /// Sign a voucher adding `amount` to the current cumulative.
    pub async fn sign_increment(&mut self, amount: u64) -> Result<SignedVoucher> {
        self.sign_voucher(self.incremented(amount)?).await
    }

    /// Build a `SessionAction::Voucher` for an increment without advancing the
    /// local watermark. Call [`record_voucher`](Self::record_voucher) once the
    /// server accepts it; concurrent prepares sign the same voucher, which the
    /// server accepts once, so a rejected request never raises the watermark.
    pub async fn prepare_voucher_action(&self, amount: u64) -> Result<SessionAction> {
        let voucher = self.prepare_increment(amount).await?;
        Ok(SessionAction::Voucher(VoucherPayload {
            channel_id: voucher.data.channel_id.clone(),
            voucher,
        }))
    }

    /// Build a `SessionAction::Voucher` wrapping a freshly-signed increment.
    ///
    /// The local watermark advances before the server has seen the voucher.
    /// Requests sharing one session must not be in flight concurrently with
    /// this: if a higher voucher lands first, the lower request is rejected
    /// while the channel still settles the higher watermark. Use
    /// [`prepare_voucher_action`](Self::prepare_voucher_action) and
    /// [`record_voucher`](Self::record_voucher) instead.
    pub async fn voucher_action(&mut self, amount: u64) -> Result<SessionAction> {
        let voucher = self.sign_increment(amount).await?;
        Ok(SessionAction::Voucher(VoucherPayload {
            channel_id: voucher.data.channel_id.clone(),
            voucher,
        }))
    }

    /// Build a `SessionAction::Close` for cooperative channel close.
    ///
    /// If `final_increment` is `Some(n)` and `n > 0`, signs one last voucher
    /// for the remaining balance before closing.
    pub async fn close_action(&mut self, final_increment: Option<u64>) -> Result<SessionAction> {
        let voucher = match final_increment {
            Some(amount) if amount > 0 => Some(self.sign_increment(amount).await?),
            _ => None,
        };
        Ok(SessionAction::Close(ClosePayload {
            channel_id: self.channel_id_str(),
            authentication: None,
            voucher,
        }))
    }

    /// Build a `SessionAction::Open` for the payment-channels program.
    #[allow(clippy::too_many_arguments)]
    pub fn open_payment_channel_action(
        &self,
        deposit: u64,
        payer: &str,
        payee: &str,
        mint: &str,
        salt: u64,
        grace_period: u32,
        open_slot: u64,
        transaction: &str,
    ) -> SessionAction {
        SessionAction::Open(OpenPayload::payment_channel(
            self.channel_id_str(),
            deposit.to_string(),
            payer.to_string(),
            payee.to_string(),
            mint.to_string(),
            salt,
            grace_period,
            open_slot,
            self.authorized_signer(),
            transaction.to_string(),
        ))
    }

    /// Build a `SessionAction::TopUp` after a top-up transaction.
    pub fn topup_action(&self, additional_amount: u64, transaction: &str) -> SessionAction {
        SessionAction::TopUp(TopUpPayload {
            channel_id: self.channel_id_str(),
            additional_amount: additional_amount.to_string(),
            transaction: transaction.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PaymentChannelOpen {
    pub channel_id: Pubkey,
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    pub salt: u64,
    /// Slot at which the channel is opened — a channel-PDA seed (fetched via
    /// RPC `getSlot` at open time).
    pub open_slot: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub recipients: Vec<Distribution>,
    pub token_program: Pubkey,
    pub program_id: Pubkey,
    /// Deployment identity retained alongside the derived channel address.
    pub channel_version: Option<u8>,
    pub channel_hooks: Option<crate::core::payment_channels_v2::ChannelHooks>,
}

impl PaymentChannelOpen {
    /// Build a top-up using the same deployment and mandatory funding callbacks
    /// approved at opening. Callback CPIs remain inside the channel instruction.
    pub fn top_up_instruction(
        &self,
        additional_amount: u64,
    ) -> Result<solana_instruction::Instruction> {
        let deployment = crate::mpp::program::channel_deployment::resolve(
            self.program_id,
            self.channel_version,
            self.channel_hooks.as_ref(),
        )?;
        if deployment.version == 2 {
            Ok(crate::core::payment_channels_v2::build_top_up_instruction(
                &self.payer,
                &self.channel_id,
                &self.mint,
                additional_amount,
                &self.token_program,
                &self.program_id,
                &self.channel_hooks.clone().unwrap_or_default(),
            )?)
        } else {
            Ok(crate::core::payment_channels::build_top_up_instruction(
                &self.payer,
                &self.channel_id,
                &self.mint,
                additional_amount,
                &self.token_program,
                &self.program_id,
            ))
        }
    }

    /// Derive this open's channel PDA.
    ///
    /// `rentPayer` is intentionally absent: it is not a channel-PDA seed (see
    /// `find_channel_pda`), and exposing a full `OpenChannelParams` here would
    /// let an external caller pass it to `build_open_instruction` and produce an
    /// open whose `rentPayer` is the channel payer instead of the operator /
    /// fee payer. The real `rentPayer` pin (== fee payer) happens inside
    /// `build_open_payment_channel_tx`.
    pub fn channel_address(&self) -> Pubkey {
        derive_channel_addresses(&OpenChannelParams {
            payer: self.payer,
            // Not a PDA seed; fixed to `payer` only so the derivation type can be
            // reused. Never surfaced to instruction building.
            rent_payer: self.payer,
            payee: self.payee,
            mint: self.mint,
            authorized_signer: self.authorized_signer,
            salt: self.salt,
            open_slot: self.open_slot,
            deposit: self.deposit,
            grace_period: self.grace_period,
            recipients: self.recipients.clone(),
            token_program: self.token_program,
            program_id: self.program_id,
        })
        .channel
    }

    pub fn open_payload(&self, transaction: impl Into<String>) -> OpenPayload {
        let mut payload = OpenPayload::payment_channel(
            pubkey_string(&self.channel_id),
            self.deposit.to_string(),
            pubkey_string(&self.payer),
            pubkey_string(&self.payee),
            pubkey_string(&self.mint),
            self.salt,
            self.grace_period,
            self.open_slot,
            pubkey_string(&self.authorized_signer),
            transaction.into(),
        );
        payload.distribution_splits = self
            .recipients
            .iter()
            .map(
                |split| crate::mpp::protocol::intents::session::SessionSplit {
                    recipient: pubkey_string(&split.recipient),
                    share_bps: split.bps,
                },
            )
            .collect();
        payload
    }
}

#[derive(Debug, Clone, Default)]
pub struct PaymentChannelOpenOptions {
    /// Highest message version the signer can sign, when that is below what
    /// the challenge accepts. The Ledger Solana app signs version 0 but not
    /// yet version 1. `None` takes the highest version the challenge accepts.
    pub max_tx_version: Option<crate::core::tx::TxVersion>,
    /// ComputeBudget instructions on version 0, or header config on version 1.
    /// `None` preserves the core transaction builder's defaults. Explicit
    /// budgets remain subject to the server's fee-sponsorship policy.
    pub compute_budget: Option<crate::core::tx::ComputeBudget>,
    /// Grace period to open with instead of the challenge's
    /// `gracePeriodSeconds`. Either is bounded by the authorization's
    /// [`SessionOpenAuthorization::max_grace_period`].
    pub grace_period: Option<u32>,
    /// Override for the channel's open slot (the program's `openSlot`).
    /// Defaults to the challenge's `recentSlot`. An override MAY be earlier
    /// (shortening the operator's post-close rent float) but never later —
    /// the server rejects an `openSlot` ahead of its challenged `recentSlot`.
    pub open_slot: Option<u64>,
    pub program_id: Option<Pubkey>,
    pub recipients: Option<Vec<Distribution>>,
    pub salt: Option<u64>,
    pub token_program: Option<Pubkey>,
    /// Payout terms the caller approved, typically [`SessionPayout::from_request`]
    /// checked against a destination policy. When set, opening fails unless
    /// the channel's payee and distribution splits are exactly these, so a
    /// challenge cannot commit escrow to destinations nobody approved.
    pub approved_payout: Option<SessionPayout>,
}

/// Where a session channel pays out: the payee and the ordered distribution
/// splits committed at open. These, not the deposit, decide who can settle
/// the escrow, so they belong in any approval of a session challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPayout {
    /// Channel payee (`recipient`).
    pub payee: Pubkey,
    /// `methodDetails.distributionSplits`, in challenge order.
    pub splits: Vec<Distribution>,
}

impl SessionPayout {
    /// The payout a session challenge asks the client to commit to.
    pub fn from_request(request: &SessionRequest) -> Result<Self> {
        Ok(Self {
            payee: parse_pubkey(&request.recipient, "recipient")?,
            splits: parse_splits(request)?,
        })
    }
}

/// Longest grace period [`SessionOpenAuthorization`] accepts unless the
/// caller sets another (30 days). The grace period is how long the payer
/// waits, after asking to close, before it can withdraw what was not settled.
pub const MAX_SESSION_GRACE_PERIOD_SECONDS: u32 = 2_592_000;

/// The escrow terms a caller authorizes for one channel open.
///
/// A session challenge proposes a deposit, who signs vouchers and how long
/// the payer's exit takes; this decides which of them the client signs. The
/// deposit is the caller's, never the challenge's `suggestedDeposit`; an
/// operator-signed channel, whose operator can settle up to the whole
/// deposit with its own vouchers, needs that operator named here; and the
/// grace period is bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOpenAuthorization {
    deposit: u64,
    operator: Option<Pubkey>,
    max_grace_period: u32,
}

impl SessionOpenAuthorization {
    /// Lock `deposit` base units in a channel whose vouchers the client signs.
    /// A challenge asking for operator vouchers is refused.
    pub fn client_signed(deposit: u64) -> Self {
        Self {
            deposit,
            operator: None,
            max_grace_period: MAX_SESSION_GRACE_PERIOD_SECONDS,
        }
    }

    /// Lock `deposit` base units and also accept a challenge whose vouchers
    /// `operator` signs. That operator can settle up to the whole deposit, so
    /// `deposit` is what the caller is prepared to pay it.
    pub fn operator_signed(deposit: u64, operator: Pubkey) -> Self {
        Self {
            operator: Some(operator),
            ..Self::client_signed(deposit)
        }
    }

    /// Replace the grace-period ceiling ([`MAX_SESSION_GRACE_PERIOD_SECONDS`]
    /// by default).
    pub fn with_max_grace_period(mut self, seconds: u32) -> Result<Self> {
        if seconds == 0 {
            return Err(Error::Other(
                "maximum grace period must be greater than zero".to_string(),
            ));
        }
        self.max_grace_period = seconds;
        Ok(self)
    }

    pub fn deposit(&self) -> u64 {
        self.deposit
    }

    pub fn operator(&self) -> Option<Pubkey> {
        self.operator
    }

    pub fn max_grace_period(&self) -> u32 {
        self.max_grace_period
    }
}

#[derive(Debug, Clone)]
pub struct DerivePaymentChannelOpenParams<'a> {
    pub request: &'a SessionRequest,
    pub payer: Pubkey,
    pub authorized_signer: Pubkey,
    pub authorization: &'a SessionOpenAuthorization,
    pub options: PaymentChannelOpenOptions,
}

pub struct PaymentChannelSessionOpen {
    pub open: PaymentChannelOpen,
    pub session: ActiveSession,
    pub action: SessionAction,
}

#[derive(Default)]
pub struct PaymentChannelSessionOpenOptions {
    pub open: PaymentChannelOpenOptions,
    pub cumulative: Option<u64>,
    pub expires_at: Option<i64>,
    pub authentication: Option<SessionAuthentication>,
    pub idle_timeout_seconds: Option<u32>,
}

pub fn derive_payment_channel_open(
    params: DerivePaymentChannelOpenParams<'_>,
) -> Result<PaymentChannelOpen> {
    let request = params.request;
    let details = &request.method_details;
    validate_challenge(request)?;
    let network = Some(details.network.as_str());
    let mint = parse_pubkey(
        crate::mpp::protocol::solana::try_resolve_stablecoin_mint(&request.currency, network)?
            .ok_or_else(|| Error::Other("session payment channels require an SPL token".into()))?,
        "mint",
    )?;
    let payee = parse_pubkey(&request.recipient, "recipient")?;
    let authorization = params.authorization;
    if details.voucher_signer == Some(SessionVoucherSigner::Operator) {
        let operator = parse_pubkey(
            details.operator.as_deref().ok_or_else(|| {
                Error::Other("operator is required for operator vouchers".to_string())
            })?,
            "operator",
        )?;
        if authorization.operator != Some(operator) {
            return Err(Error::Other(format!(
                "session challenge asks for vouchers signed by operator {operator}, which the \
                 caller did not authorize"
            )));
        }
        if params.authorized_signer != operator {
            return Err(Error::Other(
                "authorized signer is not the challenge's operator".to_string(),
            ));
        }
    }
    let deposit = authorization.deposit;
    if request
        .minimum_deposit
        .as_deref()
        .map(|value| parse_u64_string(value, "minimumDeposit"))
        .transpose()?
        .is_some_and(|minimum| deposit < minimum)
    {
        return Err(Error::Other("deposit is below minimumDeposit".to_string()));
    }
    let grace_period = params
        .options
        .grace_period
        .or(details.grace_period_seconds)
        .ok_or_else(|| Error::Other("session challenge missing gracePeriodSeconds".to_string()))?;
    if grace_period > authorization.max_grace_period {
        return Err(Error::Other(format!(
            "session gracePeriodSeconds {grace_period} exceeds the authorized maximum {}",
            authorization.max_grace_period
        )));
    }
    let program_id = parse_pubkey(&details.channel_program, "channelProgram")?;
    crate::mpp::program::channel_deployment::resolve_for_network(
        program_id,
        details.channel_version,
        details.channel_hooks.as_ref(),
        &details.network,
    )?;
    if params
        .options
        .program_id
        .is_some_and(|override_id| override_id != program_id)
    {
        return Err(Error::Other(
            "program override does not match channelProgram".into(),
        ));
    }
    let token_program = match params.options.token_program {
        Some(token_program) => token_program,
        None => match details.token_program.as_deref() {
            Some(program) => parse_pubkey(program, "tokenProgram")?,
            None => parse_pubkey(
                default_token_program_for_currency(&request.currency, network),
                "token program",
            )?,
        },
    };
    let recipients = match params.options.recipients {
        Some(recipients) => recipients,
        None => parse_splits(request)?,
    };
    if let Some(approved) = &params.options.approved_payout {
        if approved.payee != payee || approved.splits != recipients {
            return Err(Error::Other(
                "session payout does not match the approved payee and distribution splits"
                    .to_string(),
            ));
        }
    }
    let salt = params.options.salt.unwrap_or_else(random_salt);
    let open_slot = match params.options.open_slot {
        Some(open_slot) => {
            if details.recent_slot.is_some_and(|recent| open_slot > recent) {
                return Err(Error::Other(format!(
                    "openSlot override {open_slot} is ahead of the challenged recentSlot {}",
                    details.recent_slot.unwrap_or_default()
                )));
            }
            open_slot
        }
        None => details.recent_slot.ok_or_else(|| {
            Error::Other(
                "session challenge is missing recentSlot; a new-channel challenge must provide it"
                    .to_string(),
            )
        })?,
    };
    let open_params = OpenChannelParams {
        payer: params.payer,
        // rentPayer does not affect channel-PDA derivation (the only use here);
        // the real rentPayer pin (== fee payer) happens in
        // `build_open_payment_channel_tx`.
        rent_payer: params.payer,
        payee,
        mint,
        authorized_signer: params.authorized_signer,
        salt,
        open_slot,
        deposit,
        grace_period,
        recipients,
        token_program,
        program_id,
    };
    let channel_id = derive_channel_addresses(&open_params).channel;

    Ok(PaymentChannelOpen {
        channel_id,
        payer: open_params.payer,
        payee: open_params.payee,
        mint: open_params.mint,
        authorized_signer: open_params.authorized_signer,
        salt: open_params.salt,
        open_slot: open_params.open_slot,
        deposit: open_params.deposit,
        grace_period: open_params.grace_period,
        recipients: open_params.recipients,
        token_program: open_params.token_program,
        program_id: open_params.program_id,
        channel_version: details.channel_version,
        channel_hooks: details.channel_hooks.clone(),
    })
}

pub struct BuildOpenPaymentChannelTransactionParams<'a> {
    pub request: &'a SessionRequest,
    pub signer: &'a dyn TransactionSigner,
    pub authorized_signer: Pubkey,
    pub fee_payer: Option<Pubkey>,
    /// Blockhash for the open transaction, checked against the client's own
    /// cluster (see [`OpenBlockhash`]).
    pub blockhash: OpenBlockhash,
    pub authorization: &'a SessionOpenAuthorization,
    pub options: PaymentChannelOpenOptions,
}

/// The blockhash a client signs into a channel `open`.
///
/// A Solana transaction is bound to a cluster only by its blockhash, and the
/// server requires the open to use the challenge's `recentBlockhash`. That
/// value is untrusted: a hash from another cluster would make the signed
/// open valid there rather than on the network the deposit was approved for.
/// The only way to get one from a challenge is [`Self::verify`], which asks
/// the client's own RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenBlockhash(Hash);

impl OpenBlockhash {
    /// The challenge's `recentBlockhash`, once `rpc` (which serves the
    /// cluster the client means to pay on) confirms it is live there.
    pub async fn verify(
        rpc: &solana_rpc_client::rpc_client::RpcClient,
        request: &SessionRequest,
    ) -> Result<Self> {
        let challenged = request
            .method_details
            .recent_blockhash
            .as_deref()
            .ok_or_else(|| {
                Error::Other(
                    "session challenge is missing recentBlockhash; a new-channel challenge must \
                     provide it"
                        .to_string(),
                )
            })?;
        // Only the nonblocking client is reachable here: a blocking call
        // panics on a current-thread runtime.
        crate::core::blockhash::resolve_challenge_blockhash(
            rpc.get_inner_client(),
            Some(challenged),
        )
        .await
        .map(Self)
        .map_err(|e| match e {
            crate::core::blockhash::ChallengeBlockhashError::Invalid(message) => {
                Error::Other(format!("invalid challenged recentBlockhash: {message}"))
            }
            crate::core::blockhash::ChallengeBlockhashError::Rpc(message) => Error::Other(format!(
                "could not check the challenged recentBlockhash: {message}"
            )),
        })
    }

    /// A blockhash the caller fetched from its own cluster. Never pass a
    /// value read from the challenge here; use [`Self::verify`].
    pub fn from_client_cluster(hash: Hash) -> Self {
        Self(hash)
    }

    pub fn hash(&self) -> Hash {
        self.0
    }
}

pub async fn build_open_payment_channel_transaction(
    params: BuildOpenPaymentChannelTransactionParams<'_>,
) -> Result<PaymentChannelOpenTransaction> {
    let payer = params.signer.pubkey();
    let tx_options = OpenTxOptions {
        version: crate::core::tx::negotiate(
            params
                .request
                .method_details
                .transaction_versions
                .as_deref(),
            params.options.max_tx_version,
        )?,
        compute_budget: params.options.compute_budget,
        ..Default::default()
    };
    let advertised_fee_payer = if params.request.method_details.fee_payer == Some(true) {
        Some(parse_pubkey(
            params
                .request
                .method_details
                .fee_payer_key
                .as_deref()
                .ok_or_else(|| {
                    Error::Other("feePayerKey is required when feePayer is true".to_string())
                })?,
            "feePayerKey",
        )?)
    } else {
        None
    };
    let fee_payer = params.fee_payer.or(advertised_fee_payer).unwrap_or(payer);
    if advertised_fee_payer.is_some_and(|expected| fee_payer != expected)
        || advertised_fee_payer.is_none() && fee_payer != payer
    {
        return Err(Error::Other(
            "fee payer does not match the challenge policy".to_string(),
        ));
    }
    let recent_blockhash = params.blockhash.hash();
    let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
        request: params.request,
        payer: params.signer.pubkey(),
        authorized_signer: params.authorized_signer,
        authorization: params.authorization,
        options: params.options,
    })?;

    if params.request.method_details.channel_version == Some(2) {
        return Ok(
            crate::core::payment_channels_v2::build_open_payment_channel_tx_with_options(
                params.signer,
                &open.payee,
                &open.mint,
                &open.authorized_signer,
                open.salt,
                open.open_slot,
                open.deposit,
                open.grace_period,
                open.recipients.clone(),
                &open.token_program,
                &open.program_id,
                &fee_payer,
                recent_blockhash,
                &tx_options,
                &params
                    .request
                    .method_details
                    .channel_hooks
                    .clone()
                    .unwrap_or_default(),
            )
            .await?,
        );
    }

    build_open_payment_channel_tx_with_options(
        params.signer,
        &open.payee,
        &open.mint,
        &open.authorized_signer,
        open.salt,
        open.open_slot,
        open.deposit,
        open.grace_period,
        open.recipients.clone(),
        &open.token_program,
        &open.program_id,
        &fee_payer,
        recent_blockhash,
        &tx_options,
    )
    .await
    .map_err(Into::into)
}

pub async fn create_payment_channel_session_opener(
    request: &SessionRequest,
    payer_signer: &dyn TransactionSigner,
    session_signer: Box<dyn SolanaSigner>,
    blockhash: OpenBlockhash,
    authorization: &SessionOpenAuthorization,
    options: PaymentChannelSessionOpenOptions,
) -> Result<PaymentChannelSessionOpen> {
    let authorized_signer = match request.method_details.voucher_signer {
        Some(SessionVoucherSigner::Operator) => parse_pubkey(
            request.method_details.operator.as_deref().ok_or_else(|| {
                Error::Other("operator is required for operator vouchers".to_string())
            })?,
            "operator",
        )?,
        _ => session_signer.pubkey(),
    };
    let fee_payer = if request.method_details.fee_payer == Some(true) {
        parse_pubkey(
            request
                .method_details
                .fee_payer_key
                .as_deref()
                .ok_or_else(|| {
                    Error::Other("feePayerKey is required when feePayer is true".to_string())
                })?,
            "feePayerKey",
        )?
    } else {
        payer_signer.pubkey()
    };
    let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
        request,
        payer: payer_signer.pubkey(),
        authorized_signer,
        authorization,
        options: options.open.clone(),
    })?;
    // Carry the already chosen salt into the shared builder; deriving twice
    // with a random salt would sign a different channel incarnation.
    let mut build_options = options.open.clone();
    build_options.salt = Some(open.salt);
    let tx = build_open_payment_channel_transaction(BuildOpenPaymentChannelTransactionParams {
        request,
        signer: payer_signer,
        authorized_signer,
        fee_payer: Some(fee_payer),
        blockhash,
        authorization,
        options: build_options,
    })
    .await?;
    let mut session = ActiveSession::new(open.channel_id, session_signer);
    configure_session(&mut session, options.cumulative, options.expires_at);
    let mut payload = open.open_payload(tx.transaction);
    payload.authentication = options.authentication;
    payload.idle_timeout_seconds = options.idle_timeout_seconds;
    let action = SessionAction::Open(payload);

    Ok(PaymentChannelSessionOpen {
        open,
        session,
        action,
    })
}

/// The method-details rules a client checks before it signs an open
/// (draft-solana-session-00 §Method Details): `network` is one of the three
/// clusters, `decimals` is present (session currencies are always mints) and
/// within 0 through 9, `tokenProgram` (when present) is SPL Token or
/// Token-2022, and `gracePeriodSeconds` is greater than zero.
fn validate_challenge(request: &SessionRequest) -> Result<()> {
    let details = &request.method_details;
    crate::mpp::protocol::solana::validate_network(&details.network)?;
    match details.decimals {
        None => {
            return Err(Error::Other(
                "session challenge is missing decimals for its mint".to_string(),
            ))
        }
        Some(decimals) if decimals > 9 => {
            return Err(Error::Other(format!(
                "session challenge decimals {decimals} is outside 0 through 9"
            )))
        }
        Some(_) => {}
    }
    if let Some(program) = details.token_program.as_deref() {
        use crate::mpp::protocol::solana::programs::{TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
        if program != TOKEN_PROGRAM && program != TOKEN_2022_PROGRAM {
            return Err(Error::Other(format!(
                "session challenge tokenProgram {program} is neither SPL Token nor Token-2022"
            )));
        }
    }
    if details.grace_period_seconds == Some(0) {
        return Err(Error::Other(
            "session challenge gracePeriodSeconds must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn configure_session(
    session: &mut ActiveSession,
    cumulative: Option<u64>,
    expires_at: Option<i64>,
) {
    session.cumulative = cumulative.unwrap_or(0);
    session.set_expires_at(expires_at.unwrap_or(DEFAULT_SESSION_EXPIRES_AT));
}

fn parse_splits(request: &SessionRequest) -> Result<Vec<Distribution>> {
    request
        .method_details
        .distribution_splits
        .iter()
        .map(|split| {
            Ok(Distribution {
                recipient: parse_pubkey(&split.recipient, "split recipient")?,
                bps: split.share_bps,
            })
        })
        .collect()
}

fn parse_u64_string(value: &str, label: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|e| Error::Other(format!("invalid {label}: {e}")))
}

fn parse_pubkey(value: &str, label: &str) -> Result<Pubkey> {
    Pubkey::from_str(value).map_err(|e| Error::Other(format!("invalid {label}: {e}")))
}

fn pubkey_string(pubkey: &Pubkey) -> String {
    bs58::encode(pubkey.as_ref()).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpp::program::payment_channels::PAYMENT_CHANNELS_PROGRAM_ID;
    use crate::mpp::protocol::intents::session::{SessionMethodDetails, SessionSplit};
    use crate::mpp::protocol::solana::{mints, programs};
    use solana_keychain::MemorySigner;

    #[test]
    fn deployment_identity_is_explicit_and_v1_wire_is_unchanged() {
        let mut request = request(Pubkey::new_unique());
        let json = serde_json::to_value(&request).unwrap();
        assert!(json["methodDetails"].get("channelVersion").is_none());
        assert!(json["methodDetails"].get("channelHooks").is_none());
        let derive = |request: &SessionRequest, override_program| {
            derive_payment_channel_open(DerivePaymentChannelOpenParams {
                request,
                payer: Pubkey::new_unique(),
                authorized_signer: Pubkey::new_unique(),
                authorization: &auth(),
                options: PaymentChannelOpenOptions {
                    program_id: override_program,
                    ..Default::default()
                },
            })
        };
        assert!(derive(&request, None).is_ok());
        assert!(derive(&request, Some(Pubkey::new_unique())).is_err());
        request.method_details.channel_version = Some(99);
        assert!(derive(&request, None).is_err());
        request.method_details.channel_program =
            "CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ".into();
        request.method_details.channel_version = None;
        assert!(derive(&request, None).is_err());
        request.method_details.channel_version = Some(2);
        for network in ["mainnet", "", "testnet", "mainnet-beta"] {
            request.method_details.network = network.into();
            assert!(derive(&request, None).is_err());
        }
        for network in ["devnet", "localnet"] {
            request.method_details.network = network.into();
            assert!(derive(&request, None).is_ok());
        }
        request.method_details.network = "devnet".into();
        let open = derive(&request, None).unwrap();
        assert_eq!(open.channel_version, Some(2));
        assert_eq!(
            open.program_id.to_string(),
            request.method_details.channel_program
        );
    }

    fn signer(seed: u8) -> Box<dyn TransactionSigner> {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(key.as_bytes());
        bytes[32..].copy_from_slice(key.verifying_key().as_bytes());
        Box::new(MemorySigner::from_bytes(&bytes).unwrap())
    }

    /// The `recentBlockhash` every test challenge advertises.
    fn test_blockhash() -> Hash {
        Hash::new_from_array([7; 32])
    }

    fn auth() -> SessionOpenAuthorization {
        SessionOpenAuthorization::client_signed(1000)
    }

    fn request(recipient: Pubkey) -> SessionRequest {
        SessionRequest {
            amount: "25".into(),
            currency: "USDC".into(),
            recipient: pubkey_string(&recipient),
            description: None,
            external_id: None,
            minimum_deposit: Some("100".into()),
            suggested_deposit: Some("1000".into()),
            unit_type: Some("request".into()),
            method_details: SessionMethodDetails {
                network: "mainnet".into(),
                channel_program: PAYMENT_CHANNELS_PROGRAM_ID.to_string(),
                channel_version: None,
                channel_hooks: None,
                channel_id: None,
                recent_blockhash: Some(test_blockhash().to_string()),
                recent_slot: Some(42),
                decimals: Some(6),
                token_program: Some(programs::TOKEN_PROGRAM.to_string()),
                fee_payer: None,
                fee_payer_key: None,
                voucher_signer: Some(SessionVoucherSigner::Client),
                operator: None,
                min_voucher_delta: None,
                ttl_seconds: None,
                idle_timeout_options_seconds: Some(vec![60, 300]),
                idle_timeout_seconds: Some(300),
                grace_period_seconds: Some(900),
                distribution_splits: vec![],
                transaction_versions: None,
            },
        }
    }

    /// draft-solana-session-00 §Method Details: a client refuses a challenge
    /// whose network is not one of the three clusters, whose mint has no
    /// decimals (or out-of-range ones), whose tokenProgram is neither SPL
    /// Token nor Token-2022, or whose grace period is zero, before it
    /// derives or signs an open.
    #[test]
    fn open_refuses_out_of_spec_method_details() {
        let derive = |request: &SessionRequest| {
            derive_payment_channel_open(DerivePaymentChannelOpenParams {
                request,
                payer: Pubkey::new_unique(),
                authorized_signer: Pubkey::new_unique(),
                authorization: &auth(),
                options: PaymentChannelOpenOptions {
                    salt: Some(7),
                    ..Default::default()
                },
            })
        };
        assert!(derive(&request(Pubkey::new_unique())).is_ok());
        type Edit = fn(&mut SessionMethodDetails);
        let cases: [(&str, Edit); 5] = [
            ("network", |d| d.network = "testnet".into()),
            ("decimals", |d| d.decimals = None),
            ("decimals", |d| d.decimals = Some(10)),
            ("tokenProgram", |d| {
                d.token_program = Some(crate::mpp::program::payment_channels::SYSTEM_PROGRAM.into())
            }),
            ("gracePeriodSeconds", |d| d.grace_period_seconds = Some(0)),
        ];
        for (field, edit) in cases {
            let mut bad = request(Pubkey::new_unique());
            edit(&mut bad.method_details);
            let error = derive(&bad).unwrap_err().to_string();
            assert!(error.contains(field), "{field}: {error}");
        }
    }

    #[tokio::test]
    async fn active_session_signs_records_and_builds_exact_actions() {
        let channel = Pubkey::new_unique();
        let mut active = ActiveSession::new_with_expiry(channel, signer(1), 1234);
        assert_eq!(active.channel_id_str(), channel.to_string());
        assert_eq!(active.authorized_signer(), signer(1).pubkey().to_string());
        let prepared = active.prepare_increment(25).await.unwrap();
        assert_eq!(prepared.data.cumulative_amount, "25");
        assert_eq!(prepared.data.expires_at, Some(1234));
        assert_eq!(active.cumulative, 0);
        active.record_voucher(&prepared).unwrap();
        assert_eq!(active.cumulative, 25);
        assert!(active.record_voucher(&prepared).is_err());
        assert!(active.prepare_voucher(25).await.is_err());
        assert!(active
            .record_voucher(&SignedVoucher {
                data: VoucherData {
                    cumulative_amount: "bad".into(),
                    ..prepared.data.clone()
                },
                ..prepared.clone()
            })
            .is_err());

        match active.voucher_action(5).await.unwrap() {
            SessionAction::Voucher(payload) => {
                assert_eq!(payload.voucher.data.cumulative_amount, "30")
            }
            _ => panic!("voucher action"),
        }
        match active.close_action(Some(5)).await.unwrap() {
            SessionAction::Close(payload) => {
                assert_eq!(payload.voucher.unwrap().data.cumulative_amount, "35")
            }
            _ => panic!("close action"),
        }
        assert!(matches!(
            active.close_action(None).await.unwrap(),
            SessionAction::Close(_)
        ));
        assert!(matches!(
            active.topup_action(10, "topup"),
            SessionAction::TopUp(_)
        ));
        assert!(matches!(
            active.open_payment_channel_action(100, "payer", "payee", "mint", 7, 900, 42, "wire"),
            SessionAction::Open(_)
        ));
        active.set_expires_at(999);
        assert_eq!(
            active.sign_increment(1).await.unwrap().data.expires_at,
            Some(999)
        );
    }

    #[test]
    fn open_refuses_a_payout_other_than_the_approved_one() {
        let payee = Pubkey::new_unique();
        let split = Pubkey::new_unique();
        let mut req = request(payee);
        req.method_details.distribution_splits.push(SessionSplit {
            recipient: split.to_string(),
            share_bps: 250,
        });
        let payout = SessionPayout::from_request(&req).unwrap();
        assert_eq!(payout.payee, payee);
        assert_eq!(
            payout.splits,
            vec![Distribution {
                recipient: split,
                bps: 250
            }]
        );

        let derive = |request: &SessionRequest, approved: SessionPayout| {
            derive_payment_channel_open(DerivePaymentChannelOpenParams {
                request,
                payer: Pubkey::new_unique(),
                authorized_signer: Pubkey::new_unique(),
                authorization: &auth(),
                options: PaymentChannelOpenOptions {
                    open_slot: Some(42),
                    approved_payout: Some(approved),
                    ..Default::default()
                },
            })
        };
        assert!(derive(&req, payout.clone()).is_ok());

        // Same challenge, payee swapped for an attacker's.
        let mut redirected = req.clone();
        redirected.recipient = Pubkey::new_unique().to_string();
        let err = derive(&redirected, payout.clone()).unwrap_err();
        assert!(err.to_string().contains("approved payee"), "{err}");

        // Same payee, an extra split nobody approved.
        let mut extra_split = req.clone();
        extra_split
            .method_details
            .distribution_splits
            .push(SessionSplit {
                recipient: Pubkey::new_unique().to_string(),
                share_bps: 100,
            });
        assert!(derive(&extra_split, payout).is_err());
    }

    #[test]
    fn derive_open_uses_exact_nested_policy_and_validates_inputs() {
        let payer = Pubkey::new_unique();
        let payee = Pubkey::new_unique();
        let authorized = Pubkey::new_unique();
        let split = Pubkey::new_unique();
        let mut req = request(payee);
        req.method_details.distribution_splits.push(SessionSplit {
            recipient: split.to_string(),
            share_bps: 250,
        });
        let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &req,
            payer,
            authorized_signer: authorized,
            authorization: &auth(),
            options: PaymentChannelOpenOptions {
                open_slot: Some(42),
                salt: Some(7),
                ..Default::default()
            },
        })
        .unwrap();
        assert_eq!(open.deposit, 1000);
        assert_eq!(open.open_slot, 42);
        assert_eq!(open.recipients[0].bps, 250);
        assert_eq!(open.channel_address(), open.channel_id);
        let payload = open.open_payload("wire");
        assert_eq!(payload.deposit_amount, "1000");
        assert_eq!(payload.distribution_splits[0].share_bps, 250);

        // The deposit is the caller's, whatever the challenge suggests, and
        // still at least minimumDeposit.
        let mut suggested = req.clone();
        suggested.suggested_deposit = Some("bad".into());
        let derive_with = |request: &SessionRequest, authorization: &SessionOpenAuthorization| {
            derive_payment_channel_open(DerivePaymentChannelOpenParams {
                request,
                payer,
                authorized_signer: authorized,
                authorization,
                options: PaymentChannelOpenOptions {
                    open_slot: Some(1),
                    ..Default::default()
                },
            })
        };
        assert_eq!(derive_with(&suggested, &auth()).unwrap().deposit, 1000);
        let mut no_suggestion = req.clone();
        no_suggestion.suggested_deposit = None;
        no_suggestion.minimum_deposit = None;
        assert_eq!(
            derive_with(&no_suggestion, &SessionOpenAuthorization::client_signed(7))
                .unwrap()
                .deposit,
            7
        );
        assert!(
            derive_with(&req, &SessionOpenAuthorization::client_signed(99))
                .unwrap_err()
                .to_string()
                .contains("below minimumDeposit")
        );
        // Default options take `openSlot` from the challenged `recentSlot`.
        let defaulted = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &req,
            payer,
            authorized_signer: authorized,
            authorization: &auth(),
            options: Default::default(),
        })
        .unwrap();
        assert_eq!(defaulted.open_slot, 42);
        // An override may be earlier than the challenged `recentSlot`, never later.
        assert!(derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &req,
            payer,
            authorized_signer: authorized,
            authorization: &auth(),
            options: PaymentChannelOpenOptions {
                open_slot: Some(43),
                ..Default::default()
            }
        })
        .unwrap_err()
        .to_string()
        .contains("ahead of the challenged recentSlot"));
        // A new-channel challenge without `recentSlot` cannot derive an open.
        let mut no_slot = req.clone();
        no_slot.method_details.recent_slot = None;
        assert!(derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &no_slot,
            payer,
            authorized_signer: authorized,
            authorization: &auth(),
            options: Default::default()
        })
        .unwrap_err()
        .to_string()
        .contains("missing recentSlot"));
        let mut bad_program = req.clone();
        bad_program.method_details.channel_program = "bad".into();
        assert!(derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &bad_program,
            payer,
            authorized_signer: authorized,
            authorization: &auth(),
            options: PaymentChannelOpenOptions {
                open_slot: Some(1),
                ..Default::default()
            }
        })
        .is_err());
    }

    #[tokio::test]
    async fn open_compute_budget_supports_both_channel_and_message_versions() {
        use crate::core::tx::{ComputeBudget, TxVersion};
        use solana_message::VersionedMessage;

        let payer = signer(2);
        for channel_version in [1, 2] {
            for version in [TxVersion::V0, TxVersion::V1] {
                for budget in [None, Some(ComputeBudget::new(600_000, 1_000))] {
                    let mut req = request(Pubkey::new_unique());
                    req.method_details.transaction_versions = Some(vec![version]);
                    if channel_version == 2 {
                        req.method_details.network = "devnet".into();
                        req.method_details.channel_version = Some(2);
                        req.method_details.channel_program =
                            "CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ".into();
                    }
                    let tx = build_open_payment_channel_transaction(
                        BuildOpenPaymentChannelTransactionParams {
                            request: &req,
                            signer: payer.as_ref(),
                            authorized_signer: payer.pubkey(),
                            fee_payer: None,
                            blockhash: OpenBlockhash::from_client_cluster(test_blockhash()),
                            authorization: &auth(),
                            options: PaymentChannelOpenOptions {
                                compute_budget: budget,
                                ..Default::default()
                            },
                        },
                    )
                    .await
                    .unwrap();
                    let decoded = crate::core::tx::decode(&tx.transaction).unwrap();
                    match decoded.message {
                        VersionedMessage::V0(message) => {
                            assert_eq!(
                                message.instructions.len(),
                                if budget.is_some() { 3 } else { 1 }
                            );
                            if let Some(budget) = budget {
                                for (compiled, expected) in
                                    message.instructions.iter().zip(budget.instructions())
                                {
                                    assert_eq!(compiled.data, expected.data);
                                    assert_eq!(
                                        message.account_keys[compiled.program_id_index as usize],
                                        expected.program_id
                                    );
                                }
                            }
                        }
                        VersionedMessage::V1(message) => {
                            assert_eq!(message.instructions.len(), 1);
                            let expected =
                                budget.unwrap_or_else(|| ComputeBudget::runtime_default(1));
                            assert_eq!(
                                message.config.compute_unit_limit,
                                Some(expected.unit_limit)
                            );
                            assert_eq!(
                                message.config.priority_fee,
                                Some(expected.priority_fee_lamports())
                            );
                            assert_eq!(
                                message.config.loaded_accounts_data_size_limit,
                                Some(expected.loaded_accounts_data_size_limit)
                            );
                        }
                        _ => panic!("unexpected message version"),
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn transaction_and_opener_bind_fee_payer_and_operator_authentication() {
        let payer = signer(2);
        let session_signer = signer(3);
        let payee = Pubkey::new_unique();
        let mut req = request(payee);
        let tx = build_open_payment_channel_transaction(BuildOpenPaymentChannelTransactionParams {
            request: &req,
            signer: payer.as_ref(),
            authorized_signer: session_signer.pubkey(),
            fee_payer: None,
            blockhash: OpenBlockhash::from_client_cluster(test_blockhash()),
            authorization: &auth(),
            options: PaymentChannelOpenOptions {
                open_slot: Some(42),
                salt: Some(7),
                ..Default::default()
            },
        })
        .await
        .unwrap();
        assert!(!tx.transaction.is_empty());
        let decoded =
            crate::mpp::program::payment_channels::decode_transaction(&tx.transaction).unwrap();
        assert_eq!(*decoded.message.recent_blockhash(), test_blockhash());

        // A new-channel challenge without `recentBlockhash` gives the client
        // no blockhash it may verify.
        let mut no_blockhash = req.clone();
        no_blockhash.method_details.recent_blockhash = None;
        let rpc = crate::core::blockhash::mock_blockhash_rpc(true);
        assert!(OpenBlockhash::verify(&rpc, &no_blockhash)
            .await
            .unwrap_err()
            .to_string()
            .contains("missing recentBlockhash"));

        req.method_details.fee_payer = Some(true);
        req.method_details.fee_payer_key = Some(Pubkey::new_unique().to_string());
        assert!(
            build_open_payment_channel_transaction(BuildOpenPaymentChannelTransactionParams {
                request: &req,
                signer: payer.as_ref(),
                authorized_signer: session_signer.pubkey(),
                fee_payer: Some(payer.pubkey()),
                blockhash: OpenBlockhash::from_client_cluster(test_blockhash()),
                authorization: &auth(),
                options: PaymentChannelOpenOptions {
                    open_slot: Some(42),
                    ..Default::default()
                },
            })
            .await
            .is_err()
        );

        let operator = signer(4);
        req.method_details.fee_payer_key = Some(operator.pubkey().to_string());
        req.method_details.operator = Some(operator.pubkey().to_string());
        req.method_details.voucher_signer = Some(SessionVoucherSigner::Operator);
        let authentication = SessionAuthentication::sign(
            "opening",
            &Pubkey::new_unique().to_string(),
            &ed25519_dalek::SigningKey::from_bytes(&[2; 32]),
        )
        .unwrap();
        let opened = create_payment_channel_session_opener(
            &req,
            payer.as_ref(),
            session_signer,
            OpenBlockhash::verify(&crate::core::blockhash::mock_blockhash_rpc(true), &req)
                .await
                .unwrap(),
            &SessionOpenAuthorization::operator_signed(1000, operator.pubkey()),
            PaymentChannelSessionOpenOptions {
                open: PaymentChannelOpenOptions {
                    // Earlier than the challenged recentSlot (42): allowed.
                    open_slot: Some(41),
                    ..Default::default()
                },
                cumulative: Some(5),
                expires_at: Some(1234),
                authentication: Some(authentication),
                idle_timeout_seconds: Some(60),
            },
        )
        .await
        .unwrap();
        assert_eq!(opened.session.cumulative, 5);
        match opened.action {
            SessionAction::Open(payload) => {
                assert_eq!(payload.authorized_signer, operator.pubkey().to_string());
                assert_eq!(payload.idle_timeout_seconds, Some(60));
                assert!(payload.authentication.is_some());
            }
            _ => panic!("open action"),
        }
    }

    /// An operator-signed channel lets the operator settle up to the whole
    /// deposit with its own vouchers, so the challenge alone never makes the
    /// client open one: the caller names the operator it trusts.
    #[tokio::test]
    async fn operator_vouchers_need_the_caller_to_name_the_operator() {
        let operator = Pubkey::new_unique();
        let mut req = request(Pubkey::new_unique());
        req.method_details.voucher_signer = Some(SessionVoucherSigner::Operator);
        req.method_details.operator = Some(operator.to_string());
        let open = |authorization: SessionOpenAuthorization| {
            let req = req.clone();
            async move {
                create_payment_channel_session_opener(
                    &req,
                    signer(2).as_ref(),
                    signer(3),
                    OpenBlockhash::from_client_cluster(test_blockhash()),
                    &authorization,
                    PaymentChannelSessionOpenOptions::default(),
                )
                .await
            }
        };

        let error = open(auth()).await.err().expect("client-signed only");
        assert!(error.to_string().contains("did not authorize"), "{error}");
        let other = SessionOpenAuthorization::operator_signed(1000, Pubkey::new_unique());
        let error = open(other).await.err().expect("another operator");
        assert!(error.to_string().contains("did not authorize"), "{error}");

        let opened = open(SessionOpenAuthorization::operator_signed(1000, operator))
            .await
            .unwrap();
        assert_eq!(opened.open.authorized_signer, operator);
        assert_eq!(opened.open.deposit, 1000);

        // derive_payment_channel_open holds the same line for callers that
        // pick the authorized signer themselves.
        let derive = |authorized_signer, authorization: &SessionOpenAuthorization| {
            derive_payment_channel_open(DerivePaymentChannelOpenParams {
                request: &req,
                payer: Pubkey::new_unique(),
                authorized_signer,
                authorization,
                options: Default::default(),
            })
        };
        assert!(derive(operator, &auth()).is_err());
        let trusted = SessionOpenAuthorization::operator_signed(1000, operator);
        assert!(derive(Pubkey::new_unique(), &trusted).is_err());
        assert!(derive(operator, &trusted).is_ok());
    }

    /// The deposit is the caller's: a challenge's suggestedDeposit never
    /// sizes the escrow.
    #[tokio::test]
    async fn the_deposit_is_the_callers_not_the_challenges() {
        let mut req = request(Pubkey::new_unique());
        req.suggested_deposit = Some(u64::MAX.to_string());
        let opened = create_payment_channel_session_opener(
            &req,
            signer(2).as_ref(),
            signer(3),
            OpenBlockhash::from_client_cluster(test_blockhash()),
            &SessionOpenAuthorization::client_signed(250),
            PaymentChannelSessionOpenOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(opened.open.deposit, 250);
        let SessionAction::Open(payload) = opened.action else {
            panic!("open action");
        };
        assert_eq!(payload.deposit_amount, "250");
    }

    /// The grace period is the payer's wait to withdraw what was not settled,
    /// so a challenge cannot stretch it past the caller's ceiling.
    #[test]
    fn the_grace_period_is_bounded() {
        let derive = |grace: u32, option: Option<u32>, authorization: &SessionOpenAuthorization| {
            let mut req = request(Pubkey::new_unique());
            req.method_details.grace_period_seconds = Some(grace);
            derive_payment_channel_open(DerivePaymentChannelOpenParams {
                request: &req,
                payer: Pubkey::new_unique(),
                authorized_signer: Pubkey::new_unique(),
                authorization,
                options: PaymentChannelOpenOptions {
                    grace_period: option,
                    ..Default::default()
                },
            })
        };
        let error = derive(u32::MAX, None, &auth()).unwrap_err();
        assert!(
            error.to_string().contains("exceeds the authorized maximum"),
            "{error}"
        );
        assert!(derive(MAX_SESSION_GRACE_PERIOD_SECONDS + 1, None, &auth()).is_err());
        assert_eq!(
            derive(MAX_SESSION_GRACE_PERIOD_SECONDS, None, &auth())
                .unwrap()
                .grace_period,
            MAX_SESSION_GRACE_PERIOD_SECONDS
        );

        let tight = auth().with_max_grace_period(3_600).unwrap();
        assert!(derive(3_601, None, &tight).is_err());
        assert!(derive(u32::MAX, Some(3_601), &tight).is_err());
        assert_eq!(
            derive(u32::MAX, Some(900), &tight).unwrap().grace_period,
            900
        );
        let wide = auth().with_max_grace_period(u32::MAX).unwrap();
        assert_eq!(
            derive(u32::MAX, None, &wide).unwrap().grace_period,
            u32::MAX
        );
        assert!(auth().with_max_grace_period(0).is_err());
    }

    #[tokio::test]
    async fn a_challenged_blockhash_the_client_cluster_does_not_know_is_refused() {
        let req = request(Pubkey::new_unique());
        let foreign = crate::core::blockhash::mock_blockhash_rpc(false);
        let error = OpenBlockhash::verify(&foreign, &req).await.unwrap_err();
        assert!(
            error.to_string().contains("not a live blockhash"),
            "{error}"
        );

        let rpc = crate::core::blockhash::mock_blockhash_rpc(true);
        let blockhash = OpenBlockhash::verify(&rpc, &req).await.unwrap();
        assert_eq!(blockhash.hash(), test_blockhash());
        let opened = create_payment_channel_session_opener(
            &req,
            signer(2).as_ref(),
            signer(3),
            blockhash,
            &auth(),
            PaymentChannelSessionOpenOptions::default(),
        )
        .await
        .unwrap();
        let SessionAction::Open(payload) = opened.action else {
            panic!("open action");
        };
        let decoded =
            crate::mpp::program::payment_channels::decode_transaction(&payload.transaction)
                .unwrap();
        assert_eq!(*decoded.message.recent_blockhash(), test_blockhash());
    }

    #[tokio::test]
    async fn an_unreachable_client_rpc_refuses_the_challenged_blockhash() {
        let req = request(Pubkey::new_unique());
        let rpc = solana_rpc_client::rpc_client::RpcClient::new("http://127.0.0.1:1".to_string());
        let error = OpenBlockhash::verify(&rpc, &req).await.unwrap_err();
        assert!(error.to_string().contains("could not check"), "{error}");
    }

    #[test]
    fn stablecoin_and_token_program_resolution_is_exact() {
        let req = request(Pubkey::new_unique());
        let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &req,
            payer: Pubkey::new_unique(),
            authorized_signer: Pubkey::new_unique(),
            authorization: &auth(),
            options: PaymentChannelOpenOptions {
                open_slot: Some(1),
                ..Default::default()
            },
        })
        .unwrap();
        assert_eq!(open.mint.to_string(), mints::USDC_MAINNET);
        assert_eq!(open.token_program.to_string(), programs::TOKEN_PROGRAM);
    }
}
