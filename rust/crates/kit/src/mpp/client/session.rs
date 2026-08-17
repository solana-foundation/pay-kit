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
use solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;

use crate::mpp::error::{Error, Result};
use crate::mpp::program::payment_channels::{
    build_open_payment_channel_tx, derive_channel_addresses, random_salt, Distribution,
    OpenChannelParams, PaymentChannelOpenTransaction,
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
        self.prepare_voucher(self.cumulative + amount).await
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
        self.sign_voucher(self.cumulative + amount).await
    }

    /// Build a `SessionAction::Voucher` wrapping a freshly-signed increment.
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
}

impl PaymentChannelOpen {
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
    pub deposit: Option<u64>,
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
}

#[derive(Debug, Clone)]
pub struct DerivePaymentChannelOpenParams<'a> {
    pub request: &'a SessionRequest,
    pub payer: Pubkey,
    pub authorized_signer: Pubkey,
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
    let network = Some(details.network.as_str());
    let mint = parse_pubkey(
        crate::mpp::protocol::solana::try_resolve_stablecoin_mint(&request.currency, network)?
            .ok_or_else(|| Error::Other("session payment channels require an SPL token".into()))?,
        "mint",
    )?;
    let payee = parse_pubkey(&request.recipient, "recipient")?;
    let deposit = match params.options.deposit {
        Some(deposit) => deposit,
        None => parse_u64_string(
            request
                .suggested_deposit
                .as_deref()
                .or(request.minimum_deposit.as_deref())
                .ok_or_else(|| {
                    Error::Other("session challenge missing suggestedDeposit".to_string())
                })?,
            "suggestedDeposit",
        )?,
    };
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
    let program_id = match params.options.program_id {
        Some(program_id) => program_id,
        None => parse_pubkey(&details.channel_program, "channelProgram")?,
    };
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
    })
}

pub struct BuildOpenPaymentChannelTransactionParams<'a> {
    pub request: &'a SessionRequest,
    pub signer: &'a dyn SolanaSigner,
    pub authorized_signer: Pubkey,
    pub fee_payer: Option<Pubkey>,
    /// Blockhash for the open transaction. `None` (the default) takes the
    /// challenge's `recentBlockhash`, which the server requires the compiled
    /// message to use; an explicit override is for tests and custom flows
    /// that re-issue their own challenge binding.
    pub recent_blockhash: Option<Hash>,
    pub options: PaymentChannelOpenOptions,
}

/// Resolve the open transaction's blockhash: an explicit override wins,
/// otherwise the challenged `recentBlockhash` is required — the client never
/// fetches its own.
fn resolve_open_blockhash(override_hash: Option<Hash>, request: &SessionRequest) -> Result<Hash> {
    if let Some(hash) = override_hash {
        return Ok(hash);
    }
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
    Hash::from_str(challenged)
        .map_err(|e| Error::Other(format!("invalid challenged recentBlockhash: {e}")))
}

pub async fn build_open_payment_channel_transaction(
    params: BuildOpenPaymentChannelTransactionParams<'_>,
) -> Result<PaymentChannelOpenTransaction> {
    let payer = params.signer.pubkey();
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
    let recent_blockhash = resolve_open_blockhash(params.recent_blockhash, params.request)?;
    let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
        request: params.request,
        payer: params.signer.pubkey(),
        authorized_signer: params.authorized_signer,
        options: params.options,
    })?;

    build_open_payment_channel_tx(
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
    )
    .await
    .map_err(Into::into)
}

pub async fn create_payment_channel_session_opener(
    request: &SessionRequest,
    payer_signer: &dyn SolanaSigner,
    session_signer: Box<dyn SolanaSigner>,
    recent_blockhash: Option<Hash>,
    options: PaymentChannelSessionOpenOptions,
) -> Result<PaymentChannelSessionOpen> {
    let recent_blockhash = resolve_open_blockhash(recent_blockhash, request)?;
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
        options: options.open.clone(),
    })?;
    let tx = build_open_payment_channel_tx(
        payer_signer,
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
    )
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

    fn signer(seed: u8) -> Box<dyn SolanaSigner> {
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
            },
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

        let mut invalid = req.clone();
        invalid.suggested_deposit = Some("bad".into());
        assert!(derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &invalid,
            payer,
            authorized_signer: authorized,
            options: PaymentChannelOpenOptions {
                open_slot: Some(1),
                ..Default::default()
            }
        })
        .is_err());
        let mut below = req.clone();
        below.suggested_deposit = Some("1".into());
        assert!(derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &below,
            payer,
            authorized_signer: authorized,
            options: PaymentChannelOpenOptions {
                open_slot: Some(1),
                ..Default::default()
            }
        })
        .is_err());
        // Default options take `openSlot` from the challenged `recentSlot`.
        let defaulted = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &req,
            payer,
            authorized_signer: authorized,
            options: Default::default(),
        })
        .unwrap();
        assert_eq!(defaulted.open_slot, 42);
        // An override may be earlier than the challenged `recentSlot`, never later.
        assert!(derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &req,
            payer,
            authorized_signer: authorized,
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
            options: PaymentChannelOpenOptions {
                open_slot: Some(1),
                ..Default::default()
            }
        })
        .is_err());
        let mut no_deposit = req.clone();
        no_deposit.suggested_deposit = None;
        no_deposit.minimum_deposit = None;
        assert!(derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &no_deposit,
            payer,
            authorized_signer: authorized,
            options: PaymentChannelOpenOptions {
                open_slot: Some(1),
                ..Default::default()
            }
        })
        .is_err());
    }

    #[tokio::test]
    async fn transaction_and_opener_bind_fee_payer_and_operator_authentication() {
        let payer = signer(2);
        let session_signer = signer(3);
        let payee = Pubkey::new_unique();
        let mut req = request(payee);
        // No explicit blockhash: the challenged `recentBlockhash` is used.
        let tx = build_open_payment_channel_transaction(BuildOpenPaymentChannelTransactionParams {
            request: &req,
            signer: payer.as_ref(),
            authorized_signer: session_signer.pubkey(),
            fee_payer: None,
            recent_blockhash: None,
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

        // A new-channel challenge without `recentBlockhash` cannot build the
        // open transaction unless the caller overrides the blockhash.
        let mut no_blockhash = req.clone();
        no_blockhash.method_details.recent_blockhash = None;
        assert!(
            build_open_payment_channel_transaction(BuildOpenPaymentChannelTransactionParams {
                request: &no_blockhash,
                signer: payer.as_ref(),
                authorized_signer: session_signer.pubkey(),
                fee_payer: None,
                recent_blockhash: None,
                options: PaymentChannelOpenOptions {
                    open_slot: Some(42),
                    ..Default::default()
                },
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("missing recentBlockhash")
        );

        req.method_details.fee_payer = Some(true);
        req.method_details.fee_payer_key = Some(Pubkey::new_unique().to_string());
        assert!(
            build_open_payment_channel_transaction(BuildOpenPaymentChannelTransactionParams {
                request: &req,
                signer: payer.as_ref(),
                authorized_signer: session_signer.pubkey(),
                fee_payer: Some(payer.pubkey()),
                recent_blockhash: None,
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
            None,
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

    #[test]
    fn stablecoin_and_token_program_resolution_is_exact() {
        let req = request(Pubkey::new_unique());
        let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &req,
            payer: Pubkey::new_unique(),
            authorized_signer: Pubkey::new_unique(),
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
