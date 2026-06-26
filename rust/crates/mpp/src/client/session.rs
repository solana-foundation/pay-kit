//! Client-side session intent implementation.
//!
//! Tracks an open payment channel and signs cumulative vouchers for each
//! API call. Vouchers are Ed25519-signed over the on-chain Borsh voucher
//! layout used by the payment-channels program.
//!
//! # Example
//!
//! ```ignore
//! use solana_mpp::client::session::ActiveSession;
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

use crate::error::{Error, Result};
use crate::program::payment_channels::{
    build_open_payment_channel_tx, default_program_id, derive_channel_addresses, random_salt,
    Distribution, OpenChannelParams, PaymentChannelOpenTransaction,
};
use crate::protocol::intents::session::{
    ClosePayload, OpenPayload, SessionAction, SessionMode, SessionPullVoucherStrategy,
    SessionRequest, SignedVoucher, TopUpPayload, VoucherData, VoucherPayload,
    DEFAULT_SESSION_EXPIRES_AT,
};
use crate::protocol::solana::{default_token_program_for_currency, resolve_stablecoin_mint};

/// Default payment-channel close grace period (seconds). Re-exported from
/// `solana-pay-core` to preserve this crate's public path.
pub use crate::program::payment_channels::DEFAULT_GRACE_PERIOD_SECONDS;

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

    /// Nonce counter, incremented with each signed voucher.
    nonce: u64,

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
            nonce: 0,
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
            nonce: 0,
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
            cumulative: cumulative.to_string(),
            expires_at: self.expires_at,
            nonce: Some(self.nonce + 1),
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
            signature: sig_b58,
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
            .cumulative
            .parse::<u64>()
            .map_err(|_| Error::Other("invalid voucher cumulative".to_string()))?;
        if cumulative <= self.cumulative {
            return Err(Error::Other(format!(
                "Voucher cumulative {cumulative} must exceed current watermark {}",
                self.cumulative
            )));
        }
        self.cumulative = cumulative;
        self.nonce = self.nonce.max(voucher.data.nonce.unwrap_or(self.nonce + 1));
        Ok(())
    }

    /// Sign a voucher adding `amount` to the current cumulative.
    pub async fn sign_increment(&mut self, amount: u64) -> Result<SignedVoucher> {
        self.sign_voucher(self.cumulative + amount).await
    }

    /// Build a `SessionAction::Voucher` wrapping a freshly-signed increment.
    pub async fn voucher_action(&mut self, amount: u64) -> Result<SessionAction> {
        let voucher = self.sign_increment(amount).await?;
        Ok(SessionAction::Voucher(VoucherPayload { voucher }))
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
            voucher,
        }))
    }

    /// Build a `SessionAction::Open` for **push** mode.
    ///
    /// Call this after the on-chain open transaction has been confirmed.
    /// `channel_id` in the session MUST match the confirmed channel address.
    pub fn open_action(&self, deposit: u64, open_tx_signature: &str) -> SessionAction {
        SessionAction::Open(OpenPayload::push(
            self.channel_id_str(),
            deposit.to_string(),
            self.authorized_signer(),
            open_tx_signature.to_string(),
        ))
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
        open_tx_signature: &str,
    ) -> SessionAction {
        self.open_payment_channel_action_with_mode(
            SessionMode::Push,
            deposit,
            payer,
            payee,
            mint,
            salt,
            grace_period,
            open_tx_signature,
        )
    }

    /// Build a payment-channel `SessionAction::Open` with an explicit submission mode.
    #[allow(clippy::too_many_arguments)]
    pub fn open_payment_channel_action_with_mode(
        &self,
        mode: SessionMode,
        deposit: u64,
        payer: &str,
        payee: &str,
        mint: &str,
        salt: u64,
        grace_period: u32,
        open_tx_signature: &str,
    ) -> SessionAction {
        SessionAction::Open(OpenPayload::payment_channel_with_mode(
            mode,
            self.channel_id_str(),
            deposit.to_string(),
            payer.to_string(),
            payee.to_string(),
            mint.to_string(),
            salt,
            grace_period,
            self.authorized_signer(),
            open_tx_signature.to_string(),
        ))
    }

    /// Build a `SessionAction::Open` for **pull** mode (SPL token delegation).
    ///
    /// Call this after the operator has broadcast and confirmed the `approve`
    /// transaction on behalf of the client.
    ///
    /// - `token_account` is the SPL token account that was delegated (must match
    ///   `self.channel_id` — callers should create the `ActiveSession` with the
    ///   token account pubkey as the channel ID so vouchers bind to it).
    /// - `owner` is the client's wallet pubkey (base58). The operator uses this
    ///   to derive the MultiDelegate PDA at settlement time.
    pub fn open_pull_action(
        &self,
        approved_amount: u64,
        owner: &str,
        approve_tx_signature: &str,
    ) -> SessionAction {
        SessionAction::Open(OpenPayload::pull(
            self.channel_id_str(), // token_account used as the session identifier
            approved_amount.to_string(),
            owner.to_string(),
            self.authorized_signer(),
            approve_tx_signature.to_string(),
        ))
    }

    /// Build a `SessionAction::TopUp` after a top-up transaction.
    pub fn topup_action(&self, new_deposit: u64, topup_tx_signature: &str) -> SessionAction {
        SessionAction::TopUp(TopUpPayload {
            channel_id: self.channel_id_str(),
            new_deposit: new_deposit.to_string(),
            signature: topup_tx_signature.to_string(),
        })
    }
}

/// Placeholder signature used while the operator still needs to submit the
/// server-broadcast open transaction.
pub const PENDING_SERVER_SIGNATURE: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

#[derive(Debug, Clone)]
pub struct PaymentChannelOpen {
    pub channel_id: Pubkey,
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    pub salt: u64,
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
            deposit: self.deposit,
            grace_period: self.grace_period,
            recipients: self.recipients.clone(),
            token_program: self.token_program,
            program_id: self.program_id,
        })
        .channel
    }

    pub fn open_payload(&self, mode: SessionMode, signature: impl Into<String>) -> OpenPayload {
        OpenPayload::payment_channel_with_mode(
            mode,
            pubkey_string(&self.channel_id),
            self.deposit.to_string(),
            pubkey_string(&self.payer),
            pubkey_string(&self.payee),
            pubkey_string(&self.mint),
            self.salt,
            self.grace_period,
            pubkey_string(&self.authorized_signer),
            signature.into(),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct PaymentChannelOpenOptions {
    pub deposit: Option<u64>,
    pub grace_period: Option<u32>,
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
    pub signature: Option<String>,
    pub cumulative: Option<u64>,
    pub expires_at: Option<i64>,
}

#[derive(Default)]
pub struct ServerOpenedPaymentChannelSessionOpenOptions {
    pub open: PaymentChannelOpenOptions,
    pub payer: Option<Pubkey>,
    pub signature: Option<String>,
    pub cumulative: Option<u64>,
    pub expires_at: Option<i64>,
}

pub fn derive_payment_channel_open(
    params: DerivePaymentChannelOpenParams<'_>,
) -> Result<PaymentChannelOpen> {
    let request = params.request;
    let network = request.network.as_deref();
    let mint = parse_pubkey(
        resolve_stablecoin_mint(&request.currency, network)
            .ok_or_else(|| Error::Other("session payment channels require an SPL token".into()))?,
        "mint",
    )?;
    let payee = parse_pubkey(&request.recipient, "recipient")?;
    let deposit = match params.options.deposit {
        Some(deposit) => deposit,
        None => parse_u64_string(&request.cap, "session cap")?,
    };
    let grace_period = params
        .options
        .grace_period
        .unwrap_or(DEFAULT_GRACE_PERIOD_SECONDS);
    let program_id = match params.options.program_id {
        Some(program_id) => program_id,
        None => request
            .program_id
            .as_deref()
            .map(|value| parse_pubkey(value, "programId"))
            .transpose()?
            .unwrap_or_else(default_program_id),
    };
    let token_program = match params.options.token_program {
        Some(token_program) => token_program,
        None => parse_pubkey(
            default_token_program_for_currency(&request.currency, network),
            "token program",
        )?,
    };
    let recipients = match params.options.recipients {
        Some(recipients) => recipients,
        None => parse_splits(request)?,
    };
    let salt = params.options.salt.unwrap_or_else(random_salt);
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
    pub recent_blockhash: Hash,
    pub options: PaymentChannelOpenOptions,
}

pub async fn build_open_payment_channel_transaction(
    params: BuildOpenPaymentChannelTransactionParams<'_>,
) -> Result<PaymentChannelOpenTransaction> {
    let operator = parse_pubkey(&params.request.operator, "operator")?;
    let fee_payer = params.fee_payer.unwrap_or(operator);
    // The fee payer becomes the channel `rentPayer`, and the gasless server's
    // open verification requires `rentPayer == operator`. A caller-supplied fee
    // payer that differs from the operator would build an open the server
    // rejects, so reject it here rather than emit a self-incompatible open.
    if fee_payer != operator {
        return Err(Error::Other(
            "fee_payer must equal the challenge operator: the gasless server records \
             rentPayer == operator and rejects any other fee payer"
                .to_string(),
        ));
    }
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
        open.deposit,
        open.grace_period,
        open.recipients.clone(),
        &open.token_program,
        &open.program_id,
        &fee_payer,
        params.recent_blockhash,
    )
    .await
    .map_err(Into::into)
}

pub async fn create_payment_channel_session_opener(
    request: &SessionRequest,
    payer_signer: &dyn SolanaSigner,
    session_signer: Box<dyn SolanaSigner>,
    recent_blockhash: Hash,
    options: PaymentChannelSessionOpenOptions,
) -> Result<PaymentChannelSessionOpen> {
    ensure_client_voucher_pull(request)?;
    let authorized_signer = session_signer.pubkey();
    let fee_payer = parse_pubkey(&request.operator, "operator")?;
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
    let signature = options
        .signature
        .unwrap_or_else(|| PENDING_SERVER_SIGNATURE.to_string());
    let action = SessionAction::Open(
        open.open_payload(SessionMode::Pull, signature)
            .with_transaction(tx.transaction),
    );

    Ok(PaymentChannelSessionOpen {
        open,
        session,
        action,
    })
}

pub fn create_server_opened_payment_channel_session_opener(
    request: &SessionRequest,
    session_signer: Box<dyn SolanaSigner>,
    options: ServerOpenedPaymentChannelSessionOpenOptions,
) -> Result<PaymentChannelSessionOpen> {
    ensure_client_voucher_pull(request)?;
    let payer = options
        .payer
        .map(Ok)
        .unwrap_or_else(|| parse_pubkey(&request.operator, "operator"))?;
    let authorized_signer = session_signer.pubkey();
    let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
        request,
        payer,
        authorized_signer,
        options: options.open,
    })?;
    let mut session = ActiveSession::new(open.channel_id, session_signer);
    configure_session(&mut session, options.cumulative, options.expires_at);
    let signature = options
        .signature
        .unwrap_or_else(|| PENDING_SERVER_SIGNATURE.to_string());
    let action = SessionAction::Open(open.open_payload(SessionMode::Pull, signature));

    Ok(PaymentChannelSessionOpen {
        open,
        session,
        action,
    })
}

fn ensure_client_voucher_pull(request: &SessionRequest) -> Result<()> {
    if !request.modes.contains(&SessionMode::Pull) {
        return Err(Error::Other(
            "session challenge does not advertise pull mode".to_string(),
        ));
    }
    if request.pull_voucher_strategy.as_ref() != Some(&SessionPullVoucherStrategy::ClientVoucher) {
        return Err(Error::Other(
            "session challenge does not advertise pull + clientVoucher".to_string(),
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
        .splits
        .iter()
        .map(|split| {
            Ok(Distribution {
                recipient: parse_pubkey(&split.recipient, "split recipient")?,
                bps: split.bps,
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
    use solana_keychain::MemorySigner;

    /// Build a deterministic MemorySigner from a fixed 32-byte seed via
    /// ed25519-dalek (already a dep), then pack into the 64-byte format that
    /// solana-keychain's MemorySigner::from_bytes expects.
    fn make_signer() -> Box<dyn SolanaSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Box::new(MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    fn make_session() -> ActiveSession {
        ActiveSession::new(Pubkey::new_unique(), make_signer())
    }

    #[tokio::test]
    async fn new_with_expiry_and_set_expires_at_control_voucher_expiry() {
        let channel_id = Pubkey::new_unique();
        let mut session = ActiveSession::new_with_expiry(channel_id, make_signer(), 1234);
        let first = session.prepare_increment(10).await.unwrap();
        assert_eq!(first.data.expires_at, 1234);
        assert_eq!(session.cumulative, 0);

        session.set_expires_at(5678);
        let second = session.prepare_increment(10).await.unwrap();
        assert_eq!(second.data.expires_at, 5678);
    }

    #[tokio::test]
    async fn sign_increment_increases_cumulative() {
        let mut s = make_session();
        assert_eq!(s.cumulative, 0);

        let v = s.sign_increment(100).await.unwrap();
        assert_eq!(s.cumulative, 100);
        assert_eq!(v.data.cumulative, "100");
        assert_eq!(v.data.nonce, Some(1));
    }

    #[tokio::test]
    async fn sign_voucher_absolute() {
        let mut s = make_session();
        s.sign_increment(50).await.unwrap();

        let v = s.sign_voucher(200).await.unwrap();
        assert_eq!(s.cumulative, 200);
        assert_eq!(v.data.cumulative, "200");
    }

    #[tokio::test]
    async fn prepare_and_record_voucher_are_separate_steps() {
        let mut s = make_session();
        let prepared = s.prepare_increment(75).await.unwrap();
        assert_eq!(prepared.data.cumulative, "75");
        assert_eq!(prepared.data.nonce, Some(1));
        assert_eq!(s.cumulative, 0);

        s.record_voucher(&prepared).unwrap();
        assert_eq!(s.cumulative, 75);
        assert!(s.record_voucher(&prepared).is_err());
    }

    #[test]
    fn record_voucher_rejects_invalid_cumulative_and_handles_missing_nonce() {
        let mut s = make_session();
        let bad = SignedVoucher {
            data: VoucherData {
                channel_id: s.channel_id_str(),
                cumulative: "not-a-number".to_string(),
                expires_at: DEFAULT_VOUCHER_EXPIRES_AT,
                nonce: None,
            },
            signature: "sig".to_string(),
        };
        assert!(s.record_voucher(&bad).is_err());

        let without_nonce = SignedVoucher {
            data: VoucherData {
                channel_id: s.channel_id_str(),
                cumulative: "15".to_string(),
                expires_at: DEFAULT_VOUCHER_EXPIRES_AT,
                nonce: None,
            },
            signature: "sig".to_string(),
        };
        s.record_voucher(&without_nonce).unwrap();
        assert_eq!(s.cumulative, 15);
        assert_eq!(s.nonce, 1);
    }

    #[tokio::test]
    async fn sign_voucher_rejects_non_increasing() {
        let mut s = make_session();
        s.sign_increment(100).await.unwrap();

        assert!(s.sign_voucher(100).await.is_err());
        assert!(s.sign_voucher(50).await.is_err());
    }

    #[tokio::test]
    async fn sign_voucher_zero_rejected() {
        let mut s = make_session();
        assert!(s.sign_voucher(0).await.is_err());
    }

    #[tokio::test]
    async fn nonce_increments_per_voucher() {
        let mut s = make_session();
        let v1 = s.sign_increment(10).await.unwrap();
        let v2 = s.sign_increment(10).await.unwrap();
        assert_eq!(v1.data.nonce, Some(1));
        assert_eq!(v2.data.nonce, Some(2));
    }

    #[tokio::test]
    async fn voucher_channel_id_matches_session() {
        let mut s = make_session();
        let expected = s.channel_id_str();
        let v = s.sign_increment(100).await.unwrap();
        assert_eq!(v.data.channel_id, expected);
    }

    #[tokio::test]
    async fn voucher_action_fields() {
        let mut s = make_session();
        let action = s.voucher_action(33).await.unwrap();
        match action {
            SessionAction::Voucher(p) => {
                assert_eq!(p.voucher.data.cumulative, "33");
                assert_eq!(p.voucher.data.channel_id, s.channel_id_str());
            }
            _ => panic!("Expected Voucher"),
        }
    }

    #[test]
    fn open_action_fields() {
        use crate::protocol::intents::session::SessionMode;
        let s = make_session();
        let channel_id = s.channel_id_str();
        let authorized_signer = s.authorized_signer();
        let action = s.open_action(1_000_000, "txsig123");
        match action {
            SessionAction::Open(p) => {
                assert_eq!(p.mode, SessionMode::Push);
                assert_eq!(p.deposit.as_deref(), Some("1000000"));
                assert_eq!(p.signature, "txsig123");
                assert_eq!(p.channel_id.as_deref(), Some(channel_id.as_str()));
                assert_eq!(p.authorized_signer, authorized_signer);
            }
            _ => panic!("Expected Open"),
        }
    }

    #[test]
    fn open_payment_channel_action_fields() {
        use crate::protocol::intents::session::SessionMode;
        let s = make_session();
        let channel_id = s.channel_id_str();
        let action =
            s.open_payment_channel_action(9_000, "payer", "payee", "mint", 42, 60, "open-sig");
        match action {
            SessionAction::Open(p) => {
                assert_eq!(p.mode, SessionMode::Push);
                assert_eq!(p.channel_id.as_deref(), Some(channel_id.as_str()));
                assert_eq!(p.deposit.as_deref(), Some("9000"));
                assert_eq!(p.payer.as_deref(), Some("payer"));
                assert_eq!(p.payee.as_deref(), Some("payee"));
                assert_eq!(p.mint.as_deref(), Some("mint"));
                assert_eq!(p.salt, Some(42));
                assert_eq!(p.grace_period, Some(60));
                assert_eq!(p.signature, "open-sig");
            }
            _ => panic!("Expected Open"),
        }
    }

    #[test]
    fn open_payment_channel_action_can_use_pull_mode() {
        use crate::protocol::intents::session::SessionMode;
        let s = make_session();
        let channel_id = s.channel_id_str();
        let action = s.open_payment_channel_action_with_mode(
            SessionMode::Pull,
            9_000,
            "payer",
            "payee",
            "mint",
            42,
            60,
            "pending",
        );
        match action {
            SessionAction::Open(p) => {
                assert_eq!(p.mode, SessionMode::Pull);
                assert_eq!(p.channel_id.as_deref(), Some(channel_id.as_str()));
                assert_eq!(p.deposit.as_deref(), Some("9000"));
                assert!(p.token_account.is_none());
                assert!(p.approved_amount.is_none());
            }
            _ => panic!("Expected Open"),
        }
    }

    #[test]
    fn open_pull_action_fields() {
        use crate::protocol::intents::session::SessionMode;
        let s = make_session();
        let channel_id = s.channel_id_str(); // used as token_account in pull mode
        let authorized_signer = s.authorized_signer();
        let action = s.open_pull_action(5_000_000, "wallet123", "approvesig");
        match action {
            SessionAction::Open(p) => {
                assert_eq!(p.mode, SessionMode::Pull);
                assert_eq!(p.approved_amount.as_deref(), Some("5000000"));
                assert_eq!(p.signature, "approvesig");
                assert_eq!(p.token_account.as_deref(), Some(channel_id.as_str()));
                assert_eq!(p.owner.as_deref(), Some("wallet123"));
                assert_eq!(p.authorized_signer, authorized_signer);
                assert!(p.channel_id.is_none());
                assert!(p.deposit.is_none());
            }
            _ => panic!("Expected Open"),
        }
    }

    #[test]
    fn topup_action_fields() {
        let s = make_session();
        let action = s.topup_action(5_000_000, "topuptx");
        match action {
            SessionAction::TopUp(p) => {
                assert_eq!(p.new_deposit, "5000000");
                assert_eq!(p.signature, "topuptx");
            }
            _ => panic!("Expected TopUp"),
        }
    }

    #[tokio::test]
    async fn close_action_no_final_increment() {
        let mut s = make_session();
        let action = s.close_action(None).await.unwrap();
        match action {
            SessionAction::Close(p) => {
                assert!(p.voucher.is_none());
            }
            _ => panic!("Expected Close"),
        }
    }

    #[tokio::test]
    async fn close_action_with_final_increment() {
        let mut s = make_session();
        s.sign_increment(100).await.unwrap();
        let action = s.close_action(Some(50)).await.unwrap();
        match action {
            SessionAction::Close(p) => {
                let v = p.voucher.unwrap();
                assert_eq!(v.data.cumulative, "150");
            }
            _ => panic!("Expected Close"),
        }
    }

    #[tokio::test]
    async fn close_action_zero_increment_no_voucher() {
        let mut s = make_session();
        let action = s.close_action(Some(0)).await.unwrap();
        match action {
            SessionAction::Close(p) => {
                assert!(p.voucher.is_none());
            }
            _ => panic!("Expected Close"),
        }
    }
}

#[cfg(test)]
mod open_tests {
    use super::*;
    use crate::protocol::intents::session::SessionSplit;
    use crate::protocol::solana::{mints, programs};
    use base64::Engine;
    use solana_keychain::MemorySigner;
    use solana_signature::Signature;
    use solana_transaction::Transaction;

    fn make_signer(seed: u8) -> Box<dyn SolanaSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Box::new(MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    fn test_request(operator: Pubkey, recipient: Pubkey) -> SessionRequest {
        SessionRequest {
            cap: "1000".to_string(),
            currency: "USDC".to_string(),
            decimals: Some(6),
            network: Some("localnet".to_string()),
            operator: pubkey_string(&operator),
            recipient: pubkey_string(&recipient),
            splits: vec![],
            program_id: None,
            description: None,
            external_id: None,
            min_voucher_delta: None,
            modes: vec![SessionMode::Pull],
            pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
            recent_blockhash: None,
        }
    }

    fn decode_transaction(encoded: &str) -> Transaction {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64 transaction");
        bincode::deserialize(&bytes).expect("bincode transaction")
    }

    #[test]
    fn derive_payment_channel_open_uses_challenge_defaults_and_splits() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let mut request = test_request(operator, recipient);
        request.splits.push(SessionSplit {
            recipient: pubkey_string(&split_recipient),
            bps: 10,
        });

        let payer = Pubkey::new_unique();
        let authorized_signer = Pubkey::new_unique();
        let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &request,
            payer,
            authorized_signer,
            options: PaymentChannelOpenOptions {
                salt: Some(42),
                ..PaymentChannelOpenOptions::default()
            },
        })
        .unwrap();

        assert_eq!(open.payer, payer);
        assert_eq!(open.payee, recipient);
        assert_eq!(open.authorized_signer, authorized_signer);
        assert_eq!(open.deposit, 1000);
        assert_eq!(open.grace_period, DEFAULT_GRACE_PERIOD_SECONDS);
        assert_eq!(open.salt, 42);
        assert_eq!(open.recipients.len(), 1);
        assert_eq!(open.recipients[0].recipient, split_recipient);
        assert_eq!(open.recipients[0].bps, 10);
        assert_eq!(
            open.mint,
            Pubkey::from_str(mints::USDC_MAINNET).expect("valid USDC mint")
        );
        assert_eq!(
            open.token_program,
            Pubkey::from_str(programs::TOKEN_PROGRAM).expect("valid token program")
        );
        assert_eq!(open.channel_id, open.channel_address());
    }

    #[test]
    fn derive_payment_channel_open_honors_explicit_options() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let token_program = Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap();
        let mut request = test_request(operator, recipient);
        request.cap = "not-a-number".to_string();
        request.splits.push(SessionSplit {
            recipient: "not-a-pubkey".to_string(),
            bps: 999,
        });

        let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &request,
            payer: Pubkey::new_unique(),
            authorized_signer: Pubkey::new_unique(),
            options: PaymentChannelOpenOptions {
                deposit: Some(55),
                grace_period: Some(12),
                program_id: Some(program_id),
                recipients: Some(vec![Distribution {
                    recipient: split_recipient,
                    bps: 25,
                }]),
                salt: Some(7),
                token_program: Some(token_program),
            },
        })
        .unwrap();

        assert_eq!(open.deposit, 55);
        assert_eq!(open.grace_period, 12);
        assert_eq!(open.program_id, program_id);
        assert_eq!(open.token_program, token_program);
        assert_eq!(open.recipients.len(), 1);
        assert_eq!(open.recipients[0].recipient, split_recipient);
        assert_eq!(open.recipients[0].bps, 25);
    }

    #[test]
    fn derive_payment_channel_open_rejects_invalid_challenge_values() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let authorized_signer = Pubkey::new_unique();

        let mut request = test_request(operator, recipient);
        request.currency = "SOL".to_string();
        let err = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &request,
            payer,
            authorized_signer,
            options: PaymentChannelOpenOptions::default(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("SPL token"));

        let mut request = test_request(operator, recipient);
        request.cap = "not-a-number".to_string();
        let err = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &request,
            payer,
            authorized_signer,
            options: PaymentChannelOpenOptions::default(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("session cap"));

        let mut request = test_request(operator, recipient);
        request.recipient = "not-a-pubkey".to_string();
        let err = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &request,
            payer,
            authorized_signer,
            options: PaymentChannelOpenOptions::default(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("recipient"));

        let mut request = test_request(operator, recipient);
        request.program_id = Some("not-a-program".to_string());
        let err = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &request,
            payer,
            authorized_signer,
            options: PaymentChannelOpenOptions::default(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("programId"));

        let mut request = test_request(operator, recipient);
        request.splits.push(SessionSplit {
            recipient: "not-a-pubkey".to_string(),
            bps: 10,
        });
        let err = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &request,
            payer,
            authorized_signer,
            options: PaymentChannelOpenOptions::default(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("split recipient"));
    }

    #[tokio::test]
    async fn build_open_payment_channel_transaction_partially_signs_for_operator_broadcast() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let request = test_request(operator, recipient);
        let payer_signer = make_signer(7);
        let authorized_signer = make_signer(8).pubkey();

        let built =
            build_open_payment_channel_transaction(BuildOpenPaymentChannelTransactionParams {
                request: &request,
                signer: payer_signer.as_ref(),
                authorized_signer,
                fee_payer: None,
                recent_blockhash: Hash::new_unique(),
                options: PaymentChannelOpenOptions {
                    salt: Some(99),
                    ..PaymentChannelOpenOptions::default()
                },
            })
            .await
            .unwrap();
        let tx = decode_transaction(&built.transaction);
        let expected_open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
            request: &request,
            payer: payer_signer.pubkey(),
            authorized_signer,
            options: PaymentChannelOpenOptions {
                salt: Some(99),
                ..PaymentChannelOpenOptions::default()
            },
        })
        .unwrap();

        assert_eq!(built.channel_id, expected_open.channel_id);
        assert_eq!(tx.message.account_keys[0], operator);
        assert_eq!(tx.message.instructions.len(), 1);

        let payer_index = tx
            .message
            .account_keys
            .iter()
            .position(|key| key == &payer_signer.pubkey())
            .expect("payer signer account");
        assert_eq!(tx.signatures[0], Signature::default());
        assert_ne!(tx.signatures[payer_index], Signature::default());
    }

    #[tokio::test]
    async fn build_open_payment_channel_transaction_uses_operator_fee_payer() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let request = test_request(operator, recipient);
        let payer_signer = make_signer(15);

        // An explicit fee payer is allowed only when it equals the operator.
        let built =
            build_open_payment_channel_transaction(BuildOpenPaymentChannelTransactionParams {
                request: &request,
                signer: payer_signer.as_ref(),
                authorized_signer: make_signer(16).pubkey(),
                fee_payer: Some(operator),
                recent_blockhash: Hash::new_unique(),
                options: PaymentChannelOpenOptions {
                    salt: Some(123),
                    ..PaymentChannelOpenOptions::default()
                },
            })
            .await
            .unwrap();
        let tx = decode_transaction(&built.transaction);

        assert_eq!(tx.message.account_keys[0], operator);
    }

    #[tokio::test]
    async fn build_open_payment_channel_transaction_rejects_non_operator_fee_payer() {
        let operator = Pubkey::new_unique();
        let non_operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let request = test_request(operator, recipient);
        let payer_signer = make_signer(15);

        let err =
            build_open_payment_channel_transaction(BuildOpenPaymentChannelTransactionParams {
                request: &request,
                signer: payer_signer.as_ref(),
                authorized_signer: make_signer(16).pubkey(),
                fee_payer: Some(non_operator),
                recent_blockhash: Hash::new_unique(),
                options: PaymentChannelOpenOptions::default(),
            })
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("fee_payer must equal the challenge operator"));
    }

    #[tokio::test]
    async fn create_payment_channel_session_opener_builds_pull_client_voucher_action() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let request = test_request(operator, recipient);
        let payer_signer = make_signer(9);
        let session_signer = make_signer(10);
        let authorized_signer = session_signer.pubkey();

        let opened = create_payment_channel_session_opener(
            &request,
            payer_signer.as_ref(),
            session_signer,
            Hash::new_unique(),
            PaymentChannelSessionOpenOptions {
                open: PaymentChannelOpenOptions {
                    salt: Some(11),
                    ..PaymentChannelOpenOptions::default()
                },
                ..PaymentChannelSessionOpenOptions::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(opened.session.channel_id, opened.open.channel_id);
        match opened.action {
            SessionAction::Open(payload) => {
                assert_eq!(payload.mode, SessionMode::Pull);
                assert_eq!(
                    payload.channel_id.as_deref(),
                    Some(pubkey_string(&opened.open.channel_id).as_str())
                );
                assert_eq!(
                    payload.payer.as_deref(),
                    Some(pubkey_string(&payer_signer.pubkey()).as_str())
                );
                assert_eq!(payload.authorized_signer, pubkey_string(&authorized_signer));
                assert_eq!(payload.signature, PENDING_SERVER_SIGNATURE);
                assert!(payload.transaction.is_some());
                assert!(payload.token_account.is_none());
                assert!(payload.approved_amount.is_none());
                assert!(payload.init_multi_delegate_tx.is_none());
                assert!(payload.update_delegation_tx.is_none());
            }
            _ => panic!("expected open action"),
        }
    }

    #[tokio::test]
    async fn create_payment_channel_session_opener_applies_session_options() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let request = test_request(operator, recipient);
        let payer_signer = make_signer(17);

        let opened = create_payment_channel_session_opener(
            &request,
            payer_signer.as_ref(),
            make_signer(18),
            Hash::new_unique(),
            PaymentChannelSessionOpenOptions {
                open: PaymentChannelOpenOptions {
                    salt: Some(19),
                    ..PaymentChannelOpenOptions::default()
                },
                signature: Some("operator-will-fill".to_string()),
                cumulative: Some(20),
                expires_at: Some(1234),
            },
        )
        .await
        .unwrap();

        match &opened.action {
            SessionAction::Open(payload) => {
                assert_eq!(payload.signature, "operator-will-fill");
            }
            _ => panic!("expected open action"),
        }
        let voucher = opened.session.prepare_increment(5).await.unwrap();
        assert_eq!(voucher.data.cumulative, "25");
        assert_eq!(voucher.data.expires_at, 1234);
    }

    #[test]
    fn create_server_opened_session_opener_uses_operator_payer_without_transaction() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let request = test_request(operator, recipient);
        let session_signer = make_signer(12);
        let authorized_signer = session_signer.pubkey();

        let opened = create_server_opened_payment_channel_session_opener(
            &request,
            session_signer,
            ServerOpenedPaymentChannelSessionOpenOptions {
                open: PaymentChannelOpenOptions {
                    salt: Some(13),
                    ..PaymentChannelOpenOptions::default()
                },
                ..ServerOpenedPaymentChannelSessionOpenOptions::default()
            },
        )
        .unwrap();

        assert_eq!(opened.open.payer, operator);
        match opened.action {
            SessionAction::Open(payload) => {
                assert_eq!(payload.mode, SessionMode::Pull);
                assert_eq!(payload.payer.as_deref(), Some(request.operator.as_str()));
                assert_eq!(payload.authorized_signer, pubkey_string(&authorized_signer));
                assert_eq!(payload.signature, PENDING_SERVER_SIGNATURE);
                assert!(payload.transaction.is_none());
                assert!(payload.token_account.is_none());
                assert!(payload.approved_amount.is_none());
            }
            _ => panic!("expected open action"),
        }
    }

    #[test]
    fn session_opener_rejects_non_pull_challenge() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mut request = test_request(operator, recipient);
        request.modes = vec![SessionMode::Push];
        request.pull_voucher_strategy = None;

        let err = match create_server_opened_payment_channel_session_opener(
            &request,
            make_signer(20),
            ServerOpenedPaymentChannelSessionOpenOptions::default(),
        ) {
            Ok(_) => panic!("expected non-pull challenge to be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("pull mode"));
    }

    #[test]
    fn session_opener_rejects_operated_voucher_pull_challenge() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mut request = test_request(operator, recipient);
        request.pull_voucher_strategy = Some(SessionPullVoucherStrategy::OperatedVoucher);

        let err = match create_server_opened_payment_channel_session_opener(
            &request,
            make_signer(14),
            ServerOpenedPaymentChannelSessionOpenOptions::default(),
        ) {
            Ok(_) => panic!("expected operated-voucher challenge to be rejected"),
            Err(err) => err,
        };
        assert!(err
            .to_string()
            .contains("does not advertise pull + clientVoucher"));
    }
}
