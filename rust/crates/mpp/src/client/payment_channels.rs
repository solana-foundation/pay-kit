//! Client-side helpers for payment-channel open transactions.

use std::str::FromStr;

use base64::Engine;
use solana_hash::Hash;
use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use super::session::ActiveSession;
use crate::error::{Error, Result};
use crate::program::payment_channels::{
    build_open_instruction, default_program_id, derive_channel_addresses, Distribution,
    OpenChannelParams,
};
use crate::protocol::intents::session::{
    OpenPayload, SessionAction, SessionMode, SessionPullVoucherStrategy, SessionRequest,
    DEFAULT_SESSION_EXPIRES_AT,
};
use crate::protocol::solana::{default_token_program_for_currency, resolve_stablecoin_mint};

/// Default payment-channel close grace period used by the TypeScript client.
pub const DEFAULT_GRACE_PERIOD_SECONDS: u32 = 900;

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
    pub fn open_channel_params(&self) -> OpenChannelParams {
        OpenChannelParams {
            payer: self.payer,
            payee: self.payee,
            mint: self.mint,
            authorized_signer: self.authorized_signer,
            salt: self.salt,
            deposit: self.deposit,
            grace_period: self.grace_period,
            recipients: self.recipients.clone(),
            token_program: self.token_program,
            program_id: self.program_id,
        }
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

#[derive(Debug, Clone)]
pub struct PaymentChannelOpenTransaction {
    pub channel_id: Pubkey,
    pub transaction: String,
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
    let salt = params.options.salt.unwrap_or_else(unique_salt);
    let open_params = OpenChannelParams {
        payer: params.payer,
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
    let fee_payer = params
        .fee_payer
        .map(Ok)
        .unwrap_or_else(|| parse_pubkey(&params.request.operator, "operator"))?;
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

#[allow(clippy::too_many_arguments)]
pub async fn build_open_payment_channel_tx(
    signer: &dyn SolanaSigner,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    deposit: u64,
    grace_period: u32,
    recipients: Vec<Distribution>,
    token_program: &Pubkey,
    program_id: &Pubkey,
    fee_payer: &Pubkey,
    recent_blockhash: Hash,
) -> Result<PaymentChannelOpenTransaction> {
    let params = OpenChannelParams {
        payer: signer.pubkey(),
        payee: *payee,
        mint: *mint,
        authorized_signer: *authorized_signer,
        salt,
        deposit,
        grace_period,
        recipients,
        token_program: *token_program,
        program_id: *program_id,
    };
    let channel_id = derive_channel_addresses(&params).channel;
    let ix = build_open_instruction(&params);
    let message = Message::new_with_blockhash(&[ix], Some(fee_payer), &recent_blockhash);
    let mut tx = Transaction::new_unsigned(message);

    signer
        .sign_transaction(&mut tx)
        .await
        .map_err(|e| Error::Other(format!("payment-channel open signing failed: {e}")))?;

    let bytes = bincode::serialize(&tx)
        .map_err(|e| Error::Other(format!("payment-channel open tx serialization failed: {e}")))?;
    Ok(PaymentChannelOpenTransaction {
        channel_id,
        transaction: base64::engine::general_purpose::STANDARD.encode(bytes),
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

fn unique_salt() -> u64 {
    let bytes = Pubkey::new_unique().to_bytes();
    u64::from_le_bytes(bytes[..8].try_into().expect("slice is exactly 8 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::intents::session::SessionSplit;
    use crate::protocol::solana::{mints, programs};
    use solana_keychain::MemorySigner;
    use solana_signature::Signature;

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
        assert_eq!(
            open.channel_id,
            derive_channel_addresses(&open.open_channel_params()).channel
        );
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
    async fn build_open_payment_channel_transaction_uses_explicit_fee_payer() {
        let operator = Pubkey::new_unique();
        let explicit_fee_payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let request = test_request(operator, recipient);
        let payer_signer = make_signer(15);

        let built =
            build_open_payment_channel_transaction(BuildOpenPaymentChannelTransactionParams {
                request: &request,
                signer: payer_signer.as_ref(),
                authorized_signer: make_signer(16).pubkey(),
                fee_payer: Some(explicit_fee_payer),
                recent_blockhash: Hash::new_unique(),
                options: PaymentChannelOpenOptions {
                    salt: Some(123),
                    ..PaymentChannelOpenOptions::default()
                },
            })
            .await
            .unwrap();
        let tx = decode_transaction(&built.transaction);

        assert_eq!(tx.message.account_keys[0], explicit_fee_payer);
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
