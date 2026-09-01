//! Client-side payment building for the SVM `batch-settlement` scheme.
//!
//! The client opens one escrow channel, then pays per request by signing a
//! cumulative voucher — no onchain transaction in the request path after the
//! first. [`BatchChannel`] tracks the cumulative watermark for a channel.
//!
//! The tracker advances only on a confirmed `PAYMENT-RESPONSE`
//! ([`BatchChannel::apply_payment_response`]). A payment payload is an
//! authorization, not a receipt: advancing on send would desynchronize the
//! watermark from the server's whenever a request failed in flight, and every
//! later voucher would be rejected.
//!
//! See `specs/schemes/batch-settlement/scheme_batch_settlement_svm.md` §5.

use std::str::FromStr;

use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::Transaction;

use crate::core::payment_channels as pc;

use crate::x402::error::Error;
use crate::x402::protocol::schemes::batch_settlement::{
    check_corrective_voucher_state, check_token_program, check_withdraw_delay, derive_channel_id,
    errors as codes, BatchChannelConfig, BatchDeposit, BatchError, BatchPayload,
    BatchPaymentPayload, BatchRequiredEnvelope, BatchRequirements, BatchSettlementResponse,
    BatchVoucher, BATCH_SETTLEMENT_SCHEME, VOUCHER_EXPIRES_AT,
};
use crate::x402::{PAYMENT_REQUIRED_HEADER, X402_VERSION_V2};

/// Minimum random Memo nonce, in bytes, before hex encoding.
const MEMO_NONCE_BYTES: usize = 16;

fn batch_err(code: &'static str, detail: impl Into<String>) -> Error {
    BatchError::new(code, detail).into()
}

/// Terms resolved from a challenge, after the checks the client owes itself.
#[derive(Debug, Clone)]
pub struct BatchTerms {
    /// `extra.feePayer`: the sponsor and transaction fee payer.
    pub fee_payer: Pubkey,
    /// The mint being paid in.
    pub mint: Pubkey,
    /// The verified token program that owns `mint`.
    pub token_program: Pubkey,
    /// The final payment receiver.
    pub receiver: Pubkey,
    /// Forced-close grace period, in seconds.
    pub withdraw_delay: u32,
    /// Per-request price, in atomic units.
    pub amount: u64,
    /// The Memo the setup transaction must carry.
    pub memo: String,
}

/// Validate a challenge's terms without touching the network.
///
/// `token_program` must already have been confirmed against the mint's onchain
/// owner — use [`resolve_terms`] to do both. Splitting them keeps the offline
/// checks testable and lets a caller that already knows the mint owner skip the
/// RPC round trip.
pub fn resolve_terms_with_token_program(
    requirements: &BatchRequirements,
    token_program: Pubkey,
) -> Result<BatchTerms, Error> {
    let extra = &requirements.extra;
    crate::x402::protocol::schemes::batch_settlement::check_payment_flow(
        extra.payment_flow.as_deref(),
    )?;
    check_withdraw_delay(extra.withdraw_delay, requirements.max_timeout_seconds)?;
    let declared = check_token_program(&extra.token_program)?;
    if declared != token_program {
        return Err(batch_err(
            codes::INVALID_TOKEN_PROGRAM,
            format!(
                "extra.tokenProgram {} does not own asset {}",
                extra.token_program, requirements.asset
            ),
        ));
    }
    let fee_payer = pc::parse_pubkey(&extra.fee_payer)?;
    let mint = pc::parse_pubkey(&requirements.asset)?;
    let receiver = pc::parse_pubkey(&requirements.pay_to)?;
    // The seller's memo is pinned byte-for-byte when declared; otherwise the
    // sponsor requires a random hex nonce, which correlates the transaction
    // without smuggling a payload it never agreed to.
    let memo = match &extra.memo {
        Some(memo) => memo.clone(),
        None => random_hex_nonce(),
    };
    Ok(BatchTerms {
        fee_payer,
        mint,
        token_program,
        receiver,
        withdraw_delay: extra.withdraw_delay,
        amount: requirements.amount()?,
        memo,
    })
}

/// Validate a challenge's terms, confirming the advertised token program really
/// owns the asset.
///
/// A server-declared `extra.tokenProgram` is not evidence: every associated
/// token address in the `open` derives from it, so trusting a wrong value would
/// escrow funds into accounts the payment-channels program will never touch.
pub fn resolve_terms(
    rpc: &RpcClient,
    requirements: &BatchRequirements,
) -> Result<BatchTerms, Error> {
    let mint = pc::parse_pubkey(&requirements.asset)?;
    let account = rpc
        .get_account(&mint)
        .map_err(|e| Error::Rpc(format!("mint fetch failed: {e}")))?;
    resolve_terms_with_token_program(requirements, pc::from_address(&account.owner))
}

fn random_hex_nonce() -> String {
    let mut bytes = [0u8; MEMO_NONCE_BYTES];
    getrandom::fill(&mut bytes).expect("getrandom CSPRNG failure");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A client's view of one payment channel: its configuration and the cumulative
/// amount the server has confirmed charging.
#[derive(Debug, Clone)]
pub struct BatchChannel {
    channel_id: Pubkey,
    config: BatchChannelConfig,
    charged_cumulative_amount: u64,
    deposit: u64,
}

impl BatchChannel {
    /// Rebuild a tracker from persisted state.
    pub fn new(
        channel_id: Pubkey,
        config: BatchChannelConfig,
        charged_cumulative_amount: u64,
        deposit: u64,
    ) -> Self {
        Self {
            channel_id,
            config,
            charged_cumulative_amount,
            deposit,
        }
    }

    /// The channel PDA.
    pub fn channel_id(&self) -> &Pubkey {
        &self.channel_id
    }

    /// The channel configuration echoed on every payload.
    pub fn config(&self) -> &BatchChannelConfig {
        &self.config
    }

    /// The cumulative amount the server has confirmed charging.
    pub fn charged_cumulative_amount(&self) -> u64 {
        self.charged_cumulative_amount
    }

    /// The escrowed deposit ceiling last confirmed by the server.
    pub fn deposit(&self) -> u64 {
        self.deposit
    }

    /// Whether one more request at `amount` still fits under the deposit. When
    /// it does not, the next payment must be a top-up.
    pub fn can_cover(&self, amount: u64) -> bool {
        self.charged_cumulative_amount
            .checked_add(amount)
            .is_some_and(|next| next <= self.deposit)
    }

    /// Sign the next cumulative voucher without advancing local state.
    pub async fn sign_next_voucher(
        &self,
        signer: &dyn SolanaSigner,
        amount: u64,
    ) -> Result<BatchVoucher, Error> {
        let next = self
            .charged_cumulative_amount
            .checked_add(amount)
            .ok_or_else(|| Error::Other("cumulative amount overflow".into()))?;
        sign_voucher(signer, &self.channel_id, next).await
    }

    /// Build a steady-state `voucher` payload for one request.
    pub async fn voucher_payload(
        &self,
        signer: &dyn SolanaSigner,
        amount: u64,
    ) -> Result<BatchPayload, Error> {
        Ok(BatchPayload::Voucher {
            channel_config: self.config.clone(),
            voucher: self.sign_next_voucher(signer, amount).await?,
        })
    }

    /// Adopt the server's confirmed state from a successful `PAYMENT-RESPONSE`.
    ///
    /// The response must confirm the exact commitment that was sent: the same
    /// channel and cumulative amount, and a charge equal to the advertised
    /// price. A response that confirms something else is not evidence this
    /// request was the one that landed, and adopting it would silently skew the
    /// watermark.
    pub fn apply_payment_response(
        &mut self,
        response: &BatchSettlementResponse,
        requirements: &BatchRequirements,
        submitted: &BatchVoucher,
    ) -> Result<(), Error> {
        if !response.success {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                response
                    .error_reason
                    .clone()
                    .unwrap_or_else(|| "settlement failed".to_string()),
            ));
        }
        let extra = response.extra.as_ref().ok_or_else(|| {
            batch_err(
                codes::INVALID_CHANNEL_STATE,
                "PAYMENT-RESPONSE has no extra",
            )
        })?;
        if extra.commitment_id.as_deref() != Some(submitted.commitment_id().as_str()) {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                "PAYMENT-RESPONSE confirms a different commitment",
            ));
        }
        if extra.charged_amount.as_deref() != Some(requirements.amount.as_str()) {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                "PAYMENT-RESPONSE charged an amount other than the advertised price",
            ));
        }
        let state = extra.channel_state.as_ref().ok_or_else(|| {
            batch_err(
                codes::INVALID_CHANNEL_STATE,
                "PAYMENT-RESPONSE has no channelState",
            )
        })?;
        let charged = state
            .charged_cumulative_amount
            .as_deref()
            .ok_or_else(|| {
                batch_err(
                    codes::INVALID_CHANNEL_STATE,
                    "PAYMENT-RESPONSE channelState has no chargedCumulativeAmount",
                )
            })?
            .parse::<u64>()
            .map_err(|_| {
                batch_err(
                    codes::INVALID_CHANNEL_STATE,
                    "invalid chargedCumulativeAmount",
                )
            })?;
        let submitted_cumulative = submitted.max_claimable()?;
        if charged != submitted_cumulative {
            return Err(batch_err(
                codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                format!("server charged {charged}, submitted {submitted_cumulative}"),
            ));
        }
        let balance = state
            .balance
            .parse::<u64>()
            .map_err(|_| batch_err(codes::INVALID_CHANNEL_STATE, "invalid channelState.balance"))?;
        self.charged_cumulative_amount = charged;
        self.deposit = balance;
        Ok(())
    }

    /// Resynchronize from a corrective 402 after a cumulative-amount mismatch.
    ///
    /// The server's snapshot is adopted only against a voucher this client's own
    /// `payerAuthorizer` signed at that amount — otherwise a server could keep
    /// raising the cumulative base and have the client sign away funds it never
    /// spent. When the server holds no voucher, there is nothing to prove and
    /// nothing to adopt; the caller must resynchronize from onchain state.
    pub fn adopt_corrective_state(
        &mut self,
        requirements: &BatchRequirements,
    ) -> Result<u64, Error> {
        let state = requirements.extra.channel_state.as_ref().ok_or_else(|| {
            batch_err(
                codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                "corrective challenge carries no channelState",
            )
        })?;
        if state.channel_id != pc::pubkey_string(&self.channel_id) {
            return Err(batch_err(
                codes::INVALID_CHANNEL_ID_MISMATCH,
                "corrective channelState names a different channel",
            ));
        }
        let charged = state
            .charged_cumulative_amount
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|_| {
                batch_err(
                    codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                    "invalid chargedCumulativeAmount",
                )
            })?;
        let proof = requirements.extra.voucher_state.as_ref().ok_or_else(|| {
            batch_err(
                codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                "corrective challenge carries no voucherState proof",
            )
        })?;
        let adopted = check_corrective_voucher_state(
            proof,
            &state.channel_id,
            &self.config.payer_authorizer,
            charged,
        )?;
        if let Ok(balance) = state.balance.parse::<u64>() {
            self.deposit = balance;
        }
        self.charged_cumulative_amount = adopted;
        Ok(adopted)
    }
}

/// Sign a cumulative voucher over the canonical 50-byte message.
pub async fn sign_voucher(
    signer: &dyn SolanaSigner,
    channel_id: &Pubkey,
    max_claimable: u64,
) -> Result<BatchVoucher, Error> {
    let message = pc::voucher_message_bytes(channel_id, max_claimable, VOUCHER_EXPIRES_AT)?;
    let signature: [u8; 64] = signer
        .sign_message(&message)
        .await
        .map_err(|e| Error::Other(format!("voucher signing failed: {e}")))?
        .into();
    Ok(BatchVoucher {
        channel_id: pc::pubkey_string(channel_id),
        max_claimable_amount: max_claimable.to_string(),
        // Never-expiring: the forced-close grace period is the only clock that
        // bounds redemption.
        expires_at: VOUCHER_EXPIRES_AT,
        signature: bs58::encode(signature).into_string(),
    })
}

/// Build the first `deposit` payload: a channel `open` plus the first voucher.
///
/// The payer key doubles as the `payerAuthorizer`. The sponsor is the
/// transaction fee payer and the channel `rent_payer`, so the client's own SOL
/// is never spent.
pub async fn build_deposit(
    signer: &dyn SolanaSigner,
    requirements: &BatchRequirements,
    terms: &BatchTerms,
    deposit_amount: u64,
    blockhash: Hash,
    open_slot: u64,
) -> Result<(BatchChannel, BatchPayload), Error> {
    if deposit_amount < terms.amount {
        return Err(Error::Other(
            "deposit must cover at least one request".into(),
        ));
    }
    let payer = signer.pubkey();
    if payer == terms.fee_payer {
        return Err(batch_err(
            codes::INVALID_FEE_PAYER_MISMATCH,
            "the channel payer must not be the sponsor",
        ));
    }
    let salt = pc::random_salt();
    let open = pc::build_open_payment_channel_tx_with_options(
        signer,
        // The sponsor holds the zero-share payee seat; 100% of settled funds go
        // to `payTo` through the single explicit distribution entry below.
        &terms.fee_payer,
        &terms.mint,
        &payer,
        salt,
        open_slot,
        deposit_amount,
        terms.withdraw_delay,
        pc::sole_recipient(&terms.receiver),
        &terms.token_program,
        &pc::default_program_id(),
        &terms.fee_payer,
        blockhash,
        &pc::OpenTxOptions {
            memo: Some(terms.memo.clone()),
        },
    )
    .await?;

    let config = BatchChannelConfig {
        payer: pc::pubkey_string(&payer),
        payer_authorizer: pc::pubkey_string(&payer),
        receiver: requirements.pay_to.clone(),
        receiver_authorizer: requirements.extra.receiver_authorizer.clone(),
        token: requirements.asset.clone(),
        withdraw_delay: terms.withdraw_delay,
        salt: salt.to_string(),
        open_slot,
    };
    let voucher = sign_voucher(signer, &open.channel_id, terms.amount).await?;
    let channel = BatchChannel::new(open.channel_id, config.clone(), 0, deposit_amount);
    Ok((
        channel,
        BatchPayload::Deposit {
            channel_config: config,
            voucher,
            deposit: BatchDeposit {
                amount: deposit_amount.to_string(),
                transaction: open.transaction,
            },
        },
    ))
}

/// Build a `deposit` payload that tops up an existing channel and authorizes
/// this request. Used when the next voucher would exceed the escrowed deposit.
pub async fn build_top_up(
    signer: &dyn SolanaSigner,
    channel: &BatchChannel,
    terms: &BatchTerms,
    top_up_amount: u64,
    blockhash: Hash,
) -> Result<BatchPayload, Error> {
    let payer = signer.pubkey();
    let instructions = vec![
        pc::build_top_up_instruction(
            &payer,
            &channel.channel_id,
            &terms.mint,
            top_up_amount,
            &terms.token_program,
            &pc::default_program_id(),
        ),
        memo_instruction(&terms.memo),
    ];
    let transaction = sign_sponsored(signer, &terms.fee_payer, &instructions, blockhash).await?;
    let voucher = channel.sign_next_voucher(signer, terms.amount).await?;
    Ok(BatchPayload::Deposit {
        channel_config: channel.config.clone(),
        voucher,
        deposit: BatchDeposit {
            amount: top_up_amount.to_string(),
            transaction,
        },
    })
}

/// Build a `refund` payload: a payer-signed `request_close`.
///
/// This starts the forced close. It carries no voucher and no close
/// authorization: the interoperable path does not need the server's
/// cooperation, and a facilitator must not apply a voucher supplied in an
/// untrusted request. After the grace period the unused escrow returns to the
/// payer; the channel cannot be reused.
pub async fn build_refund(
    signer: &dyn SolanaSigner,
    channel: &BatchChannel,
    terms: &BatchTerms,
    blockhash: Hash,
) -> Result<BatchPayload, Error> {
    let instructions = vec![
        pc::build_request_close_instruction(
            &signer.pubkey(),
            &channel.channel_id,
            &pc::default_program_id(),
        ),
        memo_instruction(&terms.memo),
    ];
    Ok(BatchPayload::Refund {
        channel_config: channel.config.clone(),
        transaction: sign_sponsored(signer, &terms.fee_payer, &instructions, blockhash).await?,
        voucher: None,
        close_authorization: None,
    })
}

fn memo_instruction(memo: &str) -> Instruction {
    Instruction {
        program_id: pc::to_address(&pc::memo_program_id()),
        accounts: vec![],
        data: memo.as_bytes().to_vec(),
    }
}

/// Compile `instructions` with the sponsor as fee payer, sign the payer slot,
/// and return the base64 transaction for the sponsor to co-sign.
async fn sign_sponsored(
    signer: &dyn SolanaSigner,
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    blockhash: Hash,
) -> Result<String, Error> {
    let message = Message::new_with_blockhash(instructions, Some(fee_payer), &blockhash);
    let mut tx = Transaction::new_unsigned(message);
    signer
        .sign_transaction(&mut tx)
        .await
        .map_err(|e| Error::Other(format!("transaction signing failed: {e}")))?;
    let bytes = bincode::serialize(&tx)
        .map_err(|e| Error::Other(format!("transaction serialization failed: {e}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        bytes,
    ))
}

/// Wrap a payload in a `PAYMENT-SIGNATURE` envelope and base64-encode it.
pub fn encode_payment_header(
    requirements: &BatchRequirements,
    payload: BatchPayload,
) -> Result<String, Error> {
    let envelope = BatchPaymentPayload {
        x402_version: X402_VERSION_V2,
        // The server requires `accepted` to equal the requirements it priced,
        // so a payload cannot be replayed onto a differently-priced route.
        accepted: requirements.clone(),
        payload,
    };
    let json = serde_json::to_string(&envelope)
        .map_err(|e| Error::Other(format!("payment envelope serialization failed: {e}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        json.as_bytes(),
    ))
}

/// Parse a 402 `batch-settlement` challenge from a `PAYMENT-REQUIRED` header or
/// response body, returning the requirement and any corrective error code.
pub fn parse_challenge(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<(BatchRequirements, Option<String>)> {
    let from_header = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(PAYMENT_REQUIRED_HEADER))
        .and_then(|(_, value)| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).ok()
        })
        .and_then(|bytes| serde_json::from_slice::<BatchRequiredEnvelope>(&bytes).ok());
    let envelope = from_header
        .or_else(|| body.and_then(|b| serde_json::from_str::<BatchRequiredEnvelope>(b).ok()))?;
    let error = envelope.error.clone();
    let requirement = envelope
        .accepts
        .into_iter()
        .find(|r| r.scheme == BATCH_SETTLEMENT_SCHEME)?;
    Some((requirement, error))
}

/// Decode the `channelId` a challenge's corrective snapshot refers to.
pub fn corrective_channel_id(requirements: &BatchRequirements) -> Option<Pubkey> {
    let state = requirements.extra.channel_state.as_ref()?;
    Pubkey::from_str(&state.channel_id).ok()
}

/// Derive the channel PDA a configuration addresses, for callers rebuilding a
/// tracker from persisted configuration.
pub fn channel_id_for(
    config: &BatchChannelConfig,
    requirements: &BatchRequirements,
) -> Result<Pubkey, Error> {
    Ok(derive_channel_id(
        config,
        &requirements.extra.fee_payer,
        &pc::default_program_id(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::protocol::schemes::batch_settlement::{
        BatchExtra, BatchSettlementExtra, ChannelStateSnapshot, VoucherState,
    };
    use crate::x402::protocol::schemes::exact::programs;
    use async_trait::async_trait;
    use ed25519_dalek::{Signer as _, SigningKey};
    use solana_keychain::{SignTransactionResult, SignerError};
    use solana_signature::Signature;

    const PAY_TO: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

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
            tx: &mut Transaction,
        ) -> Result<SignTransactionResult, SignerError> {
            let message = tx.message.serialize();
            let signature = Signature::from(self.key.sign(&message).to_bytes());
            let index = tx
                .message
                .account_keys
                .iter()
                .position(|k| *k == self.pubkey)
                .unwrap_or(0);
            if tx.signatures.len() <= index {
                tx.signatures.resize(
                    tx.message.header.num_required_signatures as usize,
                    Signature::default(),
                );
            }
            tx.signatures[index] = signature;
            Ok(SignTransactionResult::Partial((String::new(), signature)))
        }
        async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
            Ok(Signature::from(self.key.sign(message).to_bytes()))
        }
        async fn is_available(&self) -> bool {
            true
        }
    }

    fn requirements(fee_payer: &Pubkey) -> BatchRequirements {
        BatchRequirements {
            scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
            network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
            amount: "1000".to_string(),
            asset: MINT.to_string(),
            pay_to: PAY_TO.to_string(),
            max_timeout_seconds: 300,
            extra: BatchExtra {
                payment_flow: None,
                fee_payer: pc::pubkey_string(fee_payer),
                receiver_authorizer: None,
                withdraw_delay: 3600,
                token_program: programs::TOKEN_PROGRAM.to_string(),
                memo: Some("invoice-1".to_string()),
                recent_blockhash: None,
                recent_slot: Some(341_000_000),
                channel_state: None,
                voucher_state: None,
            },
        }
    }

    fn resolve(requirements: &BatchRequirements) -> BatchTerms {
        resolve_terms_with_token_program(
            requirements,
            pc::parse_pubkey(programs::TOKEN_PROGRAM).unwrap(),
        )
        .expect("terms resolve")
    }

    #[test]
    fn terms_reject_a_token_program_the_mint_does_not_own() {
        let fee_payer = Pubkey::new_unique();
        let requirements = requirements(&fee_payer);
        let err = resolve_terms_with_token_program(
            &requirements,
            pc::parse_pubkey(programs::TOKEN_2022_PROGRAM).unwrap(),
        )
        .unwrap_err();
        assert!(err.to_string().contains(codes::INVALID_TOKEN_PROGRAM));
    }

    #[test]
    fn terms_supply_a_hex_nonce_when_the_seller_declares_no_memo() {
        let fee_payer = Pubkey::new_unique();
        let mut requirements = requirements(&fee_payer);
        requirements.extra.memo = None;
        let terms = resolve(&requirements);
        assert_eq!(terms.memo.len(), MEMO_NONCE_BYTES * 2);
        assert!(terms.memo.bytes().all(|b| b.is_ascii_hexdigit()));
        // And a declared memo is passed through verbatim.
        let requirements = self::requirements(&fee_payer);
        assert_eq!(resolve(&requirements).memo, "invoice-1");
    }

    #[tokio::test]
    async fn deposit_builds_a_sponsored_open_the_server_policy_accepts() {
        use crate::x402::protocol::schemes::batch_settlement::{
            validate_setup_transaction, SetupForm, TransactionExpectations,
        };

        let signer = TestSigner::new(5);
        let fee_payer = Pubkey::new_unique();
        let requirements = requirements(&fee_payer);
        let terms = resolve(&requirements);
        let (channel, payload) = build_deposit(
            &signer,
            &requirements,
            &terms,
            100_000,
            Hash::new_unique(),
            341_000_000,
        )
        .await
        .expect("deposit builds");

        let BatchPayload::Deposit {
            channel_config,
            voucher,
            deposit,
        } = &payload
        else {
            panic!("expected a deposit payload");
        };
        assert_eq!(voucher.max_claimable_amount, "1000");
        assert_eq!(voucher.expires_at, 0);
        assert_eq!(deposit.amount, "100000");
        // The tracker does not advance on send: only a confirmed response moves
        // the watermark.
        assert_eq!(channel.charged_cumulative_amount(), 0);

        // The transaction the client produced must satisfy the server's own
        // sponsor policy — this is the client/server contract in one assertion.
        let program_id = pc::default_program_id();
        let expectations = TransactionExpectations {
            program_id: &program_id,
            fee_payer: &fee_payer,
            config: channel_config,
            channel_id: channel.channel_id(),
            token_program: &terms.token_program,
            receiver: &terms.receiver,
            memo: Some("invoice-1"),
        };
        validate_setup_transaction(
            &deposit.transaction,
            SetupForm::Open,
            &expectations,
            100_000,
            Some(341_000_000),
        )
        .expect("client open passes the sponsor policy");
    }

    #[tokio::test]
    async fn top_up_and_refund_pass_the_sponsor_policy() {
        use crate::x402::protocol::schemes::batch_settlement::{
            validate_request_close_transaction, validate_setup_transaction, SetupForm,
            TransactionExpectations,
        };

        let signer = TestSigner::new(6);
        let fee_payer = Pubkey::new_unique();
        let requirements = requirements(&fee_payer);
        let terms = resolve(&requirements);
        let (mut channel, _) = build_deposit(
            &signer,
            &requirements,
            &terms,
            1_000,
            Hash::new_unique(),
            341_000_000,
        )
        .await
        .unwrap();
        channel.charged_cumulative_amount = 1_000;

        let program_id = pc::default_program_id();
        let expectations = TransactionExpectations {
            program_id: &program_id,
            fee_payer: &fee_payer,
            config: channel.config(),
            channel_id: channel.channel_id(),
            token_program: &terms.token_program,
            receiver: &terms.receiver,
            memo: Some("invoice-1"),
        };

        let top_up = build_top_up(&signer, &channel, &terms, 50_000, Hash::new_unique())
            .await
            .unwrap();
        let BatchPayload::Deposit {
            deposit, voucher, ..
        } = &top_up
        else {
            panic!("expected a deposit payload");
        };
        assert_eq!(voucher.max_claimable_amount, "2000");
        validate_setup_transaction(
            &deposit.transaction,
            SetupForm::TopUp,
            &expectations,
            50_000,
            None,
        )
        .expect("client top_up passes the sponsor policy");

        let refund = build_refund(&signer, &channel, &terms, Hash::new_unique())
            .await
            .unwrap();
        let BatchPayload::Refund {
            transaction,
            voucher,
            close_authorization,
            ..
        } = &refund
        else {
            panic!("expected a refund payload");
        };
        // The interoperable close carries neither a voucher nor an
        // authorization: it needs no server cooperation.
        assert!(voucher.is_none());
        assert!(close_authorization.is_none());
        validate_request_close_transaction(transaction, &expectations)
            .expect("client request_close passes the sponsor policy");
    }

    #[tokio::test]
    async fn the_watermark_advances_only_on_a_matching_payment_response() {
        let signer = TestSigner::new(7);
        let fee_payer = Pubkey::new_unique();
        let requirements = requirements(&fee_payer);
        let terms = resolve(&requirements);
        let (mut channel, _) = build_deposit(
            &signer,
            &requirements,
            &terms,
            100_000,
            Hash::new_unique(),
            341_000_000,
        )
        .await
        .unwrap();

        let voucher = channel.sign_next_voucher(&signer, 1_000).await.unwrap();
        let channel_b58 = pc::pubkey_string(channel.channel_id());
        let ok = |commitment: &str, charged: &str, cumulative: &str| BatchSettlementResponse {
            success: true,
            error_reason: None,
            payer: None,
            transaction: String::new(),
            network: requirements.network.clone(),
            amount: String::new(),
            extra: Some(BatchSettlementExtra {
                commitment_id: Some(commitment.to_string()),
                charged_amount: Some(charged.to_string()),
                channel_state: Some(ChannelStateSnapshot {
                    channel_id: channel_b58.clone(),
                    balance: "100000".to_string(),
                    total_claimed: "0".to_string(),
                    withdraw_requested_at: 0,
                    charged_cumulative_amount: Some(cumulative.to_string()),
                }),
            }),
        };

        // A response confirming a different commitment must not advance state.
        let wrong = ok("someoneelse:1000", "1000", "1000");
        assert!(channel
            .apply_payment_response(&wrong, &requirements, &voucher)
            .is_err());
        assert_eq!(channel.charged_cumulative_amount(), 0);

        // Nor one that charged more than the advertised price.
        let overcharged = ok(&voucher.commitment_id(), "2000", "1000");
        assert!(channel
            .apply_payment_response(&overcharged, &requirements, &voucher)
            .is_err());
        assert_eq!(channel.charged_cumulative_amount(), 0);

        let good = ok(&voucher.commitment_id(), "1000", "1000");
        channel
            .apply_payment_response(&good, &requirements, &voucher)
            .expect("matching response is adopted");
        assert_eq!(channel.charged_cumulative_amount(), 1_000);
        assert_eq!(channel.deposit(), 100_000);
        assert!(channel.can_cover(99_000));
        assert!(!channel.can_cover(99_001));
    }

    #[tokio::test]
    async fn corrective_state_is_adopted_only_with_a_self_signed_proof() {
        let signer = TestSigner::new(8);
        let fee_payer = Pubkey::new_unique();
        let base = requirements(&fee_payer);
        let terms = resolve(&base);
        let (mut channel, _) = build_deposit(
            &signer,
            &base,
            &terms,
            100_000,
            Hash::new_unique(),
            341_000_000,
        )
        .await
        .unwrap();
        let channel_b58 = pc::pubkey_string(channel.channel_id());

        let mut corrective = base.clone();
        corrective.extra.channel_state = Some(ChannelStateSnapshot {
            channel_id: channel_b58.clone(),
            balance: "100000".to_string(),
            total_claimed: "0".to_string(),
            withdraw_requested_at: 0,
            charged_cumulative_amount: Some("3000".to_string()),
        });

        // Without a proof there is nothing to adopt.
        assert!(channel.adopt_corrective_state(&corrective).is_err());
        assert_eq!(channel.charged_cumulative_amount(), 0);

        // A proof signed by someone else is not this client's authorization.
        let stranger = TestSigner::new(9);
        let forged = sign_voucher(&stranger, channel.channel_id(), 3_000)
            .await
            .unwrap();
        corrective.extra.voucher_state = Some(VoucherState {
            signed_max_claimable: "3000".to_string(),
            expires_at: 0,
            signature: forged.signature,
        });
        assert!(channel.adopt_corrective_state(&corrective).is_err());
        assert_eq!(channel.charged_cumulative_amount(), 0);

        // The client's own signature at that amount is proof it authorized it.
        let proof = sign_voucher(&signer, channel.channel_id(), 3_000)
            .await
            .unwrap();
        corrective.extra.voucher_state = Some(VoucherState {
            signed_max_claimable: "3000".to_string(),
            expires_at: 0,
            signature: proof.signature,
        });
        assert_eq!(channel.adopt_corrective_state(&corrective).unwrap(), 3_000);
        assert_eq!(channel.charged_cumulative_amount(), 3_000);
    }

    #[test]
    fn challenge_parsing_surfaces_the_corrective_error_code() {
        let fee_payer = Pubkey::new_unique();
        let envelope = BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: None,
            accepts: vec![requirements(&fee_payer)],
            error: Some(codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH.to_string()),
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let value =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes());
        let headers = vec![(PAYMENT_REQUIRED_HEADER.to_string(), value)];
        let (requirement, error) = parse_challenge(&headers, None).unwrap();
        assert_eq!(requirement.amount, "1000");
        assert_eq!(
            error.as_deref(),
            Some(codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH)
        );
        assert!(parse_challenge(&[], None).is_none());
    }

    #[tokio::test]
    async fn payment_header_round_trips_through_the_server_envelope() {
        let signer = TestSigner::new(11);
        let fee_payer = Pubkey::new_unique();
        let requirements = requirements(&fee_payer);
        let terms = resolve(&requirements);
        let (channel, _) = build_deposit(
            &signer,
            &requirements,
            &terms,
            100_000,
            Hash::new_unique(),
            341_000_000,
        )
        .await
        .unwrap();
        let payload = channel.voucher_payload(&signer, 1_000).await.unwrap();
        let header = encode_payment_header(&requirements, payload).unwrap();
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &header).unwrap();
        let envelope: BatchPaymentPayload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(envelope.x402_version, X402_VERSION_V2);
        assert_eq!(envelope.accepted.amount, "1000");
        assert_eq!(envelope.payload.type_name(), "voucher");
    }
}
