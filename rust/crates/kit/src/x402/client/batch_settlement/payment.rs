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

use std::collections::HashMap;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keychain::{SolanaSigner, TransactionSigner};
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;

use crate::core::payment_channels as pc;

use crate::x402::error::Error;
use crate::x402::protocol::schemes::batch_settlement::{
    check_corrective_voucher_state, check_token_program, check_voucher, check_withdraw_delay,
    derive_channel_id, errors as codes, BatchAuthorization, BatchChannelConfig, BatchDeposit,
    BatchError, BatchPayload, BatchPaymentPayload, BatchRequiredEnvelope, BatchRequirements,
    BatchSettlementResponse, BatchVoucher, BATCH_SETTLEMENT_SCHEME, VOUCHER_EXPIRES_AT,
};
use crate::x402::{PAYMENT_REQUIRED_HEADER, X402_VERSION_V2};

/// Minimum random Memo nonce, in bytes, before hex encoding.
const MEMO_NONCE_BYTES: usize = 16;

/// Domain separator for the payer proof used by server-signed channels.
const AUTHORIZATION_DOMAIN: &[u8] = b"x402-batch-authorization-v2";

/// Prefix of the payer-signed Memo that binds an open channel to the server's
/// receiver authorizer.
const RECEIVER_BINDING_MEMO_PREFIX: &str = "x402:batch-settlement:svm:rcvauth:v1:";

/// Explicit, local trust grants for server-signed channels.
///
/// In server mode the operator becomes the channel's onchain
/// `authorized_signer` and can claim up to the full deposit. A 402 response is
/// therefore never sufficient authority by itself: callers must allowlist the
/// exact operator and bound the total escrow it may control.
#[derive(Debug, Clone, Default)]
pub struct ServerSignedChannelsPolicy {
    operators: HashMap<Pubkey, u64>,
}

impl ServerSignedChannelsPolicy {
    /// Create an empty policy, which trusts no server-signed operator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `operator` up to `max_deposit` atomic units per channel.
    pub fn allow_operator(mut self, operator: Pubkey, max_deposit: u64) -> Result<Self, Error> {
        if max_deposit == 0 {
            return Err(Error::Other(
                "server-signed max_deposit must be positive".into(),
            ));
        }
        self.operators.insert(operator, max_deposit);
        Ok(self)
    }

    fn max_deposit_for(&self, operator: &Pubkey) -> Option<u64> {
        self.operators.get(operator).copied()
    }
}

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
    /// Memo for follow-up transactions. Receiver binding is open-only; a
    /// top-up or refund carries the seller memo, or a fresh correlation nonce
    /// when the seller did not declare one.
    pub continuation_memo: String,
    /// The message version to build: the highest the sponsor advertises in
    /// `extra.transactionVersions` (`0` when it advertises none).
    pub tx_version: crate::core::tx::TxVersion,
    /// Resource operator holding voucher authority in server mode.
    pub operator: Option<Pubkey>,
    /// Maximum total escrow locally granted to `operator`.
    pub server_signed_max_deposit: Option<u64>,
    /// Lifetime of a single-use server-mode payer authorization.
    pub authorization_ttl_seconds: u64,
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
    max_tx_version: Option<crate::core::tx::TxVersion>,
) -> Result<BatchTerms, Error> {
    resolve_terms_with_token_program_and_policy(requirements, token_program, max_tx_version, None)
}

/// Validate challenge terms with an optional, locally configured grant for
/// server-signed channels.
pub fn resolve_terms_with_token_program_and_policy(
    requirements: &BatchRequirements,
    token_program: Pubkey,
    max_tx_version: Option<crate::core::tx::TxVersion>,
    server_signed_policy: Option<&ServerSignedChannelsPolicy>,
) -> Result<BatchTerms, Error> {
    let extra = &requirements.extra;
    crate::x402::protocol::schemes::batch_settlement::check_payment_flow(
        extra.payment_flow.as_deref(),
    )?;
    let (operator, server_signed_max_deposit) = match extra.voucher_signer.as_deref() {
        None | Some("client") => {
            if extra.operator.is_some() {
                return Err(Error::Other(
                    "extra.operator is only valid when extra.voucherSigner is \"server\"".into(),
                ));
            }
            (None, None)
        }
        Some("server") => {
            let operator_text = extra.operator.as_deref().ok_or_else(|| {
                Error::Other(
                    "extra.operator is required when extra.voucherSigner is \"server\"".into(),
                )
            })?;
            let operator = pc::parse_pubkey(operator_text)?;
            let max_deposit = server_signed_policy
                .and_then(|policy| policy.max_deposit_for(&operator))
                .ok_or_else(|| {
                    Error::Other(format!(
                        "server-signed batch operator {operator_text} is not trusted; add an \
                         explicit local operator grant with a maximum deposit"
                    ))
                })?;
            (Some(operator), Some(max_deposit))
        }
        Some(other) => {
            return Err(Error::Other(format!(
                "extra.voucherSigner must be \"client\" or \"server\", got {other:?}"
            )))
        }
    };
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
    // sponsor requires a random hex nonce. Receiver binding is a separate,
    // open-only commitment and must not replace that nonce on later top-ups.
    let continuation_memo = extra.memo.clone().unwrap_or_else(random_hex_nonce);
    let memo = match (operator, extra.receiver_authorizer.as_deref()) {
        (Some(_), Some(receiver_authorizer)) => {
            format!("{RECEIVER_BINDING_MEMO_PREFIX}{receiver_authorizer}")
        }
        _ => continuation_memo.clone(),
    };
    Ok(BatchTerms {
        fee_payer,
        mint,
        token_program,
        receiver,
        withdraw_delay: extra.withdraw_delay,
        amount: requirements.amount()?,
        memo,
        continuation_memo,
        tx_version: crate::core::tx::negotiate(
            extra.transaction_versions.as_deref(),
            max_tx_version,
        )?,
        operator,
        server_signed_max_deposit,
        authorization_ttl_seconds: requirements.max_timeout_seconds.max(1),
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
    max_tx_version: Option<crate::core::tx::TxVersion>,
) -> Result<BatchTerms, Error> {
    resolve_terms_with_policy(rpc, requirements, max_tx_version, None)
}

/// Resolve challenge terms, including an explicit server-signed trust policy.
pub fn resolve_terms_with_policy(
    rpc: &RpcClient,
    requirements: &BatchRequirements,
    max_tx_version: Option<crate::core::tx::TxVersion>,
    server_signed_policy: Option<&ServerSignedChannelsPolicy>,
) -> Result<BatchTerms, Error> {
    let mint = pc::parse_pubkey(&requirements.asset)?;
    let account = rpc
        .get_account(&mint)
        .map_err(|e| Error::Rpc(format!("mint fetch failed: {e}")))?;
    resolve_terms_with_token_program_and_policy(
        requirements,
        pc::from_address(&account.owner),
        max_tx_version,
        server_signed_policy,
    )
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
    /// Whether `charged_cumulative_amount` includes every offchain charge.
    /// Chain recovery initially knows only the settled watermark.
    history_complete: bool,
}

/// Discover the newest compatible open channel owned by `payer`.
///
/// Channel state is recoverable from the chain after a client restart. Every
/// candidate is filtered by payer and then fully rebound to the current offer,
/// including its PDA and distribution commitment, before it is adopted.
pub fn discover_channel(
    rpc: &RpcClient,
    payer: &Pubkey,
    requirements: &BatchRequirements,
    terms: &BatchTerms,
) -> Result<Option<BatchChannel>, Error> {
    use solana_account_decoder_client_types::UiAccountEncoding;
    use solana_rpc_client_api::config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
    use solana_rpc_client_api::filter::{Memcmp, RpcFilterType};
    use solana_rpc_client_api::request::RpcRequest;
    use solana_rpc_client_api::response::RpcKeyedAccount;

    let program_id = pc::default_program_id();
    let config = RpcProgramAccountsConfig {
        filters: Some(vec![
            RpcFilterType::DataSize(pc::CHANNEL_ACCOUNT_SIZE as u64),
            RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                pc::CHANNEL_PAYER_OFFSET,
                payer.to_bytes().to_vec(),
            )),
        ]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            ..Default::default()
        },
        ..Default::default()
    };
    let params = serde_json::json!([program_id.to_string(), config]);
    let keyed: Vec<RpcKeyedAccount> = rpc
        .send(RpcRequest::GetProgramAccounts, params)
        .map_err(|e| Error::Rpc(format!("batch channel discovery failed: {e}")))?;
    let authorized_signer = terms.operator.unwrap_or(*payer);
    let expected_distribution = pc::distribution_hash(&pc::sole_recipient(&terms.receiver));
    let mut newest = None;

    for entry in keyed {
        let Ok(address) = Pubkey::from_str(&entry.pubkey) else {
            continue;
        };
        let Some(data) = entry.account.data.decode() else {
            continue;
        };
        let Ok(channel) = pc::generated::accounts::Channel::from_bytes(&data) else {
            continue;
        };
        if channel.status != 0
            || channel.closure_started_at != 0
            || pc::from_address(&channel.payer) != *payer
            || pc::from_address(&channel.payee) != terms.fee_payer
            || pc::from_address(&channel.rent_payer) != terms.fee_payer
            || pc::from_address(&channel.mint) != terms.mint
            || pc::from_address(&channel.authorized_signer) != authorized_signer
            || channel.grace_period != terms.withdraw_delay
            || channel.distribution_hash != expected_distribution
        {
            continue;
        }
        let (derived, _) = pc::find_channel_pda(
            payer,
            &terms.fee_payer,
            &terms.mint,
            &authorized_signer,
            channel.salt,
            channel.open_slot,
            &program_id,
        );
        if derived != address {
            continue;
        }
        if newest
            .as_ref()
            .is_some_and(|(_, open_slot, _): &(Pubkey, u64, BatchChannel)| {
                *open_slot >= channel.open_slot
            })
        {
            continue;
        }
        let channel_config = BatchChannelConfig {
            payer: pc::pubkey_string(payer),
            payer_authorizer: pc::pubkey_string(&authorized_signer),
            receiver: requirements.pay_to.clone(),
            receiver_authorizer: requirements.extra.receiver_authorizer.clone(),
            token: requirements.asset.clone(),
            withdraw_delay: terms.withdraw_delay,
            salt: channel.salt.to_string(),
            open_slot: channel.open_slot,
            voucher_signer: terms.operator.map(|_| "server".to_string()),
        };
        newest = Some((
            address,
            channel.open_slot,
            BatchChannel::recovered(
                address,
                channel_config,
                channel.settlement.settled,
                channel.deposit,
            ),
        ));
    }
    Ok(newest.map(|(_, _, channel)| channel))
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
            history_complete: true,
        }
    }

    fn recovered(
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
            history_complete: false,
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

    /// Build a single-use payer proof for a server-signed channel.
    pub async fn authorization_payload(
        &self,
        signer: &dyn SolanaSigner,
        amount: u64,
        expires_at: i64,
    ) -> Result<BatchPayload, Error> {
        if self.config.voucher_signer.as_deref() != Some("server") {
            return Err(Error::Other(
                "client-signed channels do not use payer authorizations".into(),
            ));
        }
        Ok(BatchPayload::Authorization {
            channel_config: self.config.clone(),
            authorization: sign_authorization(
                signer,
                &self.channel_id,
                &pc::parse_pubkey(&self.config.payer_authorizer)?,
                &random_hex_nonce(),
                amount,
                expires_at,
            )
            .await?,
        })
    }

    /// Adopt the server's confirmed state from a successful `PAYMENT-RESPONSE`.
    ///
    /// The response must confirm the exact commitment that was sent: a
    /// non-empty commitment identifier, a cumulative equal to the voucher this
    /// client signed, and a charge equal to the advertised price. A response
    /// that confirms something else is not evidence this request was the one
    /// that landed, and adopting it would silently skew the watermark.
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
        // The commitment identifier is opaque to the client: the spec requires
        // only that it be non-empty (§4.4). What the response confirms is
        // checked below against the cumulative this client actually signed.
        if extra
            .commitment_id
            .as_deref()
            .is_none_or(|id| id.is_empty())
        {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                "PAYMENT-RESPONSE carries no commitmentId",
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

    /// Adopt a metered response for a server-signed request.
    ///
    /// The operator chooses the actual charge after serving, but it must stay
    /// within this request's payer-signed ceiling and advance the confirmed
    /// cumulative watermark by exactly that amount.
    pub fn apply_authorization_response(
        &mut self,
        response: &BatchSettlementResponse,
        authorization: &BatchAuthorization,
    ) -> Result<(), Error> {
        self.apply_authorization_response_with_deposit(response, authorization, None)
    }

    /// Adopt a server-signed response and an optional client-proven escrow
    /// ceiling.
    ///
    /// `confirmed_deposit` is the total deposit after a successful `deposit`
    /// payload, as derived from the transaction the payer signed. The server's
    /// `channelState.balance` is only advisory and may be omitted, so it must
    /// not decide whether the next request needs another top-up.
    pub fn apply_authorization_response_with_deposit(
        &mut self,
        response: &BatchSettlementResponse,
        authorization: &BatchAuthorization,
        confirmed_deposit: Option<u64>,
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
        if authorization.channel_id != pc::pubkey_string(&self.channel_id)
            || authorization.payer != self.config.payer
        {
            return Err(batch_err(
                codes::INVALID_CHANNEL_ID_MISMATCH,
                "PAYMENT-RESPONSE does not correspond to the submitted authorization",
            ));
        }
        let authorized = authorization
            .authorized_amount
            .parse::<u64>()
            .map_err(|_| batch_err(codes::INVALID_CHANNEL_STATE, "invalid authorizedAmount"))?;
        let extra = response.extra.as_ref().ok_or_else(|| {
            batch_err(
                codes::INVALID_CHANNEL_STATE,
                "PAYMENT-RESPONSE has no extra",
            )
        })?;
        if extra
            .commitment_id
            .as_deref()
            .is_none_or(|id| id.is_empty())
        {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                "PAYMENT-RESPONSE carries no commitmentId",
            ));
        }
        let voucher = extra.voucher.as_ref().ok_or_else(|| {
            batch_err(
                codes::INVALID_VOUCHER_SIGNATURE,
                "server-signed PAYMENT-RESPONSE carries no voucher",
            )
        })?;
        let cumulative = check_voucher(voucher, &self.config, &self.channel_id)?;
        if cumulative < self.charged_cumulative_amount {
            return Err(batch_err(
                codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                format!(
                    "server voucher cumulative {cumulative} is below local cumulative {}",
                    self.charged_cumulative_amount
                ),
            ));
        }
        let charged = extra
            .charged_amount
            .as_deref()
            .ok_or_else(|| {
                batch_err(
                    codes::INVALID_CHANNEL_STATE,
                    "PAYMENT-RESPONSE has no chargedAmount",
                )
            })?
            .parse::<u64>()
            .map_err(|_| batch_err(codes::INVALID_CHANNEL_STATE, "invalid chargedAmount"))?;
        let cumulative_delta = cumulative - self.charged_cumulative_amount;
        if self.history_complete && cumulative_delta != charged {
            return Err(batch_err(
                codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                format!(
                    "server voucher advanced by {cumulative_delta}, but chargedAmount is {charged}"
                ),
            ));
        }
        if charged > authorized {
            return Err(batch_err(
                codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                format!("server charged {charged}, above authorized ceiling {authorized}"),
            ));
        }
        if let Some(reported) = extra
            .channel_state
            .as_ref()
            .and_then(|state| state.charged_cumulative_amount.as_deref())
        {
            let reported = reported.parse::<u64>().map_err(|_| {
                batch_err(
                    codes::INVALID_CHANNEL_STATE,
                    "invalid chargedCumulativeAmount",
                )
            })?;
            if reported != cumulative {
                return Err(batch_err(
                    codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                    format!(
                        "server reported cumulative {reported}, signed voucher confirms {cumulative}"
                    ),
                ));
            }
        }
        let deposit = confirmed_deposit.unwrap_or(self.deposit);
        if cumulative > deposit {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                format!("server voucher cumulative {cumulative} exceeds escrow ceiling {deposit}"),
            ));
        }
        if confirmed_deposit.is_some() {
            if deposit < self.deposit {
                return Err(batch_err(
                    codes::INVALID_CHANNEL_STATE,
                    "confirmed deposit is below the current escrow ceiling",
                ));
            }
            self.deposit = deposit;
        }
        self.charged_cumulative_amount = cumulative;
        self.history_complete = true;
        Ok(())
    }

    /// Resynchronize from a corrective 402 after a cumulative-amount mismatch.
    ///
    /// The server's snapshot is adopted only against a voucher the channel's
    /// `payerAuthorizer` signed at that amount. The snapshot cannot change the
    /// locally or onchain-confirmed deposit ceiling. When the server holds no
    /// voucher, there is nothing to prove and nothing to adopt; the caller must
    /// resynchronize from onchain state.
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
        if adopted > self.deposit {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                format!(
                    "corrective cumulative {adopted} exceeds local escrow ceiling {}",
                    self.deposit
                ),
            ));
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
        signature: crate::core::base58::encode_64(&signature),
    })
}

/// Encode the canonical server-mode payer proof message.
pub fn authorization_message_bytes(
    channel_id: &Pubkey,
    payer: &Pubkey,
    operator: &Pubkey,
    request_id: &str,
    authorized_amount: u64,
    expires_at: i64,
) -> Result<Vec<u8>, Error> {
    let request_id = request_id.as_bytes();
    if request_id.is_empty() || request_id.len() > 256 {
        return Err(Error::Other(
            "batch authorization requestId must encode to 1 through 256 bytes".into(),
        ));
    }
    if expires_at <= 0 {
        return Err(Error::Other(
            "batch authorization expiresAt must be positive".into(),
        ));
    }
    let request_len = u16::try_from(request_id.len())
        .map_err(|_| Error::Other("batch authorization requestId is too long".into()))?;
    let mut message = Vec::with_capacity(AUTHORIZATION_DOMAIN.len() + 114 + request_id.len());
    message.extend_from_slice(AUTHORIZATION_DOMAIN);
    message.extend_from_slice(channel_id.as_ref());
    message.extend_from_slice(payer.as_ref());
    message.extend_from_slice(operator.as_ref());
    message.extend_from_slice(&request_len.to_le_bytes());
    message.extend_from_slice(request_id);
    message.extend_from_slice(&authorized_amount.to_le_bytes());
    message.extend_from_slice(&expires_at.to_le_bytes());
    Ok(message)
}

/// Sign an expiring, single-request payer proof for `operator`.
pub async fn sign_authorization(
    signer: &dyn SolanaSigner,
    channel_id: &Pubkey,
    operator: &Pubkey,
    request_id: &str,
    authorized_amount: u64,
    expires_at: i64,
) -> Result<BatchAuthorization, Error> {
    let payer = signer.pubkey();
    let message = authorization_message_bytes(
        channel_id,
        &payer,
        operator,
        request_id,
        authorized_amount,
        expires_at,
    )?;
    let signature: [u8; 64] = signer
        .sign_message(&message)
        .await
        .map_err(|e| Error::Other(format!("batch authorization signing failed: {e}")))?
        .into();
    Ok(BatchAuthorization {
        kind: "proof".to_string(),
        channel_id: pc::pubkey_string(channel_id),
        payer: pc::pubkey_string(&payer),
        request_id: request_id.to_string(),
        authorized_amount: authorized_amount.to_string(),
        expires_at,
        signature: crate::core::base58::encode_64(&signature),
    })
}

fn authorization_expires_at(ttl_seconds: u64) -> Result<i64, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Other(format!("system clock is before Unix epoch: {e}")))?
        .as_secs();
    let expires = now
        .checked_add(ttl_seconds.max(1))
        .ok_or_else(|| Error::Other("batch authorization expiry overflow".into()))?;
    i64::try_from(expires)
        .map_err(|_| Error::Other("batch authorization expiry exceeds i64".into()))
}

/// Build the first `deposit` payload: a channel `open` plus the first voucher.
///
/// The payer key doubles as the `payerAuthorizer`. The sponsor is the
/// transaction fee payer and the channel `rent_payer`, so the client's own SOL
/// is never spent.
pub async fn build_deposit(
    signer: &dyn TransactionSigner,
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
    if let Some(max_deposit) = terms.server_signed_max_deposit {
        if deposit_amount > max_deposit {
            return Err(Error::Other(format!(
                "deposit {deposit_amount} exceeds server-signed operator grant {max_deposit}"
            )));
        }
    }
    let payer = signer.pubkey();
    if payer == terms.fee_payer {
        return Err(batch_err(
            codes::INVALID_FEE_PAYER_MISMATCH,
            "the channel payer must not be the sponsor",
        ));
    }
    let payer_authorizer = terms.operator.unwrap_or(payer);
    if payer_authorizer == terms.fee_payer {
        return Err(batch_err(
            codes::INVALID_FEE_PAYER_MISMATCH,
            "the channel voucher signer must not be the sponsor",
        ));
    }
    let salt = pc::random_salt();
    let open = pc::build_open_payment_channel_tx_with_options(
        signer,
        // The sponsor holds the zero-share payee seat; 100% of settled funds go
        // to `payTo` through the single explicit distribution entry below.
        &terms.fee_payer,
        &terms.mint,
        &payer_authorizer,
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
            version: terms.tx_version,
            ..Default::default()
        },
    )
    .await?;

    let config = BatchChannelConfig {
        payer: pc::pubkey_string(&payer),
        payer_authorizer: pc::pubkey_string(&payer_authorizer),
        receiver: requirements.pay_to.clone(),
        receiver_authorizer: requirements.extra.receiver_authorizer.clone(),
        token: requirements.asset.clone(),
        withdraw_delay: terms.withdraw_delay,
        salt: salt.to_string(),
        open_slot,
        voucher_signer: terms.operator.map(|_| "server".to_string()),
    };
    let (voucher, authorization) = if let Some(operator) = terms.operator {
        (
            None,
            Some(
                sign_authorization(
                    signer,
                    &open.channel_id,
                    &operator,
                    &random_hex_nonce(),
                    terms.amount,
                    authorization_expires_at(terms.authorization_ttl_seconds)?,
                )
                .await?,
            ),
        )
    } else {
        (
            Some(sign_voucher(signer, &open.channel_id, terms.amount).await?),
            None,
        )
    };
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
            authorization,
        },
    ))
}

/// Build a `deposit` payload that tops up an existing channel and authorizes
/// this request. Used when the next voucher would exceed the escrowed deposit.
pub async fn build_top_up(
    signer: &dyn TransactionSigner,
    channel: &BatchChannel,
    terms: &BatchTerms,
    top_up_amount: u64,
    blockhash: Hash,
) -> Result<BatchPayload, Error> {
    if let Some(max_deposit) = terms.server_signed_max_deposit {
        let total = channel
            .deposit
            .checked_add(top_up_amount)
            .ok_or_else(|| Error::Other("server-signed channel deposit overflow".into()))?;
        if total > max_deposit {
            return Err(Error::Other(format!(
                "top-up would raise server-signed escrow to {total}, above operator grant {max_deposit}"
            )));
        }
    }
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
        memo_instruction(&terms.continuation_memo),
    ];
    let transaction = sign_sponsored(
        signer,
        terms.tx_version,
        &terms.fee_payer,
        &instructions,
        blockhash,
    )
    .await?;
    let (voucher, authorization) = if let Some(operator) = terms.operator {
        (
            None,
            Some(
                sign_authorization(
                    signer,
                    &channel.channel_id,
                    &operator,
                    &random_hex_nonce(),
                    terms.amount,
                    authorization_expires_at(terms.authorization_ttl_seconds)?,
                )
                .await?,
            ),
        )
    } else {
        (
            Some(channel.sign_next_voucher(signer, terms.amount).await?),
            None,
        )
    };
    Ok(BatchPayload::Deposit {
        channel_config: channel.config.clone(),
        voucher,
        deposit: BatchDeposit {
            amount: top_up_amount.to_string(),
            transaction,
        },
        authorization,
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
    signer: &dyn TransactionSigner,
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
        memo_instruction(&terms.continuation_memo),
    ];
    Ok(BatchPayload::Refund {
        channel_config: channel.config.clone(),
        transaction: sign_sponsored(
            signer,
            terms.tx_version,
            &terms.fee_payer,
            &instructions,
            blockhash,
        )
        .await?,
        voucher: None,
        close_authorization: None,
        amount: None,
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
    signer: &dyn TransactionSigner,
    version: crate::core::tx::TxVersion,
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    blockhash: Hash,
) -> Result<String, Error> {
    let mut tx =
        crate::core::tx::build_unsigned(version, fee_payer, instructions, blockhash, None)?;
    crate::core::signing::sign_versioned_transaction_slot(signer, &mut tx)
        .await
        .map_err(|e| Error::Other(format!("transaction signing failed: {e}")))?;
    Ok(crate::core::tx::encode(&tx)?)
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
    parse_challenge_with_policy(headers, body, None)
}

/// Parse a challenge, preferring server-signed terms only when their operator
/// has an explicit local trust grant. Untrusted server-mode offers are dropped
/// so a client-signed offer for the same resource can be selected instead.
pub fn parse_challenge_with_policy(
    headers: &[(String, String)],
    body: Option<&str>,
    server_signed_policy: Option<&ServerSignedChannelsPolicy>,
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
    let accepts: Vec<_> = envelope
        .accepts
        .into_iter()
        .filter(|r| r.scheme == BATCH_SETTLEMENT_SCHEME)
        .collect();
    let trusted_server = accepts.iter().find(|requirements| {
        if requirements.extra.voucher_signer.as_deref() != Some("server") {
            return false;
        }
        let Some(operator) = requirements
            .extra
            .operator
            .as_deref()
            .and_then(|value| Pubkey::from_str(value).ok())
        else {
            return false;
        };
        server_signed_policy
            .and_then(|policy| policy.max_deposit_for(&operator))
            .is_some()
    });
    let client_signed = accepts.iter().find(|requirements| {
        matches!(
            requirements.extra.voucher_signer.as_deref(),
            None | Some("client")
        ) && requirements.extra.operator.is_none()
    });
    let requirement = trusted_server.or(client_signed)?.clone();
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
    use solana_keychain::{SignTransactionResult, SignerError, SolanaSigner};
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
        async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
            Ok(Signature::from(self.key.sign(message).to_bytes()))
        }
        async fn is_available(&self) -> bool {
            true
        }
    }

    #[async_trait]
    impl TransactionSigner for TestSigner {
        async fn sign_transaction(
            &self,
            tx: &mut solana_transaction::versioned::VersionedTransaction,
        ) -> Result<SignTransactionResult, SignerError> {
            let message = tx.message.serialize();
            let signature = Signature::from(self.key.sign(&message).to_bytes());
            let index = tx
                .message
                .static_account_keys()
                .iter()
                .position(|k| *k == self.pubkey)
                .unwrap_or(0);
            let required = tx.message.header().num_required_signatures as usize;
            if tx.signatures.len() <= index {
                tx.signatures.resize(required, Signature::default());
            }
            tx.signatures[index] = signature;
            Ok(SignTransactionResult::Partial((String::new(), signature)))
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
                min_deposit: None,
                channel_state: None,
                voucher_state: None,
                transaction_versions: None,
                voucher_signer: None,
                operator: None,
                max_idle_secs: None,
            },
        }
    }

    fn resolve(requirements: &BatchRequirements) -> BatchTerms {
        resolve_terms_with_token_program(
            requirements,
            pc::parse_pubkey(programs::TOKEN_PROGRAM).unwrap(),
            None,
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
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains(codes::INVALID_TOKEN_PROGRAM));
    }

    #[test]
    fn terms_refuse_a_server_signed_accept() {
        let fee_payer = Pubkey::new_unique();
        let mut requirements = requirements(&fee_payer);
        requirements.extra.voucher_signer = Some("server".to_string());
        requirements.extra.operator = Some(pc::pubkey_string(&Pubkey::new_unique()));
        let err = resolve_terms_with_token_program(
            &requirements,
            pc::parse_pubkey(programs::TOKEN_PROGRAM).unwrap(),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("server-signed"));
        // An operator key without the mode flag is just as much a delegation.
        let mut operator_only = self::requirements(&fee_payer);
        operator_only.extra.operator = Some(pc::pubkey_string(&Pubkey::new_unique()));
        assert!(resolve_terms_with_token_program(
            &operator_only,
            pc::parse_pubkey(programs::TOKEN_PROGRAM).unwrap(),
            None,
        )
        .is_err());
    }

    #[test]
    fn challenge_parsing_skips_server_signed_accepts() {
        let fee_payer = Pubkey::new_unique();
        let mut metered = requirements(&fee_payer);
        metered.amount = "5000".to_string();
        metered.extra.voucher_signer = Some("server".to_string());
        metered.extra.operator = Some(pc::pubkey_string(&Pubkey::new_unique()));
        let mut operator_only = requirements(&fee_payer);
        operator_only.amount = "7000".to_string();
        operator_only.extra.operator = Some(pc::pubkey_string(&Pubkey::new_unique()));
        let envelope = BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: None,
            accepts: vec![metered.clone(), operator_only, requirements(&fee_payer)],
            error: None,
        };
        let body = serde_json::to_string(&envelope).unwrap();
        let (chosen, _) = parse_challenge(&[], Some(&body)).unwrap();
        assert_eq!(chosen.amount, "1000");
        assert!(chosen.extra.voucher_signer.is_none());
        assert!(chosen.extra.operator.is_none());
        // Only a server-signed accept on offer: nothing this client can pay.
        let only_metered = BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: None,
            accepts: vec![metered],
            error: None,
        };
        let body = serde_json::to_string(&only_metered).unwrap();
        assert!(parse_challenge(&[], Some(&body)).is_none());
    }

    #[test]
    fn trusted_server_signed_accept_is_preferred_and_capped() {
        let fee_payer = Pubkey::new_unique();
        let operator = Pubkey::new_unique();
        let mut metered = requirements(&fee_payer);
        metered.extra.voucher_signer = Some("server".to_string());
        metered.extra.operator = Some(pc::pubkey_string(&operator));
        metered.extra.min_deposit = Some("10000".to_string());
        let envelope = BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: None,
            accepts: vec![requirements(&fee_payer), metered.clone()],
            error: None,
        };
        let body = serde_json::to_string(&envelope).unwrap();
        let policy = ServerSignedChannelsPolicy::new()
            .allow_operator(operator, 50_000)
            .unwrap();
        let (chosen, _) = parse_challenge_with_policy(&[], Some(&body), Some(&policy)).unwrap();
        assert_eq!(chosen.extra.voucher_signer.as_deref(), Some("server"));
        let terms = resolve_terms_with_token_program_and_policy(
            &chosen,
            pc::parse_pubkey(programs::TOKEN_PROGRAM).unwrap(),
            None,
            Some(&policy),
        )
        .unwrap();
        assert_eq!(terms.operator, Some(operator));
        assert_eq!(terms.server_signed_max_deposit, Some(50_000));
        assert_eq!(chosen.extra.min_deposit.as_deref(), Some("10000"));
    }

    #[tokio::test]
    async fn server_signed_deposit_uses_operator_and_payer_proof() {
        let signer = TestSigner::new(9);
        let fee_payer = Pubkey::new_unique();
        let operator_signer = TestSigner::new(10);
        let operator = operator_signer.pubkey();
        let receiver_authorizer = Pubkey::new_unique();
        let mut requirements = requirements(&fee_payer);
        requirements.extra.memo = None;
        requirements.extra.receiver_authorizer = Some(pc::pubkey_string(&receiver_authorizer));
        requirements.extra.voucher_signer = Some("server".to_string());
        requirements.extra.operator = Some(pc::pubkey_string(&operator));
        let policy = ServerSignedChannelsPolicy::new()
            .allow_operator(operator, 20_000)
            .unwrap();
        let terms = resolve_terms_with_token_program_and_policy(
            &requirements,
            pc::parse_pubkey(programs::TOKEN_PROGRAM).unwrap(),
            None,
            Some(&policy),
        )
        .unwrap();
        assert_eq!(
            terms.memo,
            format!("{RECEIVER_BINDING_MEMO_PREFIX}{receiver_authorizer}")
        );
        assert_eq!(terms.continuation_memo.len(), MEMO_NONCE_BYTES * 2);
        assert!(terms
            .continuation_memo
            .bytes()
            .all(|b| b.is_ascii_hexdigit()));

        let (mut channel, payload) = build_deposit(
            &signer,
            &requirements,
            &terms,
            10_000,
            Hash::new_unique(),
            341_000_000,
        )
        .await
        .unwrap();
        let BatchPayload::Deposit {
            channel_config,
            voucher,
            authorization,
            ..
        } = payload
        else {
            panic!("expected deposit");
        };
        assert!(voucher.is_none());
        assert_eq!(
            channel_config.payer_authorizer,
            pc::pubkey_string(&operator)
        );
        assert_eq!(channel_config.voucher_signer.as_deref(), Some("server"));
        let authorization = authorization.expect("server deposit carries a payer proof");
        assert_eq!(authorization.authorized_amount, "1000");
        let message = authorization_message_bytes(
            channel.channel_id(),
            &signer.pubkey(),
            &operator,
            &authorization.request_id,
            1_000,
            authorization.expires_at,
        )
        .unwrap();
        let signature = Signature::from_str(&authorization.signature).unwrap();
        assert!(signature.verify(signer.pubkey().as_ref(), &message));

        // Server mode is confirmed by the operator's signed voucher. The
        // channel snapshot's cumulative watermark is optional on the wire,
        // including on BlockRun's successful open response.
        let confirmed_voucher = sign_voucher(&operator_signer, channel.channel_id(), 750)
            .await
            .unwrap();
        let response = BatchSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some(pc::pubkey_string(&signer.pubkey())),
            transaction: String::new(),
            network: requirements.network.clone(),
            amount: String::new(),
            extra: Some(BatchSettlementExtra {
                commitment_id: Some("server-receipt".to_string()),
                charged_amount: Some("750".to_string()),
                channel_state: Some(ChannelStateSnapshot {
                    channel_id: pc::pubkey_string(channel.channel_id()),
                    balance: "10000".to_string(),
                    total_claimed: "0".to_string(),
                    withdraw_requested_at: 0,
                    charged_cumulative_amount: None,
                }),
                voucher: Some(confirmed_voucher),
            }),
        };
        channel
            .apply_authorization_response(&response, &authorization)
            .expect("signed server voucher confirms the open charge");
        assert_eq!(channel.charged_cumulative_amount(), 750);

        // Once local history is synchronized, chargedAmount must equal the
        // signed cumulative increase. A bounded chargedAmount cannot disguise
        // an operator voucher that consumes the rest of the deposit.
        let mut overstated_channel = channel.clone();
        let overstated_voucher = sign_voucher(&operator_signer, channel.channel_id(), 10_000)
            .await
            .unwrap();
        let mut overstated_response = response.clone();
        let overstated_extra = overstated_response.extra.as_mut().unwrap();
        overstated_extra.charged_amount = Some("1000".to_string());
        overstated_extra.voucher = Some(overstated_voucher);
        assert!(overstated_channel
            .apply_authorization_response(&overstated_response, &authorization)
            .is_err());
        assert_eq!(overstated_channel.charged_cumulative_amount(), 750);

        let top_up = build_top_up(&signer, &channel, &terms, 1_000, Hash::new_unique())
            .await
            .expect("server-signed top-up builds");
        let BatchPayload::Deposit {
            deposit,
            authorization: Some(top_up_authorization),
            ..
        } = top_up
        else {
            panic!("expected top-up deposit");
        };
        let transaction = pc::decode_transaction(&deposit.transaction).unwrap();
        let instructions = transaction.message.instructions();
        let memo = instructions.last().expect("top-up memo");
        assert_eq!(
            transaction.message.static_account_keys()[memo.program_id_index as usize],
            pc::memo_program_id()
        );
        let memo = std::str::from_utf8(&memo.data).unwrap();
        assert_eq!(memo.len(), MEMO_NONCE_BYTES * 2);
        assert!(memo.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!memo.starts_with(RECEIVER_BINDING_MEMO_PREFIX));

        let top_up_voucher = sign_voucher(&operator_signer, channel.channel_id(), 1_500)
            .await
            .unwrap();
        let top_up_response = BatchSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some(pc::pubkey_string(&signer.pubkey())),
            transaction: String::new(),
            network: requirements.network.clone(),
            amount: String::new(),
            extra: Some(BatchSettlementExtra {
                commitment_id: Some("top-up-receipt".to_string()),
                charged_amount: Some("750".to_string()),
                channel_state: None,
                voucher: Some(top_up_voucher),
            }),
        };
        channel
            .apply_authorization_response_with_deposit(
                &top_up_response,
                &top_up_authorization,
                Some(11_000),
            )
            .expect("signed top-up determines the escrow ceiling without channelState");
        assert_eq!(channel.charged_cumulative_amount(), 1_500);
        assert_eq!(channel.deposit(), 11_000);

        // A restarted client knows the escrow ceiling from chain, but not
        // operator-signed charges that have not been claimed yet. The receipt's
        // chargedAmount is bounded by this authorization; the signed cumulative
        // may legitimately include earlier authorizations.
        let mut recovered =
            BatchChannel::recovered(*channel.channel_id(), channel.config().clone(), 0, 11_000);
        let recovered_payload = recovered
            .authorization_payload(
                &signer,
                1_000,
                authorization_expires_at(terms.authorization_ttl_seconds).unwrap(),
            )
            .await
            .unwrap();
        let BatchPayload::Authorization {
            authorization: recovered_authorization,
            ..
        } = recovered_payload
        else {
            panic!("expected recovered authorization");
        };
        let recovered_voucher = sign_voucher(&operator_signer, channel.channel_id(), 2_500)
            .await
            .unwrap();
        let recovered_response = BatchSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some(pc::pubkey_string(&signer.pubkey())),
            transaction: String::new(),
            network: requirements.network.clone(),
            amount: String::new(),
            extra: Some(BatchSettlementExtra {
                commitment_id: Some("recovered-receipt".to_string()),
                charged_amount: Some("1000".to_string()),
                channel_state: None,
                voucher: Some(recovered_voucher),
            }),
        };
        recovered
            .apply_authorization_response(&recovered_response, &recovered_authorization)
            .expect("recovered channel adopts signed cumulative history");
        assert_eq!(recovered.charged_cumulative_amount(), 2_500);
        assert_eq!(recovered.deposit(), 11_000);

        let err = build_deposit(
            &signer,
            &requirements,
            &terms,
            20_001,
            Hash::new_unique(),
            341_000_000,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("operator grant"));
    }

    #[test]
    fn terms_supply_a_hex_nonce_when_the_seller_declares_no_memo() {
        let fee_payer = Pubkey::new_unique();
        let mut requirements = requirements(&fee_payer);
        requirements.extra.memo = None;
        let terms = resolve(&requirements);
        assert_eq!(terms.memo.len(), MEMO_NONCE_BYTES * 2);
        assert_eq!(terms.continuation_memo.len(), MEMO_NONCE_BYTES * 2);
        assert!(terms.memo.bytes().all(|b| b.is_ascii_hexdigit()));
        // And a declared memo is passed through verbatim.
        let mut requirements = self::requirements(&fee_payer);
        let terms = resolve(&requirements);
        assert_eq!(terms.memo, "invoice-1");
        assert_eq!(terms.continuation_memo, "invoice-1");

        // Receiver binding is a server-signed open policy. Client-signed
        // channels retain the normal declared memo even when the optional
        // receiver authorizer is advertised.
        requirements.extra.receiver_authorizer = Some(pc::pubkey_string(&Pubkey::new_unique()));
        let terms = resolve(&requirements);
        assert_eq!(terms.memo, "invoice-1");
        assert_eq!(terms.continuation_memo, "invoice-1");
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
            ..
        } = &payload
        else {
            panic!("expected a deposit payload");
        };
        let voucher = voucher.as_ref().expect("client deposits carry a voucher");
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
            accepted_versions: &[crate::core::tx::TxVersion::V0],
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
            accepted_versions: &[crate::core::tx::TxVersion::V0],
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
        assert_eq!(
            voucher.as_ref().map(|v| v.max_claimable_amount.as_str()),
            Some("2000")
        );
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
                voucher: None,
            }),
        };

        // A response confirming a different cumulative must not advance state.
        let wrong = ok("receipt-7f3a", "1000", "2000");
        assert!(channel
            .apply_payment_response(&wrong, &requirements, &voucher)
            .is_err());
        assert_eq!(channel.charged_cumulative_amount(), 0);

        // Nor one with no commitment identifier at all.
        let unconfirmed = ok("", "1000", "1000");
        assert!(channel
            .apply_payment_response(&unconfirmed, &requirements, &voucher)
            .is_err());
        assert_eq!(channel.charged_cumulative_amount(), 0);

        // Nor one that charged more than the advertised price.
        let overcharged = ok(&voucher.commitment_id(), "2000", "1000");
        assert!(channel
            .apply_payment_response(&overcharged, &requirements, &voucher)
            .is_err());
        assert_eq!(channel.charged_cumulative_amount(), 0);

        // The identifier itself is opaque (spec §4.4): any non-empty value is
        // accepted when the cumulative and charge match what was signed.
        let good = ok("receipt-7f3a", "1000", "1000");
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
        corrective.extra.channel_state.as_mut().unwrap().balance = "1".to_string();
        corrective.extra.voucher_state = Some(VoucherState {
            signed_max_claimable: "3000".to_string(),
            expires_at: 0,
            signature: proof.signature,
        });
        assert_eq!(channel.adopt_corrective_state(&corrective).unwrap(), 3_000);
        assert_eq!(channel.charged_cumulative_amount(), 3_000);
        assert_eq!(
            channel.deposit(),
            100_000,
            "untrusted corrective balance must not lower the escrow ceiling"
        );
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
