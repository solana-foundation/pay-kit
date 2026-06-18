//! Server-side handler for the x402 `upto` scheme (payment-channel profile).
//!
//! Flow (single HTTP round-trip, handler-determined amount):
//!
//! 1. [`X402Upto::upto`] advertises a 402 with the authorized maximum and the
//!    operator's facilitator key.
//! 2. [`X402Upto::verify_open`] validates the client authorization, broadcasts
//!    the channel `open` (co-signing as fee payer), confirms it, and reads the
//!    channel state back to bind deposit/payee/mint/signer on-chain.
//! 3. The route handler runs and determines the actual metered amount.
//! 4. [`X402Upto::settle_actual`] signs a single operator voucher for the actual
//!    amount and submits `settle_and_finalize` + `distribute`, refunding
//!    `deposit − actual` to the payer.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

use solana_pay_core::payment_channels as pc;
use solana_pay_core::payment_channels::generated::accounts::Channel;

use crate::error::Error;
use crate::protocol::schemes::exact::{
    caip2_network_for_cluster, default_rpc_url, default_token_program_for_currency,
    resolve_stablecoin_mint, ResourceInfo,
};
use crate::protocol::schemes::upto::{
    assert_settlement_within_ceiling, verify_upto_payload, UptoExtra, UptoRequiredEnvelope,
    UptoRequirements, UptoSettlementResponse, UptoSignatureEnvelope, PROFILE_PAYMENT_CHANNEL,
    UPTO_SCHEME,
};
use crate::{PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, X402_VERSION_V2};

/// `ChannelStatus::Open` discriminant in the generated client.
const CHANNEL_STATUS_OPEN: u8 = 0;

/// Server configuration for the Solana x402 `upto` scheme.
#[derive(Clone)]
pub struct UptoConfig {
    /// Base58 recipient (payTo) of the metered charge.
    pub recipient: String,
    /// Currency symbol (`"USDC"`) or mint address.
    pub currency: String,
    /// Token decimals.
    pub decimals: u8,
    /// Solana cluster: `mainnet-beta`, `devnet`, or `localnet`.
    pub cluster: String,
    /// RPC URL override (defaults per cluster).
    pub rpc_url: Option<String>,
    /// Resource identifier for the 402 challenge.
    pub resource: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Completion window in seconds.
    pub max_timeout_seconds: u64,
    /// Token program override.
    pub token_program: Option<String>,
    /// Channel program id override (defaults to the canonical deployment).
    pub program_id: Option<String>,
    /// Operator signer — co-signs the open as fee payer and signs settlement
    /// vouchers + transactions. Its pubkey is the advertised facilitator.
    pub operator_signer: Arc<dyn SolanaSigner>,
}

/// A confirmed, on-chain-verified channel open, carried from
/// [`X402Upto::verify_open`] to [`X402Upto::settle_actual`].
#[derive(Debug, Clone)]
pub struct VerifiedUptoOpen {
    pub channel_id: Pubkey,
    pub payer: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub program_id: Pubkey,
    pub deposit: u64,
    pub max_amount: u64,
    pub expires_at: i64,
    pub network: String,
}

/// Server-side payment handler for the Solana x402 `upto` scheme.
#[derive(Clone)]
pub struct X402Upto {
    rpc: Arc<RpcClient>,
    config: UptoConfig,
    operator: Pubkey,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl X402Upto {
    pub fn new(config: UptoConfig) -> Result<Self, Error> {
        if config.recipient.is_empty() {
            return Err(Error::Other("recipient is required".into()));
        }
        Pubkey::from_str(&config.recipient)
            .map_err(|e| Error::Other(format!("Invalid recipient pubkey: {e}")))?;

        let operator = config.operator_signer.pubkey();
        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&config.cluster).to_string());

        Ok(Self {
            rpc: Arc::new(RpcClient::new(rpc_url)),
            config,
            operator,
        })
    }

    /// The operator/facilitator public key (base58).
    pub fn operator(&self) -> String {
        pc::pubkey_string(&self.operator)
    }

    fn program_id(&self) -> Result<Pubkey, Error> {
        match &self.config.program_id {
            Some(value) => {
                Pubkey::from_str(value).map_err(|e| Error::Other(format!("invalid programId: {e}")))
            }
            None => Ok(pc::default_program_id()),
        }
    }

    fn mint(&self) -> Result<Pubkey, Error> {
        let mint = resolve_stablecoin_mint(&self.config.currency, Some(&self.config.cluster))
            .ok_or_else(|| Error::Other("upto requires an SPL token (not native SOL)".into()))?;
        Pubkey::from_str(mint).map_err(|e| Error::Other(format!("invalid mint: {e}")))
    }

    fn token_program(&self) -> Result<Pubkey, Error> {
        let tp = self.config.token_program.clone().unwrap_or_else(|| {
            default_token_program_for_currency(&self.config.currency, Some(&self.config.cluster))
                .to_string()
        });
        Pubkey::from_str(&tp).map_err(|e| Error::Other(format!("invalid token program: {e}")))
    }

    /// Build the `upto` payment requirement for the given authorized maximum.
    ///
    /// `max_amount` is a human-decimal amount (e.g. `"0.10"`), converted to base
    /// units using the configured decimals — same convention as the `exact`
    /// scheme, so the gate passes one dollar string everywhere.
    ///
    /// Pure (no RPC): `extra.recent_blockhash` is left `None` and filled in by
    /// [`upto`] when building the 402 challenge. The verify path reuses this
    /// without fetching (or diverging on) a blockhash.
    pub fn upto_requirements(&self, max_amount: &str) -> Result<UptoRequirements, Error> {
        let mint = self.mint()?;
        let token_program = self.token_program()?;
        let base_units = crate::server::exact::parse_units(max_amount, self.config.decimals)?;

        Ok(UptoRequirements {
            scheme: UPTO_SCHEME.to_string(),
            network: caip2_network_for_cluster(&self.config.cluster).to_string(),
            amount: base_units,
            asset: pc::pubkey_string(&mint),
            pay_to: self.config.recipient.clone(),
            max_timeout_seconds: self.config.max_timeout_seconds,
            extra: UptoExtra {
                profiles: vec![PROFILE_PAYMENT_CHANNEL.to_string()],
                decimals: Some(self.config.decimals),
                token_program: Some(pc::pubkey_string(&token_program)),
                facilitator: self.operator(),
                program_id: Some(pc::pubkey_string(&self.program_id()?)),
                recent_blockhash: None,
                valid_after: None,
            },
        })
    }

    /// Build the full `PAYMENT-REQUIRED` envelope for an `upto` challenge.
    ///
    /// This is where the (best-effort) recent blockhash is fetched and attached,
    /// so the client can build the channel `open` without an extra RPC.
    pub fn upto(&self, max_amount: &str) -> Result<UptoRequiredEnvelope, Error> {
        let mut requirement = self.upto_requirements(max_amount)?;
        requirement.extra.recent_blockhash = self
            .rpc
            .get_latest_blockhash()
            .ok()
            .map(|hash| hash.to_string());
        let resource = (!self.config.resource.is_empty()).then(|| ResourceInfo {
            url: self.config.resource.clone(),
            description: self.config.description.clone(),
            mime_type: None,
        });
        Ok(UptoRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource,
            accepts: vec![requirement],
            error: None,
        })
    }

    /// `(header-name, base64-value)` for the `upto` 402 challenge.
    pub fn payment_required_header(&self, max_amount: &str) -> Result<(String, String), Error> {
        let envelope = self.upto(max_amount)?;
        let json = serde_json::to_string(&envelope)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        Ok((
            PAYMENT_REQUIRED_HEADER.to_string(),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes()),
        ))
    }

    /// `(header-name, base64-value)` for the `PAYMENT-RESPONSE` settlement
    /// result, ready to set on the route's response.
    pub fn settlement_header(
        &self,
        settlement: &UptoSettlementResponse,
    ) -> Result<(String, String), Error> {
        let json = serde_json::to_string(settlement)
            .map_err(|e| Error::Other(format!("settlement serialization failed: {e}")))?;
        Ok((
            PAYMENT_RESPONSE_HEADER.to_string(),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes()),
        ))
    }

    /// Decode a `PAYMENT-SIGNATURE` header into an `upto` envelope.
    pub fn parse_payment_signature(&self, header: &str) -> Result<UptoSignatureEnvelope, Error> {
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, header)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        let envelope: UptoSignatureEnvelope = serde_json::from_slice(&decoded)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        if envelope.scheme != UPTO_SCHEME {
            return Err(Error::InvalidPayloadType(envelope.scheme));
        }
        Ok(envelope)
    }

    /// Verify an `upto` authorization for a route capped at `max_amount`,
    /// broadcast and confirm the channel `open`, and bind its on-chain state.
    pub async fn verify_open(
        &self,
        header: &str,
        max_amount: &str,
    ) -> Result<VerifiedUptoOpen, Error> {
        let envelope = self.parse_payment_signature(header)?;
        let requirements = self.upto_requirements(max_amount)?;
        let payload = &envelope.payload;

        verify_upto_payload(payload, &requirements, &self.operator(), now_unix())?;

        let program_id = self.program_id()?;
        let expected_mint = self.mint()?;
        let expected_payee = Pubkey::from_str(&self.config.recipient)
            .map_err(|e| Error::Other(format!("invalid recipient: {e}")))?;
        let channel_id = Pubkey::from_str(&payload.channel_id)
            .map_err(|e| Error::Other(format!("invalid channelId: {e}")))?;
        let payer = Pubkey::from_str(&payload.from)
            .map_err(|e| Error::Other(format!("invalid payer: {e}")))?;
        let max = payload.max_amount()?;

        // Broadcast the client-signed open (pull). Push (already broadcast) is
        // not yet supported; require the transaction.
        let open_tx_b64 = payload.open_transaction.as_deref().ok_or_else(|| {
            Error::Other("payment-channel profile requires openTransaction (pull)".to_string())
        })?;
        let mut tx = decode_transaction(open_tx_b64)?;
        self.cosign_fee_payer(&mut tx).await?;
        self.rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Rpc(format!("open broadcast failed: {e}")))?;

        // Read the confirmed channel state and bind it.
        let channel = self.fetch_channel(&channel_id)?;
        if channel.status != CHANNEL_STATUS_OPEN {
            return Err(Error::Other(
                "channel is not open after broadcast".to_string(),
            ));
        }
        if pc::from_address(&channel.mint) != expected_mint {
            return Err(Error::MintMismatch {
                expected: pc::pubkey_string(&expected_mint),
                actual: pc::pubkey_string(&pc::from_address(&channel.mint)),
            });
        }
        if pc::from_address(&channel.payee) != expected_payee {
            return Err(Error::RecipientMismatch {
                expected: pc::pubkey_string(&expected_payee),
                actual: pc::pubkey_string(&pc::from_address(&channel.payee)),
            });
        }
        if pc::from_address(&channel.authorized_signer) != self.operator {
            return Err(Error::Other(
                "channel authorized_signer is not the operator".to_string(),
            ));
        }
        if channel.deposit < max {
            return Err(Error::Other(format!(
                "on-chain deposit {} below authorized maximum {max}",
                channel.deposit
            )));
        }

        Ok(VerifiedUptoOpen {
            channel_id,
            payer,
            mint: expected_mint,
            token_program: self.token_program()?,
            program_id,
            deposit: channel.deposit,
            max_amount: max,
            expires_at: payload.expires_at,
            network: requirements.network,
        })
    }

    /// Settle the actual metered amount (`actual ≤ max`) against a verified
    /// open: operator-signed voucher, `settle_and_finalize` + `distribute`,
    /// refunding the remainder. `actual == 0` still finalizes (full refund).
    pub async fn settle_actual(
        &self,
        open: &VerifiedUptoOpen,
        actual: u64,
    ) -> Result<UptoSettlementResponse, Error> {
        assert_settlement_within_ceiling(actual, open.max_amount)?;

        let mut instructions = if actual == 0 {
            pc::build_settle_and_finalize_instructions(
                &self.operator,
                &open.channel_id,
                &self.operator,
                None,
                0,
                open.expires_at,
                &open.program_id,
            )?
        } else {
            let voucher_bytes =
                pc::voucher_message_bytes(&open.channel_id, actual, open.expires_at)?;
            let sig_bytes: [u8; 64] = self
                .config
                .operator_signer
                .sign_message(&voucher_bytes)
                .await
                .map_err(|e| Error::Other(format!("voucher signing failed: {e}")))?
                .into();
            pc::build_settle_and_finalize_instructions(
                &self.operator,
                &open.channel_id,
                &self.operator,
                Some(&sig_bytes),
                actual,
                open.expires_at,
                &open.program_id,
            )?
        };

        instructions.push(pc::build_distribute_instruction(
            &open.channel_id,
            &open.payer,
            &Pubkey::from_str(&self.config.recipient)
                .map_err(|e| Error::Other(format!("invalid recipient: {e}")))?,
            &pc::treasury_owner(),
            &open.mint,
            &[],
            &open.token_program,
            &open.program_id,
        ));

        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .map_err(|e| Error::Rpc(format!("blockhash fetch failed: {e}")))?;
        let message = Message::new_with_blockhash(&instructions, Some(&self.operator), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        self.config
            .operator_signer
            .sign_transaction(&mut tx)
            .await
            .map_err(|e| Error::Other(format!("settle signing failed: {e}")))?;

        let signature = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Rpc(format!("settle broadcast failed: {e}")))?;

        Ok(UptoSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some(pc::pubkey_string(&open.payer)),
            transaction: signature.to_string(),
            network: open.network.clone(),
            amount: actual.to_string(),
        })
    }

    /// Co-sign the fee-payer (operator) slot of a partially-signed transaction.
    async fn cosign_fee_payer(&self, tx: &mut VersionedTransaction) -> Result<(), Error> {
        let account_keys = tx.message.static_account_keys();
        let idx = account_keys
            .iter()
            .position(|k| k == &self.operator)
            .ok_or_else(|| Error::Other("operator (fee payer) not in open transaction".into()))?;
        if idx >= tx.signatures.len() {
            return Err(Error::Other(
                "operator is not a required signer in the open transaction".into(),
            ));
        }
        let msg_data = tx.message.serialize();
        let sig_bytes: [u8; 64] = self
            .config
            .operator_signer
            .sign_message(&msg_data)
            .await
            .map_err(|e| Error::Other(format!("fee payer signing failed: {e}")))?
            .into();
        tx.signatures[idx] = Signature::from(sig_bytes);
        Ok(())
    }

    fn fetch_channel(&self, channel_id: &Pubkey) -> Result<Channel, Error> {
        let data = self
            .rpc
            .get_account_data(channel_id)
            .map_err(|e| Error::Rpc(format!("channel account fetch failed: {e}")))?;
        Channel::from_bytes(&data).map_err(|e| Error::Other(format!("channel decode failed: {e}")))
    }
}

/// Decode a base64 (standard) bincode transaction, accepting legacy and v0.
fn decode_transaction(b64: &str) -> Result<VersionedTransaction, Error> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        .map_err(|e| Error::Other(format!("invalid base64 transaction: {e}")))?;
    bincode::deserialize::<Transaction>(&bytes)
        .map(VersionedTransaction::from)
        .or_else(|_| bincode::deserialize::<VersionedTransaction>(&bytes))
        .map_err(|e| Error::Other(format!("invalid transaction: {e}")))
}
