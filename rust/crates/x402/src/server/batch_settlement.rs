//! Server-side handler for the x402 `batch-settlement` scheme (payment-channel).
//!
//! High-throughput channel payments: the client opens an escrow channel
//! ([`X402BatchSettlement::verify_payment`] with a `deposit` payload), then signs
//! cumulative vouchers per request (`voucher` payloads) that the server accepts
//! off-chain via [`solana_pay_core::session::accept_voucher`] and serves
//! immediately. The operator redeems the latest voucher per channel on-chain
//! later, in batches ([`X402BatchSettlement::settle_batch`]), and sweeps the
//! proceeds ([`X402BatchSettlement::distribute`]). Cooperative close refunds the
//! unused deposit.
//!
//! v1: fixed per-request price; explicit operator-driven settlement (no
//! automatic cron / forced-close watchdog yet).

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::Transaction;

use solana_pay_core::payment_channels as pc;
use solana_pay_core::payment_channels::generated::accounts::Channel;
use solana_pay_core::session::accept_voucher;
use solana_pay_core::store::{ChannelState, ChannelStore, MemoryChannelStore};

use crate::error::Error;
use crate::protocol::schemes::batch_settlement::{
    check_profile, BatchChannelSnapshot, BatchExtra, BatchPayload, BatchRequiredEnvelope,
    BatchRequirements, BatchSettlementResponse, BatchSplit, BatchVoucher, BATCH_SETTLEMENT_SCHEME,
    PROFILE_PAYMENT_CHANNEL,
};
use crate::protocol::schemes::exact::{
    caip2_network_for_cluster, default_rpc_url, default_token_program_for_currency,
    resolve_stablecoin_mint, ResourceInfo,
};
use crate::server::upto::{
    cosign_operator_fee_payer, decode_transaction, validate_open_instruction,
};
use crate::{PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, X402_VERSION_V2};

/// `ChannelStatus::Open` discriminant in the generated client.
const CHANNEL_STATUS_OPEN: u8 = 0;

/// Default forced-close grace period (seconds).
const DEFAULT_GRACE_PERIOD_SECONDS: u32 = 900;

/// Conservative number of channel `settle`s packed into one Solana transaction.
/// Each channel needs its own Ed25519-precompile + `settle` instruction, so a
/// legacy transaction (~1232 bytes) fits only a handful.
const MAX_CHANNELS_PER_SETTLE_TX: usize = 3;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Server configuration for the Solana x402 `batch-settlement` scheme.
#[derive(Clone)]
pub struct BatchConfig {
    /// Base58 channel payee (proceeds recipient).
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
    /// Forced-close grace period (seconds, non-zero).
    pub grace_period_seconds: u32,
    /// Minimum cumulative increment between accepted vouchers (base units).
    pub min_voucher_delta: u64,
    /// Token program override.
    pub token_program: Option<String>,
    /// Channel program id override (defaults to the canonical deployment).
    pub program_id: Option<String>,
    /// Operator signer — co-signs `open` as fee payer and signs settlement txs.
    pub operator_signer: Arc<dyn SolanaSigner>,
    /// Merchant-side splits committed at open (recipient base58, share bps).
    pub splits: Vec<(String, u16)>,
}

impl BatchConfig {
    /// Minimal config with sane defaults.
    pub fn new(
        recipient: impl Into<String>,
        cluster: impl Into<String>,
        operator_signer: Arc<dyn SolanaSigner>,
    ) -> Self {
        Self {
            recipient: recipient.into(),
            currency: "USDC".to_string(),
            decimals: 6,
            cluster: cluster.into(),
            rpc_url: None,
            resource: String::new(),
            description: None,
            max_timeout_seconds: 3600,
            grace_period_seconds: DEFAULT_GRACE_PERIOD_SECONDS,
            min_voucher_delta: 0,
            token_program: None,
            program_id: None,
            operator_signer,
            splits: vec![],
        }
    }
}

/// Outcome of verifying a `batch-settlement` payment.
#[derive(Debug)]
pub struct BatchOutcome {
    /// Whether the gate should run the protected handler (false for refunds).
    pub serve: bool,
    /// The settlement response to surface in `PAYMENT-RESPONSE`.
    pub response: BatchSettlementResponse,
}

/// Server-side payment handler for the Solana x402 `batch-settlement` scheme.
#[derive(Clone)]
pub struct X402BatchSettlement {
    rpc: Arc<RpcClient>,
    config: BatchConfig,
    operator: Pubkey,
    store: Arc<dyn ChannelStore>,
}

impl X402BatchSettlement {
    /// Build a handler with an in-memory channel store.
    pub fn new(config: BatchConfig) -> Result<Self, Error> {
        Self::with_store(config, Arc::new(MemoryChannelStore::new()))
    }

    /// Build a handler with a caller-provided (e.g. durable) channel store.
    pub fn with_store(config: BatchConfig, store: Arc<dyn ChannelStore>) -> Result<Self, Error> {
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
            store,
        })
    }

    /// Operator/facilitator pubkey (base58).
    pub fn operator(&self) -> String {
        pc::pubkey_string(&self.operator)
    }

    fn program_id(&self) -> Result<Pubkey, Error> {
        match &self.config.program_id {
            Some(v) => {
                Pubkey::from_str(v).map_err(|e| Error::Other(format!("invalid programId: {e}")))
            }
            None => Ok(pc::default_program_id()),
        }
    }

    fn mint(&self) -> Result<Pubkey, Error> {
        let mint = resolve_stablecoin_mint(&self.config.currency, Some(&self.config.cluster))
            .ok_or_else(|| Error::Other("batch-settlement requires an SPL token".into()))?;
        Pubkey::from_str(mint).map_err(|e| Error::Other(format!("invalid mint: {e}")))
    }

    fn token_program(&self) -> Result<Pubkey, Error> {
        let tp = self.config.token_program.clone().unwrap_or_else(|| {
            default_token_program_for_currency(&self.config.currency, Some(&self.config.cluster))
                .to_string()
        });
        Pubkey::from_str(&tp).map_err(|e| Error::Other(format!("invalid token program: {e}")))
    }

    fn distributions(&self) -> Result<Vec<pc::Distribution>, Error> {
        self.config
            .splits
            .iter()
            .map(|(recipient, bps)| {
                Ok(pc::Distribution {
                    recipient: Pubkey::from_str(recipient)
                        .map_err(|e| Error::Other(format!("invalid split recipient: {e}")))?,
                    bps: *bps,
                })
            })
            .collect()
    }

    /// Build the `batch-settlement` requirement (pure; no RPC).
    pub fn requirements(&self, amount: &str) -> Result<BatchRequirements, Error> {
        let base_units = crate::server::exact::parse_units(amount, self.config.decimals)?;
        let splits = self
            .config
            .splits
            .iter()
            .map(|(recipient, bps)| BatchSplit {
                recipient: recipient.clone(),
                share_bps: *bps,
            })
            .collect();
        Ok(BatchRequirements {
            scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
            network: caip2_network_for_cluster(&self.config.cluster).to_string(),
            amount: base_units,
            asset: pc::pubkey_string(&self.mint()?),
            pay_to: self.config.recipient.clone(),
            max_timeout_seconds: self.config.max_timeout_seconds,
            extra: BatchExtra {
                profiles: vec![PROFILE_PAYMENT_CHANNEL.to_string()],
                channel_program: pc::pubkey_string(&self.program_id()?),
                grace_period_seconds: self.config.grace_period_seconds,
                decimals: Some(self.config.decimals),
                token_program: Some(pc::pubkey_string(&self.token_program()?)),
                facilitator: self.operator(),
                recent_blockhash: None,
                suggested_deposit: None,
                minimum_deposit: None,
                min_voucher_delta: (self.config.min_voucher_delta > 0)
                    .then(|| self.config.min_voucher_delta.to_string()),
                distribution_splits: splits,
            },
        })
    }

    /// Build the full 402 challenge envelope (fetches a recent blockhash).
    pub fn challenge(&self, amount: &str) -> Result<BatchRequiredEnvelope, Error> {
        let mut requirement = self.requirements(amount)?;
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .map_err(|e| Error::Rpc(format!("failed to fetch recent blockhash: {e}")))?;
        requirement.extra.recent_blockhash = Some(blockhash.to_string());
        let resource = (!self.config.resource.is_empty()).then(|| ResourceInfo {
            url: self.config.resource.clone(),
            description: self.config.description.clone(),
            mime_type: None,
        });
        Ok(BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource,
            accepts: vec![requirement],
            error: None,
        })
    }

    /// `(header-name, base64-value)` for the 402 challenge.
    pub fn payment_required_header(&self, amount: &str) -> Result<(String, String), Error> {
        let envelope = self.challenge(amount)?;
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
        response: &BatchSettlementResponse,
    ) -> Result<(String, String), Error> {
        let json = serde_json::to_string(response)
            .map_err(|e| Error::Other(format!("settlement serialization failed: {e}")))?;
        Ok((
            PAYMENT_RESPONSE_HEADER.to_string(),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes()),
        ))
    }

    /// Decode a `PAYMENT-SIGNATURE` header into a `batch-settlement` payload.
    pub fn parse_payment(&self, header: &str) -> Result<BatchPayload, Error> {
        use crate::protocol::schemes::batch_settlement::BatchSignatureEnvelope;
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, header)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        let envelope: BatchSignatureEnvelope = serde_json::from_slice(&decoded)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        if envelope.scheme != BATCH_SETTLEMENT_SCHEME {
            return Err(Error::InvalidPayloadType(envelope.scheme));
        }
        Ok(envelope.payload)
    }

    /// Verify a `batch-settlement` payment for a route priced at `amount`.
    ///
    /// `deposit` broadcasts + confirms the channel open and accepts the first
    /// voucher; `voucher` accepts a cumulative voucher off-chain; `refund`
    /// cooperatively settles + finalizes (and is not served).
    pub async fn verify_payment(&self, header: &str, amount: &str) -> Result<BatchOutcome, Error> {
        let payload = self.parse_payment(header)?;
        let requirements = self.requirements(amount)?;
        check_profile(&requirements.extra.profiles)?;
        let per_request = requirements.amount()?;

        match payload {
            BatchPayload::Deposit {
                channel_config,
                transaction,
                voucher,
            } => {
                self.process_deposit(channel_config, transaction, voucher, per_request)
                    .await
            }
            BatchPayload::Voucher {
                channel_id,
                voucher,
            } => self.process_voucher(&channel_id, voucher).await,
            BatchPayload::Refund {
                channel_id,
                voucher,
            } => self.process_refund(&channel_id, voucher).await,
        }
    }

    async fn process_deposit(
        &self,
        config: crate::protocol::schemes::batch_settlement::BatchChannelConfig,
        transaction: String,
        voucher: Option<BatchVoucher>,
        _per_request: u64,
    ) -> Result<BatchOutcome, Error> {
        let program_id = self.program_id()?;
        let expected_mint = self.mint()?;
        let expected_payee = Pubkey::from_str(&self.config.recipient)
            .map_err(|e| Error::Other(format!("invalid recipient: {e}")))?;
        let payer = Pubkey::from_str(&config.payer)
            .map_err(|e| Error::Other(format!("invalid payer: {e}")))?;
        let authorized_signer = Pubkey::from_str(&config.authorized_signer)
            .map_err(|e| Error::Other(format!("invalid authorizedSigner: {e}")))?;
        let salt: u64 = config
            .salt
            .parse()
            .map_err(|_| Error::Other(format!("invalid salt: {}", config.salt)))?;

        // Derive the expected channel PDA and validate the open transaction binds
        // it (SOL-drain guard) before the operator co-signs as fee payer.
        let (channel_id, _) = pc::find_channel_pda(
            &payer,
            &expected_payee,
            &expected_mint,
            &authorized_signer,
            salt,
            &program_id,
        );
        let mut tx = decode_transaction(&transaction)?;
        validate_open_instruction(
            &tx,
            &program_id,
            &self.operator,
            &payer,
            &expected_payee,
            &expected_mint,
            &channel_id,
        )?;
        cosign_operator_fee_payer(
            self.config.operator_signer.as_ref(),
            &self.operator,
            &mut tx,
        )
        .await?;
        self.rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Rpc(format!("open broadcast failed: {e}")))?;
        let open_sig = tx
            .signatures
            .first()
            .map(|s| s.to_string())
            .unwrap_or_default();

        // Bind the confirmed channel state.
        let channel = self.fetch_channel(&channel_id)?;
        if channel.status != CHANNEL_STATUS_OPEN {
            return Err(Error::Other("channel is not open after broadcast".into()));
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
        if pc::from_address(&channel.authorized_signer) != authorized_signer {
            return Err(Error::Other("channel authorized_signer mismatch".into()));
        }
        if pc::from_address(&channel.payer) != payer {
            return Err(Error::Other("channel payer mismatch".into()));
        }

        let channel_b58 = pc::pubkey_string(&channel_id);
        self.store
            .put_channel(
                &channel_b58,
                ChannelState {
                    channel_id: channel_b58.clone(),
                    authorized_signer: pc::pubkey_string(&authorized_signer),
                    deposit: channel.deposit,
                    cumulative: 0,
                    finalized: false,
                    highest_voucher_signature: None,
                    highest_voucher_expires_at: None,
                    close_requested_at: None,
                    // Stash the payer here so settlement/distribute can refund it
                    // without an extra account fetch.
                    operator: Some(pc::pubkey_string(&payer)),
                    next_delivery_sequence: 0,
                    pending_deliveries: vec![],
                    committed_deliveries: vec![],
                },
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;

        // Accept the first voucher (if any) off-chain.
        let charged = if let Some(v) = voucher {
            Some(self.accept(&channel_b58, &v).await?)
        } else {
            None
        };

        Ok(BatchOutcome {
            serve: true,
            response: BatchSettlementResponse {
                success: true,
                error_reason: None,
                payer: Some(pc::pubkey_string(&payer)),
                transaction: open_sig,
                network: caip2_network_for_cluster(&self.config.cluster).to_string(),
                amount: channel.deposit.to_string(),
                charged_amount: charged.map(|c| c.to_string()),
                channel_state: Some(self.snapshot(&channel_b58, channel.deposit, "open").await),
            },
        })
    }

    async fn process_voucher(
        &self,
        channel_id: &str,
        voucher: BatchVoucher,
    ) -> Result<BatchOutcome, Error> {
        let prev = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .map(|s| s.cumulative)
            .unwrap_or(0);
        let new_cumulative = self.accept(channel_id, &voucher).await?;
        let charged = new_cumulative.saturating_sub(prev);
        let deposit = self
            .store
            .get_channel(channel_id)
            .await
            .ok()
            .flatten()
            .map(|s| s.deposit)
            .unwrap_or(0);
        Ok(BatchOutcome {
            serve: true,
            response: BatchSettlementResponse {
                success: true,
                error_reason: None,
                payer: None,
                transaction: String::new(),
                network: caip2_network_for_cluster(&self.config.cluster).to_string(),
                amount: String::new(),
                charged_amount: Some(charged.to_string()),
                channel_state: Some(self.snapshot(channel_id, deposit, "open").await),
            },
        })
    }

    /// Accept a voucher off-chain via the shared core acceptance logic.
    async fn accept(&self, channel_id: &str, voucher: &BatchVoucher) -> Result<u64, Error> {
        let cumulative = voucher.cumulative()?;
        accept_voucher(
            self.store.as_ref(),
            channel_id,
            cumulative,
            voucher.expires_at,
            &voucher.signature,
            now_unix(),
            self.config.min_voucher_delta,
        )
        .await
        .map_err(Into::into)
    }

    async fn process_refund(
        &self,
        channel_id: &str,
        voucher: Option<BatchVoucher>,
    ) -> Result<BatchOutcome, Error> {
        // Accept an optional final voucher first so it settles in the close.
        if let Some(v) = &voucher {
            self.accept(channel_id, v).await?;
        }
        let sig = self.settle_and_finalize(channel_id).await?;
        let distribute_sig = self.distribute(channel_id).await?;
        self.store
            .mark_finalized(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        let deposit = self
            .store
            .get_channel(channel_id)
            .await
            .ok()
            .flatten()
            .map(|s| s.deposit)
            .unwrap_or(0);
        Ok(BatchOutcome {
            serve: false,
            response: BatchSettlementResponse {
                success: true,
                error_reason: None,
                payer: None,
                transaction: distribute_sig.unwrap_or(sig),
                network: caip2_network_for_cluster(&self.config.cluster).to_string(),
                amount: String::new(),
                charged_amount: None,
                channel_state: Some(self.snapshot(channel_id, deposit, "finalized").await),
            },
        })
    }

    /// Redeem the latest voucher of each channel on-chain, packing
    /// [`MAX_CHANNELS_PER_SETTLE_TX`] channels per transaction. Returns the
    /// broadcast signatures. Channels without an accepted voucher are skipped.
    pub async fn settle_batch(&self, channel_ids: &[String]) -> Result<Vec<String>, Error> {
        let program_id = self.program_id()?;
        let mut pending = Vec::new();
        for id in channel_ids {
            let Some(state) = self
                .store
                .get_channel(id)
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?
            else {
                continue;
            };
            let (Some(sig_b58), Some(expires_at)) = (
                state.highest_voucher_signature.as_ref(),
                state.highest_voucher_expires_at,
            ) else {
                continue; // no voucher accepted yet
            };
            if state.cumulative == 0 {
                continue;
            }
            let channel = Pubkey::from_str(&state.channel_id)
                .map_err(|e| Error::Other(format!("invalid channelId: {e}")))?;
            let signer = Pubkey::from_str(&state.authorized_signer)
                .map_err(|e| Error::Other(format!("invalid authorizedSigner: {e}")))?;
            let sig_bytes: [u8; 64] = bs58::decode(sig_b58)
                .into_vec()
                .map_err(|e| Error::Other(format!("invalid voucher signature: {e}")))?
                .try_into()
                .map_err(|_| Error::Other("voucher signature is not 64 bytes".into()))?;
            let ixs = pc::build_settle_instructions(
                &channel,
                &signer,
                &sig_bytes,
                state.cumulative,
                expires_at,
                &program_id,
            )?;
            pending.push(ixs);
        }

        let mut signatures = Vec::new();
        for chunk in pending.chunks(MAX_CHANNELS_PER_SETTLE_TX) {
            let instructions: Vec<_> = chunk.iter().flatten().cloned().collect();
            let blockhash = self
                .rpc
                .get_latest_blockhash()
                .map_err(|e| Error::Rpc(format!("blockhash fetch failed: {e}")))?;
            let message =
                Message::new_with_blockhash(&instructions, Some(&self.operator), &blockhash);
            let mut tx = Transaction::new_unsigned(message);
            self.config
                .operator_signer
                .sign_transaction(&mut tx)
                .await
                .map_err(|e| Error::Other(format!("settle signing failed: {e}")))?;
            let sig = self
                .rpc
                .send_and_confirm_transaction(&tx)
                .map_err(|e| Error::Rpc(format!("settle broadcast failed: {e}")))?;
            signatures.push(sig.to_string());
        }
        Ok(signatures)
    }

    /// Sweep a channel's accrued pool (`settled − paidOut`) to payee / splits /
    /// treasury via the program's `distribute` instruction.
    pub async fn distribute(&self, channel_id: &str) -> Result<Option<String>, Error> {
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;
        let payer = Pubkey::from_str(
            state
                .operator
                .as_deref()
                .ok_or_else(|| Error::Other("channel payer unknown".into()))?,
        )
        .map_err(|e| Error::Other(format!("invalid payer: {e}")))?;
        let channel = Pubkey::from_str(&state.channel_id)
            .map_err(|e| Error::Other(format!("invalid channelId: {e}")))?;
        let payee = Pubkey::from_str(&self.config.recipient)
            .map_err(|e| Error::Other(format!("invalid recipient: {e}")))?;
        let ix = pc::build_distribute_instruction(
            &channel,
            &payer,
            &payee,
            &pc::treasury_owner(),
            &self.mint()?,
            &self.distributions()?,
            &self.token_program()?,
            &self.program_id()?,
        );
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .map_err(|e| Error::Rpc(format!("blockhash fetch failed: {e}")))?;
        let message = Message::new_with_blockhash(&[ix], Some(&self.operator), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        self.config
            .operator_signer
            .sign_transaction(&mut tx)
            .await
            .map_err(|e| Error::Other(format!("distribute signing failed: {e}")))?;
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Rpc(format!("distribute broadcast failed: {e}")))?;
        Ok(Some(sig.to_string()))
    }

    async fn settle_and_finalize(&self, channel_id: &str) -> Result<String, Error> {
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;
        let channel = Pubkey::from_str(&state.channel_id)
            .map_err(|e| Error::Other(format!("invalid channelId: {e}")))?;
        let signer = Pubkey::from_str(&state.authorized_signer)
            .map_err(|e| Error::Other(format!("invalid authorizedSigner: {e}")))?;

        // Settle the latest accepted voucher (if any) in the finalize.
        let (sig_bytes, cumulative, expires_at) = match (
            state.highest_voucher_signature.as_ref(),
            state.highest_voucher_expires_at,
        ) {
            (Some(s), Some(exp)) if state.cumulative > 0 => {
                let arr: [u8; 64] = bs58::decode(s)
                    .into_vec()
                    .map_err(|e| Error::Other(format!("invalid voucher signature: {e}")))?
                    .try_into()
                    .map_err(|_| Error::Other("voucher signature is not 64 bytes".into()))?;
                (Some(arr), state.cumulative, exp)
            }
            _ => (None, 0, 0),
        };
        let instructions = pc::build_settle_and_finalize_instructions(
            &self.operator,
            &channel,
            &signer,
            sig_bytes.as_ref(),
            cumulative,
            expires_at,
            &self.program_id()?,
        )?;
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
            .map_err(|e| Error::Other(format!("settle_and_finalize signing failed: {e}")))?;
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Rpc(format!("settle_and_finalize broadcast failed: {e}")))?;
        Ok(sig.to_string())
    }

    fn fetch_channel(&self, channel_id: &Pubkey) -> Result<Channel, Error> {
        let data = self
            .rpc
            .get_account_data(channel_id)
            .map_err(|e| Error::Rpc(format!("channel account fetch failed: {e}")))?;
        Channel::from_bytes(&data).map_err(|e| Error::Other(format!("channel decode failed: {e}")))
    }

    async fn snapshot(&self, channel_id: &str, deposit: u64, status: &str) -> BatchChannelSnapshot {
        let cumulative = self
            .store
            .get_channel(channel_id)
            .await
            .ok()
            .flatten()
            .map(|s| s.cumulative)
            .unwrap_or(0);
        BatchChannelSnapshot {
            channel_id: channel_id.to_string(),
            deposit: deposit.to_string(),
            settled: cumulative.to_string(),
            paid_out: "0".to_string(),
            status: status.to_string(),
        }
    }
}
