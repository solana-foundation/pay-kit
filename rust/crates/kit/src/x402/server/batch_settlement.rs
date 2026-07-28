//! Server-side handler for the x402 `batch-settlement` scheme (payment-channel).
//!
//! High-throughput channel payments: the client opens an escrow channel
//! ([`X402BatchSettlement::verify_payment`] with a `deposit` payload), then signs
//! cumulative vouchers per request (`voucher` payloads) that the server accepts
//! off-chain via [`crate::core::session::accept_voucher`] and serves
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

use crate::core::payment_channels as pc;
use crate::core::payment_channels::generated::accounts::Channel;
use crate::core::session::{accept_voucher, VoucherAcceptance};
use crate::core::store::{ChannelState, ChannelStore, MemoryChannelStore, StoreError};
use crate::core::voucher::verify_voucher_signature;
use crate::core::{
    payment_channels::MAX_VOUCHER_SETTLEMENTS_PER_TX,
    settlement::packing::{pack, ChannelInstructionGroup},
};

use crate::x402::error::Error;
use crate::x402::protocol::schemes::batch_settlement::{
    check_profile, BatchChannelSnapshot, BatchExtra, BatchPayload, BatchRequiredEnvelope,
    BatchRequirements, BatchSettlementResponse, BatchSplit, BatchVoucher, BATCH_SETTLEMENT_SCHEME,
    PROFILE_PAYMENT_CHANNEL,
};
use crate::x402::protocol::schemes::exact::{
    caip2_network_for_cluster, default_rpc_url, default_token_program_for_currency,
    resolve_stablecoin_mint, ResourceInfo,
};
use crate::x402::server::upto::{
    cosign_operator_fee_payer, decode_transaction, validate_open_instruction,
};
use crate::x402::{PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, X402_VERSION_V2};

/// `ChannelStatus::Open` discriminant in the generated client.
const CHANNEL_STATUS_OPEN: u8 = 0;

/// Default forced-close grace period (seconds).
const DEFAULT_GRACE_PERIOD_SECONDS: u32 = 900;

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
        let base_units = crate::x402::server::exact::parse_units(amount, self.config.decimals)?;
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
                fee_payer: self.operator(),
                recent_blockhash: None,
                recent_slot: None,
                suggested_deposit: None,
                minimum_deposit: None,
                min_voucher_delta: (self.config.min_voucher_delta > 0)
                    .then(|| self.config.min_voucher_delta.to_string()),
                distribution_splits: splits,
            },
        })
    }

    /// Build the full 402 challenge envelope. Fetches a recent blockhash and
    /// the current slot in ONE `getLatestBlockhash` call (its response context
    /// carries the slot) — `recentSlot` is the hint clients must use as the
    /// program's `openSlot` when building the channel `open`; they never fetch
    /// a slot themselves.
    pub fn challenge(&self, amount: &str) -> Result<BatchRequiredEnvelope, Error> {
        let mut requirement = self.requirements(amount)?;
        let hint =
            crate::core::blockhash::fetch_blockhash_with_slot(&self.rpc, self.rpc.commitment())
                .map_err(|e| Error::Rpc(format!("failed to fetch recent blockhash: {e}")))?;
        requirement.extra.recent_blockhash = Some(hint.blockhash);
        requirement.extra.recent_slot = Some(hint.slot.to_string());
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
        use crate::x402::protocol::schemes::batch_settlement::BatchSignatureEnvelope;
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
    /// cooperatively settles + seals (and is not served).
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
            } => {
                self.process_voucher(&channel_id, voucher, per_request)
                    .await
            }
            BatchPayload::Refund {
                channel_id,
                voucher,
            } => self.process_refund(&channel_id, voucher).await,
        }
    }

    async fn process_deposit(
        &self,
        config: crate::x402::protocol::schemes::batch_settlement::BatchChannelConfig,
        transaction: String,
        voucher: Option<BatchVoucher>,
        per_request: u64,
    ) -> Result<BatchOutcome, Error> {
        // The first voucher (if any) pays for the request being served; reject
        // an underpriced one before opening the channel on-chain.
        if let Some(v) = &voucher {
            let charged = v.cumulative()?;
            if charged < per_request {
                return Err(Error::Other(format!(
                    "first voucher charge {charged} is below the required {per_request}"
                )));
            }
        }
        let program_id = self.program_id()?;
        let expected_mint = self.mint()?;
        let token_program = self.token_program()?;
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
        // The config's recentSlot is the program's openSlot (a PDA seed).
        let open_slot: u64 = config
            .recent_slot
            .parse()
            .map_err(|_| Error::Other(format!("invalid recentSlot: {}", config.recent_slot)))?;

        // Derive the expected channel PDA and validate the open transaction binds
        // it (SOL-drain guard) before the operator co-signs as fee payer.
        let (channel_id, _) = pc::find_channel_pda(
            &payer,
            &expected_payee,
            &expected_mint,
            &authorized_signer,
            salt,
            open_slot,
            &program_id,
        );
        let mut tx = decode_transaction(&transaction)?;
        // In `batch-settlement` the client signs vouchers, so the open's
        // authorized-signer account is the channel's `authorized_signer`
        // (the payer by default) — not the operator as in `upto`.
        validate_open_instruction(
            &tx,
            &program_id,
            // Gasless: the operator funds the rent and co-signs as fee payer, so
            // the rentPayer is the operator. The authorized_signer is the
            // channel's voucher signer (the payer in batch client mode), checked
            // independently — see the two-key rationale in `validate_open_instruction`.
            &self.operator,
            &authorized_signer,
            &payer,
            &expected_payee,
            &expected_mint,
            &token_program,
            &channel_id,
            // Deposit is validated against the on-chain channel post-broadcast
            // (batch has no single authorized maximum at open time).
            None,
            None,
            None,
            None,
            // The config's recentSlot IS the expected openSlot: the args-derived
            // PDA above already pins it exactly, and the window check keeps the
            // pre-broadcast failure mode explicit.
            Some(open_slot),
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
        // Bind the economically-relevant channel terms to what we advertised, so
        // a client can't open an under-funded channel, a different forced-close
        // window, or splits that redirect proceeds away from the payee.
        if channel.deposit < per_request {
            return Err(Error::Other(format!(
                "channel deposit {} is below one request's price {per_request}",
                channel.deposit
            )));
        }
        if channel.grace_period != self.config.grace_period_seconds {
            return Err(Error::Other(format!(
                "channel grace_period {} does not match advertised {}",
                channel.grace_period, self.config.grace_period_seconds
            )));
        }
        if channel.distribution_hash != pc::distribution_hash(&self.distributions()?) {
            return Err(Error::Other(
                "channel distribution does not match advertised splits".into(),
            ));
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
                    sealed: false,
                    highest_voucher_signature: None,
                    highest_voucher_expires_at: None,
                    close_requested_at: None,
                    // Persisted for PDA re-derivation and the reclaim gate.
                    open_slot: Some(open_slot),
                    // Stash the payer here so settlement/distribute can refund it
                    // without an extra account fetch.
                    operator: Some(pc::pubkey_string(&payer)),
                    next_delivery_sequence: 0,
                    pending_deliveries: vec![],
                    committed_deliveries: vec![],
                    lifecycle: None,
                },
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;

        // Accept the first voucher (if any) off-chain. The channel was just
        // created at cumulative 0, so the first voucher is always a fresh charge
        // (never a replay) — surface the charged amount.
        let charged = if let Some(v) = voucher {
            Some(self.accept(&channel_b58, &v).await?.charged)
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
                channel_state: Some(
                    self.snapshot(&channel_b58, channel.deposit, 0, "open")
                        .await,
                ),
            },
        })
    }

    async fn process_voucher(
        &self,
        channel_id: &str,
        voucher: BatchVoucher,
        per_request: u64,
    ) -> Result<BatchOutcome, Error> {
        let prev = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .map(|s| s.cumulative)
            .unwrap_or(0);
        // The voucher must pay at least the advertised price for this request.
        // Checked before `accept` so an underpriced voucher — or an idempotent
        // replay of the latest voucher (delta 0), which would otherwise serve
        // the route again for free — is rejected without advancing the
        // watermark.
        if voucher.cumulative()?.saturating_sub(prev) < per_request {
            return Err(Error::Other(format!(
                "voucher charge {} is below the required {per_request}",
                voucher.cumulative()?.saturating_sub(prev)
            )));
        }
        let acceptance = self.accept(channel_id, &voucher).await?;
        let charged = acceptance.charged;
        // An idempotent replay (charged == 0) is NOT a fresh paid serve: the
        // route was already paid for on the original voucher. The price check
        // above rejects replays whenever `per_request > 0`; this guards the
        // `per_request == 0` edge so a replay can never re-serve for free.
        let serve = !acceptance.replay;
        let deposit = self
            .store
            .get_channel(channel_id)
            .await
            .ok()
            .flatten()
            .map(|s| s.deposit)
            .unwrap_or(0);
        Ok(BatchOutcome {
            serve,
            response: BatchSettlementResponse {
                success: true,
                error_reason: None,
                payer: None,
                transaction: String::new(),
                network: caip2_network_for_cluster(&self.config.cluster).to_string(),
                amount: String::new(),
                charged_amount: Some(charged.to_string()),
                channel_state: Some(self.snapshot(channel_id, deposit, 0, "open").await),
            },
        })
    }

    /// Accept a voucher off-chain via the shared core acceptance logic.
    ///
    /// Returns the full [`VoucherAcceptance`] so callers can distinguish a fresh
    /// charge from an idempotent replay (`charged == 0`, `replay == true`) and
    /// never grant a fresh paid serve for a replay. The settlement window is the
    /// configured forced-close grace period: a non-zero voucher expiry must
    /// outlast it so the voucher can still settle on-chain after the async
    /// forced-close delay.
    async fn accept(
        &self,
        channel_id: &str,
        voucher: &BatchVoucher,
    ) -> Result<VoucherAcceptance, Error> {
        let cumulative = voucher.cumulative()?;
        accept_voucher(
            self.store.as_ref(),
            channel_id,
            cumulative,
            voucher.expires_at,
            &voucher.signature,
            now_unix(),
            self.config.min_voucher_delta,
            self.config.grace_period_seconds as i64,
        )
        .await
        .map_err(Into::into)
    }

    async fn process_refund(
        &self,
        channel_id: &str,
        voucher: Option<BatchVoucher>,
    ) -> Result<BatchOutcome, Error> {
        // A refund cooperatively closes the channel and bypasses the route, so
        // it must prove control of the channel: the request has to carry a
        // voucher signed by the channel's authorized signer. The channel id
        // travels in every voucher header and is not secret, so without this
        // anyone who observes one could force a close and evict the client.
        let voucher = voucher.ok_or_else(|| {
            Error::Other(
                "refund requires a voucher signed by the channel's authorized signer".into(),
            )
        })?;
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;
        let cumulative = voucher.cumulative()?;
        if cumulative > state.cumulative {
            // Advances the watermark: accept it so the final amount settles in
            // the close. `accept` verifies the signature against the signer.
            self.accept(channel_id, &voucher).await?;
        } else {
            // Proof-of-ownership only (at or below the watermark — nothing to
            // advance): still verify the signature to authorize the close.
            verify_voucher_signature(
                channel_id,
                cumulative,
                voucher.expires_at,
                &voucher.signature,
                &state.authorized_signer,
                now_unix(),
                self.config.grace_period_seconds as i64,
            )?;
        }

        // Freeze the channel before any on-chain work. Once `close_requested_at`
        // is set, `accept_voucher` rejects further vouchers, so a concurrent
        // request can no longer advance the watermark past what
        // `settle_and_seal` is about to read — an advance that would
        // otherwise be accepted off-chain yet be unrecoverable on-chain after
        // the channel is sealed at the earlier watermark.
        let frozen = self
            .store
            .update_channel(
                channel_id,
                Box::new(|s| {
                    let mut state =
                        s.ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?;
                    state.close_requested_at.get_or_insert(now_unix() as u64);
                    Ok(state)
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;

        let sig = self.settle_and_seal(channel_id).await?;
        // Skip the sweep when nothing was ever settled — `distribute` would just
        // broadcast a second transaction that moves zero, wasting fees.
        let distribute_sig = if frozen.cumulative > 0 {
            self.distribute(channel_id).await?
        } else {
            None
        };
        self.store
            .mark_sealed(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        // `distribute` sweeps the full settled pool, so once it lands the
        // on-chain `paidOut` equals the settled watermark.
        let paid_out = if distribute_sig.is_some() {
            frozen.cumulative
        } else {
            0
        };
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
                channel_state: Some(
                    self.snapshot(channel_id, frozen.deposit, paid_out, "sealed")
                        .await,
                ),
            },
        })
    }

    /// Redeem the latest voucher of each channel on-chain, packing channels into
    /// `<=1232`-byte transactions via the shared
    /// [`crate::core::settlement::packing::pack`]. Returns the broadcast
    /// signatures. Channels without an accepted voucher are skipped.
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
            // An expired voucher can never settle on-chain; skip it so it can't
            // fail — and atomically abort — a transaction it shares with
            // still-valid channels.
            if expires_at <= now_unix() {
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
            pending.push(ChannelInstructionGroup {
                channel_id: state.channel_id.clone(),
                instructions: ixs,
            });
        }

        // Shared, byte-bounded packing (same as the mpp settlement worker) —
        // groups channels into <=1232-byte legacy transactions.
        let mut signatures = Vec::new();
        for group in pack(pending, &self.operator, MAX_VOUCHER_SETTLEMENTS_PER_TX) {
            let instructions: Vec<_> = group.into_iter().flat_map(|c| c.instructions).collect();
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
            // rentPayer is pinned to the operator (the fee payer).
            &self.operator,
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

    async fn settle_and_seal(&self, channel_id: &str) -> Result<String, Error> {
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

        // Settle the latest accepted voucher (if any) in the seal.
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
        let instructions = pc::build_settle_and_seal_instructions(
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
            .map_err(|e| Error::Other(format!("settle_and_seal signing failed: {e}")))?;
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Rpc(format!("settle_and_seal broadcast failed: {e}")))?;
        Ok(sig.to_string())
    }

    fn fetch_channel(&self, channel_id: &Pubkey) -> Result<Channel, Error> {
        let data = self
            .rpc
            .get_account_data(channel_id)
            .map_err(|e| Error::Rpc(format!("channel account fetch failed: {e}")))?;
        Channel::from_bytes(&data).map_err(|e| Error::Other(format!("channel decode failed: {e}")))
    }

    /// Build a channel snapshot for a settlement response.
    ///
    /// `paid_out` is the amount the server has swept on-chain via `distribute`
    /// (`0` while the channel is open / un-swept). It is the server's own
    /// accounting, not a fresh read of the on-chain `paidOut`.
    async fn snapshot(
        &self,
        channel_id: &str,
        deposit: u64,
        paid_out: u64,
        status: &str,
    ) -> BatchChannelSnapshot {
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
            paid_out: paid_out.to_string(),
            status: status.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::client::batch_settlement::sign_voucher;
    use ed25519_dalek::SigningKey;
    use solana_keychain::memory::MemorySigner;

    const FAR_FUTURE: i64 = 4_102_444_800; // 2100-01-01

    fn memory_signer(seed: u8) -> MemorySigner {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        MemorySigner::from_bytes(&sk.to_keypair_bytes()).unwrap()
    }

    fn handler(store: Arc<MemoryChannelStore>) -> X402BatchSettlement {
        let config = BatchConfig::new(
            "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "devnet",
            Arc::new(memory_signer(1)),
        );
        X402BatchSettlement::with_store(config, store).unwrap()
    }

    fn seeded_state(channel_id: &str, authorized_signer: &str, cumulative: u64) -> ChannelState {
        ChannelState {
            channel_id: channel_id.to_string(),
            authorized_signer: authorized_signer.to_string(),
            deposit: 1_000_000,
            cumulative,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            open_slot: None,
            operator: None,
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
            lifecycle: None,
        }
    }

    // A steady-state voucher whose delta is below the advertised price must be
    // rejected — and must not advance the watermark.
    #[tokio::test]
    async fn underpriced_voucher_is_rejected_without_advancing() {
        let owner = memory_signer(4);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);

        let store = Arc::new(MemoryChannelStore::new());
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 0),
            )
            .await
            .unwrap();

        // Route priced at 100; voucher only advances by 1.
        let voucher = sign_voucher(&owner, &channel, 1, FAR_FUTURE).await.unwrap();
        let result = handler(store.clone())
            .process_voucher(&channel_b58, voucher, 100)
            .await;
        assert!(result.is_err());
        assert_eq!(
            store
                .get_channel(&channel_b58)
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            0,
            "watermark must not advance for a rejected voucher"
        );
    }

    // Replaying the latest voucher (delta 0) must not grant another free serve.
    #[tokio::test]
    async fn replayed_voucher_is_rejected() {
        let owner = memory_signer(5);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);

        let store = Arc::new(MemoryChannelStore::new());
        // Watermark already at 100 (a prior voucher was accepted).
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 100),
            )
            .await
            .unwrap();

        let replay = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let result = handler(store)
            .process_voucher(&channel_b58, replay, 100)
            .await;
        assert!(result.is_err());
    }

    // Even for a free route (per_request == 0) — where the price check cannot
    // reject a delta-0 replay — an exact idempotent replay of the latest voucher
    // must NOT be treated as a fresh paid serve (`serve == false`, charged 0).
    #[tokio::test]
    async fn idempotent_replay_is_accepted_but_not_served() {
        let owner = memory_signer(6);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);

        let store = Arc::new(MemoryChannelStore::new());
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 0),
            )
            .await
            .unwrap();
        let h = handler(store.clone());

        // First voucher: a fresh charge on a free route → served.
        let v1 = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let first = h
            .process_voucher(&channel_b58, v1.clone(), 0)
            .await
            .unwrap();
        assert!(first.serve, "fresh charge must be served");
        assert_eq!(first.response.charged_amount.as_deref(), Some("100"));

        // Exact replay (same cumulative + same signature): accepted as a no-op
        // but not served, and it must not charge again or advance the watermark.
        let replay = h.process_voucher(&channel_b58, v1, 0).await.unwrap();
        assert!(!replay.serve, "idempotent replay must not be a fresh serve");
        assert_eq!(replay.response.charged_amount.as_deref(), Some("0"));
        assert_eq!(
            store
                .get_channel(&channel_b58)
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            100,
            "replay must not advance the watermark"
        );
    }

    // A refund with no voucher carries no proof of ownership and must be
    // rejected before any on-chain work (no RPC is reachable in this test).
    #[tokio::test]
    async fn refund_without_voucher_is_rejected() {
        let store = Arc::new(MemoryChannelStore::new());
        let result = handler(store).process_refund("Chan1", None).await;
        assert!(result.is_err());
    }

    // A refund whose voucher is signed by a key other than the channel's
    // authorized signer must be rejected, and must not freeze the channel.
    #[tokio::test]
    async fn refund_with_unauthorized_signer_is_rejected() {
        let owner = memory_signer(2);
        let attacker = memory_signer(3);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);

        let store = Arc::new(MemoryChannelStore::new());
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 0),
            )
            .await
            .unwrap();

        let forged = sign_voucher(&attacker, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let result = handler(store.clone())
            .process_refund(&channel_b58, Some(forged))
            .await;
        assert!(result.is_err());

        // The rejected attempt left the channel open.
        let state = store.get_channel(&channel_b58).await.unwrap().unwrap();
        assert!(state.close_requested_at.is_none());
        assert!(!state.sealed);
    }
}
