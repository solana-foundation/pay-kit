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

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex as AsyncMutex;

use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::Transaction;

use crate::core::payment_channels as pc;
use crate::core::payment_channels::generated::accounts::Channel;
use crate::core::session::{accept_voucher, VoucherAcceptance};
use crate::core::settlement::packing::{pack, ChannelInstructions, DEFAULT_MAX_CHANNELS_PER_TX};
use crate::core::store::{ChannelState, ChannelStore, MemoryChannelStore, StoreError};
use crate::core::voucher::verify_voucher_signature;

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
use crate::x402::server::MAX_PAYMENT_SIGNATURE_HEADER_LEN;
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
    /// Per-channel serialization gates. A voucher acceptance must decide `serve`
    /// on the watermark delta it actually *commits*, not on a watermark read
    /// before the commit. Two concurrent vouchers on one channel would otherwise
    /// each read the same stale watermark, both compute a `>= price` delta from
    /// it, and both be served while only the larger cumulative is committed —
    /// under-paying for one served request. Holding this per-channel gate across
    /// the read → price-gate → accept span serializes those requests so the read
    /// is the in-lock prior watermark and the committed delta is authoritative.
    ///
    /// Entries are refcounted and evicted once no holder or waiter remains
    /// (see [`X402BatchSettlement::voucher_gate`] / [`VoucherGate`]), so an
    /// unauthenticated client posting vouchers with random channel ids cannot
    /// grow this map without bound.
    voucher_gates: Arc<Mutex<HashMap<String, GateEntry>>>,
    /// Test-only seam: fires in `process_deposit` after the fresh channel is
    /// written (`put_channel`, watermark 0) but before the first voucher is
    /// accepted — the exact window a concurrent voucher must not be able to
    /// interleave into. A test parks the deposit here and drives a concurrent
    /// voucher's acceptance to prove the deposit holds the per-channel gate
    /// across the watermark write and the first accept.
    #[cfg(test)]
    post_put_hook: Arc<Mutex<Option<PreGateHook>>>,
    /// Test-only seam: fires in `process_voucher` after the in-lock prior
    /// watermark (`prev`) is read but before the price gate and accept — i.e.
    /// with the per-channel gate held. A test parks a voucher here (holding the
    /// gate) so a concurrent voucher on the same channel is forced to wait,
    /// proving the gate serializes the read → price-gate → accept span. When the
    /// gate lock is removed the concurrent voucher instead interleaves and reads
    /// the same stale watermark, changing the serve outcome.
    #[cfg(test)]
    post_read_hook: Arc<Mutex<Option<PreGateHook>>>,
}

/// A refcounted per-channel serialization gate entry. `refs` counts holders plus
/// waiters and is guarded by [`X402BatchSettlement::voucher_gates`]'s outer
/// `Mutex`, so the last releaser observing `refs == 0` can evict the map entry.
struct GateEntry {
    lock: Arc<AsyncMutex<()>>,
    refs: usize,
}

/// Guard returned by [`X402BatchSettlement::voucher_gate`]. Holds the acquired
/// `Arc<AsyncMutex>` so the caller can `.lock().await` it, and on drop
/// decrements the entry's refcount under the map lock — evicting the entry once
/// no holder or waiter remains. Mirrors Go's acquireChannelLock /
/// releaseChannelLock so the gate map stays bounded by the number of
/// concurrently active channels rather than every channel id ever seen.
struct VoucherGate {
    gates: Arc<Mutex<HashMap<String, GateEntry>>>,
    channel_id: String,
    lock: Arc<AsyncMutex<()>>,
}

impl VoucherGate {
    /// The `Arc<AsyncMutex>` to `.lock().await` for the serialized section.
    fn lock(&self) -> &Arc<AsyncMutex<()>> {
        &self.lock
    }
}

impl Drop for VoucherGate {
    fn drop(&mut self) {
        let mut gates = self.gates.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = gates.get_mut(&self.channel_id) {
            entry.refs -= 1;
            // Evict only when this is still the same entry we bumped — a late
            // acquirer that recreated the entry after eviction owns a distinct
            // `Arc`, so compare by pointer identity before deleting.
            if entry.refs == 0 && Arc::ptr_eq(&entry.lock, &self.lock) {
                gates.remove(&self.channel_id);
            }
        }
    }
}

/// Test-only seam payload for the `post_put_hook` / `post_read_hook` seams: the
/// call that consumes the hook signals `entered` (so the test knows it reached
/// the seam) and then parks on `release` until the test drops its guard.
#[cfg(test)]
struct PreGateHook {
    entered: tokio::sync::oneshot::Sender<()>,
    release: Arc<AsyncMutex<()>>,
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
            voucher_gates: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            post_put_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            post_read_hook: Arc::new(Mutex::new(None)),
        })
    }

    /// Acquire (or create) the per-channel serialization gate for `channel_id`,
    /// bumping its refcount so a concurrent releaser cannot evict the entry
    /// while this caller is still queued on it. Returns a [`VoucherGate`] guard
    /// that decrements the refcount on drop and evicts the entry once idle, so
    /// the gate map never grows with channel ids that no request currently
    /// holds. The caller `.lock().await`s the returned guard for the serialized
    /// section. The (potentially contended) async lock is taken outside the
    /// outer map `Mutex`, so the `std::sync::Mutex` is never held across `.await`.
    fn voucher_gate(&self, channel_id: &str) -> VoucherGate {
        let lock = {
            let mut gates = self.voucher_gates.lock().unwrap_or_else(|e| e.into_inner());
            let entry = gates
                .entry(channel_id.to_string())
                .or_insert_with(|| GateEntry {
                    lock: Arc::new(AsyncMutex::new(())),
                    refs: 0,
                });
            entry.refs += 1;
            entry.lock.clone()
        };
        VoucherGate {
            gates: self.voucher_gates.clone(),
            channel_id: channel_id.to_string(),
            lock,
        }
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
        use crate::x402::protocol::schemes::batch_settlement::BatchSignatureEnvelope;
        // Cap the header before any base64 / JSON work, matching the `exact` and
        // `upto` parsers' 16 KiB `MAX_PAYMENT_SIGNATURE_HEADER_LEN`. A
        // batch-settlement header additionally embeds a full base64 transaction,
        // so without this an oversized credential header drives proportionally
        // larger decode + parse work.
        if header.len() > MAX_PAYMENT_SIGNATURE_HEADER_LEN {
            return Err(Error::InvalidPaymentRequired(format!(
                "PAYMENT-SIGNATURE header exceeds maximum length of {MAX_PAYMENT_SIGNATURE_HEADER_LEN} bytes"
            )));
        }
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

        // Serialize the watermark write and the first-voucher accept under the
        // per-channel gate. Without holding it, a concurrent `process_voucher`
        // could acquire the gate, read this fresh channel's watermark (0), pass
        // the price gate and commit a larger cumulative between our `put_channel`
        // and our first accept — leaving both the deposit and the voucher served
        // for a combined committed delta below two requests' price. Holding the
        // gate across both makes the deposit's write and first accept atomic with
        // respect to concurrent voucher acceptances on this channel.
        let gate = self.voucher_gate(&channel_b58);
        let _held = gate.lock().lock().await;

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

        // Test-only seam: fires with the gate held, after the fresh channel is
        // written but before the first voucher is accepted — the exact window a
        // concurrent voucher must not be able to interleave into.
        #[cfg(test)]
        {
            let hook = self
                .post_put_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                let _ = hook.entered.send(());
                let _ = hook.release.lock().await;
            }
        }

        // Accept the first voucher (if any) off-chain. The channel was just
        // created at cumulative 0, so the first voucher is always a fresh charge
        // (never a replay) — surface the charged amount.
        let charged = if let Some(v) = voucher {
            Some(self.accept(&channel_b58, &v).await?.charged)
        } else {
            None
        };
        drop(_held);
        drop(gate);

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
        // Serialize acceptances on this channel so the watermark that gates the
        // price and the paid serve is the in-lock prior watermark this voucher
        // commits against. Without this, two concurrent vouchers could both read
        // the same stale watermark before either commits, both pass the price
        // gate, and both be served while only the larger cumulative is committed
        // — under-paying for one served request.
        let gate = self.voucher_gate(channel_id);
        let _held = gate.lock().lock().await;

        let prev = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .map(|s| s.cumulative)
            .unwrap_or(0);

        // Test-only seam: fires with the gate held, after the in-lock `prev`
        // read but before the price gate and accept, so a test can park this
        // voucher here and prove a concurrent voucher on the same channel is
        // forced to wait for the gate rather than racing the read.
        #[cfg(test)]
        {
            let hook = self
                .post_read_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                let _ = hook.entered.send(());
                let _ = hook.release.lock().await;
            }
        }

        // The voucher must pay at least the advertised price for this request.
        // Checked before `accept` so an underpriced voucher — or an idempotent
        // replay of the latest voucher (delta 0), which would otherwise serve
        // the route again for free — is rejected without advancing the
        // watermark. `prev` is the in-lock prior watermark (the gate is held), so
        // a concurrent voucher cannot make this delta stale.
        if voucher.cumulative()?.saturating_sub(prev) < per_request {
            return Err(Error::Other(format!(
                "voucher charge {} is below the required {per_request}",
                voucher.cumulative()?.saturating_sub(prev)
            )));
        }
        let acceptance = self.accept(channel_id, &voucher).await?;
        // Gate `serve` on the delta this voucher actually committed against the
        // in-lock prior watermark — NOT on `acceptance.charged`, which is derived
        // from a pre-lock snapshot and overstates the delta when a concurrent
        // voucher advanced the watermark between the snapshot and the commit.
        // Because the per-channel gate is held across the read and the accept,
        // `prev` is the authoritative prior watermark, so this delta is the true
        // committed increment.
        let committed_delta = acceptance.cumulative.saturating_sub(prev);
        let charged = committed_delta;
        // A fresh paid serve requires committing at least one request's price and
        // not being an idempotent replay. An idempotent replay (`replay == true`,
        // delta 0) is NOT a fresh paid serve: the route was already paid for on
        // the original voucher. The `!replay` clause also guards the
        // `per_request == 0` edge so a replay can never re-serve for free.
        let serve = !acceptance.replay && committed_delta >= per_request;
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
        // `settle_and_finalize` is about to read — an advance that would
        // otherwise be accepted off-chain yet be unrecoverable on-chain after
        // the channel is finalized at the earlier watermark.
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

        let sig = self.settle_and_finalize(channel_id).await?;
        // Skip the sweep when nothing was ever settled — `distribute` would just
        // broadcast a second transaction that moves zero, wasting fees.
        let distribute_sig = if frozen.cumulative > 0 {
            self.distribute(channel_id).await?
        } else {
            None
        };
        self.store
            .mark_finalized(channel_id)
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
                    self.snapshot(channel_id, frozen.deposit, paid_out, "finalized")
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
            pending.push(ChannelInstructions {
                channel_id: state.channel_id.clone(),
                instructions: ixs,
            });
        }

        // Shared, byte-bounded packing (same as the mpp settlement worker) —
        // groups channels into <=1232-byte legacy transactions.
        let mut signatures = Vec::new();
        for group in pack(pending, &self.operator, DEFAULT_MAX_CHANNELS_PER_TX) {
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
    use crate::generated::payment_channels::generated::types::SettlementWatermarks;
    use crate::x402::client::batch_settlement::{build_deposit, encode_batch_header, sign_voucher};
    use crate::x402::server::mock_rpc::MockRpc;
    use ed25519_dalek::SigningKey;
    use solana_keychain::memory::MemorySigner;

    const FAR_FUTURE: i64 = 4_102_444_800; // 2100-01-01

    /// The payment-channels program id (owner of a channel account).
    fn program_id_b58() -> String {
        pc::pubkey_string(&pc::default_program_id())
    }

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

    /// A handler whose RPC points at the mock and whose operator/recipient are
    /// the given signers. The recipient (channel payee) is a fresh key so the
    /// deposit derives a stable PDA. `splits` are the merchant distribution
    /// splits committed at open.
    fn handler_with_rpc(
        rpc_url: String,
        operator: Arc<dyn SolanaSigner>,
        recipient: &Pubkey,
        store: Arc<dyn ChannelStore>,
        splits: Vec<(String, u16)>,
    ) -> X402BatchSettlement {
        let mut config = BatchConfig::new(pc::pubkey_string(recipient), "devnet", operator);
        config.rpc_url = Some(rpc_url);
        config.splits = splits;
        X402BatchSettlement::with_store(config, store).unwrap()
    }

    /// A borsh-serialized on-chain `Channel` account for the mock to return.
    /// Every economically-relevant field is a parameter so a test can flip one
    /// to exercise a specific bind-time mismatch branch.
    #[allow(clippy::too_many_arguments)]
    fn channel_bytes(
        status: u8,
        deposit: u64,
        grace_period: u32,
        payer: &Pubkey,
        payee: &Pubkey,
        authorized_signer: &Pubkey,
        mint: &Pubkey,
        distribution_hash: [u8; 32],
    ) -> Vec<u8> {
        let channel = Channel {
            discriminator: 0,
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
            grace_period,
            distribution_hash,
            payer: pc::to_address(payer),
            payee: pc::to_address(payee),
            authorized_signer: pc::to_address(authorized_signer),
            mint: pc::to_address(mint),
            rent_payer: pc::to_address(&Pubkey::new_unique()),
        };
        borsh::to_vec(&channel).unwrap()
    }

    fn seeded_state(channel_id: &str, authorized_signer: &str, cumulative: u64) -> ChannelState {
        ChannelState {
            channel_id: channel_id.to_string(),
            authorized_signer: authorized_signer.to_string(),
            deposit: 1_000_000,
            cumulative,
            finalized: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            operator: None,
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
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

    // ── Concurrency: the paid serve must be gated on the in-lock committed delta ─
    //
    // Two vouchers on one channel (cumulative 100 and 150, priced at 100, from a
    // zero watermark) commit a combined delta of 150 — one-and-a-half requests'
    // worth. Only one may be served. The bug: `process_voucher` decided `serve`
    // from a watermark read *before* the commit, so both vouchers read the same
    // stale `0`, both computed a `>= price` delta, and both were served while only
    // 150 total was committed — the second request was served for 50.

    // Deterministic regression guard that genuinely gates the per-channel lock.
    //
    // The seam parks voucher B (cumulative 150) *inside* the gate — after B has
    // read the prior watermark (0) but before it accepts — so B holds the gate
    // while parked. Voucher A (cumulative 100) then races on the same channel:
    //
    //   * With the gate: A blocks acquiring it. When B is released, B accepts
    //     from prev 0 (150 >= price 100) and is served, then A acquires the gate,
    //     reads the in-lock prior watermark of 150, and its increment (100 - 150
    //     saturates to 0 < 100) is refused — exactly one request served.
    //   * Without the gate lock: A does not block. It reads the same stale
    //     watermark of 0, commits 100, and is served *concurrently* with B, which
    //     also read 0 and commits 150 — two requests served for a combined 150.
    //
    // So deleting `let _held = gate.lock().lock().await` flips the served count
    // from 1 to 2 and fails this test. `A` is given a bounded head start to reach
    // (and, with the fix, block on) the gate before B is released; with the fix
    // no sleep can unblock A, and without it A completes its in-memory accept in
    // microseconds, so the outcome is deterministic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_voucher_not_served_when_gate_serializes_accept() {
        let owner = memory_signer(7);
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

        // Arm the in-lock seam: the voucher that takes it has already read the
        // prior watermark and holds the gate; it signals `entered`, then parks on
        // `release` until the test drops its guard.
        let release = Arc::new(AsyncMutex::new(()));
        let release_guard = release.clone().lock_owned().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        *h.post_read_hook.lock().unwrap() = Some(PreGateHook {
            entered: entered_tx,
            release: release.clone(),
        });

        // Spawn B (cumulative 150). It acquires the gate, reads prev 0, consumes
        // the seam, and parks — holding the gate.
        let voucher_b = sign_voucher(&owner, &channel, 150, FAR_FUTURE)
            .await
            .unwrap();
        let (hb, cb) = (h.clone(), channel_b58.clone());
        let task_b = tokio::spawn(async move { hb.process_voucher(&cb, voucher_b, 100).await });
        entered_rx.await.unwrap();

        // Spawn A (cumulative 100). With the gate it blocks on acquisition; the
        // bounded sleep gives it time to either commit (no gate) or park on the
        // lock (fix).
        let voucher_a = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let (ha, ca) = (h.clone(), channel_b58.clone());
        let task_a = tokio::spawn(async move { ha.process_voucher(&ca, voucher_a, 100).await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Release B and join both.
        drop(release_guard);
        let outcome_b = task_b.await.unwrap();
        let outcome_a = task_a.await.unwrap();

        // Count paid serves. With the gate this is exactly 1; deleting the gate
        // lock lets both A and B decide `serve` off the stale watermark of 0.
        let served = [outcome_a, outcome_b]
            .into_iter()
            .flatten()
            .filter(|o| o.serve)
            .count();
        assert_eq!(
            served, 1,
            "the per-channel gate must serialize accept so only one request is served"
        );

        // The channel advanced to 150 (B's cumulative), never past it.
        assert_eq!(
            store
                .get_channel(&channel_b58)
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            150,
            "the watermark must be the larger cumulative, committed exactly once"
        );
    }

    // Stochastic guard: race two concurrent vouchers (cumulative 100 and 150,
    // priced at 100) from a zero watermark, many times, over a multi-thread
    // runtime. Whatever the scheduling, at most one may be served, and any served
    // voucher must have committed a delta of at least the price. This catches a
    // regression that the deterministic seam's fixed ordering would miss.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_vouchers_serve_at_most_one_paid_request() {
        for iter in 0..64u8 {
            let owner = memory_signer(8);
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

            let v100 = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
                .await
                .unwrap();
            let v150 = sign_voucher(&owner, &channel, 150, FAR_FUTURE)
                .await
                .unwrap();

            let (h1, c1) = (h.clone(), channel_b58.clone());
            let (h2, c2) = (h.clone(), channel_b58.clone());
            let t1 = tokio::spawn(async move { h1.process_voucher(&c1, v100, 100).await });
            let t2 = tokio::spawn(async move { h2.process_voucher(&c2, v150, 100).await });
            let (r1, r2) = (t1.await.unwrap(), t2.await.unwrap());

            // Count served requests; every served request must have committed at
            // least the price. A served request reports its committed delta as
            // `charged_amount`.
            let mut served = 0;
            for outcome in [r1, r2].into_iter().flatten() {
                if outcome.serve {
                    served += 1;
                    let charged: u64 = outcome
                        .response
                        .charged_amount
                        .as_deref()
                        .unwrap_or("0")
                        .parse()
                        .unwrap();
                    assert!(
                        charged >= 100,
                        "iter {iter}: a served voucher committed only {charged} (< price 100)"
                    );
                }
            }
            assert!(
                served <= 1,
                "iter {iter}: {served} requests served for a combined 150 committed (price 100)"
            );
        }
    }

    // ── Gate-map eviction: unauthenticated vouchers must not leak gate entries ─
    //
    // `process_voucher` acquires the per-channel gate before it can learn the
    // channel does not exist. A client posting vouchers with random, nonexistent
    // channel ids must not grow the gate map: each gate entry is refcounted and
    // evicted once the request that created it drops its guard, so the map
    // returns to empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn voucher_gate_map_evicts_entries_for_nonexistent_channels() {
        let owner = memory_signer(41);
        let store = Arc::new(MemoryChannelStore::new());
        let h = handler(store);

        // Post vouchers against many distinct channel ids that were never opened.
        for _ in 0..32u32 {
            let channel = Pubkey::new_unique();
            let channel_b58 = pc::pubkey_string(&channel);
            let voucher = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
                .await
                .unwrap();
            // The channel does not exist in the store, so `prev` reads 0 and the
            // accept fails (or the serve is a no-op); either way the request
            // returns and its gate guard is dropped.
            let _ = h.process_voucher(&channel_b58, voucher, 100).await;
        }

        // Every gate entry must have been evicted once its request finished: the
        // grow-only map (pre-fix) would hold 32 entries here.
        let remaining = h
            .voucher_gates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert_eq!(
            remaining, 0,
            "gate entries for nonexistent channels must be evicted, found {remaining}"
        );
    }

    // A contended gate entry is evicted once the last holder releases it: two
    // vouchers race on one channel, and after both finish the map is empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn voucher_gate_map_evicts_contended_entry_after_last_release() {
        let owner = memory_signer(42);
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
        let h = handler(store);

        let v100 = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let v150 = sign_voucher(&owner, &channel, 150, FAR_FUTURE)
            .await
            .unwrap();
        let (h1, c1) = (h.clone(), channel_b58.clone());
        let (h2, c2) = (h.clone(), channel_b58.clone());
        let t1 = tokio::spawn(async move { h1.process_voucher(&c1, v100, 100).await });
        let t2 = tokio::spawn(async move { h2.process_voucher(&c2, v150, 100).await });
        let _ = t1.await.unwrap();
        let _ = t2.await.unwrap();

        let remaining = h
            .voucher_gates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert_eq!(
            remaining, 0,
            "a contended gate entry must be evicted once its last holder releases, found {remaining}"
        );
    }

    // ── Header cap: an oversized PAYMENT-SIGNATURE header is rejected up front ─
    //
    // A batch-settlement header additionally embeds a full base64 transaction, so
    // an unbounded header drives proportionally large base64 + JSON work. Cap it
    // at 16 KiB before any decode, matching the `exact` / `upto` parsers.
    #[test]
    fn parse_payment_rejects_oversized_header() {
        let h = handler(Arc::new(MemoryChannelStore::new()));
        // 16 KiB + 1 byte: one over the cap.
        let header = "A".repeat(16 * 1024 + 1);
        assert_eq!(header.len(), 16 * 1024 + 1);
        let err = h
            .parse_payment(&header)
            .expect_err("oversized header must be rejected");
        assert!(
            err.to_string().contains("exceeds maximum length"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_payment_accepts_at_max_header_size() {
        // A header of exactly 16 KiB must pass the size gate. Its contents are
        // not valid base64 JSON, so it still fails — but with a decode/parse
        // error, NOT the size error. This pins the boundary at exactly the cap.
        let h = handler(Arc::new(MemoryChannelStore::new()));
        let at_max = "A".repeat(16 * 1024);
        assert_eq!(at_max.len(), 16 * 1024);
        let err = h
            .parse_payment(&at_max)
            .expect_err("invalid payload still errors");
        assert!(
            !err.to_string().contains("exceeds maximum length"),
            "size gate must not fire at exactly the cap: {err}"
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
        assert!(!state.finalized);
    }

    // ── Deposit (open broadcast + on-chain bind) against a mock JSON-RPC ─────
    //
    // `process_deposit` is the module's biggest RPC-touching path: it broadcasts
    // the client-signed open, confirms it, reads the channel back, and binds
    // every economically-relevant field. These tests point the handler's RPC at
    // the in-process mock and drive the whole path through a real client-built
    // deposit payload, then flip individual on-chain fields to exercise each
    // bind-time mismatch branch.

    /// End-to-end deposit fixture: a mock RPC, a client-built deposit header,
    /// and the derived channel PDA. `first_charge` seeds the first voucher.
    struct DepositFixture {
        mock: MockRpc,
        handler: X402BatchSettlement,
        header: String,
        channel_id: Pubkey,
        payer: Pubkey,
        /// The channel's authorized signer (== payer in batch mode); a test can
        /// sign additional vouchers for this channel with it.
        payer_signer: MemorySigner,
        recipient: Pubkey,
        mint: Pubkey,
        amount: String,
    }

    async fn deposit_fixture(deposit: u64, first_charge: u64) -> DepositFixture {
        let mock = MockRpc::start();
        let operator = memory_signer(20);
        let payer_signer = memory_signer(21);
        let recipient = Pubkey::new_unique();
        let store: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::new());
        let handler = handler_with_rpc(mock.url(), Arc::new(operator), &recipient, store, vec![]);

        let amount = "0.10".to_string();
        // Build the requirement the server advertises, stamp a blockhash the
        // client needs to sign the open, then let the client build the deposit.
        let mut requirements = handler.requirements(&amount).unwrap();
        requirements.extra.recent_blockhash = Some("11111111111111111111111111111111".to_string());
        let (channel_id, payload) = build_deposit(
            &payer_signer,
            &requirements,
            deposit,
            first_charge,
            FAR_FUTURE,
        )
        .await
        .unwrap();
        let header = encode_batch_header(&requirements, payload).unwrap();

        let mint = handler.mint().unwrap();
        DepositFixture {
            mock,
            handler,
            header,
            channel_id,
            payer: payer_signer.pubkey(),
            payer_signer,
            recipient,
            mint,
            amount,
        }
    }

    /// Bind an on-chain channel account matching the fixture's expectations.
    fn bind_matching_channel(f: &DepositFixture, deposit: u64) {
        let dist_hash = pc::distribution_hash(&[]);
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            channel_bytes(
                CHANNEL_STATUS_OPEN,
                deposit,
                DEFAULT_GRACE_PERIOD_SECONDS,
                &f.payer,
                &f.recipient,
                &f.payer, // authorized_signer == payer in batch mode
                &f.mint,
                dist_hash,
            ),
            &program_id_b58(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_opens_channel_and_accepts_first_voucher() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        bind_matching_channel(&f, 1_000_000);

        let outcome = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap();
        assert!(outcome.serve, "a paid deposit must be served");
        assert!(outcome.response.success);
        assert_eq!(
            outcome.response.payer.as_deref(),
            Some(pc::pubkey_string(&f.payer).as_str())
        );
        // The first voucher (100_000) was accepted off-chain.
        assert_eq!(outcome.response.charged_amount.as_deref(), Some("100000"));
        assert_eq!(outcome.response.amount, "1000000");
        // Channel state persisted with the confirmed deposit.
        let state = f
            .handler
            .store
            .get_channel(&pc::pubkey_string(&f.channel_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.deposit, 1_000_000);
        assert_eq!(state.cumulative, 100_000);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_without_first_voucher_opens_channel() {
        let f = deposit_fixture(1_000_000, 0).await;
        bind_matching_channel(&f, 1_000_000);
        let outcome = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap();
        assert!(outcome.serve);
        // No first voucher → charged_amount is None.
        assert!(outcome.response.charged_amount.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_rejects_channel_not_open_after_broadcast() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        // status != Open (1 = Closing, say) → "channel is not open".
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            channel_bytes(
                1,
                1_000_000,
                DEFAULT_GRACE_PERIOD_SECONDS,
                &f.payer,
                &f.recipient,
                &f.payer,
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not open"), "got: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_rejects_mint_mismatch() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                DEFAULT_GRACE_PERIOD_SECONDS,
                &f.payer,
                &f.recipient,
                &f.payer,
                &Pubkey::new_unique(), // wrong mint
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::MintMismatch { .. }), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_rejects_payee_mismatch() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                DEFAULT_GRACE_PERIOD_SECONDS,
                &f.payer,
                &Pubkey::new_unique(), // wrong payee
                &f.payer,
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::RecipientMismatch { .. }),
            "got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_rejects_authorized_signer_mismatch() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                DEFAULT_GRACE_PERIOD_SECONDS,
                &f.payer,
                &f.recipient,
                &Pubkey::new_unique(), // wrong authorized_signer
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("authorized_signer mismatch"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_rejects_payer_mismatch() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                DEFAULT_GRACE_PERIOD_SECONDS,
                &Pubkey::new_unique(), // wrong payer
                &f.recipient,
                &f.payer,
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("payer mismatch"), "got: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_rejects_deposit_below_per_request() {
        // per_request for "0.10" @ 6 decimals = 100_000; deposit below it.
        let f = deposit_fixture(1_000_000, 100_000).await;
        bind_matching_channel(&f, 1); // on-chain deposit is 1 < 100_000
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("below one request's price"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_rejects_grace_period_mismatch() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                123, // wrong grace period
                &f.payer,
                &f.recipient,
                &f.payer,
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("grace_period"), "got: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_rejects_distribution_hash_mismatch() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        // On-chain commits to a non-empty split, but the server advertised none.
        let wrong = pc::distribution_hash(&[pc::Distribution {
            recipient: Pubkey::new_unique(),
            bps: 10_000,
        }]);
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                DEFAULT_GRACE_PERIOD_SECONDS,
                &f.payer,
                &f.recipient,
                &f.payer,
                &f.mint,
                wrong,
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("distribution does not match"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_surfaces_broadcast_error() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        f.mock
            .fail_send("preflight failed: custom program error 0x1");
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Rpc(_)), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_surfaces_channel_fetch_error() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        // Broadcast succeeds, but the channel read-back fails.
        f.mock.fail_account("account fetch unavailable");
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Rpc(_)), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_rejects_underpriced_first_voucher_before_broadcast() {
        // First voucher (1) is below per_request (100_000) → rejected before any
        // on-chain work (no account is bound).
        let f = deposit_fixture(1_000_000, 1).await;
        let err = f
            .handler
            .verify_payment(&f.header, &f.amount)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("below the required"), "got: {err}");
    }

    // ── Deposit race: the first accept must serialize under the channel gate ──
    //
    // `process_deposit` writes the fresh channel (watermark 0) and accepts its
    // first voucher (cumulative 100_000, price 100_000). A concurrent Voucher
    // (cumulative 150_000) on the same channel must not be able to interleave
    // between the watermark write and the first accept: if it did, it would read
    // the same stale watermark of 0, commit 150_000, and be served *in addition*
    // to the deposit's own served first request — two requests served for a
    // combined committed 150_000 at price 100_000. Holding the per-channel gate
    // across the deposit's `put_channel` and first accept closes that window.
    //
    // The seam parks the deposit with the gate held, after `put_channel` but
    // before the first accept. Deleting `let _held = gate.lock().lock().await`
    // from `process_deposit` lets the concurrent voucher interleave, flipping the
    // served count from 1 to 2, so this test fails without the fix.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deposit_first_accept_serializes_under_channel_gate() {
        let f = deposit_fixture(1_000_000, 100_000).await;
        bind_matching_channel(&f, 1_000_000);
        let channel_b58 = pc::pubkey_string(&f.channel_id);

        // Arm the deposit's in-gate seam: the deposit signals once it has written
        // the fresh channel and holds the gate, then parks on `release`.
        let release = Arc::new(AsyncMutex::new(()));
        let release_guard = release.clone().lock_owned().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        *f.handler.post_put_hook.lock().unwrap() = Some(PreGateHook {
            entered: entered_tx,
            release: release.clone(),
        });

        // Spawn the deposit. It broadcasts + binds the channel, writes it at
        // watermark 0 holding the gate, consumes the seam, and parks.
        let (hd, header, amount) = (f.handler.clone(), f.header.clone(), f.amount.clone());
        let task_deposit = tokio::spawn(async move { hd.verify_payment(&header, &amount).await });
        entered_rx.await.unwrap();

        // Spawn a concurrent voucher (150_000). With the gate it blocks on
        // acquisition; the bounded sleep lets it either commit (no gate) or park
        // on the lock (fix).
        let voucher = sign_voucher(&f.payer_signer, &f.channel_id, 150_000, FAR_FUTURE)
            .await
            .unwrap();
        let (hv, cv) = (f.handler.clone(), channel_b58.clone());
        let task_voucher =
            tokio::spawn(async move { hv.process_voucher(&cv, voucher, 100_000).await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Release the deposit and join both.
        drop(release_guard);
        let deposit_outcome = task_deposit.await.unwrap().unwrap();
        let voucher_outcome = task_voucher.await.unwrap();

        // The deposit always serves its first request. The concurrent voucher
        // must NOT also be served: its increment over the deposit's committed
        // 100_000 watermark (150_000 - 100_000 = 50_000) is below the price. With
        // the gate removed both are served (each off the stale watermark of 0).
        let mut served = 0;
        if deposit_outcome.serve {
            served += 1;
        }
        if let Ok(o) = &voucher_outcome {
            if o.serve {
                served += 1;
            }
        }
        assert_eq!(
            served, 1,
            "the deposit's first accept must serialize with concurrent vouchers under the gate"
        );

        // With the fix the deposit commits 100_000 first, then the concurrent
        // voucher's under-priced increment (150_000 - 100_000 = 50_000 < 100_000)
        // is refused, so the watermark stays at the deposit's first charge.
        assert_eq!(
            f.handler
                .store
                .get_channel(&channel_b58)
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            100_000
        );
    }

    // ── challenge() / payment_required_header() (blockhash fetch) ────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn challenge_fetches_blockhash_and_builds_envelope() {
        let mock = MockRpc::start();
        let store: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::new());
        let recipient = Pubkey::new_unique();
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(memory_signer(22)),
            &recipient,
            store,
            vec![],
        );
        let envelope = handler.challenge("0.10").unwrap();
        assert_eq!(envelope.accepts.len(), 1);
        assert_eq!(
            envelope.accepts[0].extra.recent_blockhash.as_deref(),
            Some("11111111111111111111111111111111")
        );

        // And the header helper base64-encodes the same envelope.
        let (name, value) = handler.payment_required_header("0.10").unwrap();
        assert_eq!(name, PAYMENT_REQUIRED_HEADER);
        assert!(!value.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn challenge_surfaces_blockhash_error() {
        let mock = MockRpc::start();
        mock.fail_blockhash("node unhealthy");
        let store: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::new());
        let recipient = Pubkey::new_unique();
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(memory_signer(23)),
            &recipient,
            store,
            vec![],
        );
        let err = handler.challenge("0.10").unwrap_err();
        assert!(matches!(err, Error::Rpc(_)), "got: {err:?}");
    }

    // ── settle_batch (voucher redemption broadcast) ─────────────────────────

    /// Seed a store with a channel carrying an accepted voucher so `settle_batch`
    /// and `distribute` have something to redeem.
    async fn seed_channel_with_voucher(
        store: &Arc<MemoryChannelStore>,
        channel: &Pubkey,
        signer: &MemorySigner,
        cumulative: u64,
    ) -> String {
        let channel_b58 = pc::pubkey_string(channel);
        let voucher = sign_voucher(signer, channel, cumulative, FAR_FUTURE)
            .await
            .unwrap();
        let mut state = seeded_state(
            &channel_b58,
            &pc::pubkey_string(&signer.pubkey()),
            cumulative,
        );
        state.highest_voucher_signature = Some(voucher.signature.clone());
        state.highest_voucher_expires_at = Some(FAR_FUTURE);
        state.operator = Some(pc::pubkey_string(&signer.pubkey()));
        store.put_channel(&channel_b58, state).await.unwrap();
        channel_b58
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_batch_redeems_channels_with_vouchers() {
        let mock = MockRpc::start();
        let store = Arc::new(MemoryChannelStore::new());
        let operator = memory_signer(24);
        let signer = memory_signer(25);
        let recipient = Pubkey::new_unique();
        let channel = Pubkey::new_unique();
        let channel_b58 = seed_channel_with_voucher(&store, &channel, &signer, 500_000).await;

        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(operator),
            &recipient,
            store.clone() as Arc<dyn ChannelStore>,
            vec![],
        );
        let sigs = handler.settle_batch(&[channel_b58]).await.unwrap();
        assert_eq!(sigs.len(), 1, "one packed settlement tx expected");
        assert!(!sigs[0].is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_batch_skips_channels_without_vouchers() {
        let mock = MockRpc::start();
        let store = Arc::new(MemoryChannelStore::new());
        let recipient = Pubkey::new_unique();
        // A channel with no accepted voucher (cumulative 0, no signature).
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);
        store
            .put_channel(
                &channel_b58,
                seeded_state(
                    &channel_b58,
                    &pc::pubkey_string(&memory_signer(9).pubkey()),
                    0,
                ),
            )
            .await
            .unwrap();
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(memory_signer(26)),
            &recipient,
            store as Arc<dyn ChannelStore>,
            vec![],
        );
        // A missing id and a voucher-less channel both yield no settlement txs.
        let sigs = handler
            .settle_batch(&[channel_b58, "MissingChannel1111".to_string()])
            .await
            .unwrap();
        assert!(sigs.is_empty(), "nothing to settle → no txs");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_batch_surfaces_broadcast_error() {
        let mock = MockRpc::start();
        mock.fail_send("blockhash expired");
        let store = Arc::new(MemoryChannelStore::new());
        let operator = memory_signer(27);
        let signer = memory_signer(28);
        let recipient = Pubkey::new_unique();
        let channel = Pubkey::new_unique();
        let channel_b58 = seed_channel_with_voucher(&store, &channel, &signer, 500_000).await;
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(operator),
            &recipient,
            store as Arc<dyn ChannelStore>,
            vec![],
        );
        let err = handler.settle_batch(&[channel_b58]).await.unwrap_err();
        assert!(matches!(err, Error::Rpc(_)), "got: {err:?}");
    }

    // ── distribute (sweep) ──────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn distribute_sweeps_channel_pool() {
        let mock = MockRpc::start();
        let store = Arc::new(MemoryChannelStore::new());
        let operator = memory_signer(29);
        let signer = memory_signer(30);
        let recipient = Pubkey::new_unique();
        let channel = Pubkey::new_unique();
        let channel_b58 = seed_channel_with_voucher(&store, &channel, &signer, 500_000).await;
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(operator),
            &recipient,
            store as Arc<dyn ChannelStore>,
            vec![],
        );
        let sig = handler.distribute(&channel_b58).await.unwrap();
        assert!(sig.is_some(), "distribute broadcasts a sweep tx");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn distribute_errors_when_payer_unknown() {
        let mock = MockRpc::start();
        let store = Arc::new(MemoryChannelStore::new());
        let recipient = Pubkey::new_unique();
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);
        // No `operator` (payer) stashed → distribute cannot refund.
        store
            .put_channel(
                &channel_b58,
                seeded_state(
                    &channel_b58,
                    &pc::pubkey_string(&memory_signer(9).pubkey()),
                    500_000,
                ),
            )
            .await
            .unwrap();
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(memory_signer(31)),
            &recipient,
            store as Arc<dyn ChannelStore>,
            vec![],
        );
        let err = handler.distribute(&channel_b58).await.unwrap_err();
        assert!(err.to_string().contains("payer unknown"), "got: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn distribute_errors_on_unknown_channel() {
        let mock = MockRpc::start();
        let store = Arc::new(MemoryChannelStore::new());
        let recipient = Pubkey::new_unique();
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(memory_signer(32)),
            &recipient,
            store as Arc<dyn ChannelStore>,
            vec![],
        );
        let err = handler.distribute("Missing1111").await.unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }

    // ── refund (cooperative close: settle_and_finalize + distribute) ─────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_settles_finalizes_and_distributes() {
        let mock = MockRpc::start();
        let store = Arc::new(MemoryChannelStore::new());
        let operator = memory_signer(33);
        let owner = memory_signer(34);
        let recipient = Pubkey::new_unique();
        let channel = Pubkey::new_unique();
        let channel_b58 = seed_channel_with_voucher(&store, &channel, &owner, 400_000).await;
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(operator),
            &recipient,
            store.clone() as Arc<dyn ChannelStore>,
            vec![],
        );

        // Refund with a proof-of-ownership voucher at the current watermark.
        let voucher = sign_voucher(&owner, &channel, 400_000, FAR_FUTURE)
            .await
            .unwrap();
        let outcome = handler
            .process_refund(&channel_b58, Some(voucher))
            .await
            .unwrap();
        assert!(!outcome.serve, "a refund is never served");
        assert!(outcome.response.success);
        // settled > 0 → distribute ran and the channel is finalized.
        let state = store.get_channel(&channel_b58).await.unwrap().unwrap();
        assert!(state.finalized);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_with_zero_watermark_finalizes_without_distribute() {
        let mock = MockRpc::start();
        let store = Arc::new(MemoryChannelStore::new());
        let operator = memory_signer(35);
        let owner = memory_signer(36);
        let recipient = Pubkey::new_unique();
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);
        // Watermark 0 (nothing settled): settle_and_finalize runs but distribute
        // is skipped.
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 0),
            )
            .await
            .unwrap();
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(operator),
            &recipient,
            store.clone() as Arc<dyn ChannelStore>,
            vec![],
        );
        let voucher = sign_voucher(&owner, &channel, 0, FAR_FUTURE).await.unwrap();
        let outcome = handler
            .process_refund(&channel_b58, Some(voucher))
            .await
            .unwrap();
        assert!(!outcome.serve);
        let state = store.get_channel(&channel_b58).await.unwrap().unwrap();
        assert!(state.finalized);
        // paid_out stays 0 when distribute is skipped.
        assert_eq!(
            outcome.response.channel_state.as_ref().unwrap().paid_out,
            "0"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_advancing_voucher_settles_the_new_amount() {
        let mock = MockRpc::start();
        let store = Arc::new(MemoryChannelStore::new());
        let operator = memory_signer(37);
        let owner = memory_signer(38);
        let recipient = Pubkey::new_unique();
        let channel = Pubkey::new_unique();
        let channel_b58 = seed_channel_with_voucher(&store, &channel, &owner, 100_000).await;
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(operator),
            &recipient,
            store.clone() as Arc<dyn ChannelStore>,
            vec![],
        );
        // A refund voucher that advances the watermark (200_000 > 100_000).
        let voucher = sign_voucher(&owner, &channel, 200_000, FAR_FUTURE)
            .await
            .unwrap();
        let outcome = handler
            .process_refund(&channel_b58, Some(voucher))
            .await
            .unwrap();
        assert!(outcome.response.success);
        let state = store.get_channel(&channel_b58).await.unwrap().unwrap();
        assert_eq!(state.cumulative, 200_000, "refund advanced the watermark");
        assert!(state.finalized);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refund_unknown_channel_is_rejected() {
        let mock = MockRpc::start();
        let store = Arc::new(MemoryChannelStore::new());
        let owner = memory_signer(39);
        let recipient = Pubkey::new_unique();
        let channel = Pubkey::new_unique();
        let handler = handler_with_rpc(
            mock.url(),
            Arc::new(memory_signer(40)),
            &recipient,
            store as Arc<dyn ChannelStore>,
            vec![],
        );
        let voucher = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let err = handler
            .process_refund(&pc::pubkey_string(&channel), Some(voucher))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }
}
