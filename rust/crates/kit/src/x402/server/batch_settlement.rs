//! Resource-server handler for the SVM `batch-settlement` scheme.
//!
//! The client deposits once into an escrow payment channel, then signs a
//! cumulative Ed25519 voucher per request. This server verifies each voucher
//! offchain, serves immediately, and redeems the accumulated vouchers onchain
//! later, in batches — so no request ever waits on a Solana transaction.
//!
//! # Roles
//!
//! This server self-facilitates: it holds the `feePayer` signer and talks to
//! the chain directly, the same shape as [`crate::x402::server::upto`]. That
//! one key is the transaction fee payer, the channel `rent_payer`, and the
//! zero-share channel `payee` — a lifecycle authority that can always seal and
//! reclaim an abandoned channel, but can never advance the settled watermark,
//! because only the client-controlled `payerAuthorizer` signs vouchers.
//!
//! # Request lifecycle (the `authorization` flow)
//!
//! 1. [`X402BatchSettlement::verify_payment`] runs before the resource handler
//!    and is read-only: it checks the voucher and reserves the channel.
//! 2. The route handler runs.
//! 3. [`X402BatchSettlement::settle_payment`] runs after it succeeds, and only
//!    then commits the watermark and broadcasts any deposit transaction. A
//!    handler that fails leaves state untouched, so the client can retry.
//!
//! Redemption is out of band: [`X402BatchSettlement::claim`] advances the
//! onchain watermark from stored vouchers and [`X402BatchSettlement::settle`]
//! pays the claimed delta to `payTo`.
//!
//! See `specs/schemes/batch-settlement/scheme_batch_settlement_svm.md`.

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

use crate::core::payment_channels as pc;
use crate::core::payment_channels::generated::accounts::Channel;
use crate::core::session::accept_voucher;
use crate::core::settlement::packing::{pack, ChannelInstructionGroup};
use crate::core::store::{
    ChannelState, ChannelStore, MemoryChannelStore, CHANNEL_STATE_SCHEMA_VERSION,
};

use crate::x402::error::Error;
use crate::x402::protocol::schemes::batch_settlement::{
    check_channel_config, check_no_cooperative_close, check_token_program, check_voucher,
    check_withdraw_delay, derive_channel_id, errors as codes, setup_form_from_transaction,
    BatchChannelConfig, BatchError, BatchExtra, BatchPayload, BatchPaymentPayload,
    BatchRequiredEnvelope, BatchRequirements, BatchSettlementExtra, BatchSettlementResponse,
    ChannelStateSnapshot, SetupForm, TransactionExpectations, VoucherState,
    BATCH_SETTLEMENT_SCHEME, MAX_CLAIMS_PER_BATCH, MIN_WITHDRAW_DELAY_SECONDS, VOUCHER_EXPIRES_AT,
};
use crate::x402::protocol::schemes::exact::{
    caip2_network_for_cluster, default_rpc_url, default_token_program_for_currency, ResourceInfo,
};
use crate::x402::server::upto::cosign_operator_fee_payer;
use crate::x402::{PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, X402_VERSION_V2};

/// `ChannelStatus::Open` discriminant in the generated client.
const CHANNEL_STATUS_OPEN: u8 = 0;

/// `ChannelStatus::Closing` discriminant.
const CHANNEL_STATUS_CLOSING: u8 = 2;

/// `ChannelStatus::Distributed` discriminant.
const CHANNEL_STATUS_DISTRIBUTED: u8 = 3;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn batch_err(code: &'static str, detail: impl Into<String>) -> Error {
    BatchError::new(code, detail).into()
}

/// Server configuration for the SVM `batch-settlement` scheme.
#[derive(Clone)]
pub struct BatchConfig {
    /// Base58 final payment receiver — the sole distribution recipient, at
    /// 10,000 bps. Normally a cold wallet, distinct from the fee payer.
    pub pay_to: String,
    /// Currency symbol (`"USDC"`) or mint address.
    pub currency: String,
    /// Token decimals.
    pub decimals: u8,
    /// Token program override; derived from `currency` when absent.
    pub token_program: Option<String>,
    /// Solana cluster: `mainnet-beta`, `devnet`, or `localnet`.
    pub cluster: String,
    /// RPC URL override (defaults per cluster).
    pub rpc_url: Option<String>,
    /// Resource identifier for the 402 challenge.
    pub resource: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// HTTP completion window in seconds.
    pub max_timeout_seconds: u64,
    /// Forced-close grace period in seconds. Must be within
    /// `900..=2592000` and at least `max_timeout_seconds`.
    pub withdraw_delay: u32,
    /// Seller-defined payment reference pinned into the setup transaction's
    /// Memo. When absent the client supplies a random hex nonce instead.
    pub memo: Option<String>,
    /// Base58 server key advertised as `extra.receiverAuthorizer`.
    ///
    /// Advertised only. This server never signs a `CloseAuthorization` and
    /// rejects any it receives — see [`check_no_cooperative_close`].
    pub receiver_authorizer: Option<String>,
    /// Signer that co-signs client setup transactions as fee payer, holds the
    /// channel `rent_payer` and zero-share `payee` seats, and signs redemption
    /// transactions.
    pub fee_payer_signer: Arc<dyn SolanaSigner>,
    /// Channel program id override (defaults to the canonical deployment).
    pub program_id: Option<String>,
}

impl BatchConfig {
    /// Minimal configuration with USDC defaults and the minimum conformant
    /// forced-close grace period.
    pub fn new(
        pay_to: impl Into<String>,
        cluster: impl Into<String>,
        fee_payer_signer: Arc<dyn SolanaSigner>,
    ) -> Self {
        Self {
            pay_to: pay_to.into(),
            currency: "USDC".to_string(),
            decimals: 6,
            token_program: None,
            cluster: cluster.into(),
            rpc_url: None,
            resource: String::new(),
            description: None,
            max_timeout_seconds: 300,
            withdraw_delay: MIN_WITHDRAW_DELAY_SECONDS,
            memo: None,
            receiver_authorizer: None,
            fee_payer_signer,
            program_id: None,
        }
    }
}

/// Per-channel, process-local serialization guard.
///
/// The spec requires the server to serialize all paid-request and close
/// processing per channel. The guard is held from `verify_payment` through
/// `settle_payment`, so a second request on the same channel cannot read the
/// watermark, serve, and commit in between.
///
/// A multi-replica deployment must route a channel to one replica until its
/// verified outcome settles; a future store reservation can remove that
/// deployment constraint.
#[derive(Clone, Default)]
struct InFlight(Arc<Mutex<HashSet<String>>>);

impl InFlight {
    fn acquire(&self, channel_id: &str) -> Result<ChannelGuard, Error> {
        let mut set = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !set.insert(channel_id.to_string()) {
            return Err(batch_err(
                codes::DUPLICATE_SETTLEMENT,
                format!("channel {channel_id} already has a request in flight"),
            ));
        }
        Ok(ChannelGuard {
            in_flight: self.clone(),
            channel_id: channel_id.to_string(),
        })
    }
}

/// Releases its channel's in-flight slot when dropped — including on the error
/// and panic paths, so a failed handler never wedges a channel.
#[derive(Debug)]
struct ChannelGuard {
    in_flight: InFlight,
    channel_id: String,
}

impl std::fmt::Debug for InFlight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InFlight")
    }
}

impl Drop for ChannelGuard {
    fn drop(&mut self) {
        self.in_flight
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.channel_id);
    }
}

/// A verified payment, carried from [`X402BatchSettlement::verify_payment`] to
/// [`X402BatchSettlement::settle_payment`].
///
/// Not `Clone`: it owns its channel's in-flight guard, released on drop.
#[derive(Debug)]
pub struct BatchOutcome {
    /// Whether the gate should run the protected handler.
    ///
    /// `false` for a `refund`: a channel close is a payment-control operation,
    /// not a paid request, so the application handler must be bypassed.
    pub serve: bool,
    /// Whether this is an idempotent retry of an already-accepted voucher.
    ///
    /// The caller MUST return its cached response for
    /// `("access", channelId, maxClaimableAmount)` and MUST NOT run the
    /// resource handler again — the request was already paid for and served.
    pub replay: bool,
    /// The derived channel PDA (base58).
    pub channel_id: String,
    /// The channel payer (base58).
    pub payer: String,
    /// What this request charges, in atomic units.
    pub charged_amount: u64,
    payload: BatchPayload,
    requirements: BatchRequirements,
    max_claimable: u64,
    /// The channel payer's signature over a carried setup transaction, which
    /// identifies it uniquely across retries.
    deposit_signature: Option<String>,
    _guard: ChannelGuard,
}

impl BatchOutcome {
    /// The payload this outcome verified.
    pub fn payload(&self) -> &BatchPayload {
        &self.payload
    }
}

/// Server-side handler for the SVM x402 `batch-settlement` scheme.
#[derive(Clone)]
pub struct X402BatchSettlement {
    rpc: Arc<RpcClient>,
    config: BatchConfig,
    fee_payer: Pubkey,
    store: Arc<dyn ChannelStore>,
    in_flight: InFlight,
}

impl X402BatchSettlement {
    /// Build a handler backed by an in-memory channel store.
    ///
    /// The store holds the only record of what a client has been charged, so a
    /// durable store is required in production — see [`Self::with_store`].
    pub fn new(config: BatchConfig) -> Result<Self, Error> {
        Self::with_store(config, Arc::new(MemoryChannelStore::new()))
    }

    /// Build a handler over a caller-provided (durable) channel store.
    ///
    /// The in-flight reservation is process-local, so multi-replica callers
    /// must consistently route each channel to one instance until settlement.
    pub fn with_store(config: BatchConfig, store: Arc<dyn ChannelStore>) -> Result<Self, Error> {
        if config.pay_to.is_empty() {
            return Err(Error::Other("pay_to is required".into()));
        }
        Pubkey::from_str(&config.pay_to)
            .map_err(|e| Error::Other(format!("invalid payTo pubkey: {e}")))?;
        crate::x402::exact::try_resolve_stablecoin_mint(&config.currency, Some(&config.cluster))?;
        check_withdraw_delay(config.withdraw_delay, config.max_timeout_seconds)
            .map_err(|e| Error::Other(e.to_string()))?;
        let fee_payer = config.fee_payer_signer.pubkey();
        if pc::pubkey_string(&fee_payer) == config.pay_to {
            // Not fatal onchain, but it collapses the cold-wallet separation the
            // scheme is built around, so surface it at construction.
            tracing::warn!(
                "batch-settlement payTo equals the fee payer; proceeds are not isolated"
            );
        }
        if let Some(authorizer) = &config.receiver_authorizer {
            Pubkey::from_str(authorizer)
                .map_err(|e| Error::Other(format!("invalid receiverAuthorizer: {e}")))?;
        }
        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&config.cluster).to_string());
        Ok(Self {
            rpc: Arc::new(RpcClient::new(rpc_url)),
            config,
            fee_payer,
            store,
            in_flight: InFlight::default(),
        })
    }

    /// The advertised `extra.feePayer` (base58).
    pub fn fee_payer(&self) -> String {
        pc::pubkey_string(&self.fee_payer)
    }

    /// The channel store backing this handler, for redemption workers.
    pub fn store(&self) -> &Arc<dyn ChannelStore> {
        &self.store
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
        let mint = crate::x402::exact::try_resolve_stablecoin_mint(
            &self.config.currency,
            Some(&self.config.cluster),
        )?
        .ok_or_else(|| Error::Other("batch-settlement requires an SPL token".into()))?;
        Pubkey::from_str(mint).map_err(|e| Error::Other(format!("invalid mint: {e}")))
    }

    fn token_program(&self) -> Result<Pubkey, Error> {
        let declared = self.config.token_program.clone().unwrap_or_else(|| {
            default_token_program_for_currency(&self.config.currency, Some(&self.config.cluster))
                .to_string()
        });
        Ok(check_token_program(&declared)?)
    }

    fn network(&self) -> String {
        caip2_network_for_cluster(&self.config.cluster).to_string()
    }

    // ── Challenge ──

    /// Build the `batch-settlement` requirement. Pure: no RPC.
    pub fn requirements(&self, amount: &str) -> Result<BatchRequirements, Error> {
        let base_units = crate::x402::server::exact::parse_units(amount, self.config.decimals)?;
        Ok(BatchRequirements {
            scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
            network: self.network(),
            amount: base_units,
            asset: pc::pubkey_string(&self.mint()?),
            pay_to: self.config.pay_to.clone(),
            max_timeout_seconds: self.config.max_timeout_seconds,
            extra: BatchExtra {
                // Omitted: the scheme already resolves to the protocol-default
                // `authorization` flow.
                payment_flow: None,
                fee_payer: self.fee_payer(),
                receiver_authorizer: self.config.receiver_authorizer.clone(),
                withdraw_delay: self.config.withdraw_delay,
                token_program: pc::pubkey_string(&self.token_program()?),
                memo: self.config.memo.clone(),
                recent_blockhash: None,
                recent_slot: None,
                channel_state: None,
                voucher_state: None,
            },
        })
    }

    /// Build the full 402 challenge.
    ///
    /// One `getLatestBlockhash` supplies both hints: its response context
    /// carries the slot, which the client uses as `channelConfig.openSlot`. Both
    /// are construction conveniences — a client may ignore them and fetch its
    /// own, and neither is part of the signed voucher.
    pub fn challenge(&self, amount: &str) -> Result<BatchRequiredEnvelope, Error> {
        let mut requirement = self.requirements(amount)?;
        let hint =
            crate::core::blockhash::fetch_blockhash_with_slot(&self.rpc, self.rpc.commitment())
                .map_err(|e| Error::Rpc(format!("failed to fetch recent blockhash: {e}")))?;
        requirement.extra.recent_blockhash = Some(hint.blockhash);
        requirement.extra.recent_slot = Some(hint.slot);
        Ok(self.envelope(requirement, None))
    }

    /// Build a corrective 402 telling the client where the server's watermark
    /// actually is, after a cumulative-amount mismatch.
    ///
    /// The snapshot carries a `voucherState` proof: the signature the client
    /// itself produced at `signedMaxClaimable`. Without it the client would have
    /// to take the server's word for how much it has been charged, and a server
    /// could walk the cumulative base up arbitrarily. When the server holds no
    /// voucher yet, the proof is omitted and the client resynchronizes from
    /// onchain state instead.
    pub async fn corrective_challenge(
        &self,
        amount: &str,
        channel_id: &str,
    ) -> Result<BatchRequiredEnvelope, Error> {
        // No blockhash or slot hint: this answers a client that already has a
        // channel and will retry with a plain `voucher`, which needs neither.
        // Keeping the error path RPC-free means a degraded RPC cannot turn a
        // recoverable mismatch into an unrecoverable failure — and a client that
        // does need to top up may fetch its own, as the scheme allows.
        let mut requirement = self.requirements(amount)?;
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| batch_err(codes::INVALID_CHANNEL_STATE, "unknown channel"))?;
        requirement.extra.voucher_state =
            state
                .highest_voucher_signature
                .as_ref()
                .map(|signature| VoucherState {
                    signed_max_claimable: state.cumulative.to_string(),
                    expires_at: state
                        .highest_voucher_expires_at
                        .unwrap_or(VOUCHER_EXPIRES_AT),
                    signature: signature.clone(),
                });
        requirement.extra.channel_state = Some(self.snapshot(&state));
        Ok(self.envelope(
            requirement,
            Some(codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH.to_string()),
        ))
    }

    fn envelope(
        &self,
        requirement: BatchRequirements,
        error: Option<String>,
    ) -> BatchRequiredEnvelope {
        BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: (!self.config.resource.is_empty()).then(|| ResourceInfo {
                url: self.config.resource.clone(),
                description: self.config.description.clone(),
                mime_type: None,
            }),
            accepts: vec![requirement],
            error,
        }
    }

    /// `(header-name, base64-value)` for the 402 challenge.
    pub fn payment_required_header(&self, amount: &str) -> Result<(String, String), Error> {
        Ok((
            PAYMENT_REQUIRED_HEADER.to_string(),
            encode_json(&self.challenge(amount)?)?,
        ))
    }

    /// `(header-name, base64-value)` for the `PAYMENT-RESPONSE` result.
    pub fn settlement_header(
        &self,
        response: &BatchSettlementResponse,
    ) -> Result<(String, String), Error> {
        Ok((PAYMENT_RESPONSE_HEADER.to_string(), encode_json(response)?))
    }

    /// Decode a `PAYMENT-SIGNATURE` header into a `batch-settlement` payload.
    pub fn parse_payment(&self, header: &str) -> Result<BatchPaymentPayload, Error> {
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, header)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        let envelope: BatchPaymentPayload = serde_json::from_slice(&decoded)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        if envelope.accepted.scheme != BATCH_SETTLEMENT_SCHEME {
            return Err(Error::InvalidPayloadType(envelope.accepted.scheme));
        }
        Ok(envelope)
    }

    /// Build the 402 to answer a failed verification with.
    ///
    /// A cumulative-amount mismatch gets the corrective challenge, carrying the
    /// server's snapshot and the voucher proof the client needs to resynchronize
    /// and retry. Every challenge carries a machine-readable error code.
    pub async fn challenge_for_failure(
        &self,
        header: &str,
        amount: &str,
        error: &Error,
    ) -> Result<(String, String), Error> {
        let is_mismatch =
            crate::x402::protocol::schemes::batch_settlement::classify(&error.to_string())
                == codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH;
        if is_mismatch {
            if let Some(channel_id) = self.channel_id_for_header(header) {
                if let Ok(envelope) = self.corrective_challenge(amount, &channel_id).await {
                    return Ok((PAYMENT_REQUIRED_HEADER.to_string(), encode_json(&envelope)?));
                }
            }
        }
        let mut envelope = self.challenge(amount)?;
        envelope.error = Some(
            crate::x402::protocol::schemes::batch_settlement::classify(&error.to_string())
                .to_string(),
        );
        Ok((PAYMENT_REQUIRED_HEADER.to_string(), encode_json(&envelope)?))
    }

    fn channel_id_for_header(&self, header: &str) -> Option<String> {
        let envelope = self.parse_payment(header).ok()?;
        let program_id = self.program_id().ok()?;
        let channel = derive_channel_id(
            envelope.payload.channel_config(),
            &envelope.accepted.extra.fee_payer,
            &program_id,
        )
        .ok()?;
        Some(pc::pubkey_string(&channel))
    }

    // ── Verify (before the resource handler) ──

    /// Verify a payment for a route priced at `amount`, without mutating state.
    ///
    /// On success the returned [`BatchOutcome`] holds the channel's in-flight
    /// guard: keep it alive across the resource handler and hand it to
    /// [`Self::settle_payment`], which commits the watermark only after the
    /// handler has succeeded.
    ///
    /// A cumulative-amount mismatch fails with
    /// `invalid_batch_settlement_svm_cumulative_amount_mismatch`; answer it with
    /// [`Self::corrective_challenge`] so the client can resynchronize.
    pub async fn verify_payment(&self, header: &str, amount: &str) -> Result<BatchOutcome, Error> {
        let envelope = self.parse_payment(header)?;
        if envelope.x402_version != X402_VERSION_V2 {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                "batch-settlement requires x402 version 2",
            ));
        }
        let requirements = self.requirements(amount)?;
        let payload = envelope.payload;
        let config = payload.channel_config().clone();

        check_channel_config(&config, &requirements)?;
        check_no_cooperative_close(&payload)?;
        self.check_accepted_matches(&envelope.accepted, &requirements)?;

        let program_id = self.program_id()?;
        let channel_id = derive_channel_id(&config, &requirements.extra.fee_payer, &program_id)?;
        let channel_b58 = pc::pubkey_string(&channel_id);
        let guard = self.in_flight.acquire(&channel_b58)?;

        let charge = requirements.amount()?;
        let stored = self
            .store
            .get_channel(&channel_b58)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;

        match &payload {
            BatchPayload::Refund { transaction, .. } => {
                self.verify_refund(transaction, &config, &requirements, &channel_id)?;
                Ok(BatchOutcome {
                    serve: false,
                    replay: false,
                    channel_id: channel_b58,
                    payer: config.payer.clone(),
                    charged_amount: 0,
                    payload,
                    requirements,
                    max_claimable: stored.as_ref().map(|s| s.cumulative).unwrap_or_default(),
                    deposit_signature: None,
                    _guard: guard,
                })
            }
            BatchPayload::Voucher { voucher, .. } => {
                let state = stored.ok_or_else(|| {
                    batch_err(
                        codes::INVALID_CHANNEL_STATE,
                        format!("no channel {channel_b58}; open one with a deposit payload"),
                    )
                })?;
                self.check_channel_open(&state)?;
                let max_claimable = check_voucher(voucher, &config, &channel_id)?;
                let replay = self.check_watermark(&state, voucher, max_claimable, charge)?;
                self.check_deposit_cap(max_claimable, state.deposit)?;
                Ok(BatchOutcome {
                    serve: !replay,
                    replay,
                    channel_id: channel_b58,
                    payer: state.payer.clone(),
                    charged_amount: if replay { 0 } else { charge },
                    payload,
                    requirements,
                    max_claimable,
                    deposit_signature: None,
                    _guard: guard,
                })
            }
            BatchPayload::Deposit {
                voucher, deposit, ..
            } => {
                let max_claimable = check_voucher(voucher, &config, &channel_id)?;
                let deposit_amount = deposit.amount()?;
                let form = setup_form_from_transaction(&deposit.transaction, &program_id)?;
                if let Some(state) = &stored {
                    self.check_channel_open(state)?;
                }
                let prior = stored.as_ref();
                let replay = match prior {
                    Some(state) => self.check_watermark(state, voucher, max_claimable, charge)?,
                    None => {
                        if max_claimable != charge {
                            return Err(batch_err(
                                codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                                format!(
                                    "first voucher must authorize exactly {charge}, got {max_claimable}"
                                ),
                            ));
                        }
                        false
                    }
                };
                let mint = self.mint()?;
                let token_program = self.token_program()?;
                let receiver = pc::parse_pubkey(&requirements.pay_to)?;
                self.check_mint_owner(&mint, &token_program)?;
                self.check_settlement_accounts(&mint, &token_program, &receiver)?;
                let expectations = TransactionExpectations {
                    program_id: &program_id,
                    fee_payer: &self.fee_payer,
                    config: &config,
                    channel_id: &channel_id,
                    token_program: &token_program,
                    receiver: &receiver,
                    memo: self.config.memo.as_deref(),
                };
                let recent_slot = matches!(form, SetupForm::Open)
                    .then(|| {
                        crate::core::blockhash::fetch_blockhash_with_slot(
                            &self.rpc,
                            self.rpc.commitment(),
                        )
                        .ok()
                        .map(|hint| hint.slot)
                    })
                    .flatten();
                let validated =
                    crate::x402::protocol::schemes::batch_settlement::validate_setup_transaction(
                        &deposit.transaction,
                        form,
                        &expectations,
                        deposit_amount,
                        recent_slot,
                    )?;
                let deposit_signature = payer_signature(&validated.transaction);
                let deposit_after = Self::deposit_ceiling(
                    stored.as_ref(),
                    deposit_amount,
                    deposit_signature.as_deref(),
                )?;
                self.check_deposit_cap(max_claimable, deposit_after)?;
                Ok(BatchOutcome {
                    serve: !replay,
                    replay,
                    channel_id: channel_b58,
                    payer: config.payer.clone(),
                    charged_amount: if replay { 0 } else { charge },
                    payload,
                    requirements,
                    max_claimable,
                    deposit_signature,
                    _guard: guard,
                })
            }
        }
    }

    /// The client must echo back the requirements it is answering, so a payload
    /// built against a different price or asset cannot be replayed onto this
    /// route.
    fn check_accepted_matches(
        &self,
        accepted: &BatchRequirements,
        requirements: &BatchRequirements,
    ) -> Result<(), Error> {
        let mismatched = accepted.network != requirements.network
            || accepted.amount != requirements.amount
            || accepted.asset != requirements.asset
            || accepted.pay_to != requirements.pay_to
            || accepted.max_timeout_seconds != requirements.max_timeout_seconds
            || accepted.extra.payment_flow != requirements.extra.payment_flow
            || accepted.extra.fee_payer != requirements.extra.fee_payer
            || accepted.extra.receiver_authorizer != requirements.extra.receiver_authorizer
            || accepted.extra.withdraw_delay != requirements.extra.withdraw_delay
            || accepted.extra.token_program != requirements.extra.token_program
            || accepted.extra.memo != requirements.extra.memo;
        if mismatched {
            return Err(batch_err(
                codes::INVALID_CHANNEL_STATE,
                "paymentPayload.accepted does not match the route's paymentRequirements",
            ));
        }
        Ok(())
    }

    fn check_channel_open(&self, state: &ChannelState) -> Result<(), Error> {
        if state.sealed {
            return Err(batch_err(codes::INVALID_CLOSE_STATE, "channel is sealed"));
        }
        // Once a payer-forced close has been broadcast the redemption window is
        // bounded by the grace period, so no further charge may be accepted.
        if state.close_requested_at.is_some() {
            return Err(batch_err(
                codes::INVALID_CLOSE_STATE,
                "channel close is pending; open a new channel",
            ));
        }
        Ok(())
    }

    /// Apply the fixed-price watermark rule, returning whether this is an
    /// idempotent replay.
    ///
    /// A fresh voucher must advance the cumulative by exactly one request's
    /// price. An exact repeat of the highest accepted voucher — same amount and
    /// same signature — is a retry of a request that was already paid for and
    /// served. Anything else is stale or a fork, and must not be served.
    fn check_watermark(
        &self,
        state: &ChannelState,
        voucher: &crate::x402::protocol::schemes::batch_settlement::BatchVoucher,
        max_claimable: u64,
        charge: u64,
    ) -> Result<bool, Error> {
        if max_claimable == state.cumulative
            && state.highest_voucher_signature.as_deref() == Some(voucher.signature.as_str())
        {
            return Ok(true);
        }
        let expected = state
            .cumulative
            .checked_add(charge)
            .ok_or_else(|| batch_err(codes::INVALID_CHANNEL_STATE, "cumulative amount overflow"))?;
        if max_claimable != expected {
            return Err(batch_err(
                codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                format!(
                    "voucher authorizes {max_claimable}, expected {expected} \
                     (charged {} + amount {charge})",
                    state.cumulative
                ),
            ));
        }
        Ok(false)
    }

    /// The deposit ceiling a request may authorize against, once its carried
    /// setup transaction confirms.
    ///
    /// A retry must not add the same escrow twice. The first attempt may have
    /// broadcast, confirmed, and recorded the deposit before failing later
    /// (a store error while committing the voucher, say), and re-adding it
    /// would leave the request permanently unsatisfiable: the ceiling would
    /// exceed what the chain will ever hold, so the confirmed-state check
    /// could never pass and the escrowed funds would be stranded. The payer's
    /// signature identifies the transaction across attempts.
    fn deposit_ceiling(
        stored: Option<&ChannelState>,
        deposit_amount: u64,
        deposit_signature: Option<&str>,
    ) -> Result<u64, Error> {
        let Some(state) = stored else {
            // No channel yet: the `open` is the whole escrow.
            return Ok(deposit_amount);
        };
        if deposit_signature.is_some_and(|signature| {
            state
                .processed_topup_signatures
                .iter()
                .any(|s| s == signature)
        }) {
            return Ok(state.deposit);
        }
        state
            .deposit
            .checked_add(deposit_amount)
            .ok_or_else(|| batch_err(codes::INVALID_CHANNEL_STATE, "deposit overflow"))
    }

    fn check_deposit_cap(&self, max_claimable: u64, deposit: u64) -> Result<(), Error> {
        if max_claimable > deposit {
            return Err(batch_err(
                codes::INVALID_CUMULATIVE_EXCEEDS_DEPOSIT,
                format!("voucher authorizes {max_claimable} over a deposit of {deposit}"),
            ));
        }
        Ok(())
    }

    /// Confirm the advertised token program really owns the mint.
    ///
    /// The ATA derivations in the setup transaction depend on it, so a token
    /// program that disagrees with the chain would have the sponsor validate
    /// accounts the program will never touch.
    fn check_mint_owner(&self, mint: &Pubkey, token_program: &Pubkey) -> Result<(), Error> {
        let account = self
            .rpc
            .get_account(mint)
            .map_err(|e| Error::Rpc(format!("mint fetch failed: {e}")))?;
        if pc::from_address(&account.owner) != *token_program {
            return Err(batch_err(
                codes::INVALID_TOKEN_PROGRAM,
                format!(
                    "tokenProgram {} does not own mint {}",
                    pc::pubkey_string(token_program),
                    pc::pubkey_string(mint)
                ),
            ));
        }
        Ok(())
    }

    /// Ensure a channel can later distribute its settled funds before the
    /// sponsor co-signs the escrow transaction.
    fn check_settlement_accounts(
        &self,
        mint: &Pubkey,
        token_program: &Pubkey,
        receiver: &Pubkey,
    ) -> Result<(), Error> {
        for (role, owner) in [
            ("payee", self.fee_payer),
            ("treasury", pc::treasury_owner()),
            ("receiver", *receiver),
        ] {
            let (ata, _) = pc::find_associated_token_address(&owner, mint, token_program);
            let account = self.rpc.get_account(&ata).map_err(|e| {
                batch_err(
                    codes::INVALID_SETUP_TRANSACTION,
                    format!("{role} settlement ATA {ata} is unavailable: {e}"),
                )
            })?;
            if pc::from_address(&account.owner) != *token_program {
                return Err(batch_err(
                    codes::INVALID_SETUP_TRANSACTION,
                    format!("{role} settlement ATA {ata} has the wrong owner"),
                ));
            }
        }
        Ok(())
    }

    fn verify_refund(
        &self,
        transaction: &str,
        config: &BatchChannelConfig,
        requirements: &BatchRequirements,
        channel_id: &Pubkey,
    ) -> Result<(), Error> {
        let program_id = self.program_id()?;
        let token_program = self.token_program()?;
        let receiver = pc::parse_pubkey(&requirements.pay_to)?;
        let expectations = TransactionExpectations {
            program_id: &program_id,
            fee_payer: &self.fee_payer,
            config,
            channel_id,
            token_program: &token_program,
            receiver: &receiver,
            memo: self.config.memo.as_deref(),
        };
        crate::x402::protocol::schemes::batch_settlement::validate_request_close_transaction(
            transaction,
            &expectations,
        )?;
        // The channel must still be closeable. `Closing` is accepted so a
        // retried refund is idempotent rather than a second transition.
        let channel = self.fetch_channel(channel_id)?;
        if channel.status != CHANNEL_STATUS_OPEN && channel.status != CHANNEL_STATUS_CLOSING {
            return Err(batch_err(
                codes::INVALID_CLOSE_STATE,
                format!("channel status {} cannot be closed", channel.status),
            ));
        }
        Ok(())
    }

    // ── Settle (after the resource handler) ──

    /// Commit a verified payment. Call only after the resource handler has
    /// succeeded — this is the step that charges the client.
    pub async fn settle_payment(
        &self,
        outcome: BatchOutcome,
    ) -> Result<BatchSettlementResponse, Error> {
        let network = outcome.requirements.network.clone();
        match &outcome.payload {
            BatchPayload::Refund { transaction, .. } => {
                let channel_id = pc::parse_pubkey(&outcome.channel_id)?;
                let mut channel = self.fetch_channel(&channel_id)?;
                self.upsert_channel(&outcome, &channel).await?;
                let signature = if channel.status == CHANNEL_STATUS_OPEN {
                    let state = self
                        .store
                        .get_channel(&outcome.channel_id)
                        .await
                        .map_err(|e| Error::Other(format!("store error: {e}")))?;
                    if state.is_some_and(|state| state.cumulative > channel.settlement.settled) {
                        self.claim(std::slice::from_ref(&outcome.channel_id))
                            .await?;
                        channel = self.fetch_channel(&channel_id)?;
                    }
                    self.broadcast_client_transaction(transaction).await?
                } else if channel.status == CHANNEL_STATUS_CLOSING {
                    String::new()
                } else {
                    return Err(batch_err(
                        codes::INVALID_CLOSE_STATE,
                        "channel cannot be closed",
                    ));
                };
                channel = self.fetch_channel(&channel_id)?;
                if channel.status != CHANNEL_STATUS_CLOSING {
                    return Err(batch_err(
                        codes::INVALID_CLOSE_STATE,
                        "request_close did not move the channel to Closing",
                    ));
                }
                let state = self.record_close(&outcome, &channel).await?;
                Ok(BatchSettlementResponse {
                    success: true,
                    error_reason: None,
                    payer: Some(outcome.payer.clone()),
                    transaction: signature,
                    network,
                    // The grace period may still be running: nothing has moved
                    // back to the payer yet, and claiming otherwise would be a
                    // lie the client could act on.
                    amount: String::new(),
                    extra: Some(BatchSettlementExtra {
                        commitment_id: None,
                        charged_amount: None,
                        channel_state: Some(self.snapshot(&state)),
                    }),
                })
            }
            BatchPayload::Voucher { voucher, .. } => {
                let state = self.commit_voucher(&outcome, voucher).await?;
                Ok(self.accepted_response(&outcome, &state, String::new(), String::new()))
            }
            BatchPayload::Deposit {
                voucher, deposit, ..
            } => {
                let signature = self
                    .broadcast_client_transaction(&deposit.transaction)
                    .await?;
                let channel_id = pc::parse_pubkey(&outcome.channel_id)?;
                let channel = self.fetch_channel(&channel_id)?;
                self.check_confirmed_channel(&outcome, &channel)?;
                self.upsert_channel(&outcome, &channel).await?;
                let state = self.commit_voucher(&outcome, voucher).await?;
                Ok(self.accepted_response(&outcome, &state, signature, deposit.amount.clone()))
            }
        }
    }

    fn accepted_response(
        &self,
        outcome: &BatchOutcome,
        state: &ChannelState,
        transaction: String,
        amount: String,
    ) -> BatchSettlementResponse {
        BatchSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some(outcome.payer.clone()),
            transaction,
            network: outcome.requirements.network.clone(),
            amount,
            extra: Some(BatchSettlementExtra {
                commitment_id: Some(format!("{}:{}", outcome.channel_id, outcome.max_claimable)),
                charged_amount: Some(outcome.charged_amount.to_string()),
                channel_state: Some(self.snapshot(state)),
            }),
        }
    }

    /// Rebuild the accepted response for an idempotent voucher retry.
    pub async fn replay_response(
        &self,
        outcome: &BatchOutcome,
    ) -> Result<BatchSettlementResponse, Error> {
        let state = self
            .store
            .get_channel(&outcome.channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| batch_err(codes::INVALID_CHANNEL_STATE, "channel vanished"))?;
        Ok(self.accepted_response(outcome, &state, String::new(), String::new()))
    }

    /// Co-sign a client-supplied transaction as fee payer and broadcast it.
    ///
    /// The transaction was already statically validated during verification, so
    /// this only adds the sponsor signature. A rejection is not authoritative on
    /// its own: a retry of a transaction whose first submission landed dies at
    /// preflight with "already processed", so the confirmed signature status
    /// decides.
    async fn broadcast_client_transaction(&self, transaction_b64: &str) -> Result<String, Error> {
        let mut tx = pc::decode_transaction(transaction_b64)?;
        cosign_operator_fee_payer(
            self.config.fee_payer_signer.as_ref(),
            &self.fee_payer,
            &mut tx,
        )
        .await?;
        let signature = *tx
            .signatures
            .first()
            .ok_or_else(|| Error::Other("transaction has no signature slot".into()))?;
        if matches!(self.rpc.get_signature_status(&signature), Ok(Some(Ok(())))) {
            return Ok(signature.to_string());
        }
        // Simulate the exact bytes before they reach the network. The static
        // policy has already bounded what the sponsor is authorizing; this
        // catches the rest — an unfunded payer, a frozen or wrong-owner token
        // account, a settlement path that would not be usable later — while
        // rejecting is still free.
        let simulation = self
            .rpc
            .simulate_transaction(&tx)
            .map_err(|e| batch_err(codes::INVALID_SETTLEMENT_SIMULATION, e.to_string()))?;
        if let Some(err) = simulation.value.err {
            return Err(batch_err(
                codes::INVALID_SETTLEMENT_SIMULATION,
                format!("simulation failed: {err:?}"),
            ));
        }
        match self.rpc.send_and_confirm_transaction(&tx) {
            Ok(confirmed) => Ok(confirmed.to_string()),
            Err(error) => {
                if matches!(self.rpc.get_signature_status(&signature), Ok(Some(Ok(())))) {
                    Ok(signature.to_string())
                } else {
                    Err(Error::Rpc(format!("broadcast failed: {error}")))
                }
            }
        }
    }

    /// Re-read the confirmed channel and bind every immutable field to the
    /// payload and requirements before reporting settlement success.
    fn check_confirmed_channel(
        &self,
        outcome: &BatchOutcome,
        channel: &Channel,
    ) -> Result<(), Error> {
        let config = outcome.payload.channel_config();
        let expect = |ok: bool, what: &str| -> Result<(), Error> {
            if ok {
                Ok(())
            } else {
                Err(batch_err(
                    codes::INVALID_CHANNEL_STATE,
                    format!("confirmed channel {what} does not match the payload"),
                ))
            }
        };
        expect(channel.status == CHANNEL_STATUS_OPEN, "status")?;
        // The escrow must cover what this voucher authorizes. That — not the
        // arithmetic ceiling computed before broadcast — is the property the
        // program enforces at `settle`, and it is the one that stays true when
        // a retry re-confirms a deposit that already landed.
        expect(channel.deposit >= outcome.max_claimable, "deposit")?;
        expect(
            pc::pubkey_string(&pc::from_address(&channel.payer)) == config.payer,
            "payer",
        )?;
        expect(pc::from_address(&channel.payee) == self.fee_payer, "payee")?;
        expect(
            pc::from_address(&channel.rent_payer) == self.fee_payer,
            "rent_payer",
        )?;
        expect(
            pc::pubkey_string(&pc::from_address(&channel.authorized_signer))
                == config.payer_authorizer,
            "authorized_signer",
        )?;
        expect(
            pc::pubkey_string(&pc::from_address(&channel.mint)) == config.token,
            "mint",
        )?;
        expect(
            channel.grace_period == config.withdraw_delay,
            "grace_period",
        )?;
        expect(channel.open_slot == config.open_slot, "open_slot")?;
        // The distribution is only committed as a hash, so it is checked by
        // rebuilding the single-recipient preimage the scheme requires.
        let receiver = pc::parse_pubkey(&outcome.requirements.pay_to)?;
        let expected_hash = pc::distribution_hash(&pc::sole_recipient(&receiver));
        expect(channel.distribution_hash == expected_hash, "distribution")?;
        Ok(())
    }

    /// Insert or refresh the channel record from confirmed onchain state.
    async fn upsert_channel(&self, outcome: &BatchOutcome, channel: &Channel) -> Result<(), Error> {
        let config = outcome.payload.channel_config().clone();
        let channel_id = outcome.channel_id.clone();
        let deposit = channel.deposit;
        let settled = channel.settlement.settled;
        let open_slot = channel.open_slot;
        let payer = config.payer.clone();
        let rent_payer = self.fee_payer();
        let authorized_signer = config.payer_authorizer.clone();
        let deposit_signature = outcome.deposit_signature.clone();
        self.store
            .update_channel(
                &channel_id.clone(),
                Box::new(move |current| {
                    let mut state = current.unwrap_or_else(|| ChannelState {
                        channel_id,
                        authorized_signer: authorized_signer.clone(),
                        deposit,
                        cumulative: 0,
                        sealed: false,
                        highest_voucher_signature: None,
                        highest_voucher_expires_at: None,
                        close_requested_at: None,
                        open_slot: Some(open_slot),
                        payer,
                        rent_payer,
                        opening_challenge_id: String::new(),
                        authentication: None,
                        voucher_signer: "client".to_string(),
                        idle_timeout_seconds: None,
                        last_activity_at: now_unix(),
                        spent_amount: 0,
                        settled_on_chain: settled,
                        processed_uses: vec![],
                        processed_topup_signatures: vec![],
                        next_delivery_sequence: 0,
                        pending_deliveries: vec![],
                        committed_deliveries: vec![],
                        lifecycle: None,
                        schema_version: CHANNEL_STATE_SCHEMA_VERSION,
                        extra: Default::default(),
                    });
                    // A top-up only ever raises the ceiling; never let a stale
                    // read lower a deposit the chain has already confirmed.
                    state.deposit = state.deposit.max(deposit);
                    state.settled_on_chain = state.settled_on_chain.max(settled);
                    state.last_activity_at = now_unix();
                    // Marks this escrow as applied, so a retry of the same
                    // transaction re-uses the confirmed deposit rather than
                    // adding it a second time.
                    if let Some(signature) = deposit_signature {
                        if !state.processed_topup_signatures.contains(&signature) {
                            state.processed_topup_signatures.push(signature);
                        }
                    }
                    Ok(state)
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        Ok(())
    }

    /// Atomically advance the offchain watermark and record the voucher.
    async fn commit_voucher(
        &self,
        outcome: &BatchOutcome,
        voucher: &crate::x402::protocol::schemes::batch_settlement::BatchVoucher,
    ) -> Result<ChannelState, Error> {
        accept_voucher(
            self.store.as_ref(),
            &outcome.channel_id,
            outcome.max_claimable,
            voucher.expires_at,
            &voucher.signature,
            now_unix() as i64,
            // Fixed pricing is enforced by `check_watermark` against the exact
            // per-request amount, so no separate minimum delta applies, and
            // vouchers never expire so the settlement window is inert.
            0,
            0,
            // Availability is not metered here: this scheme charges a fixed
            // price per request, already bound to the exact cumulative step.
            0,
        )
        .await
        .map_err(|e| batch_err(codes::INVALID_CHANNEL_STATE, e.to_string()))?;
        self.store
            .get_channel(&outcome.channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| batch_err(codes::INVALID_CHANNEL_STATE, "channel vanished mid-commit"))
    }

    async fn record_close(
        &self,
        outcome: &BatchOutcome,
        channel: &Channel,
    ) -> Result<ChannelState, Error> {
        let closed_at = u64::try_from(channel.closure_started_at).unwrap_or_else(|_| now_unix());
        self.store
            .update_channel(
                &outcome.channel_id,
                Box::new(move |current| {
                    let mut state = current.ok_or_else(|| {
                        crate::core::store::StoreError::Internal("channel not found".into())
                    })?;
                    state.close_requested_at = Some(closed_at);
                    state.last_activity_at = now_unix();
                    Ok(state)
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))
    }

    fn snapshot(&self, state: &ChannelState) -> ChannelStateSnapshot {
        ChannelStateSnapshot {
            channel_id: state.channel_id.clone(),
            balance: state.deposit.to_string(),
            total_claimed: state.settled_on_chain.to_string(),
            withdraw_requested_at: state.close_requested_at.unwrap_or(0) as i64,
            charged_cumulative_amount: Some(state.cumulative.to_string()),
        }
    }

    fn fetch_channel(&self, channel_id: &Pubkey) -> Result<Channel, Error> {
        let data = self
            .rpc
            .get_account_data(channel_id)
            .map_err(|e| Error::Rpc(format!("channel account fetch failed: {e}")))?;
        Channel::from_bytes(&data).map_err(|e| Error::Other(format!("channel decode failed: {e}")))
    }

    // ── Redemption (out of band) ──

    /// Advance the onchain `settled` watermark from each channel's stored
    /// voucher, packing up to [`MAX_CLAIMS_PER_BATCH`] channels per transaction.
    ///
    /// Every channel is processed or the call fails — a batch is never silently
    /// truncated, because a dropped channel is unclaimed value the server would
    /// forfeit if the payer force-closed.
    ///
    /// Returns the confirmed transaction signatures.
    pub async fn claim(&self, channel_ids: &[String]) -> Result<Vec<String>, Error> {
        let program_id = self.program_id()?;
        let mut groups = Vec::with_capacity(channel_ids.len());
        for channel_id in channel_ids {
            let mut state = self
                .store
                .get_channel(channel_id)
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?
                .ok_or_else(|| {
                    batch_err(
                        codes::INVALID_CHANNEL_STATE,
                        format!("unknown channel {channel_id}"),
                    )
                })?;
            let channel = pc::parse_pubkey(channel_id)?;
            let onchain = self.fetch_channel(&channel)?;
            if onchain.status != CHANNEL_STATUS_OPEN || onchain.closure_started_at != 0 {
                continue;
            }
            let settled_on_chain = onchain.settlement.settled;
            state.settled_on_chain = state.settled_on_chain.max(settled_on_chain);
            self.store
                .update_channel(
                    channel_id,
                    Box::new(move |current| {
                        let mut current = current.ok_or_else(|| {
                            crate::core::store::StoreError::Internal("channel not found".into())
                        })?;
                        current.settled_on_chain = current.settled_on_chain.max(settled_on_chain);
                        Ok(current)
                    }),
                )
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?;
            let Some(signature) = state.highest_voucher_signature.clone() else {
                continue;
            };
            // `settle` requires a strictly increasing watermark, so a channel
            // already claimed at this amount would only fail onchain.
            if state.cumulative <= state.settled_on_chain {
                continue;
            }
            let authorized_signer = pc::parse_pubkey(&state.authorized_signer)?;
            let signature_bytes = decode_signature(&signature)?;
            let expires_at = state
                .highest_voucher_expires_at
                .unwrap_or(VOUCHER_EXPIRES_AT);
            // Emits the Ed25519 precompile instruction immediately followed by
            // the program `settle` that reads it back from the instructions
            // sysvar; the pair must stay adjacent, so they are packed together.
            let instructions = pc::build_settle_instructions(
                &channel,
                &authorized_signer,
                &signature_bytes,
                state.cumulative,
                expires_at,
                &program_id,
            )?;
            groups.push(ChannelInstructionGroup {
                channel_id: channel_id.clone(),
                instructions,
            });
        }
        self.submit_groups(groups, MAX_CLAIMS_PER_BATCH).await
    }

    /// Pay each channel's newly claimed delta to `payTo` via program
    /// `distribute`. The channel stays open.
    pub async fn settle(&self, channel_ids: &[String]) -> Result<Vec<String>, Error> {
        let program_id = self.program_id()?;
        let mint = self.mint()?;
        let token_program = self.token_program()?;
        let receiver = pc::parse_pubkey(&self.config.pay_to)?;
        let mut groups = Vec::with_capacity(channel_ids.len());
        for channel_id in channel_ids {
            let channel = pc::parse_pubkey(channel_id)?;
            let onchain = self.fetch_channel(&channel)?;
            if onchain.settlement.settled <= onchain.settlement.payout_watermark {
                continue;
            }
            let instruction = pc::build_distribute_instruction(
                &channel,
                &pc::from_address(&onchain.payer),
                &self.fee_payer,
                &self.fee_payer,
                &pc::treasury_owner(),
                &mint,
                &pc::sole_recipient(&receiver),
                &token_program,
                &program_id,
            );
            groups.push(ChannelInstructionGroup {
                channel_id: channel_id.clone(),
                instructions: vec![instruction],
            });
        }
        self.submit_groups(groups, MAX_CLAIMS_PER_BATCH).await
    }

    async fn submit_groups(
        &self,
        groups: Vec<ChannelInstructionGroup>,
        max_per_tx: usize,
    ) -> Result<Vec<String>, Error> {
        if groups.is_empty() {
            return Ok(vec![]);
        }
        let batches = pack(groups, &self.fee_payer, max_per_tx);
        let mut signatures = Vec::with_capacity(batches.len());
        for batch in batches {
            let instructions: Vec<_> = batch
                .into_iter()
                .flat_map(|group| group.instructions)
                .collect();
            let blockhash = self
                .rpc
                .get_latest_blockhash()
                .map_err(|e| Error::Rpc(format!("blockhash fetch failed: {e}")))?;
            let message = Message::new_with_blockhash(
                &instructions,
                Some(&pc::to_address(&self.fee_payer)),
                &blockhash,
            );
            let mut tx = Transaction::new_unsigned(message);
            self.config
                .fee_payer_signer
                .sign_transaction(&mut tx)
                .await
                .map_err(|e| Error::Other(format!("fee payer signing failed: {e}")))?;
            let signature = self
                .rpc
                .send_and_confirm_transaction(&VersionedTransaction::from(tx))
                .map_err(|e| Error::Rpc(format!("settlement broadcast failed: {e}")))?;
            signatures.push(signature.to_string());
        }
        Ok(signatures)
    }

    /// Finalize channels whose payer-forced close has run out its grace period.
    ///
    /// After `closure_started_at + grace_period`, `seal` is permissionless. The
    /// sealed `distribute` that follows pays any settled delta to `payTo`,
    /// returns `deposit - settled` to the payer, and closes the escrow token
    /// account. Both run in one transaction per channel.
    ///
    /// Channels that are not yet due are skipped, and a channel another crank
    /// already advanced is treated as success — the terminal onchain state is
    /// what matters, not which worker got there.
    ///
    /// Claim before this runs: a voucher still unclaimed when the watermark
    /// freezes is value the server forfeits to the payer.
    pub async fn finalize_close(&self, channel_ids: &[String]) -> Result<Vec<String>, Error> {
        let program_id = self.program_id()?;
        let mint = self.mint()?;
        let token_program = self.token_program()?;
        let receiver = pc::parse_pubkey(&self.config.pay_to)?;
        let now = now_unix() as i64;
        let mut groups = Vec::new();
        for channel_id in channel_ids {
            let channel = pc::parse_pubkey(channel_id)?;
            let onchain = self.fetch_channel(&channel)?;
            if onchain.status != CHANNEL_STATUS_CLOSING {
                continue;
            }
            let due = onchain
                .closure_started_at
                .saturating_add(i64::from(onchain.grace_period));
            if now < due {
                continue;
            }
            groups.push(ChannelInstructionGroup {
                channel_id: channel_id.clone(),
                instructions: vec![
                    pc::build_seal_instruction(&channel, &program_id),
                    pc::build_distribute_instruction(
                        &channel,
                        &pc::from_address(&onchain.payer),
                        &self.fee_payer,
                        &self.fee_payer,
                        &pc::treasury_owner(),
                        &mint,
                        &pc::sole_recipient(&receiver),
                        &token_program,
                        &program_id,
                    ),
                ],
            });
        }
        // One channel per transaction: a seal/distribute pair is far larger
        // than a claim, and a single failure must not strand its neighbours.
        let finalized: Vec<_> = groups
            .iter()
            .map(|group| group.channel_id.clone())
            .collect();
        let signatures = self.submit_groups(groups, 1).await?;
        for channel_id in finalized {
            self.store
                .update_channel(
                    &channel_id,
                    Box::new(|current| {
                        let mut state = current.ok_or_else(|| {
                            crate::core::store::StoreError::Internal("channel not found".into())
                        })?;
                        state.sealed = true;
                        state.last_activity_at = now_unix();
                        Ok(state)
                    }),
                )
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?;
        }
        Ok(signatures)
    }

    /// Recover the PDA rent this server fronted for `Distributed` channels.
    ///
    /// Permissionless, and gated by the program on
    /// `clock.slot > open_slot + OPEN_SLOT_WINDOW`. Rent always returns to the
    /// recorded `rent_payer`, so an abandoned channel can never permanently
    /// lock what the sponsor put up.
    pub async fn reclaim(&self, channel_ids: &[String]) -> Result<Vec<String>, Error> {
        let program_id = self.program_id()?;
        let slot = self
            .rpc
            .get_slot()
            .map_err(|e| Error::Rpc(format!("slot fetch failed: {e}")))?;
        let mut groups = Vec::new();
        for channel_id in channel_ids {
            let channel = pc::parse_pubkey(channel_id)?;
            // A reclaimed channel's account is already gone; treat an absent or
            // undecodable account as done rather than an error.
            let Ok(onchain) = self.fetch_channel(&channel) else {
                continue;
            };
            if onchain.status != CHANNEL_STATUS_DISTRIBUTED
                || slot <= onchain.open_slot.saturating_add(pc::OPEN_SLOT_WINDOW)
            {
                continue;
            }
            groups.push(ChannelInstructionGroup {
                channel_id: channel_id.clone(),
                instructions: vec![pc::build_reclaim_instruction(
                    &channel,
                    &self.fee_payer,
                    &program_id,
                )],
            });
        }
        let reclaimed: Vec<_> = groups
            .iter()
            .map(|group| group.channel_id.clone())
            .collect();
        let signatures = self.submit_groups(groups, pc::MAX_RECLAIMS_PER_TX).await?;
        for channel_id in reclaimed {
            self.store
                .delete_channel(&channel_id)
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?;
        }
        Ok(signatures)
    }

    /// Discover every channel whose rent this server sponsored.
    ///
    /// Local state can be lost; the chain cannot. This rebuilds the lifecycle
    /// work queue by filtering on `Channel.rent_payer`, then rederives each
    /// account's PDA before accepting it — a `getProgramAccounts` filter result
    /// is never trusted on its own.
    ///
    /// It does not recover the server's charge watermark or unclaimed voucher;
    /// those exist only in the store. If they are lost the server must not
    /// invent a charge — the conservative action is to close at the current
    /// onchain `settled` and return the remainder to the payer.
    pub fn discover_sponsored_channels(&self) -> Result<Vec<(Pubkey, Channel)>, Error> {
        use solana_rpc_client_api::config::{
            RpcAccountInfoConfig, RpcProgramAccountsConfig, UiAccountEncoding,
        };
        use solana_rpc_client_api::filter::{Memcmp, RpcFilterType};
        use solana_rpc_client_api::request::RpcRequest;
        use solana_rpc_client_api::response::RpcKeyedAccount;

        let program_id = self.program_id()?;
        let config = RpcProgramAccountsConfig {
            filters: Some(vec![
                RpcFilterType::DataSize(pc::CHANNEL_ACCOUNT_SIZE as u64),
                RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
                    pc::CHANNEL_RENT_PAYER_OFFSET,
                    self.fee_payer.to_bytes().to_vec(),
                )),
            ]),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                ..Default::default()
            },
            ..Default::default()
        };
        let params = serde_json::json!([program_id.to_string(), config]);
        let keyed: Vec<RpcKeyedAccount> = self
            .rpc
            .send(RpcRequest::GetProgramAccounts, params)
            .map_err(|e| Error::Rpc(format!("getProgramAccounts failed: {e}")))?;

        let mut found = Vec::new();
        for entry in keyed {
            let Ok(address) = Pubkey::from_str(&entry.pubkey) else {
                continue;
            };
            let Some(data) = entry.account.data.decode() else {
                continue;
            };
            let Ok(channel) = Channel::from_bytes(&data) else {
                continue;
            };
            let (derived, _) = pc::find_channel_pda(
                &pc::from_address(&channel.payer),
                &pc::from_address(&channel.payee),
                &pc::from_address(&channel.mint),
                &pc::from_address(&channel.authorized_signer),
                channel.salt,
                channel.open_slot,
                &program_id,
            );
            if derived == address {
                found.push((address, channel));
            }
        }
        Ok(found)
    }
}

/// The channel payer's base58 signature over a setup transaction.
///
/// Slot 0 is the sponsor's and is still empty before co-signing, so the payer's
/// slot is what identifies a client-supplied transaction across retries. The
/// payer signs the compiled message, which commits to the blockhash and every
/// instruction, so the signature is unique to this exact transaction.
fn payer_signature(transaction: &VersionedTransaction) -> Option<String> {
    let signature = transaction.signatures.get(1)?;
    Some(signature.to_string())
}

fn decode_signature(signature_b58: &str) -> Result<[u8; 64], Error> {
    let bytes = bs58::decode(signature_b58)
        .into_vec()
        .map_err(|e| Error::Other(format!("invalid voucher signature: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::Other("voucher signature is not 64 bytes".into()))
}

fn encode_json<T: serde::Serialize>(value: &T) -> Result<String, Error> {
    let json = serde_json::to_string(value)
        .map_err(|e| Error::Other(format!("serialization failed: {e}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        json.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::protocol::schemes::batch_settlement::{
        BatchDeposit, BatchVoucher, MAX_WITHDRAW_DELAY_SECONDS,
    };
    use crate::x402::protocol::schemes::exact::programs;
    use async_trait::async_trait;
    use ed25519_dalek::{Signer as _, SigningKey};
    use solana_keychain::{SignTransactionResult, SignerError};
    use solana_signature::Signature;

    const PAY_TO: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";

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
            _tx: &mut Transaction,
        ) -> Result<SignTransactionResult, SignerError> {
            Err(SignerError::Other("unused in these tests".to_string()))
        }
        async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
            Ok(Signature::from(self.key.sign(message).to_bytes()))
        }
        async fn is_available(&self) -> bool {
            true
        }
    }

    fn handler(store: Arc<dyn ChannelStore>) -> (X402BatchSettlement, Pubkey) {
        let signer = TestSigner::new(21);
        let fee_payer = signer.pubkey();
        let mut config = BatchConfig::new(PAY_TO, "localnet", Arc::new(signer));
        config.withdraw_delay = 3600;
        config.memo = Some("invoice-1".to_string());
        (
            X402BatchSettlement::with_store(config, store).expect("valid config"),
            fee_payer,
        )
    }

    /// A client keypair, its channel config against `fee_payer`, and the derived
    /// channel PDA.
    fn client(
        fee_payer: &Pubkey,
        requirements: &BatchRequirements,
    ) -> (SigningKey, BatchChannelConfig, Pubkey) {
        let key = SigningKey::from_bytes(&[22u8; 32]);
        let payer = pc::pubkey_string(&Pubkey::from(key.verifying_key().to_bytes()));
        let config = BatchChannelConfig {
            payer: payer.clone(),
            payer_authorizer: payer,
            receiver: requirements.pay_to.clone(),
            receiver_authorizer: None,
            token: requirements.asset.clone(),
            withdraw_delay: requirements.extra.withdraw_delay,
            salt: "42".to_string(),
            open_slot: 341_000_000,
        };
        let channel = derive_channel_id(
            &config,
            &pc::pubkey_string(fee_payer),
            &pc::default_program_id(),
        )
        .expect("derivable");
        (key, config, channel)
    }

    fn voucher(key: &SigningKey, channel: &Pubkey, max_claimable: u64) -> BatchVoucher {
        let message =
            pc::voucher_message_bytes(channel, max_claimable, VOUCHER_EXPIRES_AT).unwrap();
        BatchVoucher {
            channel_id: pc::pubkey_string(channel),
            max_claimable_amount: max_claimable.to_string(),
            expires_at: VOUCHER_EXPIRES_AT,
            signature: bs58::encode(key.sign(&message).to_bytes()).into_string(),
        }
    }

    fn header(requirements: &BatchRequirements, payload: BatchPayload) -> String {
        let envelope = BatchPaymentPayload {
            x402_version: X402_VERSION_V2,
            accepted: requirements.clone(),
            payload,
        };
        encode_json(&envelope).unwrap()
    }

    fn seeded(
        channel: &Pubkey,
        config: &BatchChannelConfig,
        deposit: u64,
        cumulative: u64,
    ) -> ChannelState {
        ChannelState {
            channel_id: pc::pubkey_string(channel),
            authorized_signer: config.payer_authorizer.clone(),
            deposit,
            cumulative,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            open_slot: Some(config.open_slot),
            payer: config.payer.clone(),
            rent_payer: String::new(),
            opening_challenge_id: String::new(),
            authentication: None,
            voucher_signer: "client".to_string(),
            idle_timeout_seconds: None,
            last_activity_at: 0,
            spent_amount: 0,
            settled_on_chain: 0,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
            lifecycle: None,
            schema_version: CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        }
    }

    /// A deposit that confirmed on a first attempt must not be counted again
    /// when the request is retried.
    ///
    /// The first attempt can broadcast, confirm, and record the escrow and
    /// still fail afterwards — a store error while committing the voucher, say.
    /// If the retry re-added the same amount, the ceiling would exceed anything
    /// the chain will ever hold, the confirmed-state check could never pass,
    /// and the client's escrow would be stranded with its voucher permanently
    /// uncommittable.
    #[test]
    fn a_confirmed_deposit_is_not_counted_twice_on_retry() {
        let (_, fee_payer) = handler(Arc::new(MemoryChannelStore::new()));
        let requirements = BatchRequirements {
            scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
            network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
            amount: "1000".to_string(),
            asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            pay_to: PAY_TO.to_string(),
            max_timeout_seconds: 300,
            extra: BatchExtra {
                payment_flow: None,
                fee_payer: pc::pubkey_string(&fee_payer),
                receiver_authorizer: None,
                withdraw_delay: 3600,
                token_program: programs::TOKEN_PROGRAM.to_string(),
                memo: None,
                recent_blockhash: None,
                recent_slot: None,
                channel_state: None,
                voucher_state: None,
            },
        };
        let (_, config, channel) = client(&fee_payer, &requirements);
        let signature = "5xTopUpSignature";

        // Before the top-up is applied, its amount raises the ceiling.
        let state = seeded(&channel, &config, 5_000, 0);
        assert_eq!(
            X402BatchSettlement::deposit_ceiling(Some(&state), 3_000, Some(signature)).unwrap(),
            8_000
        );

        // After it confirms, the stored deposit already includes it, so the
        // ceiling is the confirmed deposit — not the confirmed deposit plus the
        // same top-up a second time.
        let mut applied = seeded(&channel, &config, 8_000, 0);
        applied
            .processed_topup_signatures
            .push(signature.to_string());
        assert_eq!(
            X402BatchSettlement::deposit_ceiling(Some(&applied), 3_000, Some(signature)).unwrap(),
            8_000
        );

        // A different top-up against the same channel still adds.
        assert_eq!(
            X402BatchSettlement::deposit_ceiling(Some(&applied), 3_000, Some("otherSignature"))
                .unwrap(),
            11_000
        );

        // A first deposit has no stored channel: the open is the whole escrow.
        assert_eq!(
            X402BatchSettlement::deposit_ceiling(None, 3_000, Some(signature)).unwrap(),
            3_000
        );
    }

    #[test]
    fn requirements_advertise_the_scheme_wire_contract() {
        let (handler, fee_payer) = handler(Arc::new(MemoryChannelStore::new()));
        let requirements = handler.requirements("0.001").expect("requirements build");
        assert_eq!(requirements.scheme, BATCH_SETTLEMENT_SCHEME);
        assert_eq!(requirements.amount, "1000");
        assert_eq!(requirements.pay_to, PAY_TO);
        assert_eq!(requirements.extra.fee_payer, pc::pubkey_string(&fee_payer));
        assert_eq!(requirements.extra.withdraw_delay, 3600);
        assert_eq!(requirements.extra.token_program, programs::TOKEN_PROGRAM);
        assert_eq!(requirements.extra.memo.as_deref(), Some("invoice-1"));
        // The flow is the protocol default, so it stays off the wire, and the
        // program id is never negotiated through `extra`.
        let json = serde_json::to_value(&requirements).unwrap();
        assert!(json["extra"].get("paymentFlow").is_none());
        assert!(json["extra"].get("channelProgram").is_none());
    }

    #[tokio::test]
    async fn withdraw_delay_outside_the_conformance_range_is_refused_at_verify() {
        let (mut handler, _) = handler(Arc::new(MemoryChannelStore::new()));
        handler.config.withdraw_delay = MAX_WITHDRAW_DELAY_SECONDS + 1;
        let requirements = handler.requirements("0.001").unwrap();
        // The challenge is still constructible, but a payment against it fails
        // closed rather than opening a channel the client cannot escape.
        let (key, config, channel) = client(&handler.fee_payer, &requirements);
        let payload = BatchPayload::Voucher {
            channel_config: config,
            voucher: voucher(&key, &channel, 1000),
        };
        let header = header(&requirements, payload);
        let err = handler.verify_payment(&header, "0.001").await.unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_WITHDRAW_DELAY_OUT_OF_RANGE
        );
    }

    #[tokio::test]
    async fn a_voucher_for_an_unknown_channel_is_refused() {
        let (handler, fee_payer) = handler(Arc::new(MemoryChannelStore::new()));
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        let payload = BatchPayload::Voucher {
            channel_config: config,
            voucher: voucher(&key, &channel, 1000),
        };
        let err = handler
            .verify_payment(&header(&requirements, payload), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CHANNEL_STATE
        );
    }

    #[tokio::test]
    async fn fixed_pricing_binds_the_next_voucher_and_the_deposit_ceiling() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        store
            .put_channel(
                &pc::pubkey_string(&channel),
                seeded(&channel, &config, 5_000, 2_000),
            )
            .await
            .unwrap();

        let payload = |max: u64| BatchPayload::Voucher {
            channel_config: config.clone(),
            voucher: voucher(&key, &channel, max),
        };

        // Exactly one price above the watermark is the only fresh voucher the
        // server accepts.
        let outcome = handler
            .verify_payment(&header(&requirements, payload(3_000)), "0.001")
            .await
            .expect("a correctly-stepped voucher verifies");
        assert!(outcome.serve);
        assert!(!outcome.replay);
        assert_eq!(outcome.charged_amount, 1_000);
        drop(outcome);

        // A larger step would let the client buy one request and authorize two.
        let err = handler
            .verify_payment(&header(&requirements, payload(4_000)), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH
        );

        // A stale voucher must not replay a past request into a fresh serve.
        let err = handler
            .verify_payment(&header(&requirements, payload(2_000)), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH
        );

        // And nothing may authorize beyond what is actually escrowed.
        let reseeded = seeded(&channel, &config, 3_500, 3_000);
        store
            .update_channel(
                &pc::pubkey_string(&channel),
                Box::new(move |_| Ok(reseeded)),
            )
            .await
            .unwrap();
        let err = handler
            .verify_payment(&header(&requirements, payload(4_000)), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CUMULATIVE_EXCEEDS_DEPOSIT
        );
    }

    #[tokio::test]
    async fn an_exact_repeat_is_a_replay_rather_than_a_second_serve() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        let repeated = voucher(&key, &channel, 3_000);
        let mut state = seeded(&channel, &config, 5_000, 3_000);
        state.highest_voucher_signature = Some(repeated.signature.clone());
        state.highest_voucher_expires_at = Some(VOUCHER_EXPIRES_AT);
        store
            .put_channel(&pc::pubkey_string(&channel), state)
            .await
            .unwrap();

        let payload = BatchPayload::Voucher {
            channel_config: config,
            voucher: repeated,
        };
        let outcome = handler
            .verify_payment(&header(&requirements, payload), "0.001")
            .await
            .expect("an exact repeat verifies");
        // The request was already paid for: it must not be charged or served
        // again.
        assert!(outcome.replay);
        assert!(!outcome.serve);
        assert_eq!(outcome.charged_amount, 0);
    }

    #[tokio::test]
    async fn a_channel_admits_one_request_at_a_time() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        store
            .put_channel(
                &pc::pubkey_string(&channel),
                seeded(&channel, &config, 5_000, 0),
            )
            .await
            .unwrap();
        let payload = || BatchPayload::Voucher {
            channel_config: config.clone(),
            voucher: voucher(&key, &channel, 1_000),
        };

        let first = handler
            .verify_payment(&header(&requirements, payload()), "0.001")
            .await
            .expect("first request verifies");
        // Without serialization two concurrent requests could both read the
        // watermark, both serve, and only one commit.
        let err = handler
            .verify_payment(&header(&requirements, payload()), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::DUPLICATE_SETTLEMENT
        );

        // Dropping the outcome releases the channel, including on the error and
        // panic paths.
        drop(first);
        handler
            .verify_payment(&header(&requirements, payload()), "0.001")
            .await
            .expect("the channel is free again");
    }

    #[tokio::test]
    async fn a_payload_built_for_other_requirements_is_refused() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        store
            .put_channel(
                &pc::pubkey_string(&channel),
                seeded(&channel, &config, 5_000, 0),
            )
            .await
            .unwrap();

        // A payload whose `accepted` names a cheaper price than the route: the
        // client must not be able to pay one route's price for another's.
        let mut cheaper = requirements.clone();
        cheaper.amount = "1".to_string();
        let payload = BatchPayload::Voucher {
            channel_config: config,
            voucher: voucher(&key, &channel, 1),
        };
        let err = handler
            .verify_payment(&header(&cheaper, payload), "0.001")
            .await
            .unwrap_err();
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CHANNEL_STATE
        );
    }

    #[tokio::test]
    async fn a_refund_carrying_a_cooperative_hint_is_refused() {
        let (handler, fee_payer) = handler(Arc::new(MemoryChannelStore::new()));
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        let payload = BatchPayload::Refund {
            channel_config: config,
            transaction: "b64".to_string(),
            voucher: Some(voucher(&key, &channel, 1_000)),
            close_authorization: None,
        };
        let err = handler
            .verify_payment(&header(&requirements, payload), "0.001")
            .await
            .unwrap_err();
        // A receiver-authorizer key in an untrusted request is not a trust
        // anchor, so the shortcut is refused rather than silently ignored.
        assert_eq!(
            crate::x402::protocol::schemes::batch_settlement::classify(&err.to_string()),
            codes::INVALID_CLOSE_AUTHORIZATION
        );
    }

    #[test]
    fn payment_headers_must_name_this_scheme() {
        let (handler, _) = handler(Arc::new(MemoryChannelStore::new()));
        let mut requirements = handler.requirements("0.001").unwrap();
        requirements.scheme = "exact".to_string();
        let payload = BatchPayload::Deposit {
            channel_config: BatchChannelConfig {
                payer: PAY_TO.to_string(),
                payer_authorizer: PAY_TO.to_string(),
                receiver: PAY_TO.to_string(),
                receiver_authorizer: None,
                token: requirements.asset.clone(),
                withdraw_delay: 3600,
                salt: "1".to_string(),
                open_slot: 1,
            },
            voucher: BatchVoucher {
                channel_id: PAY_TO.to_string(),
                max_claimable_amount: "1".to_string(),
                expires_at: 0,
                signature: "sig".to_string(),
            },
            deposit: BatchDeposit {
                amount: "1".to_string(),
                transaction: "b64".to_string(),
            },
        };
        let err = handler
            .parse_payment(&header(&requirements, payload))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidPayloadType(scheme) if scheme == "exact"));
    }

    #[test]
    fn settlement_headers_round_trip_the_payment_response() {
        let (handler, _) = handler(Arc::new(MemoryChannelStore::new()));
        let response = BatchSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some(PAY_TO.to_string()),
            transaction: String::new(),
            network: handler.network(),
            amount: String::new(),
            extra: Some(BatchSettlementExtra {
                commitment_id: Some("chan:5000".to_string()),
                charged_amount: Some("1000".to_string()),
                channel_state: None,
            }),
        };
        let (name, value) = handler.settlement_header(&response).unwrap();
        assert_eq!(name, PAYMENT_RESPONSE_HEADER);
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).unwrap();
        let back: BatchSettlementResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(back.success);
        assert_eq!(
            back.extra.unwrap().commitment_id.as_deref(),
            Some("chan:5000")
        );
    }

    #[tokio::test]
    async fn a_corrective_challenge_proves_what_it_claims_to_have_charged() {
        let store = Arc::new(MemoryChannelStore::new());
        let (handler, fee_payer) = handler(store.clone());
        let requirements = handler.requirements("0.001").unwrap();
        let (key, config, channel) = client(&fee_payer, &requirements);
        let held = voucher(&key, &channel, 3_000);
        let mut state = seeded(&channel, &config, 5_000, 3_000);
        state.highest_voucher_signature = Some(held.signature.clone());
        state.highest_voucher_expires_at = Some(VOUCHER_EXPIRES_AT);
        store
            .put_channel(&pc::pubkey_string(&channel), state)
            .await
            .unwrap();

        let envelope = handler
            .corrective_challenge("0.001", &pc::pubkey_string(&channel))
            .await
            .expect("corrective challenge builds");
        assert_eq!(
            envelope.error.as_deref(),
            Some(codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH)
        );
        let extra = &envelope.accepts[0].extra;
        let snapshot = extra.channel_state.as_ref().expect("snapshot present");
        assert_eq!(snapshot.charged_cumulative_amount.as_deref(), Some("3000"));
        // The proof is the client's own signature at that amount, so the client
        // can verify the server is not inflating the base it will sign from.
        let proof = extra.voucher_state.as_ref().expect("proof present");
        assert_eq!(proof.signed_max_claimable, "3000");
        assert_eq!(proof.signature, held.signature);
        crate::x402::protocol::schemes::batch_settlement::check_corrective_voucher_state(
            proof,
            &pc::pubkey_string(&channel),
            &config.payer_authorizer,
            3_000,
        )
        .expect("the client accepts the proof");
    }
}
