//! Server-side session intent — challenge issuance, voucher verification,
//! and channel lifecycle management.
//!
//! # Overview
//!
//! 1. Server calls [`SessionServer::build_challenge_request`] to produce the
//!    `SessionRequest` embedded in a 402 challenge.
//! 2. Client responds with `SessionAction::Open` — server calls
//!    [`SessionServer::process_open`] to record the channel.
//! 3. For each subsequent API call the client attaches `SessionAction::Voucher`
//!    — server calls [`SessionServer::verify_voucher`] to validate and advance
//!    the settled watermark atomically.
//! 4. At session end the client (or server) triggers close. The server calls
//!    [`SessionServer::finalize_params`] to get the parameters needed to
//!    submit on-chain finalize + distribute transactions.
//!
//! # Note on on-chain verification
//!
//! `process_open` and `process_topup` currently trust the provided transaction
//! signature and deposit amount. For production use, wire up full RPC account
//! verification before persisting channel state.

use solana_pubkey::Pubkey;

use crate::error::{Error, Result};
use crate::program::payment_channels;
use crate::protocol::intents::session::{
    ClosePayload, CommitPayload, CommitReceipt, CommitStatus, MeteringDirective, OpenPayload,
    SessionMode, SessionPullVoucherStrategy, SessionRequest, SessionSplit, SignedVoucher,
    TopUpPayload, VoucherPayload,
};
use crate::protocol::solana::{default_token_program_for_currency, resolve_stablecoin_mint};
use crate::store::{ChannelState, ChannelStore, CommittedDelivery, PendingDelivery, StoreError};

// ── Configuration ──

/// A payment split committed at channel open; distributed at close.
#[derive(Debug, Clone)]
pub struct Split {
    pub recipient: Pubkey,
    /// Share in basis points.
    pub bps: u16,
}

/// Server configuration for the session intent.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Operator public key (base58). Shown to clients in the challenge.
    pub operator: String,

    /// Primary payment recipient (base58).
    pub recipient: String,

    /// Optional splits routed to specific recipients at close.
    pub splits: Vec<Split>,

    /// Maximum cap the server will offer per session (base units).
    /// Clients may request a lower cap but not a higher one.
    pub max_cap: u64,

    /// Currency identifier (e.g., "USDC", mint address).
    pub currency: String,

    /// Token decimals (default 6 for USDC).
    pub decimals: u8,

    /// Solana network: "mainnet-beta", "devnet", "localnet".
    pub network: String,

    /// Payment-channel program ID. `None` defaults to the canonical program.
    pub program_id: Option<Pubkey>,

    /// Minimum voucher increment (base units). 0 = no minimum.
    pub min_voucher_delta: u64,

    /// Session modes this server accepts.
    ///
    /// Advertised to clients in the 402 challenge. An empty list or
    /// `[Push]` means only the payment-channel push mode is supported.
    pub modes: Vec<SessionMode>,

    /// Voucher authority used for pull sessions.
    ///
    /// Required when `modes` includes [`SessionMode::Pull`].
    pub pull_voucher_strategy: Option<SessionPullVoucherStrategy>,

    /// Solana RPC URL for on-chain open-transaction verification.
    ///
    /// When set, `process_open` calls `getSignatureStatuses` to confirm the
    /// open transaction was accepted by the network before persisting channel
    /// state. Leave `None` in unit tests or when you want to skip verification.
    pub rpc_url: Option<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            operator: String::new(),
            recipient: String::new(),
            splits: vec![],
            max_cap: 10_000_000, // 10 USDC
            currency: "USDC".to_string(),
            decimals: 6,
            network: "mainnet-beta".to_string(),
            program_id: None,
            min_voucher_delta: 0,
            modes: vec![SessionMode::Push],
            pull_voucher_strategy: None,
            rpc_url: None,
        }
    }
}

// ── Parameters returned to the caller for on-chain settlement ──

/// Parameters needed to submit a finalize + distribute transaction pair.
#[derive(Debug, Clone)]
pub struct FinalizeParams {
    /// On-chain channel address.
    pub channel_id: Pubkey,

    /// Public key authorized to sign vouchers for this channel.
    pub authorized_signer: Option<Pubkey>,

    /// Original channel payer.
    pub payer: Option<Pubkey>,

    /// SPL mint locked by the channel.
    pub mint: Option<Pubkey>,

    /// Payment-channels program ID.
    pub program_id: Pubkey,

    /// The settled watermark to commit on-chain.
    pub settled: u64,

    /// Signature for the highest accepted voucher.
    pub voucher_signature: Option<String>,

    /// Expiry timestamp for the highest accepted voucher.
    pub voucher_expires_at: Option<i64>,

    /// Primary recipient.
    pub recipient: Pubkey,

    /// Splits for the distribute instruction.
    pub splits: Vec<Split>,

    /// 32-byte distribution hash committed at channel open time.
    pub distribution_hash: [u8; 32],
}

/// Request to reserve a metered delivery for client-side ack/commit.
#[derive(Debug, Clone)]
pub struct DeliveryRequest {
    /// Channel/session ID that will pay for the delivery.
    pub session_id: String,

    /// Amount owed for this delivery in base units.
    pub amount: u64,

    /// Optional idempotency key. If omitted, the server derives one from the
    /// session id and next delivery sequence.
    pub delivery_id: Option<String>,

    /// Optional commit endpoint hint surfaced to the client.
    pub commit_url: Option<String>,

    /// Optional opaque proof surfaced to the client.
    pub proof: Option<String>,

    /// Optional directive expiry. Defaults to the voucher default expiry.
    pub expires_at: Option<i64>,
}

impl DeliveryRequest {
    pub fn new(session_id: impl Into<String>, amount: u64) -> Self {
        Self {
            session_id: session_id.into(),
            amount,
            delivery_id: None,
            commit_url: None,
            proof: None,
            expires_at: None,
        }
    }
}

// ── Server ──

/// Server-side session manager.
///
/// Generic over the channel store to support in-memory testing and
/// production persistence backends.
pub struct SessionServer<S: ChannelStore> {
    config: SessionConfig,
    store: S,
}

impl<S: ChannelStore> SessionServer<S> {
    pub fn new(config: SessionConfig, store: S) -> Self {
        Self { config, store }
    }

    /// Build the `SessionRequest` to embed in a 402 challenge.
    ///
    /// `cap` is the maximum this session will allow; clamped to `config.max_cap`.
    pub fn build_challenge_request(&self, cap: u64) -> SessionRequest {
        let effective_cap = cap.min(self.config.max_cap);
        SessionRequest {
            cap: effective_cap.to_string(),
            currency: self.config.currency.clone(),
            decimals: Some(self.config.decimals),
            network: Some(self.config.network.clone()),
            operator: self.config.operator.clone(),
            recipient: self.config.recipient.clone(),
            splits: self
                .config
                .splits
                .iter()
                .map(|s| SessionSplit {
                    recipient: bs58::encode(s.recipient.as_ref()).into_string(),
                    bps: s.bps,
                })
                .collect(),
            program_id: self
                .config
                .program_id
                .map(|p| bs58::encode(p.as_ref()).into_string()),
            description: None,
            external_id: None,
            min_voucher_delta: if self.config.min_voucher_delta > 0 {
                Some(self.config.min_voucher_delta.to_string())
            } else {
                None
            },
            // Omit if only Push — clients assume Push when modes is absent.
            modes: if self.config.modes == [SessionMode::Push] {
                vec![]
            } else {
                self.config.modes.clone()
            },
            pull_voucher_strategy: if self.config.modes.contains(&SessionMode::Pull) {
                self.config.pull_voucher_strategy.clone()
            } else {
                None
            },
            recent_blockhash: None,
        }
    }

    /// Build and validate payment-channel open parameters from an `open` payload.
    ///
    /// This verifies the client-provided payer/payee/mint/salt/deposit/channel
    /// fields against the session challenge and returns the exact on-chain open
    /// params expected by the payment-channels program.
    pub fn payment_channel_open_params(
        &self,
        payload: &OpenPayload,
    ) -> Result<payment_channels::OpenChannelParams> {
        let payer = parse_payload_pubkey(payload.payer.as_deref(), "payer")?;
        let payee = parse_payload_pubkey(payload.payee.as_deref(), "payee")?;
        let mint = parse_payload_pubkey(payload.mint.as_deref(), "mint")?;
        let authorized_signer = parse_pubkey_field(&payload.authorized_signer, "authorizedSigner")?;
        let salt = payload
            .salt
            .ok_or_else(|| Error::Other("payment-channel open missing salt".to_string()))?;
        let grace_period = payload
            .grace_period
            .ok_or_else(|| Error::Other("payment-channel open missing gracePeriod".to_string()))?;
        let deposit = payload.deposit_amount()?;
        let token_program = parse_pubkey_field(
            default_token_program_for_currency(
                &self.config.currency,
                Some(self.config.network.as_str()),
            ),
            "token program",
        )?;
        let program_id = self
            .config
            .program_id
            .unwrap_or_else(payment_channels::default_program_id);
        let expected_payee = parse_pubkey_field(&self.config.recipient, "recipient")?;
        let expected_mint = expected_payment_channel_mint(&self.config)?;

        if payee != expected_payee {
            return Err(Error::Other(
                "payment-channel open payee does not match challenge recipient".to_string(),
            ));
        }
        if mint != expected_mint {
            return Err(Error::Other(
                "payment-channel open mint does not match challenge currency".to_string(),
            ));
        }

        let recipients = self
            .config
            .splits
            .iter()
            .map(|split| payment_channels::Distribution {
                recipient: split.recipient,
                bps: split.bps,
            })
            .collect();
        let params = payment_channels::OpenChannelParams {
            payer,
            payee,
            mint,
            authorized_signer,
            salt,
            deposit,
            grace_period,
            recipients,
            token_program,
            program_id,
        };

        let expected_channel = payment_channels::derive_channel_addresses(&params).channel;
        let channel = parse_payload_pubkey(payload.channel_id.as_deref(), "channelId")?;
        if channel != expected_channel {
            return Err(Error::Other(
                "payment-channel open channelId does not match derived channel PDA".to_string(),
            ));
        }

        Ok(params)
    }

    /// Build the exact payment-channel open instruction expected for a payload.
    pub fn payment_channel_open_instruction(
        &self,
        payload: &OpenPayload,
    ) -> Result<solana_instruction::Instruction> {
        let params = self.payment_channel_open_params(payload)?;
        Ok(payment_channels::build_open_instruction(&params))
    }

    /// Process an `open` action: persist the channel state.
    ///
    /// Accepts payment-channel opens and operated-voucher delegated-token opens.
    /// Returns the stored `ChannelState`.
    ///
    /// When `config.rpc_url` is set, confirms the open transaction is finalized
    /// on-chain before persisting — rejects the open if the tx is unknown or
    /// failed. Leave `rpc_url` as `None` in unit tests.
    pub async fn process_open(&self, payload: &OpenPayload) -> Result<ChannelState> {
        let supports_mode = if self.config.modes.is_empty() {
            payload.mode == SessionMode::Push
        } else {
            self.config.modes.contains(&payload.mode)
        };
        if !supports_mode {
            return Err(Error::Other(format!(
                "Session mode {:?} is not supported by this challenge",
                payload.mode
            )));
        }

        let session_id = payload.session_id()?;
        let deposit = payload.deposit_amount()?;

        if deposit == 0 {
            return Err(Error::Other(
                "Deposit must be greater than zero".to_string(),
            ));
        }

        if deposit > self.config.max_cap {
            return Err(Error::Other(format!(
                "Deposit {deposit} exceeds max cap {}",
                self.config.max_cap
            )));
        }

        // On-chain verification: confirm the open transaction was accepted.
        //
        // Pull mode: host integrations submit server-broadcast transactions or
        // validate delegated-token state before invoking this lower-level store
        // method. Skip tx-sig verification here.
        //
        // Push mode: verify the payment-channel open tx is confirmed before persisting.
        if payload.mode == SessionMode::Push {
            if let Some(ref rpc_url) = self.config.rpc_url {
                verify_open_signature(&payload.signature, rpc_url).map_err(|e| {
                    tracing::warn!(signature = %payload.signature, %e, "open tx verification failed");
                    e
                })?;
                tracing::debug!(signature = %payload.signature, "open tx confirmed on-chain");
            }
        }

        let state = ChannelState {
            channel_id: session_id.to_string(),
            authorized_signer: payload.authorized_signer.clone(),
            deposit,
            cumulative: 0,
            finalized: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            operator: payload.owner.clone().or_else(|| payload.payer.clone()),
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
        };

        self.store
            .put_channel(session_id, state.clone())
            .await
            .map_err(store_err)?;

        Ok(state)
    }

    /// Verify a voucher, advance the watermark, and return the new cumulative.
    ///
    /// Rejects vouchers that:
    /// - Belong to an unknown channel
    /// - Have a non-increasing cumulative (unless exact idempotent replay)
    /// - Exceed the deposit cap
    /// - Have an invalid signature
    /// - Are below the minimum voucher delta
    /// - Are submitted after a close has been requested
    ///
    /// Uses atomic read-modify-write to prevent double-spend under concurrent requests.
    pub async fn verify_voucher(&self, payload: &VoucherPayload) -> Result<u64> {
        let voucher = &payload.voucher;
        let channel_id = &voucher.data.channel_id;

        // 1. Parse new_cumulative from payload
        let new_cumulative: u64 = voucher
            .data
            .cumulative
            .parse()
            .map_err(|_| Error::Other("Invalid cumulative in voucher".to_string()))?;

        // 2. Get channel state (for authorized_signer — never changes after open)
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;

        // 3. Check finalized
        if state.finalized {
            return Err(Error::Other("Channel is already finalized".to_string()));
        }

        // 4. Check close-pending
        if state.close_requested_at.is_some() {
            return Err(Error::Other(
                "Channel close is pending — no further vouchers accepted".to_string(),
            ));
        }

        // 5. Idempotent replay: same cumulative AND same signature
        if new_cumulative == state.cumulative
            && state.highest_voucher_signature.as_deref() == Some(voucher.signature.as_str())
        {
            verify_signature(voucher, &state.authorized_signer)?;
            return Ok(new_cumulative);
        }

        // 6. Must exceed watermark (non-replay case)
        if new_cumulative <= state.cumulative {
            return Err(Error::Other(format!(
                "Voucher cumulative {new_cumulative} must exceed watermark {}",
                state.cumulative
            )));
        }

        // 7. Must not exceed deposit
        if new_cumulative > state.deposit {
            return Err(Error::Other(format!(
                "Voucher cumulative {new_cumulative} exceeds deposit {}",
                state.deposit
            )));
        }

        // 8. Min delta check
        let delta = new_cumulative - state.cumulative;
        let min = self.config.min_voucher_delta;
        if min > 0 && delta < min {
            return Err(Error::Other(format!(
                "Voucher delta {delta} is below minimum {min}"
            )));
        }

        // 9. Verify signature (expensive, before touching store)
        verify_signature(voucher, &state.authorized_signer)?;

        // 10. Clone sig for use in closure
        let sig = voucher.signature.clone();
        let expires_at = voucher.data.expires_at;

        // 11. Atomic read-modify-write
        let new_state = self
            .store
            .update_channel(
                channel_id,
                Box::new(move |state_opt| {
                    let state = state_opt
                        .ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?;
                    // Re-check finalized inside closure
                    if state.finalized {
                        return Err(StoreError::Internal(
                            "Channel is already finalized".to_string(),
                        ));
                    }
                    // Re-check close-pending inside closure
                    if state.close_requested_at.is_some() {
                        return Err(StoreError::Internal(
                            "Channel close is pending — no further vouchers accepted".to_string(),
                        ));
                    }
                    // Idempotent replay inside closure
                    if new_cumulative == state.cumulative
                        && state.highest_voucher_signature.as_deref() == Some(&sig)
                    {
                        return Ok(state);
                    }
                    // Concurrent watermark advancement check
                    if new_cumulative <= state.cumulative {
                        return Err(StoreError::Internal(
                            "Concurrent update: watermark advanced".to_string(),
                        ));
                    }
                    Ok(ChannelState {
                        cumulative: new_cumulative,
                        highest_voucher_signature: Some(sig),
                        highest_voucher_expires_at: Some(expires_at),
                        ..state
                    })
                }),
            )
            .await
            .map_err(store_err)?;

        // 12. Return new cumulative
        Ok(new_state.cumulative)
    }

    /// Process a `topup` action: atomically update the channel's deposit cap.
    ///
    /// The new deposit must be greater than the current deposit.
    /// In production, verify the top-up transaction on-chain first.
    pub async fn process_topup(&self, payload: &TopUpPayload) -> Result<ChannelState> {
        let new_deposit: u64 = payload
            .new_deposit
            .parse()
            .map_err(|_| Error::Other("Invalid new_deposit".to_string()))?;
        let max_cap = self.config.max_cap;
        let cid = payload.channel_id.clone();
        self.store
            .update_channel(
                &payload.channel_id,
                Box::new(move |state_opt| {
                    let state = state_opt
                        .ok_or_else(|| StoreError::Internal(format!("Channel {cid} not found")))?;
                    if new_deposit <= state.deposit {
                        return Err(StoreError::Internal(format!(
                            "New deposit {new_deposit} must exceed current deposit {}",
                            state.deposit
                        )));
                    }
                    if new_deposit > max_cap {
                        return Err(StoreError::Internal(format!(
                            "New deposit {new_deposit} exceeds max cap {max_cap}"
                        )));
                    }
                    Ok(ChannelState {
                        deposit: new_deposit,
                        ..state
                    })
                }),
            )
            .await
            .map_err(store_err)
    }

    /// Reserve capacity for a delivered message/response and return the
    /// metering directive the client must commit after processing it.
    pub async fn begin_delivery(&self, request: DeliveryRequest) -> Result<MeteringDirective> {
        if request.amount == 0 {
            return Err(Error::Other(
                "Delivery amount must be greater than zero".to_string(),
            ));
        }

        let session_id = request.session_id.clone();
        let amount = request.amount;
        let currency = self.config.currency.clone();
        let commit_url = request.commit_url.clone();
        let proof = request.proof.clone();
        let requested_delivery_id = request.delivery_id.clone();
        let expires_at = request
            .expires_at
            .unwrap_or(crate::protocol::intents::session::DEFAULT_SESSION_EXPIRES_AT);
        let directive_out = std::sync::Arc::new(std::sync::Mutex::new(None));

        self.store
            .update_channel(
                &session_id,
                Box::new({
                    let session_id = session_id.clone();
                    let directive_out = std::sync::Arc::clone(&directive_out);
                    move |state_opt| {
                        let mut state = state_opt.ok_or_else(|| {
                            StoreError::Internal(format!("Channel {session_id} not found"))
                        })?;
                        if state.finalized {
                            return Err(StoreError::Internal(
                                "Channel is already finalized".to_string(),
                            ));
                        }
                        if state.close_requested_at.is_some() {
                            return Err(StoreError::Internal(
                                "Channel close is pending — no further deliveries accepted"
                                    .to_string(),
                            ));
                        }
                        let pending_total = state
                            .pending_deliveries
                            .iter()
                            .map(|delivery| delivery.amount)
                            .sum::<u64>();
                        if state.cumulative + pending_total + amount > state.deposit {
                            return Err(StoreError::Internal(format!(
                                "Delivery amount {amount} exceeds available deposit"
                            )));
                        }

                        let sequence = state.next_delivery_sequence + 1;
                        let delivery_id = requested_delivery_id
                            .clone()
                            .unwrap_or_else(|| format!("{session_id}:{sequence}"));
                        if state
                            .pending_deliveries
                            .iter()
                            .any(|delivery| delivery.delivery_id == delivery_id)
                            || state
                                .committed_deliveries
                                .iter()
                                .any(|delivery| delivery.delivery_id == delivery_id)
                        {
                            return Err(StoreError::Internal(format!(
                                "Delivery {delivery_id} already exists"
                            )));
                        }

                        state.next_delivery_sequence = sequence;
                        state.pending_deliveries.push(PendingDelivery {
                            delivery_id: delivery_id.clone(),
                            amount,
                            sequence,
                            expires_at,
                        });

                        *directive_out.lock().unwrap() = Some(MeteringDirective {
                            delivery_id,
                            session_id,
                            amount: amount.to_string(),
                            currency,
                            sequence,
                            expires_at,
                            commit_url,
                            proof,
                        });

                        Ok(state)
                    }
                }),
            )
            .await
            .map_err(store_err)?;

        let directive = directive_out.lock().unwrap().clone();
        directive.ok_or_else(|| {
            Error::Other("Delivery reservation did not produce directive".to_string())
        })
    }

    /// Commit a reserved delivery by verifying the attached voucher and
    /// advancing the settled watermark.
    pub async fn process_commit(&self, payload: &CommitPayload) -> Result<CommitReceipt> {
        let channel_id = payload.voucher.data.channel_id.clone();
        let new_cumulative: u64 = payload
            .voucher
            .data
            .cumulative
            .parse()
            .map_err(|_| Error::Other("Invalid cumulative in commit voucher".to_string()))?;

        let state = self
            .store
            .get_channel(&channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;

        if let Some(committed) = state
            .committed_deliveries
            .iter()
            .find(|delivery| delivery.delivery_id == payload.delivery_id)
        {
            if committed.cumulative == new_cumulative
                && committed.voucher_signature == payload.voucher.signature
            {
                verify_signature(&payload.voucher, &state.authorized_signer)?;
                return Ok(CommitReceipt {
                    delivery_id: payload.delivery_id.clone(),
                    session_id: channel_id,
                    amount: committed.amount.to_string(),
                    cumulative: committed.cumulative.to_string(),
                    status: CommitStatus::Replayed,
                });
            }
            return Err(Error::Other(format!(
                "Delivery {} was already committed with different voucher",
                payload.delivery_id
            )));
        }

        let pending = state
            .pending_deliveries
            .iter()
            .find(|delivery| delivery.delivery_id == payload.delivery_id)
            .cloned()
            .ok_or_else(|| Error::Other(format!("Delivery {} not found", payload.delivery_id)))?;
        let now = unix_now_i64();
        if pending.expires_at <= now {
            return Err(Error::Other(format!(
                "Delivery {} has expired",
                payload.delivery_id
            )));
        }
        if new_cumulative <= state.cumulative {
            return Err(Error::Other(format!(
                "Commit cumulative {new_cumulative} must exceed watermark {}",
                state.cumulative
            )));
        }
        verify_signature(&payload.voucher, &state.authorized_signer)?;

        let delivery_id = payload.delivery_id.clone();
        let signature = payload.voucher.signature.clone();
        let expires_at = payload.voucher.data.expires_at;
        let commit_outcome = std::sync::Arc::new(std::sync::Mutex::new(None));
        let _new_state = self
            .store
            .update_channel(
                &channel_id,
                Box::new({
                    let channel_id = channel_id.clone();
                    let commit_outcome = std::sync::Arc::clone(&commit_outcome);
                    move |state_opt| {
                        let mut state = state_opt.ok_or_else(|| {
                            StoreError::Internal(format!("Channel {channel_id} not found"))
                        })?;
                        if state.finalized {
                            return Err(StoreError::Internal(
                                "Channel is already finalized".to_string(),
                            ));
                        }
                        if state.close_requested_at.is_some() {
                            return Err(StoreError::Internal(
                                "Channel close is pending — no further commits accepted"
                                    .to_string(),
                            ));
                        }
                        if let Some(committed) = state
                            .committed_deliveries
                            .iter()
                            .find(|delivery| delivery.delivery_id == delivery_id)
                        {
                            if committed.cumulative == new_cumulative
                                && committed.voucher_signature == signature
                            {
                                *commit_outcome.lock().unwrap() = Some((
                                    committed.amount,
                                    committed.cumulative,
                                    CommitStatus::Replayed,
                                ));
                                return Ok(state);
                            }
                            return Err(StoreError::Internal(format!(
                                "Delivery {delivery_id} was already committed with different voucher"
                            )));
                        }
                        let pending_index = state
                            .pending_deliveries
                            .iter()
                            .position(|delivery| delivery.delivery_id == delivery_id)
                            .ok_or_else(|| {
                                StoreError::Internal(format!("Delivery {delivery_id} not found"))
                            })?;
                        let pending = state.pending_deliveries[pending_index].clone();
                        if pending.expires_at <= now {
                            return Err(StoreError::Internal(format!(
                                "Delivery {delivery_id} has expired"
                            )));
                        }
                        if new_cumulative <= state.cumulative {
                            return Err(StoreError::Internal(format!(
                                "Commit cumulative {new_cumulative} must exceed watermark {}",
                                state.cumulative
                            )));
                        }
                        let actual_amount = new_cumulative - state.cumulative;
                        if actual_amount > pending.amount {
                            return Err(StoreError::Internal(format!(
                                "Commit amount {actual_amount} exceeds reserved amount {}",
                                pending.amount
                            )));
                        }

                        state.pending_deliveries.remove(pending_index);
                        state.cumulative = new_cumulative;
                        state.highest_voucher_signature = Some(signature.clone());
                        state.highest_voucher_expires_at = Some(expires_at);
                        state.committed_deliveries.push(CommittedDelivery {
                            delivery_id: delivery_id.clone(),
                            amount: actual_amount,
                            cumulative: new_cumulative,
                            voucher_signature: signature,
                        });
                        *commit_outcome.lock().unwrap() =
                            Some((actual_amount, new_cumulative, CommitStatus::Committed));
                        Ok(state)
                    }
                }),
            )
            .await
            .map_err(store_err)?;

        let (amount, cumulative, status) = commit_outcome
            .lock()
            .unwrap()
            .ok_or_else(|| Error::Other("Commit did not produce a receipt".to_string()))?;
        Ok(CommitReceipt {
            delivery_id: payload.delivery_id.clone(),
            session_id: channel_id,
            amount: amount.to_string(),
            cumulative: cumulative.to_string(),
            status,
        })
    }

    /// Process a `close` action: atomically set close-pending, accept a final
    /// voucher if provided, and return the parameters needed for on-chain settlement.
    pub async fn process_close(&self, payload: &ClosePayload) -> Result<FinalizeParams> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let voucher_opt = payload.voucher.clone();

        self.store
            .update_channel(
                &payload.channel_id,
                Box::new(move |state_opt| {
                    let state = state_opt.ok_or_else(|| {
                        StoreError::Internal("Channel not found".to_string())
                    })?;
                    if state.finalized {
                        return Err(StoreError::Internal(
                            "Channel is already finalized".to_string(),
                        ));
                    }
                    if state.close_requested_at.is_some() {
                        return Err(StoreError::Internal("Close already requested".to_string()));
                    }

                    let (new_cumulative, new_sig, new_expires_at) =
                        if let Some(ref voucher) = voucher_opt {
                        let cumulative: u64 = voucher
                            .data
                            .cumulative
                            .parse()
                            .map_err(|_| StoreError::Internal("Invalid cumulative".to_string()))?;
                        if cumulative <= state.cumulative {
                            // Idempotent replay check
                            if cumulative == state.cumulative
                                && state.highest_voucher_signature.as_deref()
                                    == Some(voucher.signature.as_str())
                            {
                                (
                                    state.cumulative,
                                    state.highest_voucher_signature.clone(),
                                    state.highest_voucher_expires_at.or(Some(voucher.data.expires_at)),
                                )
                            } else {
                                return Err(StoreError::Internal(format!(
                                    "Final voucher cumulative {cumulative} must exceed watermark {}",
                                    state.cumulative
                                )));
                            }
                        } else {
                            if cumulative > state.deposit {
                                return Err(StoreError::Internal(
                                    "Final voucher exceeds deposit".to_string(),
                                ));
                            }
                            verify_signature(voucher, &state.authorized_signer)
                                .map_err(|e| StoreError::Internal(e.to_string()))?;
                            (
                                cumulative,
                                Some(voucher.signature.clone()),
                                Some(voucher.data.expires_at),
                            )
                        }
                    } else {
                        (
                            state.cumulative,
                            state.highest_voucher_signature.clone(),
                            state.highest_voucher_expires_at,
                        )
                    };

                    Ok(ChannelState {
                        cumulative: new_cumulative,
                        highest_voucher_signature: new_sig,
                        highest_voucher_expires_at: new_expires_at,
                        close_requested_at: Some(now),
                        ..state
                    })
                }),
            )
            .await
            .map_err(store_err)?;

        self.finalize_params(&payload.channel_id).await
    }

    /// Return finalize parameters for a channel ready for on-chain settlement.
    pub async fn finalize_params(&self, channel_id: &str) -> Result<FinalizeParams> {
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;

        let channel_pubkey = parse_pubkey(channel_id)?;
        let recipient_pubkey = parse_pubkey(&self.config.recipient)?;
        let authorized_signer = parse_pubkey(&state.authorized_signer).ok();
        let payer = state
            .operator
            .as_deref()
            .and_then(|payer| parse_pubkey(payer).ok());
        let mint = expected_payment_channel_mint(&self.config).ok();
        let program_id = self
            .config
            .program_id
            .unwrap_or_else(payment_channels::default_program_id);

        let splits_with_pubkeys: Vec<payment_channels::Distribution> = self
            .config
            .splits
            .iter()
            .map(|s| payment_channels::Distribution {
                recipient: s.recipient,
                bps: s.bps,
            })
            .collect();

        let distribution_hash = payment_channels::distribution_hash(&splits_with_pubkeys);

        Ok(FinalizeParams {
            channel_id: channel_pubkey,
            authorized_signer,
            payer,
            mint,
            program_id,
            settled: state.cumulative,
            voucher_signature: state.highest_voucher_signature,
            voucher_expires_at: state.highest_voucher_expires_at,
            recipient: recipient_pubkey,
            splits: self.config.splits.clone(),
            distribution_hash,
        })
    }

    /// Mark a channel as finalized (call after the on-chain finalize tx confirms).
    pub async fn mark_finalized(&self, channel_id: &str) -> Result<()> {
        self.store
            .mark_finalized(channel_id)
            .await
            .map_err(store_err)
    }
}

// ── Helpers ──

fn store_err(e: StoreError) -> Error {
    Error::Other(e.to_string())
}

fn unix_now_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Confirm that `sig_str` is a finalized, successful transaction on-chain.
///
/// Uses the blocking `RpcClient` — consistent with the rest of this module.
/// Returns an error if the signature is malformed, the tx was rejected, or
/// the tx is not found (not yet processed or doesn't exist).
#[cfg(feature = "server")]
fn verify_open_signature(sig_str: &str, rpc_url: &str) -> Result<()> {
    use solana_rpc_client::rpc_client::RpcClient;
    use solana_signature::Signature;
    use std::str::FromStr;

    let sig = Signature::from_str(sig_str)
        .map_err(|e| Error::Other(format!("invalid open tx signature '{sig_str}': {e}")))?;

    let rpc = RpcClient::new(rpc_url.to_string());

    match rpc
        .get_signature_status(&sig)
        .map_err(|e| Error::Other(format!("RPC error verifying open tx: {e}")))?
    {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(Error::Other(format!("open tx was rejected on-chain: {e}"))),
        None => Err(Error::Other(format!(
            "open tx '{sig_str}' not found — not yet confirmed or does not exist"
        ))),
    }
}

fn parse_pubkey(s: &str) -> Result<Pubkey> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| Error::Other(format!("Invalid pubkey {s}: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Other(format!("Pubkey {s} is not 32 bytes")))?;
    Ok(Pubkey::from(arr))
}

fn parse_payload_pubkey(value: Option<&str>, field: &str) -> Result<Pubkey> {
    let value =
        value.ok_or_else(|| Error::Other(format!("payment-channel open missing {field}")))?;
    parse_pubkey_field(value, field)
}

fn parse_pubkey_field(value: &str, field: &str) -> Result<Pubkey> {
    parse_pubkey(value).map_err(|e| Error::Other(format!("invalid payment-channel {field}: {e}")))
}

fn expected_payment_channel_mint(config: &SessionConfig) -> Result<Pubkey> {
    let mint = resolve_stablecoin_mint(&config.currency, Some(config.network.as_str()))
        .ok_or_else(|| Error::Other("payment-channel sessions require an SPL token".to_string()))?;
    parse_pubkey_field(mint, "currency")
}

/// Verify an Ed25519 voucher signature against the authorized signer.
fn verify_signature(voucher: &SignedVoucher, authorized_signer: &str) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if voucher.data.expires_at <= now {
        return Err(Error::Other("Voucher has expired".to_string()));
    }

    let message = voucher.data.message_bytes()?;

    let sig_bytes = bs58::decode(&voucher.signature)
        .into_vec()
        .map_err(|e| Error::Other(format!("Invalid signature encoding: {e}")))?;
    let pubkey_bytes = bs58::decode(authorized_signer)
        .into_vec()
        .map_err(|e| Error::Other(format!("Invalid authorized_signer: {e}")))?;

    let key_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| Error::Other("Pubkey is not 32 bytes".to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Error::Other("Signature is not 64 bytes".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| Error::Other(format!("Invalid authorized_signer key: {e}")))?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| Error::Other("Voucher signature verification failed".to_string()))
}

/// Compute the payment-channel distribution hash for explicit recipients.
///
/// The primary payee receives the implicit remainder and is not part of the
/// hashed preimage unless it is explicitly listed in `splits`.
pub fn compute_distribution_hash(_recipient: &Pubkey, splits: &[(Pubkey, u16)]) -> [u8; 32] {
    let recipients = splits
        .iter()
        .map(|(recipient, bps)| payment_channels::Distribution {
            recipient: *recipient,
            bps: *bps,
        })
        .collect::<Vec<_>>();
    payment_channels::distribution_hash(&recipients)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::intents::session::{
        ClosePayload, CommitPayload, CommitStatus, OpenPayload, SessionMode,
        SessionPullVoucherStrategy, VoucherData, VoucherPayload,
    };
    use crate::store::MemoryChannelStore;

    const RECIPIENT: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";

    fn make_server() -> SessionServer<MemoryChannelStore> {
        SessionServer::new(
            SessionConfig {
                operator: RECIPIENT.to_string(),
                recipient: RECIPIENT.to_string(),
                splits: vec![],
                max_cap: 10_000_000,
                currency: "USDC".to_string(),
                decimals: 6,
                network: "localnet".to_string(),
                program_id: None,
                min_voucher_delta: 0,
                modes: vec![SessionMode::Push],
                pull_voucher_strategy: None,
                rpc_url: None,
            },
            MemoryChannelStore::new(),
        )
    }

    fn make_server_with_min_delta(min_delta: u64) -> SessionServer<MemoryChannelStore> {
        SessionServer::new(
            SessionConfig {
                operator: RECIPIENT.to_string(),
                recipient: RECIPIENT.to_string(),
                splits: vec![],
                max_cap: 10_000_000,
                currency: "USDC".to_string(),
                decimals: 6,
                network: "localnet".to_string(),
                program_id: None,
                min_voucher_delta: min_delta,
                modes: vec![SessionMode::Push],
                pull_voucher_strategy: None,
                rpc_url: None,
            },
            MemoryChannelStore::new(),
        )
    }

    fn open_payload(channel_id: &str, deposit: u64, signer: &str) -> OpenPayload {
        OpenPayload::push(
            channel_id.to_string(),
            deposit.to_string(),
            signer.to_string(),
            "dummy_tx_sig".to_string(),
        )
    }

    // ── E2E helpers ──────────────────────────────────────────────────────────

    /// Build a deterministic MemorySigner + ActiveSession from a fixed seed.
    /// Returns (session, authorized_signer_b58, channel_id_b58).
    #[cfg(feature = "client")]
    fn make_e2e_session() -> (
        crate::client::session::ActiveSession,
        String, // authorized_signer
        String, // channel_id (base58)
        Pubkey, // channel Pubkey
    ) {
        use solana_keychain::MemorySigner;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(vk.as_bytes());
        let signer: Box<dyn solana_keychain::SolanaSigner> =
            Box::new(MemorySigner::from_bytes(&kp).expect("valid keypair"));
        let auth_signer = bs58::encode(vk.as_bytes()).into_string();
        let channel = Pubkey::new_unique();
        let chan_str = bs58::encode(channel.as_ref()).into_string();
        let session = crate::client::session::ActiveSession::new(channel, signer);
        (session, auth_signer, chan_str, channel)
    }

    // ── process_open ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn process_open_stores_state() {
        let server = make_server();
        let state = server
            .process_open(&open_payload("chan1", 1_000_000, "signer1"))
            .await
            .unwrap();
        assert_eq!(state.deposit, 1_000_000);
        assert_eq!(state.cumulative, 0);
        assert!(!state.finalized);
        assert_eq!(state.authorized_signer, "signer1");
    }

    #[tokio::test]
    async fn process_open_zero_deposit_rejected() {
        let server = make_server();
        assert!(server
            .process_open(&open_payload("chan1", 0, "signer1"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_open_exceeds_cap_rejected() {
        let server = make_server();
        assert!(server
            .process_open(&open_payload("chan1", 20_000_000, "signer1"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_open_rejects_unadvertised_pull_mode() {
        let server = make_server();
        let payload = OpenPayload::payment_channel_with_mode(
            SessionMode::Pull,
            "chan1".to_string(),
            "1000000".to_string(),
            "payer".to_string(),
            RECIPIENT.to_string(),
            "mint".to_string(),
            1,
            900,
            "signer1".to_string(),
            "pending".to_string(),
        );

        let err = server.process_open(&payload).await.unwrap_err();
        assert!(err.to_string().contains("not supported"));
    }

    #[tokio::test]
    async fn process_open_accepts_advertised_pull_client_voucher_channel() {
        let server = SessionServer::new(
            SessionConfig {
                modes: vec![SessionMode::Pull],
                pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let payload = OpenPayload::payment_channel_with_mode(
            SessionMode::Pull,
            "chan1".to_string(),
            "1000000".to_string(),
            "payer".to_string(),
            RECIPIENT.to_string(),
            "mint".to_string(),
            1,
            900,
            "signer1".to_string(),
            "pending".to_string(),
        );

        let state = server.process_open(&payload).await.unwrap();
        assert_eq!(state.channel_id, "chan1");
        assert_eq!(state.deposit, 1_000_000);
    }

    #[test]
    fn payment_channel_open_params_validate_challenge_fields() {
        use crate::protocol::solana::{mints, programs};
        use std::str::FromStr;

        let payer = Pubkey::new_unique();
        let authorized_signer = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).expect("valid recipient");
        let mint = Pubkey::from_str(mints::USDC_MAINNET).expect("valid USDC mint");
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).expect("valid token program");
        let server = SessionServer::new(
            SessionConfig {
                splits: vec![Split {
                    recipient: split_recipient,
                    bps: 10,
                }],
                modes: vec![SessionMode::Pull],
                pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let expected = payment_channels::OpenChannelParams {
            payer,
            payee: recipient,
            mint,
            authorized_signer,
            salt: 77,
            deposit: 1_000_000,
            grace_period: 900,
            recipients: vec![payment_channels::Distribution {
                recipient: split_recipient,
                bps: 10,
            }],
            token_program,
            program_id: payment_channels::default_program_id(),
        };
        let channel = payment_channels::derive_channel_addresses(&expected).channel;
        let payload = OpenPayload::payment_channel_with_mode(
            SessionMode::Pull,
            payment_channels::pubkey_string(&channel),
            expected.deposit.to_string(),
            payment_channels::pubkey_string(&payer),
            RECIPIENT.to_string(),
            mints::USDC_MAINNET.to_string(),
            expected.salt,
            expected.grace_period,
            payment_channels::pubkey_string(&authorized_signer),
            "pending".to_string(),
        );

        let params = server.payment_channel_open_params(&payload).unwrap();
        assert_eq!(params.payer, expected.payer);
        assert_eq!(params.payee, expected.payee);
        assert_eq!(params.mint, expected.mint);
        assert_eq!(params.authorized_signer, expected.authorized_signer);
        assert_eq!(params.recipients, expected.recipients);
        assert_eq!(
            server
                .payment_channel_open_instruction(&payload)
                .unwrap()
                .program_id,
            payment_channels::to_address(&expected.program_id)
        );

        let mut wrong_payee = payload.clone();
        wrong_payee.payee = Some(payment_channels::pubkey_string(&Pubkey::new_unique()));
        let err = server
            .payment_channel_open_params(&wrong_payee)
            .unwrap_err();
        assert!(err.to_string().contains("payee does not match"));

        let mut wrong_mint = payload.clone();
        wrong_mint.mint = Some(payment_channels::pubkey_string(&Pubkey::new_unique()));
        let err = server.payment_channel_open_params(&wrong_mint).unwrap_err();
        assert!(err.to_string().contains("mint does not match"));

        let mut missing_payer = payload.clone();
        missing_payer.payer = None;
        let err = server
            .payment_channel_open_params(&missing_payer)
            .unwrap_err();
        assert!(err.to_string().contains("missing payer"));

        let mut missing_salt = payload.clone();
        missing_salt.salt = None;
        let err = server
            .payment_channel_open_params(&missing_salt)
            .unwrap_err();
        assert!(err.to_string().contains("missing salt"));

        let mut missing_grace_period = payload.clone();
        missing_grace_period.grace_period = None;
        let err = server
            .payment_channel_open_params(&missing_grace_period)
            .unwrap_err();
        assert!(err.to_string().contains("missing gracePeriod"));

        let mut invalid_authorized_signer = payload.clone();
        invalid_authorized_signer.authorized_signer = "not-a-pubkey".to_string();
        let err = server
            .payment_channel_open_params(&invalid_authorized_signer)
            .unwrap_err();
        assert!(err.to_string().contains("authorizedSigner"));

        let sol_server = SessionServer::new(
            SessionConfig {
                currency: "SOL".to_string(),
                modes: vec![SessionMode::Pull],
                pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let err = sol_server
            .payment_channel_open_params(&payload)
            .unwrap_err();
        assert!(err.to_string().contains("SPL token"));

        let mut wrong_channel = payload.clone();
        wrong_channel.channel_id = Some(payment_channels::pubkey_string(&Pubkey::new_unique()));
        let err = server
            .payment_channel_open_params(&wrong_channel)
            .unwrap_err();
        assert!(err.to_string().contains("channelId does not match"));
    }

    #[test]
    fn payment_channel_open_params_resolves_token_2022_stablecoin_symbols() {
        use crate::protocol::solana::{mints, programs};
        use std::str::FromStr;

        let payer = Pubkey::new_unique();
        let authorized_signer = Pubkey::new_unique();
        let payee = Pubkey::from_str(RECIPIENT).expect("valid recipient");
        let mint = Pubkey::from_str(mints::PYUSD_DEVNET).expect("valid PYUSD mint");
        let token_program =
            Pubkey::from_str(programs::TOKEN_2022_PROGRAM).expect("valid token-2022 program");
        let server = SessionServer::new(
            SessionConfig {
                currency: "PYUSD".to_string(),
                network: "devnet".to_string(),
                modes: vec![SessionMode::Pull],
                pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
                ..make_server().config
            },
            MemoryChannelStore::new(),
        );
        let expected = payment_channels::OpenChannelParams {
            payer,
            payee,
            mint,
            authorized_signer,
            salt: 88,
            deposit: 1_000_000,
            grace_period: 901,
            recipients: vec![],
            token_program,
            program_id: payment_channels::default_program_id(),
        };
        let channel = payment_channels::derive_channel_addresses(&expected).channel;
        let payload = OpenPayload::payment_channel_with_mode(
            SessionMode::Pull,
            payment_channels::pubkey_string(&channel),
            expected.deposit.to_string(),
            payment_channels::pubkey_string(&payer),
            RECIPIENT.to_string(),
            mints::PYUSD_DEVNET.to_string(),
            expected.salt,
            expected.grace_period,
            payment_channels::pubkey_string(&authorized_signer),
            "pending".to_string(),
        );

        let params = server.payment_channel_open_params(&payload).unwrap();
        assert_eq!(params.mint, mint);
        assert_eq!(params.token_program, token_program);
        assert_eq!(params.grace_period, 901);
    }

    #[tokio::test]
    async fn process_open_exactly_at_cap_accepted() {
        let server = make_server();
        let state = server
            .process_open(&open_payload("chan1", 10_000_000, "s"))
            .await
            .unwrap();
        assert_eq!(state.deposit, 10_000_000);
    }

    // ── metered deliveries ──────────────────────────────────────────────────

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn begin_delivery_reserves_capacity() {
        let server = make_server();
        let (_session, authorized_signer, channel_id, _channel) = make_e2e_session();
        server
            .process_open(&open_payload(&channel_id, 1_000, &authorized_signer))
            .await
            .unwrap();

        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 100))
            .await
            .unwrap();
        assert_eq!(directive.session_id, channel_id);
        assert_eq!(directive.amount, "100");
        assert_eq!(directive.sequence, 1);

        let state = server
            .store
            .get_channel(&directive.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.pending_deliveries.len(), 1);
        assert_eq!(
            state.pending_deliveries[0].delivery_id,
            directive.delivery_id
        );

        let err = server
            .begin_delivery(DeliveryRequest::new(directive.session_id, 901))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds available deposit"));
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn process_commit_accepts_delivery_and_replays_idempotently() {
        let server = make_server();
        let (mut session, authorized_signer, channel_id, _channel) = make_e2e_session();
        server
            .process_open(&open_payload(&channel_id, 1_000, &authorized_signer))
            .await
            .unwrap();
        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id.clone(), 125))
            .await
            .unwrap();
        let voucher = session.sign_increment(125).await.unwrap();
        let payload = CommitPayload {
            delivery_id: directive.delivery_id.clone(),
            voucher,
        };

        let receipt = server.process_commit(&payload).await.unwrap();
        assert_eq!(receipt.delivery_id, directive.delivery_id);
        assert_eq!(receipt.amount, "125");
        assert_eq!(receipt.cumulative, "125");
        assert_eq!(receipt.status, CommitStatus::Committed);

        let replay = server.process_commit(&payload).await.unwrap();
        assert_eq!(replay.status, CommitStatus::Replayed);

        let state = server
            .store
            .get_channel(&channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.pending_deliveries.len(), 0);
        assert_eq!(state.committed_deliveries.len(), 1);
        assert_eq!(state.cumulative, 125);
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn process_commit_accepts_partial_stream_usage() {
        let server = make_server();
        let (mut session, authorized_signer, channel_id, _channel) = make_e2e_session();
        server
            .process_open(&open_payload(&channel_id, 1_000, &authorized_signer))
            .await
            .unwrap();
        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id, 125))
            .await
            .unwrap();
        let voucher = session.sign_increment(75).await.unwrap();
        let payload = CommitPayload {
            delivery_id: directive.delivery_id.clone(),
            voucher,
        };

        let receipt = server.process_commit(&payload).await.unwrap();
        assert_eq!(receipt.delivery_id, directive.delivery_id);
        assert_eq!(receipt.amount, "75");
        assert_eq!(receipt.cumulative, "75");
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn process_commit_rejects_over_reserved_cumulative() {
        let server = make_server();
        let (mut session, authorized_signer, channel_id, _channel) = make_e2e_session();
        server
            .process_open(&open_payload(&channel_id, 1_000, &authorized_signer))
            .await
            .unwrap();
        let directive = server
            .begin_delivery(DeliveryRequest::new(channel_id, 125))
            .await
            .unwrap();
        let voucher = session.sign_increment(200).await.unwrap();
        let payload = CommitPayload {
            delivery_id: directive.delivery_id,
            voucher,
        };

        let err = server.process_commit(&payload).await.unwrap_err();
        assert!(err.to_string().contains("exceeds reserved amount"));
    }

    // ── build_challenge_request ───────────────────────────────────────────────

    #[test]
    fn build_challenge_request_clamps_cap() {
        let server = make_server();
        let req = server.build_challenge_request(50_000_000);
        assert_eq!(req.cap, "10000000");
    }

    #[test]
    fn build_challenge_request_below_cap() {
        let server = make_server();
        let req = server.build_challenge_request(5_000_000);
        assert_eq!(req.cap, "5000000");
    }

    #[test]
    fn build_challenge_request_includes_fields() {
        let server = make_server();
        let req = server.build_challenge_request(1_000_000);
        assert_eq!(req.operator, RECIPIENT);
        assert_eq!(req.recipient, RECIPIENT);
        assert_eq!(req.currency, "USDC");
        assert_eq!(req.decimals, Some(6));
        assert_eq!(req.network.as_deref(), Some("localnet"));
        assert!(req.splits.is_empty());
    }

    #[test]
    fn build_challenge_request_with_splits() {
        let split_pk = Pubkey::new_unique();
        let config = SessionConfig {
            operator: RECIPIENT.to_string(),
            recipient: RECIPIENT.to_string(),
            splits: vec![Split {
                recipient: split_pk,
                bps: 1_000,
            }],
            max_cap: 10_000_000,
            currency: "USDC".to_string(),
            decimals: 6,
            network: "mainnet-beta".to_string(),
            program_id: None,
            min_voucher_delta: 0,
            modes: vec![SessionMode::Push],
            pull_voucher_strategy: None,
            rpc_url: None,
        };
        let server = SessionServer::new(config, MemoryChannelStore::new());
        let req = server.build_challenge_request(5_000_000);
        assert_eq!(req.splits.len(), 1);
        assert_eq!(req.splits[0].bps, 1_000);
    }

    #[test]
    fn build_challenge_request_min_voucher_delta() {
        let config = SessionConfig {
            operator: RECIPIENT.to_string(),
            recipient: RECIPIENT.to_string(),
            splits: vec![],
            max_cap: 10_000_000,
            currency: "USDC".to_string(),
            decimals: 6,
            network: "localnet".to_string(),
            program_id: None,
            min_voucher_delta: 500,
            modes: vec![SessionMode::Push],
            pull_voucher_strategy: None,
            rpc_url: None,
        };
        let server = SessionServer::new(config, MemoryChannelStore::new());
        let req = server.build_challenge_request(5_000_000);
        assert_eq!(req.min_voucher_delta.as_deref(), Some("500"));
    }

    #[test]
    fn build_challenge_request_omits_modes_when_push_only() {
        let server = make_server(); // modes: [Push]
        let req = server.build_challenge_request(1_000_000);
        assert!(req.modes.is_empty(), "Push-only should omit modes field");
    }

    #[test]
    fn build_challenge_request_includes_modes_when_pull_supported() {
        let config = SessionConfig {
            operator: RECIPIENT.to_string(),
            recipient: RECIPIENT.to_string(),
            splits: vec![],
            max_cap: 10_000_000,
            currency: "USDC".to_string(),
            decimals: 6,
            network: "localnet".to_string(),
            program_id: None,
            min_voucher_delta: 0,
            modes: vec![SessionMode::Push, SessionMode::Pull],
            pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
            rpc_url: None,
        };
        let server = SessionServer::new(config, MemoryChannelStore::new());
        let req = server.build_challenge_request(1_000_000);
        assert_eq!(req.modes.len(), 2);
        assert!(req.modes.contains(&SessionMode::Push));
        assert!(req.modes.contains(&SessionMode::Pull));
        assert_eq!(
            req.pull_voucher_strategy,
            Some(SessionPullVoucherStrategy::ClientVoucher)
        );
    }

    // ── verify_voucher ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn verify_voucher_unknown_channel() {
        let server = make_server();
        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "unknown".to_string(),
                cumulative: "100".to_string(),
                expires_at: i64::MAX,
                nonce: Some(1),
            },
            signature: "AAAA".to_string(),
        };
        let err = server.verify_voucher(&VoucherPayload { voucher }).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("not found"));
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn verify_voucher_valid_end_to_end() {
        let server = make_server();
        let (mut session, auth_signer, chan_str, _) = make_e2e_session();
        server
            .process_open(&open_payload(&chan_str, 5_000_000, &auth_signer))
            .await
            .unwrap();

        let voucher = session.sign_increment(1_000_000).await.unwrap();
        let result = server.verify_voucher(&VoucherPayload { voucher }).await;
        assert_eq!(result.unwrap(), 1_000_000);
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn verify_voucher_advances_watermark() {
        let server = make_server();
        let (mut session, auth_signer, chan_str, _) = make_e2e_session();
        server
            .process_open(&open_payload(&chan_str, 5_000_000, &auth_signer))
            .await
            .unwrap();

        // First voucher succeeds
        let v1 = session.sign_increment(500_000).await.unwrap();
        server
            .verify_voucher(&VoucherPayload {
                voucher: v1.clone(),
            })
            .await
            .unwrap();

        // Idempotent replay of exact same voucher (same cumulative + same signature) succeeds
        let v1_replay = v1.clone();
        let replay_result = server
            .verify_voucher(&VoucherPayload { voucher: v1_replay })
            .await;
        assert_eq!(
            replay_result.unwrap(),
            500_000,
            "Idempotent replay should return same cumulative"
        );

        // Next voucher with higher cumulative succeeds
        let v2 = session.sign_increment(500_000).await.unwrap();
        let result = server.verify_voucher(&VoucherPayload { voucher: v2 }).await;
        assert_eq!(result.unwrap(), 1_000_000);
    }

    #[tokio::test]
    async fn verify_voucher_stale_cumulative_rejected() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 5_000_000, "signer1"))
            .await
            .unwrap();

        // Manually advance watermark via store
        server
            .store
            .advance_cumulative("chan1", 0, 500_000)
            .await
            .unwrap();

        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "100".to_string(), // below watermark
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        let err = server.verify_voucher(&VoucherPayload { voucher }).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("watermark"));
    }

    #[tokio::test]
    async fn verify_voucher_exceeds_deposit_rejected() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 1_000_000, "signer1"))
            .await
            .unwrap();

        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "2000000".to_string(), // > deposit
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        let err = server.verify_voucher(&VoucherPayload { voucher }).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("deposit"));
    }

    #[tokio::test]
    async fn verify_voucher_bad_cumulative_format_rejected() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 1_000_000, "signer1"))
            .await
            .unwrap();

        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "not_a_number".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        assert!(server
            .verify_voucher(&VoucherPayload { voucher })
            .await
            .is_err());
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn verify_voucher_bad_signature_rejected() {
        let server = make_server();
        let (mut session, auth_signer, chan_str, _) = make_e2e_session();
        server
            .process_open(&open_payload(&chan_str, 5_000_000, &auth_signer))
            .await
            .unwrap();

        let mut voucher = session.sign_increment(1_000_000).await.unwrap();
        // Tamper with the signature
        voucher.signature = bs58::encode([0u8; 64]).into_string();

        assert!(server
            .verify_voucher(&VoucherPayload { voucher })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn verify_voucher_on_finalized_channel_rejected() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 1_000_000, "signer1"))
            .await
            .unwrap();
        server.mark_finalized("chan1").await.unwrap();

        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "500000".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        let err = server.verify_voucher(&VoucherPayload { voucher }).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("finalized"));
    }

    // ── process_topup ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn process_topup_valid() {
        let server = make_server();
        let chan = "chan1";
        server
            .process_open(&open_payload(chan, 1_000_000, "s"))
            .await
            .unwrap();

        let state = server
            .process_topup(&TopUpPayload {
                channel_id: chan.to_string(),
                new_deposit: "5000000".to_string(),
                signature: "topup_sig".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(state.deposit, 5_000_000);
    }

    #[tokio::test]
    async fn process_topup_lower_deposit_rejected() {
        let server = make_server();
        let chan = "chan1";
        server
            .process_open(&open_payload(chan, 3_000_000, "s"))
            .await
            .unwrap();

        assert!(server
            .process_topup(&TopUpPayload {
                channel_id: chan.to_string(),
                new_deposit: "2000000".to_string(),
                signature: "sig".to_string(),
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_topup_exceeds_cap_rejected() {
        let server = make_server();
        let chan = "chan1";
        server
            .process_open(&open_payload(chan, 1_000_000, "s"))
            .await
            .unwrap();

        assert!(server
            .process_topup(&TopUpPayload {
                channel_id: chan.to_string(),
                new_deposit: "20000000".to_string(), // > max_cap
                signature: "sig".to_string(),
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_topup_bad_amount_format_rejected() {
        let server = make_server();
        let chan = "chan1";
        server
            .process_open(&open_payload(chan, 1_000_000, "s"))
            .await
            .unwrap();

        assert!(server
            .process_topup(&TopUpPayload {
                channel_id: chan.to_string(),
                new_deposit: "not_a_number".to_string(),
                signature: "sig".to_string(),
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_topup_unknown_channel_rejected() {
        let server = make_server();
        assert!(server
            .process_topup(&TopUpPayload {
                channel_id: "ghost".to_string(),
                new_deposit: "5000000".to_string(),
                signature: "sig".to_string(),
            })
            .await
            .is_err());
    }

    // ── process_close ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn process_close_no_voucher() {
        let server = make_server();
        let chan = bs58::encode(Pubkey::new_unique().as_ref()).into_string();
        server
            .process_open(&open_payload(&chan, 5_000_000, "s"))
            .await
            .unwrap();

        let params = server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap();
        assert_eq!(params.settled, 0);
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn process_close_with_voucher() {
        let server = make_server();
        let (mut session, auth_signer, chan_str, _) = make_e2e_session();
        server
            .process_open(&open_payload(&chan_str, 5_000_000, &auth_signer))
            .await
            .unwrap();

        // Consume 500k first
        let v1 = session.sign_increment(500_000).await.unwrap();
        server
            .verify_voucher(&VoucherPayload { voucher: v1 })
            .await
            .unwrap();

        // Close with a final 200k voucher
        let final_voucher = session.sign_increment(200_000).await.unwrap();
        let params = server
            .process_close(&ClosePayload {
                channel_id: chan_str,
                voucher: Some(final_voucher),
            })
            .await
            .unwrap();
        assert_eq!(params.settled, 700_000);
    }

    #[tokio::test]
    async fn process_close_unknown_channel_rejected() {
        let server = make_server();
        let err = server
            .process_close(&ClosePayload {
                channel_id: bs58::encode(Pubkey::new_unique().as_ref()).into_string(),
                voucher: None,
            })
            .await;
        assert!(err.is_err());
    }

    // ── finalize_params ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn finalize_params_correct() {
        let server = make_server();
        let channel = Pubkey::new_unique();
        let chan_str = bs58::encode(channel.as_ref()).into_string();
        server
            .process_open(&open_payload(&chan_str, 5_000_000, "s"))
            .await
            .unwrap();

        let params = server.finalize_params(&chan_str).await.unwrap();
        assert_eq!(params.channel_id, channel);
        assert_eq!(params.settled, 0);
        assert_eq!(
            params.mint,
            Some(expected_payment_channel_mint(&server.config).unwrap())
        );
        assert!(params.splits.is_empty());
        // Hash with no splits should be deterministic
        let recipient = parse_pubkey(RECIPIENT).unwrap();
        let expected_hash = compute_distribution_hash(&recipient, &[]);
        assert_eq!(params.distribution_hash, expected_hash);
    }

    #[tokio::test]
    async fn finalize_params_unknown_channel_rejected() {
        let server = make_server();
        let err = server
            .finalize_params(&bs58::encode(Pubkey::new_unique().as_ref()).into_string())
            .await;
        assert!(err.is_err());
    }

    // ── mark_finalized ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mark_finalized_sets_flag() {
        let server = make_server();
        server
            .process_open(&open_payload("chan1", 1_000_000, "s"))
            .await
            .unwrap();
        server.mark_finalized("chan1").await.unwrap();

        let state = server.store.get_channel("chan1").await.unwrap().unwrap();
        assert!(state.finalized);
    }

    #[tokio::test]
    async fn mark_finalized_unknown_channel_errors() {
        let server = make_server();
        assert!(server.mark_finalized("ghost").await.is_err());
    }

    // ── distribution_hash ─────────────────────────────────────────────────────

    #[test]
    fn distribution_hash_deterministic() {
        let r = Pubkey::new_unique();
        let s1 = Pubkey::new_unique();
        let h1 = compute_distribution_hash(&r, &[(s1, 5_000)]);
        let h2 = compute_distribution_hash(&r, &[(s1, 5_000)]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn distribution_hash_empty_splits() {
        let r = Pubkey::new_unique();
        let h = compute_distribution_hash(&r, &[]);
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn distribution_hash_changes_with_amount() {
        let r = Pubkey::new_unique();
        let s = Pubkey::new_unique();
        assert_ne!(
            compute_distribution_hash(&r, &[(s, 100)]),
            compute_distribution_hash(&r, &[(s, 200)]),
        );
    }

    #[test]
    fn distribution_hash_empty_splits_ignores_implicit_payee() {
        let r1 = Pubkey::new_unique();
        let r2 = Pubkey::new_unique();
        assert_eq!(
            compute_distribution_hash(&r1, &[]),
            compute_distribution_hash(&r2, &[]),
        );
    }

    #[test]
    fn distribution_hash_changes_with_split_recipient() {
        let r = Pubkey::new_unique();
        let s1 = Pubkey::new_unique();
        let s2 = Pubkey::new_unique();
        assert_ne!(
            compute_distribution_hash(&r, &[(s1, 100)]),
            compute_distribution_hash(&r, &[(s2, 100)]),
        );
    }

    // ── parse_pubkey helper ───────────────────────────────────────────────────

    #[test]
    fn parse_pubkey_valid() {
        let pk = Pubkey::new_unique();
        let s = bs58::encode(pk.as_ref()).into_string();
        assert_eq!(parse_pubkey(&s).unwrap(), pk);
    }

    #[test]
    fn parse_pubkey_invalid_base58() {
        assert!(parse_pubkey("not!!valid").is_err());
    }

    #[test]
    fn parse_pubkey_wrong_length() {
        // Valid base58 but only 10 bytes
        let s = bs58::encode(&[1u8; 10]).into_string();
        assert!(parse_pubkey(&s).is_err());
    }

    // ── verify_voucher: idempotent replay ────────────────────────────────────

    #[tokio::test]
    async fn verify_voucher_idempotent_replay() {
        let server = make_server();
        // Manually set up a channel with a known highest_voucher_signature
        use crate::store::ChannelState;
        server
            .store
            .put_channel(
                "chan1",
                ChannelState {
                    channel_id: "chan1".to_string(),
                    authorized_signer: "signer1".to_string(),
                    deposit: 5_000_000,
                    cumulative: 1_000_000,
                    finalized: false,
                    highest_voucher_signature: Some("replay_sig".to_string()),
                    highest_voucher_expires_at: None,
                    close_requested_at: None,
                    operator: None,
                    next_delivery_sequence: 0,
                    pending_deliveries: vec![],
                    committed_deliveries: vec![],
                },
            )
            .await
            .unwrap();

        // A voucher with same cumulative AND same signature is idempotent replay
        // (signature verify will fail since it's fake, but let's test the path up to sig verify)
        // We just need to confirm it does NOT fail with "must exceed watermark"
        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "1000000".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "replay_sig".to_string(),
        };
        let err = server
            .verify_voucher(&VoucherPayload { voucher })
            .await
            .unwrap_err();
        // Should fail at signature verification, not watermark check
        let msg = err.to_string();
        assert!(!msg.contains("watermark"), "Expected sig error, got: {msg}");
        // The error is from crypto validation (bad encoding, wrong length, bad key, etc.)
        // Any error other than "watermark" means idempotent replay path was taken correctly
        assert!(
            msg.contains("signature")
                || msg.contains("encoding")
                || msg.contains("Invalid")
                || msg.contains("bytes")
                || msg.contains("key"),
            "Expected signature-related error, got: {msg}"
        );
    }

    // ── verify_voucher: min_delta enforcement ────────────────────────────────

    #[tokio::test]
    async fn verify_voucher_min_delta_enforced() {
        let server = make_server_with_min_delta(500_000);
        server
            .process_open(&open_payload("chan1", 5_000_000, "signer1"))
            .await
            .unwrap();

        // delta = 100_000, min = 500_000 → should be rejected
        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: "chan1".to_string(),
                cumulative: "100000".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        let err = server
            .verify_voucher(&VoucherPayload { voucher })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("below minimum"),
            "Expected min delta error, got: {err}"
        );
    }

    // ── verify_voucher: close-pending rejection ──────────────────────────────

    #[tokio::test]
    async fn verify_voucher_close_pending_rejected() {
        let server = make_server();
        let chan = bs58::encode(Pubkey::new_unique().as_ref()).into_string();
        server
            .process_open(&open_payload(&chan, 5_000_000, "s"))
            .await
            .unwrap();

        // Close the channel first
        server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap();

        // Now try to submit a voucher — should be rejected
        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: chan.clone(),
                cumulative: "100000".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "AAAA".to_string(),
        };
        let err = server
            .verify_voucher(&VoucherPayload { voucher })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("close is pending"),
            "Expected close-pending error, got: {err}"
        );
    }

    // ── process_close: sets close_requested_at ───────────────────────────────

    #[tokio::test]
    async fn process_close_sets_close_pending() {
        let server = make_server();
        let chan = bs58::encode(Pubkey::new_unique().as_ref()).into_string();
        server
            .process_open(&open_payload(&chan, 5_000_000, "s"))
            .await
            .unwrap();

        server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap();

        let state = server.store.get_channel(&chan).await.unwrap().unwrap();
        assert!(
            state.close_requested_at.is_some(),
            "Expected close_requested_at to be set"
        );
    }

    // ── process_close: prevents double-close ─────────────────────────────────

    #[tokio::test]
    async fn process_close_prevents_double_close() {
        let server = make_server();
        let chan = bs58::encode(Pubkey::new_unique().as_ref()).into_string();
        server
            .process_open(&open_payload(&chan, 5_000_000, "s"))
            .await
            .unwrap();

        // First close succeeds
        server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap();

        // Second close should fail
        let err = server
            .process_close(&ClosePayload {
                channel_id: chan.clone(),
                voucher: None,
            })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Close already requested")
                || err.to_string().contains("close"),
            "Expected double-close error, got: {err}"
        );
    }
}
