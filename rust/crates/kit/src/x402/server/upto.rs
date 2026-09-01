//! Server-side handler for the x402 `upto` scheme (payment-channel asset transfer method).
//!
//! Flow (single HTTP round-trip, handler-determined amount):
//!
//! 1. [`X402Upto::upto`] advertises a 402 with the authorized maximum and the
//!    fee payer plus receiver authorizer keys.
//! 2. [`X402Upto::verify_open`] validates the client authorization, broadcasts
//!    the channel `open` (co-signing as fee payer), confirms it, and reads the
//!    channel state back to bind deposit/payee/mint/signer on-chain.
//! 3. The route handler runs and determines the actual metered amount.
//! 4. [`X402Upto::settle_actual`] signs a single receiver-authorizer voucher for
//!    the actual amount and submits fee-payer-signed `settle_and_seal` + ATA
//!    setup + `distribute`, refunding `deposit - actual` to the payer.
//!
//! Roles: the fee payer is transaction fee payer, channel rent payer, and
//! zero-share channel payee (lifecycle authority — it signs `settle_and_seal`
//! and can always seal with `has_voucher = 0` to recover rent, but cannot
//! settle a nonzero amount or redirect funds). The receiver authorizer is the
//! channel's `authorized_signer` and signs only the Ed25519 voucher (payment
//! authority).

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use solana_instruction::Instruction;
use solana_keychain::SolanaSigner;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

use crate::core::payment_channels as pc;
use crate::core::payment_channels::generated::accounts::Channel;
// The ComputeBudget wire format is identical wherever it appears, so the
// charge verifier's policy-free decoder is reused here rather than duplicated.

use crate::x402::error::Error;
use crate::x402::protocol::schemes::exact::{
    caip2_network_for_cluster, default_rpc_url, default_token_program_for_currency, ResourceInfo,
};
use crate::x402::protocol::schemes::upto::{
    assert_settlement_within_ceiling, verify_upto_payload, UptoExtra, UptoRequiredEnvelope,
    UptoRequirements, UptoSettlementResponse, UptoSignatureEnvelope, UPTO_SCHEME,
};
use crate::x402::server::CurrencyConfig;
use crate::x402::{PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, X402_VERSION_V2};

/// `ChannelStatus::Open` discriminant in the generated client.
const CHANNEL_STATUS_OPEN: u8 = 0;

/// `Open` instruction discriminator in the generated payment-channels client
/// (`crate::generated::payment_channels::generated::instructions::OPEN_DISCRIMINATOR`).
const OPEN_INSTRUCTION_DISCRIMINATOR: u8 = 1;

/// Server configuration for the Solana x402 `upto` scheme.
#[derive(Clone)]
pub struct UptoConfig {
    /// Where settled funds go. The channel payee is always the fee payer
    /// (zero-share seat); this only decides which beneficiary the bound 100%
    /// distribution split pays.
    pub payout: UptoPayout,
    /// Non-empty universe of currencies this server offers and accepts. `[0]`
    /// is the primary/default currency. The `upto` challenge advertises one
    /// `accepts[]` entry per currency and `verify_open` accepts a payment in any
    /// of them, binding the channel to the chosen currency's mint + token
    /// program.
    pub currencies: Vec<CurrencyConfig>,
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
    /// Channel program id override (defaults to the canonical deployment).
    pub program_id: Option<String>,
    /// Channel forced-close delay, in seconds. Defaults to the payment-channel
    /// program default when set to `0`.
    pub withdraw_delay: u32,
    /// Signer that co-signs the open as transaction fee payer and channel rent
    /// payer, holds the zero-share channel payee seat, and signs
    /// `settle_and_seal` (lifecycle authority: it can always seal with
    /// `has_voucher = 0` to recover rent, but cannot settle a nonzero amount
    /// or redirect funds).
    pub fee_payer_signer: Arc<dyn SolanaSigner>,
    /// Signer for the Ed25519 settlement voucher (the channel's
    /// `authorized_signer`). Defaults to `fee_payer_signer` when absent.
    pub receiver_authorizer_signer: Option<Arc<dyn SolanaSigner>>,
}

/// Where an `upto` channel's settled funds go. The channel payee is always the
/// fee payer with a zero implicit remainder; this decides which beneficiary
/// receives the full settled amount via the bound 100% distribution split.
#[derive(Clone, Debug)]
pub enum UptoPayout {
    /// No separate beneficiary — the receiver authorizer receives the full
    /// settled amount (as the 100% distribution recipient).
    ReceiverKeepsAll,
    /// Pay `address` via a 100% distribution split.
    Beneficiary {
        /// Base58 beneficiary (principal) address.
        address: String,
    },
}

/// A confirmed, on-chain-verified channel open, carried from
/// [`X402Upto::verify_open`] to [`X402Upto::settle_actual`].
///
/// Not `Clone`: it holds the in-flight guard for its channel, released when this
/// value is dropped (after settlement, or on any error/panic path).
#[derive(Debug)]
pub struct VerifiedUptoOpen {
    pub channel_id: Pubkey,
    pub payer: Pubkey,
    pub rent_payer: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub program_id: Pubkey,
    pub deposit: u64,
    pub max_amount: u64,
    pub expires_at: i64,
    pub network: String,
    /// The channel's payee — the fee payer (zero-share seat). The beneficiary
    /// is paid via `distribution`, not by being the payee. See `verify_open`.
    pub payee: Pubkey,
    /// The bound distribution split validated at open (beneficiary at 100%).
    /// Settlement must distribute to exactly this set; the payee's implicit
    /// remainder is always zero.
    pub distribution: Vec<pc::Distribution>,
    /// Releases this channel from the in-flight set on drop.
    _in_flight: InFlightGuard,
}

/// RAII guard removing a channel id from [`X402Upto`]'s in-flight set on drop,
/// so a channel being processed can't be served concurrently (replay), and the
/// slot is always freed - including on early-return errors or a handler panic.
#[derive(Debug)]
struct InFlightGuard {
    set: Arc<Mutex<HashSet<Pubkey>>>,
    channel_id: Pubkey,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.channel_id);
    }
}

/// Server-side payment handler for the Solana x402 `upto` scheme.
#[derive(Clone)]
pub struct X402Upto {
    rpc: Arc<RpcClient>,
    config: UptoConfig,
    fee_payer: Pubkey,
    receiver_authorizer: Pubkey,
    /// Channel ids currently being processed (verify_open → settle_actual), to
    /// reject concurrent replays of the same authorization.
    in_flight: Arc<Mutex<HashSet<Pubkey>>>,
    /// Optional shared cache of a recent blockhash, refreshed out of band, so
    /// challenge issuance avoids a per-challenge RPC round-trip. `None` ⇒ fetch
    /// directly (prior behaviour).
    blockhash_cache: Option<crate::core::blockhash::BlockhashCache>,
    /// Lazily-spawned batched-settlement worker shared across deferred settles
    /// (see [`settle_actual_deferred`](Self::settle_actual_deferred)). Spawned
    /// on first use because it needs a tokio runtime; `Arc<OnceCell>` keeps the
    /// handler `Clone` while sharing one worker. Mirrors the mpp session path.
    settlement_worker:
        Arc<tokio::sync::OnceCell<crate::core::settlement::worker::SettlementHandle>>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl X402Upto {
    pub fn new(mut config: UptoConfig) -> Result<Self, Error> {
        if config.currencies.is_empty() {
            return Err(Error::Other("at least one currency is required".into()));
        }
        for currency in &config.currencies {
            crate::x402::exact::try_resolve_stablecoin_mint(
                &currency.currency,
                Some(&config.cluster),
            )?;
        }
        if let UptoPayout::Beneficiary { address } = &config.payout {
            Pubkey::from_str(address)
                .map_err(|e| Error::Other(format!("Invalid recipient pubkey: {e}")))?;
        }
        if config.withdraw_delay == 0 {
            config.withdraw_delay = pc::DEFAULT_GRACE_PERIOD_SECONDS;
        }

        let receiver_authorizer_signer = config
            .receiver_authorizer_signer
            .clone()
            .unwrap_or_else(|| config.fee_payer_signer.clone());
        config.receiver_authorizer_signer = Some(receiver_authorizer_signer.clone());
        let fee_payer = config.fee_payer_signer.pubkey();
        let receiver_authorizer = receiver_authorizer_signer.pubkey();
        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&config.cluster).to_string());

        Ok(Self {
            // `confirmed`, not the default `finalized`: the channel open + voucher
            // settlement shouldn't block ~13s on finalization.
            rpc: Arc::new(RpcClient::new_with_commitment(
                rpc_url,
                solana_commitment_config::CommitmentConfig::confirmed(),
            )),
            config,
            fee_payer,
            receiver_authorizer,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
            blockhash_cache: None,
            settlement_worker: Arc::new(tokio::sync::OnceCell::new()),
        })
    }

    /// Attach a shared blockhash cache (refreshed by a background task) so the
    /// `upto` challenge embeds a recent blockhash without a per-challenge RPC
    /// fetch. Falls back to a direct fetch when the cache is empty or stale.
    pub fn with_blockhash_cache(mut self, cache: crate::core::blockhash::BlockhashCache) -> Self {
        self.blockhash_cache = Some(cache);
        self
    }

    /// The transaction fee payer / rent payer / zero-share channel payee
    /// public key (base58).
    pub fn fee_payer(&self) -> String {
        pc::pubkey_string(&self.fee_payer)
    }

    /// The voucher signer public key (base58).
    pub fn receiver_authorizer(&self) -> String {
        pc::pubkey_string(&self.receiver_authorizer)
    }

    fn receiver_authorizer_signer(&self) -> &Arc<dyn SolanaSigner> {
        self.config
            .receiver_authorizer_signer
            .as_ref()
            .expect("receiver authorizer signer initialized")
    }

    fn program_id(&self) -> Result<Pubkey, Error> {
        match &self.config.program_id {
            Some(value) => {
                Pubkey::from_str(value).map_err(|e| Error::Other(format!("invalid programId: {e}")))
            }
            None => Ok(pc::default_program_id()),
        }
    }

    /// The primary/default currency: `currencies[0]`. The constructor rejects
    /// an empty list, so this never panics.
    fn primary_currency(&self) -> &CurrencyConfig {
        &self.config.currencies[0]
    }

    /// Resolve the mint for a specific currency descriptor on the configured
    /// cluster.
    fn mint_for(&self, cc: &CurrencyConfig) -> Result<Pubkey, Error> {
        let mint = crate::x402::exact::try_resolve_stablecoin_mint(
            &cc.currency,
            Some(&self.config.cluster),
        )?
        .ok_or_else(|| Error::Other("upto requires an SPL token (not native SOL)".into()))?;
        Pubkey::from_str(mint).map_err(|e| Error::Other(format!("invalid mint: {e}")))
    }

    /// Resolve the token program for a specific currency descriptor on the
    /// configured cluster. The descriptor's `token_program` override wins;
    /// otherwise the program (legacy SPL vs Token-2022) is derived from the
    /// currency symbol.
    fn token_program_for(&self, cc: &CurrencyConfig) -> Result<Pubkey, Error> {
        let tp = cc.token_program.clone().unwrap_or_else(|| {
            default_token_program_for_currency(&cc.currency, Some(&self.config.cluster)).to_string()
        });
        Pubkey::from_str(&tp).map_err(|e| Error::Other(format!("invalid token program: {e}")))
    }

    /// The currencies this server offers in its `upto` challenge.
    fn offered_currencies(&self) -> &[CurrencyConfig] {
        &self.config.currencies
    }

    /// The beneficiary when configured, otherwise the receiver authorizer.
    fn pay_to(&self) -> String {
        match &self.config.payout {
            UptoPayout::Beneficiary { address } => address.clone(),
            UptoPayout::ReceiverKeepsAll => self.receiver_authorizer(),
        }
    }

    fn distribution(&self) -> Result<Vec<pc::Distribution>, Error> {
        // Always explicit: the payee seat is held by the fee payer with a
        // zero implicit remainder, so 100% of settled funds must be assigned
        // to `payTo` through the recipients list.
        let recipient = Pubkey::from_str(&self.pay_to())
            .map_err(|e| Error::Other(format!("invalid recipient: {e}")))?;
        Ok(pc::sole_recipient(&recipient))
    }

    /// Build the `upto` payment requirement for the primary currency at the
    /// given authorized maximum.
    ///
    /// `max_amount` is a human-decimal amount (e.g. `"0.10"`), converted to base
    /// units using the configured decimals - same convention as the `exact`
    /// scheme, so the gate passes one dollar string everywhere.
    ///
    /// Pure (no RPC): `extra.recent_blockhash` is left `None` and filled in by
    /// [`upto`] when building the 402 challenge. The verify path reuses this
    /// without fetching (or diverging on) a blockhash.
    pub fn upto_requirements(&self, max_amount: &str) -> Result<UptoRequirements, Error> {
        self.upto_requirements_for(self.primary_currency(), max_amount)
    }

    /// Build the `upto` payment requirement for a specific currency descriptor.
    ///
    /// Same as [`X402Upto::upto_requirements`] but resolves the mint, decimals,
    /// and token program from the passed descriptor, so a multi-currency server
    /// can advertise one requirement per offered currency. Pure (no RPC): the
    /// recent blockhash is filled in by [`X402Upto::upto`].
    pub fn upto_requirements_for(
        &self,
        cc: &CurrencyConfig,
        max_amount: &str,
    ) -> Result<UptoRequirements, Error> {
        let mint = self.mint_for(cc)?;
        let token_program = self.token_program_for(cc)?;
        let base_units = crate::x402::server::exact::parse_units(max_amount, cc.decimals)?;

        Ok(UptoRequirements {
            scheme: UPTO_SCHEME.to_string(),
            network: caip2_network_for_cluster(&self.config.cluster).to_string(),
            amount: base_units,
            asset: pc::pubkey_string(&mint),
            pay_to: self.pay_to(),
            max_timeout_seconds: self.config.max_timeout_seconds,
            extra: UptoExtra {
                token_program: Some(pc::pubkey_string(&token_program)),
                fee_payer: self.fee_payer(),
                receiver_authorizer: self.receiver_authorizer(),
                withdraw_delay: self.config.withdraw_delay,
                recent_blockhash: None,
                last_valid_block_height: None,
                recent_slot: None,
                valid_after: None,
                // No seller memo: the server accepts (but never requires) the
                // client's own memo after `open`.
                memo: None,
            },
        })
    }

    /// Build the full `PAYMENT-REQUIRED` envelope for an `upto` challenge.
    ///
    /// This is where the (best-effort) recent blockhash AND current slot
    /// (`recentSlot`) are fetched and attached, so the client can build the
    /// channel `open` without any RPC of its own: the slot feeds the program's
    /// `openSlot`, a channel-PDA seed the program only accepts within a recent
    /// window, and clients MUST take it from the challenge rather than fetch a
    /// slot themselves.
    pub fn upto(&self, max_amount: &str) -> Result<UptoRequiredEnvelope, Error> {
        // Fail loudly (retryable) rather than issuing a 402 with no blockhash /
        // recentSlot: the in-SDK client hard-requires both to build the channel
        // open, so a silent `None` would surface as a non-retryable payment
        // failure on a transient RPC hiccup.
        // Prefer the shared cache (refreshed out of band) to avoid a blocking
        // RPC round-trip per challenge; fall back to a direct fetch. The
        // blockhash and the slot come from ONE `getLatestBlockhash` call (its
        // response context carries the slot), fetched ONCE and stamped on
        // every offered currency's requirement.
        let hint = match self.blockhash_cache.as_ref().and_then(|c| c.get()) {
            Some(cached) => cached,
            None => {
                crate::core::blockhash::fetch_blockhash_with_slot(&self.rpc, self.rpc.commitment())
                    .map_err(|e| Error::Rpc(format!("failed to fetch recent blockhash: {e}")))?
            }
        };

        // One `accepts[]` entry per offered currency (single-currency mode
        // yields exactly one, identical to the prior behaviour). Every entry
        // carries the SAME freshly-fetched blockhash + last-valid height +
        // recentSlot.
        let currencies = self.offered_currencies();
        let mut accepts = Vec::with_capacity(currencies.len());
        for cc in currencies {
            let mut requirement = self.upto_requirements_for(cc, max_amount)?;
            requirement.extra.recent_blockhash = Some(hint.blockhash.clone());
            requirement.extra.last_valid_block_height =
                Some(hint.last_valid_block_height.to_string());
            requirement.extra.recent_slot = Some(hint.slot.to_string());
            accepts.push(requirement);
        }

        let resource = (!self.config.resource.is_empty()).then(|| ResourceInfo {
            url: self.config.resource.clone(),
            description: self.config.description.clone(),
            mime_type: None,
        });
        Ok(UptoRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource,
            accepts,
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
        // x402 v2 spec §5.2: scheme lives in `accepted` (the chosen
        // PaymentRequirements), not at the envelope level.
        let scheme = envelope
            .accepted
            .get("scheme")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        if scheme != UPTO_SCHEME {
            return Err(Error::InvalidPayloadType(scheme.to_string()));
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
        let payload = &envelope.payload;

        // Multi-currency: build one offered requirement per advertised currency
        // and pick the one the client's `accepted` structurally matches (after
        // stripping transient blockhash hints, mirroring exact's
        // `find_matching_requirement`). The chosen asset is therefore guaranteed
        // to be one we offered; the channel is then bound to THAT currency's
        // mint + token program below.
        let offered = self
            .offered_currencies()
            .iter()
            .map(|cc| self.upto_requirements_for(cc, max_amount))
            .collect::<Result<Vec<_>, _>>()?;
        let requirements = match_offered_requirement(&offered, &envelope.accepted)?.clone();

        verify_upto_payload(
            payload,
            &requirements,
            &self.receiver_authorizer(),
            now_unix(),
        )?;
        // x402 v2 spec §5.2: network lives in `accepted` (the chosen
        // PaymentRequirements), not at the envelope level.
        let claimed_network = envelope.accepted.get("network").and_then(|n| n.as_str());
        if claimed_network != Some(requirements.network.as_str()) {
            return Err(Error::Other(format!(
                "network mismatch: payload {:?}, expected {}",
                claimed_network, requirements.network
            )));
        }

        let program_id = self.program_id()?;
        // Bind the channel to the MATCHED currency's mint + token program — not
        // the configured default — so a multi-currency open is validated
        // against the currency the client actually chose.
        let expected_mint = Pubkey::from_str(&requirements.asset)
            .map_err(|e| Error::Other(format!("invalid matched asset mint: {e}")))?;
        let token_program = requirements
            .extra
            .token_program
            .as_deref()
            .ok_or_else(|| Error::Other("matched requirement missing token program".into()))
            .and_then(|tp| {
                Pubkey::from_str(tp)
                    .map_err(|e| Error::Other(format!("invalid matched token program: {e}")))
            })?;
        // The channel payee is the fee payer: the zero-share lifecycle seat
        // that signs `settle_and_seal` and can recover rent from an abandoned
        // channel. Payment authority stays with the receiver authorizer via
        // `authorized_signer` (checked below).
        let expected_payee = self.fee_payer;
        let expected_distribution = self.distribution()?;
        let channel_id = Pubkey::from_str(&payload.channel_id)
            .map_err(|e| Error::Other(format!("invalid channelId: {e}")))?;
        let payer = Pubkey::from_str(&payload.from)
            .map_err(|e| Error::Other(format!("invalid payer: {e}")))?;
        let max = payload.max_amount()?;

        // In-flight dedup: reject a concurrent request replaying the same
        // channel before its first settlement completes. The guard releases the
        // slot on drop - including every early-return below and a handler panic.
        let in_flight = {
            let mut set = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            if !set.insert(channel_id) {
                return Err(Error::Other(
                    "channel is already being processed (concurrent request)".to_string(),
                ));
            }
            InFlightGuard {
                set: self.in_flight.clone(),
                channel_id,
            }
        };

        // Broadcast the client-signed open (pull). Push (already broadcast) is
        // not yet supported; require the transaction.
        let open_tx_b64 = payload.open_transaction.as_deref().ok_or_else(|| {
            Error::Other(
                "payment-channel asset transfer method requires openTransaction (pull)".to_string(),
            )
        })?;
        let mut tx = decode_transaction(open_tx_b64)?;
        // SECURITY: the operator co-signs as fee payer, so it must only ever
        // sign the expected channel-open instruction - never an arbitrary
        // operator-authorized instruction (e.g. a SystemProgram transfer that
        // drains the operator). Validate before co-signing/broadcasting.
        self.validate_open_transaction(
            &tx,
            &payer,
            &expected_payee,
            &expected_mint,
            &token_program,
            &channel_id,
            max,
            &payload.nonce,
            &payload.open_slot,
        )?;
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
        // The channel must commit to exactly the distribution we expect (100%
        // to the beneficiary — the zero-share payee never keeps a remainder),
        // so a client cannot redirect funds.
        validate_distribution_hash(&channel.distribution_hash, &expected_distribution)?;
        if pc::from_address(&channel.authorized_signer) != self.receiver_authorizer {
            return Err(Error::Other(
                "channel authorized_signer is not the receiver authorizer".to_string(),
            ));
        }
        if pc::from_address(&channel.rent_payer) != self.fee_payer {
            return Err(Error::Other(
                "channel rent_payer is not the fee payer".to_string(),
            ));
        }
        if channel.grace_period != self.config.withdraw_delay {
            return Err(Error::Other(format!(
                "channel withdraw delay {} does not match advertised {}",
                channel.grace_period, self.config.withdraw_delay
            )));
        }
        if channel.deposit != max {
            return Err(Error::Other(format!(
                "on-chain deposit {} != authorized maximum {max}: the deposit is the \
                 enforced ceiling and `topUp` can raise an open channel's deposit, so it \
                 must equal the authorized amount exactly - `>=` would leave the x402 \
                 ceiling advisory rather than enforced",
                channel.deposit
            )));
        }
        // Bind the on-chain payer: settlement's `distribute` refunds to this
        // account, and the program enforces it equals `channel.payer`. A
        // mismatch would fail settlement on-chain after the resource was served.
        if pc::from_address(&channel.payer) != payer {
            return Err(Error::Other(format!(
                "channel payer {} does not match payload.from {}",
                pc::pubkey_string(&pc::from_address(&channel.payer)),
                pc::pubkey_string(&payer)
            )));
        }

        Ok(VerifiedUptoOpen {
            channel_id,
            payer,
            rent_payer: pc::from_address(&channel.rent_payer),
            mint: expected_mint,
            token_program,
            program_id,
            deposit: channel.deposit,
            max_amount: max,
            expires_at: payload.expires_at,
            network: requirements.network,
            payee: expected_payee,
            distribution: expected_distribution,
            _in_flight: in_flight,
        })
    }

    /// Settle the actual metered amount (`actual ≤ max`) against a verified
    /// open: `settle_and_seal`, ATA setup, and `distribute`, then broadcast
    /// and confirm inline.
    ///
    /// Confirms before returning, so the on-chain confirm sits on the caller's
    /// path. To keep settlement off a latency-sensitive path (e.g. the proxy's
    /// response filter) and to batch concurrent settlements, prefer
    /// [`settle_actual_deferred`](Self::settle_actual_deferred), which routes
    /// the same instructions through the shared batched-settlement worker
    /// (send-now, confirm-in-background).
    pub async fn settle_actual(
        &self,
        open: &VerifiedUptoOpen,
        actual: u64,
    ) -> Result<UptoSettlementResponse, Error> {
        let instructions = self.settlement_instructions(open, actual).await?;

        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .map_err(|e| Error::Rpc(format!("blockhash fetch failed: {e}")))?;
        let message = Message::new_with_blockhash(&instructions, Some(&self.fee_payer), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        self.sign_settlement_transaction(&mut tx).await?;

        let signature = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Rpc(format!("settle broadcast failed: {e}")))?;

        Ok(self.settlement_response(open, actual, signature.to_string()))
    }

    /// Build the settlement instructions (`settle_and_seal`, ATA setup, and
    /// `distribute`) for the actual metered amount (`actual ≤ max`) against a
    /// verified open, signing the operator voucher but WITHOUT building,
    /// signing, or broadcasting a transaction.
    ///
    /// Shared by [`settle_actual`](Self::settle_actual) (which wraps them in a
    /// tx it signs + confirms) and the batched-settlement worker (which packs
    /// instructions from several channels into one fee-payer-signed tx). The
    /// settle transaction is fee-payer-signed only — the receiver authorizer's
    /// voucher authorization rides inside the `settle_and_seal` instruction
    /// data, not as a transaction signature — so the worker can sign the
    /// envelope on the caller's behalf.
    pub async fn settlement_instructions(
        &self,
        open: &VerifiedUptoOpen,
        actual: u64,
    ) -> Result<Vec<Instruction>, Error> {
        assert_settlement_within_ceiling(actual, open.max_amount)?;

        // `settle_and_seal`'s payee signer is the channel payee — the fee
        // payer. The receiver authorizer signs only the Ed25519 voucher
        // (carried in instruction data as the channel's authorized signer).
        let mut instructions = if actual == 0 {
            pc::build_settle_and_seal_instructions(
                &self.fee_payer,
                &open.channel_id,
                &self.receiver_authorizer,
                None,
                0,
                open.expires_at,
                &open.program_id,
            )?
        } else {
            let voucher_bytes =
                pc::voucher_message_bytes(&open.channel_id, actual, open.expires_at)?;
            let sig_bytes: [u8; 64] = self
                .receiver_authorizer_signer()
                .sign_message(&voucher_bytes)
                .await
                .map_err(|e| Error::Other(format!("voucher signing failed: {e}")))?
                .into();
            pc::build_settle_and_seal_instructions(
                &self.fee_payer,
                &open.channel_id,
                &self.receiver_authorizer,
                Some(&sig_bytes),
                actual,
                open.expires_at,
                &open.program_id,
            )?
        };

        let payee = open.payee;
        instructions.push(pc::build_create_associated_token_account_instruction(
            &self.fee_payer,
            &payee,
            &open.mint,
            &open.token_program,
        ));
        instructions.push(pc::build_create_associated_token_account_instruction(
            &self.fee_payer,
            &pc::treasury_owner(),
            &open.mint,
            &open.token_program,
        ));
        for entry in &open.distribution {
            instructions.push(pc::build_create_associated_token_account_instruction(
                &self.fee_payer,
                &entry.recipient,
                &open.mint,
                &open.token_program,
            ));
        }
        instructions.push(pc::build_distribute_instruction(
            &open.channel_id,
            &open.payer,
            &open.rent_payer,
            &payee,
            &pc::treasury_owner(),
            &open.mint,
            &open.distribution,
            &open.token_program,
            &open.program_id,
        ));

        Ok(instructions)
    }

    /// Build the `PAYMENT-RESPONSE` receipt for a settled `actual` amount and
    /// its broadcast `signature`. Pure: pairs the settle signature (inline or
    /// worker-provided) with the open's payer/network.
    pub fn settlement_response(
        &self,
        open: &VerifiedUptoOpen,
        actual: u64,
        signature: String,
    ) -> UptoSettlementResponse {
        UptoSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some(pc::pubkey_string(&open.payer)),
            transaction: signature,
            network: open.network.clone(),
            amount: actual.to_string(),
        }
    }

    /// Settle like [`settle_actual`](Self::settle_actual) but route the
    /// instructions through the shared batched-settlement worker instead of
    /// broadcasting inline: the worker packs concurrent channel settlements into
    /// one operator-signed transaction, **sends without waiting for
    /// confirmation**, and confirms/retries in the background. Returns once the
    /// batch is sent, carrying the (already-final) settle signature for the
    /// receipt — taking the multi-second confirm poll off the caller's path.
    ///
    /// The client's funds are locked by the confirmed channel `open`, so a
    /// late or failed background confirm is an operator-retry concern (the
    /// channel store sweeps it), not client-loss.
    ///
    /// The worker is spawned lazily on first use and shared across calls (it is
    /// keyed to this handler's operator + RPC), mirroring the mpp session
    /// settlement path.
    pub async fn settle_actual_deferred(
        &self,
        open: &VerifiedUptoOpen,
        actual: u64,
    ) -> Result<UptoSettlementResponse, Error> {
        use crate::core::settlement::worker::{spawn, RpcBroadcaster, SettlementConfig};

        // The receiver authorizer's voucher is signed into the instruction
        // data here; the settle transaction itself only needs the fee payer's
        // signature (payee + envelope), which the worker holds.
        let instructions = self.settlement_instructions(open, actual).await?;

        let fee_payer = self.fee_payer;
        let signer = self.config.fee_payer_signer.clone();
        let rpc_url = self
            .config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&self.config.cluster).to_string());
        let handle = self
            .settlement_worker
            .get_or_init(|| async move {
                spawn(
                    SettlementConfig::new(fee_payer, signer),
                    Arc::new(RpcBroadcaster::new(rpc_url)),
                )
            })
            .await;

        let signature = handle
            .settle(open.channel_id.to_string(), instructions)
            .await
            .map_err(|e| Error::Rpc(format!("upto settlement worker: {e}")))?;

        Ok(self.settlement_response(open, actual, signature))
    }

    /// Verify the client transaction carries the expected payment-channels
    /// `open` instruction before the operator co-signs it as fee payer.
    ///
    /// Without this, a malicious client could include any operator-authorized
    /// instruction (e.g. a SystemProgram transfer draining the operator) and the
    /// operator would blindly sign it. We require exactly one instruction on the
    /// payment-channels program, with the `open` discriminator, whose accounts
    /// bind the expected payer / payee / mint / fee payer / channel — wrapped, at
    /// most, by the allowlisted ComputeBudget prefix and Lighthouse/Memo suffix
    /// that [`find_canonical_open_instruction`] accepts.
    fn validate_open_transaction(
        &self,
        tx: &VersionedTransaction,
        payer: &Pubkey,
        payee: &Pubkey,
        mint: &Pubkey,
        token_program: &Pubkey,
        channel_id: &Pubkey,
        max_amount: u64,
        payload_nonce: &str,
        payload_open_slot: &str,
    ) -> Result<(), Error> {
        let program_id = self.program_id()?;
        // The challenged recentSlot at verify time: freshly fetched (cache
        // first), so the transaction's openSlot — stamped from the earlier
        // challenge — must sit at-or-before it inside the program freshness
        // window. A failed fetch skips the window check (None); the PDA bind
        // in `validate_open_instruction` still holds and the program enforces
        // the window at broadcast.
        let challenged_slot = self
            .blockhash_cache
            .as_ref()
            .and_then(|c| c.get())
            .map(|hint| hint.slot)
            .or_else(|| {
                crate::core::blockhash::fetch_blockhash_with_slot(&self.rpc, self.rpc.commitment())
                    .ok()
                    .map(|hint| hint.slot)
            });
        validate_open_instruction(
            tx,
            &program_id,
            // feePayer funds rent while receiverAuthorizer signs vouchers.
            &self.fee_payer,
            &self.receiver_authorizer,
            payer,
            payee,
            mint,
            token_program,
            channel_id,
            Some(max_amount),
            Some(self.config.withdraw_delay),
            Some(payload_nonce),
            Some(payload_open_slot),
            challenged_slot,
        )
    }

    /// Co-sign the fee-payer slot of a partially-signed transaction.
    async fn cosign_fee_payer(&self, tx: &mut VersionedTransaction) -> Result<(), Error> {
        cosign_operator_fee_payer(self.config.fee_payer_signer.as_ref(), &self.fee_payer, tx).await
    }

    /// Sign the settlement transaction. The fee payer is its only required
    /// signer: it is both the transaction fee payer and the `settle_and_seal`
    /// payee signer, while the receiver authorizer's voucher rides inside the
    /// instruction data rather than as a transaction signature.
    async fn sign_settlement_transaction(&self, tx: &mut Transaction) -> Result<(), Error> {
        self.config
            .fee_payer_signer
            .sign_transaction(tx)
            .await
            .map_err(|e| Error::Other(format!("fee payer signing failed: {e}")))?;
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

/// Co-sign the operator's (fee-payer) slot of a partially-signed transaction.
/// Shared by the `upto` and `batch-settlement` servers — the implementation
/// lives in `solana-pay-core` so the MPP session opener reuses it too.
pub(crate) async fn cosign_operator_fee_payer(
    signer: &dyn SolanaSigner,
    operator: &Pubkey,
    tx: &mut VersionedTransaction,
) -> Result<(), Error> {
    Ok(pc::cosign_fee_payer(signer, operator, tx).await?)
}

/// Decode a base64 (standard) bincode transaction, accepting legacy and v0.
/// Thin wrapper over the shared `solana-pay-core` decoder.
pub(crate) fn decode_transaction(b64: &str) -> Result<VersionedTransaction, Error> {
    Ok(pc::decode_transaction(b64)?)
}

/// Remove the server-provided build hints (`recentBlockhash` /
/// `lastValidBlockHeight` (#2693) / `recentSlot`) from a serialized
/// requirements value so the verify-time structural match ignores them. They
/// are embedded into the 402 challenge and echoed back by the client in
/// `accepted`, but the verify-time rebuild omits them. Mirrors exact's
/// `strip_blockhash_hints`.
fn strip_upto_blockhash_hints(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("recentBlockhash");
    }
    if let Some(extra) = value.get_mut("extra").and_then(|e| e.as_object_mut()) {
        extra.remove("recentBlockhash");
        extra.remove("lastValidBlockHeight");
        extra.remove("recentSlot");
    }
}

/// Find which offered `upto` requirement the client's `accepted` matches.
///
/// Serializes each offered requirement to JSON, strips transient blockhash
/// hints from both sides, and compares for structural equality — mirroring
/// exact's `find_matching_requirement`. Returns the matched offered requirement
/// (the source of truth for mint/token-program binding), or an error if the
/// client's `accepted` matches none of the offered currencies.
///
/// SECURITY: the returned requirement is always one the server offered, so the
/// chosen asset can never be attacker-controlled; the channel is bound to its
/// mint + token program by the caller.
fn match_offered_requirement<'r>(
    offered: &'r [UptoRequirements],
    accepted: &serde_json::Value,
) -> Result<&'r UptoRequirements, Error> {
    // Round-trip the client's `accepted` through the typed `UptoRequirements`
    // so both sides normalize via the same Serialize impl (field ordering,
    // skipped optionals) before comparison — mirrors exact's matcher. A
    // canonical-compatible client that echoes extra fields the server never
    // emits would fail to parse here, which is the desired strict behaviour:
    // the server only matches its own offered shapes.
    let accepted_requirements: UptoRequirements = serde_json::from_value(accepted.clone())
        .map_err(|e| Error::InvalidPaymentRequired(format!("invalid accepted requirement: {e}")))?;
    let mut accepted_json = serde_json::to_value(&accepted_requirements)
        .map_err(|e| Error::Other(format!("failed to serialize accepted: {e}")))?;
    strip_upto_blockhash_hints(&mut accepted_json);
    offered
        .iter()
        .find(|requirement| {
            serde_json::to_value(requirement)
                .map(|mut json| {
                    strip_upto_blockhash_hints(&mut json);
                    json == accepted_json
                })
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            Error::Other("credential's accepted does not match any offered currency option".into())
        })
}

/// Assert the channel committed (at open) to exactly the distribution the
/// server expects. The on-chain `distribution_hash` binds the recipient split,
/// so this guards that settlement pays the configured beneficiary and a client
/// cannot redirect funds. An empty `expected` would leave the payee the
/// implicit 100% remainder — `upto` never expects that: its fee-payer payee
/// seat is zero-share, so the split always names the beneficiary explicitly.
fn validate_distribution_hash(
    distribution_hash: &[u8; 32],
    expected: &[pc::Distribution],
) -> Result<(), Error> {
    if distribution_hash != &pc::distribution_hash(expected) {
        return Err(Error::Other(
            "channel distribution does not match the expected recipient split".to_string(),
        ));
    }
    Ok(())
}

/// Locate the canonical payment-channels `open` in `tx` and enforce the `upto`
/// top-level transaction layout: an optional ComputeBudget prefix
/// (`SetComputeUnitLimit` before `SetComputeUnitPrice`, each at most once and
/// within the spec ceilings), exactly one `open`, then an optional suffix of at
/// most [`pc::OPEN_MAX_LIGHTHOUSE_INSTRUCTIONS`] Lighthouse assertions and a
/// Memo, capped at [`pc::OPEN_MAX_OPTIONAL_SUFFIX`] instructions total.
///
/// Clients legitimately wrap the open: the canonical TypeScript client sizes the
/// compute budget and appends a Memo (a seller-declared `extra.memo`, else a
/// random nonce), and Phantom/Solflare inject Lighthouse assertions into what
/// they sign. Anything outside that allowlist is rejected — the operator
/// co-signs this transaction as fee payer, so an unrecognized instruction is one
/// the operator would blindly authorize. For the same reason no wrapper
/// instruction may name the fee payer among its accounts.
///
/// The memo's *contents* are not checked: a facilitator only pins them when the
/// seller declares `extra.memo`, and this server never does (it advertises
/// `memo: None`), so any memo the client chooses is acceptable here.
fn find_canonical_open_instruction<'tx>(
    tx: &'tx VersionedTransaction,
    keys: &[Pubkey],
    program_id: &Pubkey,
) -> Result<&'tx CompiledInstruction, Error> {
    Ok(pc::scan_channel_tx_layout(
        tx,
        keys,
        program_id,
        OPEN_INSTRUCTION_DISCRIMINATOR,
        "open",
        // `upto` servers never declare `extra.memo`, so whatever memo the
        // client chose is acceptable; only its presence is bounded.
        pc::MemoPolicy::Optional,
    )?)
}

/// Assert `tx` carries the expected payment-channels `open` instruction so the
/// operator can safely co-sign it as fee payer (see [`X402Upto::validate_open_transaction`]).
// Each account slot is an independent expected key (rentPayer vs
// authorized_signer are distinct roles), so they are passed individually
// rather than bundled. The arity is inherent to the open account layout.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_open_instruction(
    tx: &VersionedTransaction,
    program_id: &Pubkey,
    rent_payer: &Pubkey,
    authorized_signer: &Pubkey,
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
    channel_id: &Pubkey,
    max_amount: Option<u64>,
    expected_grace_period: Option<u32>,
    payload_nonce: Option<&str>,
    payload_open_slot: Option<&str>,
    recent_slot: Option<u64>,
) -> Result<(), Error> {
    // Reject v0 transactions that pull accounts from address lookup tables.
    // This validator (and the fee-payer co-sign) resolves every account via
    // `static_account_keys()`; an `open` needs only static accounts, so a
    // non-empty ALT lookup could smuggle in accounts the guards below cannot
    // see - and the operator would blindly co-sign. Mirrors the mpp charge-tx
    // verifier's `reject_address_lookup_tables`.
    if tx
        .message
        .address_table_lookups()
        .is_some_and(|lookups| !lookups.is_empty())
    {
        return Err(Error::Other(
            "open transaction must not use address lookup tables".to_string(),
        ));
    }

    let keys = tx.message.static_account_keys();
    let ix = find_canonical_open_instruction(tx, keys, program_id)?;
    // Account order from `build_open_instruction`:
    // [payer, rentPayer, payee, mint, authorized_signer, channel, ...].
    // rentPayer (slot 1) is whoever funds the channel PDA + escrow-ATA rent and
    // co-signs as fee payer; authorized_signer (slot 4) is the voucher signer.
    // These are independent roles (mirrors the mpp-session `verifyOpenTx`): in
    // gasless `upto` both are the operator, in gasless `batch` rentPayer is the
    // operator while authorized_signer is the payer, so each slot is checked
    // against its own expected key rather than a single conflated one.
    let account_at = |pos: usize| -> Option<Pubkey> {
        ix.accounts
            .get(pos)
            .and_then(|&i| keys.get(i as usize))
            .copied()
    };
    let expect = |pos: usize, want: &Pubkey, label: &str| -> Result<(), Error> {
        match account_at(pos) {
            Some(got) if got == *want => Ok(()),
            other => Err(Error::Other(format!(
                "open transaction {label} mismatch: expected {}, got {}",
                pc::pubkey_string(want),
                other
                    .map(|p| pc::pubkey_string(&p))
                    .unwrap_or_else(|| "<none>".to_string())
            ))),
        }
    };
    expect(0, payer, "payer")?;
    expect(1, rent_payer, "rent_payer")?;
    expect(2, payee, "payee")?;
    expect(3, mint, "mint")?;
    expect(4, authorized_signer, "authorized_signer")?;
    expect(5, channel_id, "channel")?;
    let (payer_token, _) = pc::find_associated_token_address(payer, mint, token_program);
    let (channel_token, _) = pc::find_associated_token_address(channel_id, mint, token_program);
    expect(6, &payer_token, "payer_token_account")?;
    expect(7, &channel_token, "channel_token_account")?;
    expect(8, token_program, "token_program")?;
    expect(9, &pc::system_program_id(), "system_program")?;
    expect(10, &pc::rent_sysvar_id(), "rent_sysvar")?;
    expect(
        11,
        &pc::associated_token_program_id(),
        "associated_token_program",
    )?;
    expect(
        12,
        &pc::find_event_authority_pda(program_id).0,
        "event_authority",
    )?;
    expect(13, program_id, "self_program")?;

    // openArgs layout:
    // [discriminator u8][salt u64][deposit u64][grace u32][openSlot u64][recipients].
    if ix.data.len() < 1 + 8 + 8 + 4 + 8 {
        return Err(Error::Other(format!(
            "open instruction data too short ({} bytes)",
            ix.data.len()
        )));
    }
    let salt = u64::from_le_bytes(ix.data[1..9].try_into().expect("8-byte slice"));
    let deposit = u64::from_le_bytes(ix.data[9..17].try_into().expect("8-byte slice"));
    let grace_period = u32::from_le_bytes(ix.data[17..21].try_into().expect("4-byte slice"));
    let open_slot = u64::from_le_bytes(ix.data[21..29].try_into().expect("8-byte slice"));
    if let Some(payload_nonce) = payload_nonce {
        if payload_nonce != salt.to_string() {
            return Err(Error::Other(format!(
                "open salt {salt} does not match payload nonce {payload_nonce:?}"
            )));
        }
    }
    if let Some(payload_open_slot) = payload_open_slot {
        if payload_open_slot != open_slot.to_string() {
            return Err(Error::Other(format!(
                "open slot {open_slot} does not match payload openSlot {payload_open_slot:?}"
            )));
        }
    }
    if let Some(expected_grace_period) = expected_grace_period {
        if grace_period != expected_grace_period {
            return Err(Error::Other(format!(
                "open withdraw delay {grace_period} must equal the advertised withdrawDelay {expected_grace_period}"
            )));
        }
    }

    // Slot-addressed channel invariant: the channel account must be the PDA
    // actually derived with the args' salt + openSlot, not just any account
    // the payload named.
    let (derived, _) = pc::find_channel_pda(
        payer,
        payee,
        mint,
        authorized_signer,
        salt,
        open_slot,
        program_id,
    );
    if derived != *channel_id {
        return Err(Error::Other(format!(
            "open channel PDA {} != derived {}",
            pc::pubkey_string(channel_id),
            pc::pubkey_string(&derived)
        )));
    }
    if let Some(max_amount) = max_amount {
        if deposit != max_amount {
            return Err(Error::Other(format!(
                "open deposit {deposit} must equal the authorized maximum {max_amount}"
            )));
        }
    }
    if let Some(recent_slot) = recent_slot {
        if open_slot > recent_slot {
            return Err(Error::Other(format!(
                "open openSlot {open_slot} is ahead of the challenged recentSlot {recent_slot}"
            )));
        }
        if recent_slot - open_slot > pc::OPEN_SLOT_WINDOW {
            return Err(Error::Other(format!(
                "open openSlot {open_slot} is outside the {}-slot freshness window of the \
                 challenged recentSlot {recent_slot}",
                pc::OPEN_SLOT_WINDOW
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::payment_channels::{
        build_open_instruction, derive_channel_addresses, OpenChannelParams,
    };
    use async_trait::async_trait;
    use solana_keychain::{SignTransactionResult, SignerError};
    use solana_signature::Signature;

    struct TestSigner(Pubkey);

    #[async_trait]
    impl SolanaSigner for TestSigner {
        fn pubkey(&self) -> Pubkey {
            self.0
        }

        async fn sign_transaction(
            &self,
            _tx: &mut Transaction,
        ) -> Result<SignTransactionResult, SignerError> {
            Err(SignerError::Other("unused".to_string()))
        }

        async fn sign_message(&self, _message: &[u8]) -> Result<Signature, SignerError> {
            Ok(Signature::from([7u8; 64]))
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    fn token_program() -> Pubkey {
        Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
    }

    fn open_params(
        payer: Pubkey,
        payee: Pubkey,
        mint: Pubkey,
        operator: Pubkey,
    ) -> OpenChannelParams {
        OpenChannelParams {
            payer,
            // rentPayer is pinned to the operator (the fee payer that co-signs open).
            rent_payer: operator,
            payee,
            mint,
            authorized_signer: operator,
            salt: 7,
            open_slot: 314,
            deposit: 1_000_000,
            grace_period: 900,
            recipients: vec![],
            token_program: token_program(),
            program_id: pc::default_program_id(),
        }
    }

    fn unsigned_tx(instructions: &[solana_instruction::Instruction]) -> VersionedTransaction {
        let msg = Message::new(instructions, Some(&Pubkey::new_unique()));
        VersionedTransaction::from(Transaction::new_unsigned(msg))
    }

    fn unsigned_tx_with_fee_payer(
        instructions: &[solana_instruction::Instruction],
        fee_payer: Pubkey,
    ) -> VersionedTransaction {
        let msg = Message::new(instructions, Some(&fee_payer));
        VersionedTransaction::from(Transaction::new_unsigned(msg))
    }

    #[test]
    fn accepts_a_well_formed_open() {
        let (payer, payee, mint, operator) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let params = open_params(payer, payee, mint, operator);
        let channel = derive_channel_addresses(&params).channel;
        let tx = unsigned_tx(&[build_open_instruction(&params)]);

        assert!(validate_open_instruction(
            &tx,
            &pc::default_program_id(),
            &operator,
            &operator,
            &payer,
            &payee,
            &mint,
            &token_program(),
            &channel,
            None,
            None,
            None,
            None,
            None,
        )
        .is_ok());
    }

    #[test]
    fn validates_distinct_rent_payer_and_authorized_signer() {
        // Gasless batch / client-voucher (matrix combo 2): the operator funds
        // the rent (rentPayer) while the payer signs vouchers (authorized_signer)
        // - two distinct keys. The old conflated validator rejected this open.
        let (payer, payee, mint, operator) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let params = OpenChannelParams {
            payer,
            rent_payer: operator,
            payee,
            mint,
            authorized_signer: payer,
            salt: 7,
            open_slot: 314,
            deposit: 1_000_000,
            grace_period: 900,
            recipients: vec![],
            token_program: token_program(),
            program_id: pc::default_program_id(),
        };
        let channel = derive_channel_addresses(&params).channel;
        let tx = unsigned_tx(&[build_open_instruction(&params)]);

        // Correct expectations (rentPayer = operator, authorized_signer = payer).
        assert!(validate_open_instruction(
            &tx,
            &pc::default_program_id(),
            &operator,
            &payer,
            &payer,
            &payee,
            &mint,
            &token_program(),
            &channel,
            None,
            None,
            None,
            None,
            None,
        )
        .is_ok());

        // Swapping the two expected keys must fail - proves the slots are
        // validated independently rather than against one conflated key.
        assert!(validate_open_instruction(
            &tx,
            &pc::default_program_id(),
            &payer,
            &operator,
            &payer,
            &payee,
            &mint,
            &token_program(),
            &channel,
            None,
            None,
            None,
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn binds_open_args_deposit_and_slot() {
        // The validator decodes openArgs and enforces the slot-addressed
        // channel invariant: a deposit that differs from the authorized
        // maximum, an openSlot ahead of the challenged recentSlot, a stale
        // openSlot outside the freshness window, and a channel account that is
        // not the PDA derived from the args all reject. `open_params` uses
        // deposit 1_000_000 and open_slot 314.
        let (payer, payee, mint, operator) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let params = open_params(payer, payee, mint, operator);
        let channel = derive_channel_addresses(&params).channel;
        let tx = unsigned_tx(&[build_open_instruction(&params)]);
        let check = |channel: &Pubkey, max_amount: Option<u64>, recent_slot: Option<u64>| {
            validate_open_instruction(
                &tx,
                &pc::default_program_id(),
                &operator,
                &operator,
                &payer,
                &payee,
                &mint,
                &token_program(),
                channel,
                max_amount,
                None,
                None,
                None,
                recent_slot,
            )
        };
        assert!(check(&channel, Some(1_000_000), Some(314)).is_ok());
        // At the window edge and with unknown bounds it still verifies.
        assert!(check(&channel, Some(1_000_000), Some(314 + pc::OPEN_SLOT_WINDOW)).is_ok());
        assert!(check(&channel, None, None).is_ok());
        // Deposit must equal the authorized maximum.
        let err = check(&channel, Some(999_999), Some(314)).unwrap_err();
        assert!(err.to_string().contains("authorized maximum"), "{err}");
        // openSlot ahead of the challenged recentSlot rejects.
        let err = check(&channel, Some(1_000_000), Some(313)).unwrap_err();
        assert!(err.to_string().contains("ahead of the challenged"), "{err}");
        // openSlot outside the freshness window rejects.
        let err = check(
            &channel,
            Some(1_000_000),
            Some(314 + pc::OPEN_SLOT_WINDOW + 1),
        )
        .unwrap_err();
        assert!(err.to_string().contains("freshness window"), "{err}");
        // A channel that is not the PDA derived from the args fails the bind
        // (the slot-5 account check fires first on the mismatch).
        let other = Pubkey::new_unique();
        let err = check(&other, Some(1_000_000), Some(314)).unwrap_err();
        assert!(err.to_string().contains("channel"), "{err}");

        let strict = |withdraw_delay: u32, payload_nonce: &str, payload_open_slot: &str| {
            validate_open_instruction(
                &tx,
                &pc::default_program_id(),
                &operator,
                &operator,
                &payer,
                &payee,
                &mint,
                &token_program(),
                &channel,
                Some(1_000_000),
                Some(withdraw_delay),
                Some(payload_nonce),
                Some(payload_open_slot),
                Some(314),
            )
        };
        assert!(strict(900, "7", "314").is_ok());
        let err = strict(901, "7", "314").unwrap_err();
        assert!(err.to_string().contains("withdraw delay"), "{err}");
        let err = strict(900, "8", "314").unwrap_err();
        assert!(err.to_string().contains("payload nonce"), "{err}");
        let err = strict(900, "7", "315").unwrap_err();
        assert!(err.to_string().contains("payload openSlot"), "{err}");
    }

    #[test]
    fn rejects_a_foreign_program_instruction() {
        // The SOL-drain vector: a SystemProgram transfer from the operator.
        let operator = Pubkey::new_unique();
        let system = Pubkey::from_str("11111111111111111111111111111111").unwrap();
        let evil = solana_instruction::Instruction {
            program_id: system,
            accounts: vec![],
            data: vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // transfer-ish
        };
        let tx = unsigned_tx(&[evil]);
        let payer = Pubkey::new_unique();
        let payee = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let channel = Pubkey::new_unique();
        assert!(validate_open_instruction(
            &tx,
            &pc::default_program_id(),
            &operator,
            &operator,
            &payer,
            &payee,
            &mint,
            &token_program(),
            &channel,
            None,
            None,
            None,
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn rejects_extra_instructions_and_account_mismatch() {
        let (payer, payee, mint, operator) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let params = open_params(payer, payee, mint, operator);
        let channel = derive_channel_addresses(&params).channel;
        let open = build_open_instruction(&params);

        // A second instruction smuggled in alongside the open.
        let extra = solana_instruction::Instruction {
            program_id: Pubkey::from_str("11111111111111111111111111111111").unwrap(),
            accounts: vec![],
            data: vec![],
        };
        let two = unsigned_tx(&[open.clone(), extra]);
        assert!(validate_open_instruction(
            &two,
            &pc::default_program_id(),
            &operator,
            &operator,
            &payer,
            &payee,
            &mint,
            &token_program(),
            &channel,
            None,
            None,
            None,
            None,
            None,
        )
        .is_err());

        // Right shape, wrong expected payee.
        let one = unsigned_tx(&[open]);
        let wrong_payee = Pubkey::new_unique();
        assert!(validate_open_instruction(
            &one,
            &pc::default_program_id(),
            &operator,
            &operator,
            &payer,
            &wrong_payee,
            &mint,
            &token_program(),
            &channel,
            None,
            None,
            None,
            None,
            None,
        )
        .is_err());
    }

    fn cu_limit_ix(units: u32) -> solana_instruction::Instruction {
        let mut data = vec![pc::COMPUTE_BUDGET_SET_UNIT_LIMIT];
        data.extend_from_slice(&units.to_le_bytes());
        solana_instruction::Instruction {
            program_id: pc::compute_budget_program_id(),
            accounts: vec![],
            data,
        }
    }

    fn cu_price_ix(micro_lamports: u64) -> solana_instruction::Instruction {
        let mut data = vec![pc::COMPUTE_BUDGET_SET_UNIT_PRICE];
        data.extend_from_slice(&micro_lamports.to_le_bytes());
        solana_instruction::Instruction {
            program_id: pc::compute_budget_program_id(),
            accounts: vec![],
            data,
        }
    }

    fn memo_ix(text: &str) -> solana_instruction::Instruction {
        solana_instruction::Instruction {
            program_id: pc::memo_program_id(),
            accounts: vec![],
            data: text.as_bytes().to_vec(),
        }
    }

    fn lighthouse_ix() -> solana_instruction::Instruction {
        solana_instruction::Instruction {
            program_id: pc::lighthouse_program_id(),
            accounts: vec![],
            data: vec![0],
        }
    }

    /// Run the layout + binding validator over `instructions` with every
    /// account expectation satisfied, so the outcome turns only on the layout.
    fn validate_layout(instructions: &[solana_instruction::Instruction]) -> Result<(), Error> {
        let (payer, payee, mint, operator) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let params = open_params(payer, payee, mint, operator);
        let channel = derive_channel_addresses(&params).channel;
        let open = build_open_instruction(&params);
        let wrapped: Vec<solana_instruction::Instruction> = instructions
            .iter()
            .cloned()
            .map(|ix| {
                if ix.program_id == Pubkey::default() {
                    open.clone()
                } else {
                    ix
                }
            })
            .collect();
        let tx = unsigned_tx(&wrapped);
        validate_open_instruction(
            &tx,
            &pc::default_program_id(),
            &operator,
            &operator,
            &payer,
            &payee,
            &mint,
            &token_program(),
            &channel,
            None,
            None,
            None,
            None,
            None,
        )
    }

    /// Placeholder standing in for the channel `open`, substituted by
    /// [`validate_layout`] so a case only spells out the wrapping.
    fn open_placeholder() -> solana_instruction::Instruction {
        solana_instruction::Instruction {
            program_id: Pubkey::default(),
            accounts: vec![],
            data: vec![],
        }
    }

    #[test]
    fn accepts_the_canonical_compute_budget_and_memo_wrapping() {
        // What the canonical TypeScript client emits: a sized compute budget
        // before the open and a memo after it.
        assert!(validate_layout(&[
            cu_limit_ix(90_000),
            cu_price_ix(1),
            open_placeholder(),
            memo_ix("order-4711"),
        ])
        .is_ok());
        // A bare open stays valid - every wrapper is optional.
        assert!(validate_layout(&[open_placeholder()]).is_ok());
        // Phantom/Solflare inject up to three Lighthouse assertions, and a
        // memo can ride alongside them.
        assert!(validate_layout(&[
            open_placeholder(),
            lighthouse_ix(),
            lighthouse_ix(),
            lighthouse_ix(),
            memo_ix("x"),
        ])
        .is_ok());
    }

    #[test]
    fn rejects_a_malformed_compute_budget_prefix() {
        // SetComputeUnitPrice before SetComputeUnitLimit: the runtime applies
        // the price to the limit, so the spec pins the order.
        assert!(
            validate_layout(&[cu_price_ix(1), cu_limit_ix(90_000), open_placeholder()]).is_err()
        );
        assert!(
            validate_layout(&[cu_limit_ix(90_000), cu_limit_ix(90_000), open_placeholder()])
                .is_err()
        );
        assert!(validate_layout(&[cu_price_ix(1), cu_price_ix(1), open_placeholder()]).is_err());
        // An unsupported ComputeBudget opcode (RequestHeapFrame).
        let heap_frame = solana_instruction::Instruction {
            program_id: pc::compute_budget_program_id(),
            accounts: vec![],
            data: vec![1, 0, 0, 0, 0],
        };
        assert!(validate_layout(&[heap_frame, open_placeholder()]).is_err());
    }

    #[test]
    fn rejects_compute_budget_values_over_the_spec_ceilings() {
        // The operator pays the priority fee on the requested limit, so both
        // knobs are capped: a client cannot bill the operator arbitrarily.
        assert!(validate_layout(&[
            cu_limit_ix(pc::OPEN_MAX_COMPUTE_UNIT_LIMIT),
            open_placeholder()
        ])
        .is_ok());
        assert!(validate_layout(&[
            cu_limit_ix(pc::OPEN_MAX_COMPUTE_UNIT_LIMIT + 1),
            open_placeholder()
        ])
        .is_err());
        assert!(validate_layout(&[
            cu_price_ix(pc::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS),
            open_placeholder()
        ])
        .is_ok());
        assert!(validate_layout(&[
            cu_price_ix(pc::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS + 1),
            open_placeholder()
        ])
        .is_err());
    }

    #[test]
    fn rejects_an_over_long_or_unknown_suffix() {
        // A fourth Lighthouse assertion is past what either wallet injects.
        assert!(validate_layout(&[
            open_placeholder(),
            lighthouse_ix(),
            lighthouse_ix(),
            lighthouse_ix(),
            lighthouse_ix(),
        ])
        .is_err());
        // Five optional instructions exceed the suffix budget.
        assert!(validate_layout(&[
            open_placeholder(),
            lighthouse_ix(),
            lighthouse_ix(),
            lighthouse_ix(),
            memo_ix("a"),
            memo_ix("b"),
        ])
        .is_err());
        // A ComputeBudget instruction may only appear before the open.
        assert!(validate_layout(&[open_placeholder(), cu_limit_ix(90_000)]).is_err());
        // A second open is not a permitted suffix instruction.
        assert!(validate_layout(&[open_placeholder(), open_placeholder()]).is_err());
    }

    #[test]
    fn rejects_a_wrapper_instruction_naming_the_fee_payer() {
        // The operator co-signs this transaction; a wrapper instruction that
        // names it could borrow its authority, so only `open` may reference it.
        let (payer, payee, mint, operator) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let params = open_params(payer, payee, mint, operator);
        let channel = derive_channel_addresses(&params).channel;
        let memo_naming_operator = solana_instruction::Instruction {
            program_id: pc::memo_program_id(),
            accounts: vec![solana_instruction::AccountMeta::new_readonly(
                operator, true,
            )],
            data: b"signed-memo".to_vec(),
        };
        let tx = unsigned_tx_with_fee_payer(
            &[build_open_instruction(&params), memo_naming_operator],
            operator,
        );
        assert!(validate_open_instruction(
            &tx,
            &pc::default_program_id(),
            &operator,
            &operator,
            &payer,
            &payee,
            &mint,
            &token_program(),
            &channel,
            None,
            None,
            None,
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_token_program_binding() {
        let (payer, payee, mint, operator) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let params = open_params(payer, payee, mint, operator);
        let channel = derive_channel_addresses(&params).channel;
        let tx = unsigned_tx(&[build_open_instruction(&params)]);
        let wrong_token_program =
            Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap();

        assert!(validate_open_instruction(
            &tx,
            &pc::default_program_id(),
            &operator,
            &operator,
            &payer,
            &payee,
            &mint,
            &wrong_token_program,
            &channel,
            None,
            None,
            None,
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn validate_distribution_hash_binds_the_expected_split() {
        let recipient = Pubkey::new_unique();
        let split = vec![pc::Distribution {
            recipient,
            bps: pc::FULL_SHARE_BPS,
        }];

        // Channel committed to exactly the expected split → accepted.
        let bound = pc::distribution_hash(&split);
        assert!(validate_distribution_hash(&bound, &split).is_ok());

        // Channel committed to a different distribution (here: empty) → rejected,
        // so a client cannot redirect the beneficiary's funds.
        let empty = pc::distribution_hash(&[]);
        assert!(validate_distribution_hash(&empty, &split).is_err());
        // And empty-expected accepts only an empty commitment.
        assert!(validate_distribution_hash(&empty, &[]).is_ok());
        assert!(validate_distribution_hash(&bound, &[]).is_err());
    }

    #[test]
    fn new_accepts_recipient_different_from_receiver_authorizer() {
        let receiver_authorizer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let engine = X402Upto::new(UptoConfig {
            payout: UptoPayout::Beneficiary {
                address: pc::pubkey_string(&recipient),
            },
            currencies: vec![CurrencyConfig {
                currency: "USDC".to_string(),
                decimals: 6,
                token_program: None,
            }],
            cluster: "localnet".to_string(),
            rpc_url: Some("http://127.0.0.1:8899".to_string()),
            resource: "/usage".to_string(),
            description: None,
            max_timeout_seconds: 300,
            program_id: None,
            withdraw_delay: 900,
            fee_payer_signer: std::sync::Arc::new(TestSigner(receiver_authorizer)),
            receiver_authorizer_signer: None,
        })
        .expect("distinct recipient should be accepted");
        let req = engine
            .upto_requirements("1.00")
            .expect("requirements should build");
        assert_eq!(req.pay_to, pc::pubkey_string(&recipient));
        assert_eq!(
            req.extra.receiver_authorizer,
            pc::pubkey_string(&receiver_authorizer)
        );
        assert_eq!(req.extra.fee_payer, pc::pubkey_string(&receiver_authorizer));
        assert_eq!(req.extra.withdraw_delay, 900);
    }

    #[tokio::test]
    async fn cosign_rejects_signer_when_not_fee_payer() {
        let signer = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let ix = solana_instruction::Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![solana_instruction::AccountMeta::new_readonly(signer, true)],
            data: vec![],
        };
        let mut tx = unsigned_tx_with_fee_payer(&[ix], fee_payer);

        let err = cosign_operator_fee_payer(&TestSigner(signer), &signer, &mut tx)
            .await
            .expect_err("signer must not be accepted outside fee-payer slot");
        assert!(err
            .to_string()
            .contains("fee payer must be the advertised fee payer"));
    }

    #[tokio::test]
    async fn cosign_accepts_fee_payer() {
        let fee_payer = Pubkey::new_unique();
        let ix = solana_instruction::Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![],
            data: vec![],
        };
        let mut tx = unsigned_tx_with_fee_payer(&[ix], fee_payer);

        cosign_operator_fee_payer(&TestSigner(fee_payer), &fee_payer, &mut tx)
            .await
            .expect("fee-payer transaction should sign");
        assert_eq!(tx.signatures[0], Signature::from([7u8; 64]));
    }

    // FIX #7: an `open` needs only static accounts, so a v0 transaction that
    // pulls accounts from an address lookup table must be rejected before the
    // operator co-signs as fee payer - otherwise it could smuggle in accounts
    // the static-key guards above cannot inspect.
    #[test]
    fn rejects_open_with_address_lookup_tables() {
        use solana_message::{v0, VersionedMessage};

        let (payer, payee, mint, operator) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let params = open_params(payer, payee, mint, operator);
        let channel = derive_channel_addresses(&params).channel;

        // Build an otherwise-valid open, then wrap it in a v0 message carrying a
        // non-empty address-table lookup.
        let legacy = Message::new(&[build_open_instruction(&params)], Some(&payer));
        let v0_msg = v0::Message {
            header: legacy.header,
            account_keys: legacy.account_keys,
            recent_blockhash: legacy.recent_blockhash,
            instructions: legacy.instructions,
            address_table_lookups: vec![v0::MessageAddressTableLookup {
                account_key: Pubkey::new_unique(),
                writable_indexes: vec![0],
                readonly_indexes: vec![],
            }],
        };
        let tx = VersionedTransaction {
            signatures: vec![Signature::default(); v0_msg.header.num_required_signatures as usize],
            message: VersionedMessage::V0(v0_msg),
        };

        let err = validate_open_instruction(
            &tx,
            &pc::default_program_id(),
            &operator,
            &operator,
            &payer,
            &payee,
            &mint,
            &token_program(),
            &channel,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("address lookup tables"),
            "expected ALT rejection, got: {err}"
        );
    }

    // ── Multi-currency tests ────────────────────────────────────────────────

    /// Build an engine offering the given currency symbols (each with 6
    /// decimals and program derived from the symbol).
    fn multi_currency_engine(symbols: &[&str]) -> X402Upto {
        let currencies = symbols
            .iter()
            .map(|s| CurrencyConfig {
                currency: s.to_string(),
                decimals: 6,
                token_program: None,
            })
            .collect();
        X402Upto::new(UptoConfig {
            payout: UptoPayout::Beneficiary {
                address: pc::pubkey_string(&Pubkey::new_unique()),
            },
            currencies,
            // Mainnet so PYUSD resolves to its Token-2022 mint (devnet PYUSD also
            // exists, but mainnet keeps the legacy-vs-2022 contrast crisp).
            cluster: "mainnet-beta".to_string(),
            rpc_url: Some("http://127.0.0.1:8899".to_string()),
            resource: "/usage".to_string(),
            description: None,
            max_timeout_seconds: 300,
            program_id: None,
            withdraw_delay: 900,
            fee_payer_signer: std::sync::Arc::new(TestSigner(Pubkey::new_unique())),
            receiver_authorizer_signer: None,
        })
        .expect("engine should build")
    }

    /// `upto()` with `accepted_currencies = Some(["USDC","PYUSD"])` advertises
    /// one `accepts[]` entry per currency, each with a distinct mint and the
    /// correct token program (legacy SPL for USDC, Token-2022 for PYUSD).
    #[test]
    fn upto_advertises_each_accepted_currency() {
        let engine = multi_currency_engine(&["USDC", "PYUSD"]);
        // Avoid an RPC round-trip: serve the blockhash from the cache.
        let cache = crate::core::blockhash::BlockhashCache::new();
        cache.set(
            "CacheTestBlockhash1111111111111111111111111".to_string(),
            100,
            314,
        );
        let engine = engine.with_blockhash_cache(cache);

        let envelope = engine.upto("1.00").expect("challenge should build");
        assert_eq!(envelope.accepts.len(), 2);

        let usdc = &envelope.accepts[0];
        let pyusd = &envelope.accepts[1];
        // Distinct mints.
        assert_ne!(usdc.asset, pyusd.asset);
        // Per-currency token program.
        let legacy = pc::pubkey_string(
            &Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap(),
        );
        let token_2022 = pc::pubkey_string(
            &Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap(),
        );
        assert_eq!(usdc.extra.token_program.as_deref(), Some(legacy.as_str()));
        assert_eq!(
            pyusd.extra.token_program.as_deref(),
            Some(token_2022.as_str())
        );
        // Both carry the same fetched blockhash + recentSlot.
        assert_eq!(usdc.extra.recent_blockhash, pyusd.extra.recent_blockhash);
        assert!(usdc.extra.recent_blockhash.is_some());
        assert_eq!(usdc.extra.recent_slot.as_deref(), Some("314"));
        assert_eq!(pyusd.extra.recent_slot.as_deref(), Some("314"));
    }

    /// The matcher selects the offered requirement whose currency the client
    /// echoed — even when the echoed `accepted` carries the challenge's
    /// blockhash build-hints — and rejects a currency that was never offered.
    #[test]
    fn match_offered_requirement_selects_chosen_currency() {
        let engine = multi_currency_engine(&["USDC", "PYUSD"]);
        let offered: Vec<_> = engine
            .offered_currencies()
            .iter()
            .map(|c| engine.upto_requirements_for(c, "1.00").unwrap())
            .collect();

        // Client echoes the PYUSD requirement with blockhash hints injected
        // (exactly what `upto()` stamped into the challenge).
        let mut accepted = serde_json::to_value(&offered[1]).unwrap();
        let extra = accepted
            .get_mut("extra")
            .and_then(|e| e.as_object_mut())
            .expect("accepted has an extra object");
        extra.insert(
            "recentBlockhash".to_string(),
            serde_json::Value::String("SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_string()),
        );
        extra.insert(
            "lastValidBlockHeight".to_string(),
            serde_json::Value::String("123456789".to_string()),
        );
        extra.insert(
            "recentSlot".to_string(),
            serde_json::Value::String("350123456".to_string()),
        );

        let matched = match_offered_requirement(&offered, &accepted).expect("PYUSD should match");
        assert_eq!(matched.asset, offered[1].asset);
        assert_eq!(matched.extra.token_program, offered[1].extra.token_program);

        // A currency the server didn't offer (USDT) must be rejected.
        let usdt_engine = multi_currency_engine(&["USDT"]);
        let usdt_req = usdt_engine
            .upto_requirements_for(&usdt_engine.config.currencies[0], "1.00")
            .unwrap();
        let not_offered = serde_json::to_value(&usdt_req).unwrap();
        let err = match_offered_requirement(&offered, &not_offered).unwrap_err();
        assert!(
            err.to_string().contains("does not match any offered"),
            "got: {err}"
        );
    }

    // ── Facilitator-as-zero-share-payee model (settle `InvalidChannelPayee`,
    // 0x6) ──
    //
    // `settle_and_seal` requires its `payee [signer]` account to equal
    // `channel.payee`. Settlement transactions are signed by the fee payer,
    // so the channel MUST be opened with `payee = feePayer` (the zero-share
    // lifecycle seat). The payout recipient is paid via a *bound 100%
    // distribution split*, NOT by being the channel payee, and the receiver
    // authorizer holds only `authorized_signer` (Ed25519 voucher authority).
    // Opening with `payee = recipient` (or `payee = receiverAuthorizer`) is
    // what reverts settle with 0x6.

    /// Regression guard for the correct open: `payee = feePayer` with the real
    /// recipient carried as a 100% distribution split. The open must validate
    /// as fee-payer-payee and must NOT validate as receiver-authorizer-payee
    /// or recipient-payee.
    #[test]
    fn open_binds_channel_payee_to_the_fee_payer_settle_signer() {
        let payer = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let receiver_authorizer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        assert_ne!(
            receiver_authorizer, recipient,
            "models recipient != receiver authorizer"
        );

        let params = OpenChannelParams {
            payer,
            rent_payer: fee_payer,
            payee: fee_payer,
            mint,
            authorized_signer: receiver_authorizer,
            salt: 7,
            open_slot: 314,
            deposit: 1_000_000,
            grace_period: 900,
            // Real recipient is paid via a bound 100% split, not as the payee.
            recipients: vec![crate::core::payment_channels::Distribution {
                recipient,
                bps: pc::FULL_SHARE_BPS,
            }],
            token_program: token_program(),
            program_id: pc::default_program_id(),
        };
        let channel = derive_channel_addresses(&params).channel;
        let tx = unsigned_tx(&[build_open_instruction(&params)]);

        let check = |payee: &Pubkey| {
            validate_open_instruction(
                &tx,
                &pc::default_program_id(),
                &fee_payer,
                &receiver_authorizer,
                &payer,
                payee,
                &mint,
                &token_program(),
                &channel,
                None,
                None,
                None,
                None,
                None,
            )
        };

        assert!(
            check(&fee_payer).is_ok(),
            "fee-payer-payee open must validate"
        );

        // Neither the receiver authorizer nor the recipient is the channel
        // payee: validating the same open against either must fail — proving
        // settle can only be authorized by the fee payer that actually signs
        // (any other payee is the shape that reverts settle with 0x6).
        assert!(
            check(&receiver_authorizer).is_err(),
            "channel payee must be the fee payer, not the receiver authorizer"
        );
        assert!(
            check(&recipient).is_err(),
            "channel payee must be the fee payer, never the payout recipient"
        );
    }

    #[test]
    fn upto_challenge_advertises_receiver_authorizer_and_beneficiary() {
        let engine = multi_currency_engine(&["USDC"]);
        let req = engine
            .upto_requirements_for(&engine.config.currencies[0], "0.01")
            .expect("requirement builds");
        assert_eq!(
            req.extra.receiver_authorizer,
            engine.receiver_authorizer(),
            "receiverAuthorizer must be the voucher signer"
        );
        assert_ne!(
            req.pay_to,
            engine.receiver_authorizer(),
            "payTo is the beneficiary, not the receiver authorizer"
        );
        assert_eq!(req.extra.fee_payer, engine.fee_payer());
        assert_eq!(req.extra.withdraw_delay, 900);
        assert!(serde_json::to_value(&req).unwrap()["extra"]
            .get("facilitatorAddress")
            .is_none());
    }
}
