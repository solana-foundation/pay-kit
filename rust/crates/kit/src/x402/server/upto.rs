//! Server-side handler for the x402 `upto` scheme (payment-channel asset transfer method).
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
//!    amount and submits `settle_and_finalize` + ATA setup + `distribute`, refunding
//!    `deposit − actual` to the payer.

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use solana_instruction::Instruction;
use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

use crate::core::payment_channels as pc;
use crate::core::payment_channels::generated::accounts::Channel;

use crate::x402::error::Error;
use crate::x402::protocol::schemes::exact::{
    caip2_network_for_cluster, default_rpc_url, default_token_program_for_currency,
    resolve_stablecoin_mint, ResourceInfo,
};
use crate::x402::protocol::schemes::upto::{
    assert_settlement_within_ceiling, verify_upto_payload, UptoExtra, UptoRequiredEnvelope,
    UptoRequirements, UptoSettlementResponse, UptoSignatureEnvelope, UPTO_ASSET_TRANSFER_METHOD,
    UPTO_SCHEME,
};
use crate::x402::server::CurrencyConfig;
use crate::x402::{PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, X402_VERSION_V2};

/// `ChannelStatus::Open` discriminant in the generated client.
const CHANNEL_STATUS_OPEN: u8 = 0;

/// Maximum accepted `PAYMENT-SIGNATURE` header length, in bytes. Mirrors the
/// MPP header parsers' `MAX_TOKEN_LEN` (16 KiB) so a hostile client cannot drive
/// unbounded base64 + JSON decode work with an oversized credential header.
const MAX_PAYMENT_SIGNATURE_HEADER_LEN: usize = 16 * 1024;

/// `Open` instruction discriminator in the generated payment-channels client
/// (`crate::generated::payment_channels::generated::instructions::OPEN_DISCRIMINATOR`).
const OPEN_INSTRUCTION_DISCRIMINATOR: u8 = 1;

/// Server configuration for the Solana x402 `upto` scheme.
#[derive(Clone)]
pub struct UptoConfig {
    /// Where settled funds go. The channel payee is always the operator (the
    /// only key the server can sign settlement with); this only decides whether
    /// the operator keeps everything or routes to a beneficiary via a bound
    /// distribution split. The fee exists only in the `Beneficiary` variant —
    /// meaningless without one — so the enum makes that unrepresentable.
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
    /// Operator signer - co-signs the open as fee payer and signs settlement
    /// vouchers + transactions. Its pubkey is the advertised facilitator.
    pub operator_signer: Arc<dyn SolanaSigner>,
}

/// Where an `upto` channel's settled funds go. The channel payee is always the
/// operator (the only key the server can sign settlement with); this decides
/// whether the operator keeps everything or routes to a beneficiary via a bound
/// distribution split. Modeling the operator fee as a field of the
/// `Beneficiary` variant makes "a fee with no beneficiary" unrepresentable.
#[derive(Clone, Debug)]
pub enum UptoPayout {
    /// No separate beneficiary — the operator keeps the full settled amount.
    OperatorKeepsAll,
    /// Pay `address` via a `10000 - operator_fee_bps` distribution split; the
    /// operator keeps `operator_fee_bps` (basis points, 0–10000) as remainder.
    Beneficiary {
        /// Base58 beneficiary (principal) address.
        address: String,
        /// Operator/facilitator cut in basis points of the settled amount.
        operator_fee_bps: u16,
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
    /// The channel's merchant/payee — the operator (the only key the server can
    /// sign `settle_and_finalize` with). The real beneficiary is paid via
    /// `distribution`, not by being the payee. See `verify_open`.
    pub payee: Pubkey,
    /// The bound distribution split validated at open (beneficiary at 100%).
    /// Settlement must distribute to exactly this set.
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
    operator: Pubkey,
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
    pub fn new(config: UptoConfig) -> Result<Self, Error> {
        if config.currencies.is_empty() {
            return Err(Error::Other("at least one currency is required".into()));
        }
        // Validate the beneficiary up front (the fee is intrinsic to the
        // `Beneficiary` variant, so it can't exist without one).
        if let UptoPayout::Beneficiary {
            address,
            operator_fee_bps,
        } = &config.payout
        {
            Pubkey::from_str(address)
                .map_err(|e| Error::Other(format!("Invalid recipient pubkey: {e}")))?;
            if *operator_fee_bps > 10_000 {
                return Err(Error::Other("operator_fee_bps must be <= 10000".into()));
            }
        }

        let operator = config.operator_signer.pubkey();
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
            operator,
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

    /// The primary/default currency: `currencies[0]`. The constructor rejects
    /// an empty list, so this never panics.
    fn primary_currency(&self) -> &CurrencyConfig {
        &self.config.currencies[0]
    }

    /// Resolve the mint for a specific currency descriptor on the configured
    /// cluster.
    fn mint_for(&self, cc: &CurrencyConfig) -> Result<Pubkey, Error> {
        let mint = resolve_stablecoin_mint(&cc.currency, Some(&self.config.cluster))
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

    /// The bound distribution split for a settled channel. The channel payee is
    /// always the operator (the only key the server can sign settlement with);
    /// the configured `recipient` (when set) receives `10000 - operator_fee_bps`
    /// basis points, and the operator keeps `operator_fee_bps` as the payee
    /// remainder. `None` recipient ⇒ empty distribution (operator keeps 100%).
    /// Re-derived server-side at verify/settle so a client cannot redirect it.
    /// EVM-aligned `payTo`: the beneficiary when configured, else the
    /// facilitator (operator keeps everything).
    fn pay_to(&self) -> String {
        match &self.config.payout {
            UptoPayout::Beneficiary { address, .. } => address.clone(),
            UptoPayout::OperatorKeepsAll => self.operator(),
        }
    }

    /// Facilitator's cut in basis points (0 when the operator keeps everything).
    fn facilitator_fee_bps(&self) -> u16 {
        match &self.config.payout {
            UptoPayout::Beneficiary {
                operator_fee_bps, ..
            } => *operator_fee_bps,
            UptoPayout::OperatorKeepsAll => 0,
        }
    }

    fn distribution(&self) -> Result<Vec<pc::Distribution>, Error> {
        let UptoPayout::Beneficiary {
            address,
            operator_fee_bps,
        } = &self.config.payout
        else {
            return Ok(Vec::new());
        };
        if *operator_fee_bps > 10_000 {
            return Err(Error::Other(
                "operator_fee_bps must be <= 10000".to_string(),
            ));
        }
        let recipient = Pubkey::from_str(address)
            .map_err(|e| Error::Other(format!("invalid recipient: {e}")))?;
        Ok(vec![pc::Distribution {
            recipient,
            bps: 10_000 - operator_fee_bps,
        }])
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
            // EVM-aligned: `payTo` is the beneficiary; the facilitator (operator)
            // is advertised separately. The channel's on-chain payee = the
            // facilitator is a client-side mapping (see `verify_open`/settle).
            pay_to: self.pay_to(),
            max_timeout_seconds: self.config.max_timeout_seconds,
            extra: UptoExtra {
                asset_transfer_method: UPTO_ASSET_TRANSFER_METHOD.to_string(),
                token_program: Some(pc::pubkey_string(&token_program)),
                facilitator_address: self.operator(),
                facilitator_fee: self.facilitator_fee_bps(),
                channel_program: Some(pc::pubkey_string(&self.program_id()?)),
                recent_blockhash: None,
                last_valid_block_height: None,
                valid_after: None,
            },
        })
    }

    /// Build the full `PAYMENT-REQUIRED` envelope for an `upto` challenge.
    ///
    /// This is where the (best-effort) recent blockhash is fetched and attached,
    /// so the client can build the channel `open` without an extra RPC.
    pub fn upto(&self, max_amount: &str) -> Result<UptoRequiredEnvelope, Error> {
        // Fail loudly (retryable) rather than issuing a 402 with no blockhash:
        // the in-SDK client hard-requires `extra.recentBlockhash` to build the
        // channel open, so a silent `None` would surface as a non-retryable
        // payment failure on a transient RPC hiccup.
        // Prefer the shared cache (refreshed out of band) to avoid a blocking
        // RPC round-trip per challenge; fall back to a direct fetch. Fetched
        // ONCE and stamped on every offered currency's requirement.
        let (blockhash, last_valid_block_height) =
            match self.blockhash_cache.as_ref().and_then(|c| c.get()) {
                Some(cached) => (cached.blockhash, cached.last_valid_block_height),
                None => {
                    let (blockhash, last_valid_block_height) = self
                        .rpc
                        .get_latest_blockhash_with_commitment(self.rpc.commitment())
                        .map_err(|e| {
                            Error::Rpc(format!("failed to fetch recent blockhash: {e}"))
                        })?;
                    (blockhash.to_string(), last_valid_block_height)
                }
            };

        // One `accepts[]` entry per offered currency (single-currency mode
        // yields exactly one, identical to the prior behaviour). Every entry
        // carries the SAME freshly-fetched blockhash + last-valid height.
        let currencies = self.offered_currencies();
        let mut accepts = Vec::with_capacity(currencies.len());
        for cc in currencies {
            let mut requirement = self.upto_requirements_for(cc, max_amount)?;
            requirement.extra.recent_blockhash = Some(blockhash.clone());
            requirement.extra.last_valid_block_height = Some(last_valid_block_height.to_string());
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
        // Cap the header before any base64 / JSON work, matching the MPP
        // parsers' 16 KiB `MAX_TOKEN_LEN`. Without it, an oversized credential
        // header drives proportionally larger decode + parse work.
        if header.len() > MAX_PAYMENT_SIGNATURE_HEADER_LEN {
            return Err(Error::InvalidPaymentRequired(format!(
                "PAYMENT-SIGNATURE header exceeds maximum length of {MAX_PAYMENT_SIGNATURE_HEADER_LEN} bytes"
            )));
        }
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

        verify_upto_payload(payload, &requirements, &self.operator(), now_unix())?;
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
        // The channel payee/merchant is the operator — the only key that can
        // sign `settle_and_finalize`. The beneficiary is paid via the bound
        // distribution split (validated below), never by being the payee.
        let expected_payee = self.operator;
        let expected_distribution = self.distribution()?;
        let channel_id = Pubkey::from_str(&payload.channel_id)
            .map_err(|e| Error::Other(format!("invalid channelId: {e}")))?;
        let payer = Pubkey::from_str(&payload.from)
            .map_err(|e| Error::Other(format!("invalid payer: {e}")))?;
        let max = payload.max_amount()?;

        // In-flight dedup: reject a concurrent request replaying the same
        // channel before its first settlement finalizes. The guard releases the
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
        // The channel must commit to exactly the distribution we expect (the
        // beneficiary at `10000 - operator_fee_bps`, or empty when no recipient
        // is configured), so settlement pays the right account and a client
        // cannot redirect funds. Bound on-chain via the distribution hash.
        validate_distribution_hash(&channel.distribution_hash, &expected_distribution)?;
        if pc::from_address(&channel.authorized_signer) != self.operator {
            return Err(Error::Other(
                "channel authorized_signer is not the operator".to_string(),
            ));
        }
        if pc::from_address(&channel.rent_payer) != self.operator {
            return Err(Error::Other(
                "channel rent_payer is not the operator".to_string(),
            ));
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
    /// open: `settle_and_finalize`, ATA setup, and `distribute`, then broadcast
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

        Ok(self.settlement_response(open, actual, signature.to_string()))
    }

    /// Build the settlement instructions (`settle_and_finalize`, ATA setup, and
    /// `distribute`) for the actual metered amount (`actual ≤ max`) against a
    /// verified open, signing the operator voucher but WITHOUT building,
    /// signing, or broadcasting a transaction.
    ///
    /// Shared by [`settle_actual`](Self::settle_actual) (which wraps them in a
    /// tx it signs + confirms) and the batched-settlement worker (which packs
    /// instructions from several channels into one operator-signed tx). The
    /// settle transaction is operator-signed only — the client's voucher
    /// authorization rides inside the `settle_and_finalize` instruction data,
    /// not as a transaction signature — so the worker can sign the envelope on
    /// the caller's behalf.
    pub async fn settlement_instructions(
        &self,
        open: &VerifiedUptoOpen,
        actual: u64,
    ) -> Result<Vec<Instruction>, Error> {
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

        // The channel payee is the operator (== the settle `merchant`); the
        // bound distribution routes the metered amount to the beneficiary split
        // and the operator keeps the remainder. Create the payee, treasury, and
        // each beneficiary ATA before distributing.
        let payee = open.payee;
        instructions.push(pc::build_create_associated_token_account_instruction(
            &self.operator,
            &payee,
            &open.mint,
            &open.token_program,
        ));
        instructions.push(pc::build_create_associated_token_account_instruction(
            &self.operator,
            &pc::treasury_owner(),
            &open.mint,
            &open.token_program,
        ));
        for entry in &open.distribution {
            instructions.push(pc::build_create_associated_token_account_instruction(
                &self.operator,
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

        let instructions = self.settlement_instructions(open, actual).await?;

        let operator = self.operator;
        let signer = self.config.operator_signer.clone();
        let rpc_url = self
            .config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&self.config.cluster).to_string());
        let handle = self
            .settlement_worker
            .get_or_init(|| async move {
                spawn(
                    SettlementConfig::new(operator, signer),
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

    /// Verify the client transaction is exactly the expected payment-channels
    /// `open` instruction before the operator co-signs it as fee payer.
    ///
    /// Without this, a malicious client could include any operator-authorized
    /// instruction (e.g. a SystemProgram transfer draining the operator) and the
    /// operator would blindly sign it. We require a single instruction, on the
    /// payment-channels program, with the `open` discriminator, whose accounts
    /// bind the expected payer / payee / mint / operator / channel.
    fn validate_open_transaction(
        &self,
        tx: &VersionedTransaction,
        payer: &Pubkey,
        payee: &Pubkey,
        mint: &Pubkey,
        token_program: &Pubkey,
        channel_id: &Pubkey,
    ) -> Result<(), Error> {
        let program_id = self.program_id()?;
        validate_open_instruction(
            tx,
            &program_id,
            // upto is gasless + delegated: the operator funds the rent and signs
            // the voucher, so it is both the rentPayer and the authorized_signer.
            &self.operator,
            &self.operator,
            payer,
            payee,
            mint,
            token_program,
            channel_id,
        )
    }

    /// Co-sign the fee-payer (operator) slot of a partially-signed transaction.
    async fn cosign_fee_payer(&self, tx: &mut VersionedTransaction) -> Result<(), Error> {
        cosign_operator_fee_payer(self.config.operator_signer.as_ref(), &self.operator, tx).await
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
/// `lastValidBlockHeight`, #2693) from a serialized requirements value so the
/// verify-time structural match ignores them. They are embedded into the 402
/// challenge and echoed back by the client in `accepted`, but the verify-time
/// rebuild omits them. Mirrors exact's `strip_blockhash_hints`.
fn strip_upto_blockhash_hints(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("recentBlockhash");
    }
    if let Some(extra) = value.get_mut("extra").and_then(|e| e.as_object_mut()) {
        extra.remove("recentBlockhash");
        extra.remove("lastValidBlockHeight");
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
/// cannot redirect funds. An empty `expected` means the operator keeps 100%.
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

/// Assert `tx` is exactly the expected payment-channels `open` instruction so the
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
    let instructions = tx.message.instructions();
    if instructions.len() != 1 {
        return Err(Error::Other(format!(
            "open transaction must contain exactly one instruction, found {}",
            instructions.len()
        )));
    }
    let ix = &instructions[0];
    let prog = keys
        .get(ix.program_id_index as usize)
        .ok_or_else(|| Error::Other("open instruction program id out of range".to_string()))?;
    if prog != program_id {
        return Err(Error::Other(
            "open transaction targets an unexpected program".to_string(),
        ));
    }
    if ix.data.first() != Some(&OPEN_INSTRUCTION_DISCRIMINATOR) {
        return Err(Error::Other(
            "open transaction is not a channel-open instruction".to_string(),
        ));
    }
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
        )
        .is_err());
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
        )
        .is_err());
    }

    #[test]
    fn validate_distribution_hash_binds_the_expected_split() {
        let recipient = Pubkey::new_unique();
        let split = vec![pc::Distribution {
            recipient,
            bps: 10_000,
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
    fn new_accepts_recipient_different_from_operator() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let engine = X402Upto::new(UptoConfig {
            payout: UptoPayout::Beneficiary {
                address: pc::pubkey_string(&recipient),
                operator_fee_bps: 0,
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
            operator_signer: std::sync::Arc::new(TestSigner(operator)),
        })
        .expect("distinct recipient should be accepted");
        let req = engine
            .upto_requirements("1.00")
            .expect("requirements should build");
        // Channel payee (pay_to) is the operator/settle-signer; the beneficiary
        // is paid via the bound distribution split, not by being the payee.
        // EVM-aligned wire: payTo = beneficiary, facilitator advertised separately.
        assert_eq!(req.pay_to, pc::pubkey_string(&recipient));
        assert_eq!(req.extra.facilitator_address, pc::pubkey_string(&operator));
        assert_eq!(req.extra.facilitator_fee, 0);
    }

    #[tokio::test]
    async fn cosign_rejects_operator_when_not_fee_payer() {
        let operator = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let ix = solana_instruction::Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![solana_instruction::AccountMeta::new_readonly(
                operator, true,
            )],
            data: vec![],
        };
        let mut tx = unsigned_tx_with_fee_payer(&[ix], fee_payer);

        let err = cosign_operator_fee_payer(&TestSigner(operator), &operator, &mut tx)
            .await
            .expect_err("operator signer must not be accepted outside fee-payer slot");
        assert!(err
            .to_string()
            .contains("fee payer must be the advertised operator"));
    }

    #[tokio::test]
    async fn cosign_accepts_operator_fee_payer() {
        let operator = Pubkey::new_unique();
        let ix = solana_instruction::Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![],
            data: vec![],
        };
        let mut tx = unsigned_tx_with_fee_payer(&[ix], operator);

        cosign_operator_fee_payer(&TestSigner(operator), &operator, &mut tx)
            .await
            .expect("operator fee-payer transaction should sign");
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
                operator_fee_bps: 0,
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
            operator_signer: std::sync::Arc::new(TestSigner(Pubkey::new_unique())),
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
        // Both carry the same fetched blockhash.
        assert_eq!(usdc.extra.recent_blockhash, pyusd.extra.recent_blockhash);
        assert!(usdc.extra.recent_blockhash.is_some());
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

    // ── PAYMENT-SIGNATURE header size cap ───────────────────────────────────

    #[test]
    fn parse_payment_signature_rejects_oversized_header() {
        // A PAYMENT-SIGNATURE header larger than the 16 KiB cap must be
        // rejected before the base64 decode + serde_json parse. The envelope
        // below is otherwise well-formed (its `accepted.scheme` is the upto
        // scheme), so without the size gate it decodes and parses fine — the
        // oversize is the ONLY reason it must be rejected.
        let engine = multi_currency_engine(&["USDC"]);
        let big_nonce = "1".repeat(24 * 1024);
        let envelope = serde_json::json!({
            "x402Version": X402_VERSION_V2,
            "accepted": { "scheme": UPTO_SCHEME },
            "payload": {
                "from": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                "maxAmount": "1000000",
                "expiresAt": 0,
                "validAfter": 0,
                "nonce": big_nonce,
                "channelId": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                "deposit": "1000000",
                "authorizedSigner": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
            }
        });
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&envelope).unwrap(),
        );
        assert!(header.len() > 16 * 1024, "header should exceed the cap");
        let err = engine
            .parse_payment_signature(&header)
            .expect_err("oversized header must be rejected");
        assert!(
            err.to_string().contains("exceeds maximum length"),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_payment_signature_accepts_at_max_header_size() {
        // A header of exactly 16 KiB must pass the size gate. Its contents are
        // not valid base64 JSON, so it still fails — but with a decode/parse
        // error, NOT the size error. This pins the boundary at exactly the cap.
        let engine = multi_currency_engine(&["USDC"]);
        let at_max = "A".repeat(16 * 1024);
        let err = engine
            .parse_payment_signature(&at_max)
            .expect_err("invalid payload still errors");
        assert!(
            !err.to_string().contains("exceeds maximum length"),
            "size gate must not fire at exactly the cap: {err:?}"
        );
    }

    // ── Bug 1 (settle `InvalidChannelPayee`, 0x6) — facilitator payee model ──
    //
    // `settle_and_finalize` requires its `merchant [signer]` account to equal
    // `channel.payee`. The only account the server can sign with is the
    // operator/authorized-signer, so the channel MUST be opened with
    // `payee = operator`. When the payout recipient differs from the operator
    // (the prod split-key config: recipient `Cs2z…`, KMS fee-payer `Bcdw…`),
    // the recipient is paid via a *bound distribution split*, NOT by being the
    // channel payee. Opening with `payee = recipient` is what reverts settle
    // with 0x6.

    /// Regression guard for the correct facilitator open: `payee = operator`
    /// with the real recipient carried as a 100% distribution split. The open
    /// must validate as operator-payee and must NOT validate as recipient-payee
    /// (so `merchant = operator` at settle always matches `channel.payee`).
    #[test]
    fn facilitator_open_binds_channel_payee_to_the_settle_signer() {
        let payer = Pubkey::new_unique();
        let operator = Pubkey::new_unique(); // signs settle_and_finalize (merchant)
        let recipient = Pubkey::new_unique(); // payout target — NOT a signer
        let mint = Pubkey::new_unique();
        assert_ne!(
            operator, recipient,
            "models recipient != operator (split keys)"
        );

        let params = OpenChannelParams {
            payer,
            rent_payer: operator,
            payee: operator, // channel.payee == the settle signer
            mint,
            authorized_signer: operator,
            salt: 7,
            deposit: 1_000_000,
            grace_period: 900,
            // Real recipient is paid via a bound 100% split, not as the payee.
            recipients: vec![crate::core::payment_channels::Distribution {
                recipient,
                bps: 10_000,
            }],
            token_program: token_program(),
            program_id: pc::default_program_id(),
        };
        let channel = derive_channel_addresses(&params).channel;
        let tx = unsigned_tx(&[build_open_instruction(&params)]);

        // verify_open binds the channel payee to the operator (== settle merchant).
        assert!(
            validate_open_instruction(
                &tx,
                &pc::default_program_id(),
                &operator,
                &operator,
                &payer,
                &operator,
                &mint,
                &token_program(),
                &channel,
            )
            .is_ok(),
            "facilitator open (payee = operator) must validate"
        );

        // The recipient is NOT the channel payee: validating the same open as
        // recipient-payee must fail — proving settle can't be authorized by a
        // recipient that never signs (the shape that caused 0x6 in prod).
        assert!(
            validate_open_instruction(
                &tx,
                &pc::default_program_id(),
                &operator,
                &operator,
                &payer,
                &recipient,
                &mint,
                &token_program(),
                &channel,
            )
            .is_err(),
            "channel payee must be the operator/signer, never the payout recipient"
        );
    }

    /// TDD spec for Bug 1's fix at the caller (challenge) layer: with
    /// recipient != operator, the advertised `pay_to` (→ channel payee) must be
    /// the operator/settle-signer, and the recipient is carried as a split.
    /// RED until the payee=operator + recipient-as-split wiring lands; remove
    /// `#[ignore]` then.
    #[test]
    fn upto_challenge_advertises_facilitator_and_beneficiary() {
        let engine = multi_currency_engine(&["USDC"]); // beneficiary != operator
        let req = engine
            .upto_requirements_for(&engine.config.currencies[0], "0.01")
            .expect("requirement builds");
        // EVM-aligned: facilitator (the settle signer) is advertised separately;
        // payTo is the beneficiary, distinct from the facilitator.
        assert_eq!(
            req.extra.facilitator_address,
            engine.operator(),
            "facilitator must be the operator/settle-signer"
        );
        assert_ne!(
            req.pay_to,
            engine.operator(),
            "payTo is the beneficiary, not the facilitator"
        );
        assert_eq!(req.extra.facilitator_fee, 0, "no fee configured");
    }

    // ── verify_open / settle_actual (broadcast + on-chain bind) ─────────────
    //
    // These exercise the RPC-touching `upto` paths against the in-process
    // Solana JSON-RPC mock: the challenge's blockhash fetch, the open broadcast +
    // channel read-back bind (with each mismatch branch), and the inline settle.

    use crate::generated::payment_channels::generated::accounts::Channel;
    use crate::generated::payment_channels::generated::types::SettlementWatermarks;
    use crate::x402::client::upto::build_upto_header;
    use crate::x402::server::mock_rpc::MockRpc;
    use ed25519_dalek::SigningKey as DalekSigningKey;
    use solana_keychain::memory::MemorySigner;

    const UPTO_FAR_FUTURE: i64 = 4_102_444_800; // 2100-01-01

    fn upto_memory_signer(seed: u8) -> MemorySigner {
        let sk = DalekSigningKey::from_bytes(&[seed; 32]);
        MemorySigner::from_bytes(&sk.to_keypair_bytes()).unwrap()
    }

    fn program_id_b58() -> String {
        pc::pubkey_string(&pc::default_program_id())
    }

    /// A handler whose RPC points at `rpc_url`, with the given operator signer
    /// (which co-signs the open and signs the settle) and payout config.
    fn upto_handler_with_rpc(
        rpc_url: String,
        operator_signer: Arc<dyn SolanaSigner>,
        payout: UptoPayout,
    ) -> X402Upto {
        X402Upto::new(UptoConfig {
            payout,
            currencies: vec![CurrencyConfig {
                currency: "USDC".to_string(),
                decimals: 6,
                token_program: None,
            }],
            cluster: "devnet".to_string(),
            rpc_url: Some(rpc_url),
            resource: "/usage".to_string(),
            description: None,
            max_timeout_seconds: 300,
            program_id: None,
            operator_signer,
        })
        .unwrap()
    }

    /// Borsh-serialized on-chain `Channel` account. Every bind-relevant field is
    /// a parameter so a test can flip one to hit a specific mismatch branch.
    #[allow(clippy::too_many_arguments)]
    fn upto_channel_bytes(
        status: u8,
        deposit: u64,
        payer: &Pubkey,
        payee: &Pubkey,
        authorized_signer: &Pubkey,
        rent_payer: &Pubkey,
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
            grace_period: 900,
            distribution_hash,
            payer: pc::to_address(payer),
            payee: pc::to_address(payee),
            authorized_signer: pc::to_address(authorized_signer),
            mint: pc::to_address(mint),
            rent_payer: pc::to_address(rent_payer),
        };
        borsh::to_vec(&channel).unwrap()
    }

    /// End-to-end `upto` open fixture: a mock RPC, a client-built credential
    /// header, and the derived channel/operator/payer keys.
    struct UptoFixture {
        mock: MockRpc,
        handler: X402Upto,
        header: String,
        channel_id: Pubkey,
        operator: Pubkey,
        payer: Pubkey,
        mint: Pubkey,
        max_amount: String,
    }

    async fn upto_fixture(payout: UptoPayout) -> UptoFixture {
        let mock = MockRpc::start();
        let operator_signer = upto_memory_signer(50);
        let operator = operator_signer.pubkey();
        let payer_signer = upto_memory_signer(51);
        let handler = upto_handler_with_rpc(mock.url(), Arc::new(operator_signer), payout);

        let max_amount = "1.00".to_string();
        let mut requirements = handler.upto_requirements(&max_amount).unwrap();
        requirements.extra.recent_blockhash = Some("11111111111111111111111111111111".to_string());
        let header = build_upto_header(&payer_signer, &requirements, UPTO_FAR_FUTURE, "nonce-1")
            .await
            .unwrap();
        // Re-derive the channel PDA the client used from the credential.
        let envelope = handler.parse_payment_signature(&header).unwrap();
        let channel_id = Pubkey::from_str(&envelope.payload.channel_id).unwrap();
        let mint = handler.mint_for(handler.primary_currency()).unwrap();

        UptoFixture {
            mock,
            handler,
            header,
            channel_id,
            operator,
            payer: payer_signer.pubkey(),
            mint,
            max_amount,
        }
    }

    /// Bind an on-chain channel account matching the fixture's expectations
    /// (operator-payee model, empty distribution, deposit == max).
    fn upto_bind_matching_channel(f: &UptoFixture, distribution: &[pc::Distribution]) {
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            upto_channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000, // deposit == max (1.00 @ 6dp)
                &f.payer,
                &f.operator, // payee == operator
                &f.operator, // authorized_signer == operator
                &f.operator, // rent_payer == operator
                &f.mint,
                pc::distribution_hash(distribution),
            ),
            &program_id_b58(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upto_challenge_fetches_blockhash() {
        let mock = MockRpc::start();
        let handler = upto_handler_with_rpc(
            mock.url(),
            Arc::new(upto_memory_signer(52)),
            UptoPayout::OperatorKeepsAll,
        );
        let envelope = handler.upto("1.00").unwrap();
        assert_eq!(envelope.accepts.len(), 1);
        assert_eq!(
            envelope.accepts[0].extra.recent_blockhash.as_deref(),
            Some("11111111111111111111111111111111")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upto_challenge_surfaces_blockhash_error() {
        let mock = MockRpc::start();
        mock.fail_blockhash("node unhealthy");
        let handler = upto_handler_with_rpc(
            mock.url(),
            Arc::new(upto_memory_signer(53)),
            UptoPayout::OperatorKeepsAll,
        );
        let err = handler.upto("1.00").unwrap_err();
        assert!(matches!(err, Error::Rpc(_)), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_binds_confirmed_channel() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        upto_bind_matching_channel(&f, &[]);
        let open = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap();
        assert_eq!(open.channel_id, f.channel_id);
        assert_eq!(open.payer, f.payer);
        assert_eq!(open.deposit, 1_000_000);
        assert_eq!(open.max_amount, 1_000_000);
        assert_eq!(open.payee, f.operator);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_rejects_channel_not_open() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            upto_channel_bytes(
                2, // not Open
                1_000_000,
                &f.payer,
                &f.operator,
                &f.operator,
                &f.operator,
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not open"), "got: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_rejects_mint_mismatch() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            upto_channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                &f.payer,
                &f.operator,
                &f.operator,
                &f.operator,
                &Pubkey::new_unique(), // wrong mint
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::MintMismatch { .. }), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_rejects_payee_mismatch() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            upto_channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                &f.payer,
                &Pubkey::new_unique(), // wrong payee
                &f.operator,
                &f.operator,
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::RecipientMismatch { .. }),
            "got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_rejects_distribution_hash_mismatch() {
        // Operator-keeps-all expects an empty distribution; bind a non-empty one.
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        upto_bind_matching_channel(
            &f,
            &[pc::Distribution {
                recipient: Pubkey::new_unique(),
                bps: 10_000,
            }],
        );
        let err = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("distribution does not match"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_rejects_authorized_signer_mismatch() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            upto_channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                &f.payer,
                &f.operator,
                &Pubkey::new_unique(), // wrong authorized_signer
                &f.operator,
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("authorized_signer is not the operator"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_rejects_rent_payer_mismatch() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            upto_channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                &f.payer,
                &f.operator,
                &f.operator,
                &Pubkey::new_unique(), // wrong rent_payer
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("rent_payer is not the operator"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_rejects_deposit_not_equal_to_max() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            upto_channel_bytes(
                CHANNEL_STATUS_OPEN,
                999_999, // deposit != max (1_000_000)
                &f.payer,
                &f.operator,
                &f.operator,
                &f.operator,
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("authorized maximum"), "got: {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_rejects_payer_mismatch() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        f.mock.set_account(
            &pc::pubkey_string(&f.channel_id),
            upto_channel_bytes(
                CHANNEL_STATUS_OPEN,
                1_000_000,
                &Pubkey::new_unique(), // wrong payer
                &f.operator,
                &f.operator,
                &f.operator,
                &f.mint,
                pc::distribution_hash(&[]),
            ),
            &program_id_b58(),
        );
        let err = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("does not match payload.from"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_surfaces_broadcast_error() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        f.mock.fail_send("preflight failed");
        let err = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Rpc(_)), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_surfaces_channel_fetch_error() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        f.mock.fail_account("account fetch unavailable");
        let err = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Rpc(_)), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_actual_broadcasts_settlement() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        upto_bind_matching_channel(&f, &[]);
        let open = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap();
        // Settle a metered amount below the ceiling.
        let response = f.handler.settle_actual(&open, 250_000).await.unwrap();
        assert!(response.success);
        assert_eq!(response.amount, "250000");
        assert!(!response.transaction.is_empty());
        assert_eq!(
            response.payer.as_deref(),
            Some(pc::pubkey_string(&f.payer).as_str())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_actual_zero_amount_finalizes_without_voucher() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        upto_bind_matching_channel(&f, &[]);
        let open = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap();
        // actual == 0 → settle_and_finalize with no voucher (full refund path).
        let response = f.handler.settle_actual(&open, 0).await.unwrap();
        assert!(response.success);
        assert_eq!(response.amount, "0");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_actual_rejects_amount_above_ceiling() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        upto_bind_matching_channel(&f, &[]);
        let open = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap();
        // actual > max ceiling → rejected before broadcast.
        let err = f.handler.settle_actual(&open, 2_000_000).await.unwrap_err();
        assert!(!format!("{err:?}").is_empty());
        // Confirm it's an error (ceiling breach), not a broadcast.
        assert!(f.handler.settle_actual(&open, 2_000_000).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_actual_surfaces_broadcast_error() {
        let f = upto_fixture(UptoPayout::OperatorKeepsAll).await;
        upto_bind_matching_channel(&f, &[]);
        let open = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap();
        // Now make the settle broadcast fail.
        f.mock.fail_send("settle preflight failed");
        let err = f.handler.settle_actual(&open, 250_000).await.unwrap_err();
        assert!(matches!(err, Error::Rpc(_)), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_open_with_beneficiary_binds_distribution_split() {
        // Beneficiary payout: the open must commit to a `10000 - fee` split.
        let beneficiary = Pubkey::new_unique();
        let payout = UptoPayout::Beneficiary {
            address: pc::pubkey_string(&beneficiary),
            operator_fee_bps: 250,
        };
        let f = upto_fixture(payout).await;
        let distribution = vec![pc::Distribution {
            recipient: beneficiary,
            bps: 10_000 - 250,
        }];
        upto_bind_matching_channel(&f, &distribution);
        let open = f
            .handler
            .verify_open(&f.header, &f.max_amount)
            .await
            .unwrap();
        assert_eq!(open.distribution, distribution);
        // And settle distributes to that beneficiary split.
        let response = f.handler.settle_actual(&open, 100_000).await.unwrap();
        assert!(response.success);
    }
}
