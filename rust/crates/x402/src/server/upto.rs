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
//!    amount and submits `settle_and_finalize` + ATA setup + `distribute`, refunding
//!    `deposit − actual` to the payer.

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

/// `Open` instruction discriminator in the generated payment-channels client
/// (`payment_channels_client::generated::instructions::OPEN_DISCRIMINATOR`).
const OPEN_INSTRUCTION_DISCRIMINATOR: u8 = 1;

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
    /// Operator signer - co-signs the open as fee payer and signs settlement
    /// vouchers + transactions. Its pubkey is the advertised facilitator.
    pub operator_signer: Arc<dyn SolanaSigner>,
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
            // `confirmed`, not the default `finalized`: the channel open + voucher
            // settlement shouldn't block ~13s on finalization.
            rpc: Arc::new(RpcClient::new_with_commitment(
                rpc_url,
                solana_commitment_config::CommitmentConfig::confirmed(),
            )),
            config,
            operator,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
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
    /// units using the configured decimals - same convention as the `exact`
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
                fee_payer: self.operator(),
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
        let mut requirement = self.upto_requirements(max_amount)?;
        // Fail loudly (retryable) rather than issuing a 402 with no blockhash:
        // the in-SDK client hard-requires `extra.recentBlockhash` to build the
        // channel open, so a silent `None` would surface as a non-retryable
        // payment failure on a transient RPC hiccup.
        let (blockhash, last_valid_block_height) = self
            .rpc
            .get_latest_blockhash_with_commitment(self.rpc.commitment())
            .map_err(|e| Error::Rpc(format!("failed to fetch recent blockhash: {e}")))?;
        requirement.extra.recent_blockhash = Some(blockhash.to_string());
        requirement.extra.last_valid_block_height = Some(last_valid_block_height.to_string());
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
        let requirements = self.upto_requirements(max_amount)?;
        let payload = &envelope.payload;

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
        let expected_mint = self.mint()?;
        let token_program = self.token_program()?;
        let expected_payee = Pubkey::from_str(&self.config.recipient)
            .map_err(|e| Error::Other(format!("invalid recipient: {e}")))?;
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
            Error::Other("payment-channel profile requires openTransaction (pull)".to_string())
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
        // This first slice does not advertise split recipients, so bind the
        // confirmed channel to the empty-recipient distribution before serving.
        validate_empty_recipient_distribution_hash(&channel.distribution_hash)?;
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
            _in_flight: in_flight,
        })
    }

    /// Settle the actual metered amount (`actual ≤ max`) against a verified
    /// open: `settle_and_finalize`, ATA setup, and `distribute`.
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

        let payee = Pubkey::from_str(&self.config.recipient)
            .map_err(|e| Error::Other(format!("invalid recipient: {e}")))?;
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
        instructions.push(pc::build_distribute_instruction(
            &open.channel_id,
            &open.payer,
            &open.rent_payer,
            &payee,
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

fn validate_empty_recipient_distribution_hash(distribution_hash: &[u8; 32]) -> Result<(), Error> {
    let expected = pc::distribution_hash(&[]);
    if distribution_hash != &expected {
        return Err(Error::Other(
            "x402 upto currently supports only empty-recipient payment channels".to_string(),
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
    use async_trait::async_trait;
    use solana_keychain::{SignTransactionResult, SignerError};
    use solana_pay_core::payment_channels::{
        build_open_instruction, derive_channel_addresses, OpenChannelParams,
    };
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
    fn rejects_non_empty_recipient_distribution_hash() {
        let empty = pc::distribution_hash(&[]);
        assert!(validate_empty_recipient_distribution_hash(&empty).is_ok());

        let non_empty = pc::distribution_hash(&[pc::Distribution {
            recipient: Pubkey::new_unique(),
            bps: 10_000,
        }]);
        assert!(validate_empty_recipient_distribution_hash(&non_empty).is_err());
    }

    #[test]
    fn new_accepts_recipient_different_from_operator() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let engine = X402Upto::new(UptoConfig {
            recipient: pc::pubkey_string(&recipient),
            currency: "USDC".to_string(),
            decimals: 6,
            cluster: "localnet".to_string(),
            rpc_url: Some("http://127.0.0.1:8899".to_string()),
            resource: "/usage".to_string(),
            description: None,
            max_timeout_seconds: 300,
            token_program: None,
            program_id: None,
            operator_signer: std::sync::Arc::new(TestSigner(operator)),
        })
        .expect("distinct recipient should be accepted");
        let req = engine
            .upto_requirements("1.00")
            .expect("requirements should build");
        assert_eq!(req.pay_to, pc::pubkey_string(&recipient));
        assert_eq!(req.extra.fee_payer, pc::pubkey_string(&operator));
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
}
