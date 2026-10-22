//! Session (draft-solana-session-00) server and client vectors: what `pkc
//! fill` runs to realize a case and what the build judge runs against an
//! SDK's build.
//!
//! Vector input (documented in `harness/src/conformance/schema.ts`
//! `VectorInput`):
//!
//! - verify: `sessionServerVerify` = `{ server, challenge?, channel?,
//!   credential }`. `server` configures the verifying session server,
//!   `challenge` (`{ id, recentBlockhash, recentSlot }`) is the challenge an
//!   `open` answers, `channel` is the server's stored per-channel state (the
//!   spec's "Per-Channel State" fields) a `voucher`, `topUp` or `close`
//!   acts on, and `credential` is the client's session action exactly as it
//!   travels in the credential payload. `sessionServerFeePayerSecretKey`
//!   is the sponsor's key when `server.feePayer` is set. Nothing in the input
//!   is a precomputed verdict: the testee parses `credential` with its SDK's
//!   wire types and hands it to the SDK's server.
//! - build: `sessionOpenBuild` = `{ request, salt, server, challenge }`:
//!   `request` is the challenge's `SessionRequest`, `salt` the channel salt
//!   the client's builder takes; `server` / `challenge` are for the judge
//!   only. `signerSecretKey` is the payer, `sessionSignerSecretKey` the
//!   voucher key the client authorizes.
//!
//! The kit runs through its public session API: `SessionServer`'s
//! `verify_voucher_for_amount` and `process_close`, and the
//! `mpp::server::session::testkit` hooks `verify_open_pre_broadcast` /
//! `verify_topup_pre_broadcast` (every check `process_open` /
//! `process_topup` makes before they touch the network).

use std::str::FromStr;

use serde_json::{json, Map, Value};
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_pay_kit::core::payment_channels as pc;
use solana_pay_kit::core::store::{
    ChannelState, ChannelStore, MemoryChannelStore, CHANNEL_STATE_SCHEMA_VERSION,
};
use solana_pay_kit::core::tx::{ComputeBudget, TxV1Mode, TxVersion};
use solana_pay_kit::mpp::client::session::{
    create_payment_channel_session_opener, derive_payment_channel_open,
    DerivePaymentChannelOpenParams, PaymentChannelOpenOptions, PaymentChannelSessionOpenOptions,
};
use solana_pay_kit::mpp::protocol::intents::session::{
    SessionAction, SessionAuthentication, SessionRequest, VoucherData,
};
use solana_pay_kit::mpp::server::session::{
    testkit, SessionConfig, SessionOpenContext, SessionServer, Split, VoucherSigner,
};
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pubkey::Pubkey;

use super::{Observed, Output};
use crate::case::{Mode, RejectCode};
use crate::keys::{self, MINT, TOKEN_PROGRAM};
use crate::mutate::Mutation;
use crate::run::judge::Failure;
use crate::run::vectors::Vector;
use crate::tx::{decode_b64, decompile, encode_b64, recompile, sign_slots};

/// The result field an accepted session build carries: the client's `open`
/// action as JSON text.
pub const BUILD_ARTIFACT: &str = "sessionCredential";

// ── fixture keys and constants ─────────────────────────────────────────────

/// The voucher key a client-mode client authorizes (never signs the open).
pub const SESSION_SIGNER_SEED: [u8; 32] = super::session_open::SESSION_SIGNER_SEED;
/// The operator: the sponsor and, in operator mode, the voucher signer.
pub const OPERATOR_SEED: [u8; 32] = keys::X402_OFFER_FEE_PAYER_SEED;
/// A key that is neither payer, operator nor voucher signer.
pub const STRANGER_SEED: [u8; 32] = [21; 32];
/// The challenge's `recentBlockhash`.
pub const BLOCKHASH: &str = super::session_open::BLOCKHASH;
/// Another blockhash, never challenged.
pub const OTHER_BLOCKHASH: &str = "9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F";
/// The challenge's `recentSlot`.
pub const RECENT_SLOT: u64 = super::session_open::RECENT_SLOT;
/// `OPEN_SLOT_WINDOW` (draft-solana-session-00 §Channel Closure).
pub const OPEN_SLOT_WINDOW: u64 = 1_500;
/// The channel salt every client picks (deterministic vectors).
pub const SALT: u64 = super::session_open::SALT;
/// The id of the challenge every open answers.
pub const CHALLENGE_ID: &str = "c_session_conformance_0001";
/// The default voucher expiry (2100-01-01), far past any clock.
pub const FAR_EXPIRY: i64 = 4_102_444_800;
/// An expiry long past (2001-09-09).
pub const PAST_EXPIRY: i64 = 1_000_000_000;

pub fn key(seed: [u8; 32]) -> Pubkey {
    keys::pubkey_of_seed(seed)
}

pub fn client() -> Pubkey {
    key(keys::CLIENT_SEED)
}

pub fn operator() -> Pubkey {
    key(OPERATOR_SEED)
}

pub fn session_signer() -> Pubkey {
    key(SESSION_SIGNER_SEED)
}

pub fn stranger() -> Pubkey {
    key(STRANGER_SEED)
}

/// An address that is not an Ed25519 curve point (a PDA).
pub fn off_curve() -> Pubkey {
    Pubkey::find_program_address(&[b"not-a-signer"], &pc::default_program_id()).0
}

// ── the verifying server ───────────────────────────────────────────────────

/// A session server's configuration (`sessionServerVerify.server`).
#[derive(Debug, Clone, PartialEq)]
pub struct Server {
    /// `client` or `operator`.
    pub voucher_signer: &'static str,
    /// The operator sponsors fees and rent (`feePayer: true`).
    pub sponsored: bool,
    pub currency: &'static str,
    pub token_program: Option<&'static str>,
    pub recipient: &'static str,
    pub amount: u64,
    pub minimum_deposit: Option<u64>,
    pub suggested_deposit: Option<u64>,
    pub grace_period_seconds: u32,
    pub idle_timeout_options: Option<Vec<u32>>,
    pub splits: Vec<(&'static str, u16)>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            voucher_signer: "client",
            sponsored: false,
            currency: "USDC",
            token_program: None,
            recipient: keys::X402_PAY_TO,
            amount: 25,
            minimum_deposit: Some(100),
            suggested_deposit: Some(1_000),
            grace_period_seconds: 900,
            idle_timeout_options: None,
            splits: vec![],
        }
    }
}

impl Server {
    pub fn json(&self) -> Value {
        let mut out = json!({
            "operator": operator().to_string(),
            "recipient": self.recipient,
            "currency": self.currency,
            "decimals": 6,
            "network": "devnet",
            "amount": self.amount.to_string(),
            "gracePeriodSeconds": self.grace_period_seconds,
            "idleTimeoutSeconds": 300,
            "voucherSigner": self.voucher_signer,
        });
        if let Some(min) = self.minimum_deposit {
            out["minimumDeposit"] = json!(min.to_string());
        }
        if let Some(suggested) = self.suggested_deposit {
            out["suggestedDeposit"] = json!(suggested.to_string());
        }
        if self.sponsored {
            out["feePayer"] = json!(operator().to_string());
        }
        if let Some(options) = &self.idle_timeout_options {
            out["idleTimeoutOptionsSeconds"] = json!(options);
        }
        if !self.splits.is_empty() {
            out["distributionSplits"] = json!(self
                .splits
                .iter()
                .map(|(recipient, bps)| json!({ "recipient": recipient, "shareBps": bps }))
                .collect::<Vec<_>>());
        }
        if let Some(program) = self.token_program {
            out["tokenProgram"] = json!(program);
        }
        out
    }

    /// The mint the server's currency resolves to.
    pub fn mint(&self) -> Pubkey {
        keys::pubkey(match self.currency {
            "USDC" => MINT,
            other => other,
        })
    }

    pub fn token_program(&self) -> Pubkey {
        keys::pubkey(self.token_program.unwrap_or(TOKEN_PROGRAM))
    }
}

fn u64_field(value: &Value, key: &str) -> Result<Option<u64>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => s.parse().map(Some).map_err(|_| format!("invalid {key}")),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| format!("invalid {key}")),
    }
}

fn signer_from(input: &Value, key: &str) -> Result<MemorySigner, String> {
    let bytes: Vec<u8> = input
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("input.{key} missing"))?
        .iter()
        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<_>>()
        .ok_or_else(|| format!("input.{key} must be bytes"))?;
    MemorySigner::from_bytes(&bytes).map_err(|e| format!("invalid {key}: {e}"))
}

/// The kit session server `server` describes, over `store`. Mirrored in the
/// Rust testee (`vector_runner/session.rs`).
pub fn kit_server(
    server: &Value,
    fee_payer: Option<MemorySigner>,
    store: MemoryChannelStore,
) -> Result<SessionServer<MemoryChannelStore>, String> {
    let text = |key: &str| {
        server
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("server.{key} missing"))
    };
    let voucher_signer = match server.get("voucherSigner").and_then(Value::as_str) {
        None | Some("client") => VoucherSigner::Client,
        Some("operator") => VoucherSigner::Operator,
        Some(other) => return Err(format!("invalid server.voucherSigner {other:?}")),
    };
    let splits = match server.get("distributionSplits") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(entries)) => entries
            .iter()
            .map(|entry| {
                Ok(Split {
                    recipient: Pubkey::from_str(entry["recipient"].as_str().unwrap_or_default())
                        .map_err(|e| format!("invalid split recipient: {e}"))?,
                    bps: entry["shareBps"]
                        .as_u64()
                        .and_then(|b| u16::try_from(b).ok())
                        .ok_or("invalid split shareBps")?,
                })
            })
            .collect::<Result<_, String>>()?,
        Some(_) => return Err("server.distributionSplits must be an array".into()),
    };
    let token_program = match server.get("tokenProgram").and_then(Value::as_str) {
        None => None,
        Some(program) => {
            Some(Pubkey::from_str(program).map_err(|e| format!("invalid tokenProgram: {e}"))?)
        }
    };
    let idle_options = match server.get("idleTimeoutOptionsSeconds") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            serde_json::from_value::<Vec<u32>>(v.clone())
                .map_err(|e| format!("invalid idleTimeoutOptionsSeconds: {e}"))?,
        ),
    };
    let config = SessionConfig {
        operator: text("operator")?,
        recipient: text("recipient")?,
        currency: text("currency")?,
        network: text("network")?,
        decimals: u8::try_from(u64_field(server, "decimals")?.ok_or("decimals missing")?)
            .map_err(|_| "invalid decimals")?,
        amount: u64_field(server, "amount")?.ok_or("amount missing")?,
        minimum_deposit: u64_field(server, "minimumDeposit")?,
        suggested_deposit: u64_field(server, "suggestedDeposit")?,
        grace_period_seconds: u32::try_from(
            u64_field(server, "gracePeriodSeconds")?.ok_or("gracePeriodSeconds missing")?,
        )
        .map_err(|_| "invalid gracePeriodSeconds")?,
        idle_timeout_seconds: u32::try_from(
            u64_field(server, "idleTimeoutSeconds")?.ok_or("idleTimeoutSeconds missing")?,
        )
        .map_err(|_| "invalid idleTimeoutSeconds")?,
        idle_timeout_options_seconds: idle_options,
        voucher_signer,
        splits,
        token_program,
        fee_payer_signer: match (server.get("feePayer").and_then(Value::as_str), fee_payer) {
            (None, _) => None,
            (Some(expected), Some(signer)) => {
                use solana_pay_kit::solana_keychain::SolanaSigner;
                if signer.pubkey().to_string() != expected {
                    return Err("sessionServerFeePayerSecretKey is not server.feePayer".into());
                }
                Some(std::sync::Arc::new(signer))
            }
            (Some(_), None) => return Err("server.feePayer without its secret key".into()),
        },
        ..SessionConfig::default()
    };
    let mut versions: Vec<TxVersion> = match server.get("transactionVersions") {
        None | Some(Value::Null) => vec![TxVersion::V0],
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|e| format!("invalid transactionVersions: {e}"))?,
    };
    versions.sort();
    versions.dedup();
    let mode = match versions.as_slice() {
        [TxVersion::V0] => TxV1Mode::Off,
        [TxVersion::V0, TxVersion::V1] => TxV1Mode::On,
        other => return Err(format!("the kit cannot accept exactly {other:?}")),
    };
    Ok(SessionServer::new(config, store).with_tx_v1(mode))
}

// ── the server's stored channel ────────────────────────────────────────────

/// The server's per-channel state (`sessionServerVerify.channel`), named as
/// in the spec's "Per-Channel State" table.
#[derive(Debug, Clone, PartialEq)]
pub struct Channel {
    /// The open the channel's address derives from.
    pub open: OpenParams,
    pub voucher_signer: &'static str,
    pub escrowed: u64,
    pub accepted: u64,
    pub spent: u64,
    pub settled: u64,
    /// The highest accepted voucher: `(cumulative, expiresAt)`, signed by
    /// the channel's authorized signer.
    pub highest: Option<(u64, Option<i64>)>,
    pub closure_started_at: Option<u64>,
    /// `status: "closed"` (sealed).
    pub closed: bool,
    /// Operator mode: the bearer proof bound at open.
    pub bound_proof: bool,
}

impl Channel {
    pub fn client(accepted: u64) -> Self {
        Self {
            open: OpenParams::client(&Server::default()),
            voucher_signer: "client",
            escrowed: 1_000,
            accepted,
            spent: accepted,
            settled: 0,
            highest: (accepted > 0).then_some((accepted, Some(FAR_EXPIRY))),
            closure_started_at: None,
            closed: false,
            bound_proof: false,
        }
    }

    pub fn operator(accepted: u64) -> Self {
        let server = Server {
            voucher_signer: "operator",
            ..Server::default()
        };
        Self {
            open: OpenParams {
                authorized_signer: OPERATOR_SEED,
                ..OpenParams::client(&server)
            },
            voucher_signer: "operator",
            highest: (accepted > 0).then_some((accepted, None)),
            bound_proof: true,
            ..Self::client(accepted)
        }
    }

    pub fn id(&self) -> Pubkey {
        self.open.channel()
    }

    pub fn proof(&self) -> Result<SessionAuthentication, String> {
        SessionAuthentication::sign(
            CHALLENGE_ID,
            &self.id().to_string(),
            &keys::signing_key(keys::CLIENT_SEED),
        )
        .map_err(|e| e.to_string())
    }

    pub fn json(&self) -> Result<Value, String> {
        let mut out = json!({
            "channelId": self.id().to_string(),
            "openSlot": self.open.open_slot.to_string(),
            "status": if self.closed { "closed" } else { "open" },
            "payer": client().to_string(),
            "rentPayer": self.open.rent_payer.to_string(),
            "voucherSigner": self.voucher_signer,
            "authorizedSigner": key(self.open.authorized_signer).to_string(),
            "escrowedAmount": self.escrowed.to_string(),
            "acceptedCumulative": self.accepted.to_string(),
            "spentAmount": self.spent.to_string(),
            "settledOnChain": self.settled.to_string(),
            "idleTimeoutSeconds": 300,
        });
        if let Some((cumulative, expires_at)) = self.highest {
            out["highestVoucher"] = signed_voucher(
                &self.id(),
                cumulative,
                expires_at,
                self.open.authorized_signer,
            )?;
        }
        if let Some(at) = self.closure_started_at {
            out["closureStartedAt"] = json!(at);
        }
        // Every opened channel records its opening challenge; an
        // operator-signed one also binds the payer's proof.
        out["openingChallengeId"] = json!(CHALLENGE_ID);
        if self.bound_proof {
            out["authentication"] =
                serde_json::to_value(self.proof()?).map_err(|e| e.to_string())?;
        }
        Ok(out)
    }
}

/// `channel` JSON to the kit's stored state. Mirrored in the Rust testee.
pub fn stored_channel(channel: &Value) -> Result<ChannelState, String> {
    let text = |key: &str| {
        channel
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("channel.{key} missing"))
    };
    let number = |key: &str| -> Result<u64, String> {
        u64_field(channel, key)?.ok_or_else(|| format!("channel.{key} missing"))
    };
    let highest = channel.get("highestVoucher");
    let proof = channel.get("authentication").filter(|v| !v.is_null());
    Ok(ChannelState {
        channel_id: text("channelId")?,
        authorized_signer: text("authorizedSigner")?,
        deposit: number("escrowedAmount")?,
        cumulative: number("acceptedCumulative")?,
        sealed: text("status")? == "closed",
        highest_voucher_signature: highest
            .and_then(|v| v.get("signature"))
            .and_then(Value::as_str)
            .map(str::to_string),
        highest_voucher_expires_at: highest.map(|v| {
            v.pointer("/voucher/expiresAt")
                .and_then(Value::as_i64)
                .unwrap_or(0)
        }),
        close_requested_at: channel.get("closureStartedAt").and_then(Value::as_u64),
        final_cumulative: None,
        open_slot: u64_field(channel, "openSlot")?,
        payer: text("payer")?,
        rent_payer: text("rentPayer")?,
        opening_challenge_id: channel
            .get("openingChallengeId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // The proof bound at open, stored as the kit's server stores it.
        authentication: proof
            .map(|v| {
                serde_json::from_value::<SessionAuthentication>(v.clone())
                    .and_then(|a| serde_json::to_string(&a))
                    .map_err(|e| format!("invalid channel.authentication: {e}"))
            })
            .transpose()?,
        voucher_signer: text("voucherSigner")?,
        idle_timeout_seconds: u64_field(channel, "idleTimeoutSeconds")?
            .map(|s| u32::try_from(s).map_err(|_| "invalid idleTimeoutSeconds"))
            .transpose()?,
        last_activity_at: 0,
        spent_amount: number("spentAmount")?,
        settled_on_chain: number("settledOnChain")?,
        distributed_on_chain: 0,
        processed_uses: vec![],
        processed_topup_signatures: vec![],
        next_delivery_sequence: 0,
        pending_deliveries: vec![],
        committed_deliveries: Default::default(),
        pending_setup: None,
        onchain_checked_at: 0,
        lifecycle: None,
        schema_version: CHANNEL_STATE_SCHEMA_VERSION,
        extra: Default::default(),
    })
}

/// A signed voucher JSON (`SignedVoucher` on the wire).
pub fn signed_voucher(
    channel: &Pubkey,
    cumulative: u64,
    expires_at: Option<i64>,
    signer_seed: [u8; 32],
) -> Result<Value, String> {
    use ed25519_dalek::Signer;
    let data = VoucherData {
        channel_id: channel.to_string(),
        cumulative_amount: cumulative.to_string(),
        expires_at,
    };
    let message = data.message_bytes().map_err(|e| e.to_string())?;
    let signature = keys::signing_key(signer_seed).sign(&message);
    let mut voucher = json!({
        "channelId": channel.to_string(),
        "cumulativeAmount": cumulative.to_string(),
    });
    if let Some(at) = expires_at {
        voucher["expiresAt"] = json!(at);
    }
    Ok(json!({
        "voucher": voucher,
        "signer": key(signer_seed).to_string(),
        "signature": bs58::encode(signature.to_bytes()).into_string(),
        "signatureType": "ed25519",
    }))
}

// ── the open the client builds ─────────────────────────────────────────────

/// The open parameters a channel derives from.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenParams {
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub authorized_signer: [u8; 32],
    pub rent_payer: Pubkey,
    pub open_slot: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub recipients: Vec<(Pubkey, u16)>,
}

impl OpenParams {
    pub fn client(server: &Server) -> Self {
        Self {
            payee: keys::pubkey(server.recipient),
            mint: server.mint(),
            token_program: server.token_program(),
            authorized_signer: SESSION_SIGNER_SEED,
            rent_payer: if server.sponsored {
                operator()
            } else {
                client()
            },
            open_slot: RECENT_SLOT,
            deposit: server.suggested_deposit.unwrap_or(1_000),
            grace_period: server.grace_period_seconds,
            recipients: server
                .splits
                .iter()
                .map(|(r, b)| (keys::pubkey(r), *b))
                .collect(),
        }
    }

    pub fn params(&self) -> pc::OpenChannelParams {
        pc::OpenChannelParams {
            payer: client(),
            rent_payer: self.rent_payer,
            payee: self.payee,
            mint: self.mint,
            authorized_signer: key(self.authorized_signer),
            salt: SALT,
            open_slot: self.open_slot,
            deposit: self.deposit,
            grace_period: self.grace_period,
            recipients: self
                .recipients
                .iter()
                .map(|(recipient, bps)| pc::Distribution {
                    recipient: *recipient,
                    bps: *bps,
                })
                .collect(),
            token_program: self.token_program,
            program_id: pc::default_program_id(),
        }
    }

    pub fn channel(&self) -> Pubkey {
        pc::derive_channel_addresses(&self.params()).channel
    }
}

/// Who the client authorizes to sign vouchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorized {
    /// A delegated session key.
    SessionKey,
    /// The payer itself.
    Payer,
}

/// How the client builds its `open` (the kit client's options).
#[derive(Debug, Clone, PartialEq)]
pub struct OpenBuild {
    /// The challenge's `recentSlot` the client built against.
    pub recent_slot: u64,
    pub authorized: Authorized,
    pub deposit: Option<u64>,
    pub open_slot: Option<u64>,
    pub idle_timeout_seconds: Option<u32>,
    /// ComputeBudget `(limit, micro-lamports)`; `None`: the kit's default
    /// (no budget instructions on version 0).
    pub budget: Option<(u32, u64)>,
    /// Sign the bearer proof (operator mode) for this challenge id.
    pub proof_for: Option<&'static str>,
}

impl Default for OpenBuild {
    fn default() -> Self {
        Self {
            recent_slot: RECENT_SLOT,
            authorized: Authorized::SessionKey,
            deposit: None,
            open_slot: None,
            idle_timeout_seconds: None,
            budget: Some((200_000, 1)),
            proof_for: None,
        }
    }
}

/// The kit server `server` describes, issuing challenges at `recent_slot`.
fn challenge_request(server: &Server, recent_slot: u64) -> Result<SessionRequest, String> {
    let sponsor = server.sponsored.then(|| {
        MemorySigner::from_bytes(&keys::keypair_bytes(OPERATOR_SEED)).expect("sponsor key")
    });
    let cache = solana_pay_kit::core::blockhash::BlockhashCache::new();
    cache.set(BLOCKHASH.to_string(), 0, recent_slot);
    kit_server(&server.json(), sponsor, MemoryChannelStore::new())?
        .with_blockhash_cache(cache)
        .build_challenge_request()
        .map_err(|e| format!("session challenge: {e}"))
}

/// The kit client's `open` action (JSON) for `server`'s challenge.
pub async fn build_open(server: &Server, build: &OpenBuild) -> Result<Value, String> {
    let request = challenge_request(server, build.recent_slot)?;
    open_for_request(&request, build).await
}

async fn open_for_request(request: &SessionRequest, build: &OpenBuild) -> Result<Value, String> {
    let payer = MemorySigner::from_bytes(&keys::keypair_bytes(keys::CLIENT_SEED))
        .map_err(|e| e.to_string())?;
    let voucher_seed = match build.authorized {
        Authorized::SessionKey => SESSION_SIGNER_SEED,
        Authorized::Payer => keys::CLIENT_SEED,
    };
    let session =
        MemorySigner::from_bytes(&keys::keypair_bytes(voucher_seed)).map_err(|e| e.to_string())?;
    let open_options = PaymentChannelOpenOptions {
        salt: Some(SALT),
        deposit: build.deposit,
        open_slot: build.open_slot,
        compute_budget: build
            .budget
            .map(|(limit, price)| ComputeBudget::new(limit, price)),
        ..Default::default()
    };
    let authentication = match build.proof_for {
        None => None,
        Some(challenge_id) => {
            let operator_key = request
                .method_details
                .operator
                .as_deref()
                .ok_or("operator challenge without operator")?;
            let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
                request,
                payer: client(),
                authorized_signer: Pubkey::from_str(operator_key).map_err(|e| e.to_string())?,
                options: open_options.clone(),
            })
            .map_err(|e| format!("derive open: {e}"))?;
            Some(
                SessionAuthentication::sign(
                    challenge_id,
                    &open.channel_id.to_string(),
                    &keys::signing_key(keys::CLIENT_SEED),
                )
                .map_err(|e| e.to_string())?,
            )
        }
    };
    let opened = create_payment_channel_session_opener(
        request,
        &payer,
        Box::new(session),
        None,
        PaymentChannelSessionOpenOptions {
            open: open_options,
            authentication,
            idle_timeout_seconds: build.idle_timeout_seconds,
            ..Default::default()
        },
    )
    .await
    .map_err(|e| format!("session open: {e}"))?;
    serde_json::to_value(&opened.action).map_err(|e| e.to_string())
}

// ── tampers (the session operators) ────────────────────────────────────────

/// One edit of the client's `open` transaction, applied to the kit-built
/// open and re-signed by the payer (and by the key the edit adds). Each is
/// paired with the reject code it must produce ([`TxTamper::expected`]);
/// materialize asserts the pairing.
#[derive(Debug, Clone, PartialEq)]
pub enum TxTamper {
    /// Recompile with another recent blockhash.
    Blockhash(&'static str),
    /// Open account at `index` set to `key`, keeping its privileges.
    OpenAccount(usize, Pubkey),
    /// Open account at `index` made writable.
    OpenWritable(usize),
    /// A fifteenth (remaining) account on the open instruction.
    OpenExtraAccount,
    /// The open instruction invoked on another program.
    OpenProgram(Pubkey),
    /// The open discriminator byte.
    OpenDiscriminator(u8),
    /// An open argument rewritten in the instruction data (the payload
    /// keeps its value; accounts unchanged).
    OpenArg(OpenArg),
    /// A second copy of the open instruction.
    DuplicateOpen,
    /// The open instruction removed.
    DropOpen,
    /// The open rebuilt for an `authorizedSigner` that is not a curve point
    /// (channel and token account re-derived, the payload updated to
    /// match), so only the curve check can refuse it.
    OffCurveSigner,
    /// The transaction fee payer set to the key of `seed`, which signs.
    FeePayer([u8; 32]),
    /// The top-up instruction's channel account set to `key`.
    TopUpChannel(Pubkey),
    /// The top-up amount argument.
    TopUpAmount(u64),
    /// A `mutate.rs` transaction operator.
    Op(Mutation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenArg {
    Deposit(u64),
    GracePeriod(u32),
}

impl TxTamper {
    /// The reject code the operator must produce.
    pub fn expected(&self) -> Option<RejectCode> {
        use RejectCode::*;
        Some(match self {
            TxTamper::Blockhash(_) => OpenBindingMismatch,
            TxTamper::OpenAccount(5, _) => ChannelIdMismatch,
            TxTamper::OpenAccount(..)
            | TxTamper::OpenWritable(_)
            | TxTamper::OpenExtraAccount
            | TxTamper::OpenArg(_) => OpenBindingMismatch,
            TxTamper::OpenProgram(_)
            | TxTamper::OpenDiscriminator(_)
            | TxTamper::DuplicateOpen
            | TxTamper::DropOpen => UnexpectedInstruction,
            TxTamper::OffCurveSigner => OpenBindingMismatch,
            TxTamper::FeePayer(_) => FeePayerMismatch,
            TxTamper::TopUpChannel(_) => ChannelIdMismatch,
            TxTamper::TopUpAmount(_) => AmountMismatch,
            TxTamper::Op(op) => return op.expected(crate::case::Suite::Session),
        })
    }

    pub fn describe(&self) -> String {
        match self {
            TxTamper::Blockhash(h) => format!("transaction recompiled with recent blockhash {h}"),
            TxTamper::OpenAccount(i, k) => format!("open account #{i} set to {k}"),
            TxTamper::OpenWritable(i) => format!("open account #{i} made writable"),
            TxTamper::OpenExtraAccount => "a fifteenth (remaining) account on open".into(),
            TxTamper::OpenProgram(p) => format!("open invoked on program {p}"),
            TxTamper::OpenDiscriminator(d) => format!("open discriminator set to {d}"),
            TxTamper::OpenArg(OpenArg::Deposit(d)) => {
                format!("open deposit argument set to {d} (payload unchanged)")
            }
            TxTamper::OpenArg(OpenArg::GracePeriod(g)) => {
                format!("open grace_period argument set to {g} (payload unchanged)")
            }
            TxTamper::DuplicateOpen => "a second open instruction".into(),
            TxTamper::DropOpen => "open instruction removed".into(),
            TxTamper::OffCurveSigner => format!(
                "open rebuilt with authorizedSigner {} (not a curve point) and the payload re-derived",
                off_curve()
            ),
            TxTamper::FeePayer(seed) => format!("transaction fee payer set to {}", key(*seed)),
            TxTamper::TopUpChannel(k) => format!("top-up channel account set to {k}"),
            TxTamper::TopUpAmount(a) => format!("top-up amount argument set to {a}"),
            TxTamper::Op(op) => op.describe(),
        }
    }

    fn apply(&self, credential: &mut Value) -> Result<(), String> {
        let tx = decode_b64(credential["transaction"].as_str().unwrap_or_default())?;
        let signers = [keys::CLIENT_SEED];
        let out = match self {
            TxTamper::Op(op) => op.apply(&tx, &signers)?,
            _ => {
                let mut d = decompile(&tx.message)?;
                let program = pc::default_program_id();
                let open_at = d
                    .instructions
                    .iter()
                    .position(|ix| ix.program_id == program)
                    .ok_or("transaction has no payment-channels instruction")?;
                let mut extra_seeds: Vec<[u8; 32]> = vec![];
                match self {
                    TxTamper::Blockhash(h) => {
                        d.blockhash = Hash::from_str(h).map_err(|e| e.to_string())?;
                    }
                    TxTamper::OpenAccount(i, k) => d.instructions[open_at].accounts[*i].pubkey = *k,
                    TxTamper::OpenWritable(i) => {
                        d.instructions[open_at].accounts[*i].is_writable = true
                    }
                    TxTamper::OpenExtraAccount => d.instructions[open_at]
                        .accounts
                        .push(AccountMeta::new_readonly(stranger(), false)),
                    TxTamper::OpenProgram(p) => d.instructions[open_at].program_id = *p,
                    TxTamper::OpenDiscriminator(b) => d.instructions[open_at].data[0] = *b,
                    TxTamper::OpenArg(arg) => {
                        let data = &mut d.instructions[open_at].data;
                        match arg {
                            OpenArg::Deposit(v) => data[9..17].copy_from_slice(&v.to_le_bytes()),
                            OpenArg::GracePeriod(v) => {
                                data[17..21].copy_from_slice(&v.to_le_bytes())
                            }
                        }
                    }
                    TxTamper::DuplicateOpen => {
                        let copy = d.instructions[open_at].clone();
                        d.instructions.insert(open_at + 1, copy);
                    }
                    TxTamper::DropOpen => {
                        d.instructions.remove(open_at);
                    }
                    TxTamper::OffCurveSigner => {
                        let mut params = open_params_of(credential)?;
                        params.authorized_signer = off_curve();
                        d.instructions[open_at] = pc::build_open_instruction(&params);
                        credential["authorizedSigner"] = json!(off_curve().to_string());
                        credential["channelId"] =
                            json!(pc::derive_channel_addresses(&params).channel.to_string());
                    }
                    TxTamper::FeePayer(seed) => {
                        d.fee_payer = key(*seed);
                        extra_seeds.push(*seed);
                    }
                    TxTamper::TopUpChannel(k) => {
                        let ix = &mut d.instructions[open_at];
                        let mint = ix.accounts[4].pubkey;
                        let token_program = ix.accounts[5].pubkey;
                        ix.accounts[1].pubkey = *k;
                        ix.accounts[3].pubkey =
                            pc::find_associated_token_address(k, &mint, &token_program).0;
                    }
                    TxTamper::TopUpAmount(a) => {
                        d.instructions[open_at].data[1..9].copy_from_slice(&a.to_le_bytes())
                    }
                    TxTamper::Op(_) => unreachable!(),
                }
                let mut out = recompile(&tx.message, &d)?;
                let mut seeds = signers.to_vec();
                seeds.extend(extra_seeds);
                sign_slots(&mut out, &seeds);
                out
            }
        };
        credential["transaction"] = json!(encode_b64(&out)?);
        Ok(())
    }
}

/// The open parameters an `open` credential declares.
fn open_params_of(credential: &Value) -> Result<pc::OpenChannelParams, String> {
    let k = |f: &str| {
        Pubkey::from_str(credential[f].as_str().unwrap_or_default())
            .map_err(|e| format!("{f}: {e}"))
    };
    let tx = decode_b64(credential["transaction"].as_str().unwrap_or_default())?;
    let rent_payer = *tx
        .message
        .static_account_keys()
        .first()
        .ok_or("no fee payer")?;
    let recipients = credential
        .get("distributionSplits")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|e| pc::Distribution {
                    recipient: keys::pubkey(e["recipient"].as_str().unwrap_or_default()),
                    bps: e["shareBps"].as_u64().unwrap_or_default() as u16,
                })
                .collect()
        })
        .unwrap_or_default();
    let mint = k("mint")?;
    let token_program = if mint == keys::pubkey(keys::MINT_2022) {
        keys::pubkey(keys::TOKEN_2022_PROGRAM)
    } else {
        keys::pubkey(TOKEN_PROGRAM)
    };
    Ok(pc::OpenChannelParams {
        payer: k("payer")?,
        rent_payer,
        payee: k("payee")?,
        mint,
        authorized_signer: k("authorizedSigner")?,
        salt: credential["salt"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or("salt")?,
        open_slot: credential["openSlot"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or("openSlot")?,
        deposit: credential["depositAmount"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or("depositAmount")?,
        grace_period: credential["gracePeriodSeconds"]
            .as_u64()
            .ok_or("gracePeriodSeconds")? as u32,
        recipients,
        token_program,
        program_id: pc::default_program_id(),
    })
}

/// An edit of the credential JSON after it is built and signed: the
/// envelope disagrees with the transaction, or carries a field it must not.
#[derive(Debug, Clone, PartialEq)]
pub enum Edit {
    /// Set the value at a JSON pointer (parents must exist).
    Set(&'static str, Value),
    /// Remove the value at a JSON pointer.
    Remove(&'static str),
}

impl Edit {
    pub fn describe(&self) -> String {
        match self {
            Edit::Set(p, v) => format!("credential {p} set to {v}"),
            Edit::Remove(p) => format!("credential {p} removed"),
        }
    }

    fn apply(&self, value: &mut Value) -> Result<(), String> {
        let (pointer, new) = match self {
            Edit::Set(p, v) => (*p, Some(v.clone())),
            Edit::Remove(p) => (*p, None),
        };
        let (parent, leaf) = pointer.rsplit_once('/').ok_or("edit pointer")?;
        let target = value
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| format!("no object at {parent}"))?;
        match new {
            Some(v) => {
                target.insert(leaf.to_string(), v);
            }
            None => {
                target
                    .remove(leaf)
                    .ok_or_else(|| format!("nothing to remove at {pointer}"))?;
            }
        }
        Ok(())
    }
}

// ── recipes ────────────────────────────────────────────────────────────────

/// A voucher the client signs.
#[derive(Debug, Clone, PartialEq)]
pub struct VoucherSpec {
    pub cumulative: u64,
    pub expires_at: Option<i64>,
    pub signer_seed: [u8; 32],
    /// Bind the voucher to another channel than the stored one.
    pub channel: Option<Pubkey>,
}

impl VoucherSpec {
    pub fn new(cumulative: u64) -> Self {
        Self {
            cumulative,
            expires_at: Some(FAR_EXPIRY),
            signer_seed: SESSION_SIGNER_SEED,
            channel: None,
        }
    }

    fn json(&self, channel: &Channel) -> Result<Value, String> {
        signed_voucher(
            &self.channel.unwrap_or_else(|| channel.id()),
            self.cumulative,
            self.expires_at,
            self.signer_seed,
        )
    }
}

/// What the credential is.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// The kit client's `open` for `built_from`'s challenge (default: the
    /// verifying server's), verified against the challenge at
    /// `verify_slot`.
    Open {
        build: OpenBuild,
        built_from: Option<Server>,
        verify_slot: u64,
    },
    Voucher {
        channel: Channel,
        voucher: VoucherSpec,
    },
    /// A top-up transaction of `amount` for `channel`, fee paid by the
    /// channel's rent payer.
    TopUp { channel: Channel, amount: u64 },
    Close {
        channel: Channel,
        voucher: Option<VoucherSpec>,
        authentication: bool,
    },
}

/// A session verify vector.
#[derive(Debug, Clone, PartialEq)]
pub struct Recipe {
    pub server: Server,
    pub action: Action,
    pub tx: Option<TxTamper>,
    pub edits: Vec<Edit>,
}

impl Recipe {
    pub fn new(server: Server, action: Action) -> Self {
        Self {
            server,
            action,
            tx: None,
            edits: vec![],
        }
    }

    pub fn open(server: Server) -> Self {
        Self::new(
            server,
            Action::Open {
                build: OpenBuild::default(),
                built_from: None,
                verify_slot: RECENT_SLOT,
            },
        )
    }

    /// Apply a transaction operator to the built credential.
    pub fn tx(mut self, tamper: TxTamper) -> Self {
        self.tx = Some(tamper);
        self
    }

    /// Edit the credential JSON after it is built and signed.
    pub fn edit(mut self, edit: Edit) -> Self {
        self.edits.push(edit);
        self
    }

    pub fn describe(&self) -> Option<String> {
        let mut parts: Vec<String> = self.edits.iter().map(Edit::describe).collect();
        if let Some(tx) = &self.tx {
            parts.insert(0, tx.describe());
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }

    pub fn expected(&self) -> Option<RejectCode> {
        self.tx.as_ref().and_then(TxTamper::expected)
    }
}

/// Build a top-up transaction (version 0, budget prefix) for `channel`.
fn topup_transaction(channel: &Channel, amount: u64) -> Result<String, String> {
    let params = channel.open.params();
    let ix = pc::build_top_up_instruction(
        &client(),
        &channel.id(),
        &params.mint,
        amount,
        &params.token_program,
        &params.program_id,
    );
    let budget = ComputeBudget::new(200_000, 1);
    let mut tx = solana_pay_kit::core::tx::build_unsigned(
        TxVersion::V0,
        &channel.open.rent_payer,
        &[ix],
        Hash::from_str(BLOCKHASH).map_err(|e| e.to_string())?,
        Some(&budget),
    )
    .map_err(|e| e.to_string())?;
    sign_slots(&mut tx, &[keys::CLIENT_SEED]);
    encode_b64(&tx)
}

pub async fn materialize(recipe: &Recipe) -> Result<Value, String> {
    let mut verify = Map::new();
    verify.insert("server".into(), recipe.server.json());
    let credential = match &recipe.action {
        Action::Open {
            build,
            built_from,
            verify_slot,
        } => {
            verify.insert(
                "challenge".into(),
                json!({
                    "id": CHALLENGE_ID,
                    "recentBlockhash": BLOCKHASH,
                    "recentSlot": verify_slot.to_string(),
                }),
            );
            build_open(built_from.as_ref().unwrap_or(&recipe.server), build).await?
        }
        Action::Voucher { channel, voucher } => {
            verify.insert("channel".into(), channel.json()?);
            json!({
                "action": "voucher",
                "channelId": voucher.channel.unwrap_or_else(|| channel.id()).to_string(),
                "voucher": voucher.json(channel)?,
            })
        }
        Action::TopUp { channel, amount } => {
            verify.insert("channel".into(), channel.json()?);
            json!({
                "action": "topUp",
                "channelId": channel.id().to_string(),
                "additionalAmount": amount.to_string(),
                "transaction": topup_transaction(channel, *amount)?,
            })
        }
        Action::Close {
            channel,
            voucher,
            authentication,
        } => {
            verify.insert("channel".into(), channel.json()?);
            let mut close = json!({
                "action": "close",
                "channelId": channel.id().to_string(),
            });
            if let Some(voucher) = voucher {
                close["voucher"] = voucher.json(channel)?;
            }
            if *authentication {
                close["authentication"] =
                    serde_json::to_value(channel.proof()?).map_err(|e| e.to_string())?;
            }
            close
        }
    };
    let mut credential = credential;
    if let Some(tx) = &recipe.tx {
        tx.apply(&mut credential)?;
    }
    for edit in &recipe.edits {
        edit.apply(&mut credential)?;
    }
    verify.insert("credential".into(), credential);
    let mut input = json!({ "sessionServerVerify": Value::Object(verify) });
    if recipe.server.sponsored {
        input["sessionServerFeePayerSecretKey"] = keys::secret_json(OPERATOR_SEED);
    }
    Ok(input)
}

// ── reject classification ──────────────────────────────────────────────────

/// The shared code for a kit session error message. Mirrored in the Rust
/// testee (`vector_runner/session.rs`).
pub fn code_for(message: &str) -> Option<RejectCode> {
    use RejectCode::*;
    let m = message.to_ascii_lowercase();
    let has = |n: &str| m.contains(n);
    Some(if has("transaction version") && has("not accepted") {
        UnsupportedVersion
    } else if has("compute unit price") && (has("exceed") || has("maximum")) {
        ComputePriceOverCap
    } else if has("compute unit limit") && (has("exceed") || has("maximum")) {
        ComputeLimitOverCap
    } else if has("invalid payload") || has("unknown field") || has("missing field") {
        InvalidPayload
    } else if has("client close requires a final voucher")
        || has("client close must not include")
        || has("operator close must not include")
        || has("operator close requires")
    {
        CloseAuthorization
    } else if has("authentication") || has("does not authenticate") {
        AuthenticationInvalid
    } else if has("fee payer does not match") || has("fee payer must be") {
        FeePayerMismatch
    } else if has("does not match the derived channel pda")
        || has("does not match derived channel pda")
        || has("action channelid does not match")
        || has("close voucher channelid does not match")
        || has("do not match the stored channel")
    {
        ChannelIdMismatch
    } else if has("unexpected instruction")
        || has("does not contain the expected open instruction")
        || has("top-up instruction not found")
        || has("unsupported compute budget")
    {
        UnexpectedInstruction
    } else if has("below minimumdeposit")
        || has("deposit must be greater than zero")
        || has("additionalamount must be positive")
        || has("does not match additionalamount")
        || has("insufficient authorized voucher availability")
    {
        AmountMismatch
    } else if has("open transaction")
        || has("open instruction")
        || has("payment-channel open")
        || has("opensl")
        || has("idletimeoutseconds")
        || has("authorizedsigner")
        || has("privileges")
    {
        OpenBindingMismatch
    } else if has("signature verification failed")
        || has("signer does not match")
        || has("invalid voucher signature")
    {
        VoucherSignature
    } else if has("must exceed watermark") || has("already accepted") {
        CumulativeAmountMismatch
    } else if has("exceeds deposit") {
        CumulativeExceedsDeposit
    } else if has("voucher has expired") {
        VoucherExpired
    } else if has("settlement window") {
        VoucherExpiresBeforeSettlement
    } else if has("close is pending") || has("close already requested") {
        ChannelClosing
    } else if has("already sealed") || has("closed or close") {
        CloseState
    } else if has("not found") {
        ChannelState
    } else if has("address lookup tables")
        || has("byte limit")
        || has("session transaction")
        || has("invalid")
        || has("decode")
    {
        InvalidPayload
    } else {
        return None;
    })
}

fn reject(message: String) -> Observed {
    Observed::Reject {
        code: code_for(&message),
        message,
    }
}

// ── kit drivers ────────────────────────────────────────────────────────────

pub async fn run(mode: Mode, input: &Value) -> Result<Observed, String> {
    match mode {
        Mode::VerifyTransaction => verify(input).await,
        Mode::BuildTransaction => build(input).await,
        Mode::CanonicalBytes => super::canonical_bytes(input),
    }
}

pub async fn verify(input: &Value) -> Result<Observed, String> {
    let params = input
        .get("sessionServerVerify")
        .ok_or("input.sessionServerVerify missing")?;
    let store = MemoryChannelStore::new();
    if let Some(channel) = params.get("channel") {
        let state = stored_channel(channel)?;
        store
            .put_channel(&state.channel_id.clone(), state)
            .await
            .map_err(|e| format!("seed channel: {e}"))?;
    }
    let fee_payer = input
        .get("sessionServerFeePayerSecretKey")
        .map(|_| signer_from(input, "sessionServerFeePayerSecretKey"))
        .transpose()?;
    let server_json = params.get("server").cloned().unwrap_or(Value::Null);
    let server = match kit_server(&server_json, fee_payer, store) {
        Ok(server) => server,
        Err(e) => return Ok(Observed::NotExpressible(e)),
    };
    let action: SessionAction = match serde_json::from_value(params["credential"].clone()) {
        Ok(action) => action,
        Err(e) => return Ok(reject(format!("invalid payload: session credential: {e}"))),
    };
    let result = match &action {
        SessionAction::Open(open) => {
            let challenge = params.get("challenge").ok_or("challenge missing")?;
            let recent_slot = u64_field(challenge, "recentSlot")?.ok_or("recentSlot missing")?;
            testkit::verify_open_pre_broadcast(
                &server,
                open,
                SessionOpenContext {
                    challenge_id: challenge["id"].as_str().unwrap_or_default(),
                    expires: None,
                    recent_blockhash: challenge["recentBlockhash"].as_str().unwrap_or_default(),
                    recent_slot,
                },
            )
            .await
        }
        SessionAction::Voucher(voucher) => {
            let amount = u64_field(&server_json, "amount")?.ok_or("amount missing")?;
            server
                .verify_voucher_for_amount(voucher, amount)
                .await
                .map(|_| ())
        }
        SessionAction::TopUp(topup) => testkit::verify_topup_pre_broadcast(&server, topup).await,
        SessionAction::Close(close) => server.process_close(close).await.map(|_| ()),
        SessionAction::Use(_) => {
            return Ok(Observed::NotExpressible(
                "the use action needs an Idempotency-Key and operator signing key".into(),
            ))
        }
    };
    Ok(match result {
        Ok(()) => Observed::Accept(Output::default()),
        Err(e) => reject(e.to_string()),
    })
}

// ── client build ───────────────────────────────────────────────────────────

/// A session open build vector: the challenge the client receives (the
/// kit server's for `server`, then `edits`), and the judge's server.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildRecipe {
    pub server: Server,
    pub authorized: Authorized,
    /// Edits of the challenge `SessionRequest` JSON.
    pub edits: Vec<Edit>,
}

pub fn build_input(recipe: &BuildRecipe) -> Result<Value, String> {
    let request = challenge_request(&recipe.server, RECENT_SLOT)?;
    let mut request = serde_json::to_value(request).map_err(|e| e.to_string())?;
    for edit in &recipe.edits {
        edit.apply(&mut request)?;
    }
    let voucher_seed = match recipe.authorized {
        Authorized::SessionKey => SESSION_SIGNER_SEED,
        Authorized::Payer => keys::CLIENT_SEED,
    };
    let mut input = json!({
        "signerSecretKey": crate::cases::client_secret(),
        "sessionSignerSecretKey": keys::secret_json(voucher_seed),
        "sessionOpenBuild": {
            "request": request,
            "salt": SALT.to_string(),
            "server": recipe.server.json(),
            "challenge": {
                "id": CHALLENGE_ID,
                "recentBlockhash": BLOCKHASH,
                "recentSlot": RECENT_SLOT.to_string(),
            },
        },
    });
    if recipe.server.sponsored {
        input["sessionServerFeePayerSecretKey"] = keys::secret_json(OPERATOR_SEED);
    }
    Ok(input)
}

/// The facts of a built `open` a build vector pins.
fn open_summary(open: &Value) -> Result<Map<String, Value>, String> {
    let tx = decode_b64(
        open["transaction"]
            .as_str()
            .ok_or("open has no transaction")?,
    )?;
    let mut out = Map::new();
    for key in [
        "channelId",
        "payer",
        "payee",
        "mint",
        "authorizedSigner",
        "salt",
        "depositAmount",
        "gracePeriodSeconds",
        "openSlot",
    ] {
        out.insert(key.into(), open.get(key).cloned().unwrap_or(Value::Null));
    }
    out.insert(
        "distributionSplits".into(),
        open.get("distributionSplits").cloned().unwrap_or(json!([])),
    );
    out.insert(
        "feePayer".into(),
        json!(tx
            .message
            .static_account_keys()
            .first()
            .map(ToString::to_string)),
    );
    out.insert(
        "recentBlockhash".into(),
        json!(tx.message.recent_blockhash().to_string()),
    );
    out.insert(
        "signatureSlots".into(),
        json!(crate::tx::signature_slots(&tx)
            .into_iter()
            .map(|(k, slot)| json!({ "key": k, "slot": format!("{slot:?}") }))
            .collect::<Vec<_>>()),
    );
    Ok(out)
}

pub async fn build(input: &Value) -> Result<Observed, String> {
    let params = input
        .get("sessionOpenBuild")
        .ok_or("input.sessionOpenBuild missing")?;
    let request: SessionRequest = match serde_json::from_value(params["request"].clone()) {
        Ok(r) => r,
        Err(e) => return Ok(reject_build(format!("invalid challenge: {e}"))),
    };
    let payer = signer_from(input, "signerSecretKey")?;
    let session = signer_from(input, "sessionSignerSecretKey")?;
    let salt = u64_field(params, "salt")?;
    let opened = create_payment_channel_session_opener(
        &request,
        &payer,
        Box::new(session),
        None,
        PaymentChannelSessionOpenOptions {
            open: PaymentChannelOpenOptions {
                salt,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let action = match opened {
        Ok(opened) => serde_json::to_value(&opened.action).map_err(|e| e.to_string())?,
        Err(e) => return Ok(reject_build(e.to_string())),
    };
    let summary = open_summary(&action)?;
    Ok(Observed::Accept(Output {
        transaction: action["transaction"].as_str().map(str::to_string),
        header: Some(action.to_string()),
        exact: Some(summary),
    }))
}

/// A client refusal: the challenge is out of spec.
fn reject_build(message: String) -> Observed {
    Observed::Reject {
        code: build_code_for(&message),
        message,
    }
}

/// The shared code for a kit session client refusal. Mirrored in the Rust
/// testee.
pub fn build_code_for(message: &str) -> Option<RejectCode> {
    let m = message.to_ascii_lowercase();
    let has = |n: &str| m.contains(n);
    (has("challenge")
        || has("network")
        || has("program")
        || has("tokenprogram")
        || has("feepayerkey")
        || has("operator")
        || has("spl token")
        || has("graceperiod")
        || has("decimals")
        || has("invalid"))
    .then_some(RejectCode::InvalidChallenge)
}

/// Judge an SDK's `open` build: the pinned summary, the kit server's offline
/// open checks on it, and the kit's own build of the same challenge.
pub async fn judge_build(vector: &Vector, artifact: &str) -> Result<(), Failure> {
    let open: Value = serde_json::from_str(artifact)
        .map_err(|e| Failure::new(format!("sessionCredential is not JSON: {e}")))?;
    let summary = open_summary(&open).map_err(Failure::new)?;
    if let Some(Value::Object(pinned)) = vector.expect().get("exactBytes") {
        for (k, want) in pinned {
            if summary.get(k) != Some(want) {
                return Err(Failure {
                    message: format!(
                        "open {k}: expected {want}, the SDK built {}",
                        summary.get(k).cloned().unwrap_or(Value::Null)
                    ),
                    path: Some(format!("exactBytes.{k}")),
                    expected: Some(want.clone()),
                    actual: summary.get(k).cloned(),
                });
            }
        }
    }
    let params = vector
        .input()
        .get("sessionOpenBuild")
        .cloned()
        .unwrap_or_default();
    let mut verify_input = json!({
        "sessionServerVerify": {
            "server": params["server"],
            "challenge": params["challenge"],
            "credential": open,
        }
    });
    if let Some(key) = vector.input().get("sessionServerFeePayerSecretKey") {
        verify_input["sessionServerFeePayerSecretKey"] = key.clone();
    }
    match verify(&verify_input).await.map_err(Failure::new)? {
        Observed::Accept(_) => {}
        other => {
            return Err(Failure {
                message: format!(
                    "the Rust kit's session server refuses the SDK's open: {}",
                    other.summary()
                ),
                path: Some("verify".into()),
                expected: Some(json!("accept")),
                actual: Some(json!(other.summary())),
            })
        }
    }
    let reference = match build(vector.input()).await.map_err(Failure::new)? {
        Observed::Accept(output) => output,
        other => {
            return Err(Failure::new(format!(
                "the Rust kit cannot build this case ({}); file against the filler",
                other.summary()
            )))
        }
    };
    let want: Value = serde_json::from_str(reference.header.as_deref().unwrap_or("null"))
        .map_err(|e| Failure::new(e.to_string()))?;
    for (k, v) in want.as_object().into_iter().flatten() {
        if k == "transaction" {
            continue;
        }
        if open.get(k) != Some(v) {
            return Err(Failure {
                message: format!("open {k} differs from the Rust kit's build"),
                path: Some(format!("open.{k}")),
                expected: Some(v.clone()),
                actual: open.get(k).cloned(),
            });
        }
    }
    crate::run::judge::compare_transactions(
        reference.transaction.as_deref().unwrap_or_default(),
        open["transaction"].as_str().unwrap_or_default(),
        false,
    )
}

/// Instructions the cases insert.
pub fn memo_ix(text: &str) -> Instruction {
    Instruction {
        program_id: keys::pubkey(keys::MEMO_PROGRAM),
        accounts: vec![],
        data: text.as_bytes().to_vec(),
    }
}
