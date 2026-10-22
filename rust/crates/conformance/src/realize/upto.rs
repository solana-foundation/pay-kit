//! Kit paths for `x402-upto` vectors: what `pkc fill` runs to realize a case
//! and what the build judge runs against an SDK's build.
//!
//! Vector input (documented in `harness/src/conformance/schema.ts`
//! `VectorInput`):
//!
//! - build: `x402Offer` (an upto `PaymentRequirements`, with the
//!   `extra.recentBlockhash` / `extra.recentSlot` hints so no live RPC is
//!   needed), `signerSecretKey`, `nowSeconds`, `rpcFixtures`, and the client
//!   call parameters SDKs whose builder takes them pass through:
//!   `x402UptoExpiresAt`, `x402UptoRequestNonce`,
//!   `x402ClientMaxTransactionVersion`.
//! - verify: `x402PaymentHeader` and the route the server is configured with
//!   (`x402Server*`), `nowSeconds`, `rpcFixtures` (`slot` is the challenged
//!   slot; `accounts` holds an existing channel).
//! - canonical bytes: `x402UptoVoucher`, `x402UptoDistribution`,
//!   `x402UptoChannelPda`.
//!
//! The kit's verifier runs through `x402::server::upto::testkit`
//! (`verify_open_pre_broadcast`): every check `X402Upto::verify_open_for_route`
//! makes before it broadcasts the open, co-signature included, at the
//! vector's clock.

use std::str::FromStr;
use std::sync::Arc;

use base64::Engine;
use serde_json::{json, Map, Value};
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{legacy, v0, v1, VersionedMessage};
use solana_pay_kit::core::payment_channels as pc;
use solana_pay_kit::core::tx::{TxV1Mode, TxVersion};
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::x402::client::upto::build_upto_header;
use solana_pay_kit::x402::server::upto::testkit::verify_open_pre_broadcast;
use solana_pay_kit::x402::server::upto::{UptoConfig, UptoPayout, X402Upto};
use solana_pay_kit::x402::server::CurrencyConfig;
use solana_pay_kit::x402::upto::UptoRequirements;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;

use super::{Observed, Output};
use crate::case::{Mode, RejectCode};
use crate::fixture_rpc::{self, Fixtures, HttpFixture};
use crate::keys::{self, BLOCKHASH, MINT, TOKEN_PROGRAM, X402_PAY_TO};
use crate::run::judge::Failure;
use crate::run::vectors::Vector;
use crate::tx::{decode_b64, encode_b64, sign_slots};

/// The result field an accepted `x402-upto` build carries.
pub const BUILD_ARTIFACT: &str = "x402PaymentHeader";

// ── fixture keys and constants ─────────────────────────────────────────────

/// Receiver-authorizer seed `[13; 32]`: the server's voucher key, distinct
/// from the fee payer (the delegated / external-facilitator shape).
pub const RECEIVER_AUTHORIZER_SEED: [u8; 32] = [13; 32];
/// A key that is neither client, fee payer nor receiver authorizer.
pub const STRANGER_SEED: [u8; 32] = [21; 32];
/// The pinned clock of every upto vector.
pub const NOW: i64 = 1_800_000_000;
/// The challenged slot (`extra.recentSlot`, the fixture's slot).
pub const SLOT: u64 = 400_000_000;
/// The route string whose memo route-bound vectors declare.
pub const ROUTE: &str = "GET /reports?id=7";
pub const LIGHTHOUSE_PROGRAM: &str = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95";

/// Seeds whose keys the harness holds: a vector names a key, the judge finds
/// its secret here.
const KNOWN_SEEDS: [[u8; 32]; 4] = [
    keys::X402_OFFER_FEE_PAYER_SEED,
    keys::X402_SERVER_FEE_PAYER_SEED,
    RECEIVER_AUTHORIZER_SEED,
    keys::CLIENT_SEED,
];

pub fn key(seed: [u8; 32]) -> Pubkey {
    keys::pubkey_of_seed(seed)
}

pub fn client() -> Pubkey {
    key(keys::CLIENT_SEED)
}

pub fn stranger() -> Pubkey {
    key(STRANGER_SEED)
}

pub fn route_memo() -> String {
    X402Upto::route_memo(ROUTE)
}

fn seed_of(address: &str) -> Option<[u8; 32]> {
    KNOWN_SEEDS
        .into_iter()
        .find(|seed| key(*seed).to_string() == address)
}

// ── the route a server is configured with ──────────────────────────────────

/// An upto route: what the server advertises and verifies against.
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub amount: u64,
    pub mint: &'static str,
    pub token_program: &'static str,
    pub pay_to: Pubkey,
    pub fee_payer_seed: [u8; 32],
    pub receiver_authorizer_seed: [u8; 32],
    pub withdraw_delay: u32,
    pub max_timeout_seconds: u64,
    /// Bound to [`ROUTE`]: the route declares its memo.
    pub bound: bool,
    /// The server's accepted message versions (`None`: `[0]`).
    pub versions: Option<Vec<u8>>,
    pub max_channel_lifetime_seconds: u64,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            amount: 1_000_000,
            mint: MINT,
            token_program: TOKEN_PROGRAM,
            pay_to: keys::pubkey(X402_PAY_TO),
            fee_payer_seed: keys::X402_OFFER_FEE_PAYER_SEED,
            receiver_authorizer_seed: RECEIVER_AUTHORIZER_SEED,
            withdraw_delay: 900,
            max_timeout_seconds: 300,
            bound: false,
            versions: None,
            max_channel_lifetime_seconds: 3_600,
        }
    }
}

impl Route {
    pub fn fee_payer(&self) -> Pubkey {
        key(self.fee_payer_seed)
    }

    pub fn receiver_authorizer(&self) -> Pubkey {
        key(self.receiver_authorizer_seed)
    }

    pub fn memo(&self) -> Option<String> {
        self.bound.then(route_memo)
    }

    /// The requirement the server offers (`accepts[]` entry), hints included,
    /// and what an honest client echoes as `accepted`.
    pub fn offer(&self) -> Value {
        let mut extra = json!({
            "feePayer": self.fee_payer().to_string(),
            "receiverAuthorizer": self.receiver_authorizer().to_string(),
            "withdrawDelay": self.withdraw_delay,
            "tokenProgram": self.token_program,
            "recentBlockhash": BLOCKHASH,
            "recentSlot": SLOT.to_string(),
        });
        if let Some(memo) = self.memo() {
            extra["memo"] = json!(memo);
        }
        if let Some(versions) = &self.versions {
            extra["transactionVersions"] = json!(versions);
        }
        json!({
            "scheme": "upto",
            "network": keys::DEVNET_CAIP2,
            "amount": self.amount.to_string(),
            "asset": self.mint,
            "payTo": self.pay_to.to_string(),
            "maxTimeoutSeconds": self.max_timeout_seconds,
            "extra": extra,
        })
    }

    /// The `x402Server*` keys plus the fixtures and clock.
    pub fn server_input(&self) -> Map<String, Value> {
        let mut input = Map::new();
        let mut put = |k: &str, v: Value| {
            input.insert(k.to_string(), v);
        };
        put("x402ServerNetwork", json!("devnet"));
        put("x402ServerRecipient", json!(self.pay_to.to_string()));
        put("x402ServerCurrency", json!(self.mint));
        put("x402ServerTokenProgram", json!(self.token_program));
        put("x402ServerAmount", json!(self.amount.to_string()));
        put("x402ServerFeePayer", json!(self.fee_payer().to_string()));
        put(
            "x402ServerFeePayerSecretKey",
            keys::secret_json(self.fee_payer_seed),
        );
        put(
            "x402ServerReceiverAuthorizer",
            json!(self.receiver_authorizer().to_string()),
        );
        put(
            "x402ServerReceiverAuthorizerSecretKey",
            keys::secret_json(self.receiver_authorizer_seed),
        );
        put("x402ServerWithdrawDelay", json!(self.withdraw_delay));
        put(
            "x402ServerMaxTimeoutSeconds",
            json!(self.max_timeout_seconds),
        );
        put(
            "x402ServerMaxChannelLifetimeSeconds",
            json!(self.max_channel_lifetime_seconds),
        );
        if let Some(memo) = self.memo() {
            put("x402ServerMemo", json!(memo));
            put("x402ServerRoute", json!(ROUTE));
        }
        if let Some(versions) = &self.versions {
            put("x402ServerTransactionVersions", json!(versions));
        }
        put("nowSeconds", json!(NOW));
        put("rpcFixtures", fixtures_json(self.mint, self.token_program));
        input
    }
}

pub fn fixtures_json(mint: &str, token_program: &str) -> Value {
    json!({
        "recentBlockhash": BLOCKHASH,
        "slot": SLOT,
        "mints": { mint: { "owner": token_program, "decimals": 6 } },
    })
}

// ── the client's open transaction ──────────────────────────────────────────

/// Message format of an open transaction.
#[derive(Debug, Clone, PartialEq)]
pub enum Form {
    Legacy,
    V0,
    /// Version 0 with an (unused) address-lookup-table entry.
    V0WithLookupTable,
    /// Version 1 with the header compute config.
    V1 {
        unit_limit: Option<u32>,
        priority_fee_lamports: Option<u64>,
        loaded_accounts_data_size_limit: Option<u32>,
    },
}

impl Form {
    /// The canonical version-1 header: 200k units at 1 micro-lamport, the
    /// runtime's maximum loaded-data limit.
    pub fn v1() -> Form {
        Form::V1 {
            unit_limit: Some(200_000),
            priority_fee_lamports: Some(1),
            loaded_accounts_data_size_limit: Some(64 * 1024 * 1024),
        }
    }
}

/// The open arguments and accounts, before any tampering.
#[derive(Debug, Clone, PartialEq)]
pub struct Open {
    pub payer: Pubkey,
    pub rent_payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    pub token_program: Pubkey,
    pub salt: u64,
    pub open_slot: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub recipients: Vec<(Pubkey, u16)>,
}

impl Open {
    pub fn for_route(route: &Route) -> Self {
        Self {
            payer: client(),
            rent_payer: route.fee_payer(),
            payee: route.fee_payer(),
            mint: keys::pubkey(route.mint),
            authorized_signer: route.receiver_authorizer(),
            token_program: keys::pubkey(route.token_program),
            salt: 4242,
            open_slot: SLOT,
            deposit: route.amount,
            grace_period: route.withdraw_delay,
            recipients: vec![(route.pay_to, pc::FULL_SHARE_BPS)],
        }
    }

    pub fn params(&self) -> pc::OpenChannelParams {
        pc::OpenChannelParams {
            payer: self.payer,
            rent_payer: self.rent_payer,
            payee: self.payee,
            mint: self.mint,
            authorized_signer: self.authorized_signer,
            salt: self.salt,
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

    /// The channel PDA these arguments derive.
    pub fn channel(&self) -> Pubkey {
        pc::derive_channel_addresses(&self.params()).channel
    }

    pub fn instruction(&self) -> Instruction {
        pc::build_open_instruction(&self.params())
    }
}

pub fn unit_limit_ix(units: u32) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&units.to_le_bytes());
    compute_budget(data)
}

pub fn unit_price_ix(micro_lamports: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    compute_budget(data)
}

pub fn compute_budget(data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: keys::pubkey(keys::COMPUTE_BUDGET_PROGRAM),
        accounts: vec![],
        data,
    }
}

pub fn memo_ix(text: &str) -> Instruction {
    Instruction {
        program_id: keys::pubkey(keys::MEMO_PROGRAM),
        accounts: vec![],
        data: text.as_bytes().to_vec(),
    }
}

/// A 16-byte random-looking nonce, hex encoded (what a client emits when the
/// route declares no memo).
pub const NONCE_MEMO: &str = "5f3c9a1e7b2d4c6e8f0a1b2c3d4e5f60";

/// A Lighthouse assertion: no accounts beyond a read of the payer's token
/// account (what wallets inject).
pub fn lighthouse_ix(open: &Open) -> Instruction {
    let (payer_token, _) =
        pc::find_associated_token_address(&open.payer, &open.mint, &open.token_program);
    Instruction {
        program_id: keys::pubkey(LIGHTHOUSE_PROGRAM),
        accounts: vec![AccountMeta::new_readonly(payer_token, false)],
        data: vec![0x0b, 0x00],
    }
}

/// A client-built open transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenTx {
    pub form: Form,
    pub fee_payer: Pubkey,
    pub prefix: Vec<Instruction>,
    pub open: Instruction,
    pub suffix: Vec<Instruction>,
    /// Extra keys that sign (a required signer the tamper added).
    pub extra_signers: Vec<[u8; 32]>,
    /// What the payer's signature slot holds.
    pub payer_signature: PayerSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayerSignature {
    Valid,
    Missing,
    /// Signed over different bytes.
    Invalid,
}

impl OpenTx {
    /// The canonical client shape: ComputeBudget limit then price, open, a
    /// memo (the route's, or a hex nonce).
    pub fn canonical(route: &Route, open: &Open) -> Self {
        Self {
            form: Form::V0,
            fee_payer: route.fee_payer(),
            prefix: vec![unit_limit_ix(200_000), unit_price_ix(1)],
            open: open.instruction(),
            suffix: vec![memo_ix(&route.memo().unwrap_or_else(|| NONCE_MEMO.into()))],
            extra_signers: vec![],
            payer_signature: PayerSignature::Valid,
        }
    }

    pub fn instructions(&self) -> Vec<Instruction> {
        self.prefix
            .iter()
            .chain(std::iter::once(&self.open))
            .chain(self.suffix.iter())
            .cloned()
            .collect()
    }

    pub fn compile(&self) -> Result<VersionedTransaction, String> {
        let blockhash = Hash::from_str(BLOCKHASH).map_err(|e| e.to_string())?;
        let ixs = self.instructions();
        let message = match &self.form {
            Form::Legacy => VersionedMessage::Legacy(legacy::Message::new_with_blockhash(
                &ixs,
                Some(&self.fee_payer),
                &blockhash,
            )),
            Form::V0 | Form::V0WithLookupTable => {
                let mut m = v0::Message::try_compile(&self.fee_payer, &ixs, &[], blockhash)
                    .map_err(|e| format!("compile v0: {e}"))?;
                if self.form == Form::V0WithLookupTable {
                    m.address_table_lookups.push(v0::MessageAddressTableLookup {
                        account_key: stranger(),
                        writable_indexes: vec![],
                        readonly_indexes: vec![0],
                    });
                }
                VersionedMessage::V0(m)
            }
            Form::V1 {
                unit_limit,
                priority_fee_lamports,
                loaded_accounts_data_size_limit,
            } => {
                let mut config = v1::TransactionConfig::empty();
                if let Some(limit) = unit_limit {
                    config = config.with_compute_unit_limit(*limit);
                }
                if let Some(fee) = priority_fee_lamports {
                    config = config.with_priority_fee(*fee);
                }
                if let Some(loaded) = loaded_accounts_data_size_limit {
                    config = config.with_loaded_accounts_data_size_limit(*loaded);
                }
                VersionedMessage::V1(
                    v1::Message::try_compile_with_config(&self.fee_payer, &ixs, blockhash, config)
                        .map_err(|e| format!("compile v1: {e}"))?,
                )
            }
        };
        let mut tx = VersionedTransaction {
            signatures: vec![
                Signature::default();
                message.header().num_required_signatures as usize
            ],
            message,
        };
        let mut seeds = self.extra_signers.clone();
        if self.payer_signature != PayerSignature::Missing {
            seeds.push(keys::CLIENT_SEED);
        }
        sign_slots(&mut tx, &seeds);
        if self.payer_signature == PayerSignature::Invalid {
            let index = tx
                .message
                .static_account_keys()
                .iter()
                .position(|k| *k == client())
                .ok_or("client is not a signer")?;
            let mut bytes: [u8; 64] = tx.signatures[index].into();
            bytes[0] ^= 1;
            tx.signatures[index] = bytes.into();
        }
        Ok(tx)
    }
}

// ── a verify vector ────────────────────────────────────────────────────────

/// Everything a verify vector is made of. Tampers edit this, then
/// [`VerifySpec::input`] renders the vector input.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifySpec {
    pub route: Route,
    pub open: Open,
    pub tx: OpenTx,
    pub payload: Map<String, Value>,
    /// `accepted` the client echoes.
    pub accepted: Value,
    /// Extra or overriding input keys.
    pub input: Map<String, Value>,
    /// An account already exists at the channel PDA.
    pub channel_exists: bool,
}

impl VerifySpec {
    pub fn honest(route: Route) -> Self {
        let open = Open::for_route(&route);
        let tx = OpenTx::canonical(&route, &open);
        Self::from_parts(route, open, tx)
    }

    /// The bare open (no prefix, no memo) the Rust kit's client builds.
    pub fn bare(route: Route) -> Self {
        let open = Open::for_route(&route);
        let mut tx = OpenTx::canonical(&route, &open);
        tx.prefix.clear();
        tx.suffix.clear();
        Self::from_parts(route, open, tx)
    }

    pub fn from_parts(route: Route, open: Open, tx: OpenTx) -> Self {
        let mut payload = Map::new();
        let mut put = |k: &str, v: Value| {
            payload.insert(k.to_string(), v);
        };
        put("from", json!(open.payer.to_string()));
        put("maxAmount", json!(route.amount.to_string()));
        put("expiresAt", json!(NOW + route.max_timeout_seconds as i64));
        put("validAfter", json!(NOW));
        put("nonce", json!(open.salt.to_string()));
        put("openSlot", json!(open.open_slot.to_string()));
        put("channelId", json!(open.channel().to_string()));
        put("deposit", json!(route.amount.to_string()));
        put(
            "authorizedSigner",
            json!(route.receiver_authorizer().to_string()),
        );
        Self {
            accepted: route.offer(),
            route,
            open,
            tx,
            payload,
            input: Map::new(),
            channel_exists: false,
        }
    }

    pub fn set(&mut self, key: &str, value: Value) {
        self.payload.insert(key.to_string(), value);
    }

    /// Rebuild the open instruction from [`Self::open`] (after an argument
    /// edit), keeping the payload as it was.
    pub fn rebuild_open(&mut self) {
        self.tx.open = self.open.instruction();
    }

    pub fn input(&self) -> Result<Value, String> {
        let tx = self.tx.compile()?;
        let mut payload = self.payload.clone();
        payload.insert("openTransaction".into(), json!(encode_b64(&tx)?));
        let envelope = json!({
            "x402Version": 2,
            "accepted": self.accepted,
            "payload": payload,
        });
        let header = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_string(&envelope).map_err(|e| e.to_string())?);
        let mut input = self.route.server_input();
        input.insert("x402PaymentHeader".into(), json!(header));
        if self.channel_exists {
            let channel = self.open.channel();
            input["rpcFixtures"]["accounts"] = json!({
                channel.to_string(): {
                    "owner": pc::PAYMENT_CHANNELS_PROGRAM_ID,
                    "data": base64::engine::general_purpose::STANDARD.encode(channel_account(&self.open)),
                }
            });
        }
        for (k, v) in &self.input {
            input.insert(k.clone(), v.clone());
        }
        Ok(Value::Object(input))
    }
}

/// The 256-byte account of an `Open` channel committed by `open` (the
/// payment-channels channel layout).
pub fn channel_account(open: &Open) -> Vec<u8> {
    let params = open.params();
    let (_, bump) = pc::find_channel_pda(
        &open.payer,
        &open.payee,
        &open.mint,
        &open.authorized_signer,
        open.salt,
        open.open_slot,
        &params.program_id,
    );
    let mut data = vec![0u8, 1, bump, 0];
    data.extend_from_slice(&open.salt.to_le_bytes());
    data.extend_from_slice(&open.deposit.to_le_bytes());
    data.extend_from_slice(&[0u8; 32]); // settlement watermarks, closure, withdrawal
    data.extend_from_slice(&open.grace_period.to_le_bytes());
    data.extend_from_slice(&pc::distribution_hash(&params.recipients));
    for key in [
        open.payer,
        open.payee,
        open.authorized_signer,
        open.mint,
        open.rent_payer,
    ] {
        data.extend_from_slice(key.as_ref());
    }
    data.extend_from_slice(&open.open_slot.to_le_bytes());
    data
}

// ── tampers (the upto mutation operators) ──────────────────────────────────

/// One violation of the open-acceptance policy or the payload bindings,
/// applied to an honest [`VerifySpec`]. Each is paired with the reject code
/// it must produce ([`Tamper::expected`]); the case constructor asserts the
/// pairing, so an operator cannot be attached to a case with another code.
#[derive(Debug, Clone, PartialEq)]
pub enum Tamper {
    /// A client-supplied payload key (`voucherSignature`, `type`).
    PayloadKey(&'static str, Value),
    /// Replace a payload value without touching the transaction.
    PayloadValue(&'static str, Value),
    /// Remove a payload key.
    PayloadRemove(&'static str),
    /// Replace an `accepted` key (dotted: `extra.feePayer`).
    Accepted(&'static str, Value),
    /// Open account at `slot` set to `key`, keeping its privileges.
    OpenAccount(usize, Pubkey),
    /// The channel slot (and its token account) set to the PDA of another
    /// salt; payload and arguments unchanged.
    ChannelNotDerived,
    /// Open argument edits (payload unchanged).
    OpenDeposit(u64),
    OpenGracePeriod(u32),
    OpenSlotArg(u64),
    OpenRecipients(Vec<(Pubkey, u16)>),
    /// Salt changed in the arguments AND the channel re-derived for it, so
    /// only `payload.nonce` disagrees.
    OpenSaltRederived(u64),
    /// Bytes appended to / cut from the open instruction data.
    OpenTrailingByte,
    OpenTruncated,
    /// A fifteenth (remaining) account / a missing fourteenth.
    OpenExtraAccount,
    OpenMissingAccount,
    /// The mint account made writable.
    OpenWritableMint,
    OpenDiscriminator(u8),
    OpenProgram(Pubkey),
    /// Replace the ComputeBudget prefix.
    Prefix(Vec<Instruction>),
    /// Replace the suffix.
    Suffix(Vec<Instruction>),
    /// Insert before the open (after the prefix).
    BeforeOpen(Instruction),
    /// Remove the open instruction.
    DropOpen,
    /// A second copy of the open in the suffix.
    DuplicateOpen,
    /// The fee payer as a read-only account of the suffix instruction `at`.
    FeePayerInSuffix(usize),
    /// A Lighthouse-shaped instruction whose program is the fee payer.
    FeePayerAsProgram,
    /// A stranger added as a required signer of the memo, signing.
    ExtraSigner,
    /// The transaction fee payer is the client (the sponsor not a signer).
    ClientPaysFees,
    Signature(PayerSignature),
    Form(Form),
    /// The channel account already exists.
    ChannelExists,
    /// The clock: `payload.expiresAt` / `payload.validAfter` relative to NOW.
    ExpiresAt(i64),
    ValidAfter(i64),
}

impl Tamper {
    /// The reject code the operator must produce.
    pub fn expected(&self) -> Option<RejectCode> {
        use RejectCode::*;
        Some(match self {
            Tamper::PayloadKey("voucherSignature", _) => UnexpectedVoucher,
            Tamper::PayloadKey("type", _) => UnexpectedType,
            Tamper::PayloadKey(..) => return None,
            Tamper::PayloadValue("authorizedSigner", _) => ReceiverAuthorizerMismatch,
            Tamper::PayloadValue("maxAmount" | "deposit", v)
                if v.as_str().is_none_or(|s| s.parse::<u64>().is_err()) =>
            {
                InvalidPayload
            }
            Tamper::PayloadValue("maxAmount", _) => AmountMismatch,
            Tamper::PayloadValue("deposit", _) => DepositNotCeiling,
            Tamper::PayloadValue("channelId", _) => ChannelIdMismatch,
            Tamper::PayloadValue("nonce" | "openSlot", _) => OpenBindingMismatch,
            Tamper::PayloadValue("expiresAt" | "validAfter", _) => InvalidPayload,
            Tamper::PayloadValue(..) => return None,
            Tamper::PayloadRemove(_) => InvalidPayload,
            Tamper::Accepted("scheme" | "network", _) => AcceptedMismatch,
            Tamper::Accepted(..) => return None,
            Tamper::OpenAccount(5, _) | Tamper::ChannelNotDerived => ChannelIdMismatch,
            Tamper::OpenAccount(..)
            | Tamper::OpenDeposit(_)
            | Tamper::OpenGracePeriod(_)
            | Tamper::OpenSlotArg(_)
            | Tamper::OpenRecipients(_)
            | Tamper::OpenSaltRederived(_)
            | Tamper::OpenTrailingByte
            | Tamper::OpenTruncated
            | Tamper::OpenExtraAccount
            | Tamper::OpenMissingAccount
            | Tamper::OpenWritableMint => OpenBindingMismatch,
            Tamper::OpenDiscriminator(_)
            | Tamper::OpenProgram(_)
            | Tamper::BeforeOpen(_)
            | Tamper::DropOpen
            | Tamper::DuplicateOpen
            | Tamper::FeePayerAsProgram
            | Tamper::ExtraSigner => UnexpectedInstruction,
            Tamper::ClientPaysFees => InvalidPayload,
            Tamper::Prefix(_) | Tamper::Suffix(_) => return None,
            Tamper::FeePayerInSuffix(_) => FeePayerNotAuthority,
            Tamper::Signature(_) => InvalidPayload,
            Tamper::Form(Form::V0WithLookupTable) => InvalidPayload,
            Tamper::Form(_) => return None,
            Tamper::ChannelExists => ChannelAlreadyOpen,
            Tamper::ExpiresAt(_) => VoucherExpired,
            Tamper::ValidAfter(_) => NotYetActive,
        })
    }

    pub fn describe(&self) -> String {
        match self {
            Tamper::PayloadKey(k, v) => format!("client payload carries {k} = {v}"),
            Tamper::PayloadValue(k, v) => format!("payload.{k} set to {v}"),
            Tamper::PayloadRemove(k) => format!("payload.{k} removed"),
            Tamper::Accepted(k, v) => format!("accepted.{k} set to {v}"),
            Tamper::OpenAccount(slot, k) => format!("open account #{slot} set to {k}"),
            Tamper::ChannelNotDerived => {
                "open channel account (and its token account) set to the PDA of another salt".into()
            }
            Tamper::OpenDeposit(d) => format!("open deposit argument set to {d}"),
            Tamper::OpenGracePeriod(g) => format!("open grace_period argument set to {g}"),
            Tamper::OpenSlotArg(s) => format!("open open_slot argument set to {s}"),
            Tamper::OpenRecipients(r) => format!("open recipients set to {r:?}"),
            Tamper::OpenSaltRederived(s) => {
                format!("open salt set to {s} with the channel re-derived; payload.nonce unchanged")
            }
            Tamper::OpenTrailingByte => "a trailing byte appended to the open data".into(),
            Tamper::OpenTruncated => "the open data truncated by one byte".into(),
            Tamper::OpenExtraAccount => "a fifteenth (remaining) account on open".into(),
            Tamper::OpenMissingAccount => "the fourteenth open account removed".into(),
            Tamper::OpenWritableMint => "the mint account made writable".into(),
            Tamper::OpenDiscriminator(d) => format!("open discriminator set to {d}"),
            Tamper::OpenProgram(p) => format!("open invoked on program {p}"),
            Tamper::Prefix(p) => {
                format!("ComputeBudget prefix replaced ({} instructions)", p.len())
            }
            Tamper::Suffix(s) => format!("suffix replaced ({} instructions)", s.len()),
            Tamper::BeforeOpen(ix) => {
                format!("instruction of {} inserted before open", ix.program_id)
            }
            Tamper::DropOpen => "open instruction removed".into(),
            Tamper::DuplicateOpen => "a second open in the suffix".into(),
            Tamper::FeePayerInSuffix(at) => format!("fee payer listed in suffix instruction #{at}"),
            Tamper::FeePayerAsProgram => {
                "a suffix instruction invokes the fee payer as its program".into()
            }
            Tamper::ExtraSigner => "a third key added as a required signer".into(),
            Tamper::ClientPaysFees => "the client is the transaction fee payer".into(),
            Tamper::Signature(s) => format!("payer signature {s:?}"),
            Tamper::Form(f) => format!("message form {f:?}"),
            Tamper::ChannelExists => "the channel account already exists on chain".into(),
            Tamper::ExpiresAt(d) => format!("payload.expiresAt = now {d:+}"),
            Tamper::ValidAfter(d) => format!("payload.validAfter = now {d:+}"),
        }
    }

    pub fn apply(&self, spec: &mut VerifySpec) {
        match self {
            Tamper::PayloadKey(k, v) | Tamper::PayloadValue(k, v) => spec.set(k, v.clone()),
            Tamper::PayloadRemove(k) => {
                spec.payload.remove(*k);
            }
            Tamper::Accepted(path, v) => {
                let mut target = &mut spec.accepted;
                let parts: Vec<&str> = path.split('.').collect();
                for part in &parts[..parts.len() - 1] {
                    target = &mut target[*part];
                }
                target[parts[parts.len() - 1]] = v.clone();
            }
            Tamper::OpenAccount(slot, k) => spec.tx.open.accounts[*slot].pubkey = *k,
            Tamper::ChannelNotDerived => {
                let mut other = spec.open.clone();
                other.salt += 1;
                let channel = other.channel();
                let (ata, _) = pc::find_associated_token_address(
                    &channel,
                    &spec.open.mint,
                    &spec.open.token_program,
                );
                let ix = &mut spec.tx.open;
                ix.accounts[5].pubkey = channel;
                ix.accounts[7].pubkey = ata;
            }
            Tamper::OpenDeposit(d) => {
                spec.open.deposit = *d;
                spec.rebuild_open();
            }
            Tamper::OpenGracePeriod(g) => {
                spec.open.grace_period = *g;
                spec.rebuild_open();
            }
            Tamper::OpenSlotArg(s) => {
                let channel = spec.open.channel();
                spec.open.open_slot = *s;
                spec.rebuild_open();
                // Keep the channel the payload names (only the argument lies).
                let (ata, _) = pc::find_associated_token_address(
                    &channel,
                    &spec.open.mint,
                    &spec.open.token_program,
                );
                spec.tx.open.accounts[5].pubkey = channel;
                spec.tx.open.accounts[7].pubkey = ata;
            }
            Tamper::OpenRecipients(r) => {
                spec.open.recipients = r.clone();
                spec.rebuild_open();
            }
            Tamper::OpenSaltRederived(s) => {
                spec.open.salt = *s;
                spec.rebuild_open();
                spec.set("channelId", json!(spec.open.channel().to_string()));
            }
            Tamper::OpenTrailingByte => spec.tx.open.data.push(0),
            Tamper::OpenTruncated => {
                spec.tx.open.data.pop();
            }
            Tamper::OpenExtraAccount => spec
                .tx
                .open
                .accounts
                .push(AccountMeta::new_readonly(stranger(), false)),
            Tamper::OpenMissingAccount => {
                spec.tx.open.accounts.pop();
            }
            Tamper::OpenWritableMint => spec.tx.open.accounts[3].is_writable = true,
            Tamper::OpenDiscriminator(d) => spec.tx.open.data[0] = *d,
            Tamper::OpenProgram(p) => spec.tx.open.program_id = *p,
            Tamper::Prefix(p) => spec.tx.prefix = p.clone(),
            Tamper::Suffix(s) => spec.tx.suffix = s.clone(),
            Tamper::BeforeOpen(ix) => {
                let open = spec.tx.open.clone();
                spec.tx.open = ix.clone();
                spec.tx.suffix.insert(0, open);
            }
            Tamper::DropOpen => {
                // The first suffix instruction takes the open's place.
                spec.tx.open = spec.tx.suffix.remove(0);
            }
            Tamper::DuplicateOpen => {
                let open = spec.tx.open.clone();
                spec.tx.suffix.insert(0, open);
            }
            Tamper::FeePayerInSuffix(at) => {
                let fee_payer = spec.tx.fee_payer;
                spec.tx.suffix[*at]
                    .accounts
                    .push(AccountMeta::new_readonly(fee_payer, false));
            }
            Tamper::FeePayerAsProgram => {
                let mut ix = lighthouse_ix(&spec.open);
                ix.program_id = spec.tx.fee_payer;
                spec.tx.suffix.insert(0, ix);
            }
            Tamper::ExtraSigner => {
                spec.tx.suffix[0]
                    .accounts
                    .push(AccountMeta::new_readonly(stranger(), true));
                spec.tx.extra_signers.push(STRANGER_SEED);
            }
            Tamper::ClientPaysFees => spec.tx.fee_payer = client(),
            Tamper::Signature(s) => spec.tx.payer_signature = *s,
            Tamper::Form(f) => {
                if matches!(f, Form::V1 { .. }) {
                    spec.tx.prefix.clear();
                }
                spec.tx.form = f.clone();
            }
            Tamper::ChannelExists => spec.channel_exists = true,
            Tamper::ExpiresAt(d) => spec.set("expiresAt", json!(NOW + d)),
            Tamper::ValidAfter(d) => spec.set("validAfter", json!(NOW + d)),
        }
    }
}

// ── reject classification ──────────────────────────────────────────────────

/// The shared code for a kit upto error message. Mirrored in the Rust
/// testee (`vector_runner/upto.rs`).
pub fn code_for(message: &str) -> Option<RejectCode> {
    use RejectCode::*;
    let m = message.to_ascii_lowercase();
    let has = |n: &str| m.contains(n);
    Some(
        if has("is not accepted; accepted versions") || has("signer signs up to version") {
            UnsupportedVersion
        } else if has("compute unit price") && (has("exceed") || has("maximum")) {
            ComputePriceOverCap
        } else if has("compute unit limit") && (has("exceed") || has("maximum")) {
            ComputeLimitOverCap
        } else if has("must not reference the fee payer") {
            FeePayerNotAuthority
        } else if has("fee payer must be the advertised fee payer")
            || has("loaded accounts data size")
            || has("must set computeunitlimit")
        {
            InvalidPayload
        } else if has("computebudget")
            || has("setcomputeunit")
            || has("compute unit limit must be positive")
            || has("no payment-channels instruction")
            || has("targets an unexpected program")
            || has("is not a payment-channels")
            || has("instructions after")
            || has("lighthouse instructions")
            || has("must be lighthouse or memo")
        {
            UnexpectedInstruction
        } else if has("memo") {
            InvalidPayload
        } else if has("open transaction channel mismatch") || has("open channel pda") {
            ChannelIdMismatch
        } else if has("open transaction")
            || has("open salt")
            || has("open slot")
            || has("open withdraw delay")
            || has("open deposit")
            || has("open distribution")
            || has("open instruction")
        {
            OpenBindingMismatch
        } else if has("amount mismatch") {
            AmountMismatch
        } else if has("channel deposit") && has("authorized maximum") {
            DepositNotCeiling
        } else if has("not yet active") {
            NotYetActive
        } else if has("authorization expired") {
            VoucherExpired
        } else if has("advertised receiver authorizer") {
            ReceiverAuthorizerMismatch
        } else if has("network mismatch")
            || has("does not match any offered")
            || has("invalid payload type")
        {
            AcceptedMismatch
        } else if has("address lookup tables")
            || has("byte limit")
            || has("exceeds")
            || has("invalid")
            || has("requires opentransaction")
            || has("decode")
        {
            InvalidPayload
        } else if has("withdrawdelay") || has("missing field") {
            InvalidChallenge
        } else {
            return None;
        },
    )
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
        Mode::CanonicalBytes => canonical(input),
        Mode::BuildTransaction => build(input).await,
        Mode::VerifyTransaction => verify(input).await,
    }
}

fn str_of<'a>(input: &'a Value, key: &str) -> Result<&'a str, String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("input.{key} missing"))
}

fn signer(input: &Value, key: &str) -> Result<MemorySigner, String> {
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

fn canonical(input: &Value) -> Result<Observed, String> {
    let mut exact = Map::new();
    let set_bytes = |exact: &mut Map<String, Value>, bytes: &[u8]| {
        exact.insert("bytes".into(), json!(bytes));
        exact.insert(
            "base64Url".into(),
            json!(solana_pay_kit::mpp::protocol::core::base64url_encode(bytes)),
        );
    };
    if let Some(v) = input.get("x402UptoVoucher") {
        let channel =
            match Pubkey::from_str(v.get("channelId").and_then(Value::as_str).unwrap_or("")) {
                Ok(c) => c,
                Err(e) => return Ok(reject(format!("invalid payload: channelId: {e}"))),
            };
        let cumulative: u64 = match v.get("cumulativeAmount") {
            Some(Value::String(s)) => s.parse().map_err(|_| "invalid cumulativeAmount")?,
            Some(n) => n.as_u64().ok_or("invalid cumulativeAmount")?,
            None => return Err("cumulativeAmount missing".into()),
        };
        let expires_at = v.get("expiresAt").and_then(Value::as_i64).unwrap_or(0);
        match pc::voucher_message_bytes(&channel, cumulative, expires_at) {
            Ok(bytes) => set_bytes(&mut exact, &bytes),
            Err(e) => return Ok(reject(format!("invalid payload: {e}"))),
        }
    }
    if let Some(d) = input.get("x402UptoDistribution") {
        let recipients = d
            .get("recipients")
            .and_then(Value::as_array)
            .ok_or("recipients missing")?
            .iter()
            .map(|r| {
                Ok(pc::Distribution {
                    recipient: Pubkey::from_str(r["recipient"].as_str().unwrap_or(""))
                        .map_err(|e| e.to_string())?,
                    bps: r["bps"].as_u64().ok_or("bps")? as u16,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        set_bytes(&mut exact, &pc::distribution_hash(&recipients));
    }
    if let Some(p) = input.get("x402UptoChannelPda") {
        let k = |name: &str| -> Result<Pubkey, String> {
            Pubkey::from_str(p[name].as_str().unwrap_or("")).map_err(|e| format!("{name}: {e}"))
        };
        let n = |name: &str| -> Result<u64, String> {
            p[name]
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("{name} must be a decimal u64"))
        };
        let (pda, _) = pc::find_channel_pda(
            &k("payer")?,
            &k("payee")?,
            &k("mint")?,
            &k("authorizedSigner")?,
            n("salt")?,
            n("openSlot")?,
            &pc::default_program_id(),
        );
        set_bytes(&mut exact, pda.as_ref());
    }
    Ok(Observed::Accept(Output {
        exact: Some(exact),
        ..Default::default()
    }))
}

/// A summary of an open transaction an authored build case can pin
/// (`expect.exactBytes`): message version, memo, compute budget carrier.
pub fn open_summary(header: &str, offer: &Value) -> Result<Map<String, Value>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header)
        .map_err(|e| format!("header base64: {e}"))?;
    let envelope: Value = serde_json::from_slice(&bytes).map_err(|e| format!("header: {e}"))?;
    let tx = decode_b64(
        envelope
            .pointer("/payload/openTransaction")
            .and_then(Value::as_str)
            .ok_or("payload.openTransaction missing")?,
    )?;
    let keys = tx.message.static_account_keys();
    let program = |ix: &solana_message::compiled_instruction::CompiledInstruction| {
        keys.get(ix.program_id_index as usize)
            .map(|k| k.to_string())
            .unwrap_or_default()
    };
    let memos: Vec<String> = tx
        .message
        .instructions()
        .iter()
        .filter(|ix| program(ix) == keys::MEMO_PROGRAM)
        .map(|ix| String::from_utf8_lossy(&ix.data).into_owned())
        .collect();
    let declared = offer
        .pointer("/extra/memo")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty());
    let memo = match (memos.as_slice(), declared) {
        ([], _) => "none",
        ([one], Some(d)) if one == d => "declared",
        ([one], None) if one.len() >= 32 && one.bytes().all(|b| b.is_ascii_hexdigit()) => "nonce",
        _ => "other",
    };
    let compute_budget_ixs = tx
        .message
        .instructions()
        .iter()
        .filter(|ix| program(ix) == keys::COMPUTE_BUDGET_PROGRAM)
        .count();
    let (version, budget) = match &tx.message {
        VersionedMessage::Legacy(_) => (json!("legacy"), compute_budget_ixs > 0),
        VersionedMessage::V0(_) => (json!(0), compute_budget_ixs > 0),
        VersionedMessage::V1(_) => (json!(1), compute_budget_ixs > 0),
    };
    let carrier = match (&tx.message, budget) {
        (_, true) => "instructions",
        (VersionedMessage::V1(_), false) => "header",
        _ => "none",
    };
    let mut out = Map::new();
    out.insert("openMessageVersion".into(), version);
    out.insert("openMemo".into(), json!(memo));
    out.insert("openComputeBudget".into(), json!(carrier));
    Ok(out)
}

async fn build(input: &Value) -> Result<Observed, String> {
    let offer = input.get("x402Offer").ok_or("input.x402Offer missing")?;
    let requirements: UptoRequirements = match serde_json::from_value(offer.clone()) {
        Ok(r) => r,
        Err(e) => {
            return Ok(Observed::Reject {
                code: Some(RejectCode::InvalidChallenge),
                message: format!("invalid challenge: x402Offer: {e}"),
            })
        }
    };
    let signer = signer(input, "signerSecretKey")?;
    let (rpc, _log) = fixture_rpc::rpc_client(&Fixtures::from_input(input)?);
    let expires_at = input
        .get("x402UptoExpiresAt")
        .and_then(Value::as_i64)
        .ok_or("input.x402UptoExpiresAt missing")?;
    let nonce = input
        .get("x402UptoRequestNonce")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let max_version = match input.get("x402ClientMaxTransactionVersion") {
        None => None,
        Some(v) => Some(
            TxVersion::try_from(v.as_u64().ok_or("x402ClientMaxTransactionVersion")? as u8)
                .map_err(|e| e.to_string())?,
        ),
    };
    Ok(
        match build_upto_header(&signer, &rpc, &requirements, expires_at, nonce, max_version).await
        {
            Ok(header) => Observed::Accept(Output {
                exact: Some(open_summary(&header, offer)?),
                header: Some(header),
                ..Default::default()
            }),
            Err(e) => {
                let message = e.to_string();
                let code = if message.contains("memo is") {
                    Some(RejectCode::InvalidChallenge)
                } else {
                    code_for(&message).map(|c| match c {
                        // The client refuses a challenge it cannot honour.
                        RejectCode::InvalidPayload => RejectCode::InvalidChallenge,
                        other => other,
                    })
                };
                Observed::Reject { code, message }
            }
        },
    )
}

/// The kit's server (`X402Upto`) configured from the `x402Server*` keys.
fn server(input: &Value, rpc_url: &str) -> Result<X402Upto, String> {
    let fixtures = Fixtures::from_input(input)?;
    let currency = str_of(input, "x402ServerCurrency")?;
    let decimals = fixtures
        .mints
        .get(currency)
        .map(|m| m.decimals)
        .unwrap_or(6);
    let fee_payer = signer(input, "x402ServerFeePayerSecretKey")?;
    let receiver = signer(input, "x402ServerReceiverAuthorizerSecretKey")?;
    let number = |k: &str| {
        input
            .get(k)
            .and_then(Value::as_u64)
            .ok_or(format!("input.{k} missing"))
    };
    let config = UptoConfig {
        payout: UptoPayout::Beneficiary {
            address: str_of(input, "x402ServerRecipient")?.to_string(),
        },
        currencies: vec![CurrencyConfig {
            currency: currency.to_string(),
            decimals,
            token_program: input
                .get("x402ServerTokenProgram")
                .and_then(Value::as_str)
                .map(str::to_string),
        }],
        cluster: str_of(input, "x402ServerNetwork")?.to_string(),
        rpc_url: Some(rpc_url.to_string()),
        resource: String::new(),
        description: None,
        max_timeout_seconds: number("x402ServerMaxTimeoutSeconds")?,
        program_id: None,
        withdraw_delay: number("x402ServerWithdrawDelay")? as u32,
        fee_payer_signer: Arc::new(fee_payer),
        receiver_authorizer_signer: Some(Arc::new(receiver)),
    };
    let server = X402Upto::new(config).map_err(|e| format!("server config: {e}"))?;
    let v1 = input
        .get("x402ServerTransactionVersions")
        .and_then(Value::as_array)
        .is_some_and(|v| v.iter().any(|x| x.as_u64() == Some(1)));
    Ok(if v1 {
        server.with_tx_v1(TxV1Mode::On)
    } else {
        server
    })
}

async fn verify(input: &Value) -> Result<Observed, String> {
    let header = str_of(input, "x402PaymentHeader")?;
    let fixture = HttpFixture::start(&Fixtures::from_input(input)?).map_err(|e| e.to_string())?;
    let server = server(input, fixture.url())?;
    let now = input
        .get("nowSeconds")
        .and_then(Value::as_i64)
        .ok_or("input.nowSeconds missing")?;
    let route = input.get("x402ServerRoute").and_then(Value::as_str);
    let amount = str_of(input, "x402ServerAmount")?;
    Ok(
        match verify_open_pre_broadcast(&server, header, amount, route, now).await {
            Ok(()) => Observed::Accept(Output {
                header: Some(header.to_string()),
                ..Default::default()
            }),
            Err(e) => reject(e.to_string()),
        },
    )
}

// ── build judging ──────────────────────────────────────────────────────────

/// The verify input a header built against `build_input`'s offer turns
/// into: the route the offer advertises, the same fixtures and clock.
pub fn verify_input_for_offer(build_input: &Value, header: &str) -> Result<Value, String> {
    let offer = build_input.get("x402Offer").ok_or("no x402Offer")?;
    let s = |p: &str| offer.pointer(p).and_then(Value::as_str).unwrap_or_default();
    let secret = |address: &str| {
        seed_of(address)
            .map(keys::secret_json)
            .ok_or_else(|| format!("the harness holds no key for {address}"))
    };
    let network = crate::run::judge::cluster_for_caip2(s("/network"))
        .ok_or_else(|| format!("unknown network {}", s("/network")))?;
    let mut input = json!({
        "x402PaymentHeader": header,
        "x402ServerNetwork": network,
        "x402ServerRecipient": s("/payTo"),
        "x402ServerCurrency": s("/asset"),
        "x402ServerAmount": s("/amount"),
        "x402ServerFeePayer": s("/extra/feePayer"),
        "x402ServerFeePayerSecretKey": secret(s("/extra/feePayer"))?,
        "x402ServerReceiverAuthorizer": s("/extra/receiverAuthorizer"),
        "x402ServerReceiverAuthorizerSecretKey": secret(s("/extra/receiverAuthorizer"))?,
        "x402ServerWithdrawDelay": offer.pointer("/extra/withdrawDelay").cloned().unwrap_or(Value::Null),
        "x402ServerMaxTimeoutSeconds": offer.get("maxTimeoutSeconds").cloned().unwrap_or(Value::Null),
        "x402ServerMaxChannelLifetimeSeconds": 3_600,
        "nowSeconds": build_input.get("nowSeconds").cloned().unwrap_or(json!(NOW)),
        "rpcFixtures": build_input.get("rpcFixtures").cloned().unwrap_or(json!({})),
    });
    let token_program = offer
        .pointer("/extra/tokenProgram")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            build_input
                .pointer(&format!("/rpcFixtures/mints/{}/owner", s("/asset")))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    if let Some(tp) = token_program {
        input["x402ServerTokenProgram"] = json!(tp);
    }
    if let Some(memo) = offer.pointer("/extra/memo").and_then(Value::as_str) {
        input["x402ServerMemo"] = json!(memo);
        if memo == route_memo() {
            input["x402ServerRoute"] = json!(ROUTE);
        }
    }
    if let Some(versions) = offer.pointer("/extra/transactionVersions") {
        input["x402ServerTransactionVersions"] = versions.clone();
    }
    Ok(input)
}

/// The kit types `extra.recentSlot` as a string while the spec's table and
/// examples use a number (RULINGS.md U1). The judge reads a numeric slot as
/// its decimal string, so that divergence alone is bypassed: every other
/// field reaches the kit's verifier and reference build unchanged.
fn stringify_recent_slot(value: &mut Value, pointer: &str) {
    if let Some(slot) = value.pointer_mut(pointer) {
        if let Some(n) = slot.as_u64() {
            *slot = json!(n.to_string());
        }
    }
}

/// The vector input as the kit's client can read it, for the reference build.
fn kit_reference_input(input: &Value) -> Value {
    let mut input = input.clone();
    stringify_recent_slot(&mut input, "/x402Offer/extra/recentSlot");
    input
}

/// The SDK's header as the kit's verifier can read it; the open transaction
/// is untouched.
fn kit_reference_header(header: &str) -> Result<String, String> {
    let mut envelope = decode_header(header)?;
    if !envelope
        .pointer("/accepted/extra/recentSlot")
        .is_some_and(Value::is_u64)
    {
        return Ok(header.to_string());
    }
    stringify_recent_slot(&mut envelope, "/accepted/extra/recentSlot");
    let bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn decode_header(header: &str) -> Result<Value, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header)
        .map_err(|e| format!("payment header base64: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("payment header JSON: {e}"))
}

/// The open instruction of a header's transaction: (accounts, data).
fn open_of(envelope: &Value) -> Result<(Vec<AccountMeta>, Vec<u8>, VersionedTransaction), String> {
    let tx = decode_b64(
        envelope
            .pointer("/payload/openTransaction")
            .and_then(Value::as_str)
            .ok_or("payload.openTransaction missing")?,
    )?;
    let program = pc::default_program_id();
    let keys = tx.message.static_account_keys().to_vec();
    let header = tx.message.header();
    let signed = header.num_required_signatures as usize;
    let ro_signed = header.num_readonly_signed_accounts as usize;
    let ro_unsigned = header.num_readonly_unsigned_accounts as usize;
    let writable = |i: usize| {
        if i < signed {
            i < signed - ro_signed
        } else {
            i < keys.len() - ro_unsigned
        }
    };
    let ix = tx
        .message
        .instructions()
        .iter()
        .find(|ix| keys.get(ix.program_id_index as usize) == Some(&program))
        .ok_or("the transaction has no payment-channels instruction")?;
    let accounts = ix
        .accounts
        .iter()
        .map(|&a| AccountMeta {
            pubkey: keys[a as usize],
            is_signer: (a as usize) < signed,
            is_writable: writable(a as usize),
        })
        .collect();
    Ok((accounts, ix.data.clone(), tx))
}

/// `header` with its declared memo replaced by [`route_memo`], in
/// `accepted.extra.memo` and in the open transaction's memo instruction,
/// whose signer slots are re-signed with the keys the harness holds.
fn with_route_memo(header: &str) -> Result<String, String> {
    let mut envelope = decode_header(header)?;
    let declared = envelope
        .pointer("/accepted/extra/memo")
        .and_then(Value::as_str)
        .ok_or("accepted.extra.memo missing")?
        .to_string();
    let tx = decode_b64(
        envelope
            .pointer("/payload/openTransaction")
            .and_then(Value::as_str)
            .ok_or("payload.openTransaction missing")?,
    )?;
    let mut d = crate::tx::decompile(&tx.message)?;
    let memo_program = keys::pubkey(keys::MEMO_PROGRAM);
    let mut replaced = 0;
    for ix in &mut d.instructions {
        if ix.program_id == memo_program && ix.data == declared.as_bytes() {
            ix.data = route_memo().into_bytes();
            replaced += 1;
        }
    }
    if replaced != 1 {
        return Err(format!(
            "the open carries the declared memo {replaced} times, expected once"
        ));
    }
    let mut out = crate::tx::recompile(&tx.message, &d)?;
    let required = out.message.header().num_required_signatures as usize;
    let seeds: Vec<[u8; 32]> = out
        .message
        .static_account_keys()
        .iter()
        .take(required)
        .zip(&tx.signatures)
        .filter(|(_, sig)| **sig != Signature::default())
        .filter_map(|(key, _)| seed_of(&key.to_string()))
        .collect();
    sign_slots(&mut out, &seeds);
    envelope["accepted"]["extra"]["memo"] = json!(route_memo());
    envelope["payload"]["openTransaction"] = json!(encode_b64(&out)?);
    let bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Judge an accepted SDK build of an `x402-upto` vector.
///
/// Always: the open-transaction summary the vector pins
/// (`expect.exactBytes`). For generated vectors (the kit is the oracle)
/// additionally: the Rust verifier, offline at the vector's clock, accepts
/// the header against the route the offer advertises; `accepted` echoes the
/// offer; and the open instruction equals the kit's own build modulo the
/// values a client chooses freely (salt, hence channel and its token
/// account) — accounts, privileges, deposit, grace period, open slot and
/// distribution must match. Authored vectors get the same checks: the
/// reference build reads them through [`kit_reference_input`], which bypasses
/// only the recorded kit divergence, and the summary pins what the spec asks
/// for where the kit differs (the memo).
pub async fn judge_build(vector: &Vector, artifact: &str) -> Result<(), Failure> {
    let offer = vector
        .input()
        .get("x402Offer")
        .cloned()
        .unwrap_or(Value::Null);
    // The envelope (version, lookup tables, size and counts) is checked on
    // the SDK's own bytes first: the declared-memo path below verifies a
    // copy with a shorter memo, which the size limit would not see.
    {
        let envelope = decode_header(artifact).map_err(Failure::new)?;
        let open = decode_b64(
            envelope
                .pointer("/payload/openTransaction")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
        .map_err(Failure::new)?;
        let advertised: Option<Vec<TxVersion>> = offer
            .pointer("/extra/transactionVersions")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let accepted = solana_pay_kit::core::tx::accepted_versions(advertised.as_deref());
        if let Err(e) = solana_pay_kit::core::tx::check_envelope(&open, accepted) {
            return Err(Failure {
                message: format!("the SDK's open fails the transaction envelope: {e}"),
                path: Some("verify.envelope".into()),
                expected: Some(json!("accept")),
                actual: Some(json!(e.to_string())),
            });
        }
    }
    let summary = open_summary(artifact, &offer).map_err(Failure::new)?;
    if let Some(Value::Object(pinned)) = vector.expect().get("exactBytes") {
        for (k, want) in pinned {
            if summary.get(k) != Some(want) {
                return Err(Failure {
                    message: format!(
                        "open transaction {k}: expected {want}, the SDK built {}",
                        summary.get(k).cloned().unwrap_or(Value::Null)
                    ),
                    path: Some(format!("exactBytes.{k}")),
                    expected: Some(want.clone()),
                    actual: summary.get(k).cloned(),
                });
            }
        }
    }
    // The kit's server derives its memo from the route, so it cannot offer
    // any other declared memo; the open is still compared with the kit's build.
    let server_can_offer = offer
        .pointer("/extra/memo")
        .and_then(Value::as_str)
        .is_none_or(|memo| memo == route_memo());
    // Otherwise the verifier still runs on everything but the memo (the
    // summary pins that): the SDK's own open with the memo the kit can
    // offer, re-signed with the harness keys, so the envelope, budget caps,
    // expiry, slot window and instruction allowlist are judged too.
    let header = if server_can_offer {
        kit_reference_header(artifact)
    } else {
        kit_reference_header(artifact).and_then(|h| with_route_memo(&h))
    }
    .map_err(Failure::new)?;
    let mut offered = vector.input().clone();
    if !server_can_offer {
        offered["x402Offer"]["extra"]["memo"] = json!(route_memo());
    }
    let input = verify_input_for_offer(&offered, &header).map_err(Failure::new)?;
    let verified = verify(&input).await;
    match verified {
        Ok(Observed::Accept(_)) => {}
        Ok(other) => {
            return Err(Failure {
                message: format!(
                    "the Rust kit's upto verifier refuses the SDK's build: {}",
                    other.summary()
                ),
                path: Some("verify".into()),
                expected: Some(json!("accept")),
                actual: Some(json!(other.summary())),
            })
        }
        Err(e) => return Err(Failure::new(format!("verify setup: {e}"))),
    }
    let reference = match build(&kit_reference_input(vector.input())).await {
        Ok(Observed::Accept(output)) => output.header.unwrap_or_default(),
        Ok(other) => {
            return Err(Failure::new(format!(
                "the Rust kit cannot build this case ({}); the vector is wrong, file against the filler",
                other.summary()
            )))
        }
        Err(e) => return Err(Failure::new(e)),
    };
    let want = decode_header(&reference).map_err(Failure::new)?;
    let got = decode_header(artifact).map_err(Failure::new)?;
    let mut problems = Vec::new();
    if got.get("x402Version") != Some(&json!(2)) {
        problems.push(format!("x402Version {}", got["x402Version"]));
    }
    for key in ["scheme", "network", "amount", "asset", "payTo"] {
        if got["accepted"].get(key) != offer.get(key) {
            problems.push(format!(
                "accepted.{key} {} (offer: {})",
                got["accepted"][key], offer[key]
            ));
        }
    }
    for key in [
        "from",
        "maxAmount",
        "deposit",
        "authorizedSigner",
        "openSlot",
    ] {
        if got["payload"].get(key) != want["payload"].get(key) {
            problems.push(format!(
                "payload.{key} {} (Rust: {})",
                got["payload"][key], want["payload"][key]
            ));
        }
    }
    let (want_accounts, want_data, _) = open_of(&want).map_err(Failure::new)?;
    let (got_accounts, got_data, got_tx) = open_of(&got).map_err(Failure::new)?;
    if got_accounts.len() != want_accounts.len() {
        problems.push(format!(
            "open has {} accounts (Rust: {})",
            got_accounts.len(),
            want_accounts.len()
        ));
    } else {
        for (slot, (g, w)) in got_accounts.iter().zip(&want_accounts).enumerate() {
            let free = slot == 5 || slot == 7;
            if (!free && g.pubkey != w.pubkey) || g.is_writable != w.is_writable {
                problems.push(format!(
                    "open account #{slot} {} (w={}) (Rust: {} w={})",
                    g.pubkey, g.is_writable, w.pubkey, w.is_writable
                ));
            }
        }
    }
    // [discriminator][salt u64][rest]: the salt is the client's choice.
    let strip = |d: &[u8]| -> Vec<u8> {
        let mut out = d.first().copied().into_iter().collect::<Vec<u8>>();
        out.extend(d.iter().skip(9));
        out
    };
    if strip(&got_data) != strip(&want_data) {
        problems.push("open arguments other than the salt differ from the kit's build".into());
    }
    // The channel is the PDA of the SDK's own salt.
    if got_data.len() >= 9 {
        let salt = u64::from_le_bytes(got_data[1..9].try_into().unwrap());
        let a = |i: usize| got_accounts.get(i).map(|m| m.pubkey).unwrap_or_default();
        let (pda, _) = pc::find_channel_pda(
            &a(0),
            &a(2),
            &a(3),
            &a(4),
            salt,
            u64::from_le_bytes(got_data.get(21..29).unwrap_or(&[0; 8]).try_into().unwrap()),
            &pc::default_program_id(),
        );
        if got["payload"]["channelId"] != json!(pda.to_string()) || a(5) != pda {
            problems.push(format!(
                "channelId {} / open channel {} is not the PDA of the open's own seeds ({pda})",
                got["payload"]["channelId"],
                a(5)
            ));
        }
        if got["payload"]["nonce"] != json!(salt.to_string()) {
            problems.push(format!(
                "payload.nonce {} is not the open salt {salt}",
                got["payload"]["nonce"]
            ));
        }
    }
    if got_tx.message.static_account_keys().first()
        != Some(&keys::pubkey(
            offer
                .pointer("/extra/feePayer")
                .and_then(Value::as_str)
                .unwrap_or(keys::SYSTEM_PROGRAM),
        ))
    {
        problems.push("the transaction fee payer is not extra.feePayer".into());
    }
    // The client signs its own slots; only the sponsoring fee payer's slot is
    // left for the facilitator. Judged here because the kit's verifier does
    // not check the payer's signature (FINDINGS.md).
    let fee_payer = offer.pointer("/extra/feePayer").and_then(Value::as_str);
    let required = got_tx.message.header().num_required_signatures as usize;
    if got_tx.signatures.len() != required {
        problems.push(format!(
            "{} signatures for {required} required signers",
            got_tx.signatures.len()
        ));
    }
    for (key, slot) in crate::tx::signature_slots(&got_tx) {
        let ok = if Some(key.as_str()) == fee_payer {
            slot == crate::tx::Slot::Empty
        } else {
            slot == crate::tx::Slot::Signed
        };
        if !ok {
            problems.push(format!("signature slot of {key} is {slot:?}"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Failure::new(format!(
            "the build differs from the Rust kit's build of the same case: {}",
            problems.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::vectors;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    fn vector(id: &str) -> Vector {
        vectors::load(&crate::repo_root().join("harness/vectors"))
            .unwrap()
            .into_iter()
            .find(|v| v.id == id)
            .unwrap()
    }

    /// The kit's build of an authored vector (read past its recorded
    /// divergence), decoded, edited by `edit`, re-encoded.
    fn edited_build(rt: &tokio::runtime::Runtime, v: &Vector, edit: impl Fn(&mut Value)) -> String {
        let header = match rt.block_on(build(&kit_reference_input(v.input()))) {
            Ok(Observed::Accept(output)) => output.header.unwrap(),
            other => panic!("{}: {other:?}", v.id),
        };
        let mut envelope = decode_header(&header).unwrap();
        edit(&mut envelope);
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&envelope).unwrap())
    }

    // An authored vector pins only the field the kit gets wrong; the rest of
    // the build is still judged against the verifier and the kit's open.
    #[test]
    fn an_authored_build_is_judged_beyond_its_pinned_summary() {
        let rt = runtime();
        let v = vector("x402-upto-build-recent-slot-number");
        let honest = edited_build(&rt, &v, |_| {});
        rt.block_on(judge_build(&v, &honest)).unwrap();

        let unsigned = edited_build(&rt, &v, |e| {
            let mut tx = decode_b64(e["payload"]["openTransaction"].as_str().unwrap()).unwrap();
            for signature in &mut tx.signatures {
                *signature = Signature::default();
            }
            e["payload"]["openTransaction"] = json!(encode_b64(&tx).unwrap());
        });
        let failure = rt.block_on(judge_build(&v, &unsigned)).unwrap_err();
        assert!(
            failure.message.contains("signature slot"),
            "{}",
            failure.message
        );

        let underfunded = edited_build(&rt, &v, |e| e["payload"]["deposit"] = json!("1"));
        let failure = rt.block_on(judge_build(&v, &underfunded)).unwrap_err();
        assert!(failure.path.is_some(), "{}", failure.message);
    }

    // A declared memo the kit's server cannot offer used to skip the
    // verifier; the rest of the build is still judged by it.
    #[test]
    fn a_declared_memo_build_is_still_verified() {
        let rt = runtime();
        let v = vector("x402-upto-build-memo-max-length");
        let honest = edited_build(&rt, &v, |_| {});
        rt.block_on(judge_build(&v, &honest)).unwrap();

        let drained = edited_build(&rt, &v, |e| {
            let tx = decode_b64(e["payload"]["openTransaction"].as_str().unwrap()).unwrap();
            let mut d = crate::tx::decompile(&tx.message).unwrap();
            let mut data = 2u32.to_le_bytes().to_vec();
            data.extend_from_slice(&1_000_000u64.to_le_bytes());
            d.instructions.push(Instruction {
                program_id: keys::pubkey(keys::SYSTEM_PROGRAM),
                accounts: vec![
                    AccountMeta::new(d.fee_payer, true),
                    AccountMeta::new(Pubkey::new_unique(), false),
                ],
                data,
            });
            let mut out = crate::tx::recompile(&tx.message, &d).unwrap();
            let seeds: Vec<[u8; 32]> = KNOWN_SEEDS.to_vec();
            sign_slots(&mut out, &seeds);
            out.signatures[0] = Signature::default();
            e["payload"]["openTransaction"] = json!(encode_b64(&out).unwrap());
        });
        let failure = rt.block_on(judge_build(&v, &drained)).unwrap_err();
        assert_eq!(
            failure.path.as_deref(),
            Some("verify"),
            "{}",
            failure.message
        );

        // Over the version-0 size limit with the declared memo, under it once
        // the shorter route memo is swapped in: the envelope sees the SDK's bytes.
        let oversized = edited_build(&rt, &v, |e| {
            let tx = decode_b64(e["payload"]["openTransaction"].as_str().unwrap()).unwrap();
            let mut d = crate::tx::decompile(&tx.message).unwrap();
            let size = |d: &crate::tx::Decompiled| {
                let out = crate::tx::recompile(&tx.message, d).unwrap();
                solana_pay_kit::core::tx::serialized_size(&out).unwrap()
            };
            let mut pad = Instruction {
                program_id: keys::pubkey(keys::MEMO_PROGRAM),
                accounts: vec![],
                data: vec![],
            };
            d.instructions.push(pad.clone());
            let room = 1232usize.saturating_sub(size(&d));
            pad.data = vec![b'p'; room + 1];
            *d.instructions.last_mut().unwrap() = pad;
            let mut out = crate::tx::recompile(&tx.message, &d).unwrap();
            sign_slots(&mut out, &KNOWN_SEEDS);
            out.signatures[0] = Signature::default();
            e["payload"]["openTransaction"] = json!(encode_b64(&out).unwrap());
        });
        let failure = rt.block_on(judge_build(&v, &oversized)).unwrap_err();
        assert_eq!(
            failure.path.as_deref(),
            Some("verify.envelope"),
            "{}",
            failure.message
        );
    }
}
