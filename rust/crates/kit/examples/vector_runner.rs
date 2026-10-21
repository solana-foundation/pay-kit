//! Cross-SDK conformance-vector runner for the Rust SDK.
//!
//! Speaks the vector ABI defined in `harness/src/conformance/schema.ts`: read
//! one `ConformanceVector` as JSON on stdin, drive the REAL solana-pay-kit
//! code for the vector's intent and mode, and write one `RunnerResult` line
//! as JSON on stdout, or (`--serve`, testee ABI v2) one request per line in
//! a long-lived process. The harness driver (`pkc run`, rust/crates/conformance)
//! asserts the result and reconciles it against
//! `harness/expectations/rust.toml`.
//!
//! Rules this runner follows:
//!
//! - Protocol logic is never re-implemented here. Builders, verifiers,
//!   canonical encoders and wire parsers are the kit's own public API. Only
//!   the transaction-shape DECODER (the oracle's view of a built
//!   transaction) and the reject-message classifier live in this file, as
//!   in every other runner.
//! - Chain state comes only from the driver's fixture JSON-RPC
//!   (`input.rpcUrl`, built from `input.rpcFixtures`), handed to the kit's
//!   real `RpcClient`. Mint owners and decimals are read by the kit itself; a
//!   mint the fixture does not serve does not exist.
//! - The request is passed to the kit verbatim. No defaults are injected that
//!   the SDK would not apply itself, no field precedence is applied and no
//!   transaction is pinned or fabricated.
//! - Verify vectors run the kit's real verifiers: the charge pre-broadcast
//!   checks (`mpp::server::charge::testkit`, feature `testkit`) and the x402
//!   exact server's `verify_payment_signature_for_requirements`. Accept means
//!   that verification passed.
//! - When the public API cannot express a vector, the runner reports
//!   `unsupported-mode` with the precise reason.
//!
//! Run directly:
//!   cat vector.json | cargo run -q -p solana-pay-kit \
//!     --features mpp,x402,client,server,testkit --example vector_runner

use std::io::Read;

use serde_json::{json, Map, Value};
use solana_pay_kit::core::session::accept_voucher;
use solana_pay_kit::core::store::{
    ChannelState, ChannelStore, MemoryChannelStore, CHANNEL_STATE_SCHEMA_VERSION,
};
use solana_pay_kit::core::tx::TxVersion;
use solana_pay_kit::mpp::client::{
    build_charge_transaction_with_options, BuildChargeTransactionOptions, ComputeBudgetOptions,
};
use solana_pay_kit::mpp::protocol::core::{base64url_decode, compute_challenge_id, Base64UrlJson};
use solana_pay_kit::mpp::protocol::intents::session::{
    SessionAction, SessionAuthentication, SessionAuthenticationType, SessionRequest, VoucherData,
};
use solana_pay_kit::mpp::protocol::intents::ChargeRequest;
use solana_pay_kit::mpp::protocol::solana::{CredentialPayload, MethodDetails};
use solana_pay_kit::mpp::server::charge::testkit::verify_transaction_pre_broadcast;
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_pay_kit::mpp::solana_keychain::SolanaSigner;
use solana_pay_kit::x402::client::exact::{build_payment_header, build_payment_header_v1};
use solana_pay_kit::x402::protocol::schemes::exact::{
    generate_payment_identifier_id, PaymentExtensions, PaymentRequirements,
};
use solana_pay_kit::x402::server::exact::{
    Config as X402Config, ExactOptions, PaymentIdentifierPolicy, X402,
};
use solana_pay_kit::x402::server::CurrencyConfig;
use solana_rpc_client::rpc_client::RpcClient;

const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// Message versions the verifiers accept: the servers' default (version 0
/// only until a host opts into version 1).
const ACCEPTED_TX_VERSIONS: &[TxVersion] = &[TxVersion::V0];

/// Outcome of one vector, rendered as the RunnerResult JSON.
enum Outcome {
    Accept(Map<String, Value>),
    Reject(Rejection),
    Unsupported(String),
}

/// A reject: the kit's message plus, when the kit's error type pins the
/// category, the shared rejectCode (otherwise the message is classified).
struct Rejection {
    message: String,
    code: Option<&'static str>,
}

impl From<String> for Rejection {
    fn from(message: String) -> Self {
        Self {
            message,
            code: None,
        }
    }
}

impl From<&str> for Rejection {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

/// Charge client errors: a refused challenge is `invalid-challenge`.
impl From<solana_pay_kit::mpp::Error> for Rejection {
    fn from(error: solana_pay_kit::mpp::Error) -> Self {
        let code = match &error {
            solana_pay_kit::mpp::Error::InvalidChallenge(_) => Some("invalid-challenge"),
            _ => None,
        };
        Self {
            message: error.to_string(),
            code,
        }
    }
}

/// x402 errors: a missing or malformed required id is
/// `payment-identifier-required`.
impl From<solana_pay_kit::x402::Error> for Rejection {
    fn from(error: solana_pay_kit::x402::Error) -> Self {
        let code = match &error {
            solana_pay_kit::x402::Error::PaymentIdentifierRequired(_) => {
                Some("payment-identifier-required")
            }
            solana_pay_kit::x402::Error::WrongNetwork { .. } => Some("wrong-network"),
            solana_pay_kit::x402::Error::AcceptedMismatch => Some("accepted-mismatch"),
            _ => None,
        };
        Self {
            message: error.to_string(),
            code,
        }
    }
}

/// Intents this runner implements; `pkc run` checks them against
/// `harness/expectations/rust.toml`.
const INTENTS: [&str; 3] = ["charge", "x402-exact", "session"];

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if std::env::args().skip(1).any(|a| a == "--serve") {
        serve().await;
        return;
    }
    let mut raw = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut raw) {
        eprintln!("rust vector runner: failed to read stdin: {error}");
        std::process::exit(2);
    }
    let vector: Value = match serde_json::from_str(raw.trim()) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("rust vector runner: invalid vector JSON: {error}");
            std::process::exit(2);
        }
    };
    println!("{}", result_for(&vector).await);
}

/// Testee ABI v2 (`harness/README.md`): newline JSON `{id, op, input}` in,
/// `{id, ok, result | error}` out, one long-lived process. `input` is the v1
/// vector and `result` the v1 `RunnerResult`.
async fn serve() {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Err(error) => {
                json!({ "id": null, "ok": false, "error": "bad-request", "detail": error.to_string() })
            }
            Ok(request) => {
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                match request.get("op").and_then(Value::as_str) {
                    Some("capabilities") => json!({ "id": id, "ok": true, "result": {
                        "abi": 2, "language": "rust", "intents": INTENTS, "honoursClock": true,
                    }}),
                    Some("build" | "verify" | "canonical-bytes") => {
                        let input = request.get("input").cloned().unwrap_or(Value::Null);
                        json!({ "id": id, "ok": true, "result": result_for(&input).await })
                    }
                    other => {
                        json!({ "id": id, "ok": false, "error": "unknown-op", "detail": format!("{other:?}") })
                    }
                }
            }
        };
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{response}");
        let _ = stdout.flush();
    }
}

/// One vector to one `RunnerResult`.
async fn result_for(vector: &Value) -> Value {
    let id = vector
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let outcome = run_vector(vector).await.unwrap_or_else(Outcome::Reject);
    let mut result = Map::new();
    result.insert("id".into(), Value::String(id));
    match outcome {
        Outcome::Accept(fields) => {
            result.insert("outcome".into(), json!("accept"));
            result.extend(fields);
        }
        Outcome::Reject(Rejection { message, code }) => {
            result.insert("outcome".into(), json!("reject"));
            if let Some(code) = code.or_else(|| classify_reject(&message)) {
                result.insert("rejectCode".into(), json!(code));
            }
            result.insert("error".into(), Value::String(message));
        }
        Outcome::Unsupported(reason) => {
            result.insert("outcome".into(), json!("unsupported-mode"));
            result.insert(
                "error".into(),
                Value::String(format!("unsupported-mode: {reason}")),
            );
        }
    }
    Value::Object(result)
}

async fn run_vector(vector: &Value) -> Result<Outcome, Rejection> {
    let intent = str_field(vector, "intent");
    let mode = str_field(vector, "mode");
    let input = vector.get("input").cloned().unwrap_or(Value::Null);

    match (intent, mode) {
        ("x402-exact", "build-transaction") => x402_build(&input).await,
        ("x402-exact", "verify-transaction") => x402_verify(&input).await,
        ("session", "verify-transaction") => Ok(session_voucher_verify(&input).await?),
        (_, "canonical-bytes") => Ok(Outcome::Accept(canonical_bytes(&input)?)),
        ("charge", "build-transaction") => {
            let transaction = charge_build(&input).await?;
            let mut fields = shape_fields(&transaction)?;
            fields.insert("transaction".into(), Value::String(transaction));
            Ok(Outcome::Accept(fields))
        }
        ("charge", "verify-transaction") => charge_verify(&input).await,
        (intent, mode) => Ok(Outcome::Unsupported(format!(
            "no Rust runner path for intent {intent:?} mode {mode:?}"
        ))),
    }
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

// ── charge ──────────────────────────────────────────────────────────────────

/// The vector's decoded charge request, parsed by the KIT's own wire type.
/// Fields the kit does not model (e.g. the x402-style `asset` / `payTo`
/// precedence twins) are therefore ignored exactly as the SDK ignores them.
fn charge_request(input: &Value) -> Result<(ChargeRequest, MethodDetails), String> {
    let request = input
        .get("request")
        .ok_or("vector is missing input.request")?;
    let charge: ChargeRequest = serde_json::from_value(request.clone())
        .map_err(|e| format!("invalid payload: ChargeRequest: {e}"))?;
    let details: MethodDetails = match &charge.method_details {
        Some(md) => serde_json::from_value(md.clone())
            .map_err(|e| format!("invalid payload: methodDetails: {e}"))?,
        None => MethodDetails::default(),
    };
    Ok((charge, details))
}

fn signer_from(input: &Value) -> Result<MemorySigner, String> {
    let bytes: Vec<u8> = input
        .get("signerSecretKey")
        .and_then(Value::as_array)
        .ok_or("vector is missing input.signerSecretKey")?
        .iter()
        .map(|b| {
            b.as_u64()
                .map(|b| b as u8)
                .ok_or("signerSecretKey must be bytes")
        })
        .collect::<Result<_, _>>()?;
    MemorySigner::from_bytes(&bytes).map_err(|e| format!("invalid signerSecretKey: {e}"))
}

/// The kit's real RPC client on the driver's fixture JSON-RPC.
fn fixture_rpc(input: &Value) -> Result<RpcClient, String> {
    let url = input
        .get("rpcUrl")
        .and_then(Value::as_str)
        .ok_or("driver did not inject input.rpcUrl")?;
    Ok(RpcClient::new(url.to_string()))
}

/// Drive the real client builder. Compute-budget overrides come from the
/// vector (reject vectors use them to exercise server caps).
async fn charge_build(input: &Value) -> Result<String, Rejection> {
    let (charge, details) = charge_request(input)?;
    let signer = signer_from(input)?;
    let request = input.get("request").cloned().unwrap_or(Value::Null);

    let mut options = BuildChargeTransactionOptions {
        external_id: charge.external_id.clone(),
        ..Default::default()
    };
    let mut budget = ComputeBudgetOptions::default();
    if let Some(limit) = request.get("computeUnitLimit").and_then(Value::as_u64) {
        budget.compute_unit_limit = limit as u32;
    }
    if let Some(price) = request.get("computeUnitPrice") {
        let price = price
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| price.to_string());
        budget.compute_unit_price_micro_lamports = price
            .parse()
            .map_err(|_| format!("invalid computeUnitPrice {price}"))?;
    }
    options.compute_budget = budget;

    let recipient = charge
        .recipient
        .clone()
        .ok_or("vector request is missing recipient")?;
    let rpc = fixture_rpc(input)?;
    let payload = build_charge_transaction_with_options(
        &signer,
        &rpc,
        &charge.amount,
        &charge.currency,
        &recipient,
        &details,
        options,
    )
    .await?;
    match payload {
        CredentialPayload::Transaction { transaction } => Ok(transaction),
        other => Err(format!("builder returned a non-transaction payload: {other:?}").into()),
    }
}

/// Run the server's real pre-broadcast checks (the ones `Mpp::verify` applies
/// before it co-signs and broadcasts) on the vector's transaction, or on the
/// kit's own build when the vector carries none.
async fn charge_verify(input: &Value) -> Result<Outcome, Rejection> {
    let (charge, details) = charge_request(input)?;
    let transaction = match input.get("transaction").and_then(Value::as_str) {
        Some(tx) => tx.to_string(),
        None => charge_build(input).await?,
    };
    let tx = decode_transaction(&transaction)?;
    verify_transaction_pre_broadcast(&tx, &charge, &details, ACCEPTED_TX_VERSIONS)
        .map_err(|e| Rejection::from(e.message))?;
    Ok(Outcome::Accept(shape_fields(&transaction)?))
}

fn decode_transaction(
    transaction_b64: &str,
) -> Result<solana_transaction::versioned::VersionedTransaction, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(transaction_b64)
        .map_err(|e| format!("invalid payload: transaction base64: {e}"))?;
    solana_pay_kit::core::tx::decode_bytes(&bytes)
        .map_err(|e| format!("invalid payload: transaction decode: {e}"))
}

// ── transaction shape decoder (oracle view; mirrors decode.ts) ──────────────

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn shape_fields(transaction_b64: &str) -> Result<Map<String, Value>, String> {
    let tx = decode_transaction(transaction_b64)?;
    let keys: Vec<String> = tx
        .message
        .static_account_keys()
        .iter()
        .map(|k| k.to_string())
        .collect();
    if keys.is_empty() {
        return Err("transaction has no account keys".into());
    }

    let mut transfers = Vec::new();
    let mut memos = Vec::new();
    let mut limit: Option<u32> = None;
    let mut price: Option<u64> = None;
    for ix in tx.message.instructions() {
        let program = keys
            .get(ix.program_id_index as usize)
            .cloned()
            .unwrap_or_default();
        let data = ix.data.as_slice();
        let account = |i: usize| -> String {
            ix.accounts
                .get(i)
                .and_then(|a| keys.get(*a as usize))
                .cloned()
                .unwrap_or_default()
        };
        match program.as_str() {
            COMPUTE_BUDGET_PROGRAM => {
                if data.len() == 5 && data[0] == 2 {
                    limit = Some(read_u32(data, 1));
                } else if data.len() == 9 && data[0] == 3 {
                    price = Some(read_u64(data, 1));
                }
            }
            MEMO_PROGRAM => memos.push(Value::String(String::from_utf8_lossy(data).into_owned())),
            SYSTEM_PROGRAM
                if data.len() >= 12 && read_u32(data, 0) == 2 && ix.accounts.len() >= 2 =>
            {
                transfers.push(json!({
                    "kind": "sol",
                    "amount": read_u64(data, 4).to_string(),
                    "destination": account(1),
                }));
            }
            TOKEN_PROGRAM | TOKEN_2022_PROGRAM
                if data.len() >= 10 && data[0] == 12 && ix.accounts.len() >= 4 =>
            {
                transfers.push(json!({
                    "kind": "spl",
                    "amount": read_u64(data, 1).to_string(),
                    "decimals": data[9],
                    "destination": account(2),
                    "mint": account(1),
                    "tokenProgram": program,
                }));
            }
            _ => {}
        }
    }

    let mut shape = Map::new();
    shape.insert("feePayer".into(), Value::String(keys[0].clone()));
    shape.insert("forbiddenPrograms".into(), json!([]));
    shape.insert("memo".into(), Value::Array(memos));
    shape.insert("transfers".into(), Value::Array(transfers));
    if let Some(limit) = limit {
        shape.insert("maxComputeUnitLimit".into(), json!(limit));
    }
    if let Some(price) = price {
        shape.insert("maxComputeUnitPrice".into(), json!(price.to_string()));
    }
    let mut out = Map::new();
    out.insert("transactionShape".into(), Value::Object(shape));
    Ok(out)
}

// ── canonical bytes ─────────────────────────────────────────────────────────

/// JCS canonical JSON through the kit's own encoder (`Base64UrlJson`, used
/// for every `request` slot on the wire).
fn canonical_json(value: &Value) -> Result<(String, String), String> {
    let encoded = Base64UrlJson::from_value(value).map_err(|e| e.to_string())?;
    let bytes = base64url_decode(encoded.raw()).map_err(|e| e.to_string())?;
    let json = String::from_utf8(bytes).map_err(|e| e.to_string())?;
    Ok((json, encoded.raw().to_string()))
}

fn canonical_bytes(input: &Value) -> Result<Map<String, Value>, String> {
    let mut exact = Map::new();
    let set_bytes = |exact: &mut Map<String, Value>, bytes: &[u8]| {
        exact.insert("bytes".into(), json!(bytes));
        exact.insert(
            "base64Url".into(),
            json!(solana_pay_kit::mpp::protocol::core::base64url_encode(bytes)),
        );
    };

    if let Some(value) = input.get("value").filter(|v| !v.is_null()) {
        let (json, b64) = canonical_json(value)?;
        exact.insert("canonicalJson".into(), json!(json));
        exact.insert("base64Url".into(), json!(b64));
    }

    if let Some(enc) = input.get("encodeBase64Url") {
        if let Some(hex) = enc.get("hexBytes").and_then(Value::as_str) {
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|e| format!("invalid hexBytes: {e}"))?;
            set_bytes(&mut exact, &bytes);
        } else if let Some(utf8) = enc.get("utf8").and_then(Value::as_str) {
            exact.insert(
                "base64Url".into(),
                json!(solana_pay_kit::mpp::protocol::core::base64url_encode(
                    utf8.as_bytes()
                )),
            );
        }
    }

    if let Some(cid) = input.get("challengeId") {
        let opt = |k: &str| cid.get(k).and_then(Value::as_str);
        let id = compute_challenge_id(
            opt("secretKey").unwrap_or(""),
            opt("realm").unwrap_or(""),
            opt("method").unwrap_or(""),
            opt("intent").unwrap_or(""),
            opt("request").unwrap_or(""),
            opt("expires"),
            opt("digest"),
            opt("opaque"),
        );
        exact.insert("base64Url".into(), json!(id));
    }

    if let Some(vp) = input.get("voucherPreimage") {
        let voucher = VoucherData {
            channel_id: str_field(vp, "channelId").to_string(),
            cumulative_amount: match vp.get("cumulativeAmount") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            },
            expires_at: vp.get("expiresAt").and_then(Value::as_i64),
        };
        let bytes = voucher.message_bytes().map_err(|e| e.to_string())?;
        set_bytes(&mut exact, &bytes);
    }

    if let Some(sam) = input.get("sessionAuthenticationMessage") {
        let auth = SessionAuthentication {
            kind: SessionAuthenticationType::Proof,
            challenge_id: str_field(sam, "challengeId").to_string(),
            payer: str_field(sam, "payer").to_string(),
            signature: String::new(),
        };
        let bytes = auth
            .message_bytes(str_field(sam, "channelId"))
            .map_err(|e| e.to_string())?;
        exact.insert(
            "canonicalJson".into(),
            json!(String::from_utf8(bytes.clone()).map_err(|e| e.to_string())?),
        );
        exact.insert(
            "base64Url".into(),
            json!(solana_pay_kit::mpp::protocol::core::base64url_encode(
                &bytes
            )),
        );
    }

    if let Some(sw) = input.get("sessionWire") {
        let value = sw.get("value").cloned().unwrap_or(Value::Null);
        let reencoded = match str_field(sw, "shape") {
            "request" => {
                serde_json::from_value::<SessionRequest>(value).and_then(serde_json::to_value)
            }
            "action" => {
                serde_json::from_value::<SessionAction>(value).and_then(serde_json::to_value)
            }
            other => return Err(format!("unknown sessionWire shape {other:?}")),
        }
        .map_err(|e| format!("invalid session payload: {e}"))?;
        let (json, b64) = canonical_json(&reencoded)?;
        exact.insert("canonicalJson".into(), json!(json));
        exact.insert("base64Url".into(), json!(b64));
    }

    let mut out = Map::new();
    out.insert("exactBytes".into(), Value::Object(exact));
    Ok(out)
}

// ── session voucher verify ──────────────────────────────────────────────────

/// Sign one voucher with the vector key and drive the production acceptance
/// path (`core::session::accept_voucher`) against a fresh channel at the
/// pinned clock.
async fn session_voucher_verify(input: &Value) -> Result<Outcome, String> {
    let Some(params) = input.get("sessionVoucherVerify") else {
        return Ok(Outcome::Unsupported(
            "session verify vector without sessionVoucherVerify".into(),
        ));
    };
    let signer = signer_from(input)?;
    let channel_id = str_field(params, "channelId").to_string();
    let cumulative: u64 = match params.get("cumulativeAmount") {
        Some(Value::String(s)) => s.parse().map_err(|_| "invalid cumulativeAmount")?,
        Some(v) => v.as_u64().ok_or("invalid cumulativeAmount")?,
        None => return Err("missing cumulativeAmount".into()),
    };
    let expires_at = params.get("expiresAt").and_then(Value::as_i64).unwrap_or(0);
    let now = params
        .get("nowSeconds")
        .and_then(Value::as_i64)
        .ok_or("missing nowSeconds")?;
    let window = params
        .get("settlementWindowSeconds")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let deposit: u64 = match params.get("deposit") {
        Some(Value::String(s)) => s.parse().map_err(|_| "invalid deposit")?,
        Some(v) => v.as_u64().ok_or("invalid deposit")?,
        None => return Err("missing deposit".into()),
    };

    let voucher = VoucherData {
        channel_id: channel_id.clone(),
        cumulative_amount: cumulative.to_string(),
        expires_at: Some(expires_at),
    };
    let message = voucher.message_bytes().map_err(|e| e.to_string())?;
    let signature = signer
        .sign_message(&message)
        .await
        .map_err(|e| format!("sign voucher: {e}"))?;
    let signature_b58 = signature.to_string();
    let authorized_signer = signer.pubkey().to_string();

    let store = MemoryChannelStore::new();
    store
        .put_channel(
            &channel_id,
            fresh_channel(&channel_id, &authorized_signer, deposit),
        )
        .await
        .map_err(|e| format!("seed channel: {e}"))?;

    match accept_voucher(
        &store,
        &channel_id,
        cumulative,
        expires_at,
        &signature_b58,
        now,
        0,
        window,
        0,
    )
    .await
    {
        Ok(_) => Ok(Outcome::Accept(Map::new())),
        Err(error) => Err(error.to_string()),
    }
}

fn fresh_channel(channel_id: &str, signer: &str, deposit: u64) -> ChannelState {
    ChannelState {
        channel_id: channel_id.to_string(),
        authorized_signer: signer.to_string(),
        deposit,
        cumulative: 0,
        sealed: false,
        highest_voucher_signature: None,
        highest_voucher_expires_at: None,
        close_requested_at: None,
        final_cumulative: None,
        open_slot: None,
        payer: String::new(),
        rent_payer: String::new(),
        opening_challenge_id: String::new(),
        authentication: None,
        voucher_signer: "client".to_string(),
        idle_timeout_seconds: None,
        last_activity_at: 0,
        spent_amount: 0,
        settled_on_chain: 0,
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
    }
}

// ── x402 exact ──────────────────────────────────────────────────────────────

/// The client builds and signs a real exact transaction: the kit fetches the
/// blockhash and reads the mint's decimals over the fixture RPC.
async fn x402_build(input: &Value) -> Result<Outcome, Rejection> {
    let offer = input
        .get("x402Offer")
        .ok_or("x402 build vector is missing input.x402Offer")?;
    let requirements: PaymentRequirements = serde_json::from_value(offer.clone())
        .map_err(|e| format!("invalid payload: x402Offer: {e}"))?;
    let signer = signer_from(input)?;
    let rpc = fixture_rpc(input)?;

    let header = if input.get("x402Version").and_then(Value::as_u64) == Some(1) {
        build_payment_header_v1(&signer, &rpc, &requirements, None).await?
    } else {
        // Echo-and-append (x402 v2 §5.1.2) is the caller's job in the Rust
        // SDK: echo the advertised extensions, and fill the id when the server
        // requires one (pinned for determinism, else freshly generated).
        let mut extensions = PaymentExtensions::echoing(input.get("x402AdvertisedExtensions"))
            .map_err(|e| format!("invalid payload: extensions: {e}"))?;
        if extensions
            .as_ref()
            .is_some_and(PaymentExtensions::requires_payment_identifier)
        {
            let id = input
                .get("x402PaymentIdentifierId")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(generate_payment_identifier_id);
            extensions = extensions.map(|e| e.with_payment_identifier_id(id));
        }
        build_payment_header(&signer, &rpc, &requirements, extensions, None).await?
    };
    let mut fields = envelope_fields(&header)?;
    // The built header itself, so the driver can verify it with the Rust
    // kit and compare its transaction with the kit's own build.
    fields.insert("x402PaymentHeader".into(), Value::String(header));
    Ok(Outcome::Accept(fields))
}

/// Drive `X402::verify_payment_signature_for_requirements` against the
/// route's own requirements (`X402::exact_requirements`), configured from the
/// vector's server route. The kit decodes and verifies the vector's real
/// partially-signed transaction (pre-broadcast checks; nothing is co-signed
/// or broadcast).
async fn x402_verify(input: &Value) -> Result<Outcome, Rejection> {
    let header = input
        .get("x402PaymentHeader")
        .and_then(Value::as_str)
        .ok_or("x402 verify vector is missing input.x402PaymentHeader")?;
    let network = input
        .get("x402ServerNetwork")
        .and_then(Value::as_str)
        .ok_or("x402 verify vector is missing input.x402ServerNetwork")?;
    let currency = str_field(input, "x402ServerCurrency");
    // The Rust server takes the route's token decimals as operator config.
    // The route's token is the fixture mint, so configure its decimals.
    let decimals = input
        .pointer(&format!("/rpcFixtures/mints/{currency}/decimals"))
        .and_then(Value::as_u64)
        .ok_or("x402 verify vector has no fixture mint for the server currency")?
        as u8;
    let payment_identifier = if input
        .get("x402ServerRequiresPaymentIdentifier")
        .and_then(Value::as_bool)
        == Some(true)
    {
        PaymentIdentifierPolicy::Required
    } else {
        PaymentIdentifierPolicy::NotAdvertised
    };
    let config = X402Config {
        recipient: str_field(input, "x402ServerRecipient").to_string(),
        currencies: vec![CurrencyConfig {
            currency: currency.to_string(),
            decimals,
            token_program: None,
        }],
        network: network.to_string(),
        rpc_url: Some(fixture_rpc_url(input)?),
        fee_payer_key: input
            .get("x402ServerFeePayer")
            .and_then(Value::as_str)
            .map(str::to_string),
        payment_identifier,
        ..Default::default()
    };
    let server = X402::new(config).map_err(|e| format!("server config: {e}"))?;
    // The vector carries the route amount in base units; the server API
    // takes a human decimal price and converts it with `core::parse_units`.
    let base_units = str_field(input, "x402ServerAmount");
    let price = human_price(base_units, decimals)?;
    // The route's extra.memo, which the verifier enforces on the transaction.
    let options = ExactOptions {
        memo: input.get("x402ServerMemo").and_then(Value::as_str),
        ..Default::default()
    };
    let requirements = server
        .exact_requirements(&price, options)
        .map_err(|e| format!("route requirements: {e}"))?;
    if let Err(error) = server
        .verify_payment_signature_for_requirements(header, &requirements)
        .await
    {
        // A v2 credential names its network inside `accepted`, so a v2
        // network mismatch is an `accepted` mismatch (v1 keeps wrong-network).
        let v2 = envelope_fields(header)
            .ok()
            .and_then(|shape| shape.get("x402EnvelopeShape").cloned())
            .and_then(|shape| shape.get("x402Version").and_then(Value::as_u64))
            == Some(2);
        let message = error.to_string();
        if v2 && message.starts_with("Network mismatch") {
            return Err(Rejection {
                message,
                code: Some("accepted-mismatch"),
            });
        }
        return Err(error.into());
    }
    Ok(Outcome::Accept(envelope_fields(header)?))
}

fn fixture_rpc_url(input: &Value) -> Result<String, String> {
    input
        .get("rpcUrl")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "driver did not inject input.rpcUrl".to_string())
}

/// Render base units as the decimal price the server API expects, and prove
/// the conversion with the kit's own `parse_units` (round trip must be exact).
fn human_price(base_units: &str, decimals: u8) -> Result<String, String> {
    let units: u128 = base_units
        .parse()
        .map_err(|_| format!("invalid x402ServerAmount {base_units}"))?;
    let scale = 10u128.pow(u32::from(decimals));
    let whole = units / scale;
    let frac = units % scale;
    let price = if frac == 0 {
        whole.to_string()
    } else {
        let frac = format!("{frac:0width$}", width = decimals as usize);
        format!("{whole}.{}", frac.trim_end_matches('0'))
    };
    let back = solana_pay_kit::core::parse_units(&price, decimals).map_err(|e| e.to_string())?;
    if back != base_units {
        return Err(format!(
            "unit conversion {base_units} -> {price} -> {back} is not exact"
        ));
    }
    Ok(price)
}

/// Decode a base64(JSON) payment header into the X402EnvelopeShape oracle
/// (mirrors decodeEnvelopeShape in harness/src/conformance/x402.ts).
fn envelope_fields(header_b64: &str) -> Result<Map<String, Value>, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header_b64)
        .map_err(|e| format!("invalid payload: header base64: {e}"))?;
    let env: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid payload: header json: {e}"))?;
    let accepted = env.get("accepted").filter(|a| a.is_object());
    let transaction = env
        .get("payload")
        .and_then(|p| p.get("transaction"))
        .and_then(Value::as_str);
    let mut shape = Map::new();
    shape.insert(
        "x402Version".into(),
        env.get("x402Version").cloned().unwrap_or(Value::Null),
    );
    shape.insert("hasAccepted".into(), json!(accepted.is_some()));
    shape.insert(
        "payloadHasTransaction".into(),
        json!(transaction.is_some_and(|t| !t.is_empty())),
    );
    for key in ["scheme", "network"] {
        if let Some(v) = env.get(key) {
            shape.insert(key.into(), v.clone());
        }
    }
    if let Some(accepted) = accepted {
        for (from, to) in [
            ("scheme", "acceptedScheme"),
            ("network", "acceptedNetwork"),
            ("asset", "acceptedAsset"),
            ("payTo", "acceptedPayTo"),
            ("amount", "acceptedAmount"),
        ] {
            shape.insert(
                to.into(),
                accepted.get(from).cloned().unwrap_or(Value::Null),
            );
        }
    }
    match env.get("extensions").and_then(Value::as_object) {
        Some(extensions) => {
            let mut keys: Vec<&String> = extensions.keys().collect();
            keys.sort();
            shape.insert("hasExtensions".into(), json!(!keys.is_empty()));
            shape.insert("extensionKeys".into(), json!(keys));
            let pid = extensions
                .get("payment-identifier")
                .filter(|p| p.is_object());
            shape.insert("hasPaymentIdentifier".into(), json!(pid.is_some()));
            if let Some(info) = pid.and_then(|p| p.get("info")).and_then(Value::as_object) {
                if let Some(required) = info.get("required") {
                    shape.insert("paymentIdentifierRequired".into(), required.clone());
                }
                if let Some(id) = info.get("id") {
                    shape.insert("paymentIdentifierId".into(), id.clone());
                }
            }
        }
        None => {
            shape.insert("hasExtensions".into(), json!(false));
            shape.insert("hasPaymentIdentifier".into(), json!(false));
            shape.insert("extensionKeys".into(), json!([]));
        }
    }
    let mut out = Map::new();
    out.insert("x402EnvelopeShape".into(), Value::Object(shape));
    Ok(out)
}

// ── reject classification (mirrors harness/src/conformance/reject.ts) ───────

fn classify_reject(message: &str) -> Option<&'static str> {
    if let Some(code) = classify_x402_exact_reason(message) {
        return Some(code);
    }
    let m = message.to_ascii_lowercase();
    let has = |needle: &str| m.contains(needle);
    // Charge verification policy and client challenge checks (mirrors the
    // block at the top of harness/src/conformance/reject.ts).
    let code = if has("fee payer cannot fund") || has("fee payer token account cannot fund") {
        "fee-payer-is-funds-source"
    } else if has("primary amount is zero after splits") || has("split amounts exceed") {
        "splits-exceed-amount"
    } else if has("splits exceed maximum") {
        "too-many-splits"
    } else if has("ata creation owner is not authorized")
        || has("unsupported compute budget")
        || has("unexpected_signer")
    {
        "unexpected-instruction"
    } else if has("atacreationrequired requires")
        || has("unsupported challenge network")
        || has("invalid amount")
        || has("requires feepayerkey")
    {
        "invalid-challenge"
    } else if has("ata creation")
        || has("ata payer")
        || has("transaction fee payer must be")
        || has("transaction fee payer mismatch")
        || has("memo cannot exceed")
    {
        "invalid-payload"
    } else if has("invalid challenge") {
        "invalid-challenge"
    } else if has("compute unit price") && (has("exceeds") || has("cap") || has("maximum")) {
        "compute-price-over-cap"
    } else if has("compute unit limit") && (has("exceeds") || has("cap") || has("maximum")) {
        "compute-limit-over-cap"
    } else if has("credential claims a different recipient")
        || has("currency mismatch")
        || has("structurally match")
        || has("does not match any offered")
        || (has("amount mismatch: expected") && !has("_amount_mismatch"))
    {
        // x402 v2: the credential's `accepted` disagrees with the route.
        "accepted-mismatch"
    } else if has("no memo instruction found") {
        "invalid-payload"
    } else if has("fee payer cannot authorize") {
        "fee-payer-not-authority"
    } else if has("fee payer") && (has("funding source") || has("funds source")) {
        "fee-payer-is-funds-source"
    } else if has("splits consume the entire amount") {
        "splits-exceed-amount"
    } else if has("too many splits") {
        "too-many-splits"
    } else if has("no matching") && has("transfer") {
        "no-matching-transfer"
    } else if has("unexpected") && (has("instruction") || has("transfer")) {
        "unexpected-instruction"
    } else if has("amount") && (has("mismatch") || has("does not match")) {
        "amount-mismatch"
    } else if has("unsupported x402 version") {
        "unsupported-version"
    } else if has("network mismatch") {
        "wrong-network"
    } else if has("payment-identifier") || has("payment identifier") {
        "payment-identifier-required"
    } else if has("voucher has expired") {
        "voucher-expired"
    } else if has("settlement window") {
        "voucher-expires-before-settlement"
    } else if has("invalid") || has("malformed") || has("decode") || has("payload") {
        "invalid-payload"
    } else {
        return None;
    };
    Some(code)
}

/// The x402 exact verifier reports snake_case reasons
/// (`invalid_exact_svm_payload_*`, x402 facilitator vocabulary). Map them onto
/// the shared reject codes.
fn classify_x402_exact_reason(message: &str) -> Option<&'static str> {
    let reason = message.strip_prefix("invalid_exact_svm_payload_")?;
    let has = |needle: &str| reason.contains(needle);
    Some(if has("fee_payer") {
        "fee-payer-not-authority"
    } else if has("compute_price_instruction_too_high") {
        "compute-price-over-cap"
    } else if has("compute_limit_instruction_too_high") {
        "compute-limit-over-cap"
    } else if has("amount_mismatch") {
        "amount-mismatch"
    } else if has("decimals_mismatch") {
        "decimals-mismatch"
    } else if has("no_transfer_instruction") || has("mint_mismatch") || has("recipient_mismatch") {
        "no-matching-transfer"
    } else if has("multiple_matching_transfers")
        || has("unknown_")
        || has("instructions_length")
        || has("unexpected_signer")
    {
        "unexpected-instruction"
    } else {
        "invalid-payload"
    })
}
