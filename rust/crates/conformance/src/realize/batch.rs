//! Kit paths for `x402-batch-settlement` vectors: what `pkc fill` runs to
//! realize a case and what the build judge runs against an SDK's build.
//!
//! Three vector shapes, one per mode:
//!
//! - **canonical-bytes**: one of `batchVoucherMessage`,
//!   `batchAuthorizationMessage`, `batchCloseAuthorizationDigest`,
//!   `batchReceiverBindingMemo`, `batchChannelId` or `batchWire`
//!   (`{shape, value}` round-tripped through the kit's wire types).
//! - **verify-transaction**: a resource server configured from
//!   `batchServer` (it self-facilitates: the sponsor key is its fee payer),
//!   whose channel store holds `batchServerChannel`, verifies and reserves
//!   `x402PaymentHeader` against the chain state of `rpcFixtures`. A
//!   `batchCorrective` input is the client-side check of a corrective 402.
//! - **build-transaction**: the client builds the payload `batchClient`
//!   names against `batchClient.requirements`; the judge checks the build
//!   against the spec's structural rules and the Rust server's verifier.
//!
//! [`fx`] holds the deterministic keys, wire objects, transactions and
//! account bytes the case registry builds its inputs from.

use std::sync::Arc;

use base64::Engine;
use serde_json::{json, Map, Value};
use solana_pay_kit::core::payment_channels as pc;
use solana_pay_kit::core::store::{ChannelStore, MemoryChannelStore};
use solana_pay_kit::core::tx::{TxV1Mode, TxVersion};
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::solana_keychain::SolanaSigner;
use solana_pay_kit::x402::client::batch_settlement as client;
use solana_pay_kit::x402::protocol::schemes::batch_settlement::{
    self as scheme, errors as codes, BatchChannelConfig, BatchPayload, BatchPaymentPayload,
    BatchRedemptionPayload, BatchRequiredEnvelope, BatchRequirements, BatchSettlementResponse,
    BatchVoucher,
};
use solana_pay_kit::x402::server::batch_settlement::{
    BatchAccess, BatchConfig, X402BatchSettlement,
};
use solana_pubkey::Pubkey;

use super::{canonical_json, Observed, Output};
use crate::case::{Mode, RejectCode};
use crate::fixture_rpc::{self, Fixtures, HttpFixture};
use crate::run::judge::Failure;
use crate::run::vectors::Vector;

/// The result field an accepted `x402-batch-settlement` build carries.
pub const BUILD_ARTIFACT: &str = "x402PaymentHeader";

pub async fn run(mode: Mode, input: &Value) -> Result<Observed, String> {
    match mode {
        Mode::CanonicalBytes => canonical(input),
        Mode::VerifyTransaction if input.get("batchCorrective").is_some() => corrective(input),
        Mode::VerifyTransaction => server_verify(input).await,
        Mode::BuildTransaction => client_build(input).await,
    }
}

// ── reject vocabulary ──────────────────────────────────────────────────────

/// The shared reject code for a spec error code
/// (`invalid_batch_settlement_svm_*`, spec §7).
pub fn code_for(wire: &str) -> Option<RejectCode> {
    use RejectCode::*;
    Some(match wire {
        codes::INVALID_PAYLOAD_TYPE => PayloadType,
        codes::INVALID_PAYMENT_FLOW => PaymentFlow,
        codes::INVALID_TOKEN_PROGRAM => TokenProgram,
        codes::INVALID_VOUCHER_SIGNATURE => VoucherSignature,
        codes::INVALID_CHANNEL_ID_MISMATCH => ChannelIdMismatch,
        codes::INVALID_FEE_PAYER_MISMATCH => FeePayerMismatch,
        codes::INVALID_RECEIVER_AUTHORIZER_MISMATCH => ReceiverAuthorizerMismatch,
        codes::INVALID_CLOSE_AUTHORIZATION => CloseAuthorization,
        codes::INVALID_CLOSE_AMOUNT_UNSUPPORTED => CloseAmountUnsupported,
        codes::INVALID_CLOSE_STATE => CloseState,
        codes::INVALID_WITHDRAW_DELAY_MISMATCH => WithdrawDelayMismatch,
        codes::INVALID_WITHDRAW_DELAY_OUT_OF_RANGE => WithdrawDelayOutOfRange,
        codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH => CumulativeAmountMismatch,
        codes::INVALID_CUMULATIVE_EXCEEDS_DEPOSIT => CumulativeExceedsDeposit,
        codes::INVALID_VOUCHER_EXPIRY => VoucherExpiry,
        codes::INVALID_SETUP_TRANSACTION => SetupTransaction,
        codes::INVALID_SETTLEMENT_SIMULATION => SettlementSimulation,
        codes::INVALID_CHANNEL_STATE => ChannelState,
        codes::INVALID_REFUND_TRANSACTION => RefundTransaction,
        codes::INVALID_CHANNEL_CLOSING => ChannelClosing,
        codes::DUPLICATE_SETTLEMENT => DuplicateSettlement,
        _ => return None,
    })
}

fn reject(code: Option<RejectCode>, message: impl Into<String>) -> Observed {
    Observed::Reject {
        code,
        message: message.into(),
    }
}

/// A kit error to the shared vocabulary: the spec code the kit tagged it
/// with, else the error variant.
fn kit_reject(error: &solana_pay_kit::x402::Error) -> Observed {
    use solana_pay_kit::x402::Error;
    let message = error.to_string();
    let code = code_for(scheme::classify(&message)).or(match error {
        // `parse_payment`: an envelope for another scheme.
        Error::InvalidPayloadType(_) => Some(RejectCode::UnsupportedScheme),
        // `parse_payment`: not a decodable batch envelope.
        Error::InvalidPaymentRequired(_) => Some(RejectCode::InvalidPayload),
        _ => None,
    });
    reject(code, message)
}

/// A client-side refusal of the challenge's terms (no spec code exists for
/// a client refusing an offer): the version negotiation failure is
/// `unsupported_transaction_version` (x402-txv1 "Transaction versions"),
/// anything else is a refused challenge.
fn client_reject(error: &solana_pay_kit::x402::Error) -> Observed {
    let message = error.to_string();
    let code = code_for(scheme::classify(&message)).unwrap_or(
        if message.contains("the server accepts transaction versions") {
            RejectCode::UnsupportedVersion
        } else {
            RejectCode::InvalidChallenge
        },
    );
    reject(Some(code), message)
}

// ── canonical bytes ────────────────────────────────────────────────────────

fn set_bytes(exact: &mut Map<String, Value>, bytes: &[u8]) {
    exact.insert("bytes".into(), json!(bytes));
    exact.insert(
        "base64Url".into(),
        json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)),
    );
}

fn accept_exact(exact: Map<String, Value>) -> Observed {
    Observed::Accept(Output {
        exact: Some(exact),
        ..Default::default()
    })
}

fn invalid(message: impl Into<String>) -> Observed {
    reject(Some(RejectCode::InvalidPayload), message)
}

fn canonical(input: &Value) -> Result<Observed, String> {
    let mut exact = Map::new();
    if let Some(vm) = input.get("batchVoucherMessage") {
        // The kit's own wire type parses the voucher fields (decimal-string
        // u64 amount), then the program voucher layout encodes them.
        let voucher: BatchVoucher = match serde_json::from_value(json!({
            "channelId": vm.get("channelId"),
            "maxClaimableAmount": vm.get("maxClaimableAmount"),
            "expiresAt": vm.get("expiresAt"),
            "signature": "",
        })) {
            Ok(v) => v,
            Err(e) => return Ok(invalid(format!("invalid voucher: {e}"))),
        };
        let amount = match voucher.max_claimable() {
            Ok(a) => a,
            Err(e) => return Ok(invalid(e.to_string())),
        };
        let channel = match pc::parse_pubkey(&voucher.channel_id) {
            Ok(c) => c,
            Err(e) => return Ok(invalid(e.to_string())),
        };
        match pc::voucher_message_bytes(&channel, amount, voucher.expires_at) {
            Ok(bytes) => set_bytes(&mut exact, &bytes),
            Err(e) => return Ok(invalid(e.to_string())),
        }
        return Ok(accept_exact(exact));
    }
    if let Some(am) = input.get("batchAuthorizationMessage") {
        let key = |k: &str| pc::parse_pubkey(super::str_field(am, k));
        let (channel, payer, operator) = match (key("channelId"), key("payer"), key("operator")) {
            (Ok(c), Ok(p), Ok(o)) => (c, p, o),
            _ => return Ok(invalid("authorization addresses must be base58 pubkeys")),
        };
        let amount = match super::str_field(am, "authorizedAmount").parse::<u64>() {
            Ok(a) => a,
            Err(_) => return Ok(invalid("authorizedAmount must be a decimal u64")),
        };
        let expires_at = am.get("expiresAt").and_then(Value::as_i64).unwrap_or(0);
        return Ok(
            match client::authorization_message_bytes(
                &channel,
                &payer,
                &operator,
                super::str_field(am, "requestId"),
                amount,
                expires_at,
            ) {
                Ok(bytes) => {
                    set_bytes(&mut exact, &bytes);
                    accept_exact(exact)
                }
                Err(e) => invalid(e.to_string()),
            },
        );
    }
    if input.get("batchCloseAuthorizationDigest").is_some() {
        return Ok(Observed::NotExpressible(
            "the Rust kit has no CloseAuthorization encoder: it refuses cooperative closes".into(),
        ));
    }
    if input.get("batchReceiverBindingMemo").is_some() {
        return Ok(Observed::NotExpressible(
            "the Rust kit exposes no receiver-binding memo encoder".into(),
        ));
    }
    if let Some(ci) = input.get("batchChannelId") {
        let config: BatchChannelConfig =
            match ci.get("channelConfig").cloned().map(serde_json::from_value) {
                Some(Ok(c)) => c,
                Some(Err(e)) => return Ok(invalid(format!("invalid channelConfig: {e}"))),
                None => return Err("batchChannelId.channelConfig missing".into()),
            };
        return Ok(
            match scheme::derive_channel_id(
                &config,
                super::str_field(ci, "feePayer"),
                &pc::default_program_id(),
            ) {
                Ok(id) => {
                    set_bytes(&mut exact, id.as_ref());
                    accept_exact(exact)
                }
                Err(e) => invalid(e.to_string()),
            },
        );
    }
    if let Some(wire) = input.get("batchWire") {
        let value = wire.get("value").cloned().unwrap_or(Value::Null);
        let reencoded =
            match super::str_field(wire, "shape") {
                "requirements" => serde_json::from_value::<BatchRequirements>(value)
                    .and_then(serde_json::to_value),
                "paymentPayload" => serde_json::from_value::<BatchPaymentPayload>(value)
                    .and_then(serde_json::to_value),
                "payload" => {
                    serde_json::from_value::<BatchPayload>(value).and_then(serde_json::to_value)
                }
                "redemption" => serde_json::from_value::<BatchRedemptionPayload>(value)
                    .and_then(serde_json::to_value),
                "settlementResponse" => serde_json::from_value::<BatchSettlementResponse>(value)
                    .and_then(serde_json::to_value),
                "paymentRequired" => serde_json::from_value::<BatchRequiredEnvelope>(value)
                    .and_then(serde_json::to_value),
                other => return Err(format!("unknown batchWire shape {other:?}")),
            };
        return Ok(match reencoded {
            Ok(value) => {
                let (json, b64) = canonical_json(&value)?;
                exact.insert("canonicalJson".into(), json!(json));
                exact.insert("base64Url".into(), json!(b64));
                accept_exact(exact)
            }
            Err(e) => invalid(format!("invalid batch-settlement wire object: {e}")),
        });
    }
    Err("no batch-settlement canonical-bytes key in input".into())
}

/// JCS canonical JSON through the kit's encoder (authored wire cases).
pub fn jcs(value: &Value) -> String {
    canonical_json(value)
        .map(|(json, _)| json)
        .unwrap_or_default()
}

// ── server verify ──────────────────────────────────────────────────────────

fn u64_field(value: &Value, key: &str) -> Result<u64, String> {
    match value.get(key) {
        Some(Value::String(s)) => s.parse().map_err(|_| format!("invalid {key}")),
        Some(v) => v.as_u64().ok_or_else(|| format!("invalid {key}")),
        None => Err(format!("missing {key}")),
    }
}

fn signer(value: &Value, key: &str) -> Result<MemorySigner, String> {
    let bytes: Vec<u8> = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} missing"))?
        .iter()
        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<_>>()
        .ok_or_else(|| format!("{key} must be bytes"))?;
    MemorySigner::from_bytes(&bytes).map_err(|e| format!("invalid {key}: {e}"))
}

/// The kit server `batchServer` configures, on `rpc_url`.
pub fn kit_server(
    server: &Value,
    rpc_url: Option<String>,
    store: Arc<dyn ChannelStore>,
) -> Result<X402BatchSettlement, String> {
    let fee_payer = signer(server, "feePayerSecretKey")?;
    let mut config = BatchConfig::new(
        super::str_field(server, "payTo"),
        super::str_field(server, "cluster"),
        Arc::new(fee_payer),
    );
    config.currency = super::str_field(server, "currency").to_string();
    config.decimals = server
        .get("decimals")
        .and_then(Value::as_u64)
        .and_then(|d| u8::try_from(d).ok())
        .ok_or("batchServer.decimals missing")?;
    config.max_timeout_seconds = u64_field(server, "maxTimeoutSeconds")?;
    config.withdraw_delay =
        u32::try_from(u64_field(server, "withdrawDelay")?).map_err(|e| e.to_string())?;
    config.memo = server
        .get("memo")
        .and_then(Value::as_str)
        .map(str::to_string);
    config.receiver_authorizer = server
        .get("receiverAuthorizer")
        .and_then(Value::as_str)
        .map(str::to_string);
    config.rpc_url = rpc_url;
    let handler = X402BatchSettlement::with_store(config, store).map_err(|e| e.to_string())?;
    let v1 = server
        .get("transactionVersions")
        .and_then(Value::as_array)
        .is_some_and(|versions| versions.iter().any(|v| v.as_u64() == Some(1)));
    Ok(handler.with_tx_v1(if v1 { TxV1Mode::On } else { TxV1Mode::Off }))
}

/// Seed the server's channel store with `batchServerChannel`: the record
/// this server wrote when it accepted the channel's earlier requests.
pub async fn seed_channel(
    server: &X402BatchSettlement,
    store: &MemoryChannelStore,
    record: &Value,
) -> Result<(), String> {
    let channel_id = super::str_field(record, "channelId").to_string();
    let mut state = super::fresh_channel(
        &channel_id,
        super::str_field(record, "payerAuthorizer"),
        u64_field(record, "deposit")?,
    );
    state.payer = super::str_field(record, "payer").to_string();
    state.rent_payer = server.fee_payer();
    state.open_slot = Some(u64_field(record, "openSlot")?);
    state.cumulative = u64_field(record, "chargedCumulativeAmount")?;
    state.settled_on_chain = u64_field(record, "settled").unwrap_or(0);
    state.close_requested_at = record.get("closeRequestedAt").and_then(Value::as_u64);
    state.sealed = record.get("sealed").and_then(Value::as_bool) == Some(true);
    state.set_binding(&server.binding());
    store
        .put_channel(&channel_id, state)
        .await
        .map_err(|e| format!("seed channel: {e}"))
}

async fn server_verify(input: &Value) -> Result<Observed, String> {
    let server_json = input.get("batchServer").ok_or("batchServer missing")?;
    let fixtures = Fixtures::from_input(input)?;
    let http = HttpFixture::start(&fixtures).map_err(|e| e.to_string())?;
    let store = Arc::new(MemoryChannelStore::new());
    let server = kit_server(server_json, Some(http.url().to_string()), store.clone())?;
    if let Some(record) = input.get("batchServerChannel") {
        seed_channel(&server, &store, record).await?;
    }
    let header = super::str_field(input, "x402PaymentHeader");
    let price = super::str_field(server_json, "price");
    Ok(
        match server.verify_and_reserve_payment(header, price).await {
            Ok(BatchAccess::Serve(_) | BatchAccess::Control(_)) => Observed::Accept(Output {
                header: Some(header.to_string()),
                ..Default::default()
            }),
            Ok(other) => reject(
                None,
                format!(
                    "verify answered {} rather than serving the request",
                    match other {
                        BatchAccess::Resume(_) => "resume",
                        BatchAccess::Replay(..) => "replay",
                        BatchAccess::InProgress => "in-progress",
                        _ => "?",
                    }
                ),
            ),
            Err(error) => kit_reject(&error),
        },
    )
}

// ── client: corrective 402 ─────────────────────────────────────────────────

fn tracker(
    channel: &Value,
    requirements: &BatchRequirements,
) -> Result<client::BatchChannel, String> {
    let config: BatchChannelConfig = serde_json::from_value(
        channel
            .get("channelConfig")
            .cloned()
            .ok_or("channel.channelConfig missing")?,
    )
    .map_err(|e| format!("channelConfig: {e}"))?;
    let id = client::channel_id_for(&config, requirements).map_err(|e| e.to_string())?;
    Ok(client::BatchChannel::new(
        id,
        config,
        u64_field(channel, "chargedCumulativeAmount")?,
        u64_field(channel, "deposit")?,
    ))
}

fn corrective(input: &Value) -> Result<Observed, String> {
    let c = &input["batchCorrective"];
    let requirements: BatchRequirements =
        serde_json::from_value(c["requirements"].clone()).map_err(|e| e.to_string())?;
    let mut channel = tracker(&c["channel"], &requirements)?;
    Ok(match channel.adopt_corrective_state(&requirements) {
        Ok(_) => Observed::Accept(Output::default()),
        Err(error) => kit_reject(&error),
    })
}

// ── client build ───────────────────────────────────────────────────────────

async fn client_build(input: &Value) -> Result<Observed, String> {
    let c = input.get("batchClient").ok_or("batchClient missing")?;
    let requirements: BatchRequirements = match serde_json::from_value(c["requirements"].clone()) {
        Ok(r) => r,
        Err(e) => return Ok(reject(Some(RejectCode::InvalidChallenge), e.to_string())),
    };
    let payer = signer(c, "secretKey")?;
    let fixtures = Fixtures::from_input(input)?;
    let (rpc, _) = fixture_rpc::rpc_client(&fixtures);
    let max_version = match c.get("maxTransactionVersion").and_then(Value::as_u64) {
        None => None,
        Some(0) => Some(TxVersion::V0),
        Some(_) => Some(TxVersion::V1),
    };
    let terms = match client::resolve_terms(&rpc, &requirements, max_version) {
        Ok(t) => t,
        Err(e) => return Ok(client_reject(&e)),
    };
    let blockhash = || -> Result<solana_hash::Hash, String> {
        super::str_field(c, "blockhash")
            .parse()
            .map_err(|e| format!("blockhash: {e}"))
    };
    let payload = match super::str_field(c, "operation") {
        "deposit" => client::build_deposit(
            &payer,
            &requirements,
            &terms,
            u64_field(c, "depositAmount")?,
            blockhash()?,
            u64_field(c, "openSlot")?,
        )
        .await
        .map(|(_, payload)| payload),
        "voucher" => {
            let channel = tracker(&c["channel"], &requirements)?;
            channel.voucher_payload(&payer, terms.amount).await
        }
        "topUp" => {
            let channel = tracker(&c["channel"], &requirements)?;
            client::build_top_up(
                &payer,
                &channel,
                &terms,
                u64_field(c, "depositAmount")?,
                blockhash()?,
            )
            .await
        }
        "refund" => {
            let channel = tracker(&c["channel"], &requirements)?;
            client::build_refund(&payer, &channel, &terms, blockhash()?).await
        }
        other => return Err(format!("unknown batchClient.operation {other:?}")),
    };
    Ok(
        match payload.and_then(|p| client::encode_payment_header(&requirements, p)) {
            Ok(header) => Observed::Accept(Output {
                header: Some(header),
                ..Default::default()
            }),
            Err(e) => client_reject(&e),
        },
    )
}

// ── build judge ────────────────────────────────────────────────────────────

fn fail(message: impl Into<String>) -> Failure {
    Failure::new(message)
}

fn fail_at(
    path: &str,
    expected: Option<&Value>,
    actual: Option<&Value>,
    message: impl Into<String>,
) -> Failure {
    Failure {
        message: message.into(),
        path: Some(path.to_string()),
        expected: Some(expected.cloned().unwrap_or(Value::Null)),
        actual: Some(actual.cloned().unwrap_or(Value::Null)),
    }
}

/// Judge an accepted SDK build: the spec's structural rules for the
/// operation, then (for the forms the Rust server can verify against the
/// pinned spec) the Rust server's verifier on the vector's own chain state.
pub async fn judge_build(vector: &Vector, artifact: &str) -> Result<(), Failure> {
    let input = vector.input();
    let c = &input["batchClient"];
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(artifact)
        .map_err(|e| fail(format!("payment header is not base64: {e}")))?;
    let envelope: Value = serde_json::from_slice(&bytes)
        .map_err(|e| fail(format!("payment header is not JSON: {e}")))?;
    if envelope["x402Version"] != json!(2) {
        return Err(fail("x402Version must be 2"));
    }
    if envelope["accepted"] != c["requirements"] {
        return Err(fail_at(
            "accepted",
            Some(&c["requirements"]),
            Some(&envelope["accepted"]),
            "paymentPayload.accepted MUST equal the paymentRequirements",
        ));
    }
    let requirements: BatchRequirements =
        serde_json::from_value(c["requirements"].clone()).map_err(|e| fail(e.to_string()))?;
    let payload = &envelope["payload"];
    let amount = requirements.amount().map_err(|e| fail(e.to_string()))?;
    let charged = c
        .get("channel")
        .map(|ch| u64_field(ch, "chargedCumulativeAmount"))
        .transpose()
        .map_err(fail)?
        .unwrap_or(0);
    let operation = super::str_field(c, "operation");
    let want_type = match operation {
        "deposit" | "topUp" => "deposit",
        other => other,
    };
    if payload["type"] != json!(want_type) {
        return Err(fail_at(
            "payload.type",
            Some(&json!(want_type)),
            Some(&payload["type"]),
            "wrong payload variant",
        ));
    }
    let config: BatchChannelConfig = serde_json::from_value(payload["channelConfig"].clone())
        .map_err(|e| fail(format!("payload.channelConfig: {e}")))?;
    // The config every operation is bound to (mint, receiver, receiver
    // authorizer, withdraw delay, flow) is the one the requirements allow.
    scheme::check_channel_config(&config, &requirements).map_err(|e| {
        fail_at(
            "payload.channelConfig",
            None,
            Some(&payload["channelConfig"]),
            format!("channelConfig does not match the requirements: {e}"),
        )
    })?;
    // The client holds one key: it is the payer and the voucher
    // authorizer, and the channel opens at the slot the caller gave.
    let client_key = signer(c, "secretKey").map_err(fail)?.pubkey().to_string();
    for (field, got) in [
        ("payer", &config.payer),
        ("payerAuthorizer", &config.payer_authorizer),
    ] {
        if *got != client_key {
            return Err(fail_at(
                &format!("payload.channelConfig.{field}"),
                Some(&json!(client_key)),
                Some(&json!(got)),
                "the channel must be bound to the client's own key",
            ));
        }
    }
    if c.get("openSlot")
        .and_then(Value::as_u64)
        .is_some_and(|slot| slot != config.open_slot)
    {
        return Err(fail_at(
            "payload.channelConfig.openSlot",
            Some(&c["openSlot"]),
            Some(&json!(config.open_slot)),
            "the channel must open at the slot the caller gave",
        ));
    }
    let channel_id =
        client::channel_id_for(&config, &requirements).map_err(|e| fail(e.to_string()))?;
    // Every client variant carries a voucher in client mode (refund: the
    // accepted cumulative, spec §4.3).
    let expected_cumulative = match operation {
        "refund" => charged,
        _ => charged + amount,
    };
    let voucher: BatchVoucher =
        serde_json::from_value(payload["voucher"].clone()).map_err(|e| {
            fail_at(
                "payload.voucher",
                Some(&json!("a BatchVoucher")),
                Some(&payload["voucher"]),
                format!("client-mode {want_type} payload carries no valid voucher: {e}"),
            )
        })?;
    if voucher.max_claimable().ok() != Some(expected_cumulative) {
        return Err(fail_at(
            "payload.voucher.maxClaimableAmount",
            Some(&json!(expected_cumulative.to_string())),
            Some(&json!(voucher.max_claimable_amount)),
            "the voucher must authorize chargedCumulativeAmount + amount",
        ));
    }
    scheme::check_voucher(&voucher, &config, &channel_id)
        .map_err(|e| fail(format!("voucher: {e}")))?;
    if operation == "deposit" {
        judge_open(payload, c, &requirements, &config, &channel_id)?;
        return Ok(());
    }
    if operation == "refund" {
        return judge_refund(payload, &requirements, &config, &channel_id);
    }
    // A top-up funds what the caller asked for; the server below only ties
    // the transaction to payload.deposit.amount.
    if operation == "topUp" && c.get("depositAmount").is_some() {
        let requested = u64_field(c, "depositAmount").map_err(fail)?;
        let declared = u64_field(&payload["deposit"], "amount").map_err(fail)?;
        if declared != requested {
            return Err(fail_at(
                "payload.deposit.amount",
                Some(&json!(requested.to_string())),
                Some(&json!(declared.to_string())),
                "the top-up must be the amount the caller asked for",
            ));
        }
    }
    // Voucher and top-up: the Rust server accepts the build on the chain
    // state the vector pins.
    let mut verify = input.clone();
    verify["x402PaymentHeader"] = json!(artifact);
    match server_verify(&verify).await.map_err(fail)? {
        Observed::Accept(_) => Ok(()),
        other => Err(fail_at(
            "verify",
            Some(&json!("accept")),
            Some(&json!(other.summary())),
            format!(
                "the Rust server refuses the SDK's build: {}",
                other.summary()
            ),
        )),
    }
}

/// The canonical `open` (spec §4.2, Phase 1): sponsor as fee payer,
/// rent payer and payee, the payer signed and the sponsor slot empty, the
/// single 100% distribution to `payTo`, the seller memo plus the binding
/// memo, a version the challenge advertises.
fn judge_open(
    payload: &Value,
    client: &Value,
    requirements: &BatchRequirements,
    config: &BatchChannelConfig,
    channel_id: &Pubkey,
) -> Result<(), Failure> {
    let tx = crate::tx::decode_b64(payload["deposit"]["transaction"].as_str().unwrap_or(""))
        .map_err(fail)?;
    let version = TxVersion::of(&tx.message).map_err(|e| fail(e.to_string()))?;
    let accepted = solana_pay_kit::core::tx::accepted_versions(
        requirements.extra.transaction_versions.as_deref(),
    );
    if !accepted.contains(&version) {
        return Err(fail(format!("open is version {version}, not advertised")));
    }
    let keys = tx.message.static_account_keys();
    // A malformed build is a failed build, never a panic: every account
    // index below is resolved through `key`, and a lookup-table account
    // (outside the static keys) is refused.
    let key = |index: u8| {
        keys.get(index as usize)
            .copied()
            .ok_or_else(|| fail(format!("account index {index} is not a static account key")))
    };
    let fee_payer =
        pc::parse_pubkey(&requirements.extra.fee_payer).map_err(|e| fail(e.to_string()))?;
    let payer = pc::parse_pubkey(&config.payer).map_err(|e| fail(e.to_string()))?;
    if keys.first() != Some(&fee_payer) {
        return Err(fail("the open's fee payer must be extra.feePayer"));
    }
    let slots = crate::tx::signature_slots(&tx);
    for (key, slot) in &slots {
        let want = if *key == fee_payer.to_string() {
            crate::tx::Slot::Empty
        } else {
            crate::tx::Slot::Signed
        };
        if *slot != want {
            return Err(fail(format!(
                "signature slot of {key} is {slot:?}, expected {want:?}"
            )));
        }
    }
    if slots.len() != 2 {
        return Err(fail(
            "the open must require exactly {payer, feePayer} signatures",
        ));
    }
    let program = pc::default_program_id();
    let mut memos = Vec::new();
    let mut open = None;
    for ix in tx.message.instructions() {
        let program_id = key(ix.program_id_index)?;
        if program_id == program {
            open = Some(ix);
        } else if program_id == pc::memo_program_id() {
            memos.push(String::from_utf8_lossy(&ix.data).to_string());
        }
    }
    let open = open.ok_or_else(|| fail("no payment-channels open instruction"))?;
    // Only the open, its ComputeBudget prefix, memos and Lighthouse
    // assertions may ride along (spec §4.2 setup transaction suffix).
    let lighthouse = pc::parse_pubkey(fx::LIGHTHOUSE).map_err(|e| fail(e.to_string()))?;
    let allowed = [
        program,
        pc::memo_program_id(),
        pc::compute_budget_program_id(),
        lighthouse,
    ];
    let mut opens = 0;
    for ix in tx.message.instructions() {
        let program_id = key(ix.program_id_index)?;
        if !allowed.contains(&program_id) {
            return Err(fail(format!(
                "the open transaction invokes {program_id}, outside the setup allowlist"
            )));
        }
        opens += usize::from(program_id == program);
    }
    if opens != 1 {
        return Err(fail(format!(
            "the open transaction must carry exactly one payment-channels instruction, found {opens}"
        )));
    }
    // The open arguments fully decode (no trailing bytes), derive the
    // channel PDA, and fund exactly the deposit the payload declares and
    // the caller asked for.
    let args = pc::decode_open_for_channel(&tx.message, channel_id, &program)
        .ok_or_else(|| fail("the open arguments do not decode or do not derive the channel"))?;
    let declared = u64_field(&payload["deposit"], "amount").map_err(fail)?;
    if args.deposit != declared {
        return Err(fail_at(
            "open.deposit",
            Some(&json!(declared.to_string())),
            Some(&json!(args.deposit.to_string())),
            "the open must fund payload.deposit.amount",
        ));
    }
    if client.get("depositAmount").is_some() {
        let requested = u64_field(client, "depositAmount").map_err(fail)?;
        if declared != requested {
            return Err(fail_at(
                "payload.deposit.amount",
                Some(&json!(requested.to_string())),
                Some(&json!(declared.to_string())),
                "the deposit must be the amount the caller asked for",
            ));
        }
    }
    if args.grace_period != requirements.extra.withdraw_delay {
        return Err(fail(format!(
            "open grace period {} is not extra.withdrawDelay {}",
            args.grace_period, requirements.extra.withdraw_delay
        )));
    }
    let at = |i: usize| open.accounts.get(i).and_then(|&k| key(k).ok());
    if at(0) != Some(payer) || at(1) != Some(fee_payer) || at(2) != Some(fee_payer) {
        return Err(fail(
            "open must bind payer, rent_payer = payee = extra.feePayer",
        ));
    }
    if at(5) != Some(*channel_id) {
        return Err(fail("open channel account is not the derived PDA"));
    }
    // Every one of the 14 accounts, with its privileges, is the one the
    // kit's own builder writes for these arguments: a swapped token
    // account, token program or sysvar re-signed by the payer is refused.
    let parse = |s: &str| pc::parse_pubkey(s).map_err(|e| fail(e.to_string()));
    let receiver = parse(&requirements.pay_to)?;
    let expected = pc::build_open_instruction(&pc::OpenChannelParams {
        payer,
        rent_payer: fee_payer,
        payee: fee_payer,
        mint: parse(&config.token)?,
        authorized_signer: parse(&config.payer_authorizer)?,
        salt: args.salt,
        open_slot: args.open_slot,
        deposit: args.deposit,
        grace_period: args.grace_period,
        recipients: pc::sole_recipient(&receiver),
        token_program: parse(&requirements.extra.token_program)?,
        program_id: program,
    });
    if open.accounts.len() != expected.accounts.len() {
        return Err(fail(format!(
            "open names {} accounts, expected {}",
            open.accounts.len(),
            expected.accounts.len()
        )));
    }
    // A message gives each key one privilege set, the union of its roles
    // (the fee payer is also rent payer and payee), so that union is what
    // each slot is compared with.
    let privileges = |key: Pubkey| {
        let fee = key == fee_payer;
        expected
            .accounts
            .iter()
            .filter(|m| pc::from_address(&m.pubkey) == key)
            .fold((fee, fee), |(s, w), m| {
                (s || m.is_signer, w || m.is_writable)
            })
    };
    for (i, (&index, want)) in open.accounts.iter().zip(&expected.accounts).enumerate() {
        let got = key(index)?;
        let index = index as usize;
        let signer = tx.message.is_signer(index);
        let writable = tx.message.is_maybe_writable_with_reserved_addresses(
            index,
            None::<&std::collections::HashSet<Pubkey>>,
        );
        let want_key = pc::from_address(&want.pubkey);
        let (want_signer, want_writable) = privileges(want_key);
        if got != want_key || signer != want_signer || writable != want_writable {
            return Err(fail_at(
                &format!("open.accounts[{i}]"),
                Some(
                    &json!({"key": want_key.to_string(), "signer": want_signer, "writable": want_writable}),
                ),
                Some(&json!({"key": got.to_string(), "signer": signer, "writable": writable})),
                "the open must name the accounts and privileges the program requires",
            ));
        }
    }
    let mut distribution = 1u32.to_le_bytes().to_vec();
    distribution.extend_from_slice(receiver.as_ref());
    distribution.extend_from_slice(&pc::FULL_SHARE_BPS.to_le_bytes());
    if !open.data.ends_with(&distribution) || open.data.len() != 29 + distribution.len() {
        return Err(fail(
            "open distribution must pay 100% to payTo, nothing else",
        ));
    }
    let mut want_memos = Vec::new();
    if let Some(memo) = &requirements.extra.memo {
        want_memos.push(memo.clone());
    }
    if let Some(authorizer) = &requirements.extra.receiver_authorizer {
        want_memos.push(fx::binding_memo(authorizer));
    }
    // Exactly the seller's memo and the binding memo, once each: a second
    // memo (another binding, a stray nonce) is not part of the setup suffix.
    let mut sorted_want = want_memos.clone();
    sorted_want.sort();
    let mut sorted_got = memos.clone();
    sorted_got.sort();
    if sorted_got != sorted_want {
        return Err(fail_at(
            "open.memos",
            Some(&json!(want_memos)),
            Some(&json!(memos)),
            "the open must carry exactly the seller memo and the receiver binding memo",
        ));
    }
    Ok(())
}

/// A client-mode refund (spec §4.3): the voucher at the charged cumulative
/// (checked by the caller), no `amount`, and an optional request_close the
/// sponsor's policy accepts.
fn judge_refund(
    payload: &Value,
    requirements: &BatchRequirements,
    config: &BatchChannelConfig,
    channel_id: &Pubkey,
) -> Result<(), Failure> {
    if payload.get("amount").is_some() {
        return Err(fail_at(
            "payload.amount",
            None,
            Some(&payload["amount"]),
            "a refund payload MUST NOT contain an amount",
        ));
    }
    let Some(transaction) = payload.get("transaction") else {
        return Ok(());
    };
    let transaction = transaction
        .as_str()
        .ok_or_else(|| fail("payload.transaction must be a base64 string"))?;
    let program_id = pc::default_program_id();
    let fee_payer =
        pc::parse_pubkey(&requirements.extra.fee_payer).map_err(|e| fail(e.to_string()))?;
    let token_program =
        pc::parse_pubkey(&requirements.extra.token_program).map_err(|e| fail(e.to_string()))?;
    let receiver = pc::parse_pubkey(&requirements.pay_to).map_err(|e| fail(e.to_string()))?;
    let accepted = solana_pay_kit::core::tx::accepted_versions(
        requirements.extra.transaction_versions.as_deref(),
    );
    let expectations = scheme::TransactionExpectations {
        program_id: &program_id,
        fee_payer: &fee_payer,
        accepted_versions: accepted,
        config,
        channel_id,
        token_program: &token_program,
        receiver: &receiver,
        memo: requirements.extra.memo.as_deref(),
    };
    scheme::validate_request_close_transaction(transaction, &expectations)
        .map(|_| ())
        .map_err(|e| fail(format!("refund request_close: {e}")))
}

// ── fixtures ───────────────────────────────────────────────────────────────

/// Deterministic batch-settlement wire objects, transactions and account
/// bytes for the case registry. Keys are seed-derived (`keys.rs` style);
/// account bytes use the kit's own `Channel` account type.
pub mod fx {
    use std::sync::Arc;

    use base64::Engine;
    use ed25519_dalek::Signer as _;
    use serde_json::{json, Value};
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::{v1, VersionedMessage};
    use solana_pay_kit::core::payment_channels as pc;
    use solana_pay_kit::core::store::MemoryChannelStore;
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use solana_transaction::versioned::VersionedTransaction;

    use crate::keys::{self, pubkey, pubkey_of_seed, secret_json};
    use crate::tx::{compile_v0, sign_slots, Decompiled};

    pub const NETWORK: &str = keys::DEVNET_CAIP2;
    pub const CLUSTER: &str = "devnet";
    pub const PRICE: &str = "0.001";
    /// `PRICE` in atomic units (6 decimals).
    pub const AMOUNT: u64 = 1_000;
    pub const WITHDRAW_DELAY: u32 = 3_600;
    pub const MAX_TIMEOUT: u64 = 300;
    pub const MEMO: &str = "invoice-42";
    pub const SALT: u64 = 42;
    pub const OPEN_SLOT: u64 = 341_000_000;
    /// The fixture's current slot: inside the open-slot window of `OPEN_SLOT`.
    pub const SLOT: u64 = 341_000_100;
    pub const PAYER_SEED: [u8; 32] = keys::CLIENT_SEED;
    pub const FEE_PAYER_SEED: [u8; 32] = keys::X402_SERVER_FEE_PAYER_SEED;
    /// The server's receiver-authorizer key, seed `[13; 32]`.
    pub const RECEIVER_AUTHORIZER_SEED: [u8; 32] = [13; 32];
    /// A key nobody in the channel controls, seed `[21; 32]`.
    pub const STRANGER_SEED: [u8; 32] = [21; 32];
    /// A resource-operator key for server-mode offers, seed `[23; 32]`.
    pub const OPERATOR_SEED: [u8; 32] = [23; 32];
    pub const LIGHTHOUSE: &str = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95";

    pub fn addr(seed: [u8; 32]) -> String {
        pubkey_of_seed(seed).to_string()
    }
    pub fn payer() -> String {
        addr(PAYER_SEED)
    }
    pub fn fee_payer() -> String {
        addr(FEE_PAYER_SEED)
    }
    pub fn receiver_authorizer() -> String {
        addr(RECEIVER_AUTHORIZER_SEED)
    }
    pub fn stranger() -> String {
        addr(STRANGER_SEED)
    }

    pub fn binding_memo(receiver_authorizer: &str) -> String {
        format!("x402:batch-settlement:svm:rcvauth:v1:{receiver_authorizer}")
    }

    /// A route's server configuration.
    #[derive(Clone)]
    pub struct Route {
        pub receiver_authorizer: Option<String>,
        pub memo: Option<&'static str>,
        pub withdraw_delay: u32,
        pub max_timeout: u64,
        pub price: &'static str,
        pub tx_versions: Option<Vec<u8>>,
    }

    impl Default for Route {
        fn default() -> Self {
            Self {
                receiver_authorizer: Some(receiver_authorizer()),
                memo: Some(MEMO),
                withdraw_delay: WITHDRAW_DELAY,
                max_timeout: MAX_TIMEOUT,
                price: PRICE,
                tx_versions: None,
            }
        }
    }

    impl Route {
        pub fn server_json(&self) -> Value {
            let mut server = json!({
                "payTo": keys::X402_PAY_TO,
                "currency": keys::MINT,
                "decimals": 6,
                "cluster": CLUSTER,
                "price": self.price,
                "withdrawDelay": self.withdraw_delay,
                "maxTimeoutSeconds": self.max_timeout,
                "feePayerSecretKey": secret_json(FEE_PAYER_SEED),
            });
            if let Some(memo) = self.memo {
                server["memo"] = json!(memo);
            }
            if let Some(authorizer) = &self.receiver_authorizer {
                server["receiverAuthorizer"] = json!(authorizer);
            }
            if let Some(versions) = &self.tx_versions {
                server["transactionVersions"] = json!(versions);
            }
            server
        }

        /// The requirements the kit server advertises for this route.
        pub fn requirements(&self) -> Value {
            let server = super::kit_server(
                &self.server_json(),
                None,
                Arc::new(MemoryChannelStore::new()),
            )
            .unwrap_or_else(|e| panic!("route server: {e}"));
            serde_json::to_value(
                server
                    .requirements(self.price)
                    .unwrap_or_else(|e| panic!("route requirements: {e}")),
            )
            .unwrap()
        }
    }

    /// The honest client's channel configuration for `route`.
    pub fn config(route: &Route) -> Value {
        let mut config = json!({
            "payer": payer(),
            "payerAuthorizer": payer(),
            "receiver": keys::X402_PAY_TO,
            "token": keys::MINT,
            "withdrawDelay": route.withdraw_delay,
            "salt": SALT.to_string(),
            "openSlot": OPEN_SLOT,
        });
        if let Some(authorizer) = &route.receiver_authorizer {
            config["receiverAuthorizer"] = json!(authorizer);
        }
        config
    }

    /// The channel PDA a configuration derives (`extra.feePayer` as payee).
    pub fn channel_id(config: &Value) -> Pubkey {
        let s = |k: &str| pubkey(config[k].as_str().unwrap());
        let salt: u64 = config["salt"].as_str().unwrap().parse().unwrap();
        pc::find_channel_pda(
            &s("payer"),
            &pubkey(&fee_payer()),
            &s("token"),
            &s("payerAuthorizer"),
            salt,
            config["openSlot"].as_u64().unwrap(),
            &pc::default_program_id(),
        )
        .0
    }

    pub fn sign_voucher(channel: &str, cumulative: u64, expires_at: i64, seed: [u8; 32]) -> String {
        let message = pc::voucher_message_bytes(&pubkey(channel), cumulative, expires_at).unwrap();
        bs58::encode(keys::signing_key(seed).sign(&message).to_bytes()).into_string()
    }

    /// A `BatchVoucher` signed by `seed`.
    pub fn voucher(channel: &str, cumulative: u64, expires_at: i64, seed: [u8; 32]) -> Value {
        json!({
            "channelId": channel,
            "maxClaimableAmount": cumulative.to_string(),
            "expiresAt": expires_at,
            "signature": sign_voucher(channel, cumulative, expires_at, seed),
        })
    }

    pub fn header(accepted: &Value, payload: &Value) -> String {
        envelope_header(&json!({ "x402Version": 2, "accepted": accepted, "payload": payload }))
    }

    pub fn envelope_header(envelope: &Value) -> String {
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(envelope).unwrap())
    }

    // ── chain state ──

    pub fn token_account(owner: &str, state: u8) -> Value {
        let mut data = Vec::with_capacity(165);
        data.extend_from_slice(pubkey(keys::MINT).as_ref());
        data.extend_from_slice(pubkey(owner).as_ref());
        data.extend_from_slice(&1_000_000_000u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 36]); // delegate: None
        data.push(state);
        data.extend_from_slice(&[0u8; 12]); // is_native: None
        data.extend_from_slice(&0u64.to_le_bytes()); // delegated_amount
        data.extend_from_slice(&[0u8; 36]); // close_authority: None
        json!({
            "owner": keys::TOKEN_PROGRAM,
            "data": base64::engine::general_purpose::STANDARD.encode(data),
        })
    }

    /// Onchain fields of a channel account, defaulting to the honest
    /// channel the configuration opened.
    #[derive(Clone)]
    pub struct ChannelAccount {
        pub status: u8,
        pub deposit: u64,
        pub settled: u64,
        pub closure_started_at: i64,
        pub discriminator: u8,
        pub payee: String,
        pub distribution_to: String,
        pub empty_distribution: bool,
    }

    impl Default for ChannelAccount {
        fn default() -> Self {
            Self {
                status: 0,
                deposit: 10_000,
                settled: 0,
                closure_started_at: 0,
                // `AccountDiscriminator::Channel` in the program IDL.
                discriminator: 1,
                payee: fee_payer(),
                distribution_to: keys::X402_PAY_TO.to_string(),
                empty_distribution: false,
            }
        }
    }

    pub fn channel_account(config: &Value, account: &ChannelAccount) -> Value {
        use pc::generated::generated::accounts::Channel;
        use pc::generated::generated::types::SettlementWatermarks;
        let s = |k: &str| pc::to_address(&pubkey(config[k].as_str().unwrap()));
        let distribution_hash = if account.empty_distribution {
            [0u8; 32]
        } else {
            pc::distribution_hash(&pc::sole_recipient(&pubkey(&account.distribution_to)))
        };
        let bump = pc::find_channel_pda(
            &pubkey(config["payer"].as_str().unwrap()),
            &pubkey(&fee_payer()),
            &pubkey(config["token"].as_str().unwrap()),
            &pubkey(config["payerAuthorizer"].as_str().unwrap()),
            config["salt"].as_str().unwrap().parse().unwrap(),
            config["openSlot"].as_u64().unwrap(),
            &pc::default_program_id(),
        )
        .1;
        let channel = Channel {
            discriminator: account.discriminator,
            version: 1,
            bump,
            status: account.status,
            salt: config["salt"].as_str().unwrap().parse().unwrap(),
            deposit: account.deposit,
            settlement: SettlementWatermarks {
                settled: account.settled,
                payout_watermark: 0,
            },
            closure_started_at: account.closure_started_at,
            payer_withdrawn_at: 0,
            grace_period: config["withdrawDelay"].as_u64().unwrap() as u32,
            distribution_hash,
            payer: s("payer"),
            payee: pc::to_address(&pubkey(&account.payee)),
            authorized_signer: s("payerAuthorizer"),
            mint: s("token"),
            rent_payer: pc::to_address(&pubkey(&fee_payer())),
            open_slot: config["openSlot"].as_u64().unwrap(),
        };
        let data = borsh::to_vec(&channel).unwrap();
        assert_eq!(data.len(), pc::CHANNEL_ACCOUNT_SIZE);
        json!({
            "owner": pc::default_program_id().to_string(),
            "data": base64::engine::general_purpose::STANDARD.encode(data),
        })
    }

    /// Which settlement token accounts exist and in what state.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Atas {
        /// Every settlement ATA initialized (state 1).
        Healthy,
        /// The `payTo` recipient ATA is absent.
        MissingReceiver,
        /// The payer's return ATA is frozen (state 2).
        FrozenPayer,
    }

    /// `rpcFixtures`: the mint, the settlement ATAs and, when given, the
    /// channel account.
    pub fn rpc_fixtures(
        channel: Option<(&Value, &ChannelAccount)>,
        atas: Atas,
        mint_owner: &str,
    ) -> Value {
        let mut accounts = serde_json::Map::new();
        let ata = |owner: &str| keys::ata(owner, keys::MINT, keys::TOKEN_PROGRAM).to_string();
        let treasury = pc::treasury_owner_for_cluster(CLUSTER).to_string();
        for (owner, state) in [
            (fee_payer(), 1u8),
            (treasury, 1),
            (keys::X402_PAY_TO.to_string(), 1),
            (payer(), if atas == Atas::FrozenPayer { 2 } else { 1 }),
        ] {
            if atas == Atas::MissingReceiver && owner == keys::X402_PAY_TO {
                continue;
            }
            accounts.insert(ata(&owner), token_account(&owner, state));
        }
        if let Some((config, account)) = channel {
            accounts.insert(
                channel_id(config).to_string(),
                channel_account(config, account),
            );
        }
        json!({
            "recentBlockhash": keys::BLOCKHASH,
            "slot": SLOT,
            "mints": { keys::MINT: { "owner": mint_owner, "decimals": 6 } },
            "accounts": accounts,
        })
    }

    /// The server's stored record for the channel.
    pub fn store_record(config: &Value, charged: u64, deposit: u64) -> Value {
        json!({
            "channelId": channel_id(config).to_string(),
            "payer": config["payer"],
            "payerAuthorizer": config["payerAuthorizer"],
            "openSlot": config["openSlot"],
            "chargedCumulativeAmount": charged.to_string(),
            "deposit": deposit.to_string(),
            "settled": "0",
        })
    }

    // ── transactions ──

    pub fn memo_ix(text: &str) -> Instruction {
        Instruction {
            program_id: pc::memo_program_id(),
            accounts: vec![],
            data: text.as_bytes().to_vec(),
        }
    }

    pub fn lighthouse_ix(data: &[u8]) -> Instruction {
        Instruction {
            program_id: pubkey(LIGHTHOUSE),
            accounts: vec![],
            data: data.to_vec(),
        }
    }

    pub fn compute_ix(data: &[u8]) -> Instruction {
        Instruction {
            program_id: pubkey(keys::COMPUTE_BUDGET_PROGRAM),
            accounts: vec![],
            data: data.to_vec(),
        }
    }

    pub fn unit_limit(units: u32) -> Vec<u8> {
        let mut d = vec![2u8];
        d.extend_from_slice(&units.to_le_bytes());
        d
    }

    pub fn unit_price(micro: u64) -> Vec<u8> {
        let mut d = vec![3u8];
        d.extend_from_slice(&micro.to_le_bytes());
        d
    }

    pub fn top_up_ix(config: &Value, amount: u64) -> Instruction {
        pc::build_top_up_instruction(
            &pubkey(config["payer"].as_str().unwrap()),
            &channel_id(config),
            &pubkey(config["token"].as_str().unwrap()),
            amount,
            &pubkey(keys::TOKEN_PROGRAM),
            &pc::default_program_id(),
        )
    }

    pub fn request_close_ix(config: &Value) -> Instruction {
        pc::build_request_close_instruction(
            &pubkey(config["payer"].as_str().unwrap()),
            &channel_id(config),
            &pc::default_program_id(),
        )
    }

    /// The canonical `open` for `config`, recipient `pay_to` at 100%.
    pub fn open_ix(config: &Value, deposit: u64, pay_to: &str) -> Instruction {
        let s = |k: &str| pubkey(config[k].as_str().unwrap());
        pc::build_open_instruction(&pc::OpenChannelParams {
            payer: s("payer"),
            rent_payer: pubkey(&fee_payer()),
            payee: pubkey(&fee_payer()),
            mint: s("token"),
            authorized_signer: s("payerAuthorizer"),
            salt: config["salt"].as_str().unwrap().parse().unwrap(),
            open_slot: config["openSlot"].as_u64().unwrap(),
            deposit,
            grace_period: config["withdrawDelay"].as_u64().unwrap() as u32,
            recipients: pc::sole_recipient(&pubkey(pay_to)),
            token_program: pubkey(keys::TOKEN_PROGRAM),
            program_id: pc::default_program_id(),
        })
    }

    /// Mark `key` a read-only signer on `ix` (an extra required signature).
    pub fn with_signer(mut ix: Instruction, key: &str) -> Instruction {
        ix.accounts
            .push(AccountMeta::new_readonly(pubkey(key), true));
        ix
    }

    /// Compile as version 0 with `fee_payer` paying, sign `signers`' slots.
    pub fn v0_tx(instructions: Vec<Instruction>, fee_payer: &str, signers: &[[u8; 32]]) -> String {
        let mut tx = compile_v0(&Decompiled {
            fee_payer: pubkey(fee_payer),
            blockhash: Hash::default(),
            instructions,
        })
        .unwrap();
        sign_slots(&mut tx, signers);
        crate::tx::encode_b64(&tx).unwrap()
    }

    /// The payer-signed, sponsor-unsigned version-0 transaction.
    pub fn sponsored(instructions: Vec<Instruction>) -> String {
        v0_tx(instructions, &fee_payer(), &[PAYER_SEED])
    }

    /// A legacy (unversioned) message, payer-signed.
    pub fn sponsored_legacy(instructions: Vec<Instruction>) -> String {
        let message = solana_message::legacy::Message::new_with_blockhash(
            &instructions,
            Some(&pubkey(&fee_payer())),
            &Hash::default(),
        );
        let message = VersionedMessage::Legacy(message);
        let mut tx = VersionedTransaction {
            signatures: vec![
                Signature::default();
                message.header().num_required_signatures as usize
            ],
            message,
        };
        sign_slots(&mut tx, &[PAYER_SEED]);
        crate::tx::encode_b64(&tx).unwrap()
    }

    /// A version-1 message whose header config is `config`, payer-signed.
    pub fn sponsored_v1(instructions: Vec<Instruction>, config: v1::TransactionConfig) -> String {
        let message = VersionedMessage::V1(
            v1::Message::try_compile_with_config(
                &pubkey(&fee_payer()),
                &instructions,
                Hash::default(),
                config,
            )
            .unwrap(),
        );
        let mut tx = VersionedTransaction {
            signatures: vec![
                Signature::default();
                message.header().num_required_signatures as usize
            ],
            message,
        };
        sign_slots(&mut tx, &[PAYER_SEED]);
        crate::tx::encode_b64(&tx).unwrap()
    }

    /// The canonical version-1 header budget: limit 200k, price 1000
    /// µlamports/CU (a 200-lamport total priority fee), full loaded-data
    /// limit.
    pub fn v1_budget() -> v1::TransactionConfig {
        v1::TransactionConfig::empty()
            .with_compute_unit_limit(200_000)
            .with_priority_fee(200)
            .with_loaded_accounts_data_size_limit(64 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::Intent;
    use crate::run::vectors;
    use solana_message::VersionedMessage;

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

    /// The kit's own build of `id`, decoded, edited by `edit`, re-encoded.
    fn edited_build(rt: &tokio::runtime::Runtime, v: &Vector, edit: impl Fn(&mut Value)) -> String {
        let header = match rt.block_on(super::super::run(
            Intent::X402BatchSettlement,
            Mode::BuildTransaction,
            v.input(),
        )) {
            Observed::Accept(output) => output.header.unwrap(),
            other => panic!("{}: {}", v.id, other.summary()),
        };
        let engine = base64::engine::general_purpose::STANDARD;
        let mut envelope: Value = serde_json::from_slice(&engine.decode(header).unwrap()).unwrap();
        edit(&mut envelope);
        engine.encode(serde_json::to_vec(&envelope).unwrap())
    }

    // The kit's deposit build is a known failure (FINDINGS.md
    // #batch-open-binding-memo: no binding memo), which the judge reports
    // last; an inflated declared deposit must fail first, on the deposit.
    #[test]
    fn a_declared_deposit_the_open_does_not_fund_fails_the_build_judge() {
        let rt = runtime();
        let v = vector("batch-build-deposit-open");
        let honest = edited_build(&rt, &v, |_| {});
        let kit = rt.block_on(judge_build(&v, &honest)).unwrap_err();
        assert_eq!(kit.path.as_deref(), Some("open.memos"), "{}", kit.message);
        assert!(
            kit.expected
                .as_ref()
                .is_some_and(|e| e.to_string().contains("rcvauth")),
            "{:?}",
            kit.expected
        );
        let inflated = edited_build(&rt, &v, |e| {
            let declared = u64_field(&e["payload"]["deposit"], "amount").unwrap();
            e["payload"]["deposit"]["amount"] = json!((declared + 1).to_string());
        });
        let failure = rt.block_on(judge_build(&v, &inflated)).unwrap_err();
        assert!(
            failure.message.contains("payload.deposit.amount"),
            "{}",
            failure.message
        );
    }

    // The open names 14 accounts; the judge used to check only the payer,
    // rent payer, payee and channel slots. A payer re-signing a deposit
    // whose token accounts or token program are swapped must fail on that
    // account, before the memo check the kit's own build fails last.
    #[test]
    fn a_swapped_open_account_fails_the_build_judge() {
        let rt = runtime();
        let v = vector("batch-build-deposit-open");
        let seed: [u8; 32] = v.input()["batchClient"]["secretKey"]
            .as_array()
            .unwrap()
            .iter()
            .take(32)
            .map(|b| b.as_u64().unwrap() as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        for slot in [6usize, 7, 8] {
            let swapped = edited_build(&rt, &v, |e| {
                let mut tx =
                    crate::tx::decode_b64(e["payload"]["deposit"]["transaction"].as_str().unwrap())
                        .unwrap();
                let program = pc::default_program_id();
                let keys = tx.message.static_account_keys();
                let open = tx
                    .message
                    .instructions()
                    .iter()
                    .find(|ix| keys[ix.program_id_index as usize] == program)
                    .unwrap();
                let index = open.accounts[slot] as usize;
                match &mut tx.message {
                    VersionedMessage::Legacy(m) => m.account_keys[index] = Pubkey::new_unique(),
                    VersionedMessage::V0(m) => m.account_keys[index] = Pubkey::new_unique(),
                    _ => panic!("the kit builds legacy or version 0"),
                }
                crate::tx::sign_slots(&mut tx, &[seed]);
                e["payload"]["deposit"]["transaction"] = json!(crate::tx::encode_b64(&tx).unwrap());
            });
            let failure = rt.block_on(judge_build(&v, &swapped)).unwrap_err();
            assert_eq!(
                failure.path.as_deref(),
                Some(format!("open.accounts[{slot}]").as_str()),
                "slot {slot}: {}",
                failure.message
            );
        }
    }

    // An index past the static keys decodes; the judge must report it as a
    // failed build instead of panicking the run.
    #[test]
    fn an_open_account_index_out_of_range_fails_the_build_judge() {
        let rt = runtime();
        let v = vector("batch-build-deposit-open");
        let seed: [u8; 32] = v.input()["batchClient"]["secretKey"].as_array().unwrap()[..32]
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let broken = edited_build(&rt, &v, |e| {
            let mut tx =
                crate::tx::decode_b64(e["payload"]["deposit"]["transaction"].as_str().unwrap())
                    .unwrap();
            let program = pc::default_program_id();
            let keys = tx.message.static_account_keys().to_vec();
            let at = tx
                .message
                .instructions()
                .iter()
                .position(|ix| keys[ix.program_id_index as usize] == program)
                .unwrap();
            match &mut tx.message {
                VersionedMessage::Legacy(m) => m.instructions[at].accounts[6] = 200,
                VersionedMessage::V0(m) => m.instructions[at].accounts[6] = 200,
                _ => panic!("the kit builds legacy or version 0"),
            }
            crate::tx::sign_slots(&mut tx, &[seed]);
            e["payload"]["deposit"]["transaction"] = json!(crate::tx::encode_b64(&tx).unwrap());
        });
        let failure = rt.block_on(judge_build(&v, &broken)).unwrap_err();
        assert!(failure.message.contains("200"), "{}", failure.message);
    }

    /// `memos` appended to the kit's deposit open, re-signed by the payer.
    fn with_memos(e: &mut Value, seed: [u8; 32], memos: &[String]) {
        let tx = crate::tx::decode_b64(e["payload"]["deposit"]["transaction"].as_str().unwrap())
            .unwrap();
        let mut d = crate::tx::decompile(&tx.message).unwrap();
        for memo in memos {
            d.instructions.push(solana_instruction::Instruction {
                program_id: pc::memo_program_id(),
                accounts: vec![],
                data: memo.as_bytes().to_vec(),
            });
        }
        let mut out = crate::tx::recompile(&tx.message, &d).unwrap();
        crate::tx::sign_slots(&mut out, &[seed]);
        e["payload"]["deposit"]["transaction"] = json!(crate::tx::encode_b64(&out).unwrap());
    }

    fn client_seed(v: &Vector) -> [u8; 32] {
        v.input()["batchClient"]["secretKey"].as_array().unwrap()[..32]
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    // The deposit judge binds channelConfig to the requirements and the
    // client's key, and takes exactly the seller and binding memos.
    #[test]
    fn a_deposit_off_its_requirements_fails_the_build_judge() {
        let rt = runtime();
        let v = vector("batch-build-deposit-open");
        let seed = client_seed(&v);
        let authorizer = v.input()["batchClient"]["requirements"]["extra"]["receiverAuthorizer"]
            .as_str()
            .unwrap()
            .to_string();
        let binding = fx::binding_memo(&authorizer);
        let complete = edited_build(&rt, &v, |e| {
            with_memos(e, seed, std::slice::from_ref(&binding))
        });
        rt.block_on(judge_build(&v, &complete)).unwrap();

        let extra = edited_build(&rt, &v, |e| {
            with_memos(e, seed, &[binding.clone(), "a second memo".into()])
        });
        let failure = rt.block_on(judge_build(&v, &extra)).unwrap_err();
        assert_eq!(
            failure.path.as_deref(),
            Some("open.memos"),
            "{}",
            failure.message
        );

        for (field, value) in [
            ("token", json!(crate::keys::OTHER_MINT)),
            ("payerAuthorizer", json!(fx::stranger())),
        ] {
            let off = edited_build(&rt, &v, |e| {
                with_memos(e, seed, std::slice::from_ref(&binding));
                e["payload"]["channelConfig"][field] = value.clone();
            });
            let failure = rt.block_on(judge_build(&v, &off)).unwrap_err();
            assert!(
                failure
                    .path
                    .as_deref()
                    .is_some_and(|p| p.starts_with("payload.channelConfig")),
                "{field}: {:?} {}",
                failure.path,
                failure.message
            );
        }
    }

    // A self-consistent top-up of another amount used to pass: the server
    // ties the transaction to payload.deposit.amount, not to the request.
    #[test]
    fn a_top_up_of_another_amount_fails_the_build_judge() {
        let rt = runtime();
        let v = vector("batch-build-top-up");
        let honest = edited_build(&rt, &v, |_| {});
        rt.block_on(judge_build(&v, &honest)).unwrap();
        for amount in ["1", "600000"] {
            let mut input = v.input().clone();
            input["batchClient"]["depositAmount"] = json!(amount);
            let other = match rt.block_on(super::super::run(
                Intent::X402BatchSettlement,
                Mode::BuildTransaction,
                &input,
            )) {
                Observed::Accept(output) => output.header.unwrap(),
                other => panic!("{amount}: {}", other.summary()),
            };
            let failure = rt.block_on(judge_build(&v, &other)).unwrap_err();
            assert_eq!(
                failure.path.as_deref(),
                Some("payload.deposit.amount"),
                "{amount}: {}",
                failure.message
            );
        }
    }

    /// A spec-shaped client refund (§4.3): channelConfig plus the voucher at
    /// the charged cumulative. The kit's own refund is the superseded shape
    /// (FINDINGS.md#batch-refund-superseded-shape), so it is built here.
    fn spec_refund(rt: &tokio::runtime::Runtime, v: &Vector, extra: &[(&str, Value)]) -> String {
        let c = &v.input()["batchClient"];
        let config: BatchChannelConfig =
            serde_json::from_value(c["channel"]["channelConfig"].clone()).unwrap();
        let requirements: BatchRequirements =
            serde_json::from_value(c["requirements"].clone()).unwrap();
        let channel_id = client::channel_id_for(&config, &requirements).unwrap();
        let charged = u64_field(&c["channel"], "chargedCumulativeAmount").unwrap();
        let payer = signer(c, "secretKey").unwrap();
        let voucher = rt
            .block_on(client::sign_voucher(&payer, &channel_id, charged))
            .unwrap();
        let mut payload = json!({
            "type": "refund",
            "channelConfig": c["channel"]["channelConfig"],
            "voucher": voucher,
        });
        for (k, val) in extra {
            payload[*k] = val.clone();
        }
        let envelope = json!({
            "x402Version": 2,
            "accepted": c["requirements"],
            "payload": payload,
        });
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&envelope).unwrap())
    }

    #[test]
    fn a_refund_carrying_an_amount_fails_the_build_judge() {
        let rt = runtime();
        let v = vector("batch-build-refund");
        rt.block_on(judge_build(&v, &spec_refund(&rt, &v, &[])))
            .unwrap_or_else(|f| panic!("spec refund: {}", f.message));
        let with_amount = spec_refund(&rt, &v, &[("amount", json!("1"))]);
        let failure = rt.block_on(judge_build(&v, &with_amount)).unwrap_err();
        assert!(failure.message.contains("amount"), "{}", failure.message);
        let bad_tx = spec_refund(&rt, &v, &[("transaction", json!("AQID"))]);
        let failure = rt.block_on(judge_build(&v, &bad_tx)).unwrap_err();
        assert!(
            failure.message.contains("request_close"),
            "{}",
            failure.message
        );
    }
}
