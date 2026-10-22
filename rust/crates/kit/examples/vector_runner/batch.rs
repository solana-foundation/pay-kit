//! `x402-batch-settlement` vectors: the testee passes the vector's input to
//! the kit unchanged (harness/AGENTS.md "Never put logic in the testee").
//!
//! - canonical-bytes: the kit's voucher layout, payer-proof message, channel
//!   PDA derivation, CloseAuthorization digest, receiver-binding memo and
//!   wire types.
//! - verify-transaction: `X402BatchSettlement` configured from
//!   `batchServer`, its store seeded with the record `batchServerChannel`
//!   describes, runs `verify_and_reserve_payment` against `input.rpcUrl`;
//!   `batchCorrective` runs the client's `adopt_corrective_state`.
//! - build-transaction: the kit client (`resolve_terms` on `input.rpcUrl`,
//!   then `build_deposit` / `voucher_payload` / `build_top_up` /
//!   `build_refund` (the cooperative refund), then `encode_payment_header`).
//!
//! Rejections carry the spec's error code mapped onto the shared vocabulary.

use std::sync::Arc;

use base64::Engine;
use serde_json::{json, Map, Value};
use solana_pay_kit::core::payment_channels as pc;
use solana_pay_kit::core::store::{ChannelStore, MemoryChannelStore};
use solana_pay_kit::core::tx::{TxV1Mode, TxVersion};
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_pay_kit::x402::client::batch_settlement as client;
use solana_pay_kit::x402::protocol::schemes::batch_settlement::{
    self as scheme, errors as codes, BatchChannelConfig, BatchPayload, BatchPaymentPayload,
    BatchRedemptionPayload, BatchRequiredEnvelope, BatchRequirements, BatchSettlementResponse,
    BatchVoucher,
};
use solana_pay_kit::x402::server::batch_settlement::{
    BatchAccess, BatchConfig, X402BatchSettlement,
};

use super::{str_field, Outcome, Rejection};

pub async fn run(mode: &str, input: &Value) -> Result<Outcome, Rejection> {
    match mode {
        "canonical-bytes" => canonical(input),
        "verify-transaction" if input.get("batchCorrective").is_some() => corrective(input),
        "verify-transaction" => server_verify(input).await,
        "build-transaction" => client_build(input).await,
        other => Ok(Outcome::Unsupported(format!(
            "no Rust runner path for x402-batch-settlement mode {other:?}"
        ))),
    }
}

/// The shared reject code for a spec error code (spec §7).
fn code_for(wire: &str) -> Option<&'static str> {
    Some(match wire {
        codes::INVALID_PAYLOAD_TYPE => "payload-type",
        codes::INVALID_PAYMENT_FLOW => "payment-flow",
        codes::INVALID_TOKEN_PROGRAM => "token-program",
        codes::INVALID_VOUCHER_SIGNATURE => "voucher-signature",
        codes::INVALID_CHANNEL_ID_MISMATCH => "channel-id-mismatch",
        codes::INVALID_FEE_PAYER_MISMATCH => "fee-payer-mismatch",
        codes::INVALID_RECEIVER_AUTHORIZER_MISMATCH => "receiver-authorizer-mismatch",
        codes::INVALID_CLOSE_AUTHORIZATION => "close-authorization",
        codes::INVALID_CLOSE_AMOUNT_UNSUPPORTED => "close-amount-unsupported",
        codes::INVALID_CLOSE_STATE => "close-state",
        codes::INVALID_WITHDRAW_DELAY_MISMATCH => "withdraw-delay-mismatch",
        codes::INVALID_WITHDRAW_DELAY_OUT_OF_RANGE => "withdraw-delay-out-of-range",
        codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH => "cumulative-amount-mismatch",
        codes::INVALID_CUMULATIVE_EXCEEDS_DEPOSIT => "cumulative-exceeds-deposit",
        codes::INVALID_VOUCHER_EXPIRY => "voucher-expiry",
        codes::INVALID_SETUP_TRANSACTION => "setup-transaction",
        codes::INVALID_SETTLEMENT_SIMULATION => "settlement-simulation",
        codes::INVALID_CHANNEL_STATE => "channel-state",
        codes::INVALID_REFUND_TRANSACTION => "refund-transaction",
        codes::INVALID_CHANNEL_CLOSING => "channel-closing",
        codes::INVALID_RECEIVER_BINDING_UNAVAILABLE => "receiver-binding-unavailable",
        codes::INVALID_X402_VERSION | codes::UNSUPPORTED_TRANSACTION_VERSION => {
            "unsupported-version"
        }
        codes::INVALID_PAYMENT_REQUIREMENTS => "accepted-mismatch",
        codes::DUPLICATE_SETTLEMENT => "duplicate-settlement",
        _ => return None,
    })
}

fn reject(code: Option<&'static str>, message: impl Into<String>) -> Outcome {
    Outcome::Reject(Rejection {
        message: message.into(),
        code,
    })
}

fn kit_reject(error: &solana_pay_kit::x402::Error) -> Outcome {
    use solana_pay_kit::x402::Error;
    let message = error.to_string();
    let code = code_for(scheme::classify(&message)).or(match error {
        Error::InvalidPayloadType(_) => Some("unsupported-scheme"),
        Error::InvalidPaymentRequired(_) => Some("invalid-payload"),
        _ => None,
    });
    reject(code, message)
}

/// A client refusing a challenge: the version negotiation failure is
/// `unsupported-version`, any other refusal of the terms a
/// refused challenge.
fn client_reject(error: &solana_pay_kit::x402::Error) -> Outcome {
    let message = error.to_string();
    let code = code_for(scheme::classify(&message)).unwrap_or(
        if message.contains("the server accepts transaction versions") {
            "unsupported-version"
        } else {
            "invalid-challenge"
        },
    );
    reject(Some(code), message)
}

fn invalid(message: impl Into<String>) -> Outcome {
    reject(Some("invalid-payload"), message)
}

fn bytes_outcome(bytes: &[u8]) -> Outcome {
    let mut exact = Map::new();
    exact.insert("bytes".into(), json!(bytes));
    exact.insert(
        "base64Url".into(),
        json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)),
    );
    let mut fields = Map::new();
    fields.insert("exactBytes".into(), Value::Object(exact));
    Outcome::Accept(fields)
}

fn canonical(input: &Value) -> Result<Outcome, Rejection> {
    if let Some(vm) = input.get("batchVoucherMessage") {
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
        return Ok(
            match pc::voucher_message_bytes(&channel, amount, voucher.expires_at) {
                Ok(bytes) => bytes_outcome(&bytes),
                Err(e) => invalid(e.to_string()),
            },
        );
    }
    if let Some(am) = input.get("batchAuthorizationMessage") {
        let key = |k: &str| pc::parse_pubkey(str_field(am, k));
        let (channel, payer, operator) = match (key("channelId"), key("payer"), key("operator")) {
            (Ok(c), Ok(p), Ok(o)) => (c, p, o),
            _ => return Ok(invalid("authorization addresses must be base58 pubkeys")),
        };
        let Ok(amount) = str_field(am, "authorizedAmount").parse::<u64>() else {
            return Ok(invalid("authorizedAmount must be a decimal u64"));
        };
        return Ok(
            match client::authorization_message_bytes(
                &channel,
                &payer,
                &operator,
                str_field(am, "requestId"),
                amount,
                am.get("expiresAt").and_then(Value::as_i64).unwrap_or(0),
            ) {
                Ok(bytes) => bytes_outcome(&bytes),
                Err(e) => invalid(e.to_string()),
            },
        );
    }
    if let Some(cd) = input.get("batchCloseAuthorizationDigest") {
        let key = |k: &str| pc::parse_pubkey(str_field(cd, k));
        let (program_id, fee_payer, channel_id) =
            match (key("programId"), key("feePayer"), key("channelId")) {
                (Ok(p), Ok(f), Ok(c)) => (p, f, c),
                _ => {
                    return Ok(invalid(
                        "close authorization addresses must be base58 pubkeys",
                    ))
                }
            };
        let Ok(max_claimable_amount) = str_field(cd, "maxClaimableAmount").parse::<u64>() else {
            return Ok(invalid("maxClaimableAmount must be a decimal u64"));
        };
        let (Some(voucher_expires_at), Some(valid_before)) = (
            cd.get("voucherExpiresAt").and_then(Value::as_i64),
            cd.get("validBefore").and_then(Value::as_i64),
        ) else {
            return Ok(invalid("voucherExpiresAt and validBefore must be integers"));
        };
        let scope = scheme::CloseAuthorizationScope {
            network: str_field(cd, "network"),
            program_id: &program_id,
            fee_payer: &fee_payer,
            channel_id: &channel_id,
            max_claimable_amount,
            voucher_expires_at,
        };
        return Ok(
            match scheme::close_authorization_digest(&scope, valid_before) {
                Ok(digest) => bytes_outcome(&digest),
                Err(e) => invalid(e.to_string()),
            },
        );
    }
    if let Some(binding) = input.get("batchReceiverBindingMemo") {
        return Ok(
            match pc::parse_pubkey(str_field(binding, "receiverAuthorizer")) {
                Ok(key) => bytes_outcome(scheme::receiver_binding_memo(&key).as_bytes()),
                Err(e) => invalid(e.to_string()),
            },
        );
    }
    if let Some(ci) = input.get("batchChannelId") {
        let config: BatchChannelConfig =
            match serde_json::from_value(ci.get("channelConfig").cloned().unwrap_or(Value::Null)) {
                Ok(c) => c,
                Err(e) => return Ok(invalid(format!("invalid channelConfig: {e}"))),
            };
        return Ok(
            match scheme::derive_channel_id(
                &config,
                str_field(ci, "feePayer"),
                &pc::default_program_id(),
            ) {
                Ok(id) => bytes_outcome(id.as_ref()),
                Err(e) => invalid(e.to_string()),
            },
        );
    }
    if let Some(wire) = input.get("batchWire") {
        let value = wire.get("value").cloned().unwrap_or(Value::Null);
        let reencoded =
            match str_field(wire, "shape") {
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
                other => return Ok(Outcome::Unsupported(format!("batchWire shape {other:?}"))),
            };
        return Ok(match reencoded {
            Ok(value) => {
                let (json, b64) = super::canonical_json(&value)?;
                let mut exact = Map::new();
                exact.insert("canonicalJson".into(), json!(json));
                exact.insert("base64Url".into(), json!(b64));
                let mut fields = Map::new();
                fields.insert("exactBytes".into(), Value::Object(exact));
                Outcome::Accept(fields)
            }
            Err(e) => invalid(format!("invalid batch-settlement wire object: {e}")),
        });
    }
    Ok(Outcome::Unsupported(
        "no batch-settlement canonical-bytes key in input".into(),
    ))
}

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

/// `X402BatchSettlement` from the vector's `batchServer` configuration.
fn kit_server(
    server: &Value,
    rpc_url: String,
    store: Arc<dyn ChannelStore>,
) -> Result<X402BatchSettlement, String> {
    let mut config = BatchConfig::new(
        str_field(server, "payTo"),
        str_field(server, "cluster"),
        Arc::new(signer(server, "feePayerSecretKey")?),
    );
    config.currency = str_field(server, "currency").to_string();
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
    config.rpc_url = Some(rpc_url);
    let handler = X402BatchSettlement::with_store(config, store).map_err(|e| e.to_string())?;
    let v1 = server
        .get("transactionVersions")
        .and_then(Value::as_array)
        .is_some_and(|versions| versions.iter().any(|v| v.as_u64() == Some(1)));
    Ok(handler.with_tx_v1(if v1 { TxV1Mode::On } else { TxV1Mode::Off }))
}

/// The record this server wrote for the channel, as `batchServerChannel`
/// describes it.
async fn seed_channel(
    server: &X402BatchSettlement,
    store: &MemoryChannelStore,
    record: &Value,
) -> Result<(), String> {
    let channel_id = str_field(record, "channelId").to_string();
    let mut state = super::fresh_channel(
        &channel_id,
        str_field(record, "payerAuthorizer"),
        u64_field(record, "deposit")?,
    );
    state.payer = str_field(record, "payer").to_string();
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

async fn server_verify(input: &Value) -> Result<Outcome, Rejection> {
    let server_json = input.get("batchServer").ok_or("batchServer missing")?;
    let store = Arc::new(MemoryChannelStore::new());
    let server = kit_server(server_json, super::fixture_rpc_url(input)?, store.clone())?;
    if let Some(record) = input.get("batchServerChannel") {
        seed_channel(&server, &store, record).await?;
    }
    Ok(
        match server
            .verify_and_reserve_payment(
                str_field(input, "x402PaymentHeader"),
                str_field(server_json, "price"),
            )
            .await
        {
            Ok(BatchAccess::Serve(_) | BatchAccess::Control(_)) => Outcome::Accept(Map::new()),
            Ok(_) => reject(
                None,
                "verify did not serve the request (replay or in progress)",
            ),
            Err(error) => kit_reject(&error),
        },
    )
}

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

fn corrective(input: &Value) -> Result<Outcome, Rejection> {
    let c = &input["batchCorrective"];
    let requirements: BatchRequirements =
        serde_json::from_value(c["requirements"].clone()).map_err(|e| e.to_string())?;
    let mut channel = tracker(&c["channel"], &requirements)?;
    Ok(match channel.adopt_corrective_state(&requirements) {
        Ok(_) => Outcome::Accept(Map::new()),
        Err(error) => kit_reject(&error),
    })
}

async fn client_build(input: &Value) -> Result<Outcome, Rejection> {
    let c = input.get("batchClient").ok_or("batchClient missing")?;
    let requirements: BatchRequirements = match serde_json::from_value(c["requirements"].clone()) {
        Ok(r) => r,
        // A spec code the kit tagged the parse failure with wins (a
        // non-integer withdrawDelay is out of range); otherwise a refused
        // challenge.
        Err(e) => {
            return Ok(client_reject(&solana_pay_kit::x402::Error::Other(
                e.to_string(),
            )))
        }
    };
    let payer = signer(c, "secretKey")?;
    let rpc = super::fixture_rpc(input)?;
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
        str_field(c, "blockhash")
            .parse()
            .map_err(|e| format!("blockhash: {e}"))
    };
    let payload = match str_field(c, "operation") {
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
            tracker(&c["channel"], &requirements)?
                .voucher_payload(&payer, terms.amount)
                .await
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
            client::build_refund(&payer, &channel, &terms).await
        }
        other => {
            return Ok(Outcome::Unsupported(format!(
                "batchClient.operation {other:?}"
            )))
        }
    };
    Ok(
        match payload.and_then(|p| client::encode_payment_header(&requirements, p)) {
            Ok(header) => {
                let mut fields = Map::new();
                fields.insert("x402PaymentHeader".into(), Value::String(header));
                Outcome::Accept(fields)
            }
            Err(e) => client_reject(&e),
        },
    )
}
