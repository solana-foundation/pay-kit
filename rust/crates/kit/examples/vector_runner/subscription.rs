//! `subscription` vectors: the testee passes the vector's input to the kit
//! unchanged (harness/AGENTS.md "Never put logic in the testee").
//!
//! - canonical bytes: the bearer-proof message (`SubscriptionAuthentication::
//!   message_bytes`), the period mapping (`SubscriptionRequest::period_hours`),
//!   the delegation / authority PDAs, the subscribe / transfer_subscription
//!   data encoders, and the wire types re-encoded as JCS;
//! - build: `build_subscription_activation_credential` against the fixture
//!   RPC;
//! - verify: the route's `SubscriptionServer` at the pinned clock through the
//!   `testkit` hooks (activation checks up to the broadcast; the on-chain
//!   usability check), or `SubscriptionAuthentication::verify`.
//!
//! Reject categories: the client refusing a challenge is `invalid-challenge`;
//! otherwise the kit's message is classified (mirrors
//! `rust/crates/conformance/src/realize/subscription.rs`).

use std::sync::Arc;

use serde_json::{json, Map, Value};
use solana_pay_kit::mpp::client::build_subscription_activation_credential;
use solana_pay_kit::mpp::program::subscriptions::{
    find_subscription_authority_pda, find_subscription_pda, parse_pubkey, SubscribeData,
    TransferData, INSTRUCTION_TRANSFER_SUBSCRIPTION,
};
use solana_pay_kit::mpp::protocol::core::{
    base64url_decode, base64url_encode, parse_authorization, Base64UrlJson, PaymentChallenge,
};
use solana_pay_kit::mpp::protocol::intents::{
    ActivatePayload, SubscriptionAccessPayload, SubscriptionAuthentication,
    SubscriptionAuthenticationType, SubscriptionPeriodUnit, SubscriptionRequest,
};
use solana_pay_kit::mpp::server::subscription::testkit::{
    verify_activation_pre_broadcast, verify_active_subscription_at, PreBroadcast,
};
use solana_pay_kit::mpp::server::subscription::{SubscriptionConfig, SubscriptionServer};
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_rpc_client::rpc_client::RpcClient;

use super::{Outcome, Rejection};

pub async fn run(mode: &str, input: &Value) -> Result<Outcome, Rejection> {
    match mode {
        "canonical-bytes" => canonical(input),
        "build-transaction" => build(input).await,
        "verify-transaction" => {
            if input.get("subscriptionAuthorization").is_some() {
                verify_activation(input).await
            } else if input.get("subscriptionActive").is_some() {
                verify_active(input).await
            } else if input.get("subscriptionProof").is_some() {
                verify_proof(input)
            } else {
                Ok(Outcome::Unsupported(
                    "subscription verify input carries no credential".into(),
                ))
            }
        }
        other => Ok(Outcome::Unsupported(format!(
            "no Rust runner path for intent \"subscription\" mode {other:?}"
        ))),
    }
}

fn reject_as(code: &'static str, message: impl Into<String>) -> Rejection {
    Rejection {
        message: message.into(),
        code: Some(code),
    }
}

fn reject(message: impl Into<String>) -> Rejection {
    let message = message.into();
    Rejection {
        code: classify(&message),
        message,
    }
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn pubkey(value: &str, field: &str) -> Result<solana_pubkey::Pubkey, Rejection> {
    parse_pubkey(value, field).map_err(|e| Rejection::from(e.to_string()))
}

fn exact(fields: Vec<(&str, Value)>) -> Outcome {
    let mut exact = Map::new();
    for (k, v) in fields {
        exact.insert(k.to_string(), v);
    }
    let mut out = Map::new();
    out.insert("exactBytes".into(), Value::Object(exact));
    Outcome::Accept(out)
}

fn jcs(value: &Value) -> Result<Outcome, Rejection> {
    let encoded = Base64UrlJson::from_value(value).map_err(|e| e.to_string())?;
    let bytes = base64url_decode(encoded.raw()).map_err(|e| e.to_string())?;
    let text = String::from_utf8(bytes).map_err(|e| e.to_string())?;
    Ok(exact(vec![
        ("canonicalJson", json!(text)),
        ("base64Url", json!(encoded.raw())),
    ]))
}

fn canonical(input: &Value) -> Result<Outcome, Rejection> {
    if let Some(m) = input.get("subscriptionAuthenticationMessage") {
        let authentication = SubscriptionAuthentication {
            kind: SubscriptionAuthenticationType::Proof,
            challenge_id: str_of(m, "challengeId").to_string(),
            payer: str_of(m, "payer").to_string(),
            signature: String::new(),
        };
        let bytes = authentication
            .message_bytes(str_of(m, "subscriptionDelegation"))
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8(bytes.clone()).map_err(|e| e.to_string())?;
        return Ok(exact(vec![
            ("canonicalJson", json!(text)),
            ("base64Url", json!(base64url_encode(&bytes))),
        ]));
    }
    if let Some(p) = input.get("subscriptionPeriod") {
        let unit: SubscriptionPeriodUnit =
            serde_json::from_value(p.get("periodUnit").cloned().unwrap_or(Value::Null))
                .map_err(|e| reject_as("invalid-challenge", format!("invalid periodUnit: {e}")))?;
        let request = SubscriptionRequest {
            period_unit: unit,
            period_count: str_of(p, "periodCount").to_string(),
            ..Default::default()
        };
        let hours = request
            .period_hours()
            .map_err(|e| reject_as("invalid-challenge", e.to_string()))?;
        return jcs(&json!({ "periodHours": hours }));
    }
    if let Some(p) = input.get("subscriptionPda") {
        let program = pubkey(str_of(p, "subscriptionProgram"), "subscriptionProgram")?;
        let address = match str_of(p, "kind") {
            "delegation" => {
                find_subscription_pda(
                    &pubkey(str_of(p, "planAddress"), "planAddress")?,
                    &pubkey(str_of(p, "subscriber"), "subscriber")?,
                    &program,
                )
                .0
            }
            "authority" => {
                find_subscription_authority_pda(
                    &pubkey(str_of(p, "subscriber"), "subscriber")?,
                    &pubkey(str_of(p, "mint"), "mint")?,
                    &program,
                )
                .0
            }
            other => return Err(format!("unknown subscriptionPda kind {other:?}").into()),
        };
        return jcs(&json!({ "address": address.to_string() }));
    }
    if let Some(ix) = input.get("subscriptionInstruction") {
        let num = |k: &str| -> Result<i128, Rejection> {
            match ix.get(k) {
                Some(Value::String(s)) => s.parse().map_err(|_| format!("invalid {k}").into()),
                Some(Value::Number(n)) => n
                    .as_i64()
                    .map(i128::from)
                    .or_else(|| n.as_u64().map(i128::from))
                    .ok_or_else(|| format!("invalid {k}").into()),
                _ => Err(format!("missing {k}").into()),
            }
        };
        let bytes = match str_of(ix, "kind") {
            "subscribe" => SubscribeData {
                plan_id: num("planId")? as u64,
                plan_bump: num("planBump")? as u8,
                expected_mint: pubkey(str_of(ix, "mint"), "mint")?,
                expected_amount: num("amount")? as u64,
                expected_period_hours: num("periodHours")? as u64,
                expected_created_at: num("createdAt")? as i64,
                expected_subscription_authority_init_id: num("authorityInitId")? as i64,
            }
            .to_bytes(),
            "transfer" => TransferData {
                amount: num("amount")? as u64,
                delegator: pubkey(str_of(ix, "delegator"), "delegator")?,
                mint: pubkey(str_of(ix, "mint"), "mint")?,
            }
            .to_bytes(INSTRUCTION_TRANSFER_SUBSCRIPTION),
            other => return Err(format!("unknown subscriptionInstruction kind {other:?}").into()),
        };
        return Ok(exact(vec![
            ("bytes", json!(bytes)),
            ("base64Url", json!(base64url_encode(&bytes))),
        ]));
    }
    if let Some(w) = input.get("subscriptionWire") {
        let value = w.get("value").cloned().unwrap_or(Value::Null);
        let (reencoded, code) = match str_of(w, "shape") {
            "request" => (
                serde_json::from_value::<SubscriptionRequest>(value).and_then(serde_json::to_value),
                "invalid-challenge",
            ),
            "activation" => (
                serde_json::from_value::<ActivatePayload>(value).and_then(serde_json::to_value),
                "invalid-payload",
            ),
            "access" => (
                serde_json::from_value::<SubscriptionAccessPayload>(value)
                    .and_then(serde_json::to_value),
                "invalid-payload",
            ),
            other => return Err(format!("unknown subscriptionWire shape {other:?}").into()),
        };
        return match reencoded {
            Ok(reencoded) => jcs(&reencoded),
            Err(e) => Err(reject_as(
                code,
                format!("invalid subscription wire value: {e}"),
            )),
        };
    }
    Ok(Outcome::Unsupported(
        "no subscription canonical-bytes input".into(),
    ))
}

fn signer_from(input: &Value, key: &str) -> Result<MemorySigner, Rejection> {
    let bytes: Vec<u8> = input
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("vector is missing input.{key}"))?
        .iter()
        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<_>>()
        .ok_or_else(|| format!("{key} must be bytes"))?;
    MemorySigner::from_bytes(&bytes).map_err(|e| Rejection::from(format!("invalid {key}: {e}")))
}

fn rpc_url(input: &Value) -> Result<String, Rejection> {
    input
        .get("rpcUrl")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "driver did not inject input.rpcUrl".into())
}

/// The kit's client on the challenge the vector carries.
async fn build(input: &Value) -> Result<Outcome, Rejection> {
    let signer = signer_from(input, "signerSecretKey")?;
    let c = input
        .get("subscriptionChallenge")
        .ok_or("vector is missing input.subscriptionChallenge")?;
    let request = Base64UrlJson::from_value(c.get("request").unwrap_or(&Value::Null))
        .map_err(|e| e.to_string())?;
    let mut challenge = PaymentChallenge::new(
        str_of(c, "id"),
        str_of(c, "realm"),
        str_of(c, "method"),
        str_of(c, "intent"),
        request,
    );
    challenge.expires = c.get("expires").and_then(Value::as_str).map(str::to_string);
    let rpc = RpcClient::new(rpc_url(input)?);
    let activation = build_subscription_activation_credential(&signer, &rpc, &challenge)
        .await
        // Every refusal of the client builder is a refusal of the challenge.
        .map_err(|e| reject_as("invalid-challenge", e.to_string()))?;
    let transaction = activation
        .credential
        .payload
        .get("transaction")
        .and_then(Value::as_str)
        .ok_or("activation credential carries no transaction")?;
    let mut out = Map::new();
    out.insert("transaction".into(), json!(transaction));
    Ok(Outcome::Accept(out))
}

fn server_from(input: &Value) -> Result<SubscriptionServer, Rejection> {
    let s = input
        .get("subscriptionServer")
        .ok_or("vector is missing input.subscriptionServer")?;
    let period_unit: SubscriptionPeriodUnit =
        serde_json::from_value(s.get("periodUnit").cloned().unwrap_or(Value::Null))
            .map_err(|e| format!("server periodUnit: {e}"))?;
    let fee_payer_signer: Option<Arc<dyn solana_pay_kit::solana_keychain::TransactionSigner>> =
        match input.get("subscriptionServerFeePayerSecretKey") {
            Some(_) => Some(Arc::new(signer_from(
                input,
                "subscriptionServerFeePayerSecretKey",
            )?)),
            None => None,
        };
    let fee_payer_pubkey = s
        .get("feePayerKey")
        .and_then(Value::as_str)
        .map(str::to_string);
    SubscriptionServer::new(SubscriptionConfig {
        plan_id: str_of(s, "planAddress").to_string(),
        mint: str_of(s, "mint").to_string(),
        decimals: s
            .get("decimals")
            .and_then(Value::as_u64)
            .unwrap_or_default() as u8,
        token_program: str_of(s, "tokenProgram").to_string(),
        puller: str_of(s, "puller").to_string(),
        recipient: str_of(s, "recipient").to_string(),
        period_unit,
        period_count: s
            .get("periodCount")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        amount_base_units: str_of(s, "amount").to_string(),
        network: str_of(s, "network").to_string(),
        program_id: s
            .get("subscriptionProgram")
            .and_then(Value::as_str)
            .map(str::to_string),
        rpc_url: Some(rpc_url(input)?),
        challenge_binding_secret: str_of(s, "secretKey").to_string(),
        realm: str_of(s, "realm").to_string(),
        fee_payer: fee_payer_pubkey.is_some(),
        fee_payer_signer,
        fee_payer_pubkey,
        ..Default::default()
    })
    .map_err(|e| Rejection::from(format!("server config: {e}")))
}

fn now_of(input: &Value) -> Result<i64, Rejection> {
    input
        .get("nowSeconds")
        .and_then(Value::as_i64)
        .ok_or_else(|| "vector is missing input.nowSeconds".into())
}

async fn verify_activation(input: &Value) -> Result<Outcome, Rejection> {
    let server = server_from(input)?;
    let credential = parse_authorization(str_of(input, "subscriptionAuthorization"))
        .map_err(|e| reject_as("invalid-payload", e.to_string()))?;
    match verify_activation_pre_broadcast(&server, &credential, now_of(input)?).await {
        Ok(PreBroadcast::Activation) => Ok(Outcome::Accept(Map::new())),
        Ok(PreBroadcast::AccessProof) => Ok(Outcome::Unsupported(
            "a type=\"proof\" credential needs the binding a confirmed activation writes".into(),
        )),
        Err(error) => Err(reject(error.message)),
    }
}

async fn verify_active(input: &Value) -> Result<Outcome, Rejection> {
    let server = server_from(input)?;
    let active = &input["subscriptionActive"];
    let subscriber = pubkey(str_of(active, "subscriber"), "subscriber")?;
    match verify_active_subscription_at(
        &server,
        &subscriber,
        str_of(active, "amount"),
        now_of(input)?,
    )
    .await
    {
        Ok(_) => Ok(Outcome::Accept(Map::new())),
        Err(error) => {
            let mut rejection = reject(error.message);
            rejection.code = rejection.code.or(Some("subscription-inactive"));
            Err(rejection)
        }
    }
}

fn verify_proof(input: &Value) -> Result<Outcome, Rejection> {
    let p = &input["subscriptionProof"];
    let authentication: SubscriptionAuthentication =
        serde_json::from_value(p["authentication"].clone()).map_err(|e| {
            reject_as(
                "authentication-invalid",
                format!("invalid authentication: {e}"),
            )
        })?;
    match authentication.verify(str_of(p, "subscriptionDelegation")) {
        Ok(true) => Ok(Outcome::Accept(Map::new())),
        Ok(false) => Err(reject_as(
            "authentication-invalid",
            "the proof signature does not verify over the canonical message",
        )),
        Err(e) => Err(reject_as("authentication-invalid", e.to_string())),
    }
}

/// The shared reject category of a kit subscription error message.
fn classify(message: &str) -> Option<&'static str> {
    let m = message.to_ascii_lowercase();
    let has = |needle: &str| m.contains(needle);
    let any = |needles: &[&str]| needles.iter().any(|n| m.contains(n));
    Some(
        if has("network does not match") || has("network mismatch") {
            "wrong-network"
        } else if any(&[
            "hmac mismatch",
            "did not issue",
            "was not issued by this server",
            "does not match this server",
            "is not a subscription",
            "terms do not match",
            "does not match this route",
        ]) {
            "challenge-mismatch"
        } else if any(&["challenge has expired", "challenge expired"]) {
            "challenge-expired"
        } else if any(&["subscription has expired", "subscription expired"]) {
            "subscription-expired"
        } else if any(&[
            "authentication proof",
            "proof challengeid does not match",
            "proof payer does not match",
            "missing authentication",
            "authentication.type",
            "authentication is required",
        ]) {
            "authentication-invalid"
        } else if any(&[
            "receiver does not match",
            "transfer_subscription accounts do not match",
        ]) {
            "recipient-mismatch"
        } else if has("source") && (has("does not match") || has("did:pkh")) {
            "source-mismatch"
        } else if any(&[
            "fee payer must be",
            "fee payer pubkey not present",
            "fee-payer signer does not match",
        ]) {
            "fee-payer-mismatch"
        } else if has("compute unit limit exceeds") {
            "compute-limit-over-cap"
        } else if has("compute unit price exceeds") {
            "compute-price-over-cap"
        } else if any(&[
            "unsupported program",
            "multiple subscribe",
            "multiple transfer_subscription",
            "multiple initialize_subscription_authority",
            "initialize_subscription_authority is not allowed",
            "idempotent",
            "ata creation",
            "unsupported subscriptions instruction",
            "unsupported compute-budget",
            "multiple memo",
            "multiple compute-unit",
        ]) {
            "unexpected-instruction"
        } else if any(&[
            "missing subscribe",
            "missing transfer_subscription",
            "subscribe must precede",
            "subscribe accounts do not match",
            "transfer_subscription data does not match",
            "transfer_subscription amount does not match",
            "transfer_subscription delegator does not match",
            "transfer_subscription mint does not match",
            "memo does not match",
            "missing challenge externalid memo",
            "signers must be exactly",
        ]) {
            "activation-scope"
        } else if any(&[
            "not paid for the current billing period",
            "cancellation has taken effect",
            "authority has been invalidated",
            "subscriptionauthority account",
            "subscriptiondelegation account",
            "does not match the bound plan and payer",
            "owner mismatch",
            "subscriptiondelegation discriminator",
            "subscriptiondelegation length",
        ]) {
            "subscription-inactive"
        } else if any(&[
            "invalid subscription challenge",
            "requires feepayerkey",
            "feepayerkey is required",
            "untrusted subscription program",
            "currency must match",
            "must match amount",
            "must match recipient",
            "does not match the challenge",
            "plan owner does not match",
            "plan account not found",
            "invalid recentblockhash",
            "pubkey",
            "periodcount",
            "period_hours",
            "periodunit",
            "methoddetails",
            "invalid amount",
        ]) {
            "invalid-challenge"
        } else if any(&[
            "push-mode",
            "unsupported payload type",
            "payload type",
            "missing `transaction`",
            "missing transaction",
            "failed to decode",
            "tx decode",
            "invalid transaction",
            "could not identify subscriber",
            "subscriber cannot",
            "does not verify",
            "cannot be used with fee sponsorship",
        ]) {
            "invalid-payload"
        } else {
            return None;
        },
    )
}
