//! `x402-upto` vectors: the testee passes the vector's input to the kit
//! unchanged (harness/AGENTS.md "Never put logic in the testee").
//!
//! - build: `client::upto::build_upto_header` on `input.x402Offer`, with the
//!   caller parameters its API takes (`x402UptoExpiresAt`,
//!   `x402UptoRequestNonce`, `x402ClientMaxTransactionVersion`) and the
//!   driver's fixture RPC.
//! - verify: `X402Upto` configured from the `x402Server*` route, run through
//!   `server::upto::testkit::verify_open_pre_broadcast` (every check
//!   `verify_open_for_route` makes before broadcasting) at `nowSeconds`.
//! - canonical bytes: the payment-channels voucher message, distribution
//!   hash and channel PDA.

use std::str::FromStr;
use std::sync::Arc;

use serde_json::{json, Map, Value};
use solana_pay_kit::core::payment_channels as pc;
use solana_pay_kit::core::tx::{TxV1Mode, TxVersion};
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_pay_kit::x402::client::upto::build_upto_header;
use solana_pay_kit::x402::server::upto::testkit::verify_open_pre_broadcast;
use solana_pay_kit::x402::server::upto::{UptoConfig, UptoPayout, X402Upto};
use solana_pay_kit::x402::server::CurrencyConfig;
use solana_pay_kit::x402::upto::UptoRequirements;
use solana_pubkey::Pubkey;

use super::{fixture_rpc, Outcome, Rejection};

pub async fn run(mode: &str, input: &Value) -> Result<Outcome, Rejection> {
    match mode {
        "build-transaction" => build(input).await,
        "verify-transaction" => verify(input).await,
        "canonical-bytes" => canonical(input),
        other => Ok(Outcome::Unsupported(format!(
            "no Rust runner path for intent \"x402-upto\" mode {other:?}"
        ))),
    }
}

/// The shared code for a kit upto error (mirrors `code_for` in
/// rust/crates/conformance/src/realize/upto.rs).
fn code_for(message: &str) -> Option<&'static str> {
    let m = message.to_ascii_lowercase();
    let has = |n: &str| m.contains(n);
    Some(
        if has("is not accepted; accepted versions") || has("signer signs up to version") {
            "unsupported-version"
        } else if has("compute unit price") && (has("exceed") || has("maximum")) {
            "compute-price-over-cap"
        } else if has("compute unit limit") && (has("exceed") || has("maximum")) {
            "compute-limit-over-cap"
        } else if has("must not reference the fee payer") {
            "fee-payer-not-authority"
        } else if has("fee payer must be the advertised fee payer")
            || has("loaded accounts data size")
            || has("must set computeunitlimit")
        {
            "invalid-payload"
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
            "unexpected-instruction"
        } else if has("memo") {
            "invalid-payload"
        } else if has("open transaction channel mismatch") || has("open channel pda") {
            "channel-id-mismatch"
        } else if has("open transaction")
            || has("open salt")
            || has("open slot")
            || has("open withdraw delay")
            || has("open deposit")
            || has("open distribution")
            || has("open instruction")
        {
            "open-binding-mismatch"
        } else if has("amount mismatch") {
            "amount-mismatch"
        } else if has("channel deposit") && has("authorized maximum") {
            "deposit-not-ceiling"
        } else if has("not yet active") {
            "not-yet-active"
        } else if has("authorization expired") {
            "voucher-expired"
        } else if has("advertised receiver authorizer") {
            "receiver-authorizer-mismatch"
        } else if has("network mismatch")
            || has("does not match any offered")
            || has("invalid payload type")
        {
            "accepted-mismatch"
        } else if has("address lookup tables")
            || has("byte limit")
            || has("exceeds")
            || has("invalid")
            || has("requires opentransaction")
            || has("decode")
        {
            "invalid-payload"
        } else if has("withdrawdelay") || has("missing field") {
            "invalid-challenge"
        } else {
            return None;
        },
    )
}

fn rejection(message: String) -> Rejection {
    Rejection {
        code: code_for(&message),
        message,
    }
}

fn str_of<'a>(input: &'a Value, key: &str) -> Result<&'a str, Rejection> {
    input
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("vector is missing input.{key}").into())
}

fn signer(input: &Value, key: &str) -> Result<MemorySigner, Rejection> {
    let bytes: Vec<u8> = input
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("vector is missing input.{key}"))?
        .iter()
        .map(|b| {
            b.as_u64()
                .map(|b| b as u8)
                .ok_or("secret key must be bytes")
        })
        .collect::<Result<_, _>>()?;
    MemorySigner::from_bytes(&bytes).map_err(|e| format!("invalid {key}: {e}").into())
}

async fn build(input: &Value) -> Result<Outcome, Rejection> {
    let offer = input
        .get("x402Offer")
        .ok_or("vector is missing input.x402Offer")?;
    let requirements: UptoRequirements =
        serde_json::from_value(offer.clone()).map_err(|e| Rejection {
            message: format!("invalid challenge: x402Offer: {e}"),
            code: Some("invalid-challenge"),
        })?;
    let signer = signer(input, "signerSecretKey")?;
    let rpc = fixture_rpc(input)?;
    let expires_at = input
        .get("x402UptoExpiresAt")
        .and_then(Value::as_i64)
        .ok_or("vector is missing input.x402UptoExpiresAt")?;
    let nonce = input
        .get("x402UptoRequestNonce")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let max_version = match input.get("x402ClientMaxTransactionVersion") {
        None => None,
        Some(v) => Some(
            TxVersion::try_from(v.as_u64().unwrap_or(u64::MAX).min(255) as u8)
                .map_err(Rejection::from)?,
        ),
    };
    match build_upto_header(&signer, &rpc, &requirements, expires_at, nonce, max_version).await {
        Ok(header) => {
            let mut fields = Map::new();
            fields.insert("x402PaymentHeader".into(), json!(header));
            Ok(Outcome::Accept(fields))
        }
        Err(e) => {
            let message = e.to_string();
            let code = if message.contains("memo is") {
                Some("invalid-challenge")
            } else {
                // The client refuses a challenge it cannot honour.
                code_for(&message).map(|c| {
                    if c == "invalid-payload" {
                        "invalid-challenge"
                    } else {
                        c
                    }
                })
            };
            Err(Rejection { message, code })
        }
    }
}

async fn verify(input: &Value) -> Result<Outcome, Rejection> {
    let header = str_of(input, "x402PaymentHeader")?;
    let rpc_url = str_of(input, "rpcUrl")?;
    let currency = str_of(input, "x402ServerCurrency")?;
    let decimals = input
        .pointer(&format!("/rpcFixtures/mints/{currency}/decimals"))
        .and_then(Value::as_u64)
        .unwrap_or(6) as u8;
    let number = |k: &str| {
        input
            .get(k)
            .and_then(Value::as_u64)
            .ok_or_else(|| Rejection::from(format!("vector is missing input.{k}")))
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
        fee_payer_signer: Arc::new(signer(input, "x402ServerFeePayerSecretKey")?),
        receiver_authorizer_signer: Some(Arc::new(signer(
            input,
            "x402ServerReceiverAuthorizerSecretKey",
        )?)),
    };
    let mut server = X402Upto::new(config).map_err(|e| format!("server config: {e}"))?;
    let v1 = input
        .get("x402ServerTransactionVersions")
        .and_then(Value::as_array)
        .is_some_and(|v| v.iter().any(|x| x.as_u64() == Some(1)));
    if v1 {
        server = server.with_tx_v1(TxV1Mode::On);
    }
    let now = input
        .get("nowSeconds")
        .and_then(Value::as_i64)
        .ok_or("vector is missing input.nowSeconds")?;
    verify_open_pre_broadcast(
        &server,
        header,
        str_of(input, "x402ServerAmount")?,
        input.get("x402ServerRoute").and_then(Value::as_str),
        now,
    )
    .await
    .map_err(|e| rejection(e.to_string()))?;
    Ok(Outcome::Accept(Map::new()))
}

fn canonical(input: &Value) -> Result<Outcome, Rejection> {
    let mut exact = Map::new();
    let set_bytes = |exact: &mut Map<String, Value>, bytes: &[u8]| {
        exact.insert("bytes".into(), json!(bytes));
        exact.insert(
            "base64Url".into(),
            json!(solana_pay_kit::mpp::protocol::core::base64url_encode(bytes)),
        );
    };
    let key = |v: &Value, name: &str| -> Result<Pubkey, Rejection> {
        Pubkey::from_str(v.get(name).and_then(Value::as_str).unwrap_or(""))
            .map_err(|e| rejection(format!("invalid payload: {name}: {e}")))
    };
    if let Some(v) = input.get("x402UptoVoucher") {
        let channel = key(v, "channelId")?;
        let cumulative: u64 = match v.get("cumulativeAmount") {
            Some(Value::String(s)) => s.parse().map_err(|_| "invalid cumulativeAmount")?,
            Some(n) => n.as_u64().ok_or("invalid cumulativeAmount")?,
            None => return Err("cumulativeAmount missing".into()),
        };
        let expires_at = v.get("expiresAt").and_then(Value::as_i64).unwrap_or(0);
        let bytes = pc::voucher_message_bytes(&channel, cumulative, expires_at)
            .map_err(|e| rejection(format!("invalid payload: {e}")))?;
        set_bytes(&mut exact, &bytes);
    }
    if let Some(d) = input.get("x402UptoDistribution") {
        let recipients = d
            .get("recipients")
            .and_then(Value::as_array)
            .ok_or("recipients missing")?
            .iter()
            .map(|r| {
                Ok(pc::Distribution {
                    recipient: key(r, "recipient")?,
                    bps: r.get("bps").and_then(Value::as_u64).ok_or("bps missing")? as u16,
                })
            })
            .collect::<Result<Vec<_>, Rejection>>()?;
        set_bytes(&mut exact, &pc::distribution_hash(&recipients));
    }
    if let Some(p) = input.get("x402UptoChannelPda") {
        let n = |name: &str| -> Result<u64, Rejection> {
            p.get(name)
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| rejection(format!("invalid payload: {name} must be a decimal u64")))
        };
        let (pda, _) = pc::find_channel_pda(
            &key(p, "payer")?,
            &key(p, "payee")?,
            &key(p, "mint")?,
            &key(p, "authorizedSigner")?,
            n("salt")?,
            n("openSlot")?,
            &pc::default_program_id(),
        );
        set_bytes(&mut exact, pda.as_ref());
    }
    let mut fields = Map::new();
    fields.insert("exactBytes".into(), Value::Object(exact));
    Ok(Outcome::Accept(fields))
}
