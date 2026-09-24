//! x402 `batch-settlement` harness client.
//!
//! Opens one channel with a deposit, pays each later request with a cumulative
//! voucher, tops up when the deposit cannot cover the next voucher, and then
//! optionally asks the server to redeem or sends a refund. Emits one `result`
//! line describing every request.

use std::{collections::HashMap, env};

use base64::Engine;
use serde_json::{json, Value};
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::x402::{
    batch_settlement::{errors as codes, BatchSettlementResponse},
    client::batch_settlement::{
        build_deposit, build_refund, build_top_up, encode_payment_header, parse_challenge,
        resolve_terms, BatchChannel,
    },
    PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER,
};
use solana_rpc_client::rpc_client::RpcClient;

const DEFAULT_REQUESTS: u64 = 3;
const DEFAULT_SETTLEMENT_HEADER: &str = "x-payment-settlement-signature";
const REDEEM_PATH: &str = "/__harness/batch/redeem";

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy, PartialEq)]
enum Flow {
    Basic,
    TopUp,
    Redeem,
    Refund,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The decoded `PAYMENT-RESPONSE`, as raw JSON and typed.
    fn payment_response(&self) -> Option<(Value, BatchSettlementResponse)> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(self.header(PAYMENT_RESPONSE_HEADER)?)
            .ok()?;
        let raw: Value = serde_json::from_slice(&bytes).ok()?;
        let typed = serde_json::from_value(raw.clone()).ok()?;
        Some((raw, typed))
    }
}

fn json_or_text(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|_| Value::String(body.to_string()))
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let target_url = read_required_env("X402_HARNESS_TARGET_URL")?;
    let rpc_url = read_required_env("X402_HARNESS_RPC_URL")?;
    let signer = read_memory_signer("X402_HARNESS_CLIENT_SECRET_KEY")?;
    let flow = read_flow()?;
    let requests = read_u64_env("X402_HARNESS_BATCH_REQUESTS")?.unwrap_or(DEFAULT_REQUESTS);
    let settlement_header = env::var("X402_HARNESS_SETTLEMENT_HEADER")
        .unwrap_or_else(|_| DEFAULT_SETTLEMENT_HEADER.to_string());

    let http = reqwest::Client::new();
    let rpc = RpcClient::new(rpc_url);

    let challenge = send(&http, &target_url, None).await?;
    // Pays the first `batch-settlement` accept the server offers.
    let (requirements, _) = parse_challenge(&challenge.headers, Some(&challenge.body))
        .ok_or("server did not return an x402 batch-settlement challenge")?;
    let terms = resolve_terms(&rpc, &requirements, None)?;
    let price = terms.amount;
    // A top-up run starts with one request's worth so the next voucher
    // cannot fit and must carry a top-up.
    let default_deposit = if flow == Flow::TopUp {
        price
    } else {
        price.checked_mul(requests).ok_or("deposit overflows u64")?
    };
    let deposit = read_u64_env("X402_HARNESS_BATCH_DEPOSIT")?.unwrap_or(default_deposit);

    let mut channel: Option<BatchChannel> = None;
    let mut records = Vec::new();
    let mut last: Option<(Reply, String)> = None;
    let mut open_signature: Option<String> = None;
    let mut ok = true;

    for index in 1..=requests {
        let mut corrected = false;
        let (reply, record, payment_header) = loop {
            let (kind, payload, pending) = match &channel {
                None => {
                    let blockhash = match requirements
                        .extra
                        .recent_blockhash
                        .as_deref()
                        .map(str::parse)
                    {
                        Some(Ok(hash)) => hash,
                        _ => rpc.get_latest_blockhash()?,
                    };
                    let open_slot = match requirements.extra.recent_slot {
                        Some(slot) => slot,
                        None => rpc.get_slot()?,
                    };
                    let (opened, payload) = build_deposit(
                        &signer,
                        &requirements,
                        &terms,
                        deposit,
                        blockhash,
                        open_slot,
                    )
                    .await?;
                    ("deposit", payload, Some(opened))
                }
                Some(open) if !open.can_cover(price) => {
                    let remaining = requests - index + 1;
                    let top_up = price.checked_mul(remaining).ok_or("top-up overflows u64")?;
                    let payload =
                        build_top_up(&signer, open, &terms, top_up, rpc.get_latest_blockhash()?)
                            .await?;
                    ("topUp", payload, None)
                }
                Some(open) => ("voucher", open.voucher_payload(&signer, price).await?, None),
            };
            let voucher = payload
                .charge_voucher()
                .cloned()
                .ok_or("paid payload carries no voucher")?;
            let payment_header = encode_payment_header(&requirements, payload)?;
            let reply = send(&http, &target_url, Some(&payment_header)).await?;

            // A cumulative mismatch answers with a corrective 402. Adopt the
            // server's proven watermark and retry this request once.
            if reply.status == 402 && !corrected && pending.is_none() {
                if let (Some(open), Some((corrective, Some(code)))) = (
                    channel.as_mut(),
                    parse_challenge(&reply.headers, Some(&reply.body)),
                ) {
                    if code == codes::INVALID_CUMULATIVE_AMOUNT_MISMATCH {
                        open.adopt_corrective_state(&corrective)?;
                        corrected = true;
                        continue;
                    }
                }
            }

            if let Some(opened) = pending {
                channel = Some(opened);
            }
            let payment_response = reply.payment_response();
            let mut error = None;
            if reply.status == 200 {
                match (&payment_response, channel.as_mut()) {
                    (Some((_, settled)), Some(open)) => {
                        if let Err(e) =
                            open.apply_payment_response(settled, &requirements, &voucher)
                        {
                            error = Some(e.to_string());
                        }
                    }
                    _ => error = Some("200 without a PAYMENT-RESPONSE".to_string()),
                }
            } else {
                error = Some(format!("paid request returned {}", reply.status));
            }
            let transaction = payment_response
                .as_ref()
                .map(|(_, settled)| settled.transaction.clone());
            if kind == "deposit" && error.is_none() {
                open_signature = transaction.clone().filter(|t| !t.is_empty());
            }
            let record = json!({
                "index": index,
                "kind": kind,
                "status": reply.status,
                "chargedCumulativeAmount": channel
                    .as_ref()
                    .map(|open| open.charged_cumulative_amount().to_string()),
                "transaction": transaction,
                "settlementSignature": reply.header(&settlement_header),
                "paymentResponse": payment_response.map(|(raw, _)| raw),
                "corrected": corrected,
                "error": error,
                "body": json_or_text(&reply.body),
            });
            break (reply, record, payment_header);
        };
        let failed = !record["error"].is_null();
        records.push(record);
        last = Some((reply, payment_header));
        if failed {
            ok = false;
            break;
        }
    }

    let mut body = json!({
        "flow": flow_name(flow),
        "channelId": channel.as_ref().map(|open| open.channel_id().to_string()),
        "openSignature": open_signature,
        "deposit": deposit.to_string(),
        "price": price.to_string(),
        "requests": records,
    });

    if ok && flow == Flow::Redeem {
        let mut url = reqwest::Url::parse(&target_url)?;
        url.set_path(REDEEM_PATH);
        url.set_query(None);
        let response = http.post(url).send().await?;
        let status = response.status().as_u16();
        ok = status == 200;
        body["redeem"] = json!({ "status": status, "body": json_or_text(&response.text().await?) });
    }

    if ok && flow == Flow::Refund {
        let open = channel.as_ref().ok_or("refund needs an open channel")?;
        let payload = build_refund(&signer, open, &terms, rpc.get_latest_blockhash()?).await?;
        let payment_header = encode_payment_header(&requirements, payload)?;
        let reply = send(&http, &target_url, Some(&payment_header)).await?;
        let payment_response = reply.payment_response();
        ok = reply.status == 200;
        body["refund"] = json!({
            "status": reply.status,
            "transaction": payment_response
                .as_ref()
                .map(|(_, settled)| settled.transaction.clone()),
            "settlementSignature": reply.header(&settlement_header),
            "paymentResponse": payment_response.map(|(raw, _)| raw),
            "body": json_or_text(&reply.body),
        });
    }

    let (status, headers): (u16, HashMap<String, String>) = match last {
        Some((reply, payment_header)) => {
            let mut headers: HashMap<String, String> = reply.headers.into_iter().collect();
            headers.insert(
                format!("{}-sent", PAYMENT_SIGNATURE_HEADER.to_ascii_lowercase()),
                payment_header,
            );
            (reply.status, headers)
        }
        None => (challenge.status, challenge.headers.into_iter().collect()),
    };

    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "result",
            "implementation": "rust",
            "role": "client",
            "ok": ok && status == 200,
            "status": status,
            "responseHeaders": headers,
            "responseBody": body,
            "settlement": open_signature,
        }))?
    );

    Ok(())
}

async fn send(
    http: &reqwest::Client,
    url: &str,
    payment_header: Option<&str>,
) -> Result<Reply, BoxError> {
    let mut request = http.get(url);
    if let Some(value) = payment_header {
        request = request.header(PAYMENT_SIGNATURE_HEADER, value);
    }
    let response = request.send().await?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| Ok((name.as_str().to_string(), value.to_str()?.to_string())))
        .collect::<Result<Vec<_>, BoxError>>()?;
    Ok(Reply {
        status,
        headers,
        body: response.text().await?,
    })
}

fn read_flow() -> Result<Flow, BoxError> {
    match env::var("X402_HARNESS_BATCH_FLOW").as_deref() {
        Err(_) | Ok("basic") => Ok(Flow::Basic),
        Ok("top-up") => Ok(Flow::TopUp),
        Ok("redeem") => Ok(Flow::Redeem),
        Ok("refund") => Ok(Flow::Refund),
        Ok(other @ ("server-signed" | "untrusted-fallback")) => Err(format!(
            "X402_HARNESS_BATCH_FLOW={other} is Python-only; the Rust batch-settlement client \
             signs its own vouchers"
        )
        .into()),
        Ok(other) => Err(format!(
            "unsupported X402_HARNESS_BATCH_FLOW={other}; expected basic, top-up, redeem or refund"
        )
        .into()),
    }
}

fn flow_name(flow: Flow) -> &'static str {
    match flow {
        Flow::Basic => "basic",
        Flow::TopUp => "top-up",
        Flow::Redeem => "redeem",
        Flow::Refund => "refund",
    }
}

fn read_u64_env(name: &str) -> Result<Option<u64>, BoxError> {
    match env::var(name) {
        Ok(raw) if !raw.trim().is_empty() => {
            Ok(Some(raw.trim().parse().map_err(|_| {
                format!("{name} must be an unsigned integer, got {raw}")
            })?))
        }
        _ => Ok(None),
    }
}

fn read_required_env(name: &str) -> Result<String, BoxError> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn read_memory_signer(name: &str) -> Result<MemorySigner, BoxError> {
    let raw = read_required_env(name)?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)?;
    Ok(MemorySigner::from_bytes(&bytes)?)
}
