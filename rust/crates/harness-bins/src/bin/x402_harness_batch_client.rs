//! Interop client for x402 `batch-settlement`.
//!
//! Opens `X402_HARNESS_BATCH_CHANNELS` channels against the server (each paid
//! by its `deposit`, which carries the first voucher), pays a second request on
//! the first channel with a plain voucher, then asks the server to redeem
//! every channel (`POST /redeem`) and reports the deposit and redemption
//! signatures for the runner to check on chain.

use std::{collections::HashMap, env};

use serde_json::json;
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::x402::{
    client::batch_settlement::{
        build_deposit, encode_payment_header, parse_challenge, resolve_terms, BatchChannel,
    },
    protocol::schemes::batch_settlement::{
        BatchPayload, BatchRequirements, BatchSettlementResponse, BatchVoucher,
    },
    PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER,
};
use solana_rpc_client::rpc_client::RpcClient;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const DEFAULT_CHANNELS: u8 = 1;
/// Requests each deposit escrows, so a channel never needs a top-up here.
const DEPOSIT_REQUESTS: u64 = 10;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let target_url = read_required_env("X402_HARNESS_TARGET_URL")?;
    let rpc_url = read_required_env("X402_HARNESS_RPC_URL")?;
    let signer = read_memory_signer("X402_HARNESS_CLIENT_SECRET_KEY")?;
    let channels: u8 = env::var("X402_HARNESS_BATCH_CHANNELS")
        .ok()
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(DEFAULT_CHANNELS);

    let http = reqwest::Client::new();
    let rpc = RpcClient::new(rpc_url);

    let challenge = http.get(&target_url).send().await?;
    let headers = response_headers(challenge.headers())?;
    let body = challenge.text().await?;
    let (requirements, _) = parse_challenge(&headers, Some(&body))
        .ok_or("server did not return a supported batch-settlement challenge")?;
    let terms = resolve_terms(&rpc, &requirements, None)?;

    let mut deposits = Vec::new();
    let mut first: Option<(BatchChannel, BatchVoucher)> = None;
    let mut last_status = 0u16;
    for _ in 0..channels {
        let blockhash = rpc.get_latest_blockhash()?;
        let open_slot = rpc.get_slot()?;
        let (channel, payload) = build_deposit(
            &signer,
            &requirements,
            &terms,
            terms.amount * DEPOSIT_REQUESTS,
            blockhash,
            open_slot,
        )
        .await?;
        let voucher = submitted_voucher(&payload)?;
        let (status, response) = pay(&http, &target_url, &requirements, payload).await?;
        last_status = status;
        let response = response.ok_or_else(|| format!("deposit answered {status}"))?;
        deposits.push(response.transaction.clone());
        if first.is_none() {
            let mut channel = channel;
            channel.apply_payment_response(&response, &requirements, &voucher)?;
            first = Some((channel, voucher));
        }
    }

    // A second, offchain voucher on the first channel.
    if let Some((channel, _)) = &first {
        let payload = channel.voucher_payload(&signer, terms.amount).await?;
        let (status, response) = pay(&http, &target_url, &requirements, payload).await?;
        last_status = status;
        response.ok_or_else(|| format!("voucher answered {status}"))?;
    }

    let redeem_url = redeem_url(&target_url)?;
    let redeemed = http.post(&redeem_url).send().await?;
    let redeem_status = redeemed.status();
    let redemption: serde_json::Value = redeemed.json().await?;
    let ok = last_status == 200 && redeem_status.is_success();

    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "result",
            "implementation": "rust",
            "role": "client",
            "ok": ok,
            "status": if ok { 200 } else { redeem_status.as_u16() },
            "responseHeaders": HashMap::<String, String>::new(),
            "responseBody": {
                "ok": ok,
                "paid": ok,
                "deposits": deposits,
                "redemption": redemption,
            },
            "settlement": deposits.first(),
        }))?
    );
    Ok(())
}

/// Send one paid request; returns the status and the decoded `PAYMENT-RESPONSE`.
async fn pay(
    http: &reqwest::Client,
    url: &str,
    requirements: &BatchRequirements,
    payload: BatchPayload,
) -> Result<(u16, Option<BatchSettlementResponse>), BoxError> {
    let header = encode_payment_header(requirements, payload)?;
    let response = http
        .get(url)
        .header(PAYMENT_SIGNATURE_HEADER, header)
        .send()
        .await?;
    let status = response.status().as_u16();
    let settlement = response
        .headers()
        .get(PAYMENT_RESPONSE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(decode_settlement)
        .transpose()?;
    Ok((status, settlement.filter(|s| s.success)))
}

fn decode_settlement(value: &str) -> Result<BatchSettlementResponse, BoxError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn submitted_voucher(payload: &BatchPayload) -> Result<BatchVoucher, BoxError> {
    match payload {
        BatchPayload::Deposit {
            voucher: Some(voucher),
            ..
        } => Ok(voucher.clone()),
        _ => Err("a client-signed deposit carries its first voucher".into()),
    }
}

/// `POST /redeem` on the server behind `target_url` (the proxy forwards it).
fn redeem_url(target_url: &str) -> Result<String, BoxError> {
    let after_scheme = target_url
        .find("://")
        .map(|i| i + 3)
        .ok_or("target URL has no scheme")?;
    let path_start = target_url[after_scheme..]
        .find('/')
        .map(|i| after_scheme + i)
        .unwrap_or(target_url.len());
    Ok(format!("{}/redeem", &target_url[..path_start]))
}

fn response_headers(
    headers: &reqwest::header::HeaderMap,
) -> Result<Vec<(String, String)>, BoxError> {
    headers
        .iter()
        .map(|(name, value)| Ok((name.as_str().to_string(), value.to_str()?.to_string())))
        .collect()
}

fn read_required_env(name: &str) -> Result<String, BoxError> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn read_memory_signer(name: &str) -> Result<MemorySigner, BoxError> {
    let raw = read_required_env(name)?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)?;
    Ok(MemorySigner::from_bytes(&bytes)?)
}
