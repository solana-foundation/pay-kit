use std::{
    collections::HashMap,
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::json;
use solana_keychain::memory::MemorySigner;
use solana_pay_kit::x402::{
    client::upto::{build_upto_header, parse_upto_challenge},
    PAYMENT_SIGNATURE_HEADER,
};
use solana_rpc_client::rpc_client::RpcClient;

const DEFAULT_NETWORK: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const DEFAULT_SETTLEMENT_HEADER: &str = "x-fixture-settlement";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target_url = read_required_env("X402_HARNESS_TARGET_URL")?;
    let rpc_url = read_required_env("X402_HARNESS_RPC_URL")?;
    let _network = env::var("X402_HARNESS_NETWORK").unwrap_or_else(|_| DEFAULT_NETWORK.to_string());
    let signer = read_memory_signer("X402_HARNESS_CLIENT_SECRET_KEY")?;
    let actual_amount = env::var("X402_HARNESS_ACTUAL_AMOUNT").unwrap_or_else(|_| "0".to_string());
    let settlement_header = env::var("X402_HARNESS_SETTLEMENT_HEADER")
        .unwrap_or_else(|_| DEFAULT_SETTLEMENT_HEADER.to_string());

    let http = reqwest::Client::new();
    let first_response = http.get(&target_url).send().await?;
    let first_headers = response_headers(first_response.headers())?;
    let first_body = first_response.text().await?;

    let requirements = parse_upto_challenge(&first_headers, Some(&first_body))
        .ok_or_else(|| "server did not return a supported x402 upto challenge".to_string())?;

    let _rpc = RpcClient::new(rpc_url);
    let expires_at = now_unix() + 3600;
    let nonce = format!("upto-{}", now_unix());
    // `openSlot` (like `recentBlockhash`) rides in the challenge requirements;
    // the client never fetches its own slot.
    let payment_header = build_upto_header(&signer, &requirements, expires_at, nonce).await?;

    let paid_response = http
        .get(&target_url)
        .header(PAYMENT_SIGNATURE_HEADER, payment_header.clone())
        .header("X402-HARNESS-ACTUAL-AMOUNT", &actual_amount)
        .send()
        .await?;
    let status = paid_response.status();
    let paid_headers = response_headers(paid_response.headers())?;
    let mut paid_headers = headers_to_map(paid_headers);
    paid_headers.insert(format!("{PAYMENT_SIGNATURE_HEADER}-sent"), payment_header);
    let settlement = paid_headers.get(&settlement_header).cloned();
    let raw_body = paid_response.text().await?;
    let response_body = serde_json::from_str::<serde_json::Value>(&raw_body)
        .unwrap_or(serde_json::Value::String(raw_body));

    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "result",
            "implementation": "rust",
            "role": "client",
            "ok": status.is_success(),
            "status": status.as_u16(),
            "responseHeaders": paid_headers,
            "responseBody": response_body,
            "settlement": settlement,
        }))?
    );

    Ok(())
}

fn response_headers(
    headers: &reqwest::header::HeaderMap,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error + Send + Sync>> {
    headers
        .iter()
        .map(|(name, value)| Ok((name.as_str().to_string(), value.to_str()?.to_string())))
        .collect()
}

fn read_required_env(name: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn read_memory_signer(
    name: &str,
) -> Result<MemorySigner, Box<dyn std::error::Error + Send + Sync>> {
    let raw = read_required_env(name)?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)?;
    Ok(MemorySigner::from_bytes(&bytes)?)
}

fn headers_to_map(headers: Vec<(String, String)>) -> HashMap<String, String> {
    headers.into_iter().collect()
}
