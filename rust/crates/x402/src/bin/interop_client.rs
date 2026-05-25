use std::{collections::HashMap, env};

use serde_json::json;
use solana_keychain::memory::MemorySigner;
use solana_rpc_client::rpc_client::RpcClient;
use solana_x402::{
    client::exact::{build_payment_header, parse_x402_challenge_with_selection, ChallengeSelection},
    PAYMENT_SIGNATURE_HEADER,
};

const DEFAULT_NETWORK: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const SETTLEMENT_HEADER: &str = "x-fixture-settlement";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target_url = read_required_env("X402_INTEROP_TARGET_URL")?;
    let rpc_url = read_required_env("X402_INTEROP_RPC_URL")?;
    let network = env::var("X402_INTEROP_NETWORK").unwrap_or_else(|_| DEFAULT_NETWORK.to_string());
    let signer = read_memory_signer("X402_INTEROP_CLIENT_SECRET_KEY")?;

    // For multi-currency interop, the harness passes
    //   X402_INTEROP_PREFER_CURRENCIES = "PYUSD,USDC"
    // to communicate the client's currency preference order. With no env
    // var set the client falls back to "cheapest amount on preferred
    // network" — same as before.
    let preferred_currencies: Option<Vec<String>> =
        env::var("X402_INTEROP_PREFER_CURRENCIES").ok().map(|raw| {
            raw.split(',')
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect()
        });

    let http = reqwest::Client::new();
    let first_response = http.get(&target_url).send().await?;
    let first_headers = response_headers(first_response.headers())?;
    let first_body = first_response.text().await?;
    let preferred_refs: Option<Vec<&str>> = preferred_currencies
        .as_ref()
        .map(|list| list.iter().map(String::as_str).collect());
    let selection = ChallengeSelection {
        network: Some(&network),
        currencies: preferred_refs.as_deref(),
    };
    let requirements = parse_x402_challenge_with_selection(
        &first_headers,
        Some(&first_body),
        &selection,
    )
    .ok_or_else(|| "server did not return a supported SVM x402 challenge".to_string())?;

    let rpc = RpcClient::new(rpc_url);
    let payment_header = build_payment_header(&signer, &rpc, &requirements).await?;

    let paid_response = http
        .get(&target_url)
        .header(PAYMENT_SIGNATURE_HEADER, payment_header)
        .send()
        .await?;
    let status = paid_response.status();
    let paid_headers = response_headers(paid_response.headers())?;
    let paid_headers = headers_to_map(paid_headers);
    let settlement = paid_headers.get(SETTLEMENT_HEADER).cloned();
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
