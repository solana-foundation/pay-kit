use std::{
    collections::HashMap,
    env,
    io::{self, Write},
    process,
};

use serde_json::json;

/// Write a line to stdout, swallowing `BrokenPipe` (EPIPE) errors instead of
/// panicking the way Rust's default `println!` macro would when the harness
/// has stopped reading our pipe. Mirrors the helper in `interop_server.rs`.
fn write_stdout_line(line: &str) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    match writeln!(handle, "{line}") {
        Ok(()) => {
            let _ = handle.flush();
        }
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => process::exit(0),
        Err(err) => panic!("failed printing to stdout: {err}"),
    }
}
use solana_mpp::client::build_credential_header;
use solana_mpp::solana_keychain::memory::MemorySigner;
use solana_mpp::solana_rpc_client::rpc_client::RpcClient;
use solana_mpp::{parse_www_authenticate_all, AUTHORIZATION_HEADER, WWW_AUTHENTICATE_HEADER};

const SETTLEMENT_HEADER: &str = "x-fixture-settlement";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target_url = read_required_env("MPP_INTEROP_TARGET_URL")?;
    let rpc_url = read_required_env("MPP_INTEROP_RPC_URL")?;
    let signer = read_memory_signer("MPP_INTEROP_CLIENT_SECRET_KEY")?;
    let settlement_header =
        env::var("MPP_INTEROP_SETTLEMENT_HEADER").unwrap_or_else(|_| SETTLEMENT_HEADER.to_string());

    let http = reqwest::Client::new();
    let first_response = http.get(&target_url).send().await?;
    let first_headers = response_headers(first_response.headers())?;
    let challenge_values = first_headers
        .iter()
        .filter(|(name, _)| name == WWW_AUTHENTICATE_HEADER)
        .map(|(_, value)| value.as_str());
    let challenge = parse_www_authenticate_all(challenge_values)
        .into_iter()
        .filter_map(Result::ok)
        .find(|challenge| {
            challenge.method.as_str() == "solana" && challenge.intent.as_str() == "charge"
        })
        .ok_or_else(|| "server did not return a supported Payment challenge".to_string())?;

    let rpc = RpcClient::new(rpc_url);
    let authorization = build_credential_header(&signer, &rpc, &challenge).await?;

    let paid_response = http
        .get(&target_url)
        .header(AUTHORIZATION_HEADER, authorization)
        .send()
        .await?;
    let status = paid_response.status();
    let paid_headers = headers_to_map(response_headers(paid_response.headers())?);
    let settlement = paid_headers.get(&settlement_header).cloned();
    let raw_body = paid_response.text().await?;
    let response_body = serde_json::from_str::<serde_json::Value>(&raw_body)
        .unwrap_or(serde_json::Value::String(raw_body));

    write_stdout_line(&serde_json::to_string(&json!({
        "type": "result",
        "implementation": "rust",
        "role": "client",
        "ok": status.is_success(),
        "status": status.as_u16(),
        "responseHeaders": paid_headers,
        "responseBody": response_body,
        "settlement": settlement,
    }))?);

    Ok(())
}

fn response_headers(
    headers: &reqwest::header::HeaderMap,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error + Send + Sync>> {
    headers
        .iter()
        .map(|(name, value)| {
            Ok((
                name.as_str().to_ascii_lowercase(),
                value.to_str()?.to_string(),
            ))
        })
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
