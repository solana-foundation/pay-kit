//! Canonical interop test client.
//!
//! Tests the full payment cycle against any MPP server:
//!   1. GET /health → 200
//!   2. GET /fortune → 402 + WWW-Authenticate
//!   3. Fund test keypair via surfpool
//!   4. Build credential using solana-mpp client
//!   5. GET /fortune with Authorization → 200 + fortune
//!
//! Usage: SERVER_URL=http://localhost:3001 cargo run

use std::sync::Arc;

use solana_mpp::client::{build_credential_header, parse_challenge};
use solana_mpp::solana_keychain::SolanaSigner;

#[tokio::main]
async fn main() {
    let server_url =
        std::env::var("SERVER_URL").unwrap_or_else(|_| "http://localhost:3001".to_string());
    let fortune_path =
        std::env::var("FORTUNE_PATH").unwrap_or_else(|_| "/fortune".to_string());
    let rpc_url =
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());

    println!("Interop test: Rust client → {server_url}");
    println!("RPC: {rpc_url}");

    let http = reqwest::Client::new();
    let rpc = Arc::new(solana_rpc_client::rpc_client::RpcClient::new(rpc_url.clone()));

    // ── Test 1: Health ──
    print!("  health ... ");
    let resp = http
        .get(format!("{server_url}/health"))
        .send()
        .await
        .expect("health request failed");
    assert_eq!(resp.status(), 200, "health should return 200");
    println!("OK");

    // ── Test 2: Challenge ──
    print!("  challenge ... ");
    let resp = http
        .get(format!("{server_url}{fortune_path}"))
        .send()
        .await
        .expect("fortune request failed");
    assert_eq!(resp.status(), 402, "fortune without auth should return 402");
    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("missing WWW-Authenticate")
        .to_str()
        .expect("invalid header value")
        .to_string();
    assert!(
        www_auth.starts_with("Payment "),
        "should use Payment scheme"
    );
    let challenge = parse_challenge(&www_auth).expect("failed to parse challenge");
    assert_eq!(challenge.method.as_str(), "solana");
    assert_eq!(challenge.intent.as_str(), "charge");
    println!("OK (id={}…)", &challenge.id[..12]);

    // ── Test 3: Fund test keypair via surfpool ──
    print!("  fund ... ");
    // Generate a fresh Ed25519 keypair for testing
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let mut keypair_bytes = [0u8; 64];
    keypair_bytes[..32].copy_from_slice(signing_key.as_bytes());
    keypair_bytes[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
    let signer = solana_keychain::memory::MemorySigner::from_bytes(&keypair_bytes)
        .expect("create signer");
    let pubkey = signer.pubkey();
    let pubkey_str = pubkey.to_string();

    // Decode request to get currency info
    let request: serde_json::Value = challenge.request.decode().expect("decode request");
    let currency = request["currency"].as_str().unwrap_or("sol");
    let is_native_sol = currency.eq_ignore_ascii_case("sol");
    let method_details = &request["methodDetails"];
    let token_program = method_details["tokenProgram"]
        .as_str()
        .unwrap_or("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    let recipient = request["recipient"].as_str().expect("missing recipient");

    // Fund SOL
    rpc_call(
        &http,
        &rpc_url,
        "surfnet_setAccount",
        serde_json::json!([
            pubkey_str,
            {"lamports": 2_000_000_000_u64, "data": "", "executable": false, "owner": "11111111111111111111111111111111", "rentEpoch": 0}
        ]),
    )
    .await;

    if !is_native_sol {
        // Fund token account
        let amount: u64 = request["amount"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        rpc_call(
            &http,
            &rpc_url,
            "surfnet_setTokenAccount",
            serde_json::json!([pubkey_str, currency, {"amount": amount, "state": "initialized"}, token_program]),
        )
        .await;
        // Ensure recipient has token account
        rpc_call(
            &http,
            &rpc_url,
            "surfnet_setTokenAccount",
            serde_json::json!([recipient, currency, {"amount": 0, "state": "initialized"}, token_program]),
        )
        .await;
    }
    println!("OK (pubkey={}…)", &pubkey_str[..8]);

    // ── Test 4: Build credential ──
    print!("  credential ... ");
    let auth_header = build_credential_header(&signer, &rpc, &challenge)
        .await
        .expect("build_credential_header failed");
    assert!(
        auth_header.starts_with("Payment "),
        "credential should start with Payment"
    );
    println!("OK");

    // ── Test 5: Submit and get fortune ──
    print!("  payment ... ");
    let resp = http
        .get(format!("{server_url}{fortune_path}"))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("payment request failed");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, 200,
        "payment should return 200, got {status}: {body}"
    );
    let data: serde_json::Value =
        serde_json::from_str(&body).expect("response should be valid JSON");
    assert!(
        data.get("fortune").is_some(),
        "response should contain fortune"
    );
    println!("OK → {}", data["fortune"].as_str().unwrap_or("?"));

    println!("\n  ✓ All interop tests passed");
}

async fn rpc_call(
    http: &reqwest::Client,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) {
    let resp = http
        .post(rpc_url)
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .await
        .unwrap_or_else(|e| panic!("RPC {method} failed: {e}"));
    let data: serde_json::Value = resp.json().await.unwrap();
    if let Some(err) = data.get("error") {
        panic!("RPC {method} error: {err}");
    }
}
