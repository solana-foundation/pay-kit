//! Minimal test server for Playwright E2E tests of the HTML payment link flow.
//!
//! Run with: `cargo run --example payment_link_server`
//! Listens on http://localhost:3001
//! Requires Surfpool on localhost:8899

use axum::{
    extract::Query,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use solana_mpp::protocol::core::headers::parse_authorization;
use solana_mpp::protocol::intents::ChargeRequest;
use solana_mpp::server::{html, Config, Mpp};
use std::collections::HashMap;
use std::sync::Arc;

const ROUTE_PRICE: &str = "0.01";

/// Build the route's expected charge request. Threading this into
/// `verify_credential_with_expected` is what protects against cross-route
/// credential replay — without it, a credential issued for a cheaper route
/// (or different recipient/currency) on the same server would be accepted.
fn expected_request_for_route(mpp: &Mpp) -> Option<ChargeRequest> {
    mpp.charge(ROUTE_PRICE)
        .ok()
        .and_then(|challenge| challenge.request.decode().ok())
}

const CSP: &str = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src *; worker-src 'self'";

async fn fortune(
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    mpp: axum::extract::State<Arc<Mpp>>,
) -> Response {
    // Authenticated request — verify the credential and return fortune.
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        let auth_str = auth.to_str().unwrap_or("");
        if auth_str.starts_with("Payment ") {
            match parse_authorization(auth_str) {
                Ok(credential) => {
                    if let Some(expected) = expected_request_for_route(&mpp) {
                        match mpp
                            .verify_credential_with_expected(&credential, &expected)
                            .await
                        {
                            Ok(receipt) => {
                                let ref_id = receipt.reference;
                                return (
                                    StatusCode::OK,
                                    [
                                        ("content-type", "application/json"),
                                        ("payment-receipt", &ref_id),
                                    ],
                                    r#"{"fortune":"A smooth sea never made a skilled sailor."}"#,
                                )
                                    .into_response();
                            }
                            Err(e) => {
                                eprintln!("verify_credential_with_expected failed: {e}");
                                // Fall through to re-issue challenge
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("parse_authorization failed: {e}");
                }
            }
        }
    }

    // Service worker JS.
    if params.contains_key(html::SERVICE_WORKER_PARAM) {
        return (
            StatusCode::OK,
            [
                ("content-type", "application/javascript"),
                ("service-worker-allowed", "/"),
            ],
            html::service_worker_js(),
        )
            .into_response();
    }

    // Generate challenge.
    let challenge = mpp
        .charge_with_options(
            ROUTE_PRICE,
            solana_mpp::server::ChargeOptions {
                description: Some("Open a fortune cookie"),
                ..Default::default()
            },
        )
        .expect("charge");
    let www_auth = solana_mpp::format_www_authenticate(&challenge).unwrap_or_default();

    // Browser — HTML payment page.
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if html::accepts_html(accept) {
        let page = html::challenge_to_html(&challenge, mpp.rpc_url(), mpp.network());
        return (
            StatusCode::PAYMENT_REQUIRED,
            [
                ("content-type", "text/html; charset=utf-8"),
                ("content-security-policy", CSP),
                ("www-authenticate", &www_auth),
            ],
            page,
        )
            .into_response();
    }

    // API client — JSON 402.
    (
        StatusCode::PAYMENT_REQUIRED,
        [
            ("content-type", "application/json"),
            ("www-authenticate", &www_auth),
        ],
        serde_json::to_string(&challenge).unwrap(),
    )
        .into_response()
}

async fn health() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        r#"{"ok":true}"#,
    )
}

#[tokio::main]
async fn main() {
    let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());

    // No fee payer — test mode client pays its own fees.
    let mpp = Arc::new(
        Mpp::new(Config {
            recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            secret_key: Some(
                "e2e-test-secret-key-long-enough-for-hmac-operations-1234567890".into(),
            ),
            network: "localnet".to_string(),
            rpc_url: Some(rpc_url),
            currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            decimals: 6,
            html: true,
            ..Default::default()
        })
        .expect("valid config"),
    );

    // Fund the recipient so their token account exists (surfpool cheatcode).
    let rpc_url = mpp.rpc_url().to_string();
    let recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
    let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    let token_program = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    // Set recipient SOL balance
    let _ = reqwest::Client::new()
        .post(&rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "surfnet_setAccount",
            "params": [recipient, {"lamports": 1_000_000_000_u64, "data": "", "executable": false, "owner": "11111111111111111111111111111111", "rentEpoch": 0}]
        }))
        .send().await;

    // Set recipient USDC token account
    let _ = reqwest::Client::new()
        .post(&rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "surfnet_setTokenAccount",
            "params": [recipient, mint, {"amount": 0, "state": "initialized"}, token_program]
        }))
        .send()
        .await;

    let app = axum::Router::new()
        .route("/fortune", get(fortune))
        .route("/health", get(health))
        .with_state(mpp);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    println!("payment_link_server listening on http://localhost:3001");
    axum::serve(listener, app).await.unwrap();
}
