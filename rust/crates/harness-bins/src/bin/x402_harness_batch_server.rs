//! x402 `batch-settlement` harness server.
//!
//! Serves the paid resource through the PayKit batch gate, plus an unpaid,
//! test-only `POST /__harness/batch/redeem` that runs `claim` then `settle` so
//! the harness can observe the payout on chain.

use std::{env, sync::Arc};

use axum::{
    extract::State,
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::map_response_with_state,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use serde_json::{json, Value};
use solana_pay_kit::solana_keychain::{memory::MemorySigner, TransactionSigner};
use solana_pay_kit::x402::{server::X402BatchSettlement, PAYMENT_RESPONSE_HEADER};
use solana_pay_kit::{paid_batch_get, PayKit, PayKitConfig, Payment};

const DEFAULT_RESOURCE_PATH: &str = "/batch";
const REDEEM_PATH: &str = "/__harness/batch/redeem";
const HEALTH_PATH: &str = "/health";
const DEFAULT_SETTLEMENT_HEADER: &str = "x-payment-settlement-signature";
const TOKEN_DECIMALS: u8 = 6;
/// PayKit always builds an MPP charge handler, which refuses to start without a
/// binding secret. This bin never mounts an MPP route, so the value is inert.
const UNUSED_MPP_BINDING_SECRET: &str = "paykit-harness-batch-server-mpp-route-not-mounted";

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // The gate reports why it rejected a payment only through `tracing`;
    // stdout stays reserved for the ready line.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    reject_unsupported_flow()?;
    let rpc_url = read_required_env("X402_HARNESS_RPC_URL")?;
    // Same label as the upto server: a local Surfpool whose payment-channels
    // treasury owner is the mainnet constant, never real devnet.
    let network = env::var("X402_HARNESS_NETWORK").unwrap_or_else(|_| "localnet".to_string());
    let mint = env::var("X402_HARNESS_MINT")
        .unwrap_or_else(|_| "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU".to_string());
    let pay_to = read_required_env("X402_HARNESS_PAY_TO")?;
    let fee_payer: Arc<dyn TransactionSigner> = Arc::new(read_memory_signer_any(&[
        "X402_HARNESS_FEE_PAYER_SECRET_KEY",
        "X402_HARNESS_FACILITATOR_SECRET_KEY",
    ])?);
    let price =
        normalize_price(&env::var("X402_HARNESS_PRICE").unwrap_or_else(|_| "$0.10".to_string()))?;
    let resource_path = env::var("X402_HARNESS_RESOURCE_PATH")
        .unwrap_or_else(|_| DEFAULT_RESOURCE_PATH.to_string());
    let settlement_header = HeaderName::from_bytes(
        env::var("X402_HARNESS_SETTLEMENT_HEADER")
            .unwrap_or_else(|_| DEFAULT_SETTLEMENT_HEADER.to_string())
            .as_bytes(),
    )?;
    let mpp_secret = env::var("MPP_HARNESS_SECRET_KEY")
        .unwrap_or_else(|_| UNUSED_MPP_BINDING_SECRET.to_string());

    let pay = PayKit::new(PayKitConfig {
        recipient: pay_to,
        currency: mint,
        decimals: TOKEN_DECIMALS,
        network,
        rpc_url: Some(rpc_url),
        challenge_binding_secret: Some(mpp_secret),
        fee_payer_signer: Some(fee_payer),
        ..Default::default()
    })?;
    let batch = pay
        .x402_batch()
        .cloned()
        .ok_or("PayKit built no batch-settlement handler")?;

    let app = Router::new()
        .route(HEALTH_PATH, get(|| async { Json(json!({ "ok": true })) }))
        .route(&resource_path, paid_batch_get(resource, price, &pay))
        .route(REDEEM_PATH, post(move || redeem(batch.clone())))
        .layer(map_response_with_state(
            settlement_header,
            copy_settlement_signature,
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "ready",
            "implementation": "rust",
            "role": "server",
            "port": port,
            "capabilities": ["batch-settlement"],
        }))?
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn resource(payment: Payment) -> Json<Value> {
    Json(json!({
        "ok": true,
        "paid": true,
        "channelId": payment.reference,
        "amount": payment.amount,
    }))
}

/// Redeem every channel this server holds vouchers for: `claim` advances the
/// onchain watermark, then `settle` pays the claimed delta to `payTo`.
async fn redeem(batch: Arc<X402BatchSettlement>) -> Response {
    let result = async {
        let channels: Vec<String> = batch
            .store()
            .list_channels()
            .await
            .map_err(|e| format!("channel listing failed: {e}"))?
            .into_iter()
            .map(|state| state.channel_id)
            .collect();
        let claim = batch
            .claim(&channels)
            .await
            .map_err(|e| format!("claim failed: {e}"))?;
        let settle = batch
            .settle(&channels)
            .await
            .map_err(|e| format!("settle failed: {e}"))?;
        Ok::<_, String>(json!({ "channels": channels, "claim": claim, "settle": settle }))
    }
    .await;
    match result {
        Ok(body) => Json(body).into_response(),
        Err(error) => {
            eprintln!("harness rust batch server redeem error: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": error })),
            )
                .into_response()
        }
    }
}

/// Mirror the `PAYMENT-RESPONSE` transaction into the scenario settlement
/// header, the way the other harness servers expose it. Empty for a plain
/// voucher, which settles offchain.
async fn copy_settlement_signature(
    State(header): State<HeaderName>,
    mut response: Response,
) -> Response {
    let transaction = response
        .headers()
        .get(PAYMENT_RESPONSE_HEADER)
        .and_then(|value| {
            base64::engine::general_purpose::STANDARD
                .decode(value.as_bytes())
                .ok()
        })
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|body| body.get("transaction")?.as_str().map(str::to_string));
    if let Some(value) = transaction.and_then(|t| HeaderValue::from_str(&t).ok()) {
        response.headers_mut().insert(header, value);
    }
    response
}

fn reject_unsupported_flow() -> Result<(), BoxError> {
    match env::var("X402_HARNESS_BATCH_FLOW").as_deref() {
        Ok("server-signed" | "untrusted-fallback") => Err(
            "X402_HARNESS_BATCH_FLOW server-signed and untrusted-fallback are Python-only; \
             the Rust batch-settlement server accepts client-signed vouchers only"
                .into(),
        ),
        _ => Ok(()),
    }
}

fn read_required_env(name: &str) -> Result<String, BoxError> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn read_memory_signer_any(names: &[&str]) -> Result<MemorySigner, BoxError> {
    for name in names {
        if let Ok(raw) = env::var(name) {
            let bytes: Vec<u8> = serde_json::from_str(&raw)?;
            return Ok(MemorySigner::from_bytes(&bytes)?);
        }
    }
    Err(format!("one of {} is required", names.join(", ")).into())
}

fn normalize_price(price: &str) -> Result<String, BoxError> {
    let without_symbol = price.trim().strip_prefix('$').unwrap_or(price.trim());
    let amount = without_symbol
        .split_whitespace()
        .next()
        .ok_or_else(|| "price is required".to_string())?;
    if amount.is_empty()
        || amount.matches('.').count() > 1
        || !amount.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return Err(format!("invalid price: {price}").into());
    }
    Ok(amount.to_string())
}
