//! Server-side usage (`upto`): charge for actual usage up to a ceiling.
//!
//! Mirrors `crates/kit/examples/axum_upto.rs`. Not one of the playground's four
//! primitives, so the playground extractor ignores it — the SDK docs read it
//! directly. See `../../../docs/snippets-convention.md`.

use std::sync::Arc;

use axum::Router;
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::{paid_upto_post, Charge, PayKit, PayKitConfig, Payment};

/// Price per generated token, in USDC base units (6 decimals): 100 = $0.0001.
const PRICE_PER_TOKEN_BASE_UNITS: u64 = 100;

// `Payment` carries the authorized ceiling; `Charge` reports actual usage.
async fn summarize(payment: Payment, charge: Charge, body: String) -> String {
    let tokens = (body.len() / 4).max(1) as u64;
    let owed = tokens.saturating_mul(PRICE_PER_TOKEN_BASE_UNITS);

    // Report actual usage; the gate settles this (clamped to the ceiling) and
    // refunds the unused deposit.
    charge.charge(owed);

    format!(
        "billed {} of up to {} base units (ceiling {})",
        owed.min(charge.max_base_units()),
        charge.max_base_units(),
        payment.amount,
    )
}

#[tokio::main]
async fn main() {
    let operator = MemorySigner::from_private_key_string(
        &std::env::var("MPP_OPERATOR_KEY").expect("set MPP_OPERATOR_KEY to a 64-byte keypair JSON"),
    )
    .expect("valid operator keypair");

    // snippet:start
    let pay = PayKit::new(PayKitConfig {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        network: "localnet".to_string(),
        rpc_url: Some("https://402.surfnet.dev:8899".to_string()),
        // `upto` uses this signer as fee payer and, by default, receiver authorizer.
        fee_payer_signer: Some(Arc::new(operator)),
        ..Default::default()
    })
    .expect("valid config");

    // Maximum $1.00; the handler bills only for actual usage via `charge.charge`,
    // and the gate refunds the remainder.
    let app = Router::new().route("${PATH}", paid_upto_post(summarize, "1.00", &pay));
    // snippet:end

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4568")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
