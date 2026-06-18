//! Usage-based (`upto`) gate: charge per actual usage, up to a ceiling.
//!
//! The route advertises a **maximum** price. The client opens a payment channel
//! depositing that ceiling; the handler meters real usage and reports it via the
//! [`Charge`] extractor; the gate settles the actual amount and refunds the
//! remainder. This is the shape you want for LLM-token billing or per-byte
//! metering, where the final cost is unknown until after the work runs.
//!
//! `upto` settlement is operator-signed, so it requires a `fee_payer_signer`.
//! Provide the operator key as a JSON byte array in `MPP_OPERATOR_KEY`:
//!
//! ```bash
//! export MPP_OPERATOR_KEY='[12,34,...]'   # 64-byte keypair
//! cargo run -p solana-pay-kit --example axum_upto --features axum
//! ```

use std::sync::Arc;

use axum::Router;
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_pay_kit::{paid_upto_post, Charge, PayKit, PayKitConfig, Payment};

/// Price per generated token, in USDC base units (6 decimals): 100 = $0.0001.
const PRICE_PER_TOKEN_BASE_UNITS: u64 = 100;

/// Summarize the request body and bill for the tokens "generated".
///
/// `Payment` carries the authorized ceiling; `Charge` reports actual usage. The
/// body is the text to summarize. Extractors that read the body come last.
async fn summarize(payment: Payment, charge: Charge, body: String) -> String {
    // Pretend we ran a model: one token per 4 input bytes, min one token.
    let tokens = (body.len() / 4).max(1) as u64;
    let owed = tokens.saturating_mul(PRICE_PER_TOKEN_BASE_UNITS);

    // Report actual usage; the gate settles this (clamped to the ceiling) and
    // refunds the unused deposit.
    charge.charge(owed);

    format!(
        "summarized {} bytes as {tokens} tokens; billed {} of up to {} base units (ceiling {})",
        body.len(),
        owed.min(charge.max_base_units()),
        charge.max_base_units(),
        payment.amount,
    )
}

#[tokio::main]
async fn main() {
    let operator_json = std::env::var("MPP_OPERATOR_KEY")
        .expect("set MPP_OPERATOR_KEY to a 64-byte keypair JSON array");
    let operator = MemorySigner::from_private_key_string(&operator_json)
        .expect("valid operator keypair in MPP_OPERATOR_KEY");

    let pay = PayKit::new(PayKitConfig {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        network: "devnet".to_string(),
        rpc_url: Some("https://402.surfnet.dev:8899".to_string()),
        // upto settlement vouchers are operator-signed, so a signer is required.
        fee_payer_signer: Some(Arc::new(operator)),
        ..Default::default()
    })
    .expect("valid config");

    // Maximum $1.00; the handler bills only for actual tokens generated.
    let app = Router::new().route("/summarize", paid_upto_post(summarize, "1.00", &pay));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4568")
        .await
        .unwrap();
    println!("listening on http://127.0.0.1:4568/summarize");
    axum::serve(listener, app).await.unwrap();
}
