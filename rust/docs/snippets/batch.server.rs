//! Server-side batch-settlement: one channel, many cheap requests.
//!
//! Mirrors `crates/kit/examples/axum_batch.rs`. Not one of the playground's four
//! primitives, so the playground extractor ignores it — the SDK docs read it
//! directly. See `../../../docs/snippets-convention.md`.

use std::sync::Arc;

use axum::Router;
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::{paid_batch_get, PayKit, PayKitConfig, Payment};

// A cheap, high-frequency endpoint: each call costs $0.001.
async fn quote(payment: Payment) -> String {
    format!("quote for channel {} ({})", payment.reference, payment.amount)
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
        // batch-settlement transactions are operator-signed.
        fee_payer_signer: Some(Arc::new(operator)),
        ..Default::default()
    })
    .expect("valid config");

    // The client opens one channel and signs a cumulative voucher per request;
    // the gate verifies it off-chain and serves immediately. Redeem vouchers
    // on-chain later, in batches, via `pay.x402_batch()`.
    let app = Router::new().route("${PATH}", paid_batch_get(quote, "0.001", &pay));
    // snippet:end

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4569")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
