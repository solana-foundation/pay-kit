//! Server-side charge: gate an axum route with a fixed price.
//!
//! Mirrors `crates/kit/examples/axum_quickstart.rs`. See
//! `../../../docs/snippets-convention.md` for the snippet:start/end convention —
//! only the marked region is shown; the rest keeps the file compilable.

use axum::Router;
use solana_pay_kit::{paid_get, PayKit, PayKitConfig, Payment};

// The verified payment lands in the handler.
async fn quote(payment: Payment) -> String {
    format!("quote — paid {} via {}", payment.amount, payment.protocol)
}

#[tokio::main]
async fn main() {
    // snippet:start
    let pay = PayKit::new(PayKitConfig {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        network: "localnet".to_string(),
        rpc_url: Some("https://402.surfnet.dev:8899".to_string()),
        ..Default::default()
    })
    .expect("valid config");

    // `paid_get(handler, price, &pay)` settles the 402 (MPP or x402, the
    // client's choice) before the handler runs.
    let app = Router::new().route("${PATH}", paid_get(quote, "0.01", &pay));
    // snippet:end

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4567")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
