//! Minimal dual-protocol paid API.
//!
//! Gates one route on payment. An unpaid request gets a 402 carrying both the
//! MPP `WWW-Authenticate` challenge and the x402 `PAYMENT-REQUIRED` challenge;
//! a client pays with whichever protocol it supports and the handler runs.
//!
//! Run with:
//!   cargo run -p solana-pay-kit --example axum_quickstart --features axum
//!
//! Then, in another shell:
//!   curl -i http://127.0.0.1:4567/report        # 402 Payment Required (both challenges)
//!   pay curl -i http://127.0.0.1:4567/report     # pays + gets 200

use axum::Router;
use solana_pay_kit::{paid_get, PayKit, PayKitConfig, Payment, Price};

// A fixed-price route: the verified payment lands in the handler.
async fn report(payment: Payment) -> String {
    format!(
        "premium report — paid {} via {} (ref {})",
        payment.amount, payment.protocol, payment.reference
    )
}

// A dynamically-priced route: ?tier=premium costs more.
async fn quote(payment: Payment) -> String {
    format!("quote @ {} — ref {}", payment.amount, payment.reference)
}

#[tokio::main]
async fn main() {
    // Zero-config beyond the wallet address: a published demo recipient and the
    // hosted Surfpool sandbox. Swap in your own wallet for production, and set
    // MPP_SECRET_KEY to a >= 32-byte secret (`openssl rand -base64 32`).
    let pay = PayKit::new(PayKitConfig {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        network: "localnet".to_string(),
        rpc_url: Some("https://402.surfnet.dev:8899".to_string()),
        challenge_binding_secret: Some(
            std::env::var("MPP_SECRET_KEY")
                .unwrap_or_else(|_| "demo-only-secret-key-with-32-bytes-padding".to_string()),
        ),
        ..Default::default()
    })
    .expect("valid PayKit config");

    let app: Router = Router::new()
        .route("/report", paid_get(report, "0.10", &pay))
        .route(
            "/quote",
            paid_get(
                quote,
                Price::dynamic(|ctx| match ctx.query_param("tier").as_deref() {
                    Some("premium") => "5.00".to_string(),
                    _ => "0.10".to_string(),
                }),
                &pay,
            ),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4567")
        .await
        .expect("bind :4567");
    println!("listening on http://127.0.0.1:4567 (try /report and /quote?tier=premium)");
    axum::serve(listener, app).await.expect("serve");
}
