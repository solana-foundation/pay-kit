//! High-throughput (`batch-settlement`) gate: one channel, many cheap requests.
//!
//! The client opens a payment channel once and signs a cumulative voucher per
//! request. The gate (`paid_batch_get` / `paid_batch_post`) verifies each
//! voucher off-chain and serves immediately — no on-chain transaction per
//! request. The operator redeems vouchers on-chain later, in batches, via
//! `pay.x402_batch()`.
//!
//! `batch-settlement` settlement is operator-signed, so it needs a
//! `fee_payer_signer`. Provide the operator key as a JSON byte array in
//! `MPP_OPERATOR_KEY`:
//!
//! ```bash
//! export MPP_OPERATOR_KEY='[12,34,...]'   # 64-byte keypair
//! cargo run -p solana-pay-kit --example axum_batch --features axum
//! ```

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_pay_kit::{paid_batch_get, PayKit, PayKitConfig, Payment};

/// A cheap, high-frequency endpoint: each call costs $0.001.
async fn quote(payment: Payment) -> String {
    format!(
        "quote for channel {} (price {})",
        payment.reference, payment.amount
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
        network: "localnet".to_string(),
        rpc_url: Some("https://402.surfnet.dev:8899".to_string()),
        // batch-settlement settlement transactions are operator-signed.
        fee_payer_signer: Some(Arc::new(operator)),
        ..Default::default()
    })
    .expect("valid config");

    // Operator-side settlement runs out of band: on a cadence (or a threshold),
    // redeem the latest voucher per active channel in batches, then sweep.
    if let Some(batch) = pay.x402_batch().cloned() {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                // In a real deployment, enumerate active channel ids from your
                // store and pass them here; settle_batch packs several per tx.
                let channels: Vec<String> = vec![];
                if channels.is_empty() {
                    continue;
                }
                match batch.settle_batch(&channels).await {
                    Ok(sigs) => {
                        for id in &channels {
                            let _ = batch.distribute(id).await;
                        }
                        tracing::info!(?sigs, "settled batch");
                    }
                    Err(e) => tracing::warn!(error = %e, "batch settle failed"),
                }
            }
        });
    }

    let app = Router::new().route("/quote", paid_batch_get(quote, "0.001", &pay));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4569")
        .await
        .unwrap();
    println!("listening on http://127.0.0.1:4569/quote");
    axum::serve(listener, app).await.unwrap();
}
