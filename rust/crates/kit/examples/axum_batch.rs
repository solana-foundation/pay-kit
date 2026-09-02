//! High-throughput (`batch-settlement`) gate: one channel, many cheap requests.
//!
//! The client opens a payment channel once and signs a cumulative voucher per
//! request. The gate (`paid_batch_get` / `paid_batch_post`) verifies each
//! voucher off-chain and serves immediately — no on-chain transaction per
//! request. The server redeems vouchers on-chain later, in batches, via
//! `pay.x402_batch()`: `claim` advances each channel's on-chain watermark from
//! its latest stored voucher, then `settle` pays the claimed delta to `payTo`.
//!
//! The server self-facilitates, so it needs a `fee_payer_signer` — the key that
//! sponsors channel rent, co-signs the client's `open`, and signs redemption.
//! Provide it as a JSON byte array in `MPP_OPERATOR_KEY`:
//!
//! ```bash
//! export MPP_OPERATOR_KEY='[12,34,...]'   # 64-byte keypair
//! cargo run -p solana-pay-kit --example axum_batch --features axum
//! ```

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use solana_pay_kit::solana_keychain::memory::MemorySigner;
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

    // Redemption runs out of band, never in the request path. Claim promptly:
    // a voucher that is not claimed before a payer's forced close completes is
    // value the server forfeits.
    if let Some(batch) = pay.x402_batch().cloned() {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                // Channels this server has state for. `discover_sponsored_channels()`
                // rebuilds the on-chain half of this list after state loss.
                let channels: Vec<String> = match batch.store().list_channels().await {
                    Ok(states) => states.into_iter().map(|s| s.channel_id).collect(),
                    Err(e) => {
                        tracing::warn!(error = %e, "channel listing failed");
                        continue;
                    }
                };
                if channels.is_empty() {
                    continue;
                }
                // `claim` advances the on-chain watermark (up to four channels
                // per transaction); `settle` then pays the newly claimed delta.
                match batch.claim(&channels).await {
                    Ok(sigs) => tracing::info!(?sigs, "claimed vouchers"),
                    Err(e) => {
                        tracing::warn!(error = %e, "claim failed");
                        continue;
                    }
                }
                match batch.settle(&channels).await {
                    Ok(sigs) => tracing::info!(?sigs, "distributed settled funds"),
                    Err(e) => tracing::warn!(error = %e, "distribute failed"),
                }
                match batch.finalize_close(&channels).await {
                    Ok(sigs) => tracing::info!(?sigs, "finalized due channel closes"),
                    Err(e) => tracing::warn!(error = %e, "close finalization failed"),
                }
                match batch.reclaim(&channels).await {
                    Ok(sigs) => tracing::info!(?sigs, "reclaimed channel rent"),
                    Err(e) => tracing::warn!(error = %e, "rent reclaim failed"),
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
