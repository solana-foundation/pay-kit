//! Single confidential-settlement worker run-loop (opt-in `worker` feature).
//!
//! Spun up once at boot (not per request). It owns the shared replay /
//! orphan-guard store and the gateway fee-payer signer, serves confidential
//! settlement over an mpsc channel (one oneshot reply per request), and runs a
//! periodic orphan sweep on the same loop. Centralizing this gives the orphan
//! guard and replay protection a single shared store, and keeps the fee-payer
//! signer resident instead of rebuilding it per request.
//!
//! The loop processes settlement messages sequentially. Confidential volume is
//! low (a premium path), so this is fine; if it ever needs concurrency, spawn a
//! small fixed pool of these loops sharing one receiver.
//!
//! The worker binds an `Mpp` per settlement because `Mpp` fixes its recipient +
//! currency at construction; the shared store is injected via `Config.store`.

use std::sync::Arc;
use std::time::Duration;

use solana_keychain::SolanaSigner;
use tokio::sync::{mpsc, oneshot};

use super::charge::{Config as MppConfig, Mpp, VerificationError};
use crate::store::{MemoryStore, Store};
use crate::{ChargeRequest, PaymentCredential, Receipt};

const SWEEP_INTERVAL_SECS: u64 = 300;
const CHANNEL_CAPACITY: usize = 256;

/// Static configuration the worker needs to build per-settlement `Mpp`s and the
/// long-lived sweep `Mpp`.
pub struct ConfidentialWorkerConfig {
    pub network: String,
    pub rpc_url: String,
    pub challenge_binding_secret: Option<String>,
    pub realm: String,
    /// A Token-2022 stablecoin (mint + decimals) configured on this network,
    /// used to construct the long-lived sweep `Mpp`. The sweep itself is
    /// currency-agnostic (it scans the ZK proof + record programs).
    pub sweep_currency: String,
    pub sweep_decimals: u8,
    /// Gateway fee-payer pubkey — the sweep `Mpp`'s nominal recipient.
    pub fee_payer_pubkey: String,
    /// Payee wallet signer, when the gateway controls the recipient. `Some`
    /// enables recipient-key settlement (the worker decrypts the recipient's
    /// pending-balance delta and enforces the exact amount); `None` is
    /// facilitator/trust-proofs mode (no amount enforcement — only valid when
    /// the gateway is not the payee, e.g. relaying to an arbitrary recipient).
    pub recipient_signer: Option<Arc<dyn SolanaSigner>>,
}

/// Messages the worker accepts. Boxed payloads keep the enum small.
enum ConfidentialMsg {
    Settle {
        credential: Box<PaymentCredential>,
        charge_request: Box<ChargeRequest>,
        /// Mint + decimals of the charge currency.
        currency: String,
        decimals: u8,
        reply: oneshot::Sender<Result<Receipt, VerificationError>>,
    },
}

/// Cloneable handle the request handlers use to talk to the worker.
#[derive(Clone)]
pub struct ConfidentialHandle {
    tx: mpsc::Sender<ConfidentialMsg>,
}

impl ConfidentialHandle {
    /// Settle a confidential bundle on the worker and await its receipt.
    pub async fn settle(
        &self,
        credential: PaymentCredential,
        charge_request: ChargeRequest,
        currency: String,
        decimals: u8,
    ) -> Result<Receipt, VerificationError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(ConfidentialMsg::Settle {
                credential: Box::new(credential),
                charge_request: Box::new(charge_request),
                currency,
                decimals,
                reply,
            })
            .await
            .map_err(|_| VerificationError::new("confidential worker unavailable"))?;
        rx.await
            .map_err(|_| VerificationError::new("confidential worker dropped the reply"))?
    }
}

/// Spawn the single confidential worker run-loop and return a handle. The loop
/// lives for the process lifetime; the returned handle (and its clones) drive it.
pub fn spawn(cfg: ConfidentialWorkerConfig, signer: Arc<dyn SolanaSigner>) -> ConfidentialHandle {
    let (tx, mut rx) = mpsc::channel::<ConfidentialMsg>(CHANNEL_CAPACITY);
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

    tokio::spawn(async move {
        // Build the long-lived sweep Mpp once (shares the store with settlement).
        let sweep_mpp = build_mpp(
            &cfg,
            cfg.fee_payer_pubkey.clone(),
            cfg.sweep_currency.clone(),
            cfg.sweep_decimals,
            signer.clone(),
            store.clone(),
        );
        if sweep_mpp.is_none() {
            tracing::warn!("confidential worker: sweep Mpp unavailable; orphan sweep disabled");
        }

        let mut sweep = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    let Some(msg) = msg else { break }; // all handles dropped
                    match msg {
                        ConfidentialMsg::Settle {
                            credential,
                            charge_request,
                            currency,
                            decimals,
                            reply,
                        } => {
                            let result = settle(
                                &cfg, &signer, &store, &credential, &charge_request, &currency, decimals,
                            )
                            .await;
                            let _ = reply.send(result);
                        }
                    }
                }
                _ = sweep.tick() => {
                    let Some(mpp) = sweep_mpp.as_ref() else { continue };
                    match mpp.sweep_confidential_orphans().await {
                        Ok(r) if r.closed_contexts + r.closed_records + r.failed > 0 => tracing::info!(
                            closed_contexts = r.closed_contexts,
                            closed_records = r.closed_records,
                            deferred = r.deferred,
                            failed = r.failed,
                            "confidential orphan sweep"
                        ),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "confidential orphan sweep failed"),
                    }
                }
            }
        }
        tracing::info!("confidential worker run-loop stopped");
    });

    ConfidentialHandle { tx }
}

/// Settle one confidential bundle: build a per-charge `Mpp` (sharing the worker's
/// store + signer) and verify the credential through it.
async fn settle(
    cfg: &ConfidentialWorkerConfig,
    signer: &Arc<dyn SolanaSigner>,
    store: &Arc<dyn Store>,
    credential: &PaymentCredential,
    charge_request: &ChargeRequest,
    currency: &str,
    decimals: u8,
) -> Result<Receipt, VerificationError> {
    // Pin the Mpp's recipient to the credential's so the verify recipient check
    // holds for both send layouts (as the direct path does).
    let recipient = charge_request
        .recipient
        .clone()
        .unwrap_or_else(|| cfg.fee_payer_pubkey.clone());
    let mpp = build_mpp(
        cfg,
        recipient,
        currency.to_string(),
        decimals,
        signer.clone(),
        store.clone(),
    )
    .ok_or_else(|| VerificationError::new("failed to build settlement Mpp"))?;

    mpp.verify(credential, charge_request).await
}

fn build_mpp(
    cfg: &ConfidentialWorkerConfig,
    recipient: String,
    currency: String,
    decimals: u8,
    signer: Arc<dyn SolanaSigner>,
    store: Arc<dyn Store>,
) -> Option<Mpp> {
    Mpp::new(MppConfig {
        recipient,
        currency,
        decimals,
        network: cfg.network.clone(),
        rpc_url: Some(cfg.rpc_url.clone()),
        challenge_binding_secret: cfg.challenge_binding_secret.clone(),
        realm: Some(cfg.realm.clone()),
        fee_payer: true,
        fee_payer_signer: Some(signer),
        // Recipient-key amount enforcement when the gateway controls the payee.
        recipient_signer: cfg.recipient_signer.clone(),
        store: Some(store),
        html: false,
        ..Default::default()
    })
    .ok()
}
