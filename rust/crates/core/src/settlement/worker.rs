//! Background batched-settlement worker (feature `worker`).
//!
//! An mpsc actor that accumulates per-channel settlement instructions and
//! flushes them as **legacy** transactions on either trigger:
//!   - **size:** the batch fills (`max_channels_per_tx`, or the next channel
//!     would exceed the 1232-byte packet limit) → seal a tx, start a new batch;
//!   - **timer:** a `linger` window (default 350ms) elapses → flush whatever's
//!     pending.
//!
//! Each flush signs with the **operator** (fee-payer + Delegated authority),
//! **sends** (does not wait for confirmation — the signature is returned to
//! callers immediately), then a background task confirms/retries. Un-settled
//! channels remain the caller's store's responsibility to reconcile.
//!
//! Broadcast is behind the [`Broadcaster`] trait so the actor is unit-testable
//! without an RPC and reusable by both the mpp session and x402 paths.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::Transaction;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::Instant;
use tracing::Instrument;

use super::packing::{tx_size, would_overflow_tx, DEFAULT_MAX_CHANNELS_PER_TX};

/// Settlement outcome returned to a submitter: the broadcast tx signature.
pub type SettlementResult = Result<String, String>;

/// One channel's settlement, submitted to the worker.
pub struct SettlementUnit {
    pub channel_id: String,
    pub instructions: Vec<Instruction>,
    /// Submitter's span — the flush span `follows_from` it so a voucher/close
    /// links to its settlement tx in the trace view.
    pub parent: tracing::Span,
    pub reply: oneshot::Sender<SettlementResult>,
}

/// Outcome of a confirmation poll for a previously-sent signature.
#[derive(Debug, Clone)]
pub enum ConfirmOutcome {
    /// Landed and succeeded on-chain.
    Confirmed,
    /// Not yet observed (still propagating / not finalized) — keep polling.
    Pending,
    /// Landed but failed on-chain (permanent) — stop polling. Carries the error.
    Failed(String),
}

/// Broadcast surface — abstracted for testing and reuse.
#[async_trait]
pub trait Broadcaster: Send + Sync {
    async fn latest_blockhash(&self) -> Result<Hash, String>;
    /// Broadcast a signed tx; return its signature (no confirmation wait).
    async fn send(&self, tx: &Transaction) -> Result<String, String>;
    /// Poll confirmation for a previously-sent signature. `Err` is a transient
    /// RPC error (caller may retry); `Ok` distinguishes confirmed / pending /
    /// permanent on-chain failure so the caller can stop polling a dead tx.
    async fn confirm(&self, signature: &str) -> Result<ConfirmOutcome, String>;
}

pub struct SettlementConfig {
    pub operator: Pubkey,
    pub operator_signer: Arc<dyn SolanaSigner>,
    /// Calibrated cap (P0 = 3 for settle+finalize); packing is also byte-bounded.
    pub max_channels_per_tx: usize,
    /// Linger window before flushing a partial batch.
    pub linger: Duration,
    /// Max concurrent in-flight flush transactions.
    pub max_in_flight_tx: usize,
    /// Confirmation poll attempts before giving up (store reconciles the rest).
    pub confirm_attempts: u32,
}

impl SettlementConfig {
    pub fn new(operator: Pubkey, operator_signer: Arc<dyn SolanaSigner>) -> Self {
        Self {
            operator,
            operator_signer,
            max_channels_per_tx: DEFAULT_MAX_CHANNELS_PER_TX,
            linger: Duration::from_millis(350),
            max_in_flight_tx: 16,
            confirm_attempts: 10,
        }
    }
}

/// Cloneable handle to submit settlement units.
#[derive(Clone)]
pub struct SettlementHandle {
    tx: mpsc::Sender<SettlementUnit>,
}

impl SettlementHandle {
    /// Submit one channel for settlement. Returns the broadcast tx signature
    /// once its batch is flushed (errors if the worker has stopped).
    pub async fn settle(
        &self,
        channel_id: impl Into<String>,
        instructions: Vec<Instruction>,
    ) -> SettlementResult {
        let (reply, rx) = oneshot::channel();
        let unit = SettlementUnit {
            channel_id: channel_id.into(),
            instructions,
            parent: tracing::Span::current(),
            reply,
        };
        self.tx
            .send(unit)
            .await
            .map_err(|_| "settlement worker stopped".to_string())?;
        rx.await
            .map_err(|_| "settlement reply dropped".to_string())?
    }
}

/// Spawn the worker actor; returns a handle. Dropping all handles stops it
/// (after flushing what's pending).
pub fn spawn(cfg: SettlementConfig, broadcaster: Arc<dyn Broadcaster>) -> SettlementHandle {
    let (tx, mut rx) = mpsc::channel::<SettlementUnit>(1024);
    let cfg = Arc::new(cfg);
    let sem = Arc::new(Semaphore::new(cfg.max_in_flight_tx.max(1)));

    tokio::spawn(async move {
        let mut pending: Vec<SettlementUnit> = Vec::new();
        let mut deadline: Option<Instant> = None;

        loop {
            let timer = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            };

            tokio::select! {
                maybe = rx.recv() => match maybe {
                    Some(unit) => {
                        pending.push(unit);
                        if deadline.is_none() {
                            deadline = Some(Instant::now() + cfg.linger);
                        }
                        // Size trigger: seal full transactions eagerly. Clamp to
                        // >=1 so a misconfigured `max_channels_per_tx == 0` can't
                        // spin draining nothing while spawning empty flushes.
                        let max_per_tx = cfg.max_channels_per_tx.max(1);
                        while pending.len() >= max_per_tx {
                            let batch = pending.drain(..max_per_tx).collect();
                            spawn_flush(batch, cfg.clone(), broadcaster.clone(), sem.clone(), "size");
                        }
                        if pending.is_empty() {
                            deadline = None;
                        }
                    }
                    None => {
                        if !pending.is_empty() {
                            spawn_flush(std::mem::take(&mut pending), cfg.clone(), broadcaster.clone(), sem.clone(), "drain");
                        }
                        break;
                    }
                },
                _ = timer => {
                    if !pending.is_empty() {
                        spawn_flush(std::mem::take(&mut pending), cfg.clone(), broadcaster.clone(), sem.clone(), "timer");
                    }
                    deadline = None;
                }
            }
        }
        tracing::debug!("settlement worker stopped");
    });

    SettlementHandle { tx }
}

/// Re-group units to be byte- and count-safe, then settle each group as one tx.
fn spawn_flush(
    units: Vec<SettlementUnit>,
    cfg: Arc<SettlementConfig>,
    broadcaster: Arc<dyn Broadcaster>,
    sem: Arc<Semaphore>,
    trigger: &'static str,
) {
    tokio::spawn(async move {
        for group in regroup(units, &cfg.operator, cfg.max_channels_per_tx) {
            // One permit per settle transaction (not per flush, which may
            // regroup into several): bounds concurrent in-flight settle txs
            // across all flushes to `max_in_flight_tx`. The worker owns the
            // semaphore and never closes it, so acquire cannot fail — an `Err`
            // would otherwise bypass the limit, so make that explicit.
            let _permit = sem
                .clone()
                .acquire_owned()
                .await
                .expect("settlement semaphore is never closed");
            settle_group(group, &cfg, broadcaster.clone(), trigger).await;
        }
    });
}

/// Greedy byte+count packing over units. Same boundary rule as
/// [`super::packing::pack`] (via [`super::packing::would_overflow_tx`]) but
/// keeps the per-unit reply channels.
fn regroup(
    units: Vec<SettlementUnit>,
    payer: &Pubkey,
    max_per_tx: usize,
) -> Vec<Vec<SettlementUnit>> {
    let mut out: Vec<Vec<SettlementUnit>> = Vec::new();
    let mut cur: Vec<SettlementUnit> = Vec::new();
    for u in units {
        if !cur.is_empty() {
            let cur_ix: Vec<Instruction> = cur
                .iter()
                .flat_map(|c| c.instructions.iter().cloned())
                .collect();
            if would_overflow_tx(&cur_ix, cur.len(), &u.instructions, payer, max_per_tx) {
                out.push(std::mem::take(&mut cur));
            }
        }
        cur.push(u);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

async fn settle_group(
    group: Vec<SettlementUnit>,
    cfg: &SettlementConfig,
    broadcaster: Arc<dyn Broadcaster>,
    trigger: &'static str,
) {
    let started = Instant::now();
    let ids: Vec<String> = group.iter().map(|u| u.channel_id.clone()).collect();
    let span = tracing::info_span!(
        "settlement_flush",
        trigger,
        channels = group.len(),
        tx_sig = tracing::field::Empty,
        tx_bytes = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
    );
    for u in &group {
        if let Some(id) = u.parent.id() {
            span.follows_from(id);
        }
    }

    // Instrument the whole body rather than holding an `Entered` guard across
    // the `.await`s below: a held guard misattributes any work the executor
    // runs on this thread after a yield. `Instrument` re-enters per poll.
    async move {
        let span = tracing::Span::current();
        let flat: Vec<Instruction> = group
            .iter()
            .flat_map(|u| u.instructions.iter().cloned())
            .collect();
        span.record("tx_bytes", tx_size(&flat, &cfg.operator));

        // Build + sign + broadcast.
        let result: SettlementResult = async {
            let blockhash = broadcaster.latest_blockhash().await?;
            let message = Message::new_with_blockhash(&flat, Some(&cfg.operator), &blockhash);
            let mut tx = Transaction::new_unsigned(message);
            cfg.operator_signer
                .sign_transaction(&mut tx)
                .await
                .map_err(|e| format!("settle signing failed: {e}"))?;
            broadcaster.send(&tx).await
        }
        .await;

        match &result {
            Ok(sig) => {
                span.record("tx_sig", sig.as_str());
                span.record("latency_ms", started.elapsed().as_millis() as u64);
                tracing::info!(
                    monotonic_counter.pay_settlement_tx_total = 1_u64,
                    histogram.pay_settlement_batch_channels = group.len() as u64,
                    histogram.pay_settlement_latency_ms = started.elapsed().as_millis() as u64,
                    trigger,
                    channels = group.len(),
                    channel_ids = ?ids,
                    tx = %sig,
                    "settlement batch broadcast",
                );
            }
            Err(e) => {
                tracing::warn!(
                    monotonic_counter.pay_settlement_errors_total = 1_u64,
                    trigger,
                    channels = group.len(),
                    channel_ids = ?ids,
                    error = %e,
                    "settlement batch failed (store will reconcile)",
                );
            }
        }

        // Reply to every channel in the group with the (shared) tx signature.
        for u in group {
            let _ = u.reply.send(result.clone());
        }

        // Background confirm (best-effort; store is the durable source of truth).
        if let Ok(sig) = result {
            let attempts = cfg.confirm_attempts;
            tokio::spawn(async move {
                for _ in 0..attempts {
                    match broadcaster.confirm(&sig).await {
                        Ok(ConfirmOutcome::Confirmed) => {
                            tracing::debug!(tx = %sig, "settlement confirmed");
                            return;
                        }
                        Ok(ConfirmOutcome::Pending) => {
                            tokio::time::sleep(Duration::from_millis(400)).await
                        }
                        // Permanent on-chain failure: don't spin the full retry
                        // window — log and let the store reconcile.
                        Ok(ConfirmOutcome::Failed(err)) => {
                            tracing::warn!(
                                monotonic_counter.pay_settlement_failed_total = 1_u64,
                                tx = %sig,
                                error = %err,
                                "settlement failed on-chain (store will reconcile)",
                            );
                            return;
                        }
                        Err(e) => {
                            tracing::debug!(tx = %sig, error = %e, "confirm poll error");
                            tokio::time::sleep(Duration::from_millis(400)).await;
                        }
                    }
                }
                tracing::warn!(
                    monotonic_counter.pay_settlement_unconfirmed_total = 1_u64,
                    tx = %sig,
                    "settlement not confirmed in window",
                );
            });
        }
    }
    .instrument(span)
    .await
}

/// Production broadcaster over a blocking `RpcClient` (calls run on
/// `spawn_blocking` so they never stall the async runtime).
pub struct RpcBroadcaster {
    rpc: Arc<RpcClient>,
}

impl RpcBroadcaster {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc: Arc::new(RpcClient::new(rpc_url.into())),
        }
    }
}

#[async_trait]
impl Broadcaster for RpcBroadcaster {
    async fn latest_blockhash(&self) -> Result<Hash, String> {
        let rpc = self.rpc.clone();
        tokio::task::spawn_blocking(move || rpc.get_latest_blockhash())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
    }

    async fn send(&self, tx: &Transaction) -> Result<String, String> {
        let rpc = self.rpc.clone();
        let tx = tx.clone();
        tokio::task::spawn_blocking(move || rpc.send_transaction(&tx))
            .await
            .map_err(|e| e.to_string())?
            .map(|s| s.to_string())
            .map_err(|e| e.to_string())
    }

    async fn confirm(&self, signature: &str) -> Result<ConfirmOutcome, String> {
        use solana_signature::Signature;
        let rpc = self.rpc.clone();
        let sig: Signature = signature.parse().map_err(|_| "bad signature".to_string())?;
        tokio::task::spawn_blocking(move || {
            let statuses = rpc
                .get_signature_statuses(&[sig])
                .map_err(|e| e.to_string())?;
            Ok(match statuses.value.into_iter().next().flatten() {
                Some(s) => match s.err {
                    Some(e) => ConfirmOutcome::Failed(format!("{e:?}")),
                    None => ConfirmOutcome::Confirmed,
                },
                None => ConfirmOutcome::Pending,
            })
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_instruction::AccountMeta;
    use solana_keychain::{SignTransactionResult, SignerError};
    use solana_signature::Signature;
    use std::sync::Mutex;

    // ── Mock signer: no real keypair; the mock broadcaster doesn't verify. ──
    struct TestSigner(Pubkey);
    #[async_trait]
    impl SolanaSigner for TestSigner {
        fn pubkey(&self) -> Pubkey {
            self.0
        }
        async fn sign_transaction(
            &self,
            tx: &mut Transaction,
        ) -> Result<SignTransactionResult, SignerError> {
            let sig = Signature::from([1u8; 64]);
            if let Some(s) = tx.signatures.first_mut() {
                *s = sig;
            }
            Ok(SignTransactionResult::Complete((String::new(), sig)))
        }
        async fn sign_message(&self, _m: &[u8]) -> Result<Signature, SignerError> {
            Ok(Signature::from([1u8; 64]))
        }
        async fn is_available(&self) -> bool {
            true
        }
    }

    // ── Mock broadcaster: records channels-per-tx, returns sequential sigs. ──
    #[derive(Default)]
    struct MockBroadcaster {
        sent: Mutex<Vec<usize>>, // instruction count per tx
        seq: Mutex<u64>,
    }
    #[async_trait]
    impl Broadcaster for MockBroadcaster {
        async fn latest_blockhash(&self) -> Result<Hash, String> {
            Ok(Hash::new_from_array([9u8; 32]))
        }
        async fn send(&self, tx: &Transaction) -> Result<String, String> {
            self.sent
                .lock()
                .unwrap()
                .push(tx.message.instructions.len());
            let mut seq = self.seq.lock().unwrap();
            *seq += 1;
            Ok(format!("sig{seq}"))
        }
        async fn confirm(&self, _sig: &str) -> Result<ConfirmOutcome, String> {
            Ok(ConfirmOutcome::Confirmed)
        }
    }

    fn unit_instructions(i: u64) -> Vec<Instruction> {
        // One small instruction whose accounts are unique per channel.
        let program = Pubkey::new_from_array([1u8; 32]);
        let acct = Pubkey::new_from_array({
            let mut b = [2u8; 32];
            b[1..9].copy_from_slice(&i.to_le_bytes());
            b
        });
        vec![Instruction::new_with_bytes(
            program,
            &[0u8; 8],
            vec![AccountMeta::new(acct, false)],
        )]
    }

    fn handle(max_per_tx: usize, linger_ms: u64) -> (SettlementHandle, Arc<MockBroadcaster>) {
        let bc = Arc::new(MockBroadcaster::default());
        let mut cfg = SettlementConfig::new(
            Pubkey::new_from_array([0xAA; 32]),
            Arc::new(TestSigner(Pubkey::new_from_array([0xAA; 32]))),
        );
        cfg.max_channels_per_tx = max_per_tx;
        cfg.linger = Duration::from_millis(linger_ms);
        (spawn(cfg, bc.clone()), bc)
    }

    #[tokio::test]
    async fn size_trigger_seals_full_tx() {
        let (h, bc) = handle(3, 5_000); // long linger so only the size trigger fires
        let mut tasks = Vec::new();
        for i in 0..3u64 {
            let h = h.clone();
            tasks.push(tokio::spawn(async move {
                h.settle(format!("c{i}"), unit_instructions(i)).await
            }));
        }
        for t in tasks {
            assert!(t.await.unwrap().is_ok());
        }
        // One tx carrying all 3 channels' instructions.
        let sent = bc.sent.lock().unwrap().clone();
        assert_eq!(sent, vec![3], "expected one 3-channel tx, got {sent:?}");
    }

    #[tokio::test]
    async fn timer_flushes_partial_batch() {
        let (h, bc) = handle(10, 120); // cap high → only the timer flushes
        let r = h.settle("c0", unit_instructions(0)).await;
        assert!(r.is_ok());
        assert_eq!(
            bc.sent.lock().unwrap().clone(),
            vec![1],
            "timer should flush the single channel"
        );
    }

    /// End-to-end (minus the program executing): drive the worker over K
    /// channels built with the REAL settle+finalize instructions and assert the
    /// emitted transactions are correctly batched, operator-signed, and
    /// packet-legal. Proves everything the worker is responsible for; only the
    /// on-chain finalize (which needs the deployed program) is out of scope.
    #[tokio::test]
    async fn batched_settle_emits_correct_transactions() {
        use crate::payment_channels::{build_settle_and_finalize_instructions, default_program_id};
        use crate::settlement::packing::{tx_size, MAX_TX_BYTES};

        let operator = Pubkey::new_from_array([0xAA; 32]); // Delegated: authorized_signer == operator
        let program_id = default_program_id();

        // Build 7 channels' real settle instructions (ed25519 verify + settle).
        let mut channels = Vec::new();
        for i in 0..7u64 {
            let channel = Pubkey::new_from_array({
                let mut b = [0x10; 32];
                b[1..9].copy_from_slice(&i.to_le_bytes());
                b
            });
            let sig = [7u8; 64];
            let ixs = build_settle_and_finalize_instructions(
                &operator,
                &channel,
                &operator,
                Some(&sig),
                1_000,
                9_999_999_999,
                &program_id,
            )
            .unwrap();
            assert_eq!(
                ixs.len(),
                2,
                "settle+finalize with voucher = ed25519 + settle"
            );
            // Each channel's own tx must be packet-legal.
            assert!(tx_size(&ixs, &operator) <= MAX_TX_BYTES);
            channels.push((channel.to_string(), ixs));
        }

        let (h, bc) = handle(3, 5_000); // cap 3, long linger → size trigger packs 3,3,1
        let mut tasks = Vec::new();
        for (id, ixs) in channels {
            let h = h.clone();
            tasks.push(tokio::spawn(async move { h.settle(id, ixs).await }));
        }
        let mut sigs = Vec::new();
        for t in tasks {
            let r = t.await.unwrap();
            sigs.push(r.expect("settle reply ok"));
        }

        // 7 channels @ 3/tx ⇒ 3 transactions.
        let mut distinct = sigs.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            3,
            "7 channels should batch into 3 transactions"
        );

        // Instruction counts per tx: 2 per channel ⇒ [6, 6, 2].
        let mut sent = bc.sent.lock().unwrap().clone();
        sent.sort();
        assert_eq!(
            sent,
            vec![2, 6, 6],
            "expected 3+3+1 channels per tx (2 ix each)"
        );
    }
}
