//! Micro-batched Ed25519 voucher verification (opt-in mode).
//!
//! Vouchers arrive one per API request, but at high request rates many sit at
//! the signature-verify step at the same instant. This coalesces those
//! concurrent, otherwise-independent verifications into `ed25519_dalek::verify_batch`
//! calls: a pool of worker tasks each collect up to `max_batch` submissions (or
//! wait up to `window`), verify them in one batched multi-scalar multiplication,
//! then reply per submission. A batch that fails is re-verified per signature
//! with `verify_strict`, so one bad voucher only rejects itself — never its
//! batchmates (otherwise a single malformed voucher would be a batch-wide DoS).
//!
//! Enabled by `PAY_VERIFY_BATCH=1`; tunables (env): `PAY_VERIFY_BATCH_WORKERS`,
//! `PAY_VERIFY_BATCH_MAX`, `PAY_VERIFY_BATCH_WINDOW_US`. When off, the caller
//! verifies inline with `verify_strict` (unchanged behavior).
//!
//! Semantics note: the batched fast path uses cofactored verification (the
//! standard batch equation), whereas the inline path uses `verify_strict`. The
//! per-signature fallback restores `verify_strict`. For normal client keys the
//! two agree; the difference only concerns small-order/malleable edge cases,
//! which is why this is an explicit opt-in mode.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use tokio::sync::{mpsc, oneshot};

struct Job {
    message: Vec<u8>,
    key: VerifyingKey,
    signature: Signature,
    reply: oneshot::Sender<bool>,
}

/// A pool of batching worker tasks. Submissions are sharded round-robin across
/// workers so the crypto parallelizes across the runtime's threads.
pub struct BatchVerifier {
    senders: Vec<mpsc::UnboundedSender<Job>>,
    next: AtomicUsize,
}

impl BatchVerifier {
    fn spawn(workers: usize, max_batch: usize, window: Duration) -> Self {
        let workers = workers.max(1);
        let max_batch = max_batch.max(1);
        let mut senders = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (tx, rx) = mpsc::unbounded_channel::<Job>();
            senders.push(tx);
            tokio::spawn(worker_loop(rx, max_batch, window));
        }
        tracing::info!(
            workers,
            max_batch,
            window_us = window.as_micros() as u64,
            "batch-verify mode enabled"
        );
        Self {
            senders,
            next: AtomicUsize::new(0),
        }
    }

    /// Verify one voucher signature through the batch pool. Returns `true` iff
    /// the signature is valid. Fails closed (`false`) if the worker is gone.
    pub async fn verify(&self, message: Vec<u8>, key: VerifyingKey, signature: Signature) -> bool {
        let (reply, rx) = oneshot::channel();
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        let job = Job {
            message,
            key,
            signature,
            reply,
        };
        if self.senders[idx].send(job).is_err() {
            return false;
        }
        rx.await.unwrap_or(false)
    }
}

async fn worker_loop(mut rx: mpsc::UnboundedReceiver<Job>, max_batch: usize, window: Duration) {
    while let Some(first) = rx.recv().await {
        let mut batch = Vec::with_capacity(max_batch);
        batch.push(first);
        // Coalesce further arrivals until the batch is full or the window
        // elapses, whichever comes first. At high RPS the window fills quickly;
        // at low RPS it caps the added latency.
        let deadline = Instant::now() + window;
        while batch.len() < max_batch {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(job)) => batch.push(job),
                Ok(None) => break, // channel closed
                Err(_) => break,   // window elapsed
            }
        }
        verify_and_reply(batch);
    }
}

fn verify_and_reply(batch: Vec<Job>) {
    if batch.len() == 1 {
        // A batch of one has no amortization; verify_strict directly (also keeps
        // the stricter check for the degenerate case).
        let job = batch.into_iter().next().expect("len == 1");
        let ok = job.key.verify_strict(&job.message, &job.signature).is_ok();
        let _ = job.reply.send(ok);
        return;
    }
    let messages: Vec<&[u8]> = batch.iter().map(|j| j.message.as_slice()).collect();
    let signatures: Vec<Signature> = batch.iter().map(|j| j.signature).collect();
    let keys: Vec<VerifyingKey> = batch.iter().map(|j| j.key).collect();
    if ed25519_dalek::verify_batch(&messages, &signatures, &keys).is_ok() {
        for job in batch {
            let _ = job.reply.send(true);
        }
    } else {
        // At least one signature is bad. Find which with per-signature strict
        // verification so valid batchmates still pass.
        for job in batch {
            let ok = job.key.verify_strict(&job.message, &job.signature).is_ok();
            let _ = job.reply.send(ok);
        }
    }
}

static BATCH_VERIFIER: OnceLock<Option<BatchVerifier>> = OnceLock::new();

/// The process-wide batch verifier, or `None` when the mode is off. Lazily
/// initialized from the environment on first call — which MUST happen from
/// within a Tokio runtime (i.e. on the request hot path), since it spawns the
/// worker tasks. `PAY_VERIFY_BATCH=1` enables it.
pub fn batch_verifier() -> Option<&'static BatchVerifier> {
    BATCH_VERIFIER.get_or_init(init_from_env).as_ref()
}

fn init_from_env() -> Option<BatchVerifier> {
    if std::env::var("PAY_VERIFY_BATCH").ok().as_deref() != Some("1") {
        return None;
    }
    let workers = env_usize("PAY_VERIFY_BATCH_WORKERS", default_workers());
    let max_batch = env_usize("PAY_VERIFY_BATCH_MAX", 64);
    let window_us = env_usize("PAY_VERIFY_BATCH_WINDOW_US", 100) as u64;
    Some(BatchVerifier::spawn(
        workers,
        max_batch,
        Duration::from_micros(window_us),
    ))
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| (n.get() / 4).max(4))
        .unwrap_or(8)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}
