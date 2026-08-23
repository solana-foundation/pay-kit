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
//! standard batch equation), whereas the inline path uses `verify_strict`.
//! Cofactored verification alone is a real gap, not just an edge case:
//! `R = identity`/`s = H(R‖A‖M)·a mod L` satisfies the batch equation for any
//! message under any key whose scalar the signer knows, no crafted key
//! needed, while `verify_strict` rejects it outright. [`is_degenerate`]
//! screens every batch input for exactly the two checks `verify_strict` makes
//! beyond the batch equation (small-order `R`, small-order key) before the
//! batch equation runs at all, so the two paths agree on every input, not
//! just "normal" ones. The per-signature fallback on a failing batch restores
//! `verify_strict` too.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use curve25519_dalek::edwards::CompressedEdwardsY;
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

/// Whether `job` is degenerate the way `verify_strict` rejects but the raw
/// cofactored batch equation does not: an `R` or verifying key of small order.
///
/// `ed25519_dalek::verify_batch` checks `[8]sB = [8]R + [8]hA`, which is blind
/// to the curve's 8-torsion subgroup — multiplying by the cofactor 8 maps every
/// small-order point to the identity on both sides. Concretely, `R = identity`
/// (order 1, small-order) and `s = H(R‖A‖M)·a mod L` satisfies that equation
/// for *any* message M, for any key whose private scalar `a` the signer knows
/// — no weak/crafted key required. `verify_strict` closes this by explicitly
/// rejecting a small-order `R` or verifying key before its own (cofactorless)
/// check; batching must apply the same two checks before trusting the batch
/// equation, or a holder of a legitimate signing key (e.g. the payer, in
/// scheme variants where the payer is the channel's own voucher signer) can
/// produce a signature this gate accepts but on-chain settlement — which
/// verifies with `verify_strict` via the Ed25519 precompile — never will:
/// service served, nothing ever collectible.
fn is_degenerate(key: &VerifyingKey, signature: &Signature) -> bool {
    if key.is_weak() {
        return true;
    }
    match CompressedEdwardsY(*signature.r_bytes()).decompress() {
        Some(point) => point.is_small_order(),
        // Doesn't even decompress to a curve point; verify_strict would also
        // reject it, by way of `InternalSignature::try_from` failing first.
        None => true,
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

    // Reject degenerate jobs before batch verification runs, so one can never
    // ride a passing batch to acceptance. Cheap relative to the multiscalar
    // multiplication it guards: one point decompression per job.
    let mut candidates = Vec::with_capacity(batch.len());
    for job in batch {
        if is_degenerate(&job.key, &job.signature) {
            let _ = job.reply.send(false);
        } else {
            candidates.push(job);
        }
    }

    match candidates.len() {
        0 => {}
        1 => {
            let job = candidates.into_iter().next().expect("len == 1");
            let ok = job.key.verify_strict(&job.message, &job.signature).is_ok();
            let _ = job.reply.send(ok);
        }
        _ => {
            let messages: Vec<&[u8]> = candidates.iter().map(|j| j.message.as_slice()).collect();
            let signatures: Vec<Signature> = candidates.iter().map(|j| j.signature).collect();
            let keys: Vec<VerifyingKey> = candidates.iter().map(|j| j.key).collect();
            if ed25519_dalek::verify_batch(&messages, &signatures, &keys).is_ok() {
                for job in candidates {
                    let _ = job.reply.send(true);
                }
            } else {
                // At least one signature is bad. Find which with per-signature
                // strict verification so valid batchmates still pass.
                for job in candidates {
                    let ok = job.key.verify_strict(&job.message, &job.signature).is_ok();
                    let _ = job.reply.send(ok);
                }
            }
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

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::Identity;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha512};

    use super::*;

    fn keypair(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Constructs the exact degenerate forgery `is_degenerate` must reject:
    /// `R = identity`, `s = H(R‖A‖M)·a mod L`. Satisfies `verify_batch`'s
    /// cofactored equation for *any* message under any key whose scalar `a`
    /// the caller knows (no small-order/crafted key needed); `verify_strict`
    /// rejects it via its explicit small-order-`R` check.
    fn forge_degenerate_signature(signer: &SigningKey, message: &[u8]) -> Signature {
        let verifying_key = signer.verifying_key();
        let r_bytes = EdwardsPoint::identity().compress().to_bytes();
        let mut hasher = Sha512::new();
        hasher.update(r_bytes);
        hasher.update(verifying_key.as_bytes());
        hasher.update(message);
        let h = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
        let s = h * signer.to_scalar();
        Signature::from_components(r_bytes, s.to_bytes())
    }

    #[test]
    fn forged_signature_is_internally_consistent() {
        // Sanity check on the forgery construction itself: R really is the
        // identity, and it really does encode a point on the curve.
        let r_bytes = EdwardsPoint::identity().compress().to_bytes();
        assert!(!ED25519_BASEPOINT_POINT.is_small_order());
        assert!(EdwardsPoint::identity().is_small_order());
        assert_eq!(r_bytes.len(), 32);
    }

    #[test]
    fn degenerate_signature_satisfies_the_raw_batch_equation_but_not_verify_strict() {
        // Documents the underlying library behavior `is_degenerate` guards
        // against (ed25519_dalek's, not ours): the vulnerability Efe's review
        // reported exists one call below this module, in the crate itself.
        let attacker = keypair(7);
        let message = b"anything";
        let forged = forge_degenerate_signature(&attacker, message);

        assert!(attacker
            .verifying_key()
            .verify_strict(message, &forged)
            .is_err());
        assert!(ed25519_dalek::verify_batch(
            &[message.as_slice()],
            &[forged],
            &[attacker.verifying_key()]
        )
        .is_ok());
    }

    #[test]
    fn is_degenerate_rejects_the_forgery_and_accepts_a_real_signature() {
        let signer = keypair(1);
        let message = b"real message";

        let honest = signer.sign(message);
        assert!(!is_degenerate(&signer.verifying_key(), &honest));

        let forged = forge_degenerate_signature(&signer, message);
        assert!(is_degenerate(&signer.verifying_key(), &forged));
    }

    #[test]
    fn is_degenerate_rejects_a_weak_verifying_key() {
        // A small-order verifying key, independent of any particular signature.
        let weak_key = VerifyingKey::from_bytes(&EdwardsPoint::identity().compress().to_bytes())
            .expect("identity is a valid (if weak) verifying key encoding");
        assert!(weak_key.is_weak());
        let honest_looking = keypair(9).sign(b"m");
        assert!(is_degenerate(&weak_key, &honest_looking));
    }

    #[tokio::test]
    async fn batched_verification_rejects_a_degenerate_signature_riding_an_honest_batchmate() {
        // The exact scenario the raw library allows and this module must not:
        // a forged signature riding a batch alongside a real, honest one.
        let honest_signer = keypair(2);
        let honest_message = b"paid request".to_vec();
        let honest_signature = honest_signer.sign(&honest_message);

        let attacker = keypair(3);
        let attacker_message = b"free request".to_vec();
        let forged = forge_degenerate_signature(&attacker, &attacker_message);

        let (honest_reply, honest_rx) = oneshot::channel();
        let (forged_reply, forged_rx) = oneshot::channel();
        verify_and_reply(vec![
            Job {
                message: honest_message,
                key: honest_signer.verifying_key(),
                signature: honest_signature,
                reply: honest_reply,
            },
            Job {
                message: attacker_message,
                key: attacker.verifying_key(),
                signature: forged,
                reply: forged_reply,
            },
        ]);

        assert!(
            honest_rx.await.unwrap(),
            "the honest signature must still verify"
        );
        assert!(
            !forged_rx.await.unwrap(),
            "the forged signature must be rejected"
        );
    }

    #[tokio::test]
    async fn batch_verifier_end_to_end_rejects_the_forgery() {
        // Same scenario through the public async API a real caller uses,
        // proving the fix holds through the worker-pool path too.
        let verifier = BatchVerifier::spawn(1, 8, Duration::from_millis(50));

        let honest_signer = keypair(4);
        let honest_message = b"paid".to_vec();
        let honest_signature = honest_signer.sign(&honest_message);

        let attacker = keypair(5);
        let attacker_message = b"free".to_vec();
        let forged = forge_degenerate_signature(&attacker, &attacker_message);

        let (honest_ok, forged_ok) = tokio::join!(
            verifier.verify(
                honest_message,
                honest_signer.verifying_key(),
                honest_signature
            ),
            verifier.verify(attacker_message, attacker.verifying_key(), forged),
        );
        assert!(honest_ok, "the honest signature must still verify");
        assert!(!forged_ok, "the forged signature must be rejected");
    }
}
