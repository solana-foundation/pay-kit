//! Wire-agnostic payment-channel voucher verification.
//!
//! A voucher authorizes a cumulative spend on a channel: the 50-byte Borsh
//! payload `magic(0x56 0x01) ‖ channelId ‖ cumulativeAmount ‖ expiresAt` (see
//! [`crate::core::payment_channels::voucher_message_bytes`]) signed Ed25519 by the
//! channel's authorized signer. The magic prefix exists only in the signed
//! bytes — the wire/JSON voucher shape is unchanged. Shared by the MPP
//! `session` intent and the x402 `batch-settlement` scheme.

use std::str::FromStr;

use ed25519_dalek::{Signature, VerifyingKey};

use solana_pubkey::Pubkey;

use crate::core::payment_channels::voucher_message_bytes;
use crate::core::{Error, Result};

/// Verify an Ed25519 voucher signature against the authorized signer and check
/// that its expiry is acceptable.
///
/// - `channel_id`, `signature_b58`, `authorized_signer_b58` are base58.
/// - `now` is the current Unix time in seconds.
/// - `settlement_window` is the channel's forced-close grace period (seconds).
///   A non-zero `expires_at` MUST outlast the settlement window — i.e. it must
///   be at least `now + settlement_window` — so the operator can still redeem
///   the voucher on-chain after the asynchronous settlement delay. Pass `0` to
///   only require the voucher be unexpired (`expires_at > now`).
///
/// Expiry semantics mirror the on-chain program (`expires_at != 0 && now >=
/// expires_at` rejects): **`expires_at == 0` means the voucher never expires**
/// and is always accepted regardless of `now` or `settlement_window`. A
/// non-zero `expires_at` is rejected when it is at/before `now` (expired) or
/// before `now + settlement_window` (would lapse before settlement).
pub fn verify_voucher_signature(
    channel_id: &str,
    cumulative: u64,
    expires_at: i64,
    signature_b58: &str,
    authorized_signer_b58: &str,
    now: i64,
    settlement_window: i64,
) -> Result<()> {
    parse_voucher_signature(
        channel_id,
        cumulative,
        expires_at,
        signature_b58,
        authorized_signer_b58,
        now,
        settlement_window,
    )?
    .verify_strict()
}

struct ParsedVoucherSignature {
    message: [u8; 50],
    signature: Signature,
    verifying_key: VerifyingKey,
}

impl ParsedVoucherSignature {
    fn verify_strict(&self) -> Result<()> {
        self.verifying_key
            .verify_strict(&self.message, &self.signature)
            .map_err(|_| Error::Other("Voucher signature verification failed".to_string()))
    }

    #[cfg(feature = "server")]
    fn ensure_batch_safe(&self) -> Result<()> {
        let r_bytes = self.signature.r_bytes();
        if !compressed_edwards_y_is_canonical(r_bytes)
            || compressed_edwards_y_is_small_order(r_bytes)
            || self.verifying_key.is_weak()
        {
            return Err(Error::Other(
                "Voucher signature verification failed".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "server")]
fn compressed_edwards_y_is_canonical(encoded: &[u8; 32]) -> bool {
    // The low 255 bits encode y in little-endian form; the high bit encodes
    // the sign of x. A canonical field element must be less than 2^255 - 19.
    const FIELD_MODULUS: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    let mut y = *encoded;
    y[31] &= 0x7f;
    for index in (0..32).rev() {
        if y[index] != FIELD_MODULUS[index] {
            return y[index] < FIELD_MODULUS[index];
        }
    }
    false
}

#[cfg(feature = "server")]
fn compressed_edwards_y_is_small_order(encoded: &[u8; 32]) -> bool {
    static SMALL_ORDER_ENCODINGS: std::sync::OnceLock<[[u8; 32]; 8]> = std::sync::OnceLock::new();
    SMALL_ORDER_ENCODINGS
        .get_or_init(|| {
            curve25519_dalek::constants::EIGHT_TORSION.map(|point| point.compress().to_bytes())
        })
        .contains(encoded)
}

#[allow(clippy::too_many_arguments)]
fn parse_voucher_signature(
    channel_id: &str,
    cumulative: u64,
    expires_at: i64,
    signature_b58: &str,
    authorized_signer_b58: &str,
    now: i64,
    settlement_window: i64,
) -> Result<ParsedVoucherSignature> {
    // `expires_at == 0` is never-expires (on-chain parity); skip all time checks.
    if expires_at != 0 {
        if expires_at <= now {
            return Err(Error::Other("Voucher has expired".to_string()));
        }
        // Must outlast the forced-close grace period so it can still settle
        // on-chain after the async settlement delay. `now + settlement_window`
        // is computed with saturating math to avoid i64 overflow.
        let settle_deadline = now.saturating_add(settlement_window.max(0));
        if expires_at < settle_deadline {
            return Err(Error::Other(format!(
                "Voucher expiry {expires_at} does not outlast the settlement window \
                 (must be >= {settle_deadline} = now {now} + window {settlement_window})"
            )));
        }
    }

    let channel = Pubkey::from_str(channel_id)
        .map_err(|e| Error::Other(format!("invalid channelId: {e}")))?;
    let message: [u8; 50] = voucher_message_bytes(&channel, cumulative, expires_at)?
        .try_into()
        .map_err(|_| Error::Other("invalid voucher message length".to_string()))?;

    let sig_bytes = bs58::decode(signature_b58)
        .into_vec()
        .map_err(|e| Error::Other(format!("Invalid signature encoding: {e}")))?;
    let pubkey_bytes = bs58::decode(authorized_signer_b58)
        .into_vec()
        .map_err(|e| Error::Other(format!("Invalid authorized_signer: {e}")))?;

    let key_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| Error::Other("Pubkey is not 32 bytes".to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Error::Other("Signature is not 64 bytes".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| Error::Other(format!("Invalid authorized_signer key: {e}")))?;
    let signature = Signature::from_bytes(&sig_arr);

    Ok(ParsedVoucherSignature {
        message,
        signature,
        verifying_key,
    })
}

/// Concurrent voucher verifier that combines queued Ed25519 checks into
/// bounded batches. A low-traffic caller still takes the strict single-check
/// path without an artificial batching delay.
#[cfg(feature = "server")]
#[derive(Default)]
pub struct VoucherBatchVerifier {
    sender: tokio::sync::OnceCell<tokio::sync::mpsc::Sender<VerificationJob>>,
}

#[cfg(feature = "server")]
impl VoucherBatchVerifier {
    /// Verify one voucher, sharing batch work with concurrent callers.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify(
        &self,
        channel_id: &str,
        cumulative: u64,
        expires_at: i64,
        signature_b58: &str,
        authorized_signer_b58: &str,
        now: i64,
        settlement_window: i64,
    ) -> Result<()> {
        let parsed = parse_voucher_signature(
            channel_id,
            cumulative,
            expires_at,
            signature_b58,
            authorized_signer_b58,
            now,
            settlement_window,
        )?;
        // `verify_batch` deliberately omits strict weak-point checks. Perform
        // both checks from `verify_strict` before a request can enter a batch.
        parsed.ensure_batch_safe()?;

        let sender = self
            .sender
            .get_or_init(|| async { start_batch_worker() })
            .await;
        let (response, verified) = tokio::sync::oneshot::channel();
        sender
            .send(VerificationJob { parsed, response })
            .await
            .map_err(|_| Error::Other("voucher verification worker stopped".to_string()))?;
        verified
            .await
            .map_err(|_| Error::Other("voucher verification worker stopped".to_string()))?
            .map_err(|_| Error::Other("Voucher signature verification failed".to_string()))
    }
}

#[cfg(feature = "server")]
struct VerificationJob {
    parsed: ParsedVoucherSignature,
    response: tokio::sync::oneshot::Sender<std::result::Result<(), ()>>,
}

#[cfg(feature = "server")]
fn start_batch_worker() -> tokio::sync::mpsc::Sender<VerificationJob> {
    const QUEUE_CAPACITY: usize = 16_384;
    const BATCH_SIZE: usize = 128;

    let (sender, mut receiver) = tokio::sync::mpsc::channel::<VerificationJob>(QUEUE_CAPACITY);
    let parallel_batches = std::thread::available_parallelism()
        .map(|cpus| (cpus.get() / 4).clamp(1, 32))
        .unwrap_or(1);
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(parallel_batches));
    tokio::spawn(async move {
        let mut batch_count = 0_u64;
        let mut verified_jobs = 0_u64;
        while let Some(first) = receiver.recv().await {
            let mut jobs = Vec::with_capacity(BATCH_SIZE);
            jobs.push(first);
            // Give requests made runnable in the same scheduling turn a chance
            // to join this batch, without adding a wall-clock latency timer.
            tokio::task::yield_now().await;
            while jobs.len() < BATCH_SIZE {
                let Ok(job) = receiver.try_recv() else {
                    break;
                };
                jobs.push(job);
            }

            // Cross-runtime senders can arrive just after the first drain.
            // Once concurrency is proven, spend a tightly bounded interval
            // collecting them instead of scheduling many tiny blocking jobs.
            // The single-request path below never pays this spin cost.
            if jobs.len() > 1 && jobs.len() < BATCH_SIZE {
                let deadline = std::time::Instant::now() + std::time::Duration::from_micros(200);
                while jobs.len() < BATCH_SIZE && std::time::Instant::now() < deadline {
                    match receiver.try_recv() {
                        Ok(job) => jobs.push(job),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                            std::hint::spin_loop();
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
            }

            batch_count += 1;
            verified_jobs += jobs.len() as u64;
            if batch_count <= 8 || batch_count.is_multiple_of(10_000) {
                tracing::trace!(
                    batch_count,
                    verified_jobs,
                    latest_batch_size = jobs.len(),
                    mean_batch_size = verified_jobs as f64 / batch_count as f64,
                    "voucher verification batch formed"
                );
            }

            if jobs.len() == 1 {
                let job = jobs.pop().expect("one verification job");
                let result = job.parsed.verify_strict().map_err(|_| ());
                let _ = job.response.send(result);
                continue;
            }

            let permit = match std::sync::Arc::clone(&permits).acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => break,
            };
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                verify_batch_jobs(jobs);
            });
        }
    });
    sender
}

#[cfg(feature = "server")]
fn verify_batch_jobs(jobs: Vec<VerificationJob>) {
    static BATCH_RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static FAILED_BATCHES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let messages: Vec<&[u8]> = jobs
        .iter()
        .map(|job| job.parsed.message.as_slice())
        .collect();
    let signatures: Vec<Signature> = jobs.iter().map(|job| job.parsed.signature).collect();
    let verifying_keys: Vec<VerifyingKey> =
        jobs.iter().map(|job| job.parsed.verifying_key).collect();
    let batch_valid = ed25519_dalek::verify_batch(&messages, &signatures, &verifying_keys).is_ok();
    let batch_run = BATCH_RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let failed_batches = if batch_valid {
        FAILED_BATCHES.load(std::sync::atomic::Ordering::Relaxed)
    } else {
        FAILED_BATCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
    };
    if batch_run <= 8 || batch_run.is_multiple_of(10_000) {
        tracing::trace!(
            batch_run,
            failed_batches,
            batch_size = jobs.len(),
            batch_valid,
            "voucher verification batch completed"
        );
    }

    for job in jobs {
        let result = if batch_valid {
            Ok(())
        } else {
            job.parsed.verify_strict().map_err(|_| ())
        };
        let _ = job.response.send(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(
        channel: &Pubkey,
        cumulative: u64,
        expires_at: i64,
        sk: &SigningKey,
    ) -> (String, String) {
        let msg = voucher_message_bytes(channel, cumulative, expires_at).unwrap();
        let sig = sk.sign(&msg);
        let signer = bs58::encode(sk.verifying_key().as_bytes()).into_string();
        (bs58::encode(sig.to_bytes()).into_string(), signer)
    }

    #[test]
    fn accepts_a_valid_unexpired_voucher_and_rejects_tampering() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let channel = Pubkey::new_unique();
        let channel_b58 = bs58::encode(channel.as_ref()).into_string();
        let (sig, signer) = signed(&channel, 1_000, 4_102_444_800, &sk);

        assert!(
            verify_voucher_signature(&channel_b58, 1_000, 4_102_444_800, &sig, &signer, 1, 0)
                .is_ok()
        );
        // Wrong cumulative → signature no longer matches the message.
        assert!(
            verify_voucher_signature(&channel_b58, 2_000, 4_102_444_800, &sig, &signer, 1, 0)
                .is_err()
        );
        // Expired.
        assert!(verify_voucher_signature(&channel_b58, 1_000, 100, &sig, &signer, 200, 0).is_err());
    }

    // FIX #9a: expires_at == 0 means never-expires (on-chain parity), so it is
    // accepted regardless of `now` or the settlement window.
    #[test]
    fn zero_expiry_means_never_expires() {
        let sk = SigningKey::from_bytes(&[8u8; 32]);
        let channel = Pubkey::new_unique();
        let channel_b58 = bs58::encode(channel.as_ref()).into_string();
        let (sig, signer) = signed(&channel, 1_000, 0, &sk);

        // Accepted even with a large `now` and a large settlement window.
        assert!(verify_voucher_signature(
            &channel_b58,
            1_000,
            0,
            &sig,
            &signer,
            1_000_000_000,
            900
        )
        .is_ok());
    }

    // FIX #9b: a non-zero expiry must outlast the settlement window.
    #[test]
    fn nonzero_expiry_must_outlast_settlement_window() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let channel = Pubkey::new_unique();
        let channel_b58 = bs58::encode(channel.as_ref()).into_string();
        let now = 1_000;
        let window = 900;

        // expires_at just inside the window → rejected (would lapse before settle).
        let (sig_short, signer) = signed(&channel, 1_000, now + window - 1, &sk);
        let err = verify_voucher_signature(
            &channel_b58,
            1_000,
            now + window - 1,
            &sig_short,
            &signer,
            now,
            window,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("settlement window"),
            "expected settlement-window error, got: {err}"
        );

        // expires_at exactly at now + window → accepted.
        let (sig_ok, _) = signed(&channel, 1_000, now + window, &sk);
        assert!(verify_voucher_signature(
            &channel_b58,
            1_000,
            now + window,
            &sig_ok,
            &signer,
            now,
            window,
        )
        .is_ok());

        // expired (at/before now) → rejected even with a zero window.
        let (sig_exp, _) = signed(&channel, 1_000, now, &sk);
        assert!(
            verify_voucher_signature(&channel_b58, 1_000, now, &sig_exp, &signer, now, 0).is_err()
        );
    }

    #[cfg(feature = "server")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_verifier_accepts_valid_jobs_and_attributes_a_bad_signature() {
        let sk = SigningKey::from_bytes(&[10u8; 32]);
        let channel = Pubkey::new_unique();
        let channel_b58 = bs58::encode(channel.as_ref()).into_string();
        let signer = bs58::encode(sk.verifying_key().as_bytes()).into_string();
        let verifier = std::sync::Arc::new(VoucherBatchVerifier::default());
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(33));
        let mut jobs = Vec::new();

        for cumulative in 1..=32_u64 {
            let signed_cumulative = if cumulative == 17 {
                cumulative + 1
            } else {
                cumulative
            };
            let (signature, _) = signed(&channel, signed_cumulative, 0, &sk);
            let verifier = std::sync::Arc::clone(&verifier);
            let barrier = std::sync::Arc::clone(&barrier);
            let channel_b58 = channel_b58.clone();
            let signer = signer.clone();
            jobs.push(tokio::spawn(async move {
                barrier.wait().await;
                verifier
                    .verify(&channel_b58, cumulative, 0, &signature, &signer, 1, 0)
                    .await
            }));
        }

        barrier.wait().await;
        for (index, job) in jobs.into_iter().enumerate() {
            let result = job.await.unwrap();
            if index == 16 {
                assert!(result.is_err());
            } else {
                assert!(result.is_ok(), "valid batch job {index} was rejected");
            }
        }
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn batch_verifier_rejects_a_small_order_signature_point() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let channel = Pubkey::new_unique();
        let channel_b58 = bs58::encode(channel.as_ref()).into_string();
        let signer = bs58::encode(sk.verifying_key().as_bytes()).into_string();
        let mut signature = [0_u8; 64];
        signature[0] = 1;
        let signature = bs58::encode(signature).into_string();

        let result = VoucherBatchVerifier::default()
            .verify(&channel_b58, 1, 0, &signature, &signer, 1, 0)
            .await;
        assert!(result.is_err());
    }
}
