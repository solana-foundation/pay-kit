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
        use curve25519_dalek::edwards::CompressedEdwardsY;

        let r = CompressedEdwardsY(*self.signature.r_bytes())
            .decompress()
            .ok_or_else(|| Error::Other("Voucher signature verification failed".to_string()))?;
        if r.compress().as_bytes() != self.signature.r_bytes()
            || self.verifying_key.is_weak()
            || r.is_small_order()
        {
            return Err(Error::Other(
                "Voucher signature verification failed".to_string(),
            ));
        }
        Ok(())
    }
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
    let messages: Vec<&[u8]> = jobs
        .iter()
        .map(|job| job.parsed.message.as_slice())
        .collect();
    let signatures: Vec<Signature> = jobs.iter().map(|job| job.parsed.signature).collect();
    let verifying_keys: Vec<VerifyingKey> =
        jobs.iter().map(|job| job.parsed.verifying_key).collect();
    let batch_valid = ed25519_dalek::verify_batch(&messages, &signatures, &verifying_keys).is_ok();

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
