//! Wire-agnostic payment-channel voucher verification.
//!
//! A voucher authorizes a cumulative spend on a channel: the 48-byte Borsh
//! payload `channelId ‖ cumulativeAmount ‖ expiresAt` (see
//! [`crate::payment_channels::voucher_message_bytes`]) signed Ed25519 by the
//! channel's authorized signer. Shared by the MPP `session` intent and the x402
//! `batch-settlement` scheme.

use std::str::FromStr;

use solana_pubkey::Pubkey;

use crate::payment_channels::voucher_message_bytes;
use crate::{Error, Result};

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
    use ed25519_dalek::{Signature, VerifyingKey};

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
    let message = voucher_message_bytes(&channel, cumulative, expires_at)?;

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

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| Error::Other("Voucher signature verification failed".to_string()))
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
}
