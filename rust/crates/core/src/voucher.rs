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
/// that it has not expired.
///
/// - `channel_id`, `signature_b58`, `authorized_signer_b58` are base58.
/// - `now` is the current Unix time in seconds.
/// - A voucher with `expires_at <= now` is rejected as expired (so vouchers MUST
///   carry a future expiry; `0` is treated as already-expired).
pub fn verify_voucher_signature(
    channel_id: &str,
    cumulative: u64,
    expires_at: i64,
    signature_b58: &str,
    authorized_signer_b58: &str,
    now: i64,
) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey};

    if expires_at <= now {
        return Err(Error::Other("Voucher has expired".to_string()));
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
            verify_voucher_signature(&channel_b58, 1_000, 4_102_444_800, &sig, &signer, 1).is_ok()
        );
        // Wrong cumulative → signature no longer matches the message.
        assert!(
            verify_voucher_signature(&channel_b58, 2_000, 4_102_444_800, &sig, &signer, 1).is_err()
        );
        // Expired.
        assert!(verify_voucher_signature(&channel_b58, 1_000, 100, &sig, &signer, 200).is_err());
    }
}
