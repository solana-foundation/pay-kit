//! Pure (no-RPC) checks for the x402 `batch-settlement` scheme.
//!
//! Voucher acceptance against channel state (monotonicity, deposit cap, atomic
//! watermark advance) lives in `crate::core::session::accept_voucher`; the
//! channel binding (broadcast + on-chain state) is confirmed by the server. This
//! module holds the cheap, stateless checks.

use crate::x402::error::Error;

use super::types::{BatchVoucher, PROFILE_PAYMENT_CHANNEL};

/// Self-consistency check on a voucher: its Ed25519 signature verifies against
/// the `signer` it names, and it is not expired. `now` is current Unix seconds.
///
/// This is a cheap pre-filter; the authoritative binding (`signer ==
/// channel.authorized_signer`) and the settlement-window expiry check (a
/// non-zero expiry must outlast the channel's forced-close grace period) are
/// enforced by [`crate::core::session::accept_voucher`] against stored
/// channel state. This pre-filter only requires the voucher be unexpired
/// (settlement window `0`), since the channel grace period is not in scope here.
pub fn verify_batch_voucher(voucher: &BatchVoucher, now: i64) -> Result<(), Error> {
    let cumulative = voucher.cumulative()?;
    crate::core::voucher::verify_voucher_signature(
        &voucher.channel_id,
        cumulative,
        voucher.expires_at,
        &voucher.signature,
        &voucher.signer,
        now,
        0,
    )
    .map_err(Into::into)
}

/// Confirm a profile string is one the server advertised and that this crate
/// supports (`payment-channel`).
pub fn check_profile(profiles: &[String]) -> Result<(), Error> {
    if profiles.iter().any(|p| p == PROFILE_PAYMENT_CHANNEL) {
        Ok(())
    } else {
        Err(Error::Other(
            "batch-settlement requires the payment-channel profile".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use solana_pubkey::Pubkey;

    #[test]
    fn verifies_a_self_consistent_voucher() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let channel = Pubkey::new_unique();
        let channel_b58 = bs58::encode(channel.as_ref()).into_string();
        let signer = bs58::encode(sk.verifying_key().as_bytes()).into_string();
        let msg =
            crate::core::payment_channels::voucher_message_bytes(&channel, 500, 4_102_444_800)
                .unwrap();
        let sig = bs58::encode(sk.sign(&msg).to_bytes()).into_string();

        let voucher = BatchVoucher {
            channel_id: channel_b58,
            cumulative_amount: "500".to_string(),
            expires_at: 4_102_444_800,
            signer,
            signature: sig,
        };
        assert!(verify_batch_voucher(&voucher, 1).is_ok());

        // Tampered cumulative → signature mismatch.
        let mut bad = voucher.clone();
        bad.cumulative_amount = "600".to_string();
        assert!(verify_batch_voucher(&bad, 1).is_err());
    }

    #[test]
    fn profile_check() {
        assert!(check_profile(&[PROFILE_PAYMENT_CHANNEL.to_string()]).is_ok());
        assert!(check_profile(&["permit".to_string()]).is_err());
    }
}
