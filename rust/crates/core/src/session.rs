//! Wire-agnostic payment-channel session logic shared by the MPP `session`
//! intent and the x402 `batch-settlement` scheme.
//!
//! [`accept_voucher`] is the server-side acceptance of a cumulative voucher:
//! signature + expiry + monotonicity + deposit-cap + idempotent-replay checks,
//! committed atomically against a [`ChannelStore`]. Both protocol crates map
//! their own wire voucher type onto this.

use crate::store::{ChannelState, ChannelStore, StoreError};
use crate::voucher::verify_voucher_signature;
use crate::{Error, Result};

fn store_err(e: StoreError) -> Error {
    Error::Other(format!("store error: {e}"))
}

/// Accept a cumulative voucher against the channel's stored state.
///
/// Verifies the Ed25519 signature against the channel's `authorized_signer`,
/// enforces monotonicity (`new_cumulative > current`), the deposit cap, and the
/// optional `min_voucher_delta`, then atomically advances the watermark and
/// records the voucher signature/expiry. An exact replay of the highest voucher
/// (same cumulative + signature) is accepted idempotently. Returns the channel's
/// cumulative after acceptance.
pub async fn accept_voucher(
    store: &dyn ChannelStore,
    channel_id: &str,
    new_cumulative: u64,
    expires_at: i64,
    signature_b58: &str,
    now: i64,
    min_voucher_delta: u64,
) -> Result<u64> {
    // Read current state (for authorized_signer, watermark, deposit).
    let state = store
        .get_channel(channel_id)
        .await
        .map_err(store_err)?
        .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;

    if state.finalized {
        return Err(Error::Other("Channel is already finalized".to_string()));
    }
    if state.close_requested_at.is_some() {
        return Err(Error::Other(
            "Channel close is pending — no further vouchers accepted".to_string(),
        ));
    }

    // Idempotent replay: same cumulative AND same signature as the latest voucher.
    if new_cumulative == state.cumulative
        && state.highest_voucher_signature.as_deref() == Some(signature_b58)
    {
        verify_voucher_signature(
            channel_id,
            new_cumulative,
            expires_at,
            signature_b58,
            &state.authorized_signer,
            now,
        )?;
        return Ok(new_cumulative);
    }

    if new_cumulative <= state.cumulative {
        return Err(Error::Other(format!(
            "Voucher cumulative {new_cumulative} must exceed watermark {}",
            state.cumulative
        )));
    }
    if new_cumulative > state.deposit {
        return Err(Error::Other(format!(
            "Voucher cumulative {new_cumulative} exceeds deposit {}",
            state.deposit
        )));
    }

    let delta = new_cumulative - state.cumulative;
    if min_voucher_delta > 0 && delta < min_voucher_delta {
        return Err(Error::Other(format!(
            "Voucher delta {delta} is below minimum {min_voucher_delta}"
        )));
    }

    // Verify the signature (expensive) before touching the store.
    verify_voucher_signature(
        channel_id,
        new_cumulative,
        expires_at,
        signature_b58,
        &state.authorized_signer,
        now,
    )?;

    let sig = signature_b58.to_string();
    let new_state = store
        .update_channel(
            channel_id,
            Box::new(move |state_opt| {
                let state = state_opt
                    .ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?;
                if state.finalized {
                    return Err(StoreError::Internal(
                        "Channel is already finalized".to_string(),
                    ));
                }
                if state.close_requested_at.is_some() {
                    return Err(StoreError::Internal(
                        "Channel close is pending — no further vouchers accepted".to_string(),
                    ));
                }
                if new_cumulative == state.cumulative
                    && state.highest_voucher_signature.as_deref() == Some(&sig)
                {
                    return Ok(state);
                }
                if new_cumulative <= state.cumulative {
                    return Err(StoreError::Internal(
                        "Concurrent update: watermark advanced".to_string(),
                    ));
                }
                Ok(ChannelState {
                    cumulative: new_cumulative,
                    highest_voucher_signature: Some(sig),
                    highest_voucher_expires_at: Some(expires_at),
                    ..state
                })
            }),
        )
        .await
        .map_err(store_err)?;

    Ok(new_state.cumulative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payment_channels::voucher_message_bytes;
    use crate::store::MemoryChannelStore;
    use ed25519_dalek::{Signer, SigningKey};
    use solana_pubkey::Pubkey;

    fn setup() -> (MemoryChannelStore, String, String, SigningKey, Pubkey) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let signer = bs58::encode(sk.verifying_key().as_bytes()).into_string();
        let channel = Pubkey::new_unique();
        let channel_b58 = bs58::encode(channel.as_ref()).into_string();
        let store = MemoryChannelStore::new();
        (store, channel_b58, signer, sk, channel)
    }

    fn sign(channel: &Pubkey, cumulative: u64, expires_at: i64, sk: &SigningKey) -> String {
        let msg = voucher_message_bytes(channel, cumulative, expires_at).unwrap();
        bs58::encode(sk.sign(&msg).to_bytes()).into_string()
    }

    #[tokio::test]
    async fn accepts_monotonic_vouchers_and_rejects_regressions() {
        let (store, channel_b58, signer, sk, channel) = setup();
        store
            .put_channel(
                &channel_b58,
                ChannelState {
                    channel_id: channel_b58.clone(),
                    authorized_signer: signer.clone(),
                    deposit: 1_000_000,
                    cumulative: 0,
                    finalized: false,
                    highest_voucher_signature: None,
                    highest_voucher_expires_at: None,
                    close_requested_at: None,
                    operator: None,
                    next_delivery_sequence: 0,
                    pending_deliveries: vec![],
                    committed_deliveries: vec![],
                },
            )
            .await
            .unwrap();

        let exp = 4_102_444_800;
        let sig1 = sign(&channel, 100, exp, &sk);
        assert_eq!(
            accept_voucher(&store, &channel_b58, 100, exp, &sig1, 1, 0)
                .await
                .unwrap(),
            100
        );
        // Idempotent replay of the latest voucher.
        assert_eq!(
            accept_voucher(&store, &channel_b58, 100, exp, &sig1, 1, 0)
                .await
                .unwrap(),
            100
        );
        // Advance.
        let sig2 = sign(&channel, 250, exp, &sk);
        assert_eq!(
            accept_voucher(&store, &channel_b58, 250, exp, &sig2, 1, 0)
                .await
                .unwrap(),
            250
        );
        // Regression rejected.
        let sig_lo = sign(&channel, 200, exp, &sk);
        assert!(
            accept_voucher(&store, &channel_b58, 200, exp, &sig_lo, 1, 0)
                .await
                .is_err()
        );
        // Over deposit rejected.
        let sig_hi = sign(&channel, 2_000_000, exp, &sk);
        assert!(
            accept_voucher(&store, &channel_b58, 2_000_000, exp, &sig_hi, 1, 0)
                .await
                .is_err()
        );
    }
}
