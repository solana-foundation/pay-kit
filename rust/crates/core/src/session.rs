//! Wire-agnostic payment-channel session logic shared by the MPP `session`
//! intent and the x402 `batch-settlement` scheme.
//!
//! [`accept_voucher`] is the server-side acceptance of a cumulative voucher:
//! signature + expiry + monotonicity + deposit-cap + idempotent-replay checks,
//! committed atomically against a [`ChannelStore`]. Both protocol crates map
//! their own wire voucher type onto this.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::store::{ChannelState, ChannelStore, StoreError};
use crate::voucher::verify_voucher_signature;
use crate::{Error, Result};

fn store_err(e: StoreError) -> Error {
    Error::Other(format!("store error: {e}"))
}

/// Outcome of accepting a cumulative voucher.
///
/// Carries the post-acceptance watermark plus enough signal for callers to
/// distinguish a fresh charge from an idempotent replay — so a replay (delta 0)
/// is never mistaken for a fresh paid serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoucherAcceptance {
    /// The channel's cumulative watermark after acceptance.
    pub cumulative: u64,
    /// Amount newly charged by this voucher (`cumulative - prior watermark`).
    /// `0` for an exact idempotent replay of the highest voucher.
    pub charged: u64,
    /// `true` when this was an exact replay of the highest accepted voucher
    /// (same cumulative AND same signature) — no new value was charged.
    pub replay: bool,
}

/// Accept a cumulative voucher against the channel's stored state.
///
/// Verifies the Ed25519 signature against the channel's `authorized_signer`,
/// enforces monotonicity (`new_cumulative > current`), the deposit cap, the
/// optional `min_voucher_delta`, and the expiry (`settlement_window` — see
/// [`crate::voucher::verify_voucher_signature`]), then atomically advances the
/// watermark and records the voucher signature/expiry.
///
/// The cumulative amount doubles as the channel's nonce: a new charge requires a
/// STRICT increment (`new_cumulative > current`). An exact replay of the highest
/// voucher (same cumulative AND same signature) is accepted idempotently as a
/// no-charge ([`VoucherAcceptance::replay`] = `true`, `charged` = `0`); any other
/// non-increasing or differently-signed voucher is rejected.
// Each parameter is an independent part of the voucher-acceptance contract
// (channel binding, the signed cumulative/expiry/signature, the clock, and the
// two policy knobs); bundling them into a struct would only obscure the call
// sites, so the arity is inherent.
#[allow(clippy::too_many_arguments)]
pub async fn accept_voucher(
    store: &dyn ChannelStore,
    channel_id: &str,
    new_cumulative: u64,
    expires_at: i64,
    signature_b58: &str,
    now: i64,
    min_voucher_delta: u64,
    settlement_window: i64,
) -> Result<VoucherAcceptance> {
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

    // Idempotent replay: same cumulative AND same signature as the latest
    // voucher. Treated as a no-charge no-op (the route was already paid for) —
    // never a fresh serve.
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
            settlement_window,
        )?;
        return Ok(VoucherAcceptance {
            cumulative: new_cumulative,
            charged: 0,
            replay: true,
        });
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
        settlement_window,
    )?;

    let prior_cumulative = state.cumulative;
    let sig = signature_b58.to_string();
    // The authoritative replay decision is made under the store lock: if another
    // writer landed this exact voucher first, the in-lock branch below treats it
    // as a replay. Capturing it here (rather than comparing the pre-lock snapshot)
    // ensures `charged`/`replay` are correct under concurrency, so x402 batch
    // cannot serve the same paid request twice.
    let replayed = Arc::new(AtomicBool::new(false));
    let replayed_cl = Arc::clone(&replayed);
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
                    replayed_cl.store(true, Ordering::SeqCst);
                    return Ok(state);
                }
                if new_cumulative <= state.cumulative {
                    return Err(StoreError::Internal(
                        "Concurrent update: watermark advanced".to_string(),
                    ));
                }
                // Set on every committing run so a retried closure (e.g. a
                // CAS-based store) reflects the final decision, not an earlier one.
                replayed_cl.store(false, Ordering::SeqCst);
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

    let was_replay = replayed.load(Ordering::SeqCst);
    Ok(VoucherAcceptance {
        cumulative: new_state.cumulative,
        charged: if was_replay {
            0
        } else {
            new_state.cumulative.saturating_sub(prior_cumulative)
        },
        replay: was_replay,
    })
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
        // First charge: strict increment from 0 → charged 100, not a replay.
        let first = accept_voucher(&store, &channel_b58, 100, exp, &sig1, 1, 0, 0)
            .await
            .unwrap();
        assert_eq!(first.cumulative, 100);
        assert_eq!(first.charged, 100);
        assert!(!first.replay);
        // Idempotent replay of the latest voucher: no charge, flagged as replay.
        let replay = accept_voucher(&store, &channel_b58, 100, exp, &sig1, 1, 0, 0)
            .await
            .unwrap();
        assert_eq!(replay.cumulative, 100);
        assert_eq!(replay.charged, 0);
        assert!(replay.replay);
        // Advance.
        let sig2 = sign(&channel, 250, exp, &sk);
        let advanced = accept_voucher(&store, &channel_b58, 250, exp, &sig2, 1, 0, 0)
            .await
            .unwrap();
        assert_eq!(advanced.cumulative, 250);
        assert_eq!(advanced.charged, 150);
        assert!(!advanced.replay);
        // Regression rejected.
        let sig_lo = sign(&channel, 200, exp, &sk);
        assert!(
            accept_voucher(&store, &channel_b58, 200, exp, &sig_lo, 1, 0, 0)
                .await
                .is_err()
        );
        // Over deposit rejected.
        let sig_hi = sign(&channel, 2_000_000, exp, &sk);
        assert!(
            accept_voucher(&store, &channel_b58, 2_000_000, exp, &sig_hi, 1, 0, 0)
                .await
                .is_err()
        );
    }

    fn seeded(channel_b58: &str, signer: &str, deposit: u64) -> ChannelState {
        ChannelState {
            channel_id: channel_b58.to_string(),
            authorized_signer: signer.to_string(),
            deposit,
            cumulative: 0,
            finalized: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            operator: None,
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
        }
    }

    // FIX #8: a different signature at the SAME cumulative as the watermark is
    // NOT an idempotent replay — it must be rejected (not advance, not serve).
    #[tokio::test]
    async fn different_signature_at_watermark_is_rejected() {
        let (store, channel_b58, signer, sk, channel) = setup();
        store
            .put_channel(&channel_b58, seeded(&channel_b58, &signer, 1_000_000))
            .await
            .unwrap();
        let exp = 4_102_444_800;
        let sig1 = sign(&channel, 100, exp, &sk);
        accept_voucher(&store, &channel_b58, 100, exp, &sig1, 1, 0, 0)
            .await
            .unwrap();

        // A second, distinct signature over the same cumulative. The on-chain
        // message commits (channel, cumulative, expires_at) so a different
        // expiry yields a valid-but-different signature at the same cumulative.
        let sig_other = sign(&channel, 100, exp + 1, &sk);
        assert_ne!(sig1, sig_other);
        let err = accept_voucher(&store, &channel_b58, 100, exp + 1, &sig_other, 1, 0, 0)
            .await
            .unwrap_err();
        // Rejected as non-monotonic (it is not the exact replay of the latest).
        assert!(
            err.to_string().contains("must exceed watermark"),
            "expected watermark error, got: {err}"
        );
        // Watermark untouched.
        let state = store.get_channel(&channel_b58).await.unwrap().unwrap();
        assert_eq!(state.cumulative, 100);
        assert_eq!(state.highest_voucher_signature.as_deref(), Some(&*sig1));
    }

    // FIX #9a: a voucher with expires_at == 0 (never-expires) is accepted.
    #[tokio::test]
    async fn zero_expiry_voucher_is_accepted() {
        let (store, channel_b58, signer, sk, channel) = setup();
        store
            .put_channel(&channel_b58, seeded(&channel_b58, &signer, 1_000_000))
            .await
            .unwrap();
        let sig = sign(&channel, 100, 0, &sk);
        let out = accept_voucher(&store, &channel_b58, 100, 0, &sig, 1_000, 0, 900)
            .await
            .unwrap();
        assert_eq!(out.cumulative, 100);
        assert_eq!(out.charged, 100);
    }

    // FIX #9b: a non-zero expiry that does not outlast the settlement window is
    // rejected by acceptance.
    #[tokio::test]
    async fn expiry_within_settlement_window_is_rejected() {
        let (store, channel_b58, signer, sk, channel) = setup();
        store
            .put_channel(&channel_b58, seeded(&channel_b58, &signer, 1_000_000))
            .await
            .unwrap();
        let now = 1_000;
        let window = 900;
        // expires_at inside the window → rejected.
        let exp = now + window - 1;
        let sig = sign(&channel, 100, exp, &sk);
        let err = accept_voucher(&store, &channel_b58, 100, exp, &sig, now, 0, window)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("settlement window"),
            "expected settlement-window error, got: {err}"
        );
        // Channel watermark untouched.
        let state = store.get_channel(&channel_b58).await.unwrap().unwrap();
        assert_eq!(state.cumulative, 0);
    }
}
