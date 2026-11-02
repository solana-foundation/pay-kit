//! Pure (no-RPC) verification for the x402 `upto` scheme.
//!
//! These checks run at the envelope level: amounts, time window, advertised
//! receiver-authorizer binding. The on-chain binding (channel
//! deposit/payee/mint/status) is confirmed by the server after it broadcasts
//! and confirms the `open` transaction — see `server::upto`.

use crate::x402::error::Error;

use super::types::{UptoPayload, UptoRequirements};

/// Scheme-specific error string for an over-ceiling settlement.
pub const ERR_SETTLEMENT_EXCEEDS_AMOUNT: &str =
    "invalid_upto_svm_payload_settlement_exceeds_amount";

/// `maxTimeoutSeconds` or the remaining `expiresAt - now` exceeds the
/// facilitator's `maxChannelLifetimeSecs`.
pub const ERR_CHANNEL_LIFETIME_EXCEEDED: &str =
    "invalid_upto_svm_payload_channel_lifetime_exceeded";

/// `expiresAt` is later than `now + maxTimeoutSeconds` plus clock skew.
pub const ERR_EXPIRES_AT_MISMATCH: &str = "invalid_upto_svm_payload_expires_at_mismatch";

/// Clock skew allowed on `expiresAt` against `now + maxTimeoutSeconds` and
/// `now + maxChannelLifetimeSecs` (Phase 3 step 7 “plus clock skew”).
pub const EXPIRES_AT_CLOCK_SKEW_SECONDS: i64 = 60;

/// The facilitator's `maxChannelLifetimeSecs`: the longest a channel it
/// sponsors may stay open before abandon-close can reclaim the rent. Not
/// zero, by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxChannelLifetime(std::num::NonZeroU64);

impl MaxChannelLifetime {
    /// One hour, the reference facilitator's default.
    pub const ONE_HOUR: Self = match std::num::NonZeroU64::new(3600) {
        Some(n) => Self(n),
        None => unreachable!(),
    };

    /// `None` for zero, which would admit no channel at all.
    pub fn from_secs(seconds: u64) -> Option<Self> {
        std::num::NonZeroU64::new(seconds).map(Self)
    }

    pub fn secs(self) -> u64 {
        self.0.get()
    }
}

/// Verify an `upto` payload against the route's pinned requirements.
///
/// `receiver_authorizer` is the server's voucher signer key (base58);
/// `max_lifetime` the facilitator's `maxChannelLifetimeSecs`; `now` is the
/// current Unix time in seconds. Returns `Ok(())` when the authorization is
/// valid for the ceiling — the actual charge is validated later by
/// [`assert_settlement_within_ceiling`].
pub fn verify_upto_payload(
    payload: &UptoPayload,
    requirements: &UptoRequirements,
    receiver_authorizer: &str,
    max_lifetime: MaxChannelLifetime,
    now: i64,
) -> Result<(), Error> {
    let max = requirements.max_amount()?;
    let signed_max = payload.max_amount()?;
    if signed_max != max {
        return Err(Error::AmountMismatch {
            expected: max.to_string(),
            actual: signed_max.to_string(),
        });
    }

    let deposit = payload.deposit()?;
    if deposit != max {
        return Err(Error::Other(format!(
            "channel deposit {deposit} != authorized maximum {max}: the deposit is the \
             enforced ceiling and `topUp` can raise it, so it must equal the authorized \
             amount exactly, not merely cover it"
        )));
    }

    if now < payload.valid_after {
        return Err(Error::Other(format!(
            "authorization not yet active (validAfter {} > now {now})",
            payload.valid_after
        )));
    }
    if payload.expires_at == 0 || now >= payload.expires_at {
        return Err(Error::Other(format!(
            "authorization expired (expiresAt {} < now {now})",
            payload.expires_at
        )));
    }

    verify_upto_lifetime(payload, requirements, max_lifetime, now)?;

    if payload.authorized_signer != receiver_authorizer {
        return Err(Error::Other(
            "voucher authorized_signer must be the advertised receiver authorizer".to_string(),
        ));
    }

    Ok(())
}

/// Phase 3 step 7, second half: the channel cannot outlive the
/// facilitator's lifetime ceiling, and `expiresAt` stays inside the
/// challenge's completion window. Abandon-close may not run before
/// `expiresAt`, so an unbounded deadline would lock the sponsor's rent.
fn verify_upto_lifetime(
    payload: &UptoPayload,
    requirements: &UptoRequirements,
    max_lifetime: MaxChannelLifetime,
    now: i64,
) -> Result<(), Error> {
    let lifetime = max_lifetime.secs();
    if requirements.max_timeout_seconds > lifetime {
        return Err(Error::Other(format!(
            "{ERR_CHANNEL_LIFETIME_EXCEEDED}: maxTimeoutSeconds {} exceeds maxChannelLifetimeSecs {lifetime}",
            requirements.max_timeout_seconds
        )));
    }
    let secs = |s: u64| i64::try_from(s).unwrap_or(i64::MAX);
    let remaining = payload.expires_at.saturating_sub(now);
    if remaining > secs(lifetime).saturating_add(EXPIRES_AT_CLOCK_SKEW_SECONDS) {
        return Err(Error::Other(format!(
            "{ERR_CHANNEL_LIFETIME_EXCEEDED}: expiresAt is {remaining}s away, over maxChannelLifetimeSecs {lifetime}"
        )));
    }
    let window_end = now
        .saturating_add(secs(requirements.max_timeout_seconds))
        .saturating_add(EXPIRES_AT_CLOCK_SKEW_SECONDS);
    if payload.expires_at > window_end {
        return Err(Error::Other(format!(
            "{ERR_EXPIRES_AT_MISMATCH}: expiresAt {} is later than now + maxTimeoutSeconds ({}) plus {EXPIRES_AT_CLOCK_SKEW_SECONDS}s skew",
            payload.expires_at, requirements.max_timeout_seconds
        )));
    }
    Ok(())
}

/// Enforce `actual ≤ max` at settlement.
pub fn assert_settlement_within_ceiling(actual: u64, max: u64) -> Result<(), Error> {
    if actual > max {
        return Err(Error::Other(ERR_SETTLEMENT_EXCEEDS_AMOUNT.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::protocol::schemes::upto::types::{
        Slot, UptoExtra, UptoNonce, UptoRequirements,
    };

    const RECEIVER_AUTHORIZER: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
    const NOW: i64 = 1000;

    fn lifetime(secs: u64) -> MaxChannelLifetime {
        MaxChannelLifetime::from_secs(secs).unwrap()
    }

    fn verify(p: &UptoPayload, r: &UptoRequirements) -> Result<(), Error> {
        verify_upto_payload(p, r, RECEIVER_AUTHORIZER, lifetime(3600), NOW)
    }

    fn requirements() -> UptoRequirements {
        UptoRequirements {
            scheme: "upto".to_string(),
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            amount: "1000000".to_string(),
            asset: "USDC".to_string(),
            pay_to: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_timeout_seconds: 300,
            extra: UptoExtra {
                token_program: None,
                fee_payer: RECEIVER_AUTHORIZER.to_string(),
                receiver_authorizer: RECEIVER_AUTHORIZER.to_string(),
                withdraw_delay: 900,
                recent_blockhash: None,
                last_valid_block_height: None,
                recent_slot: None,
                valid_after: None,
                memo: None,
                transaction_versions: None,
            },
        }
    }

    fn payload() -> UptoPayload {
        UptoPayload {
            from: "Payer1111111111111111111111111111111111111".to_string(),
            max_amount: "1000000".to_string(),
            expires_at: NOW + 300,
            valid_after: 0,
            nonce: UptoNonce::new(7),
            channel_id: "Chan1111111111111111111111111111111111111".to_string(),
            deposit: "1000000".to_string(),
            authorized_signer: RECEIVER_AUTHORIZER.to_string(),
            open_slot: Slot::new(55555),
            open_transaction: Some("tx".to_string()),
        }
    }

    #[test]
    fn accepts_valid_payload() {
        assert!(verify(&payload(), &requirements()).is_ok());
    }

    #[test]
    fn rejects_max_mismatch() {
        let mut p = payload();
        p.max_amount = "999999".to_string();
        assert!(matches!(
            verify(&p, &requirements()),
            Err(Error::AmountMismatch { .. })
        ));
    }

    #[test]
    fn rejects_deposit_mismatch() {
        let mut p = payload();
        p.deposit = "500000".to_string();
        assert!(verify(&p, &requirements()).is_err());

        let mut p = payload();
        p.deposit = "1000001".to_string();
        assert!(verify(&p, &requirements()).is_err());
    }

    #[test]
    fn rejects_deposit_above_ceiling() {
        // `deposit == maxAmount` is required: a larger deposit would let the
        // operator settle above the authorized ceiling on-chain.
        let mut p = payload();
        p.deposit = "2000000".to_string();
        assert!(verify(&p, &requirements()).is_err());
    }

    #[test]
    fn rejects_expired_and_not_yet_active() {
        let mut p = payload();
        p.expires_at = 500;
        assert!(verify(&p, &requirements()).is_err());

        let mut p = payload();
        p.expires_at = NOW;
        assert!(verify(&p, &requirements()).is_err());

        let mut p = payload();
        p.valid_after = 2000;
        assert!(verify(&p, &requirements()).is_err());
    }

    #[test]
    fn rejects_wrong_receiver_authorizer() {
        let mut p = payload();
        p.authorized_signer = "Payer1111111111111111111111111111111111111".to_string();
        assert!(verify(&p, &requirements()).is_err());
    }

    #[test]
    fn expires_at_is_bounded_by_the_completion_window() {
        // At the window edge plus the allowed skew: accepted.
        let mut p = payload();
        p.expires_at = NOW + 300 + EXPIRES_AT_CLOCK_SKEW_SECONDS;
        assert!(verify(&p, &requirements()).is_ok());
        // One second later: refused even though the lifetime allows it.
        p.expires_at += 1;
        let err = verify_upto_payload(
            &p,
            &requirements(),
            RECEIVER_AUTHORIZER,
            lifetime(86_400),
            NOW,
        )
        .unwrap_err();
        assert!(err.to_string().contains(ERR_EXPIRES_AT_MISMATCH), "{err}");
    }

    #[test]
    fn the_channel_lifetime_bounds_timeout_and_expiry() {
        let mut long = requirements();
        long.max_timeout_seconds = 7200;
        let mut p = payload();
        let err = verify(&p, &long).unwrap_err();
        assert!(
            err.to_string().contains(ERR_CHANNEL_LIFETIME_EXCEEDED),
            "{err}"
        );

        p.expires_at = NOW + 86_400;
        let err = verify(&p, &requirements()).unwrap_err();
        assert!(
            err.to_string().contains(ERR_CHANNEL_LIFETIME_EXCEEDED),
            "{err}"
        );

        assert!(MaxChannelLifetime::from_secs(0).is_none());
    }

    #[test]
    fn settlement_ceiling_enforced() {
        assert!(assert_settlement_within_ceiling(0, 1_000_000).is_ok());
        assert!(assert_settlement_within_ceiling(999_999, 1_000_000).is_ok());
        assert!(assert_settlement_within_ceiling(1_000_000, 1_000_000).is_ok());
        let err = assert_settlement_within_ceiling(1_000_001, 1_000_000).unwrap_err();
        assert!(err.to_string().contains(ERR_SETTLEMENT_EXCEEDS_AMOUNT));
    }
}
