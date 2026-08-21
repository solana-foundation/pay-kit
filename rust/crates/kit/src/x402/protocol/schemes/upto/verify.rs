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

/// Verify an `upto` payload against the route's pinned requirements.
///
/// `receiver_authorizer` is the server's voucher signer key (base58); `now` is
/// the current Unix time in seconds. Returns `Ok(())` when the authorization is
/// valid for the ceiling — the actual charge is validated later by
/// [`assert_settlement_within_ceiling`].
pub fn verify_upto_payload(
    payload: &UptoPayload,
    requirements: &UptoRequirements,
    receiver_authorizer: &str,
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

    if payload.authorized_signer != receiver_authorizer {
        return Err(Error::Other(
            "voucher authorized_signer must be the advertised receiver authorizer".to_string(),
        ));
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
    use crate::x402::protocol::schemes::upto::types::{UptoExtra, UptoRequirements};

    const RECEIVER_AUTHORIZER: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

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
            },
        }
    }

    fn payload() -> UptoPayload {
        UptoPayload {
            from: "Payer1111111111111111111111111111111111111".to_string(),
            max_amount: "1000000".to_string(),
            expires_at: 4_102_444_800,
            valid_after: 0,
            nonce: "n-1".to_string(),
            channel_id: "Chan1111111111111111111111111111111111111".to_string(),
            deposit: "1000000".to_string(),
            authorized_signer: RECEIVER_AUTHORIZER.to_string(),
            open_slot: "55555".to_string(),
            open_transaction: Some("tx".to_string()),
        }
    }

    #[test]
    fn accepts_valid_payload() {
        assert!(
            verify_upto_payload(&payload(), &requirements(), RECEIVER_AUTHORIZER, 1000).is_ok()
        );
    }

    #[test]
    fn rejects_max_mismatch() {
        let mut p = payload();
        p.max_amount = "999999".to_string();
        assert!(matches!(
            verify_upto_payload(&p, &requirements(), RECEIVER_AUTHORIZER, 1000),
            Err(Error::AmountMismatch { .. })
        ));
    }

    #[test]
    fn rejects_deposit_mismatch() {
        let mut p = payload();
        p.deposit = "500000".to_string();
        assert!(verify_upto_payload(&p, &requirements(), RECEIVER_AUTHORIZER, 1000).is_err());

        let mut p = payload();
        p.deposit = "1000001".to_string();
        assert!(verify_upto_payload(&p, &requirements(), RECEIVER_AUTHORIZER, 1000).is_err());
    }

    #[test]
    fn rejects_deposit_above_ceiling() {
        // `deposit == maxAmount` is required: a larger deposit would let the
        // operator settle above the authorized ceiling on-chain.
        let mut p = payload();
        p.deposit = "2000000".to_string();
        assert!(verify_upto_payload(&p, &requirements(), RECEIVER_AUTHORIZER, 1000).is_err());
    }

    #[test]
    fn rejects_expired_and_not_yet_active() {
        let mut p = payload();
        p.expires_at = 500;
        assert!(verify_upto_payload(&p, &requirements(), RECEIVER_AUTHORIZER, 1000).is_err());

        let mut p = payload();
        p.expires_at = 1000;
        assert!(verify_upto_payload(&p, &requirements(), RECEIVER_AUTHORIZER, 1000).is_err());

        let mut p = payload();
        p.valid_after = 2000;
        assert!(verify_upto_payload(&p, &requirements(), RECEIVER_AUTHORIZER, 1000).is_err());
    }

    #[test]
    fn rejects_wrong_receiver_authorizer() {
        let mut p = payload();
        p.authorized_signer = "Payer1111111111111111111111111111111111111".to_string();
        assert!(verify_upto_payload(&p, &requirements(), RECEIVER_AUTHORIZER, 1000).is_err());
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
