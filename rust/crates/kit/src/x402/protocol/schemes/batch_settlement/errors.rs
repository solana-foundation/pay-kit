//! Machine-readable failure codes for the SVM `batch-settlement` scheme.
//!
//! These are the values a facilitator puts in `VerifyResponse.invalidReason` or
//! `SettlementResponse.errorReason`, and a resource server puts in a corrective
//! `PaymentRequired.error`. They are wire strings shared with the TypeScript
//! implementation, so the constants below are the single source of truth.
//!
//! See `specs/schemes/batch-settlement/scheme_batch_settlement_svm.md` §7.

/// Payload `type` is not valid for the current verify or settle operation.
pub const INVALID_PAYLOAD_TYPE: &str = "invalid_batch_settlement_svm_payload_type";

/// `extra.paymentFlow` is present and is not `"authorization"`.
pub const INVALID_PAYMENT_FLOW: &str = "invalid_batch_settlement_svm_payment_flow";

/// `extra.tokenProgram` is not a supported SPL token program, or does not own
/// the selected mint.
pub const INVALID_TOKEN_PROGRAM: &str = "invalid_batch_settlement_svm_token_program";

/// Voucher signature is invalid, or `channelConfig.payerAuthorizer` does not
/// match the channel `authorized_signer`.
pub const INVALID_VOUCHER_SIGNATURE: &str = "invalid_batch_settlement_svm_voucher_signature";

/// `voucher.channelId` does not match the canonical PDA derivation.
pub const INVALID_CHANNEL_ID_MISMATCH: &str = "invalid_batch_settlement_svm_channel_id_mismatch";

/// Channel `payee` or `rent_payer` does not match `extra.feePayer`.
pub const INVALID_FEE_PAYER_MISMATCH: &str = "invalid_batch_settlement_svm_fee_payer_mismatch";

/// `channelConfig.receiverAuthorizer` does not match `extra.receiverAuthorizer`
/// or the facilitator's trusted server binding.
pub const INVALID_RECEIVER_AUTHORIZER_MISMATCH: &str =
    "invalid_batch_settlement_svm_receiver_authorizer_mismatch";

/// Close authorization is malformed, expired, signed by the wrong receiver
/// authorizer, or does not bind the exact cooperative-close request.
pub const INVALID_CLOSE_AUTHORIZATION: &str = "invalid_batch_settlement_svm_close_authorization";

/// The `refund` payload carries an `amount`; this scheme returns only the full
/// unused escrow.
pub const INVALID_CLOSE_AMOUNT_UNSUPPORTED: &str =
    "invalid_batch_settlement_svm_close_amount_unsupported";

/// The channel cannot be closed, or an optional cooperative voucher does not
/// equal server state / is behind the channel's onchain `settled` value.
pub const INVALID_CLOSE_STATE: &str = "invalid_batch_settlement_svm_close_state";

/// Channel grace period does not match `extra.withdrawDelay`.
pub const INVALID_WITHDRAW_DELAY_MISMATCH: &str =
    "invalid_batch_settlement_svm_withdraw_delay_mismatch";

/// `withdrawDelay` is outside `900..=2592000` seconds, or is shorter than
/// `maxTimeoutSeconds`.
pub const INVALID_WITHDRAW_DELAY_OUT_OF_RANGE: &str =
    "invalid_batch_settlement_svm_withdraw_delay_out_of_range";

/// Corrective 402: the client's cumulative voucher does not match server state.
pub const INVALID_CUMULATIVE_AMOUNT_MISMATCH: &str =
    "invalid_batch_settlement_svm_cumulative_amount_mismatch";

/// Voucher `maxClaimableAmount` exceeds the escrowed deposit.
pub const INVALID_CUMULATIVE_EXCEEDS_DEPOSIT: &str =
    "invalid_batch_settlement_svm_cumulative_exceeds_deposit";

/// Voucher `expiresAt` is nonzero; this scheme requires non-expiring vouchers.
pub const INVALID_VOUCHER_EXPIRY: &str = "invalid_batch_settlement_svm_voucher_expiry";

/// The client-supplied setup transaction fails the sponsor safety checks.
pub const INVALID_SETUP_TRANSACTION: &str = "invalid_batch_settlement_svm_setup_transaction";

/// Setup or settlement-readiness simulation failed before accepting the deposit.
pub const INVALID_SETTLEMENT_SIMULATION: &str =
    "invalid_batch_settlement_svm_settlement_simulation";

/// Confirmed channel state does not match the payload and challenge-bound
/// requirements.
pub const INVALID_CHANNEL_STATE: &str = "invalid_batch_settlement_svm_channel_state";

/// Refund transaction is not a valid payer-signed `request_close` for the
/// derived channel, or contains an unauthorized instruction.
pub const INVALID_REFUND_TRANSACTION: &str = "invalid_batch_settlement_svm_refund_transaction";

/// The same client-supplied setup or refund transaction is already settling.
/// A standard x402 code rather than a scheme-specific one.
pub const DUPLICATE_SETTLEMENT: &str = "duplicate_settlement";

/// Every scheme code, for exhaustiveness checks and error classification.
pub const ALL_CODES: &[&str] = &[
    INVALID_PAYLOAD_TYPE,
    INVALID_PAYMENT_FLOW,
    INVALID_TOKEN_PROGRAM,
    INVALID_VOUCHER_SIGNATURE,
    INVALID_CHANNEL_ID_MISMATCH,
    INVALID_FEE_PAYER_MISMATCH,
    INVALID_RECEIVER_AUTHORIZER_MISMATCH,
    INVALID_CLOSE_AUTHORIZATION,
    INVALID_CLOSE_AMOUNT_UNSUPPORTED,
    INVALID_CLOSE_STATE,
    INVALID_WITHDRAW_DELAY_MISMATCH,
    INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
    INVALID_CUMULATIVE_AMOUNT_MISMATCH,
    INVALID_CUMULATIVE_EXCEEDS_DEPOSIT,
    INVALID_VOUCHER_EXPIRY,
    INVALID_SETUP_TRANSACTION,
    INVALID_SETTLEMENT_SIMULATION,
    INVALID_CHANNEL_STATE,
    INVALID_REFUND_TRANSACTION,
    DUPLICATE_SETTLEMENT,
];

/// A `batch-settlement` failure carrying the wire code the counterparty needs
/// plus a human-readable detail for logs.
///
/// The scheme's failures are reported to the client as an `invalidReason` /
/// `errorReason` string, so errors are tagged at the point they are raised
/// rather than reverse-engineered from a message later.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct BatchError {
    /// The wire code (one of the constants in this module).
    pub code: &'static str,
    /// Human-readable detail; never sent as the machine-readable reason.
    pub detail: String,
}

impl BatchError {
    /// Build a failure with `code` and a human-readable `detail`.
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl From<BatchError> for crate::x402::error::Error {
    fn from(err: BatchError) -> Self {
        crate::x402::error::Error::Other(err.to_string())
    }
}

/// Recover the scheme code from an error message produced by [`BatchError`],
/// falling back to `transaction_failed` for anything unrecognized.
///
/// The server composes checks that return the crate-wide [`crate::x402::error::Error`],
/// which erases the code into a string; this maps it back for the wire without
/// forcing every intermediate helper to thread a typed error.
pub fn classify(message: &str) -> &'static str {
    ALL_CODES
        .iter()
        .find(|code| message.contains(*code))
        .copied()
        .unwrap_or("transaction_failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scheme_code_carries_the_spec_prefix() {
        for code in ALL_CODES {
            assert!(
                code.starts_with("invalid_batch_settlement_svm_") || *code == DUPLICATE_SETTLEMENT,
                "unexpected code shape: {code}"
            );
        }
        // No duplicates: `classify` returns the first match, so a repeated
        // constant would silently shadow another code.
        let mut sorted = ALL_CODES.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "ALL_CODES contains duplicates");
    }

    #[test]
    fn classify_recovers_the_code_from_a_formatted_error() {
        let err = BatchError::new(INVALID_VOUCHER_EXPIRY, "expiresAt was 42");
        assert_eq!(classify(&err.to_string()), INVALID_VOUCHER_EXPIRY);
        assert!(err.to_string().contains("expiresAt was 42"));
        assert_eq!(classify("something else entirely"), "transaction_failed");
    }
}
