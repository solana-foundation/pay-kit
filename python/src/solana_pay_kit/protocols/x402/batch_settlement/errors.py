"""Machine-readable failure codes for the SVM x402 ``batch-settlement`` scheme.

These are the strings a server puts in a corrective ``PaymentRequired.error``
or a ``SettlementResponse.errorReason``: wire values, so the constants below
are the single source of truth for this SDK. The Rust scheme
(``x402/protocol/schemes/batch_settlement/errors.rs``) lists 20 of these;
``channel_closing``, ``deposit_below_min_deposit`` and
``payout_attribution_ambiguous`` come from the scheme spec (section 7) and have
no Rust constant yet, and pay-kit #332 adds the first and the last of those
three. Nothing on either side ever answers ``payout_attribution_ambiguous``:
both read ``payoutWatermark`` from the channel account instead of attributing
payouts from token-balance deltas. ``tests/test_pk_x402_batch_wire.py`` checks
this list against the Rust one.
"""

from __future__ import annotations

from solana_pay_kit.errors import InvalidProofError

__all__ = [
    "ALL_CODES",
    "DUPLICATE_SETTLEMENT",
    "INVALID_CHANNEL_CLOSING",
    "INVALID_CHANNEL_ID_MISMATCH",
    "INVALID_CHANNEL_STATE",
    "INVALID_CLOSE_AMOUNT_UNSUPPORTED",
    "INVALID_CLOSE_AUTHORIZATION",
    "INVALID_CLOSE_STATE",
    "INVALID_CUMULATIVE_AMOUNT_MISMATCH",
    "INVALID_CUMULATIVE_EXCEEDS_DEPOSIT",
    "INVALID_DEPOSIT_BELOW_MIN_DEPOSIT",
    "INVALID_FEE_PAYER_MISMATCH",
    "INVALID_PAYLOAD_TYPE",
    "INVALID_PAYMENT_FLOW",
    "INVALID_PAYOUT_ATTRIBUTION_AMBIGUOUS",
    "INVALID_RECEIVER_AUTHORIZER_MISMATCH",
    "INVALID_REFUND_TRANSACTION",
    "INVALID_SETTLEMENT_SIMULATION",
    "INVALID_SETUP_TRANSACTION",
    "INVALID_TOKEN_PROGRAM",
    "INVALID_VOUCHER_EXPIRY",
    "INVALID_VOUCHER_SIGNATURE",
    "INVALID_WITHDRAW_DELAY_MISMATCH",
    "INVALID_WITHDRAW_DELAY_OUT_OF_RANGE",
    "BatchSettlementError",
    "classify",
]

_PREFIX = "invalid_batch_settlement_svm_"

#: Payload ``type`` or shape is not valid for the operation.
INVALID_PAYLOAD_TYPE = f"{_PREFIX}payload_type"
#: ``extra.paymentFlow`` is present and is not ``"authorization"``.
INVALID_PAYMENT_FLOW = f"{_PREFIX}payment_flow"
#: ``extra.tokenProgram`` is not SPL Token / Token-2022, or does not own the mint.
INVALID_TOKEN_PROGRAM = f"{_PREFIX}token_program"
#: Voucher or payer-proof signature is invalid, or signed by the wrong key.
INVALID_VOUCHER_SIGNATURE = f"{_PREFIX}voucher_signature"
#: ``voucher.channelId`` does not match the canonical PDA derivation.
INVALID_CHANNEL_ID_MISMATCH = f"{_PREFIX}channel_id_mismatch"
#: Channel ``payer``/``payerAuthorizer`` collides with, or ``payee``/``rent_payer`` differs from, ``extra.feePayer``.
INVALID_FEE_PAYER_MISMATCH = f"{_PREFIX}fee_payer_mismatch"
#: ``channelConfig.receiverAuthorizer`` does not match ``extra.receiverAuthorizer``.
INVALID_RECEIVER_AUTHORIZER_MISMATCH = f"{_PREFIX}receiver_authorizer_mismatch"
#: Close authorization is malformed, expired, mis-signed, or a refund carried a close hint.
INVALID_CLOSE_AUTHORIZATION = f"{_PREFIX}close_authorization"
#: A ``refund`` payload carried an ``amount``; only the full unused escrow is returned.
INVALID_CLOSE_AMOUNT_UNSUPPORTED = f"{_PREFIX}close_amount_unsupported"
#: The channel cannot take this operation in its current lifecycle state.
INVALID_CLOSE_STATE = f"{_PREFIX}close_state"
#: A voucher or payer proof arrived for a channel that is already closing.
INVALID_CHANNEL_CLOSING = f"{_PREFIX}channel_closing"
#: Channel grace period does not match ``extra.withdrawDelay``.
INVALID_WITHDRAW_DELAY_MISMATCH = f"{_PREFIX}withdraw_delay_mismatch"
#: ``withdrawDelay`` is outside ``900..=2592000`` or shorter than ``maxTimeoutSeconds``.
INVALID_WITHDRAW_DELAY_OUT_OF_RANGE = f"{_PREFIX}withdraw_delay_out_of_range"
#: Corrective 402: the client's cumulative voucher does not match server state.
INVALID_CUMULATIVE_AMOUNT_MISMATCH = f"{_PREFIX}cumulative_amount_mismatch"
#: The voucher, or charged plus reserved ceilings, exceeds the escrowed deposit.
INVALID_CUMULATIVE_EXCEEDS_DEPOSIT = f"{_PREFIX}cumulative_exceeds_deposit"
#: Voucher ``expiresAt`` is nonzero; this scheme requires non-expiring vouchers.
INVALID_VOUCHER_EXPIRY = f"{_PREFIX}voucher_expiry"
#: The client-supplied setup transaction fails the sponsor safety checks.
INVALID_SETUP_TRANSACTION = f"{_PREFIX}setup_transaction"
#: Setup or settlement-readiness simulation failed before accepting the deposit.
INVALID_SETTLEMENT_SIMULATION = f"{_PREFIX}settlement_simulation"
#: A server enforcing a minimum deposit refused a smaller one.
INVALID_DEPOSIT_BELOW_MIN_DEPOSIT = f"{_PREFIX}deposit_below_min_deposit"
#: Confirmed channel state does not match the payload and requirements.
INVALID_CHANNEL_STATE = f"{_PREFIX}channel_state"
#: Refund transaction is not a valid payer-signed ``request_close`` for the channel.
INVALID_REFUND_TRANSACTION = f"{_PREFIX}refund_transaction"
#: A payout cannot be attributed to one channel unambiguously.
INVALID_PAYOUT_ATTRIBUTION_AMBIGUOUS = f"{_PREFIX}payout_attribution_ambiguous"
#: The same setup/refund transaction, or the exact same voucher, is already settled.
#: A standard x402 code rather than a scheme-specific one.
DUPLICATE_SETTLEMENT = "duplicate_settlement"

#: Every code, for exhaustiveness checks and :func:`classify`.
ALL_CODES: tuple[str, ...] = (
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
    INVALID_CHANNEL_CLOSING,
    INVALID_WITHDRAW_DELAY_MISMATCH,
    INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
    INVALID_CUMULATIVE_AMOUNT_MISMATCH,
    INVALID_CUMULATIVE_EXCEEDS_DEPOSIT,
    INVALID_VOUCHER_EXPIRY,
    INVALID_SETUP_TRANSACTION,
    INVALID_SETTLEMENT_SIMULATION,
    INVALID_DEPOSIT_BELOW_MIN_DEPOSIT,
    INVALID_CHANNEL_STATE,
    INVALID_REFUND_TRANSACTION,
    INVALID_PAYOUT_ATTRIBUTION_AMBIGUOUS,
    DUPLICATE_SETTLEMENT,
)


class BatchSettlementError(InvalidProofError):
    """A ``batch-settlement`` rejection carrying its wire ``code`` and a log-only ``detail``."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}", code=code)
        self.detail = detail


def classify(message: str) -> str:
    """Recover the scheme code embedded in an error message, else ``transaction_failed``."""
    return next((code for code in ALL_CODES if code in message), "transaction_failed")
