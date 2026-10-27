"""Machine-readable failure codes for the SVM ``batch-settlement`` scheme.

These are the values a facilitator puts in ``VerifyResponse.invalidReason`` or
``SettlementResponse.errorReason``, and a resource server puts in a corrective
``PaymentRequired.error``. They are wire strings shared with every other SDK
(``scheme_batch_settlement_svm.md`` section 7). Mirrors the Rust kit
(``x402/protocol/schemes/batch_settlement/errors.rs``).
"""

from __future__ import annotations

__all__ = [
    "ALL_CODES",
    "BatchSettlementError",
    "DUPLICATE_SETTLEMENT",
    "INVALID_CHANNEL_CLOSING",
    "INVALID_CHANNEL_ID_MISMATCH",
    "INVALID_CHANNEL_STATE",
    "INVALID_CLOSE_AMOUNT_UNSUPPORTED",
    "INVALID_CLOSE_AUTHORIZATION",
    "INVALID_CLOSE_STATE",
    "INVALID_CUMULATIVE_AMOUNT_MISMATCH",
    "INVALID_CUMULATIVE_EXCEEDS_DEPOSIT",
    "INVALID_FEE_PAYER_MISMATCH",
    "INVALID_PAYLOAD_TYPE",
    "INVALID_PAYMENT_FLOW",
    "INVALID_PAYMENT_REQUIREMENTS",
    "INVALID_PAYOUT_ATTRIBUTION_AMBIGUOUS",
    "INVALID_RECEIVER_AUTHORIZER_MISMATCH",
    "INVALID_RECEIVER_BINDING_UNAVAILABLE",
    "INVALID_REFUND_TRANSACTION",
    "INVALID_SETTLEMENT_SIMULATION",
    "INVALID_SETUP_TRANSACTION",
    "INVALID_TOKEN_PROGRAM",
    "INVALID_VOUCHER_EXPIRY",
    "INVALID_VOUCHER_SIGNATURE",
    "INVALID_WITHDRAW_DELAY_MISMATCH",
    "INVALID_WITHDRAW_DELAY_OUT_OF_RANGE",
    "INVALID_X402_VERSION",
    "UNSUPPORTED_TRANSACTION_VERSION",
    "classify",
    "leading_code",
]

#: Payload ``type`` is not valid for the current verify or settle operation.
INVALID_PAYLOAD_TYPE = "invalid_batch_settlement_svm_payload_type"
#: ``extra.paymentFlow`` is present and is not ``"authorization"``.
INVALID_PAYMENT_FLOW = "invalid_batch_settlement_svm_payment_flow"
#: ``extra.tokenProgram`` is not a supported SPL token program, or does not own the mint.
INVALID_TOKEN_PROGRAM = "invalid_batch_settlement_svm_token_program"
#: Voucher signature is invalid, or ``payerAuthorizer`` is not the channel ``authorized_signer``.
INVALID_VOUCHER_SIGNATURE = "invalid_batch_settlement_svm_voucher_signature"
#: ``voucher.channelId`` does not match the canonical PDA derivation.
INVALID_CHANNEL_ID_MISMATCH = "invalid_batch_settlement_svm_channel_id_mismatch"
#: Channel ``payee`` or ``rent_payer`` does not match ``extra.feePayer``.
INVALID_FEE_PAYER_MISMATCH = "invalid_batch_settlement_svm_fee_payer_mismatch"
#: ``channelConfig.receiverAuthorizer`` does not match ``extra.receiverAuthorizer``.
INVALID_RECEIVER_AUTHORIZER_MISMATCH = "invalid_batch_settlement_svm_receiver_authorizer_mismatch"
#: Close authorization is malformed, expired, or signed by the wrong key.
INVALID_CLOSE_AUTHORIZATION = "invalid_batch_settlement_svm_close_authorization"
#: The ``refund`` payload carries an ``amount``; only the full unused escrow is returned.
INVALID_CLOSE_AMOUNT_UNSUPPORTED = "invalid_batch_settlement_svm_close_amount_unsupported"
#: The channel cannot be closed, or a cooperative voucher does not equal server state.
INVALID_CLOSE_STATE = "invalid_batch_settlement_svm_close_state"
#: Channel grace period does not match ``extra.withdrawDelay``.
INVALID_WITHDRAW_DELAY_MISMATCH = "invalid_batch_settlement_svm_withdraw_delay_mismatch"
#: ``withdrawDelay`` is outside ``900..=2592000`` or shorter than ``maxTimeoutSeconds``.
INVALID_WITHDRAW_DELAY_OUT_OF_RANGE = "invalid_batch_settlement_svm_withdraw_delay_out_of_range"
#: Corrective 402: the client's cumulative voucher does not match server state.
INVALID_CUMULATIVE_AMOUNT_MISMATCH = "invalid_batch_settlement_svm_cumulative_amount_mismatch"
#: Voucher ``maxClaimableAmount`` exceeds the escrowed deposit.
INVALID_CUMULATIVE_EXCEEDS_DEPOSIT = "invalid_batch_settlement_svm_cumulative_exceeds_deposit"
#: Voucher ``expiresAt`` is nonzero.
INVALID_VOUCHER_EXPIRY = "invalid_batch_settlement_svm_voucher_expiry"
#: The client-supplied setup transaction fails the sponsor safety checks.
INVALID_SETUP_TRANSACTION = "invalid_batch_settlement_svm_setup_transaction"
#: Setup or settlement-readiness checks failed before accepting the deposit.
INVALID_SETTLEMENT_SIMULATION = "invalid_batch_settlement_svm_settlement_simulation"
#: Confirmed channel state does not match the payload and requirements.
INVALID_CHANNEL_STATE = "invalid_batch_settlement_svm_channel_state"
#: Refund transaction is not a valid payer-signed ``request_close`` for the channel.
INVALID_REFUND_TRANSACTION = "invalid_batch_settlement_svm_refund_transaction"
#: The payer started a forced close: no claim, voucher or authorization is accepted.
INVALID_CHANNEL_CLOSING = "invalid_batch_settlement_svm_channel_closing"
#: A settle payout cannot be attributed because a sealed payout aliases ``payTo``.
INVALID_PAYOUT_ATTRIBUTION_AMBIGUOUS = "invalid_batch_settlement_svm_payout_attribution_ambiguous"
#: The receiver-authorizer binding is unavailable; retry with a ``request_close``.
INVALID_RECEIVER_BINDING_UNAVAILABLE = "invalid_batch_settlement_svm_receiver_binding_unavailable"
#: x402 v2: the envelope's protocol version is not supported.
INVALID_X402_VERSION = "invalid_x402_version"
#: x402 v2: ``paymentPayload.accepted`` does not equal the route's requirements.
INVALID_PAYMENT_REQUIREMENTS = "invalid_payment_requirements"
#: x402-txv1: a client transaction's message version is not advertised.
UNSUPPORTED_TRANSACTION_VERSION = "unsupported_transaction_version"
#: The same client-supplied transaction or channel request is already in flight.
DUPLICATE_SETTLEMENT = "duplicate_settlement"

#: Every code, in the Rust kit's order (``classify`` searches it in order).
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
    INVALID_WITHDRAW_DELAY_MISMATCH,
    INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
    INVALID_CUMULATIVE_AMOUNT_MISMATCH,
    INVALID_CUMULATIVE_EXCEEDS_DEPOSIT,
    INVALID_VOUCHER_EXPIRY,
    INVALID_SETUP_TRANSACTION,
    INVALID_SETTLEMENT_SIMULATION,
    INVALID_CHANNEL_STATE,
    INVALID_REFUND_TRANSACTION,
    INVALID_CHANNEL_CLOSING,
    INVALID_PAYOUT_ATTRIBUTION_AMBIGUOUS,
    INVALID_RECEIVER_BINDING_UNAVAILABLE,
    INVALID_X402_VERSION,
    INVALID_PAYMENT_REQUIREMENTS,
    UNSUPPORTED_TRANSACTION_VERSION,
    DUPLICATE_SETTLEMENT,
)


class BatchSettlementError(Exception):
    """A ``batch-settlement`` failure tagged with its wire code.

    ``str(error)`` is ``"<code>: <detail>"``; ``code`` is what goes on the wire,
    ``detail`` is for logs only.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def leading_code(message: str) -> str | None:
    """The code a :class:`BatchSettlementError` message leads with, if any.

    Never searches the detail, so a decision on it cannot be steered by text a
    client supplied.
    """
    for code in ALL_CODES:
        if message.startswith(code) and message[len(code) :].startswith(": "):
            return code
    return None


def classify(message: str) -> str:
    """The scheme code an error message carries, ``transaction_failed`` otherwise.

    The leading code wins; otherwise the first code (in :data:`ALL_CODES`
    order) the message contains.
    """
    code = leading_code(message)
    if code is not None:
        return code
    for candidate in ALL_CODES:
        if candidate in message:
            return candidate
    return "transaction_failed"
