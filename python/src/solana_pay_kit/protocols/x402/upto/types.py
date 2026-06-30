"""x402 ``upto`` wire types and scheme constants.

The ``upto`` scheme reuses the x402 v2 transport (``PAYMENT-REQUIRED`` →
``PAYMENT-SIGNATURE`` → ``PAYMENT-RESPONSE``); only the scheme value and the
payload shape differ from ``exact``. These TypedDicts mirror the Rust spine
(``rust/crates/x402/src/protocol/schemes/upto/types.rs``) and the Go reference
(``go/protocols/x402/upto.go``) field-for-field: camelCase JSON keys, amounts as
base-10 u64 strings, timestamps as Unix seconds.
"""

from __future__ import annotations

from typing import TypedDict

__all__ = [
    "UPTO_SCHEME",
    "UPTO_ASSET_TRANSFER_METHOD",
    "UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT",
    "UptoExtra",
    "UptoRequirements",
    "UptoPayload",
    "UptoSignatureEnvelope",
    "UptoRequiredEnvelope",
    "UptoSettlementResponse",
]

#: The x402 scheme identifier for usage-based ``upto`` authorizations.
UPTO_SCHEME = "upto"

#: The SVM asset transfer method for ``upto`` authorizations.
UPTO_ASSET_TRANSFER_METHOD = "payment-channel"

#: Settlement error raised when the metered actual exceeds the signed ceiling.
#: Identical string to the Rust/Go constant so cross-language error parity holds.
UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT = "invalid_upto_svm_payload_settlement_exceeds_amount"


class _UptoExtraRequired(TypedDict):
    """Spec-required ``extra`` fields (always advertised by a server offer)."""

    assetTransferMethod: str
    decimals: int
    tokenProgram: str
    facilitatorAddress: str


class UptoExtra(_UptoExtraRequired, total=False):
    """The ``extra`` object on an ``upto`` payment requirement.

    ``assetTransferMethod``/``decimals``/``tokenProgram``/``facilitatorAddress``
    are required. ``facilitatorFee`` is optional and defaults to zero basis
    points. ``channelProgram``/``recentBlockhash``/``validAfter`` are optional.
    """

    facilitatorFee: int
    channelProgram: str
    recentBlockhash: str
    lastValidBlockHeight: str
    validAfter: int


class UptoRequirements(TypedDict):
    """The ``accepts[]`` entry advertised for the ``upto`` scheme.

    ``amount`` is phase-dependent: the authorized **maximum** during
    verification, the **actual** charge during settlement.
    """

    scheme: str
    network: str
    amount: str
    asset: str
    payTo: str
    maxTimeoutSeconds: int
    extra: UptoExtra


# ``from`` is a Python keyword, so the payload TypedDicts use functional syntax.
_UptoPayloadRequired = TypedDict(
    "_UptoPayloadRequired",
    {
        "from": str,
        "maxAmount": str,
        "expiresAt": int,
        "validAfter": int,
        "nonce": str,
        "channelId": str,
        "deposit": str,
        "authorizedSigner": str,
    },
)


class UptoPayload(_UptoPayloadRequired, total=False):
    """The client authorization in ``PAYMENT-SIGNATURE.payload``.

    The common + ``payment-channel`` fields are required; ``openTransaction``
    (pull-style) and ``signature`` (push-style) are optional.
    """

    openTransaction: str
    signature: str


class UptoSignatureEnvelope(TypedDict, total=False):
    """The ``PAYMENT-SIGNATURE`` envelope carrying the client authorization."""

    x402Version: int
    scheme: str
    network: str
    accepted: UptoRequirements
    payload: UptoPayload


class UptoRequiredEnvelope(TypedDict, total=False):
    """The ``PAYMENT-REQUIRED`` challenge body for the ``upto`` scheme."""

    x402Version: int
    resource: dict[str, str]
    accepts: list[UptoRequirements]
    error: str


class _UptoSettlementRequired(TypedDict):
    """Spec-required settlement-receipt fields (§4.3)."""

    success: bool
    transaction: str
    network: str
    amount: str


class UptoSettlementResponse(_UptoSettlementRequired, total=False):
    """The ``PAYMENT-RESPONSE`` settlement receipt.

    ``transaction`` MAY be the empty string when no token movement occurred
    (a zero-amount settlement); ``amount`` is the actual base units charged.
    ``errorReason``/``payer`` are optional.
    """

    errorReason: str
    payer: str
