"""Wire types and strict parsers for the SVM x402 ``batch-settlement`` scheme.

Field names, casing and encodings are normative: they are the bytes on the
wire and match the Rust (``x402/protocol/schemes/batch_settlement/types.rs``)
and TypeScript implementations. Keys are camelCase; amounts are decimal u64
strings (``^[0-9]+$``, so ``"+5"`` is refused even though Rust's
``u64::from_str`` takes it); slots, delays and timestamps are JSON integers;
keys and signatures are case-sensitive base58. Absent optionals are omitted,
never ``null``.

Fields marked server-signed exist only in the PR #23 server-signed mode.
Rust ignores them on deserialize, which is why a Python server must list its
client-signed accept first.

The parsers are the trust boundary: they validate every field's type with
pydantic in strict mode, drop unknown keys, and enforce the payload-union rules
(voucher xor payer proof by mode, no top-level ``requestId``, no refund
``amount``) before any semantic check runs.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal, NotRequired, cast

import pydantic

# pydantic builds validators from these TypedDicts, and on Python < 3.12 it
# only accepts typing_extensions.TypedDict.
from typing_extensions import TypedDict

from solana_pay_kit.protocols.x402.batch_settlement.errors import (
    INVALID_CLOSE_AMOUNT_UNSUPPORTED,
    INVALID_PAYLOAD_TYPE,
    BatchSettlementError,
)

__all__ = [
    "BATCH_SETTLEMENT_SCHEME",
    "MAX_CLAIMS_PER_BATCH",
    "MAX_WITHDRAW_DELAY_SECONDS",
    "MIN_WITHDRAW_DELAY_SECONDS",
    "PAYMENT_FLOW_AUTHORIZATION",
    "U64_MAX",
    "VOUCHER_EXPIRES_AT",
    "BatchAuthorization",
    "BatchAuthorizationPayload",
    "BatchChannelConfig",
    "BatchChannelState",
    "BatchClaimEntry",
    "BatchClaimPayload",
    "BatchDeposit",
    "BatchDepositPayload",
    "BatchExtra",
    "BatchPayload",
    "BatchPaymentPayload",
    "BatchPaymentRequired",
    "BatchRefundPayload",
    "BatchRequirements",
    "BatchSealPayload",
    "BatchSettleEntry",
    "BatchSettlePayload",
    "BatchSettlementExtra",
    "BatchSettlementResponse",
    "BatchVoucher",
    "BatchVoucherPayload",
    "BatchVoucherState",
    "CloseAuthorization",
    "VoucherSigner",
    "commitment_id",
    "parse_payment_payload",
    "parse_requirements",
    "parse_u64",
]

#: The x402 scheme identifier.
BATCH_SETTLEMENT_SCHEME = "batch-settlement"
#: The only payment flow this scheme resolves to.
PAYMENT_FLOW_AUTHORIZATION = "authorization"
#: Forced-close grace period floor (15 minutes), an x402 conformance bound.
MIN_WITHDRAW_DELAY_SECONDS = 900
#: Forced-close grace period ceiling (30 days).
MAX_WITHDRAW_DELAY_SECONDS = 2_592_000
#: Voucher claims (or settle/distribute entries) per redemption transaction.
MAX_CLAIMS_PER_BATCH = 4
#: The only voucher expiry this scheme permits: the grace period bounds redemption.
VOUCHER_EXPIRES_AT = 0
#: Largest value an on-chain ``u64`` holds.
U64_MAX = 0xFFFF_FFFF_FFFF_FFFF

_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1
_U32_MAX = 0xFFFF_FFFF
_U64_PATTERN = re.compile(r"[0-9]+")


def _u64_string(value: str) -> str:
    if _U64_PATTERN.fullmatch(value) is None or int(value) > U64_MAX:
        raise ValueError("must be a decimal u64 string")
    return value


_U64Str = Annotated[str, pydantic.AfterValidator(_u64_string)]
_U64 = Annotated[int, pydantic.Field(ge=0, le=U64_MAX)]
_U32 = Annotated[int, pydantic.Field(ge=0, le=_U32_MAX)]
_I64 = Annotated[int, pydantic.Field(ge=_I64_MIN, le=_I64_MAX)]
_PositiveI64 = Annotated[int, pydantic.Field(ge=1, le=_I64_MAX)]
_NonEmpty = Annotated[str, pydantic.Field(min_length=1)]

#: Voucher-signing mode: ``"client"`` (default) or ``"server"`` (PR #23).
VoucherSigner = Literal["client", "server"]


class BatchChannelConfig(TypedDict):
    """Channel configuration carried on every client payload; every field is a PDA seed or immutable."""

    payer: _NonEmpty
    payerAuthorizer: _NonEmpty
    receiver: _NonEmpty
    receiverAuthorizer: NotRequired[_NonEmpty]
    token: _NonEmpty
    withdrawDelay: _U32
    salt: _U64Str
    openSlot: _U64
    # Server-signed only. "client" is canonicalized away on parse, so client
    # mode always omits the key (as the TypeScript client does).
    voucherSigner: NotRequired[Literal["server"]]


class BatchVoucher(TypedDict):
    """A signed cumulative voucher: ``0x56 0x01 || channelId || u64 LE || i64 LE`` signed by payerAuthorizer."""

    channelId: _NonEmpty
    maxClaimableAmount: _U64Str
    expiresAt: _I64
    signature: _NonEmpty


class BatchAuthorization(TypedDict):
    """Server-signed mode: the payer's expiring, single-request, amount-bounded proof."""

    type: Literal["proof"]
    channelId: _NonEmpty
    payer: _NonEmpty
    requestId: _NonEmpty
    authorizedAmount: _U64Str
    expiresAt: _PositiveI64
    signature: _NonEmpty


class CloseAuthorization(TypedDict):
    """Receiver-authorizer signature binding one cooperative close until ``validBefore``."""

    validBefore: _PositiveI64
    signature: _NonEmpty


class BatchChannelState(TypedDict):
    """On-chain channel snapshot carried by settlement responses and corrective 402s."""

    channelId: _NonEmpty
    balance: _U64Str
    totalClaimed: _U64Str
    withdrawRequestedAt: _I64
    chargedCumulativeAmount: NotRequired[_U64Str]


class BatchVoucherState(TypedDict):
    """Corrective 402 proof: the cumulative the server holds a client signature for."""

    signedMaxClaimable: _U64Str
    expiresAt: _I64
    signature: _NonEmpty


class BatchExtra(TypedDict):
    """The ``extra`` object on a ``batch-settlement`` requirement."""

    feePayer: _NonEmpty
    withdrawDelay: _U32
    tokenProgram: _NonEmpty
    # Checked against "authorization" by verify.check_terms (its own code).
    paymentFlow: NotRequired[str]
    receiverAuthorizer: NotRequired[_NonEmpty]
    memo: NotRequired[str]
    recentBlockhash: NotRequired[_NonEmpty]
    recentSlot: NotRequired[_U64]
    # pay-kit/Rust only: the message versions a server accepts. Python servers omit it.
    transactionVersions: NotRequired[list[Literal[0, 1]]]
    minDeposit: NotRequired[_U64Str]
    maxIdleSecs: NotRequired[_U64]
    voucherSigner: NotRequired[VoucherSigner]
    operator: NotRequired[_NonEmpty]
    channelState: NotRequired[BatchChannelState]
    voucherState: NotRequired[BatchVoucherState]


class BatchRequirements(TypedDict):
    """One ``accepts[]`` entry of a ``batch-settlement`` challenge."""

    scheme: Literal["batch-settlement"]
    network: _NonEmpty
    amount: _U64Str
    asset: _NonEmpty
    payTo: _NonEmpty
    maxTimeoutSeconds: _U64
    extra: BatchExtra


class BatchPaymentRequired(TypedDict):
    """The ``PAYMENT-REQUIRED`` envelope; ``error`` is set on a corrective 402."""

    x402Version: int
    accepts: list[BatchRequirements]
    resource: NotRequired[dict[str, Any]]
    error: NotRequired[str]


class BatchDeposit(TypedDict):
    """Escrow funding: the amount and the base64 client-signed ``open``/``top_up`` transaction."""

    amount: _U64Str
    transaction: _NonEmpty


class BatchDepositPayload(TypedDict):
    """Open or top up a channel and authorize this request (voucher xor authorization, by mode)."""

    type: Literal["deposit"]
    channelConfig: BatchChannelConfig
    deposit: BatchDeposit
    voucher: NotRequired[BatchVoucher]
    authorization: NotRequired[BatchAuthorization]


class BatchVoucherPayload(TypedDict):
    """Client-signed steady-state request: a new cumulative voucher, no transaction."""

    type: Literal["voucher"]
    channelConfig: BatchChannelConfig
    voucher: BatchVoucher


class BatchAuthorizationPayload(TypedDict):
    """Server-signed steady-state request: a fresh payer proof, no transaction."""

    type: Literal["authorization"]
    channelConfig: BatchChannelConfig
    authorization: BatchAuthorization


class BatchRefundPayload(TypedDict):
    """Payer-forced close: a client-signed ``request_close``; the resource handler is bypassed."""

    type: Literal["refund"]
    channelConfig: BatchChannelConfig
    transaction: _NonEmpty
    # Cooperative-close hints: valid wire, refused by verify.check_no_cooperative_close.
    voucher: NotRequired[BatchVoucher]
    closeAuthorization: NotRequired[CloseAuthorization]


BatchPayload = BatchDepositPayload | BatchVoucherPayload | BatchAuthorizationPayload | BatchRefundPayload


class BatchPaymentPayload(TypedDict):
    """The ``PAYMENT-SIGNATURE`` envelope: the echoed ``accepted`` requirement and the payload."""

    x402Version: Literal[2]
    accepted: BatchRequirements
    payload: Annotated[BatchPayload, pydantic.Field(discriminator="type")]
    resource: NotRequired[dict[str, Any]]
    extensions: NotRequired[dict[str, Any]]


# Server-authored redemption payloads, in-process only (the PR #23 entry shape).


class BatchClaimEntry(TypedDict):
    """One voucher to redeem in a ``claim`` batch."""

    channelId: str
    channelConfig: BatchChannelConfig
    voucher: BatchVoucher


class BatchClaimPayload(TypedDict):
    """One to :data:`MAX_CLAIMS_PER_BATCH` claims, redeemed with ``[ed25519, settle]`` pairs."""

    type: Literal["claim"]
    claims: list[BatchClaimEntry]


class BatchSettleEntry(TypedDict):
    """One channel to distribute in a ``settle`` batch."""

    channelId: str
    channelConfig: BatchChannelConfig


class BatchSettlePayload(TypedDict):
    """One to :data:`MAX_CLAIMS_PER_BATCH` channels whose settled delta is paid to ``payTo``."""

    type: Literal["settle"]
    channels: list[BatchSettleEntry]


class BatchSealPayload(TypedDict):
    """Cooperative close of a ``Closing`` channel at the latest accepted voucher."""

    type: Literal["seal"]
    channelId: str
    channelConfig: BatchChannelConfig
    voucher: BatchVoucher
    closeAuthorization: NotRequired[CloseAuthorization]


class BatchSettlementExtra(TypedDict, total=False):
    """Scheme fields under ``SettlementResponse.extra``.

    ``commitmentId`` is ``"{channelId}:{maxClaimableAmount}"``, which the Rust
    client checks verbatim; ``chargedAmount`` is required in client mode and
    ``voucher`` (the operator-signed receipt) in server mode.
    """

    commitmentId: str
    chargedAmount: str
    channelState: BatchChannelState
    voucher: BatchVoucher


class BatchSettlementResponse(TypedDict):
    """The ``PAYMENT-RESPONSE`` result; ``transaction``/``amount`` are ``""`` for voucher acceptance."""

    success: bool
    transaction: str
    network: str
    amount: str
    errorReason: NotRequired[str]
    payer: NotRequired[str]
    extra: NotRequired[BatchSettlementExtra]


# Validated with strict=True: no str->int coercion, no bool as int, no float as int.
_PAYMENT_PAYLOAD = pydantic.TypeAdapter(BatchPaymentPayload)
_REQUIREMENTS = pydantic.TypeAdapter(BatchRequirements)


def parse_u64(value: object, field: str, code: str = INVALID_PAYLOAD_TYPE) -> int:
    """Parse a decimal u64 wire string strictly (``^[0-9]+$``, at most ``2**64 - 1``)."""
    if not isinstance(value, str):
        raise BatchSettlementError(code, f"{field} must be a decimal u64 string")
    try:
        return int(_u64_string(value))
    except ValueError:
        raise BatchSettlementError(code, f"{field} {value!r} is not a decimal u64 string") from None


def commitment_id(channel_id: str, max_claimable_amount: str) -> str:
    """The ``SettlementResponse.extra.commitmentId`` a voucher establishes."""
    return f"{channel_id}:{max_claimable_amount}"


def parse_requirements(raw: object) -> BatchRequirements:
    """Validate one ``batch-settlement`` requirement, dropping unknown keys."""
    try:
        return _REQUIREMENTS.validate_python(raw, strict=True)
    except pydantic.ValidationError as exc:
        raise BatchSettlementError(INVALID_PAYLOAD_TYPE, f"malformed requirements: {exc}") from None


def parse_payment_payload(raw: object) -> BatchPaymentPayload:
    """Validate a decoded ``PAYMENT-SIGNATURE`` envelope and its payload union.

    Rules beyond the field types: ``x402Version`` is 2; a ``refund`` carrying
    ``amount`` is refused with ``close_amount_unsupported``; ``deposit`` and
    ``authorization`` payloads carry no top-level ``requestId`` or
    ``maxClaimableAmount``; a client-mode deposit carries a voucher and no
    authorization, a server-mode deposit the reverse; ``voucher`` payloads are
    client-mode only and ``authorization`` payloads server-mode only.
    """
    envelope = _canonical_envelope(raw)
    try:
        parsed = _PAYMENT_PAYLOAD.validate_python(envelope, strict=True)
    except pydantic.ValidationError as exc:
        raise BatchSettlementError(INVALID_PAYLOAD_TYPE, f"malformed batch-settlement payload: {exc}") from None
    payload = parsed["payload"]
    server_mode = payload["channelConfig"].get("voucherSigner") == "server"
    if payload["type"] == "deposit":
        has_voucher = "voucher" in payload
        has_authorization = "authorization" in payload
        if (has_voucher, has_authorization) != (not server_mode, server_mode):
            raise BatchSettlementError(
                INVALID_PAYLOAD_TYPE, "a deposit carries a voucher in client mode and a payer proof in server mode"
            )
    elif payload["type"] == "voucher" and server_mode:
        raise BatchSettlementError(INVALID_PAYLOAD_TYPE, "voucher payloads are client-signed mode only")
    elif payload["type"] == "authorization" and not server_mode:
        raise BatchSettlementError(INVALID_PAYLOAD_TYPE, "authorization payloads are server-signed mode only")
    return parsed


def _canonical_envelope(raw: object) -> object:
    """Apply the raw-key rules pydantic would silently drop, and canonicalize ``voucherSigner: "client"``."""
    if not isinstance(raw, dict):
        return raw
    envelope = cast("dict[str, Any]", raw)
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return envelope
    body = cast("dict[str, Any]", payload)
    kind = body.get("type")
    if kind == "refund" and "amount" in body:
        raise BatchSettlementError(
            INVALID_CLOSE_AMOUNT_UNSUPPORTED, "refund returns the full unused escrow; it takes no amount"
        )
    if kind in ("deposit", "authorization") and ("requestId" in body or "maxClaimableAmount" in body):
        raise BatchSettlementError(INVALID_PAYLOAD_TYPE, f"{kind} payload carries a top-level requestId/amount")
    config = body.get("channelConfig")
    if not isinstance(config, dict):
        return envelope
    fields = cast("dict[str, Any]", config)
    if fields.get("voucherSigner") != "client":
        return envelope
    # "client" and omitted both select client mode; keep one spelling so stored
    # configs compare equal whichever the client sent.
    canonical = {key: value for key, value in fields.items() if key != "voucherSigner"}
    return {**envelope, "payload": {**body, "channelConfig": canonical}}
