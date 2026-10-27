"""Wire types for the SVM ``batch-settlement`` scheme.

The client deposits once into an escrow payment channel, then signs a
cumulative Ed25519 voucher per request; the server verifies each voucher
offchain, serves immediately, and redeems the latest voucher onchain later, in
batches. Field names, casing and encodings are normative: they are the bytes on
the wire (``scheme_batch_settlement_svm.md`` section 4).

Every type parses strictly (:meth:`from_dict`) and re-encodes canonically
(:meth:`to_dict`), mirroring the Rust kit's serde types
(``x402/protocol/schemes/batch_settlement/types.rs``): a required field that is
missing or of the wrong JSON type is refused, optional fields that are absent
or ``null`` are dropped on output, and unknown fields are ignored.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeVar, cast

from solana_pay_kit.protocols.x402.batch_settlement.errors import (
    INVALID_PAYLOAD_TYPE,
    INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
)

__all__ = [
    "BATCH_SETTLEMENT_SCHEME",
    "MAX_CLAIMS_PER_BATCH",
    "MAX_WITHDRAW_DELAY_SECONDS",
    "MIN_WITHDRAW_DELAY_SECONDS",
    "PAYMENT_FLOW_AUTHORIZATION",
    "V1_MAX_CLAIM_CHANNELS",
    "V1_MAX_SETTLE_CHANNELS",
    "VOUCHER_EXPIRES_AT",
    "BatchAuthorization",
    "BatchChannelConfig",
    "BatchClaim",
    "BatchDeposit",
    "BatchExtra",
    "BatchPayload",
    "BatchPaymentPayload",
    "BatchRedemptionPayload",
    "BatchRefund",
    "BatchRequiredEnvelope",
    "BatchRequirements",
    "BatchSeal",
    "BatchSettle",
    "BatchSettleChannel",
    "BatchSettlementExtra",
    "BatchSettlementResponse",
    "BatchVoucher",
    "BatchVoucherClaim",
    "BatchWireError",
    "ChannelStateSnapshot",
    "CloseAuthorization",
    "ResourceInfo",
    "VoucherState",
    "parse_amount",
]

#: ``batch-settlement`` scheme identifier.
BATCH_SETTLEMENT_SCHEME = "batch-settlement"
#: The only payment flow this scheme resolves to.
PAYMENT_FLOW_AUTHORIZATION = "authorization"
#: Minimum forced-close grace period (15 minutes).
MIN_WITHDRAW_DELAY_SECONDS = 900
#: Maximum forced-close grace period (30 days).
MAX_WITHDRAW_DELAY_SECONDS = 2_592_000
#: Channels per ``claim`` or ``settle`` when no capacity is advertised (and per
#: legacy or version-0 redemption).
MAX_CLAIMS_PER_BATCH = 4
#: Ed25519 + ``settle`` pairs that fit one version-1 redemption.
V1_MAX_CLAIM_CHANNELS = 18
#: ``distribute`` instructions that fit one version-1 redemption.
V1_MAX_SETTLE_CHANNELS = 13
#: The only voucher expiry this scheme permits.
VOUCHER_EXPIRES_AT = 0

_U64_MAX = (1 << 64) - 1
_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1
_U32_MAX = (1 << 32) - 1

T = TypeVar("T")


class BatchWireError(ValueError):
    """A wire object that does not parse as the scheme's type."""


# ── strict field readers ──────────────────────────────────────────────────


def _object(value: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BatchWireError(f"{what} must be a JSON object")
    return cast("Mapping[str, Any]", value)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _req(obj: Mapping[str, Any], key: str, what: str) -> Any:
    value = obj.get(key)
    if value is None:
        raise BatchWireError(f"{what}: missing field `{key}`")
    return value


def _str(obj: Mapping[str, Any], key: str, what: str) -> str:
    value = _req(obj, key, what)
    if not isinstance(value, str):
        raise BatchWireError(f"{what}.{key} must be a string")
    return value


def _opt_str(obj: Mapping[str, Any], key: str, what: str) -> str | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise BatchWireError(f"{what}.{key} must be a string")
    return value


def _int_in(value: Any, low: int, high: int, label: str) -> int:
    if not _is_int(value) or not low <= value <= high:
        raise BatchWireError(f"{label} must be an integer in {low}..={high}")
    return cast("int", value)


def _u64(obj: Mapping[str, Any], key: str, what: str) -> int:
    return _int_in(_req(obj, key, what), 0, _U64_MAX, f"{what}.{key}")


def _opt_u64(obj: Mapping[str, Any], key: str, what: str) -> int | None:
    value = obj.get(key)
    return None if value is None else _int_in(value, 0, _U64_MAX, f"{what}.{key}")


def _opt_u32(obj: Mapping[str, Any], key: str, what: str) -> int | None:
    value = obj.get(key)
    return None if value is None else _int_in(value, 0, _U32_MAX, f"{what}.{key}")


def _i64(obj: Mapping[str, Any], key: str, what: str) -> int:
    return _int_in(_req(obj, key, what), _I64_MIN, _I64_MAX, f"{what}.{key}")


def _bool(obj: Mapping[str, Any], key: str, what: str) -> bool:
    value = _req(obj, key, what)
    if not isinstance(value, bool):
        raise BatchWireError(f"{what}.{key} must be a boolean")
    return value


def _opt(obj: Mapping[str, Any], key: str, parse: Callable[[Any], T]) -> T | None:
    value = obj.get(key)
    return None if value is None else parse(value)


def _put(out: dict[str, Any], key: str, value: Any) -> None:
    """Serialize an optional field: ``None`` is skipped (``skip_serializing_if``)."""
    if value is not None:
        out[key] = value


def parse_amount(value: str, label: str) -> int:
    """Parse an atomic-unit amount carried on the wire as a decimal ``u64`` string."""
    if not value or not value.isascii() or not value.isdigit():
        raise ValueError(f"invalid {label}: {value!r}")
    parsed = int(value, 10)
    if parsed > _U64_MAX:
        raise ValueError(f"invalid {label}: {value!r}")
    return parsed


def _withdraw_delay(value: Any) -> int:
    """``extra.withdrawDelay``: any JSON number parses, so a fractional or
    negative value is refused with the range code rather than as malformed."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BatchWireError("extra.withdrawDelay must be a number")
    if not _is_int(value) or not 0 <= value <= _U32_MAX:
        raise BatchWireError(
            f"{INVALID_WITHDRAW_DELAY_OUT_OF_RANGE}: withdrawDelay {value} is not an integer number of "
            f"seconds from {MIN_WITHDRAW_DELAY_SECONDS} through {MAX_WITHDRAW_DELAY_SECONDS}"
        )
    return cast("int", value)


def _transaction_versions(value: Any) -> list[int]:
    if not isinstance(value, list):
        raise BatchWireError("extra.transactionVersions must be an array")
    versions: list[int] = []
    for entry in cast("list[Any]", value):
        if not _is_int(entry) or entry not in (0, 1):
            raise BatchWireError(f"unsupported transaction version {entry!r}")
        versions.append(cast("int", entry))
    return versions


# ── shared objects ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ResourceInfo:
    """x402 v2 resource metadata."""

    url: str
    description: str | None = None
    mime_type: str | None = None

    @classmethod
    def from_dict(cls, value: Any) -> ResourceInfo:
        obj = _object(value, "resource")
        return cls(
            url=_str(obj, "url", "resource"),
            description=_opt_str(obj, "description", "resource"),
            mime_type=_opt_str(obj, "mimeType", "resource"),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"url": self.url}
        _put(out, "description", self.description)
        _put(out, "mimeType", self.mime_type)
        return out


@dataclass(frozen=True)
class ChannelStateSnapshot:
    """Onchain channel snapshot in settlement responses and corrective challenges."""

    channel_id: str
    balance: str
    total_claimed: str
    withdraw_requested_at: int
    charged_cumulative_amount: str | None = None

    @classmethod
    def from_dict(cls, value: Any) -> ChannelStateSnapshot:
        what = "channelState"
        obj = _object(value, what)
        return cls(
            channel_id=_str(obj, "channelId", what),
            balance=_str(obj, "balance", what),
            total_claimed=_str(obj, "totalClaimed", what),
            withdraw_requested_at=_i64(obj, "withdrawRequestedAt", what),
            charged_cumulative_amount=_opt_str(obj, "chargedCumulativeAmount", what),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "channelId": self.channel_id,
            "balance": self.balance,
            "totalClaimed": self.total_claimed,
            "withdrawRequestedAt": self.withdraw_requested_at,
        }
        _put(out, "chargedCumulativeAmount", self.charged_cumulative_amount)
        return out


@dataclass(frozen=True)
class VoucherState:
    """The signed voucher proof a corrective 402 carries."""

    signed_max_claimable: str
    expires_at: int
    signature: str

    @classmethod
    def from_dict(cls, value: Any) -> VoucherState:
        what = "voucherState"
        obj = _object(value, what)
        return cls(
            signed_max_claimable=_str(obj, "signedMaxClaimable", what),
            expires_at=_i64(obj, "expiresAt", what),
            signature=_str(obj, "signature", what),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "signedMaxClaimable": self.signed_max_claimable,
            "expiresAt": self.expires_at,
            "signature": self.signature,
        }

    def signed_max_claimable_amount(self) -> int:
        return parse_amount(self.signed_max_claimable, "voucherState.signedMaxClaimable")


# ── PaymentRequirements ───────────────────────────────────────────────────


@dataclass(frozen=True)
class BatchExtra:
    """The ``extra`` object of a ``batch-settlement`` requirement.

    The payment-channels program id is deliberately absent: it is a network
    constant, never negotiated from a server-provided field.
    """

    fee_payer: str
    withdraw_delay: int
    token_program: str
    payment_flow: str | None = None
    transaction_versions: list[int] | None = None
    receiver_authorizer: str | None = None
    memo: str | None = None
    recent_blockhash: str | None = None
    recent_slot: int | None = None
    min_deposit: str | None = None
    voucher_signer: str | None = None
    operator: str | None = None
    max_idle_secs: int | None = None
    max_claim_channels: int | None = None
    max_settle_channels: int | None = None
    channel_state: ChannelStateSnapshot | None = None
    voucher_state: VoucherState | None = None

    @classmethod
    def from_dict(cls, value: Any) -> BatchExtra:
        what = "extra"
        obj = _object(value, what)
        return cls(
            payment_flow=_opt_str(obj, "paymentFlow", what),
            fee_payer=_str(obj, "feePayer", what),
            transaction_versions=_opt(obj, "transactionVersions", _transaction_versions),
            receiver_authorizer=_opt_str(obj, "receiverAuthorizer", what),
            withdraw_delay=_withdraw_delay(_req(obj, "withdrawDelay", what)),
            token_program=_str(obj, "tokenProgram", what),
            memo=_opt_str(obj, "memo", what),
            recent_blockhash=_opt_str(obj, "recentBlockhash", what),
            recent_slot=_opt_u64(obj, "recentSlot", what),
            min_deposit=_opt_str(obj, "minDeposit", what),
            voucher_signer=_opt_str(obj, "voucherSigner", what),
            operator=_opt_str(obj, "operator", what),
            max_idle_secs=_opt_u64(obj, "maxIdleSecs", what),
            max_claim_channels=_opt_u32(obj, "maxClaimChannels", what),
            max_settle_channels=_opt_u32(obj, "maxSettleChannels", what),
            channel_state=_opt(obj, "channelState", ChannelStateSnapshot.from_dict),
            voucher_state=_opt(obj, "voucherState", VoucherState.from_dict),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        _put(out, "paymentFlow", self.payment_flow)
        out["feePayer"] = self.fee_payer
        _put(out, "transactionVersions", None if self.transaction_versions is None else list(self.transaction_versions))
        _put(out, "receiverAuthorizer", self.receiver_authorizer)
        out["withdrawDelay"] = self.withdraw_delay
        out["tokenProgram"] = self.token_program
        _put(out, "memo", self.memo)
        _put(out, "recentBlockhash", self.recent_blockhash)
        _put(out, "recentSlot", self.recent_slot)
        _put(out, "minDeposit", self.min_deposit)
        _put(out, "voucherSigner", self.voucher_signer)
        _put(out, "operator", self.operator)
        _put(out, "maxIdleSecs", self.max_idle_secs)
        _put(out, "maxClaimChannels", self.max_claim_channels)
        _put(out, "maxSettleChannels", self.max_settle_channels)
        _put(out, "channelState", None if self.channel_state is None else self.channel_state.to_dict())
        _put(out, "voucherState", None if self.voucher_state is None else self.voucher_state.to_dict())
        return out


@dataclass(frozen=True)
class BatchRequirements:
    """One ``accepts[]`` entry of a ``batch-settlement`` 402."""

    network: str
    amount: str
    asset: str
    pay_to: str
    max_timeout_seconds: int
    extra: BatchExtra
    scheme: str = BATCH_SETTLEMENT_SCHEME

    @classmethod
    def from_dict(cls, value: Any) -> BatchRequirements:
        what = "requirements"
        obj = _object(value, what)
        scheme = obj.get("scheme", BATCH_SETTLEMENT_SCHEME)
        if not isinstance(scheme, str):
            raise BatchWireError("requirements.scheme must be a string")
        return cls(
            scheme=scheme,
            network=_str(obj, "network", what),
            amount=_str(obj, "amount", what),
            asset=_str(obj, "asset", what),
            pay_to=_str(obj, "payTo", what),
            max_timeout_seconds=_u64(obj, "maxTimeoutSeconds", what),
            extra=BatchExtra.from_dict(_req(obj, "extra", what)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "network": self.network,
            "amount": self.amount,
            "asset": self.asset,
            "payTo": self.pay_to,
            "maxTimeoutSeconds": self.max_timeout_seconds,
            "extra": self.extra.to_dict(),
        }

    def amount_units(self) -> int:
        """The per-request price in atomic units."""
        return parse_amount(self.amount, "amount")

    def is_corrective(self) -> bool:
        """Whether this requirement carries a corrective channel snapshot."""
        return self.extra.channel_state is not None


@dataclass(frozen=True)
class BatchRequiredEnvelope:
    """The ``PAYMENT-REQUIRED`` envelope of a ``batch-settlement`` challenge."""

    x402_version: int
    accepts: list[BatchRequirements] = field(default_factory=lambda: [])
    resource: ResourceInfo | None = None
    error: str | None = None

    @classmethod
    def from_dict(cls, value: Any) -> BatchRequiredEnvelope:
        what = "paymentRequired"
        obj = _object(value, what)
        accepts_raw = obj.get("accepts")
        if accepts_raw is None:
            accepts_raw = []
        if not isinstance(accepts_raw, list):
            raise BatchWireError("paymentRequired.accepts must be an array")
        return cls(
            x402_version=_u64(obj, "x402Version", what),
            resource=_opt(obj, "resource", ResourceInfo.from_dict),
            accepts=[BatchRequirements.from_dict(entry) for entry in cast("list[Any]", accepts_raw)],
            error=_opt_str(obj, "error", what),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"x402Version": self.x402_version}
        _put(out, "resource", None if self.resource is None else self.resource.to_dict())
        out["accepts"] = [entry.to_dict() for entry in self.accepts]
        _put(out, "error", self.error)
        return out


# ── client payload objects ────────────────────────────────────────────────


@dataclass(frozen=True)
class BatchChannelConfig:
    """Channel configuration, carried on every client payload.

    Every field is a channel-PDA seed or an immutable channel property.
    """

    payer: str
    payer_authorizer: str
    receiver: str
    token: str
    withdraw_delay: int
    salt: str
    open_slot: int
    receiver_authorizer: str | None = None
    voucher_signer: str | None = None

    @classmethod
    def from_dict(cls, value: Any) -> BatchChannelConfig:
        what = "channelConfig"
        obj = _object(value, what)
        return cls(
            payer=_str(obj, "payer", what),
            payer_authorizer=_str(obj, "payerAuthorizer", what),
            receiver=_str(obj, "receiver", what),
            receiver_authorizer=_opt_str(obj, "receiverAuthorizer", what),
            token=_str(obj, "token", what),
            withdraw_delay=_int_in(_req(obj, "withdrawDelay", what), 0, _U32_MAX, "channelConfig.withdrawDelay"),
            salt=_str(obj, "salt", what),
            open_slot=_u64(obj, "openSlot", what),
            voucher_signer=_opt_str(obj, "voucherSigner", what),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "payer": self.payer,
            "payerAuthorizer": self.payer_authorizer,
            "receiver": self.receiver,
        }
        _put(out, "receiverAuthorizer", self.receiver_authorizer)
        out["token"] = self.token
        out["withdrawDelay"] = self.withdraw_delay
        out["salt"] = self.salt
        out["openSlot"] = self.open_slot
        _put(out, "voucherSigner", self.voucher_signer)
        return out

    def salt_value(self) -> int:
        return parse_amount(self.salt, "channelConfig.salt")


@dataclass(frozen=True)
class BatchVoucher:
    """A signed cumulative voucher: the offchain authorization for one request."""

    channel_id: str
    max_claimable_amount: str
    expires_at: int
    signature: str

    @classmethod
    def from_dict(cls, value: Any) -> BatchVoucher:
        what = "voucher"
        obj = _object(value, what)
        return cls(
            channel_id=_str(obj, "channelId", what),
            max_claimable_amount=_str(obj, "maxClaimableAmount", what),
            expires_at=_i64(obj, "expiresAt", what),
            signature=_str(obj, "signature", what),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "channelId": self.channel_id,
            "maxClaimableAmount": self.max_claimable_amount,
            "expiresAt": self.expires_at,
            "signature": self.signature,
        }

    def max_claimable(self) -> int:
        return parse_amount(self.max_claimable_amount, "voucher.maxClaimableAmount")

    def commitment_id(self) -> str:
        """``channelId:maxClaimableAmount``, the settlement ``commitmentId``."""
        return f"{self.channel_id}:{self.max_claimable_amount}"


@dataclass(frozen=True)
class BatchAuthorization:
    """The expiring payer proof of server mode (``BatchAuthorization``, spec 4.2)."""

    channel_id: str
    payer: str
    request_id: str
    authorized_amount: str
    expires_at: int
    signature: str
    kind: str = "proof"

    @classmethod
    def from_dict(cls, value: Any) -> BatchAuthorization:
        what = "authorization"
        obj = _object(value, what)
        return cls(
            kind=_str(obj, "type", what),
            channel_id=_str(obj, "channelId", what),
            payer=_str(obj, "payer", what),
            request_id=_str(obj, "requestId", what),
            authorized_amount=_str(obj, "authorizedAmount", what),
            expires_at=_i64(obj, "expiresAt", what),
            signature=_str(obj, "signature", what),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.kind,
            "channelId": self.channel_id,
            "payer": self.payer,
            "requestId": self.request_id,
            "authorizedAmount": self.authorized_amount,
            "expiresAt": self.expires_at,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class CloseAuthorization:
    """The receiver authorizer's signature binding one exact cooperative close."""

    valid_before: int
    signature: str

    @classmethod
    def from_dict(cls, value: Any) -> CloseAuthorization:
        what = "closeAuthorization"
        obj = _object(value, what)
        return cls(valid_before=_i64(obj, "validBefore", what), signature=_str(obj, "signature", what))

    def to_dict(self) -> dict[str, Any]:
        return {"validBefore": self.valid_before, "signature": self.signature}


@dataclass(frozen=True)
class BatchDeposit:
    """The escrow funding carried on a ``deposit`` payload."""

    amount: str
    transaction: str

    @classmethod
    def from_dict(cls, value: Any) -> BatchDeposit:
        what = "deposit"
        obj = _object(value, what)
        return cls(amount=_str(obj, "amount", what), transaction=_str(obj, "transaction", what))

    def to_dict(self) -> dict[str, Any]:
        return {"amount": self.amount, "transaction": self.transaction}

    def amount_units(self) -> int:
        return parse_amount(self.amount, "deposit.amount")


@dataclass(frozen=True)
class BatchPayload:
    """The client authorization in ``PAYMENT-SIGNATURE.payload``: a tagged union on ``type``.

    ``type`` is one of ``deposit`` (open or top up, plus this request's
    voucher), ``voucher`` (steady state), ``authorization`` (server-mode payer
    proof) or ``refund`` (close and return the unused escrow).
    """

    type: str
    channel_config: BatchChannelConfig
    voucher: BatchVoucher | None = None
    deposit: BatchDeposit | None = None
    authorization: BatchAuthorization | None = None
    #: ``refund`` only: payer-signed ``request_close`` (retry after the binding was unavailable).
    transaction: str | None = None
    #: ``refund`` only: added by the server before forwarding; never client-authored.
    close_authorization: CloseAuthorization | None = None
    #: ``refund`` only: a partial-refund amount, which this scheme refuses.
    amount: str | None = None

    @classmethod
    def from_dict(cls, value: Any) -> BatchPayload:
        what = "payload"
        obj = _object(value, what)
        kind = _str(obj, "type", what)
        config = BatchChannelConfig.from_dict(_req(obj, "channelConfig", what))
        if kind == "deposit":
            return cls(
                type=kind,
                channel_config=config,
                voucher=_opt(obj, "voucher", BatchVoucher.from_dict),
                deposit=BatchDeposit.from_dict(_req(obj, "deposit", what)),
                authorization=_opt(obj, "authorization", BatchAuthorization.from_dict),
            )
        if kind == "voucher":
            return cls(type=kind, channel_config=config, voucher=BatchVoucher.from_dict(_req(obj, "voucher", what)))
        if kind == "authorization":
            return cls(
                type=kind,
                channel_config=config,
                authorization=BatchAuthorization.from_dict(_req(obj, "authorization", what)),
            )
        if kind == "refund":
            voucher = _opt(obj, "voucher", BatchVoucher.from_dict)
            authorization = _opt(obj, "authorization", BatchAuthorization.from_dict)
            if voucher is None and authorization is None:
                raise BatchWireError(
                    f"{INVALID_PAYLOAD_TYPE}: a refund carries the accepted voucher in client mode or the "
                    "payer authorization in server mode, and this one carries neither"
                )
            if voucher is not None and authorization is not None:
                raise BatchWireError(
                    f"{INVALID_PAYLOAD_TYPE}: a refund carries a voucher (client mode) or an authorization "
                    "(server mode), not both"
                )
            return cls(
                type=kind,
                channel_config=config,
                voucher=voucher,
                authorization=authorization,
                transaction=_opt_str(obj, "transaction", what),
                close_authorization=_opt(obj, "closeAuthorization", CloseAuthorization.from_dict),
                amount=_opt_str(obj, "amount", what),
            )
        raise BatchWireError(
            f"unknown variant `{kind}`, expected one of `deposit`, `voucher`, `authorization`, `refund`"
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type, "channelConfig": self.channel_config.to_dict()}
        _put(out, "voucher", None if self.voucher is None else self.voucher.to_dict())
        _put(out, "deposit", None if self.deposit is None else self.deposit.to_dict())
        _put(out, "authorization", None if self.authorization is None else self.authorization.to_dict())
        _put(out, "transaction", self.transaction)
        _put(
            out, "closeAuthorization", None if self.close_authorization is None else self.close_authorization.to_dict()
        )
        _put(out, "amount", self.amount)
        return out

    def charge_voucher(self) -> BatchVoucher | None:
        """The voucher this payload charges with: ``None`` for ``refund`` and ``authorization``."""
        if self.type in ("deposit", "voucher"):
            return self.voucher
        return None


#: A ``refund`` payload (``BatchPayload`` with ``type == "refund"``).
BatchRefund = BatchPayload


@dataclass(frozen=True)
class BatchPaymentPayload:
    """The ``PAYMENT-SIGNATURE`` envelope of a ``batch-settlement`` payment."""

    x402_version: int
    accepted: BatchRequirements
    payload: BatchPayload

    @classmethod
    def from_dict(cls, value: Any) -> BatchPaymentPayload:
        what = "paymentPayload"
        obj = _object(value, what)
        return cls(
            x402_version=_u64(obj, "x402Version", what),
            accepted=BatchRequirements.from_dict(_req(obj, "accepted", what)),
            payload=BatchPayload.from_dict(_req(obj, "payload", what)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "x402Version": self.x402_version,
            "accepted": self.accepted.to_dict(),
            "payload": self.payload.to_dict(),
        }


# ── server-authored redemption payloads ───────────────────────────────────


@dataclass(frozen=True)
class BatchVoucherClaim:
    """One channel in a ``claim`` batch."""

    channel_id: str
    channel_config: BatchChannelConfig
    voucher: BatchVoucher

    @classmethod
    def from_dict(cls, value: Any) -> BatchVoucherClaim:
        what = "claim"
        obj = _object(value, what)
        return cls(
            channel_id=_str(obj, "channelId", what),
            channel_config=BatchChannelConfig.from_dict(_req(obj, "channelConfig", what)),
            voucher=BatchVoucher.from_dict(_req(obj, "voucher", what)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "channelId": self.channel_id,
            "channelConfig": self.channel_config.to_dict(),
            "voucher": self.voucher.to_dict(),
        }


@dataclass(frozen=True)
class BatchSettleChannel:
    """One channel in a ``settle`` batch."""

    channel_id: str
    channel_config: BatchChannelConfig

    @classmethod
    def from_dict(cls, value: Any) -> BatchSettleChannel:
        what = "channel"
        obj = _object(value, what)
        return cls(
            channel_id=_str(obj, "channelId", what),
            channel_config=BatchChannelConfig.from_dict(_req(obj, "channelConfig", what)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"channelId": self.channel_id, "channelConfig": self.channel_config.to_dict()}


def _batch(value: Any, key: str, parse: Callable[[Any], T], maximum: int) -> list[T]:
    if not isinstance(value, list):
        raise BatchWireError(f"{key} must be an array")
    entries = [parse(entry) for entry in cast("list[Any]", value)]
    if not 1 <= len(entries) <= maximum:
        raise BatchWireError(f"a redemption batch must carry 1 through {maximum} entries, got {len(entries)}")
    return entries


@dataclass(frozen=True)
class BatchClaim:
    """``claim``: one to :data:`V1_MAX_CLAIM_CHANNELS` channels; program ``settle``."""

    claims: list[BatchVoucherClaim]

    def __post_init__(self) -> None:
        if not 1 <= len(self.claims) <= V1_MAX_CLAIM_CHANNELS:
            raise BatchWireError(
                f"a redemption batch must carry 1 through {V1_MAX_CLAIM_CHANNELS} entries, got {len(self.claims)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"type": "claim", "claims": [entry.to_dict() for entry in self.claims]}


@dataclass(frozen=True)
class BatchSettle:
    """``settle``: one to :data:`V1_MAX_SETTLE_CHANNELS` channels; program ``distribute``."""

    channels: list[BatchSettleChannel]

    def __post_init__(self) -> None:
        if not 1 <= len(self.channels) <= V1_MAX_SETTLE_CHANNELS:
            raise BatchWireError(
                f"a redemption batch must carry 1 through {V1_MAX_SETTLE_CHANNELS} entries, got {len(self.channels)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"type": "settle", "channels": [entry.to_dict() for entry in self.channels]}


@dataclass(frozen=True)
class BatchSeal:
    """``seal``: finalize a ``Closing`` channel with the latest voucher."""

    channel_id: str
    channel_config: BatchChannelConfig
    voucher: BatchVoucher
    close_authorization: CloseAuthorization | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "type": "seal",
            "channelId": self.channel_id,
            "channelConfig": self.channel_config.to_dict(),
            "voucher": self.voucher.to_dict(),
        }
        _put(
            out, "closeAuthorization", None if self.close_authorization is None else self.close_authorization.to_dict()
        )
        return out


BatchRedemptionPayload = BatchClaim | BatchSettle | BatchSeal


def parse_redemption(value: Any) -> BatchRedemptionPayload:
    """Parse a server-authored ``claim``, ``settle`` or ``seal`` payload."""
    what = "redemption"
    obj = _object(value, what)
    kind = _str(obj, "type", what)
    if kind == "claim":
        return BatchClaim(
            _batch(_req(obj, "claims", what), "claims", BatchVoucherClaim.from_dict, V1_MAX_CLAIM_CHANNELS)
        )
    if kind == "settle":
        return BatchSettle(
            _batch(_req(obj, "channels", what), "channels", BatchSettleChannel.from_dict, V1_MAX_SETTLE_CHANNELS)
        )
    if kind == "seal":
        return BatchSeal(
            channel_id=_str(obj, "channelId", what),
            channel_config=BatchChannelConfig.from_dict(_req(obj, "channelConfig", what)),
            voucher=BatchVoucher.from_dict(_req(obj, "voucher", what)),
            close_authorization=_opt(obj, "closeAuthorization", CloseAuthorization.from_dict),
        )
    raise BatchWireError(f"unknown variant `{kind}`, expected one of `claim`, `settle`, `seal`")


# ── responses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BatchSettlementExtra:
    """Scheme fields nested under ``SettlementResponse.extra``."""

    commitment_id: str | None = None
    charged_amount: str | None = None
    channel_state: ChannelStateSnapshot | None = None
    voucher: BatchVoucher | None = None

    @classmethod
    def from_dict(cls, value: Any) -> BatchSettlementExtra:
        what = "extra"
        obj = _object(value, what)
        return cls(
            commitment_id=_opt_str(obj, "commitmentId", what),
            charged_amount=_opt_str(obj, "chargedAmount", what),
            channel_state=_opt(obj, "channelState", ChannelStateSnapshot.from_dict),
            voucher=_opt(obj, "voucher", BatchVoucher.from_dict),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        _put(out, "commitmentId", self.commitment_id)
        _put(out, "chargedAmount", self.charged_amount)
        _put(out, "channelState", None if self.channel_state is None else self.channel_state.to_dict())
        _put(out, "voucher", None if self.voucher is None else self.voucher.to_dict())
        return out


@dataclass(frozen=True)
class BatchSettlementResponse:
    """The ``PAYMENT-RESPONSE`` settlement result."""

    success: bool
    transaction: str
    network: str
    amount: str = ""
    error_reason: str | None = None
    payer: str | None = None
    extra: BatchSettlementExtra | None = None

    @classmethod
    def from_dict(cls, value: Any) -> BatchSettlementResponse:
        what = "settlementResponse"
        obj = _object(value, what)
        amount = obj.get("amount")
        if amount is not None and not isinstance(amount, str):
            raise BatchWireError("settlementResponse.amount must be a string")
        return cls(
            success=_bool(obj, "success", what),
            error_reason=_opt_str(obj, "errorReason", what),
            payer=_opt_str(obj, "payer", what),
            transaction=_str(obj, "transaction", what),
            network=_str(obj, "network", what),
            amount=amount if isinstance(amount, str) else "",
            extra=_opt(obj, "extra", BatchSettlementExtra.from_dict),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"success": self.success}
        _put(out, "errorReason", self.error_reason)
        _put(out, "payer", self.payer)
        out["transaction"] = self.transaction
        out["network"] = self.network
        out["amount"] = self.amount
        _put(out, "extra", None if self.extra is None else self.extra.to_dict())
        return out

    @classmethod
    def failure(cls, network: str, reason: str, payer: str | None = None) -> BatchSettlementResponse:
        return cls(success=False, error_reason=reason, payer=payer, transaction="", network=network)

    def channel_state(self) -> ChannelStateSnapshot | None:
        return None if self.extra is None else self.extra.channel_state


def wire_roundtrip(shape: str, value: Any) -> dict[str, Any]:
    """Parse ``value`` as the wire ``shape`` and re-encode it canonically."""
    parsers: dict[str, Callable[[Any], Any]] = {
        "requirements": BatchRequirements.from_dict,
        "paymentPayload": BatchPaymentPayload.from_dict,
        "payload": BatchPayload.from_dict,
        "redemption": parse_redemption,
        "settlementResponse": BatchSettlementResponse.from_dict,
        "paymentRequired": BatchRequiredEnvelope.from_dict,
    }
    parser = parsers.get(shape)
    if parser is None:
        raise ValueError(f"unknown batch-settlement wire shape {shape!r}")
    return cast("dict[str, Any]", parser(value).to_dict())
