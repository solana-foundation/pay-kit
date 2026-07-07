"""MPP intent layer: the charge and session intent request bodies.

Carries the charge intent (:class:`~solana_pay_kit.protocols.mpp.intents.charge.ChargeRequest`,
with string-encoded base-unit amounts so JSON consumers without ``u64`` safety
stay correct) and the session intent (:class:`SessionRequest` plus the
:class:`SessionAction` credential union, signed vouchers, and the metering
types). It also re-exports the :func:`parse_units` helper that converts a
human-readable decimal amount into base units at the SDK boundary. The wire
format is defined by the MPP specification's charge and session intents.

The individual intent modules
(:mod:`solana_pay_kit.protocols.mpp.intents.charge`,
:mod:`solana_pay_kit.protocols.mpp.intents.session`) remain the canonical import path;
the session public types are re-exported here for convenience.
"""

from __future__ import annotations

from solana_pay_kit.protocols.mpp.intents.charge import (
    ChargeRequest,
    parse_units,
    validate_max_amount,
)
from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    ClosePayload,
    CommitPayload,
    CommitReceipt,
    CommitStatus,
    MeteredEnvelope,
    MeteringDirective,
    MeteringUsage,
    OpenPayload,
    SessionAction,
    SessionMode,
    SessionPullVoucherStrategy,
    SessionRequest,
    SessionSplit,
    SignedVoucher,
    TopUpPayload,
    VoucherData,
    VoucherPayload,
)

__all__ = [
    # charge intent
    "ChargeRequest",
    "parse_units",
    "validate_max_amount",
    # session intent
    "DEFAULT_SESSION_EXPIRES_AT",
    "SessionMode",
    "SessionPullVoucherStrategy",
    "CommitStatus",
    "SessionSplit",
    "SessionRequest",
    "SessionAction",
    "OpenPayload",
    "VoucherPayload",
    "VoucherData",
    "SignedVoucher",
    "CommitPayload",
    "CommitReceipt",
    "TopUpPayload",
    "ClosePayload",
    "MeteringDirective",
    "MeteringUsage",
    "MeteredEnvelope",
]
