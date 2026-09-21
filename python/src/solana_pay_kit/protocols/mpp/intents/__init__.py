"""MPP intent layer: the charge, session and subscription intent request bodies.

Carries the charge intent (:class:`~solana_pay_kit.protocols.mpp.intents.charge.ChargeRequest`,
with string-encoded base-unit amounts so JSON consumers without ``u64`` safety
stay correct) and the session intent (:class:`SessionRequest` plus the
:class:`SessionAction` credential union, signed vouchers, and the metering
types), and the subscription intent (:class:`SubscriptionRequest`, its
credential payloads and the reusable bearer proof). It also re-exports the
:func:`parse_units` helper that converts a human-readable decimal amount into
base units at the SDK boundary. The wire format is defined by the MPP
specification's charge, session and subscription intents.

The individual intent modules
(:mod:`solana_pay_kit.protocols.mpp.intents.charge`,
:mod:`solana_pay_kit.protocols.mpp.intents.session`,
:mod:`solana_pay_kit.protocols.mpp.intents.subscription`) remain the canonical
import path; the session and subscription public types are re-exported here for
convenience.
"""

from __future__ import annotations

from solana_pay_kit.protocols.mpp.intents.charge import (
    ChargeRequest,
    parse_units,
    validate_max_amount,
)
from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    MAX_IDLE_TIMEOUT_SECONDS,
    SESSION_AUTHENTICATION_DOMAIN,
    ClosePayload,
    CommitPayload,
    CommitReceipt,
    CommitStatus,
    MeteredEnvelope,
    MeteringDirective,
    MeteringUsage,
    OpenPayload,
    SessionAction,
    SessionAuthentication,
    SessionMethodDetails,
    SessionRequest,
    SessionSplit,
    SessionVoucherSigner,
    SignedVoucher,
    TopUpPayload,
    UsePayload,
    VoucherData,
    VoucherPayload,
    resolve_idle_timeout_seconds,
    sign_session_authentication,
    validate_idle_timeout_options,
    verify_session_authentication,
)
from solana_pay_kit.protocols.mpp.intents.subscription import (
    SUBSCRIPTION_AUTHENTICATION_DOMAIN,
    AccessPayload,
    ActivatePayload,
    PeriodUnit,
    SubscriptionAuthentication,
    SubscriptionMethodDetails,
    SubscriptionRequest,
    parse_positive_u64,
    parse_subscription_payload,
    period_hours,
    sign_subscription_authentication,
    verify_subscription_authentication,
)

__all__ = [
    # charge intent
    "ChargeRequest",
    "parse_units",
    "validate_max_amount",
    # session intent
    "DEFAULT_SESSION_EXPIRES_AT",
    "MAX_IDLE_TIMEOUT_SECONDS",
    "SESSION_AUTHENTICATION_DOMAIN",
    "SessionVoucherSigner",
    "SessionAuthentication",
    "SessionMethodDetails",
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
    "UsePayload",
    "ClosePayload",
    "MeteringDirective",
    "MeteringUsage",
    "MeteredEnvelope",
    "resolve_idle_timeout_seconds",
    "sign_session_authentication",
    "validate_idle_timeout_options",
    "verify_session_authentication",
    # subscription intent
    "SUBSCRIPTION_AUTHENTICATION_DOMAIN",
    "AccessPayload",
    "ActivatePayload",
    "PeriodUnit",
    "SubscriptionAuthentication",
    "SubscriptionMethodDetails",
    "SubscriptionRequest",
    "parse_positive_u64",
    "parse_subscription_payload",
    "period_hours",
    "sign_subscription_authentication",
    "verify_subscription_authentication",
]
