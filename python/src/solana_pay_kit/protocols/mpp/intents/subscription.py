"""Subscription intent request, credential payload and bearer-proof types.

A subscription is a fixed amount pulled once per billing period through an
on-chain ``SubscriptionDelegation``. Activation creates the delegation and
collects the first period in one transaction; later requests present a reusable
Ed25519 bearer proof bound to the activation challenge and the delegation.

Wire format: the Solana subscription profile (mpp-specs PR #310) and the Rust
reference in ``rust/crates/kit/src/mpp/protocol/intents/subscription.rs``.
Wire keys are camelCase; ``amount`` and ``periodCount`` are canonical
positive integer strings (no sign, no leading zeros, at most ``u64``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, cast

from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from solana_pay_kit._paycore.solana import TOKEN_2022_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit.protocols.mpp.core.expires import parse_rfc3339
from solana_pay_kit.protocols.mpp.core.json import encode_canonical

__all__ = [
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

#: Domain separator signed into every subscription bearer proof.
SUBSCRIPTION_AUTHENTICATION_DOMAIN = "mpp-subscription-auth-v1"

#: Billing period unit. ``month`` is not representable on chain and is rejected.
PeriodUnit = Literal["day", "week"]

_U64_MAX = 2**64 - 1
_I64_MIN, _I64_MAX = -(2**63), 2**63 - 1
_CANONICAL_POSITIVE = re.compile(r"[1-9][0-9]*")
_TOKEN_PROGRAMS = (TOKEN_PROGRAM, TOKEN_2022_PROGRAM)
_NETWORKS = ("mainnet", "devnet", "testnet", "localnet")


def parse_positive_u64(raw: object, name: str) -> int:
    """Parse a canonical positive integer string (``^[1-9][0-9]*$``) that fits in ``u64``."""
    if not isinstance(raw, str) or not _CANONICAL_POSITIVE.fullmatch(raw):
        raise ValueError(f"{name} must be a positive integer string without sign or leading zeros")
    value = int(raw)
    if value > _U64_MAX:
        raise ValueError(f"{name} exceeds u64")
    return value


def period_hours(unit: PeriodUnit, count: int) -> int:
    """Map ``(periodUnit, periodCount)`` to the program's ``period_hours`` (1..8760)."""
    limit, hours = (365, 24) if unit == "day" else (52, 168)
    if not 1 <= count <= limit:
        raise ValueError(f'periodCount={count} for periodUnit="{unit}" must be between 1 and {limit}')
    return count * hours


def _string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} is required and must be a non-empty string")
    return value


def _optional_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _pubkey(data: dict[str, Any], key: str, *, required: bool = True) -> str:
    value = _string(data, key) if required else _optional_string(data, key)
    if value:
        try:
            Pubkey.from_string(value)
        except ValueError as exc:
            raise ValueError(f"{key} is not a base58 public key") from exc
    return value


def _int(data: dict[str, Any], key: str, low: int, high: int, *, required: bool = False) -> int | None:
    value = data.get(key)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{key} must be an integer between {low} and {high}")
    return value


def _put(out: dict[str, Any], key: str, value: object) -> None:
    if value not in ("", None):
        out[key] = value


@dataclass(frozen=True)
class SubscriptionMethodDetails:
    """Solana ``methodDetails`` for the subscription intent, plus the optional Rust plan extensions."""

    plan_address: str
    mint: str
    decimals: int
    token_program: str
    puller: str
    subscription_program: str
    network: str = "mainnet"
    fee_payer: bool = False
    fee_payer_key: str = ""
    recent_blockhash: str = ""
    # Server extensions emitted by the Rust reference. Clients never require
    # them; when present they must agree with the on-chain plan.
    merchant: str = ""
    recipient: str = ""
    amount: str = ""
    plan_id_numeric: int | None = None
    plan_bump: int | None = None
    expected_period_hours: int | None = None
    expected_created_at: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the camelCase wire object, omitting unset optional fields."""
        out: dict[str, Any] = {
            "planAddress": self.plan_address,
            "mint": self.mint,
            "decimals": self.decimals,
            "tokenProgram": self.token_program,
            "puller": self.puller,
            "subscriptionProgram": self.subscription_program,
            "network": self.network,
        }
        if self.fee_payer:
            out["feePayer"] = True
        _put(out, "feePayerKey", self.fee_payer_key)
        _put(out, "recentBlockhash", self.recent_blockhash)
        _put(out, "merchant", self.merchant)
        _put(out, "recipient", self.recipient)
        _put(out, "amount", self.amount)
        _put(out, "planIdNumeric", self.plan_id_numeric)
        _put(out, "planBump", self.plan_bump)
        _put(out, "expectedPeriodHours", self.expected_period_hours)
        _put(out, "expectedCreatedAt", self.expected_created_at)
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubscriptionMethodDetails:
        """Parse and validate the wire object; unknown keys are ignored."""
        token_program = _string(data, "tokenProgram")
        if token_program not in _TOKEN_PROGRAMS:
            raise ValueError("tokenProgram must be the SPL Token or Token-2022 program")
        fee_payer = data.get("feePayer", False)
        if not isinstance(fee_payer, bool):
            raise ValueError("feePayer must be a boolean")
        fee_payer_key = _pubkey(data, "feePayerKey", required=fee_payer)
        amount = _optional_string(data, "amount")
        if amount:
            parse_positive_u64(amount, "methodDetails.amount")
        network = data.get("network", "mainnet")
        if network not in _NETWORKS:
            raise ValueError(f"network must be one of {', '.join(_NETWORKS)}, got {network!r}")
        return cls(
            plan_address=_pubkey(data, "planAddress"),
            mint=_pubkey(data, "mint"),
            decimals=cast(int, _int(data, "decimals", 0, 255, required=True)),
            token_program=token_program,
            puller=_pubkey(data, "puller"),
            subscription_program=_pubkey(data, "subscriptionProgram"),
            network=network,
            fee_payer=fee_payer,
            fee_payer_key=fee_payer_key,
            recent_blockhash=_optional_string(data, "recentBlockhash"),
            merchant=_pubkey(data, "merchant", required=False),
            recipient=_pubkey(data, "recipient", required=False),
            amount=amount,
            plan_id_numeric=_int(data, "planIdNumeric", 0, _U64_MAX),
            plan_bump=_int(data, "planBump", 0, 255),
            expected_period_hours=_int(data, "expectedPeriodHours", 1, 8760),
            expected_created_at=_int(data, "expectedCreatedAt", _I64_MIN, _I64_MAX),
        )


@dataclass(frozen=True)
class SubscriptionRequest:
    """Subscription intent request embedded in a 402 challenge."""

    amount: str
    currency: str
    period_unit: PeriodUnit
    period_count: str
    recipient: str
    method_details: SubscriptionMethodDetails
    subscription_expires: str = ""
    description: str = ""
    external_id: str = ""

    def period_hours(self) -> int:
        """Return the mapped per-period interval in hours."""
        return period_hours(self.period_unit, parse_positive_u64(self.period_count, "periodCount"))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the camelCase wire object, omitting empty optional fields."""
        out: dict[str, Any] = {
            "amount": self.amount,
            "currency": self.currency,
            "periodUnit": self.period_unit,
            "periodCount": self.period_count,
            "recipient": self.recipient,
            "methodDetails": self.method_details.to_dict(),
        }
        _put(out, "subscriptionExpires", self.subscription_expires)
        _put(out, "description", self.description)
        _put(out, "externalId", self.external_id)
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubscriptionRequest:
        """Parse and validate the wire object (strict integers, day or week, currency equal to mint)."""
        details = data.get("methodDetails")
        if not isinstance(details, dict):
            raise ValueError("methodDetails is required and must be an object")
        method_details = SubscriptionMethodDetails.from_dict(cast(dict[str, Any], details))
        unit = data.get("periodUnit")
        if unit not in ("day", "week"):
            raise ValueError(f"periodUnit must be 'day' or 'week', got {unit!r}")
        amount = _string(data, "amount")
        parse_positive_u64(amount, "amount")
        currency = _pubkey(data, "currency")
        if currency != method_details.mint:
            raise ValueError("currency must equal methodDetails.mint")
        request = cls(
            amount=amount,
            currency=currency,
            period_unit=unit,
            period_count=_string(data, "periodCount"),
            recipient=_pubkey(data, "recipient"),
            method_details=method_details,
            subscription_expires=_optional_string(data, "subscriptionExpires"),
            description=_optional_string(data, "description"),
            external_id=_optional_string(data, "externalId"),
        )
        request.period_hours()
        if request.subscription_expires:
            parse_rfc3339(request.subscription_expires)
        return request


@dataclass(frozen=True)
class SubscriptionAuthentication:
    """Reusable Ed25519 payer proof bound to one activation challenge and delegation."""

    challenge_id: str
    payer: str
    signature: str
    type: Literal["proof"] = "proof"

    def message_bytes(self, subscription_delegation: str) -> bytes:
        """Return the JCS (RFC 8785) message the payer signs."""
        return encode_canonical(
            {
                "domain": SUBSCRIPTION_AUTHENTICATION_DOMAIN,
                "payer": self.payer,
                "subscriptionChallengeId": self.challenge_id,
                "subscriptionDelegation": subscription_delegation,
            }
        )

    def to_dict(self) -> dict[str, str]:
        """Serialize to the camelCase wire object."""
        return {"type": self.type, "challengeId": self.challenge_id, "payer": self.payer, "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubscriptionAuthentication:
        """Parse the wire object; ``type`` must be ``proof``."""
        if data.get("type") != "proof":
            raise ValueError("authentication.type must be 'proof'")
        return cls(
            challenge_id=_string(data, "challengeId"),
            payer=_string(data, "payer"),
            signature=_string(data, "signature"),
        )


def sign_subscription_authentication(
    challenge_id: str, subscription_delegation: str, signer: Any
) -> SubscriptionAuthentication:
    """Sign a bearer proof with a solana_pay_kit signer (``sign``) or a solders ``Keypair`` (``sign_message``)."""
    unsigned = SubscriptionAuthentication(challenge_id, str(signer.pubkey()), "")
    message = unsigned.message_bytes(subscription_delegation)
    if callable(getattr(signer, "sign", None)):
        signature = Signature.from_bytes(bytes(signer.sign(message)))
    else:
        signature = signer.sign_message(message)
    return SubscriptionAuthentication(challenge_id, unsigned.payer, str(signature))


def verify_subscription_authentication(
    authentication: SubscriptionAuthentication, subscription_delegation: str
) -> bool:
    """Return whether the proof's signature verifies for its payer over ``subscription_delegation``."""
    try:
        payer = Pubkey.from_string(authentication.payer)
        signature = Signature.from_string(authentication.signature)
    except ValueError:
        return False
    return bool(signature.verify(payer, authentication.message_bytes(subscription_delegation)))


@dataclass(frozen=True)
class ActivatePayload:
    """``type="transaction"`` credential payload: the subscriber-signed activation transaction."""

    transaction: str
    authentication: SubscriptionAuthentication

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the camelCase wire object."""
        return {"type": "transaction", "transaction": self.transaction, "authentication": self.authentication.to_dict()}


@dataclass(frozen=True)
class AccessPayload:
    """``type="proof"`` credential payload: the bearer proof for an active subscription."""

    subscription_delegation: str
    authentication: SubscriptionAuthentication

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the camelCase wire object."""
        return {
            "type": "proof",
            "subscriptionDelegation": self.subscription_delegation,
            "authentication": self.authentication.to_dict(),
        }


def parse_subscription_payload(data: dict[str, Any]) -> ActivatePayload | AccessPayload:
    """Parse a credential payload; only ``transaction`` and ``proof`` are defined for this profile."""
    authentication = data.get("authentication")
    if not isinstance(authentication, dict):
        raise ValueError("authentication is required and must be an object")
    proof = SubscriptionAuthentication.from_dict(cast(dict[str, Any], authentication))
    kind = data.get("type")
    if kind == "transaction":
        return ActivatePayload(transaction=_string(data, "transaction"), authentication=proof)
    if kind == "proof":
        return AccessPayload(subscription_delegation=_string(data, "subscriptionDelegation"), authentication=proof)
    raise ValueError(f"subscription payload type must be 'transaction' or 'proof', got {kind!r}")
