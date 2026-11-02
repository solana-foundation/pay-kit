"""Subscription intent request type and supporting payloads.

The subscription intent (draft-solana-subscription-00) is a recurring
fixed-amount payment authorized once per billing period through an on-chain
delegation. Activation atomically creates the delegation and executes the
first billing-period charge; renewals are server-driven on-chain transactions
and produce no HTTP credentials.

Parsing is strict and mirrors the Rust kit's serde shapes
(``rust/crates/kit/src/mpp/protocol/intents/subscription.rs``): required
fields must be present with their JSON type, optional fields may be absent or
``null``, unknown fields are ignored, and every format the profile constrains
(amount and period counts, the period mapping, addresses, the token program)
is checked once by :meth:`SubscriptionRequest.terms`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from solana_pay_kit._paycore.solana import TOKEN_2022_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit._paycore.txv1 import TransactionVersionError, parse_transaction_versions
from solana_pay_kit.protocols.mpp.core.json import encode_canonical
from solana_pay_kit.protocols.mpp.program.subscriptions import parse_pubkey

#: Domain separator of the reusable subscription bearer proof.
SUBSCRIPTION_AUTHENTICATION_DOMAIN = "mpp-subscription-auth-v1"

#: The program's ``period_hours`` bound.
MAX_PERIOD_HOURS = 8760

_U8_MAX = (1 << 8) - 1
_U64_MAX = (1 << 64) - 1
_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1

SubscriptionPeriodUnit = Literal["day", "week"]


class SubscriptionError(ValueError):
    """A subscription wire value or request term is malformed or out of profile."""


# ── Strict field readers (serde semantics) ────────────────────────────────────


def _object(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SubscriptionError(f"invalid type: expected {what} to be a JSON object")
    return value


def _required_str(data: dict[str, Any], key: str) -> str:
    if key not in data:
        raise SubscriptionError(f"missing field `{key}`")
    value = data[key]
    if not isinstance(value, str):
        raise SubscriptionError(f"invalid type for `{key}`: expected a string")
    return value


def _optional_str(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise SubscriptionError(f"invalid type for `{key}`: expected a string")
    return value


def _optional_int(data: dict[str, Any], key: str, low: int, high: int) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise SubscriptionError(f"invalid type for `{key}`: expected an integer")
    if value < low or value > high:
        raise SubscriptionError(f"invalid value for `{key}`: {value} is out of range")
    return value


def parse_period_unit(value: Any) -> SubscriptionPeriodUnit:
    """``day`` or ``week``; ``month`` (and anything else) is not representable."""
    if value == "day":
        return "day"
    if value == "week":
        return "week"
    if isinstance(value, str):
        raise SubscriptionError(f"unknown variant `{value}`, expected `day` or `week`")
    raise SubscriptionError("invalid type for `periodUnit`: expected a string")


def parse_positive_integer(value: str, field: str) -> int:
    """A positive base-10 integer in canonical form, at most ``u64::MAX``.

    ASCII digits only: no sign, decimal point, exponent, whitespace or leading
    zero (draft-solana-subscription-00 §Optional Fields).
    """

    def invalid(why: str) -> SubscriptionError:
        return SubscriptionError(f"Invalid {field} {value!r}: {why}")

    if value == "":
        raise invalid("empty")
    if not all("0" <= ch <= "9" for ch in value):
        raise invalid("must be a base-10 integer with no sign, decimal point, exponent or whitespace")
    if value.startswith("0"):
        raise invalid("must be positive with no leading zero")
    parsed = int(value)
    if parsed > _U64_MAX:
        raise invalid("out of range")
    return parsed


def period_hours_for(unit: SubscriptionPeriodUnit, count: int) -> int:
    """Map ``(unit, count)`` to the program's ``period_hours``."""
    if count == 0:
        raise SubscriptionError("periodCount must be a positive integer")
    if unit == "day":
        if count > 365:
            raise SubscriptionError(f'periodCount={count} for periodUnit="day" exceeds 365')
        hours = count * 24
    else:
        if count > 52:
            raise SubscriptionError(f'periodCount={count} for periodUnit="week" exceeds 52')
        hours = count * 168
    if hours == 0 or hours > MAX_PERIOD_HOURS:
        raise SubscriptionError(f"period_hours {hours} out of [1, {MAX_PERIOD_HOURS}] range")
    return hours


def billing_period_hours(unit: SubscriptionPeriodUnit, count: str) -> int:
    """Parse ``periodCount`` in canonical form and map it to hours."""
    return period_hours_for(unit, parse_positive_integer(count, "periodCount"))


# ── Bearer proof ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SubscriptionAuthentication:
    """Reusable payer proof bound to one activation challenge and delegation."""

    challenge_id: str
    payer: str
    signature: str
    type: Literal["proof"] = "proof"

    def message_bytes(self, subscription_delegation: str) -> bytes:
        """The RFC 8785 (JCS) message the subscriber signs."""
        return encode_canonical(
            {
                "domain": SUBSCRIPTION_AUTHENTICATION_DOMAIN,
                "payer": self.payer,
                "subscriptionChallengeId": self.challenge_id,
                "subscriptionDelegation": subscription_delegation,
            }
        )

    def verify(self, subscription_delegation: str) -> bool:
        """Verify the Ed25519 proof against ``payer`` and the bound delegation.

        Raises :class:`SubscriptionError` when ``payer`` or ``signature`` is
        not a well-formed key or signature; returns ``False`` when the
        signature does not verify.
        """
        try:
            payer = Pubkey.from_string(self.payer)
        except (TypeError, ValueError) as exc:
            raise SubscriptionError(f"payer must be a 32-byte base58 key: {exc}") from exc
        try:
            signature = Signature.from_string(self.signature)
        except (TypeError, ValueError) as exc:
            raise SubscriptionError(f"signature must be a 64-byte base58 signature: {exc}") from exc
        return bool(signature.verify(payer, self.message_bytes(subscription_delegation)))

    def to_dict(self) -> dict[str, str]:
        return {"type": self.type, "challengeId": self.challenge_id, "payer": self.payer, "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> SubscriptionAuthentication:
        data = _object(data, "authentication")
        kind = _required_str(data, "type")
        if kind != "proof":
            raise SubscriptionError(f"unknown variant `{kind}` for authentication.type, expected `proof`")
        return cls(
            challenge_id=_required_str(data, "challengeId"),
            payer=_required_str(data, "payer"),
            signature=_required_str(data, "signature"),
        )


# ── Method details ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SubscriptionMethodDetails:
    """Typed ``methodDetails`` of the Solana subscription intent.

    ``planAddress``, ``mint``, ``tokenProgram`` and ``puller`` must be present
    to parse; :meth:`validate` then requires the spec's REQUIRED fields to be
    non-empty. The ``merchant`` .. ``expectedCreatedAt`` fields are server
    extensions; clients read the plan from the chain instead.
    """

    plan_address: str
    mint: str
    token_program: str
    puller: str
    decimals: int | None = None
    merchant: str | None = None
    recipient: str | None = None
    amount: str | None = None
    subscription_program: str | None = None
    network: str | None = None
    fee_payer: bool = False
    fee_payer_key: str | None = None
    transaction_versions: list[int] | None = None
    recent_blockhash: str | None = None
    plan_id_numeric: int | None = None
    plan_bump: int | None = None
    expected_period_hours: int | None = None
    expected_created_at: int | None = None

    @classmethod
    def from_json(cls, value: Any) -> SubscriptionMethodDetails:
        try:
            return cls._parse(value)
        except (SubscriptionError, TransactionVersionError) as exc:
            raise SubscriptionError(f"Invalid methodDetails: {exc}") from exc

    @classmethod
    def _parse(cls, value: Any) -> SubscriptionMethodDetails:
        data = _object(value, "methodDetails")
        fee_payer = data.get("feePayer", False)
        if not isinstance(fee_payer, bool):
            raise SubscriptionError("invalid type for `feePayer`: expected a boolean")
        return cls(
            plan_address=_required_str(data, "planAddress"),
            mint=_required_str(data, "mint"),
            token_program=_required_str(data, "tokenProgram"),
            puller=_required_str(data, "puller"),
            decimals=_optional_int(data, "decimals", 0, _U8_MAX),
            merchant=_optional_str(data, "merchant"),
            recipient=_optional_str(data, "recipient"),
            amount=_optional_str(data, "amount"),
            subscription_program=_optional_str(data, "subscriptionProgram"),
            network=_optional_str(data, "network"),
            fee_payer=fee_payer,
            fee_payer_key=_optional_str(data, "feePayerKey"),
            transaction_versions=parse_transaction_versions(data.get("transactionVersions")),
            recent_blockhash=_optional_str(data, "recentBlockhash"),
            plan_id_numeric=_optional_int(data, "planIdNumeric", 0, _U64_MAX),
            plan_bump=_optional_int(data, "planBump", 0, _U8_MAX),
            expected_period_hours=_optional_int(data, "expectedPeriodHours", 0, _U64_MAX),
            expected_created_at=_optional_int(data, "expectedCreatedAt", _I64_MIN, _I64_MAX),
        )

    def validate(self) -> None:
        """Require the spec's REQUIRED fields to be non-empty."""
        if not self.plan_address:
            raise SubscriptionError("methodDetails.planAddress is required")
        if not self.mint:
            raise SubscriptionError("methodDetails.mint is required")
        if not self.token_program:
            raise SubscriptionError("methodDetails.tokenProgram is required")
        if not self.puller:
            raise SubscriptionError("methodDetails.puller is required")
        if self.decimals is None:
            raise SubscriptionError("methodDetails.decimals is required")
        if not self.subscription_program:
            raise SubscriptionError("methodDetails.subscriptionProgram is required")
        if self.fee_payer and self.fee_payer_key is None:
            raise SubscriptionError("methodDetails.feePayerKey is required when feePayer is true")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "planAddress": self.plan_address,
            "mint": self.mint,
            "tokenProgram": self.token_program,
            "puller": self.puller,
        }
        optional: dict[str, Any] = {
            "decimals": self.decimals,
            "merchant": self.merchant,
            "recipient": self.recipient,
            "amount": self.amount,
            "subscriptionProgram": self.subscription_program,
            "network": self.network,
            "feePayerKey": self.fee_payer_key,
            "transactionVersions": self.transaction_versions,
            "recentBlockhash": self.recent_blockhash,
            "planIdNumeric": self.plan_id_numeric,
            "planBump": self.plan_bump,
            "expectedPeriodHours": self.expected_period_hours,
            "expectedCreatedAt": self.expected_created_at,
        }
        out.update({key: value for key, value in optional.items() if value is not None})
        if self.fee_payer:
            out["feePayer"] = True
        return out


# ── Request and terms ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SubscriptionRequest:
    """The ``subscription`` intent request body."""

    amount: str
    currency: str
    period_unit: SubscriptionPeriodUnit
    period_count: str
    recipient: str
    subscription_expires: str | None = None
    description: str | None = None
    external_id: str | None = None
    method_details: Any = None

    @classmethod
    def from_dict(cls, data: Any) -> SubscriptionRequest:
        data = _object(data, "the subscription request")
        if "periodUnit" not in data:
            raise SubscriptionError("missing field `periodUnit`")
        return cls(
            amount=_required_str(data, "amount"),
            currency=_required_str(data, "currency"),
            period_unit=parse_period_unit(data["periodUnit"]),
            period_count=_required_str(data, "periodCount"),
            recipient=_required_str(data, "recipient"),
            subscription_expires=_optional_str(data, "subscriptionExpires"),
            description=_optional_str(data, "description"),
            external_id=_optional_str(data, "externalId"),
            method_details=data.get("methodDetails"),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "amount": self.amount,
            "currency": self.currency,
            "periodUnit": self.period_unit,
            "periodCount": self.period_count,
            "recipient": self.recipient,
        }
        optional = {
            "subscriptionExpires": self.subscription_expires,
            "description": self.description,
            "externalId": self.external_id,
            "methodDetails": self.method_details,
        }
        out.update({key: value for key, value in optional.items() if value is not None})
        return out

    def parse_amount(self) -> int:
        return parse_positive_integer(self.amount, "amount")

    def parse_period_count(self) -> int:
        return parse_positive_integer(self.period_count, "periodCount")

    def period_hours(self) -> int:
        """The on-chain ``period_hours``, validating the mapping and bound."""
        return billing_period_hours(self.period_unit, self.period_count)

    def terms(self) -> SubscriptionTerms:
        """Parse the request into :class:`SubscriptionTerms`."""
        return SubscriptionTerms.parse(self)


def parse_token_program(value: str) -> Pubkey:
    """SPL Token or Token-2022; any other program is refused."""
    program = parse_pubkey(value, "tokenProgram")
    if str(program) not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        raise SubscriptionError(f"methodDetails.tokenProgram {value} is neither SPL Token nor Token-2022")
    return program


@dataclass(frozen=True)
class SubscriptionTerms:
    """A request that passed every format and consistency check of the profile.

    Built only by :meth:`SubscriptionRequest.terms`. ``fee_payer`` is the
    server's ``feePayerKey`` when the server sponsors fees, else ``None``.
    """

    amount: int
    mint: Pubkey
    period_unit: SubscriptionPeriodUnit
    period_count: int
    period_hours: int
    recipient: Pubkey
    subscription_expires: str | None
    external_id: str | None
    plan_address: Pubkey
    token_program: Pubkey
    decimals: int
    puller: Pubkey
    subscription_program: Pubkey
    network: str
    fee_payer: Pubkey | None
    recent_blockhash: Hash | None
    transaction_versions: list[int] | None

    @classmethod
    def parse(cls, request: SubscriptionRequest) -> SubscriptionTerms:
        amount = request.parse_amount()
        count = request.parse_period_count()
        hours = period_hours_for(request.period_unit, count)
        recipient = parse_pubkey(request.recipient, "recipient")
        if request.method_details is None:
            raise SubscriptionError("Subscription request is missing methodDetails")
        details = SubscriptionMethodDetails.from_json(request.method_details)
        details.validate()
        mint = parse_pubkey(details.mint, "methodDetails.mint")
        if parse_pubkey(request.currency, "currency") != mint:
            raise SubscriptionError("Subscription currency must match methodDetails.mint")
        assert details.decimals is not None  # validate() requires it
        fee_payer: Pubkey | None = None
        if details.fee_payer:
            assert details.fee_payer_key is not None  # validate() requires it
            fee_payer = parse_pubkey(details.fee_payer_key, "feePayerKey")
        recent_blockhash: Hash | None = None
        if details.recent_blockhash is not None:
            try:
                recent_blockhash = Hash.from_string(details.recent_blockhash)
            except Exception as exc:  # noqa: BLE001 - solders raises ParseHashError, not ValueError
                raise SubscriptionError(f"Invalid recentBlockhash: {exc}") from exc
        return cls(
            amount=amount,
            mint=mint,
            period_unit=request.period_unit,
            period_count=count,
            period_hours=hours,
            recipient=recipient,
            subscription_expires=request.subscription_expires,
            external_id=request.external_id,
            plan_address=parse_pubkey(details.plan_address, "planAddress"),
            token_program=parse_token_program(details.token_program),
            decimals=details.decimals,
            puller=parse_pubkey(details.puller, "puller"),
            subscription_program=parse_pubkey(details.subscription_program or "", "subscriptionProgram"),
            network=details.network if details.network is not None else "mainnet",
            fee_payer=fee_payer,
            recent_blockhash=recent_blockhash,
            transaction_versions=details.transaction_versions,
        )


# ── Credential payloads ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class ActivatePayload:
    """Activation payload: ``type="transaction"`` (server broadcasts) or
    ``type="signature"`` (client broadcast), with the REQUIRED bearer proof."""

    type: str
    authentication: SubscriptionAuthentication
    transaction: str | None = None
    signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type, "authentication": self.authentication.to_dict()}
        if self.transaction is not None:
            out["transaction"] = self.transaction
        if self.signature is not None:
            out["signature"] = self.signature
        return out

    @classmethod
    def from_dict(cls, data: Any) -> ActivatePayload:
        data = _object(data, "the activation payload")
        kind = _required_str(data, "type")
        transaction = _optional_str(data, "transaction")
        signature = _optional_str(data, "signature")
        if "authentication" not in data:
            raise SubscriptionError("missing field `authentication`")
        return cls(
            type=kind,
            transaction=transaction,
            signature=signature,
            authentication=SubscriptionAuthentication.from_dict(data["authentication"]),
        )


@dataclass(frozen=True)
class SubscriptionAccessPayload:
    """Later-access payload: the retained proof and the delegation it binds."""

    subscription_delegation: str
    authentication: SubscriptionAuthentication
    type: Literal["proof"] = "proof"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "subscriptionDelegation": self.subscription_delegation,
            "authentication": self.authentication.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Any) -> SubscriptionAccessPayload:
        data = _object(data, "the access payload")
        kind = _required_str(data, "type")
        if kind != "proof":
            raise SubscriptionError(f"unknown variant `{kind}` for type, expected `proof`")
        delegation = _required_str(data, "subscriptionDelegation")
        if "authentication" not in data:
            raise SubscriptionError("missing field `authentication`")
        return cls(
            subscription_delegation=delegation,
            authentication=SubscriptionAuthentication.from_dict(data["authentication"]),
        )


def decode_activate_payload(payload: Any) -> ActivatePayload:
    """The activation payload of a credential.

    Accepts the spec's raw shape and the tagged ``{"action": "activate", ...}``
    wrapper; a payload without ``authentication`` is reported as a missing
    proof rather than a decode failure.
    """
    data = _object(payload, "the credential payload")
    try:
        return ActivatePayload.from_dict(data)
    except SubscriptionError as exc:
        if "authentication" not in data:
            raise SubscriptionError('Subscription activation is missing authentication.type="proof"') from exc
        raise SubscriptionError(f"Failed to decode payload: {exc}") from exc
