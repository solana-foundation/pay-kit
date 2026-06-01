"""A single protected unit: amount, optional fees, and accepted protocols.

A :class:`Gate` is a frozen value object built once at boot. It carries the
base :class:`~pay_kit.price.Price`, an optional ``pay_to`` override (falling
back to the configured operator recipient), an ordered list of accepted
protocols, and zero or more named fees (``within`` / ``on_top``).

All validation runs in :meth:`Gate.build`; misconfigured gates die at boot,
not at request time. The rules mirror the Ruby/PHP reference:

1. Fixed :class:`Price` amounts only (Decimal under the hood; no floats).
2. One main recipient via ``pay_to`` (defaults to the operator recipient).
3. All fee prices share the gate amount's currency.
4. ``sum(fee_within) <= amount``.
5. No fee recipient may equal ``pay_to`` (fold it into the amount instead),
   and fee recipients must be unique.
6. x402 is auto-disabled when fees are present (stock x402 facilitators
   settle to a single address); an explicit ``accept=(Protocol.X402,)`` on a
   fee-bearing gate raises :class:`~pay_kit.errors.ProtocolIncompatibleError`,
   as does a fee-bearing gate whose accept list collapses to empty.

:func:`dynamic` wraps a request-evaluated builder in a :class:`DynamicGate`,
which resolves to a fully validated :class:`Gate` per request.
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import Any, Literal, cast

import pydantic

from pay_kit._paycore.protocol import Protocol
from pay_kit.errors import (
    ConfigurationError,
    MixedCurrenciesError,
    ProtocolIncompatibleError,
)
from pay_kit.fee import Fee
from pay_kit.price import Price

__all__ = ["Gate", "DynamicGate", "dynamic"]


def _build_fees(
    fee_within: object,
    fee_on_top: object,
) -> tuple[Fee, ...]:
    """Coerce the ``{recipient: Price}`` fee maps into an ordered Fee tuple.

    Both maps are typed ``object``: they arrive from untyped DSL/config callers,
    so the isinstance ladder validating the dict / recipient / Price shape is the
    load-bearing runtime guard, not redundant.
    """
    fees: list[Fee] = []
    pairs: tuple[tuple[Literal["within", "on_top"], object], ...] = (
        ("within", fee_within),
        ("on_top", fee_on_top),
    )
    for kind, mapping in pairs:
        if mapping is None:
            continue
        if not isinstance(mapping, dict):
            raise ConfigurationError(f"pay_kit: fee_{kind} must be a dict of {{recipient: Price}}")
        items = cast("dict[object, object]", mapping)
        for recipient, price in items.items():
            if not isinstance(recipient, str) or not recipient:
                raise ConfigurationError(f"pay_kit: fee_{kind} recipient must be a non-empty string, got {recipient!r}")
            if not isinstance(price, Price):
                raise ConfigurationError(
                    f"pay_kit: fee_{kind} price for {recipient!r} must be a Price (use usd/eur/gbp)"
                )
            fees.append(Fee(recipient=recipient, price=price, kind=kind))
    return tuple(fees)


def _resolve_accept(
    name: str,
    accept: tuple[Protocol, ...] | None,
    has_fees: bool,
) -> tuple[Protocol, ...] | None:
    """Apply the x402-vs-fees rule and return the effective accept tuple.

    ``None`` means "inherit from Config". When fees are present, x402 is
    stripped silently from an inherited list; an explicit x402 in the accept
    list raises, and an accept list that collapses to empty raises.
    """
    if not has_fees:
        return accept

    if accept is None:
        # Inherited accept; the resolver/middleware strips x402 on a
        # fee-bearing gate. Leave None so Config's list is honored there.
        return None

    if Protocol.X402 in accept:
        raise ProtocolIncompatibleError(
            f"pay_kit: gate {name!r}: x402 cannot be combined with fees "
            f"(stock x402 facilitators settle to a single address). "
            f"Drop Protocol.X402 from accept or remove the fees."
        )
    if not accept:
        raise ProtocolIncompatibleError(
            f"pay_kit: gate {name!r}: fees present and x402 auto-disabled, "
            f"no remaining accepted protocols (add Protocol.MPP to accept)"
        )
    return accept


class Gate(pydantic.BaseModel):
    """A frozen, fully validated protected unit built via :meth:`Gate.build`."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    name: str
    amount: Price
    pay_to: str | None = None
    accept: tuple[Protocol, ...] | None = None
    description: str | None = None
    external_id: str | None = None
    fees: tuple[Fee, ...] = ()

    @classmethod
    def build(
        cls,
        *,
        name: str,
        amount: Price,
        pay_to: str | None = None,
        accept: tuple[Protocol, ...] | None = None,
        description: str | None = None,
        external_id: str | None = None,
        fee_within: dict[str, Price] | None = None,
        fee_on_top: dict[str, Price] | None = None,
        default_pay_to: str | None = None,
        accept_default: tuple[Protocol, ...] | None = None,
    ) -> Gate:
        """Build a Gate with full boot validation.

        ``default_pay_to`` and ``accept_default`` carry the resolved Config
        defaults the DSL omits; ``pay_to`` and ``accept`` override them.
        Raises :class:`~pay_kit.errors.ConfigurationError` (and subclasses) on
        any rule violation so misconfiguration fails at boot.
        """
        # isinstance guards are load-bearing against untyped DSL callers (the
        # public DX keeps the precise str/Price annotations); pyright sees them
        # as redundant under strict, so silence that one rule per line.
        if not isinstance(name, str) or not name:  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ConfigurationError(f"pay_kit: gate name must be a non-empty string, got {name!r}")
        if not isinstance(amount, Price):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ConfigurationError(f"pay_kit: gate {name!r}: amount must be a Price (use usd/eur/gbp)")

        resolved_pay_to = pay_to if pay_to is not None else default_pay_to
        if not isinstance(resolved_pay_to, str) or not resolved_pay_to:
            raise ConfigurationError(
                f"pay_kit: gate {name!r}: pay_to is required (set it on the gate or configure an operator recipient)"
            )

        fees = _build_fees(fee_within, fee_on_top)

        cls._validate_fee_recipients(name, resolved_pay_to, fees)
        cls._validate_denominations(name, amount, fees)
        cls._validate_within_sum(name, amount, fees)

        requested = accept if accept is not None else accept_default
        if accept is None and accept_default is not None and not accept_default:
            raise ConfigurationError(f"pay_kit: gate {name!r}: accept resolved to an empty list")
        # When an explicit accept is given for a fee gate it is validated by
        # _resolve_accept; an inherited list is left as-is (None or default).
        resolved_accept = _resolve_accept(name, requested, bool(fees))

        return cls(
            name=name,
            amount=amount,
            pay_to=resolved_pay_to,
            accept=resolved_accept,
            description=description,
            external_id=external_id,
            fees=fees,
        )

    def total(self) -> Price:
        """The amount the customer pays: base amount plus all on-top fees."""
        total: Decimal = self.amount.amount
        for fee in self.fees:
            if fee.is_on_top():
                total += fee.price.amount
        return self.amount.with_amount(total)

    def payout(self, address: str) -> Price | None:
        """What ``address`` nets, or ``None`` if this gate does not address it.

        ``pay_to`` nets the amount minus all ``within`` fees; a fee recipient
        nets their fee price; any other address returns ``None``.
        """
        if self.pay_to == address:
            net: Decimal = self.amount.amount
            for fee in self.fees:
                if fee.is_within():
                    net -= fee.price.amount
            return self.amount.with_amount(net)
        for fee in self.fees:
            if fee.recipient == address:
                return fee.price
        return None

    def has_fees(self) -> bool:
        """Whether this gate carries any fees."""
        return len(self.fees) > 0

    def x402_accepted(self) -> bool:
        """Whether x402 is in the resolved accept list."""
        return self.accept is not None and Protocol.X402 in self.accept

    def mpp_accepted(self) -> bool:
        """Whether MPP is in the resolved accept list."""
        return self.accept is not None and Protocol.MPP in self.accept

    @staticmethod
    def _validate_fee_recipients(name: str, pay_to: str, fees: tuple[Fee, ...]) -> None:
        """Rule 5: no fee recipient may equal pay_to and recipients are unique."""
        seen: set[str] = set()
        for fee in fees:
            if fee.recipient == pay_to:
                raise ConfigurationError(
                    f"pay_kit: gate {name!r}: fee recipient {pay_to!r} duplicates "
                    f"pay_to; fold the fee into the amount instead"
                )
            if fee.recipient in seen:
                raise ConfigurationError(f"pay_kit: gate {name!r}: duplicate fee recipient {fee.recipient!r}")
            seen.add(fee.recipient)

    @staticmethod
    def _validate_denominations(name: str, amount: Price, fees: tuple[Fee, ...]) -> None:
        """Rule 3: every fee price shares the gate amount's currency."""
        for fee in fees:
            if fee.price.currency != amount.currency:
                raise MixedCurrenciesError(
                    f"pay_kit: gate {name!r}: fee for {fee.recipient!r} is "
                    f"{fee.price.currency.value}, gate amount is {amount.currency.value}; "
                    f"all prices on a gate must share one denomination"
                )

    @staticmethod
    def _validate_within_sum(name: str, amount: Price, fees: tuple[Fee, ...]) -> None:
        """Rule 4: sum of within fees must not exceed the gate amount."""
        within_sum = sum(
            (fee.price.amount for fee in fees if fee.is_within()),
            start=Decimal(0),
        )
        if within_sum > amount.amount:
            raise ConfigurationError(
                f"pay_kit: gate {name!r}: sum(fee_within) = {within_sum} exceeds amount {amount.amount_string()}"
            )


class DynamicGate:
    """A request-evaluated gate: a builder callable resolves to a Gate per request.

    Deliberately exposes no ``has_fees`` method: a dynamic gate cannot answer
    "do I have fees?" without a request to evaluate the builder against.
    Callers must :meth:`resolve` first.
    """

    __slots__ = ("name", "accept", "description", "_builder", "_defaults")

    def __init__(
        self,
        *,
        name: str,
        accept: tuple[Protocol, ...] | None,
        description: str | None,
        builder: Callable[[Any], object],
        defaults: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.accept = accept
        self.description = description
        self._builder = builder
        self._defaults = defaults or {}

    def resolve(self, request: Any) -> Gate:
        """Run the builder against ``request`` and return a validated Gate.

        The builder may return a :class:`Gate` directly or a :class:`Price`,
        in which case a Gate is constructed from it with the dynamic gate's
        accept/description and the resolved Config defaults.
        """
        result = self._builder(request)
        if isinstance(result, Gate):
            return result
        if isinstance(result, Price):
            return Gate.build(
                name=self.name,
                amount=result,
                accept=self.accept,
                description=self.description,
                default_pay_to=self._defaults.get("pay_to"),
                accept_default=self._defaults.get("accept"),
            )
        raise ConfigurationError(
            f"pay_kit: dynamic gate {self.name!r}: builder must return a Gate or a Price, got {type(result).__name__}"
        )


def dynamic(
    name: str,
    *,
    accept: tuple[Protocol, ...] | None = None,
    description: str | None = None,
) -> Callable[[Callable[[Any], object]], DynamicGate]:
    """Decorator turning a request-builder callable into a :class:`DynamicGate`.

    The decorated function receives the request and returns a :class:`Gate`
    (or a :class:`Price` to be wrapped). Config defaults are applied lazily at
    :meth:`DynamicGate.resolve` time by the middleware that owns the request.
    """

    def _wrap(builder: Callable[[Any], object]) -> DynamicGate:
        return DynamicGate(
            name=name,
            accept=accept,
            description=description,
            builder=builder,
        )

    return _wrap
