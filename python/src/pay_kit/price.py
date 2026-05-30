"""Denominated amount plus an ordered settlement-preference list.

``Price.usd("0.10")`` reads "ten cents USD, settle in whatever the config
prefers". ``Price.usd("0.10", Stablecoin.USDC)`` narrows settlement to USDC.
The variadic stablecoin order is preference; the resolver picks the first coin
it can settle.

Amounts are :class:`decimal.Decimal`. The factories reject ``float`` at the
signature level (accept ``str | int | Decimal`` only) so binary-float rounding
never touches money. Build via :meth:`Price.usd` / :meth:`Price.eur` /
:meth:`Price.gbp`, never the raw constructor.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

import pydantic

from pay_kit._paycore.currency import Currency
from pay_kit._paycore.stablecoin import Stablecoin
from pay_kit.errors import ConfigurationError, MixedCurrenciesError

__all__ = ["Price", "Settlement"]

_AMOUNT_RE = re.compile(r"^\d+(\.\d+)?$")


def _to_decimal(amount: object) -> Decimal:
    """Coerce a money input to Decimal, rejecting float and bad formats.

    Accepts ``object`` (not just ``str | int | Decimal``) because the public
    factories forward untyped caller input and the field validator forwards a
    raw pydantic value; the isinstance ladder is the load-bearing runtime guard.
    """
    if isinstance(amount, bool):  # bool is an int subclass; reject explicitly.
        raise ConfigurationError("pay_kit: Price amount must be str | int | Decimal, not bool")
    if isinstance(amount, float):
        raise ConfigurationError("pay_kit: Price amount must be str | int | Decimal, not float")
    if isinstance(amount, Decimal):
        coerced = amount
    elif isinstance(amount, int):
        coerced = Decimal(amount)
    elif isinstance(amount, str):
        if not _AMOUNT_RE.match(amount):
            raise ConfigurationError(f"pay_kit: invalid Price amount: {amount!r}")
        try:
            coerced = Decimal(amount)
        except InvalidOperation as exc:
            raise ConfigurationError(f"pay_kit: invalid Price amount: {amount!r}") from exc
    else:
        raise ConfigurationError("pay_kit: Price amount must be str | int | Decimal")
    # The str path rejects negatives via _AMOUNT_RE, but the int and Decimal
    # paths reach here unguarded; validate the sign uniformly so usd(-1) and
    # usd(Decimal("-0.01")) raise instead of building an invalid Price. Zero is
    # allowed (a free gate).
    if coerced < 0:
        raise ConfigurationError(f"pay_kit: Price amount must not be negative: {amount!r}")
    return coerced


class Settlement(pydantic.BaseModel):
    """A single settlement preference: pay ``amount`` denominated in ``coin``."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    coin: Stablecoin
    amount: str

    def __str__(self) -> str:
        return f"{self.amount} {self.coin.value}"


class Price(pydantic.BaseModel):
    """Currency-denominated amount with an ordered settlement-coin preference."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    amount: Decimal
    currency: Currency
    settlements: tuple[Stablecoin, ...] = ()

    @pydantic.field_validator("amount", mode="before")
    @classmethod
    def _coerce_amount(cls, value: object) -> Decimal:
        return _to_decimal(value)

    @classmethod
    def usd(cls, amount: str | int | Decimal, *settlements: Stablecoin) -> Price:
        """Build a USD-denominated price."""
        return cls(amount=_to_decimal(amount), currency=Currency.USD, settlements=settlements)

    @classmethod
    def eur(cls, amount: str | int | Decimal, *settlements: Stablecoin) -> Price:
        """Build a EUR-denominated price."""
        return cls(amount=_to_decimal(amount), currency=Currency.EUR, settlements=settlements)

    @classmethod
    def gbp(cls, amount: str | int | Decimal, *settlements: Stablecoin) -> Price:
        """Build a GBP-denominated price."""
        return cls(amount=_to_decimal(amount), currency=Currency.GBP, settlements=settlements)

    def with_amount(self, amount: str | int | Decimal) -> Price:
        """Return a copy with a new amount, same currency and settlements."""
        return Price(amount=_to_decimal(amount), currency=self.currency, settlements=self.settlements)

    def plus(self, other: Price) -> Price:
        """Sum two same-currency prices; raise on a currency mismatch."""
        if self.currency != other.currency:
            raise MixedCurrenciesError(
                f"pay_kit: cannot sum prices of different currencies ({self.currency.value} vs {other.currency.value})"
            )
        return Price(
            amount=self.amount + other.amount,
            currency=self.currency,
            settlements=self.settlements,
        )

    def amount_string(self) -> str:
        """The wire-form decimal string, preserving trailing zeros."""
        return format(self.amount, "f")

    def primary_coin(self) -> Stablecoin | None:
        """The most-preferred settlement coin, or None to defer to config."""
        return self.settlements[0] if self.settlements else None
