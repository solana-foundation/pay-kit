"""Fiat currency denominations supported by Price value objects."""

from __future__ import annotations

from enum import StrEnum

__all__ = ["Currency"]


class Currency(StrEnum):
    """ISO 4217 fiat currency used to denominate a gate amount."""

    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
