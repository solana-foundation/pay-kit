"""Fiat currency denominations and decimal/base-unit conversion.

``parse_units`` is protocol-agnostic (both the MPP charge server and the x402
exact offer builder convert a human-readable decimal amount into integer base
units), so it lives in the shared core. Neither protocol package owns it and
neither imports the other to reach it (R2).
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["Currency", "parse_units"]


class Currency(StrEnum):
    """ISO 4217 fiat currency used to denominate a gate amount."""

    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"


def parse_units(amount: str, decimals: int) -> str:
    """Convert a human-readable decimal amount to integer base units.

    Examples:
        parse_units("1.5", 6)  -> "1500000"
        parse_units("0.01", 2) -> "1"
        parse_units("100", 6)  -> "100000000"
    """
    amount = amount.strip()
    if not amount:
        raise ValueError("amount is required")
    if amount.startswith("-"):
        raise ValueError("amount cannot be negative")

    parts = amount.split(".")
    if len(parts) > 2:
        raise ValueError(f"invalid amount: {amount}")

    whole = parts[0] or "0"
    fractional = parts[1] if len(parts) == 2 else ""

    if len(fractional) > decimals:
        raise ValueError(f"amount {amount} has too many decimal places for {decimals} decimals")

    # Pad fractional part to fill decimals
    value_str = whole + fractional + "0" * (decimals - len(fractional))

    # Strip leading zeros
    value_str = value_str.lstrip("0") or "0"

    # Validate it's a valid integer
    try:
        val = int(value_str)
    except ValueError as exc:
        raise ValueError(f"invalid amount: {amount}") from exc

    return str(val)
