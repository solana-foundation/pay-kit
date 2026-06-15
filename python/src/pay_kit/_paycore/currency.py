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

    has_fraction = len(parts) == 2
    whole = parts[0]
    fractional = parts[1] if has_fraction else ""

    # Audit #44/#45: reject malformed shapes that ``int()`` would otherwise
    # silently accept. Mirrors the Rust ``parse_units`` guards
    # (rust/crates/mpp/src/protocol/intents/mod.rs): no empty integer/fraction
    # halves (".5", "5.", "."), and every digit must be an ASCII 0-9 — Python's
    # ``int()`` accepts a leading "+", underscore grouping ("1_000"), and
    # non-ASCII Unicode digits ("١٢٣"), all of which would silently corrupt the
    # base-unit amount. ``str.isdigit()`` is too loose (it accepts superscripts
    # and other numeric Unicode), so screen each char with ``isascii``+``isdigit``.
    if has_fraction and (not whole or not fractional):
        raise ValueError(f"invalid amount: {amount}")
    if not whole:
        raise ValueError(f"invalid amount: {amount}")

    def _all_ascii_digits(s: str) -> bool:
        return s != "" and all(c.isascii() and c.isdigit() for c in s)

    if not _all_ascii_digits(whole):
        raise ValueError(f"invalid amount: {amount}")
    if fractional and not _all_ascii_digits(fractional):
        raise ValueError(f"invalid amount: {amount}")

    if len(fractional) > decimals:
        raise ValueError(f"amount {amount} has too many decimal places for {decimals} decimals")

    # Pad fractional part to fill decimals
    value_str = whole + fractional + "0" * (decimals - len(fractional))

    # Strip leading zeros
    value_str = value_str.lstrip("0") or "0"

    # Validate it's a valid integer (guards above already screened the digits)
    try:
        val = int(value_str)
    except ValueError as exc:
        raise ValueError(f"invalid amount: {amount}") from exc

    return str(val)
