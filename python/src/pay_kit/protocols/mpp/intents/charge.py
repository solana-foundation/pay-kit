"""Charge intent types and amount parsing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ChargeRequest:
    """Method-agnostic charge intent body."""

    amount: str
    currency: str
    recipient: str = ""
    description: str = ""
    external_id: str = ""
    method_details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"amount": self.amount, "currency": self.currency}
        if self.recipient:
            d["recipient"] = self.recipient
        if self.description:
            d["description"] = self.description
        if self.external_id:
            d["externalId"] = self.external_id
        if self.method_details:
            d["methodDetails"] = self.method_details
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChargeRequest:
        return cls(
            amount=data.get("amount", ""),
            currency=data.get("currency", ""),
            recipient=data.get("recipient", ""),
            description=data.get("description", ""),
            external_id=data.get("externalId", ""),
            method_details=data.get("methodDetails"),
        )


def parse_units(amount: str, decimals: int) -> str:
    """Convert a human-readable decimal amount to base units.

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


def validate_max_amount(request: ChargeRequest, max_amount: str) -> None:
    """Validate that a charge request does not exceed a max base-unit amount."""
    try:
        actual = int(request.amount)
    except ValueError as exc:
        raise ValueError(f"invalid amount: {request.amount}") from exc

    try:
        maximum = int(max_amount)
    except ValueError as exc:
        raise ValueError(f"invalid max amount: {max_amount}") from exc

    if actual > maximum:
        raise ValueError(f"amount {actual} exceeds maximum {maximum}")
