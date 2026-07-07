"""Charge intent types and amount parsing.

``parse_units`` is re-exported from the shared core (:mod:`solana_pay_kit._paycore.currency`)
so the MPP intent layer keeps a stable name while the actual implementation
stays protocol-agnostic and shared with x402 without either protocol importing
the other (R2).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from solana_pay_kit._paycore.currency import parse_units

__all__ = ["ChargeRequest", "parse_units", "validate_max_amount"]


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
