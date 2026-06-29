"""Request-scoped proof returned after a successful payment verification."""

from __future__ import annotations

import pydantic

from solana_pay_kit._paycore.protocol import Protocol

__all__ = ["Payment"]


class Payment(pydantic.BaseModel):
    """Immutable record of a settled payment attached to the request scope.

    Built by an adapter (:class:`solana_pay_kit.protocols.mpp.MppAdapter` or
    :class:`solana_pay_kit.protocols.x402.X402Adapter`) after on-chain settlement.
    ``transaction`` is the settled signature/reference, ``settlement_headers``
    are echoed onto the framework response, and ``raw`` keeps the original
    proof string (Authorization / Payment-Signature) for auditing.
    """

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")

    protocol: Protocol
    transaction: str
    gate_name: str | None = None
    settlement_headers: dict[str, str] = pydantic.Field(default_factory=dict)
    raw: str | None = None
