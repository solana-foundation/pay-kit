# examples/playground_api/subscriptions.py
"""One subscription-gated route for the playground (FastAPI).

solana_pay_kit ships the gate as ``RequireSubscription`` over
:class:`~solana_pay_kit.protocols.mpp.server.subscription.SubscriptionServer`:
the first call activates a recurring on-chain authorization against the plan,
later calls in the same period reuse the bearer proof for free, and an unpaid
period is collected on access. So the route is one ``Depends`` line, the
subscription counterpart of the charge and session gates.

The on-chain ``Plan`` comes from ``PAY_KIT_PLAYGROUND_PLAN_ID``; the example
never creates one. The puller is the operator signer, because this server signs
the renewal itself. Mirrors the TS playground's ``GET /api/v1/feed``.
"""

from __future__ import annotations

import os
import random
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request

import solana_pay_kit
from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.solana import resolve_mint
from solana_pay_kit._paycore.store import MemoryStore
from solana_pay_kit.fastapi import RequireSubscription
from solana_pay_kit.protocols.mpp.server.subscription import (
    SubscriptionChallengeOptions,
    SubscriptionConfig,
    SubscriptionServer,
)

router = APIRouter()

_cfg = solana_pay_kit.config()
#: The on-chain ``Plan`` PDA this route bills against. Unset disables the route.
PLAN_ID = os.getenv("PAY_KIT_PLAYGROUND_PLAN_ID", "")
#: 0.10 USDC per day, the same price the TS playground's `feed` charges.
PRICE_BASE_UNITS = 100_000
_DESCRIPTION = "Feed subscription"

server = (
    SubscriptionServer(
        SubscriptionConfig(
            plan=PLAN_ID,
            mint=resolve_mint("USDC", _cfg.network.mints_label()),
            recipient=_cfg.effective_recipient(),
            amount=PRICE_BASE_UNITS,
            puller_signer=_cfg.operator.signer,
            store=MemoryStore(),
            period_unit="day",
            period_count=1,
            network=_cfg.network.mints_label(),
            rpc_url=_cfg.effective_rpc_url(),
            secret_key=_cfg.mpp.challenge_binding_secret or "",
            description=_DESCRIPTION,
        )
    )
    if PLAN_ID
    else None
)

_gate = RequireSubscription(server, SubscriptionChallengeOptions(description=_DESCRIPTION)) if server else None

_HEADLINES = (
    "Agents settle their own invoices",
    "Stablecoin rails reach the long tail",
    "A payment channel closes itself",
    "Subscriptions renew without a card",
    "Micropayments outgrow the checkout page",
)


async def _subscription(request: Request) -> dict[str, str]:
    """The 402 subscription gate, or a clear 503 when the plan is missing or unreadable."""
    if _gate is None:
        raise HTTPException(
            503,
            {"error": "set PAY_KIT_PLAYGROUND_PLAN_ID to an on-chain Plan PDA to enable GET /api/v1/feed"},
        )
    try:
        return await _gate(request)
    except PaymentError as exc:
        # Issuing the challenge reads the plan: a missing plan or an unreachable
        # RPC is the operator's problem, not the caller's.
        raise HTTPException(503, {"error": f"subscription plan {PLAN_ID} is unavailable: {exc}"}) from exc


@router.get("/api/v1/feed")
async def feed(_receipt: dict[str, str] = Depends(_subscription)) -> dict[str, object]:  # noqa: B008
    """The gated feed: the first call activates the subscription, the rest reuse it."""
    return {
        "generatedAt": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "headlines": random.sample(_HEADLINES, 3),
    }
