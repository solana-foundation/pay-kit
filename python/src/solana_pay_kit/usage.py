"""Usage-gated (x402 ``upto``) metering: the ``Charge`` meter and settlement policy.

Unlike the fixed ``exact`` gate (settled inline before the handler), an ``upto``
gate is two-phase: the channel is opened and bound before the resource is served,
the handler records the actual metered amount via a :class:`Charge`, and the
operator settles that amount (``actual ≤ max``) after the handler returns.

This module is the host-neutral half shared by every framework shim and the
conformance harness server:

* :class:`Charge` - the meter handed to the handler (clamps to the ceiling).
* :func:`finalize_usage` - the settlement policy. It honours the protocol
  (``settle_actual`` settles any ``actual ≤ max``, including 0) but applies the
  PayKit **fail-closed** policy at the app layer: a missing or zero charge still
  settles 0 on-chain (channel finalize + full refund) yet withholds the protected
  body (HTTP 402). Mirrors Go ``paykit/usage.go`` (``settleZeroAndFailClosed``).

The engine-layer zero behaviour (settle 0 → success, full refund) lives in
:class:`~solana_pay_kit.protocols.x402.upto.X402Upto`; the fail-closed withhold is this
app-layer policy, exactly the two-layer split the spec allows.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

__all__ = [
    "Charge",
    "UsageOutcome",
    "finalize_usage",
    "charge_from",
    "fetch_recent_blockhash",
    "CHARGE_ATTR",
]

#: Request attribute the framework shims write the per-request Charge meter under.
CHARGE_ATTR = "paykit_charge"


def _empty_headers() -> dict[str, str]:
    return {}


class Charge:
    """Usage meter handed to a usage-gated handler.

    The handler reports the actual amount consumed (token base units) via
    :meth:`charge`; the gate settles that amount - never above the authorized
    ceiling - after the handler returns. Mirrors the Go ``Charge`` and the
    TypeScript ``Charge`` clamp behaviour (values above the ceiling clamp down;
    negatives floor to 0).
    """

    def __init__(self, max_base_units: int) -> None:
        """Create a meter with the authorized ceiling ``max_base_units``."""
        self._max = max_base_units
        self._amount = 0
        self._charged = False
        self._lock = threading.Lock()

    @property
    def max_base_units(self) -> int:
        """The authorized maximum for this request, in base units."""
        return self._max

    def charge(self, base_units: int) -> None:
        """Record the actual amount consumed; clamp to ``[0, max_base_units]``."""
        with self._lock:
            amount = base_units
            if amount < 0:
                amount = 0
            if amount > self._max:
                amount = self._max
            self._amount = amount
            self._charged = True

    def settled_base_units(self) -> int:
        """The amount to settle: the clamped charge, or 0 if never charged."""
        with self._lock:
            return self._amount

    def was_charged(self) -> bool:
        """Whether :meth:`charge` was called at least once."""
        with self._lock:
            return self._charged


@dataclass
class UsageOutcome:
    """The result of finalizing a usage-gated request."""

    ok: bool
    status: int
    settlement_headers: dict[str, str] = field(default_factory=_empty_headers)
    transaction: str = ""
    code: str | None = None
    detail: str | None = None


async def finalize_usage(engine: Any, verified: Any, charge: Charge) -> UsageOutcome:
    """Settle a usage-gated request after the handler ran, applying fail-closed policy.

    On a positive charge: settle the metered amount and return ``ok=True`` with
    the settlement receipt headers. On a missing or zero charge: still settle 0
    on-chain (the channel finalizes and the full deposit is refunded) but return
    ``ok=False`` (HTTP 402) so the protected body is withheld - the developer
    must meter a positive amount to serve. ``settle_actual`` releases the
    channel reservation in either branch.
    """
    actual = charge.settled_base_units()
    if not charge.was_charged() or actual == 0:
        reason = (
            "usage Charge must be called before the handler returns"
            if not charge.was_charged()
            else "usage Charge must be greater than zero"
        )
        try:
            await engine.settle_actual(verified, 0)
        except Exception as exc:  # noqa: BLE001 - withhold regardless; the reservation is released by settle_actual
            return UsageOutcome(ok=False, status=402, code="settlement_failed", detail=str(exc))
        return UsageOutcome(ok=False, status=402, code="settlement_failed", detail=reason)

    settlement = await engine.settle_actual(verified, actual)
    return UsageOutcome(
        ok=True,
        status=200,
        settlement_headers=engine.settlement_headers(settlement),
        transaction=cast("dict[str, Any]", settlement).get("transaction", ""),
    )


def charge_from(request: Any) -> Charge | None:
    """The :class:`Charge` meter attached to ``request`` by the usage middleware.

    Tolerates an attribute bag, a ``.state`` namespace (FastAPI/Starlette), or a
    mapping. Returns ``None`` when no usage gate is active for the request.
    """
    state = getattr(request, "state", None)
    if state is not None and hasattr(state, CHARGE_ATTR):
        value = getattr(state, CHARGE_ATTR)
        return value if isinstance(value, Charge) else None
    if hasattr(request, CHARGE_ATTR):
        value = getattr(request, CHARGE_ATTR)
        return value if isinstance(value, Charge) else None
    if isinstance(request, Mapping):
        value = cast("Mapping[str, object]", request).get(CHARGE_ATTR)
        return value if isinstance(value, Charge) else None
    return None


def fetch_recent_blockhash(rpc_url: str) -> str | None:
    """Fetch a recent blockhash over a blocking JSON-RPC call (no asyncio).

    The ``upto`` challenge stamps ``extra.recentBlockhash`` so the client can
    build the channel-open without an extra RPC round-trip. The engine reads it
    synchronously from ``accepts_entry``, so this must stay blocking; the
    framework shims wire it as the engine's ``recent_blockhash_provider``.
    Returns ``None`` on any RPC/transport failure so the challenge degrades to
    "no pre-fetched blockhash" rather than failing the request.
    """
    import json
    import urllib.request

    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "confirmed"}],
        }
    ).encode("utf-8")
    request = urllib.request.Request(rpc_url, data=body, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read())
        blockhash = payload["result"]["value"]["blockhash"]
    except Exception:
        return None
    return blockhash if isinstance(blockhash, str) and blockhash else None
