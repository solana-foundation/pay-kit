# examples/playground_api/utils.py
"""Shared helpers: the surfnet JSON-RPC cheatcode caller, the JSON error body,
env lookups, and the settlement / receipt log lines.

Mirrors the Go example's ``utils.go``. The ANSI color helpers there map onto
the standard ``logging`` records used at boot here.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from pay_kit.protocols.mpp.core.headers import PAYMENT_RECEIPT_HEADER, parse_receipt

logger = logging.getLogger("playground-api")


def env_or(name: str, fallback: str) -> str:
    """Return the environment variable value, or fallback when unset or empty."""
    value = os.getenv(name)
    return value if value else fallback


async def rpc_call(rpc_url: str, method: str, params: list[Any]) -> Any:
    """Perform a JSON-RPC call against the surfnet endpoint and return the raw
    result.

    Used for the ``surfnet_*`` cheatcodes the standard RPC client does not
    expose (faucet airdrops and the boot-time funding). Raises ``RuntimeError``
    on a JSON-RPC error payload.
    """
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    async with httpx.AsyncClient(timeout=8.0) as http:
        response = await http.post(rpc_url, json=payload)
    response.raise_for_status()
    body = response.json()
    error = body.get("error")
    if error is not None:
        raise RuntimeError(f"{method}: {error.get('message', 'rpc error')}")
    return body.get("result")


def log_tx(path: str, reference: str) -> None:
    """Log a settlement-signature link for quick eyeball debugging."""
    studio = env_or("STUDIO_PORT", "18488")
    logger.info("ok %s  tx: http://localhost:%s/?t=%s", path, studio, reference)


def log_payment(path: str, headers: Any) -> None:
    """Log the receipt reference from a Payment-Receipt response header, when
    present.

    ``headers`` is anything with a case-insensitive ``get`` (e.g. a Starlette
    ``Headers`` or a plain dict).
    """
    value = headers.get(PAYMENT_RECEIPT_HEADER)
    if not value:
        return
    try:
        receipt = parse_receipt(value)
    except Exception:
        return
    if receipt.reference:
        log_tx(path, receipt.reference)


def json_error(message: str) -> dict[str, str]:
    """Build the standard ``{"error": message}`` JSON error body.

    Pair with a FastAPI ``JSONResponse(status_code=..., content=json_error(...))``
    or raise it through ``HTTPException(detail=...)`` at the call site.
    """
    return {"error": message}
