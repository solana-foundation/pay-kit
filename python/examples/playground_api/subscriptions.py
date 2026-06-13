# examples/playground_api/subscriptions.py
"""Subscriptions module. The Python SDK does not implement the subscription
server method yet, so this module keeps the ``/api/v1/premium/feed`` route
(nothing is silently dropped) and answers 501 with an explicit pointer at the
gap. The endpoint catalog omits the subscription entry, so the playground UI
renders its graceful empty state. See README.md.

Mirrors the Go example's ``subscriptions.go``.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse


def register_subscriptions(app: FastAPI) -> None:
    """Mount the documented subscription stub."""

    @app.get("/api/v1/premium/feed")
    async def premium_feed() -> JSONResponse:
        return JSONResponse(
            {
                "error": "not_implemented",
                "detail": (
                    "The Python SDK does not ship the solana.subscription server method yet; "
                    "this route exists for parity with go/examples/playground-api and "
                    "will be gated once the Python subscription intent lands."
                ),
            },
            status_code=501,
        )
