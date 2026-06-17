# examples/playground_api/sessions.py
"""The session-gated demo endpoints (FastAPI).

Driven by the in-process MPP session method
(:func:`pay_kit.protocols.mpp.server.new_session`), the reserve/commit metering
side channel (:func:`pay_kit.protocols.mpp.server.session_routes`), and the
settle-status receipt poll. Both methods share one
:class:`~pay_kit.protocols.mpp.server.MemoryChannelStore` so the receipt
endpoint reads channel state whichever endpoint opened the channel.

Faithful port of ``typescript/examples/playground-api/modules/sessions.ts``.
The Python SDK does not ship the TS ``Mppx.session()`` request handler, so the
402 gate is built inline from :meth:`Session.challenge` and
:meth:`Session.verify_credential`. The server-broadcast open path
(``openTxSubmitter=server``) and the on-chain settle-at-close are not ported, so
this uses the default client-broadcast submitter and ``rpc=None``;
``settledSignature`` stays ``null`` until that lands.
"""

from __future__ import annotations

import asyncio
import datetime
import json
from typing import TYPE_CHECKING, Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from pay_kit._paycore.errors import PaymentError, payment_required_response
from pay_kit.protocols.mpp.core.headers import (
    AUTHORIZATION_HEADER,
    PAYMENT_RECEIPT_HEADER,
    format_receipt,
    format_www_authenticate,
    parse_authorization,
)
from pay_kit.protocols.mpp.server import (
    MemoryChannelStore,
    RouteResponse,
    Session,
    SessionChallengeOptions,
    SessionOptions,
    new_session,
    session_routes,
)

from . import constants
from .utils import json_error, log_payment

if TYPE_CHECKING:
    from .app import AppState

# The canned token-stream payload. Mirrors TS ``TOKEN_CHUNKS``.
TOKEN_CHUNKS = [
    "A payment channel ",
    "lets a client and server ",
    "authorize many small ",
    "off-chain debits ",
    "against a single on-chain ",
    "deposit, settling the highest ",
    "cumulative voucher at close.",
]


def _session_gate(session: Session, options: SessionChallengeOptions):
    """Build the 402 gate for a route as a FastAPI dependency (the Python SDK has
    no ``SessionMiddleware``), mirroring how charge routes use ``RequirePayment``.

    Returns an async dependency that yields the verified-receipt response headers
    when an Authorization credential verifies, or raises ``HTTPException(402)``
    (challenge in WWW-Authenticate) otherwise. The challenge is built only when a
    402 is issued, so the verify path never prefetches a blockhash.
    """

    async def gate(request: Request) -> dict[str, str]:
        error: PaymentError | None = None
        auth_header = request.headers.get(AUTHORIZATION_HEADER)
        if auth_header:
            try:
                receipt = await session.verify_credential(parse_authorization(auth_header))
                try:
                    return {PAYMENT_RECEIPT_HEADER: format_receipt(receipt)}
                except Exception:
                    return {}
            except PaymentError as err:
                error = err
            except Exception as err:  # noqa: BLE001 (framework/parse errors map to a 402)
                error = PaymentError(str(err), code="invalid-payload")

        challenge = await session.challenge(options)
        problem = payment_required_response(
            str(error) if error else "Payment required",
            code=(error.code if error and error.code else "payment_invalid"),
            challenge_header=format_www_authenticate(challenge),
        )
        raise HTTPException(status_code=problem["status_code"], detail=problem["body"], headers=problem["headers"])

    return gate


async def _body(request: Request) -> dict[str, Any]:
    """Best-effort JSON object request body."""
    try:
        body = await request.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


def _commit_ack(body: dict[str, Any]) -> dict[str, str]:
    """The minimal CommitReceipt-shaped ack a voucher commit returns. Mirrors TS
    ``commitAck``."""
    return {
        "amount": str(body.get("amount") or "0"),
        "deliveryId": str(body.get("deliveryId", "")),
        "status": "committed",
    }


async def _route_response(handler: Any, request: Request) -> JSONResponse:
    """Adapt a framework-agnostic side-channel :class:`RouteResponse` handler to a
    FastAPI ``JSONResponse``."""
    raw = await request.body()
    result: RouteResponse = await handler(request.method, raw if raw else b"{}")
    return JSONResponse(result.body, status_code=result.status)


def register_sessions(app: FastAPI, state: AppState) -> Any:
    """Mount the session endpoints and return the watchdog shutdown hook.

    Routes (mirroring TS ``registerSessions``):

    * ``GET  /sessions/stream``: pay-per-chunk SSE, cap 1.00 USDC, 0.0001 USDC/chunk
    * ``POST /sessions/stream``: voucher commits for the stream endpoint
    * ``POST /sessions/compute``: pay-per-call compute, cap 0.50 USDC, 0.005 USDC/call
      (also accepts voucher commits)
    * ``POST /__402/session/deliveries``: SessionFetch delivery reservation
    * ``POST /__402/session/commit``: body-voucher commit variant of the above
    * ``GET  /sessions/receipt/{channel_id}``: settle-status poll for the UI
    """
    # Shared store so /sessions/receipt reads channel state regardless of which
    # endpoint opened the channel.
    shared_store = MemoryChannelStore()

    def new_method(cap: int) -> Session:
        return new_session(
            SessionOptions(
                operator=state.fee_payer_pubkey,
                recipient=state.recipient,
                cap=cap,
                currency=constants.USDC_MAINNET_MINT,
                decimals=constants.USDC_DECIMALS,
                network=state.network,
                secret_key=state.secret_key,
                modes=["pull"],
                pull_voucher_strategy="clientVoucher",
                store=shared_store,
            )
        )

    stream_session = new_method(1_000_000)  # 1.00 USDC
    compute_session = new_method(500_000)  # 0.50 USDC

    def shutdown() -> None:
        stream_session.shutdown()
        compute_session.shutdown()

    stream_gate = _session_gate(
        stream_session,
        SessionChallengeOptions(cap="1000000", description="Metered token stream"),
    )
    compute_gate = _session_gate(
        compute_session,
        SessionChallengeOptions(cap="500000", description="Voucher-billed inference call"),
    )

    # Gates as FastAPI dependencies, so the session routes read like the charge
    # routes (assigned first to keep the Depends call out of the arg default).
    stream_dep = Depends(stream_gate)
    compute_dep = Depends(compute_gate)

    # GET /sessions/stream: stream tokens as SSE; each chunk costs 0.0001 USDC.
    @app.get("/sessions/stream")
    async def sessions_stream_get(headers: dict[str, str] = stream_dep) -> Any:
        async def body() -> Any:
            for chunk in TOKEN_CHUNKS:
                yield "data: " + json.dumps({"chunk": chunk, "cost": "100"}, separators=(",", ":")) + "\n\n"
                await asyncio.sleep(0.08)
            yield "data: [DONE]\n\n"

        return StreamingResponse(
            body(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive", **headers},
        )

    # POST /sessions/stream: voucher commits arrive on the URL the session was
    # opened against; the gate's verify path applies the voucher, the body is an ack.
    @app.post("/sessions/stream")
    async def sessions_stream_post(request: Request, headers: dict[str, str] = stream_dep) -> JSONResponse:
        return JSONResponse(_commit_ack(await _body(request)), headers=headers)

    # POST /sessions/compute: pay-per-call compute; the same handler accepts
    # voucher commits (a deliveryId in the body discriminates).
    @app.post("/sessions/compute")
    async def sessions_compute_post(request: Request, headers: dict[str, str] = compute_dep) -> JSONResponse:
        body = await _body(request)
        if str(body.get("deliveryId", "")) != "":
            return JSONResponse(_commit_ack(body), headers=headers)
        log_payment(request.url.path, headers)
        prompt = str(body.get("prompt", ""))
        return JSONResponse(
            {
                "prompt": prompt,
                "output": "Echo: " + prompt + " (computed for 0.005 USDC)",
                "computedAt": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            headers=headers,
        )

    # Side-channel metering routes: clients reserve capacity for each metered
    # delivery before signing + committing the voucher. Both share the store.
    routes = session_routes(stream_session.core(), touch=None)

    @app.post("/__402/session/deliveries")
    async def session_deliveries(request: Request) -> JSONResponse:
        return await _route_response(routes.deliveries, request)

    @app.post("/__402/session/commit")
    async def session_commit(request: Request) -> JSONResponse:
        return await _route_response(routes.commit, request)

    # Receipt poll: the UI hits this after the stream ends to learn the settle
    # signature. With no ported settlement path it stays null; the
    # watermark/deposit come from the shared store.
    @app.get("/sessions/receipt/{channel_id}")
    async def sessions_receipt(channel_id: str) -> JSONResponse:
        if not channel_id:
            return JSONResponse(json_error("invalid-channel-id"), status_code=400)
        state_channel = await shared_store.get_channel(channel_id)
        if state_channel is None:
            return JSONResponse(json_error("channel-not-found"), status_code=404)
        return JSONResponse(
            {
                "channelId": state_channel.channel_id,
                "cumulative": str(state_channel.cumulative),
                "deposit": str(state_channel.deposit),
                "finalized": state_channel.finalized,
                "settledSignature": state_channel.settled_signature,
            }
        )

    return shutdown
