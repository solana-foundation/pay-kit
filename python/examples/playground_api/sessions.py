# examples/playground_api/sessions.py
"""The two session-gated demo endpoints (FastAPI).

Both endpoints are driven by the in-process MPP session method
(:func:`pay_kit.protocols.mpp.server.new_session`), the reserve/commit metering
side channel (:func:`pay_kit.protocols.mpp.server.session_routes`), and the
settle-status receipt poll. Both methods share one
:class:`~pay_kit.protocols.mpp.server.MemoryChannelStore` so the receipt
endpoint can read the channel state whichever endpoint opened the channel.

Ports ``go/examples/playground-api/sessions.go``. The route shapes, handler
bodies, canned token stream, and JSON acks mirror the Go example.

Differences from the Go example, where the Python SDK port lacks a capability
the closest faithful behavior is served (nothing is silently dropped):

* The Go example opens channels with ``OpenTxSubmitterServer`` (the server
  completes the fee-payer signature and broadcasts the client-built open) and
  arms ``CloseDelay`` with ``Signer`` + ``RPC`` so the idle-close watchdog
  drives on-chain settle-and-distribute. The Python session method
  (:mod:`pay_kit.protocols.mpp.server.session_method`) does not yet port the
  server-broadcast open path or the on-chain settlement at close, so this app
  uses the default client-broadcast submitter and ``rpc=None`` (the offline
  core, which trusts the open signature / deposit as provided). The
  ``/sessions/receipt`` poll still resolves from the shared store: it reports
  the channel watermark/deposit and a ``settledSignature`` of ``null`` until
  the Python settlement path lands.
"""

from __future__ import annotations

import asyncio
import datetime
import json
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Request
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

# token_chunks is the canned token stream payload. Mirrors Go ``tokenChunks``.
TOKEN_CHUNKS = [
    "A payment channel ",
    "lets a client and server ",
    "authorize many small ",
    "off-chain debits ",
    "against a single on-chain ",
    "deposit, settling the highest ",
    "cumulative voucher at close.",
]


def _session_gate(session: Session, challenge_options: SessionChallengeOptions):
    """Build the session-payment gate for a route, mirroring the Go
    ``SessionMiddleware`` behavior inline for FastAPI.

    Returns an async callable taking the request and returning a
    ``(credential, receipt)`` pair when payment verifies, or a 402
    :class:`JSONResponse` (with the session challenge in WWW-Authenticate) when
    it does not. The challenge is only built when a 402 is actually issued, so
    the verify path never prefetches a blockhash. Mirrors Go ``SessionMiddleware``.
    """

    async def gate(request: Request) -> tuple[Any, Any] | JSONResponse:
        verification_error: PaymentError | None = None
        auth_header = request.headers.get(AUTHORIZATION_HEADER)
        if auth_header:
            try:
                credential = parse_authorization(auth_header)
                receipt = await session.verify_credential(credential)
                return credential, receipt
            except PaymentError as err:
                verification_error = err
            except Exception as err:  # noqa: BLE001 (framework/parse errors)
                verification_error = PaymentError(str(err), code="invalid-payload")

        challenge = await session.challenge(challenge_options)
        www_auth = format_www_authenticate(challenge)
        if verification_error is None:
            problem = payment_required_response(
                "Payment required",
                code="payment_invalid",
                challenge_header=www_auth,
            )
        else:
            problem = payment_required_response(
                str(verification_error) or "Payment required",
                code=verification_error.code or "payment_invalid",
                challenge_header=www_auth,
            )
        return JSONResponse(
            problem["body"],
            status_code=problem["status_code"],
            headers=problem["headers"],
        )

    return gate


def _receipt_header(receipt: Any) -> dict[str, str]:
    """Expose the verified receipt in the Payment-Receipt response header, as
    the Go middleware does after a successful verify. Best-effort: a formatting
    failure simply omits the header."""
    try:
        return {PAYMENT_RECEIPT_HEADER: format_receipt(receipt)}
    except Exception:
        return {}


def _commit_ack(body: dict[str, Any]) -> dict[str, str]:
    """Build the minimal CommitReceipt-shaped JSON ack the stream commit handler
    returns. Mirrors Go ``commitAck``."""
    amount = body.get("amount") or "0"
    return {
        "amount": str(amount),
        "deliveryId": str(body.get("deliveryId", "")),
        "status": "committed",
    }


async def _route_response(handler: Any, request: Request) -> JSONResponse:
    """Adapt a framework-agnostic side-channel :class:`RouteResponse` handler
    (method + raw body -> RouteResponse) to a FastAPI ``JSONResponse``."""
    raw = await request.body()
    result: RouteResponse = await handler(request.method, raw if raw else b"{}")
    return JSONResponse(result.body, status_code=result.status)


def register_sessions(app: FastAPI, state: AppState) -> Any:
    """Mount the session endpoints and return the watchdog shutdown hook.

    Routes (mirroring Go ``registerSessions``):

    * ``GET  /sessions/stream``: pay-per-chunk SSE, cap 1.00 USDC, 0.0001 USDC/chunk
    * ``POST /sessions/stream``: voucher commits for the stream endpoint
    * ``POST /sessions/compute``: pay-per-call compute, cap 0.50 USDC, 0.005 USDC/call
      (also accepts voucher commits)
    * ``POST /__402/session/deliveries``: SessionFetch-style delivery reservation
    * ``POST /__402/session/commit``: body-voucher commit variant of the above
    * ``GET  /sessions/receipt/{channel_id}``: settle-status poll for the UI
    """
    # Shared store across both session methods so /sessions/receipt can read
    # channel state regardless of which endpoint opened the channel.
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
                # The Python port does not yet support the server-broadcast open
                # path (openTxSubmitter=server) or the on-chain settlement at
                # close, so this uses the default client-broadcast submitter and
                # no RPC client (offline core); see the module docstring.
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

    # GET /sessions/stream: stream tokens as SSE; each chunk costs 0.0001 USDC.
    @app.get("/sessions/stream")
    async def sessions_stream_get(request: Request) -> Any:
        gated = await stream_gate(request)
        if isinstance(gated, JSONResponse):
            return gated
        _credential, receipt = gated

        async def body() -> Any:
            for chunk in TOKEN_CHUNKS:
                yield "data: " + json.dumps({"chunk": chunk, "cost": "100"}, separators=(",", ":")) + "\n\n"
                await asyncio.sleep(0.08)
            yield "data: [DONE]\n\n"

        return StreamingResponse(
            body(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                **_receipt_header(receipt),
            },
        )

    # POST /sessions/stream: voucher commits arrive on the URL the session was
    # opened against, with the signed voucher in the Authorization credential.
    # The gate's verify path applies it; the body is an ack. Mirrors Go.
    @app.post("/sessions/stream")
    async def sessions_stream_post(request: Request) -> JSONResponse:
        gated = await stream_gate(request)
        if isinstance(gated, JSONResponse):
            return gated
        _credential, receipt = gated
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        return JSONResponse(_commit_ack(body), headers=_receipt_header(receipt))

    # POST /sessions/compute: pay-per-call compute; the same handler also accepts
    # voucher commits (a deliveryId in the body discriminates). Mirrors Go.
    @app.post("/sessions/compute")
    async def sessions_compute_post(request: Request) -> JSONResponse:
        gated = await compute_gate(request)
        if isinstance(gated, JSONResponse):
            return gated
        _credential, receipt = gated
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        delivery_id = str(body.get("deliveryId", ""))
        receipt_headers = _receipt_header(receipt)
        if delivery_id != "":
            return JSONResponse(
                {"amount": "0", "deliveryId": delivery_id, "status": "committed"},
                headers=receipt_headers,
            )
        log_payment(request.url.path, receipt_headers)
        prompt = str(body.get("prompt", ""))
        return JSONResponse(
            {
                "prompt": prompt,
                "output": "Echo: " + prompt + " (computed for 0.005 USDC)",
                "computedAt": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            headers=receipt_headers,
        )

    # Side-channel metering routes: SessionFetch-style clients reserve capacity
    # for each metered delivery before signing + committing the voucher. Both
    # handlers share the methods' channel store. Mirrors Go.
    routes = session_routes(stream_session.core(), touch=None)

    @app.post("/__402/session/deliveries")
    async def session_deliveries(request: Request) -> JSONResponse:
        return await _route_response(routes.deliveries, request)

    @app.post("/__402/session/commit")
    async def session_commit(request: Request) -> JSONResponse:
        return await _route_response(routes.commit, request)

    # Receipt poll endpoint: the UI hits this after the stream ends to learn the
    # on-chain settle signature. With no ported settlement path the settled
    # signature stays null; the watermark/deposit are reported from the shared
    # store. Mirrors Go's settle-status poll shape.
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
