"""httpx transport and refund driver for x402 ``batch-settlement`` (Solana).

:class:`BatchPaymentTransport` answers a 402 ``batch-settlement`` challenge with
a payment from a :class:`~.payment.BatchSettlementClient`, reconciles the
client's channel with the ``PAYMENT-RESPONSE``, and retries once after a
corrective 402 the client adopted. :func:`refund_batch_channel` drives the
payer's forced close. The retry rule is the corrective ``PaymentRequired`` of
the SVM ``batch-settlement`` spec (section 4.6); the refund flow is its
payer-forced close (section 5). Shaped like this SDK's
``client/exact/transport.py``, and comparable with the x402 PR #23
``client/refund.ts``.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from collections.abc import AsyncGenerator, AsyncIterable, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, cast

import httpx

from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    BATCH_SETTLEMENT_SCHEME,
    BatchPaymentPayload,
    BatchSettlementResponse,
)
from solana_pay_kit.protocols.x402.client.exact.transport import PAYMENT_SIGNATURE_HEADER

if TYPE_CHECKING:
    from solana_pay_kit.protocols.x402.client.batch_settlement.payment import BatchSettlementClient

__all__ = [
    "PAYMENT_REQUIRED_HEADER",
    "PAYMENT_RESPONSE_HEADER",
    "BatchPaymentTransport",
    "parse_payment_required",
    "probe_batch_requirements",
    "refund_batch_channel",
]

logger = logging.getLogger("solana_pay_kit")

#: Default cap on a streaming request body this transport will hold in memory.
MAX_BUFFERED_BODY_BYTES = 8 * 1024 * 1024

#: 402 header carrying the base64 JSON ``PaymentRequired`` envelope.
PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
#: Response header carrying the base64 JSON settlement response.
PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"


def _b64json(value: str) -> object:
    try:
        return json.loads(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError):
        return None


def parse_payment_required(headers: Mapping[str, str], body: str | None) -> dict[str, Any] | None:
    """The 402 envelope from ``PAYMENT-REQUIRED``, else from a JSON body; ``None`` without a batch accept.

    The envelope's ``error`` is the corrective code, when the server sent one.
    """
    header = httpx.Headers(dict(headers)).get(PAYMENT_REQUIRED_HEADER)
    envelope = _b64json(header) if header else None
    if not isinstance(envelope, dict) and body:
        try:
            envelope = json.loads(body)
        except ValueError:
            envelope = None
    if not isinstance(envelope, dict):
        return None
    required = cast("dict[str, Any]", envelope)
    accepts = required.get("accepts")
    if not isinstance(accepts, list) or not any(
        isinstance(a, dict) and cast("dict[str, Any]", a).get("scheme") == BATCH_SETTLEMENT_SCHEME
        for a in cast("list[Any]", accepts)
    ):
        return None
    return required


def _payment_response(response: httpx.Response) -> BatchSettlementResponse | None:
    header = response.headers.get(PAYMENT_RESPONSE_HEADER)
    decoded = _b64json(header) if header else None
    return cast("BatchSettlementResponse", decoded) if isinstance(decoded, dict) else None


async def _challenge(response: httpx.Response) -> dict[str, Any] | None:
    if response.status_code != 402:
        return None
    await response.aread()
    try:
        body: str | None = response.text
    except UnicodeDecodeError:  # pragma: no cover - a non-text body just means "header only"
        body = None
    return parse_payment_required(response.headers, body)


def _encode(payment: BatchPaymentPayload) -> str:
    return base64.b64encode(json.dumps(payment).encode()).decode("ascii")


class BatchPaymentTransport(httpx.AsyncBaseTransport):
    """httpx transport that pays x402 ``batch-settlement`` 402s from one :class:`BatchSettlementClient`.

    A gated request is sent twice, unpaid then paid, so its body has to be
    replayable. Bodies httpx already holds (bytes, text, json, files) are; a
    streaming body is read into memory once before the first send, up to
    ``max_buffered_body_bytes``. A larger one is refused before anything is
    sent, because paying for a request whose body cannot be repeated would
    charge the payer for a body the server never receives.
    """

    def __init__(
        self,
        client: BatchSettlementClient,
        *,
        base_transport: httpx.AsyncBaseTransport | None = None,
        max_buffered_body_bytes: int = MAX_BUFFERED_BODY_BYTES,
    ) -> None:
        """Wrap ``base_transport`` (a fresh ``httpx.AsyncHTTPTransport`` by default)."""
        self._client = client
        self._inner = base_transport or httpx.AsyncHTTPTransport()
        self._max_body = max_buffered_body_bytes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Send ``request``; on a batch challenge pay and resend, once more after an adopted corrective.

        A streaming body is buffered before the first send: it would otherwise
        be consumed by the unpaid attempt and arrive empty on the paid one.
        """
        request = await self._replayable(request)
        response = await self._inner.handle_async_request(request)
        required = await _challenge(response)
        if required is None:
            return response
        for retried in (False, True):
            try:
                payment, _ = await self._client.create_payment_header(required)
            except Exception:  # noqa: BLE001 - surface the 402 when no payment can be built
                logger.warning("solana_pay_kit: failed to build a batch-settlement payment", exc_info=True)
                return response
            headers = dict(request.headers)
            headers[PAYMENT_SIGNATURE_HEADER] = _encode(payment)
            paid = httpx.Request(
                request.method, request.url, headers=headers, stream=request.stream, extensions=request.extensions
            )
            try:
                response = await self._inner.handle_async_request(paid)
                corrective = await _challenge(response)
            except BaseException:
                # No answer (reset, timeout, cancel): release the channel now,
                # not at the end of the lease, then surface the error.
                await self._client.handle_payment_response(payment, response=None)
                raise
            if response.status_code != 402:
                try:
                    await self._client.handle_payment_response(payment, response=_payment_response(response))
                except BatchSettlementError:
                    # The server answered; the client keeps its confirmed state.
                    logger.warning("solana_pay_kit: rejected a batch-settlement PAYMENT-RESPONSE", exc_info=True)
                return response
            adopted = await self._client.handle_payment_response(payment, response=None, payment_required=corrective)
            if not adopted or retried:
                return response
        return response  # pragma: no cover - the loop always returns

    async def _replayable(self, request: httpx.Request) -> httpx.Request:
        """Return a request whose body can be sent again, reading a stream in once.

        Nothing to do for a body httpx already holds. A stream is read up to
        the cap and rebuilt as bytes; over the cap it raises before the first
        send, so the server never sees half a request.
        """
        if hasattr(request, "_content"):
            return request
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._max_body:
            raise _too_large(int(declared), self._max_body)
        chunks: list[bytes] = []
        size = 0
        stream = cast("AsyncIterable[bytes]", request.stream)
        async for chunk in stream:
            size += len(chunk)
            if size > self._max_body:
                raise _too_large(size, self._max_body)
            chunks.append(chunk)
        framing = {"content-length", "transfer-encoding"}
        headers = {name: value for name, value in request.headers.items() if name.lower() not in framing}
        return httpx.Request(
            request.method, request.url, headers=headers, content=b"".join(chunks), extensions=request.extensions
        )

    async def aclose(self) -> None:
        """Close the inner transport."""
        await self._inner.aclose()


def _too_large(size: int, limit: int) -> ValueError:
    return ValueError(
        f"batch-settlement: a streaming body of {size} bytes is over max_buffered_body_bytes ({limit}); "
        "a paid request is sent twice, so its body must fit in memory"
    )


@asynccontextmanager
async def _session(http: httpx.AsyncClient | None) -> AsyncGenerator[httpx.AsyncClient]:
    if http is not None:
        yield http
        return
    async with httpx.AsyncClient() as owned:
        yield owned


async def probe_batch_requirements(url: str, http: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Every ``batch-settlement`` accept an unpaid ``GET`` of ``url`` advertises (the terms channels derive from)."""
    probe = await http.get(url)
    if probe.status_code != 402:
        raise ValueError(f"refund probe expected 402 from {url}, got {probe.status_code}")
    required = parse_payment_required(probe.headers, probe.text)
    if required is None:
        raise ValueError(f"{url} does not offer {BATCH_SETTLEMENT_SCHEME}")
    accepts = cast("list[dict[str, Any]]", required["accepts"])
    return [a for a in accepts if a.get("scheme") == BATCH_SETTLEMENT_SCHEME]


async def refund_batch_channel(
    build: Callable[[Mapping[str, Any]], Awaitable[BatchPaymentPayload]],
    url: str,
    *,
    requirements: Mapping[str, Any] | None = None,
    http: httpx.AsyncClient | None = None,
) -> BatchSettlementResponse:
    """Start the payer-forced close of the channel behind ``url``; return what the server reported.

    The escrow does not come back with this response: ``request_close`` starts
    the grace period, after which all unused escrow returns (there is no partial
    refund). A close carries no cumulative amount, so nothing is retried.
    """
    async with _session(http) as session:
        accepted = requirements if requirements is not None else (await probe_batch_requirements(url, session))[0]
        payment = await build(accepted)
        response = await session.get(url, headers={PAYMENT_SIGNATURE_HEADER: _encode(payment)})
    settled = _payment_response(response)
    if settled is not None:
        return settled
    if response.status_code == 402:
        reason = (parse_payment_required(response.headers, response.text) or {}).get("error")
        raise BatchSettlementError(str(reason or "refund_refused"), f"refund refused: {reason or 'no reason given'}")
    raise ValueError(f"refund response has no {PAYMENT_RESPONSE_HEADER} header (status {response.status_code})")
