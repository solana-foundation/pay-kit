"""Payment-aware httpx transport for automatic x402 ``exact`` 402 handling.

Mirrors the Go x402 ``PaymentTransport`` / ``NewClient``
(``go/protocols/x402/client/client.go``): a request whose first response is a
402 with an x402 ``exact`` challenge is satisfied by building a
``PAYMENT-SIGNATURE`` header and retrying the request once. The header name is
the one the pay_kit x402 server reads (``Payment-Signature``; confirmed in
``pay_kit.protocols.x402._payment_signature_header``).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Any

import httpx

from pay_kit.protocols.x402.client.exact.payment import (
    ChallengeSelection,
    build_payment_header,
    build_payment_header_legacy,
    parse_x402_challenge_with_version,
)
from pay_kit.protocols.x402.exact.legacy import X402_LEGACY_PAYMENT_HEADER
from pay_kit.protocols.x402.exact.verify import X402_VERSION_V1

if TYPE_CHECKING:
    from pay_kit.signer import LocalSigner

logger = logging.getLogger("pay_kit")

#: Request header the pay_kit x402 server reads the credential from.
PAYMENT_SIGNATURE_HEADER = "Payment-Signature"

__all__ = ["PaymentTransport", "X402Client", "x402_async_client", "PAYMENT_SIGNATURE_HEADER"]


class PaymentTransport(httpx.AsyncBaseTransport):
    """httpx transport that auto-pays x402 ``exact`` 402 responses.

    Wraps an inner transport and, on a 402 carrying an x402 ``exact`` challenge
    (``payment-required`` header or ``accepts[]`` JSON body), builds the
    ``PAYMENT-SIGNATURE`` header and retries the request once.
    """

    def __init__(
        self,
        signer: LocalSigner,
        rpc: Any,
        *,
        network: str | None = None,
        currencies: Sequence[str] | None = None,
        base_transport: httpx.AsyncBaseTransport | None = None,
        recent_blockhash_provider: Callable[[], Awaitable[str] | str] | None = None,
    ) -> None:
        self._signer = signer
        self._rpc = rpc
        self._selection = ChallengeSelection(network=network, currencies=currencies)
        self._inner = base_transport or httpx.AsyncHTTPTransport()
        self._recent_blockhash_provider = recent_blockhash_provider

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Handle a request, retrying once with a credential on a 402 challenge."""
        response = await self._inner.handle_async_request(request)
        if response.status_code != 402:
            return response

        await response.aread()
        body: str | None
        try:
            body = response.text
        except Exception:  # noqa: BLE001 - a non-decodable body just means "header only"
            body = None

        requirement, version = parse_x402_challenge_with_version(
            dict(response.headers), body, self._selection
        )
        if requirement is None:
            return response

        # Emit the producer matching the challenge's declared version: a v1
        # challenge gets the legacy X-PAYMENT credential, v2 (the default) gets
        # PAYMENT-SIGNATURE. Mirrors the go/swift transports.
        is_legacy = version == X402_VERSION_V1
        builder = build_payment_header_legacy if is_legacy else build_payment_header
        credential_header = X402_LEGACY_PAYMENT_HEADER if is_legacy else PAYMENT_SIGNATURE_HEADER
        try:
            header_value = await builder(
                self._signer,
                self._rpc,
                requirement,
                recent_blockhash_provider=self._recent_blockhash_provider,
            )
        except Exception:  # noqa: BLE001 - surface the original 402 on a build failure
            logger.warning("pay_kit: failed to build x402 payment credential", exc_info=True)
            return response

        headers = dict(request.headers)
        headers[credential_header] = header_value
        retry_request = httpx.Request(
            method=request.method,
            url=request.url,
            headers=headers,
            stream=request.stream,
            extensions=request.extensions,
        )
        return await self._inner.handle_async_request(retry_request)

    async def aclose(self) -> None:
        """Close the inner transport."""
        await self._inner.aclose()


def X402Client(  # noqa: N802 - factory named for the type it returns
    signer: LocalSigner,
    rpc: Any,
    *,
    network: str | None = None,
    currencies: Sequence[str] | None = None,
    recent_blockhash_provider: Callable[[], Awaitable[str] | str] | None = None,
    **client_kwargs: Any,
) -> httpx.AsyncClient:
    """Build an ``httpx.AsyncClient`` that auto-pays x402 ``exact`` 402s.

    Mirrors the Go ``NewClient`` ergonomics: pass a signer + RPC and get back a
    ready-to-use async client.
    """
    transport = PaymentTransport(
        signer,
        rpc,
        network=network,
        currencies=currencies,
        recent_blockhash_provider=recent_blockhash_provider,
        base_transport=client_kwargs.pop("base_transport", None),
    )
    return httpx.AsyncClient(transport=transport, **client_kwargs)


#: snake_case alias matching the rust/go free-function ergonomics.
x402_async_client = X402Client
