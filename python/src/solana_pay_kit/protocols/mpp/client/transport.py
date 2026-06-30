"""Payment-aware HTTP transport for automatic 402 handling."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from solana_pay_kit.protocols.mpp.client.charge import build_credential_header
from solana_pay_kit.protocols.mpp.core.headers import parse_www_authenticate_all

logger = logging.getLogger(__name__)


class PaymentTransport(httpx.AsyncBaseTransport):
    """httpx transport that handles 402 Payment Required responses.

    Wraps an inner transport and automatically:
    1. Detects 402 responses with WWW-Authenticate: Payment headers
    2. Parses the challenge
    3. Builds a payment credential and retries the request

    Example:
        transport = PaymentTransport(
            signer=keypair,
            rpc_client=async_client,
        )

        async with httpx.AsyncClient(transport=transport) as client:
            response = await client.get("https://api.example.com/resource")
    """

    def __init__(
        self,
        signer: Any,
        rpc_client: Any,
        base_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._signer = signer
        self._rpc_client = rpc_client
        self._inner = base_transport or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Handle request, automatically retrying on 402 with credentials."""
        response = await self._inner.handle_async_request(request)

        if response.status_code != 402:
            return response

        # Read the response body
        await response.aread()

        # Look for WWW-Authenticate: Payment header
        www_auth_headers = response.headers.get_list("www-authenticate")

        challenges = parse_www_authenticate_all(www_auth_headers)
        challenge = challenges[0] if challenges else None

        if challenge is None:
            return response

        # Build credential and retry
        try:
            auth_header = await build_credential_header(
                signer=self._signer,
                rpc_client=self._rpc_client,
                challenge=challenge,
            )
        except Exception:
            logger.warning("Failed to build payment credential", exc_info=True)
            return response

        # Clone the request with the Authorization header
        headers = dict(request.headers)
        headers["authorization"] = auth_header

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
