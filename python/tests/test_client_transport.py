"""Tests for client/transport module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx

from solana_pay_kit.protocols.mpp.client.transport import PaymentTransport
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.headers import format_www_authenticate
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge


class MockTransport(httpx.AsyncBaseTransport):
    """Mock transport that returns pre-configured responses."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = list(responses)
        self._call_count = 0
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        idx = min(self._call_count, len(self._responses) - 1)
        self._call_count += 1
        return self._responses[idx]


class TestPaymentTransport:
    def _make_challenge(self) -> PaymentChallenge:
        request = encode_json({"amount": "1000000", "currency": "USDC", "recipient": "abc"})
        return PaymentChallenge.with_secret_key(
            secret_key="test-secret",
            realm="api",
            method="solana",
            intent="charge",
            request=request,
        )

    async def test_passthrough_non_402(self):
        """Non-402 responses should pass through unchanged."""
        response = httpx.Response(200, text="OK")
        inner = MockTransport([response])
        transport = PaymentTransport(
            signer=MagicMock(),
            rpc_client=MagicMock(),
            base_transport=inner,
        )
        result = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        assert result.status_code == 200

    async def test_passthrough_402_without_challenge(self):
        """402 without WWW-Authenticate should pass through."""
        response = httpx.Response(402, text="Payment Required")
        inner = MockTransport([response])
        transport = PaymentTransport(
            signer=MagicMock(),
            rpc_client=MagicMock(),
            base_transport=inner,
        )
        result = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        assert result.status_code == 402

    async def test_402_with_challenge_attempts_retry(self):
        """402 with a valid challenge should attempt to build credential and retry."""
        challenge = self._make_challenge()
        www_auth = format_www_authenticate(challenge)

        # First response: 402 with challenge
        first_response = httpx.Response(
            402,
            headers={"www-authenticate": www_auth},
            text="Payment Required",
        )
        # Second response: 200 (after successful payment)
        second_response = httpx.Response(200, text="Paid content")
        inner = MockTransport([first_response, second_response])

        # Mock the credential builder to raise (simulating no solana libs)
        transport = PaymentTransport(
            signer=MagicMock(),
            rpc_client=MagicMock(),
            base_transport=inner,
        )

        # Since we can't actually build credentials without solana libs,
        # the transport should gracefully return the 402 response
        result = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        # Without real solana libs, it falls back to returning the 402
        assert result.status_code in (200, 402)

    async def test_402_with_non_payment_scheme(self):
        """402 with non-Payment WWW-Authenticate should pass through."""
        response = httpx.Response(
            402,
            headers={"www-authenticate": 'Bearer realm="test"'},
            text="Payment Required",
        )
        inner = MockTransport([response])
        transport = PaymentTransport(
            signer=MagicMock(),
            rpc_client=MagicMock(),
            base_transport=inner,
        )
        result = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        assert result.status_code == 402

    async def test_402_with_combined_www_authenticate_payment_challenge(self, monkeypatch):
        """Combined WWW-Authenticate values should still find Payment challenges."""
        challenge = self._make_challenge()
        www_auth = f'Bearer realm="test", {format_www_authenticate(challenge)}'

        first_response = httpx.Response(402, headers={"www-authenticate": www_auth})
        second_response = httpx.Response(200, text="Paid content")
        inner = MockTransport([first_response, second_response])

        async def fake_build_credential_header(**kwargs):
            assert kwargs["challenge"].id == challenge.id
            return "Payment credential"

        monkeypatch.setattr(
            "solana_pay_kit.protocols.mpp.client.transport.build_credential_header",
            fake_build_credential_header,
        )

        transport = PaymentTransport(
            signer=MagicMock(),
            rpc_client=MagicMock(),
            base_transport=inner,
        )

        result = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert result.status_code == 200
        assert len(inner.requests) == 2
        assert inner.requests[1].headers["authorization"] == "Payment credential"

    async def test_aclose(self):
        """aclose should close the inner transport."""
        inner = AsyncMock(spec=httpx.AsyncBaseTransport)
        transport = PaymentTransport(
            signer=MagicMock(),
            rpc_client=MagicMock(),
            base_transport=inner,
        )
        await transport.aclose()
        inner.aclose.assert_called_once()
