"""Tests for the high-level automatic-payment permission layer."""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock

import httpx
import pytest

from solana_pay_kit._paycore.mints import resolve_stablecoin_mint, token_program_for
from solana_pay_kit._paycore.network import SOLANA_MAINNET_CAIP2
from solana_pay_kit.client import (
    AssetPermission,
    ClientPermissions,
    OriginPermissionOverride,
    PaymentCandidate,
    PermissionConfigurationError,
    PermissionDeniedError,
    PermissionedPaymentTransport,
    usd,
)
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.headers import format_www_authenticate
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge

UNKNOWN_MINT = "11111111111111111111111111111111"


class MockTransport(httpx.AsyncBaseTransport):
    """Return fixed responses while recording requests."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses[min(len(self.requests) - 1, len(self.responses) - 1)]

    async def aclose(self) -> None:
        return None


def candidate(*, amount: int, origin: str = "https://api.example/path", mint: str = "USDC") -> PaymentCandidate:
    """Build a mainnet candidate for policy tests."""
    return PaymentCandidate(amount=amount, mint=mint, network="mainnet", origin=origin)


def test_default_is_mainnet_stablecoins_with_one_dollar_cap() -> None:
    permissions = ClientPermissions.builder().build()

    assert permissions.authorize(candidate(amount=1_000_000)).max_amount_atomic == 1_000_000
    with pytest.raises(PermissionDeniedError) as raised:
        permissions.authorize(candidate(amount=1_000_001))
    assert raised.value.rejections[0].code == "amount_exceeds_limit"


def test_global_and_exact_origin_caps_do_not_grant_an_origin() -> None:
    permissions = (
        ClientPermissions.builder()
        .allow_origin("https://api.example/a")
        .max_amount_per_payment(usd("2"))
        .override_origin(
            OriginPermissionOverride.builder("https://trusted.example/resource")
            .max_amount_per_payment(usd("5"))
            .build()
        )
        .build()
    )

    assert permissions.authorize(candidate(amount=2_000_000)).max_amount_atomic == 2_000_000
    with pytest.raises(PermissionDeniedError) as raised:
        permissions.authorize(candidate(amount=1, origin="https://trusted.example"))
    assert raised.value.rejections[0].code == "origin_not_allowed"


def test_origin_asset_cap_overrides_global_asset_cap() -> None:
    permissions = (
        ClientPermissions.builder()
        .allow_asset(AssetPermission.with_cap("mainnet", UNKNOWN_MINT, 10))
        .override_origin(
            OriginPermissionOverride.builder("https://trusted.example")
            .asset_cap(AssetPermission.with_cap("mainnet", UNKNOWN_MINT, 25))
            .build()
        )
        .build()
    )

    assert (
        permissions.authorize(
            candidate(amount=25, origin="https://trusted.example", mint=UNKNOWN_MINT)
        ).max_amount_atomic
        == 25
    )
    with pytest.raises(PermissionDeniedError):
        permissions.authorize(candidate(amount=11, origin="https://other.example", mint=UNKNOWN_MINT))


def test_unknown_assets_require_explicit_permission() -> None:
    with pytest.raises(PermissionDeniedError):
        ClientPermissions.builder().build().authorize(candidate(amount=1, mint=UNKNOWN_MINT))
    assert (
        ClientPermissions.builder()
        .allow_any_asset()
        .build()
        .authorize(candidate(amount=99, mint=UNKNOWN_MINT))
        .max_amount_atomic
        is None
    )


def test_usd_parser_is_exact() -> None:
    assert usd("$0.000001").micro_usd == 1
    with pytest.raises(PermissionConfigurationError):
        usd("0.0000001")
    with pytest.raises(PermissionConfigurationError):
        usd("0")


async def test_denial_happens_before_mpp_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    challenge = PaymentChallenge.with_secret_key(
        secret_key="secret",
        realm="api",
        method="solana",
        intent="charge",
        request=encode_json(
            {
                "amount": "1000001",
                "currency": "USDC",
                "recipient": UNKNOWN_MINT,
                "methodDetails": {"network": "mainnet"},
            }
        ),
    )
    inner = MockTransport([httpx.Response(402, headers={"www-authenticate": format_www_authenticate(challenge)})])
    signer = MagicMock()
    build = MagicMock()
    monkeypatch.setattr("solana_pay_kit.client.client.build_credential_header", build)
    transport = PermissionedPaymentTransport(
        signer,
        MagicMock(),
        network="mainnet",
        permissions=ClientPermissions.builder().build(),
        protocols=("mpp",),
        base_transport=inner,
    )

    with pytest.raises(PermissionDeniedError):
        await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))

    build.assert_not_called()
    assert len(inner.requests) == 1


async def test_permitted_mpp_post_replays_body_and_authorization(monkeypatch: pytest.MonkeyPatch) -> None:
    challenge = PaymentChallenge.with_secret_key(
        secret_key="secret",
        realm="api",
        method="solana",
        intent="charge",
        request=encode_json(
            {
                "amount": "1000",
                "currency": "USDC",
                "recipient": UNKNOWN_MINT,
                "methodDetails": {"network": "mainnet"},
            }
        ),
    )
    inner = MockTransport(
        [
            httpx.Response(402, headers={"www-authenticate": format_www_authenticate(challenge)}),
            httpx.Response(200),
        ]
    )

    async def credential(**_kwargs: object) -> str:
        return "Payment credential"

    monkeypatch.setattr("solana_pay_kit.client.client.build_credential_header", credential)
    transport = PermissionedPaymentTransport(
        MagicMock(),
        MagicMock(),
        network="mainnet",
        permissions=ClientPermissions.builder().build(),
        protocols=("mpp",),
        base_transport=inner,
    )

    result = await transport.handle_async_request(
        httpx.Request("POST", "https://api.example/paid", content=b'{"query":"report"}')
    )

    assert result.status_code == 200
    assert [request.content for request in inner.requests] == [b'{"query":"report"}'] * 2
    assert inner.requests[1].headers["authorization"] == "Payment credential"


async def test_mpp_build_failure_falls_back_to_x402(monkeypatch: pytest.MonkeyPatch) -> None:
    challenge = PaymentChallenge.with_secret_key(
        secret_key="secret",
        realm="api",
        method="solana",
        intent="charge",
        request=encode_json(
            {
                "amount": "1000",
                "currency": "USDC",
                "recipient": UNKNOWN_MINT,
                "methodDetails": {"network": "mainnet"},
            }
        ),
    )
    mint = resolve_stablecoin_mint("USDC", "mainnet")
    assert mint is not None
    envelope = {
        "x402Version": 2,
        "resource": {"type": "http", "url": "https://api.example/paid"},
        "accepts": [
            {
                "protocol": "x402",
                "scheme": "exact",
                "network": SOLANA_MAINNET_CAIP2,
                "asset": mint,
                "amount": "1000",
                "maxAmountRequired": "1000",
                "payTo": UNKNOWN_MINT,
                "maxTimeoutSeconds": 60,
                "extra": {
                    "feePayer": UNKNOWN_MINT,
                    "decimals": 6,
                    "tokenProgram": token_program_for("USDC", "mainnet"),
                    "memo": "permission-test",
                },
            }
        ],
    }
    payment_required = base64.b64encode(json.dumps(envelope).encode()).decode()
    inner = MockTransport(
        [
            httpx.Response(
                402,
                headers={
                    "www-authenticate": format_www_authenticate(challenge),
                    "payment-required": payment_required,
                },
            ),
            httpx.Response(200),
        ]
    )

    async def broken_mpp(**_kwargs: object) -> str:
        raise ValueError("expired challenge")

    async def x402_credential(*_args: object, **_kwargs: object) -> str:
        return "x402 credential"

    monkeypatch.setattr("solana_pay_kit.client.client.build_credential_header", broken_mpp)
    monkeypatch.setattr("solana_pay_kit.client.client.build_payment_header", x402_credential)
    transport = PermissionedPaymentTransport(
        MagicMock(),
        MagicMock(),
        network="mainnet",
        permissions=ClientPermissions.builder().build(),
        protocols=("mpp", "x402"),
        base_transport=inner,
    )

    result = await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))

    assert result.status_code == 200
    assert inner.requests[1].headers["payment-signature"] == "x402 credential"


async def test_unsupported_x402_network_is_not_signed(monkeypatch: pytest.MonkeyPatch) -> None:
    envelope = {
        "x402Version": 2,
        "resource": {"type": "http", "url": "https://api.example/paid"},
        "accepts": [
            {
                "protocol": "x402",
                "scheme": "exact",
                "network": "solana:unsupported",
                "asset": "USDC",
                "amount": "500000",
                "maxAmountRequired": "500000",
                "payTo": UNKNOWN_MINT,
                "maxTimeoutSeconds": 60,
                "extra": {},
            }
        ],
    }
    payment_required = base64.b64encode(json.dumps(envelope).encode()).decode()
    inner = MockTransport([httpx.Response(402, headers={"payment-required": payment_required})])
    build = MagicMock()
    monkeypatch.setattr("solana_pay_kit.client.client.build_payment_header", build)
    transport = PermissionedPaymentTransport(
        MagicMock(),
        MagicMock(),
        network="mainnet",
        permissions=ClientPermissions.builder().build(),
        protocols=("x402",),
        base_transport=inner,
    )

    response = await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))

    assert response.status_code == 402
    build.assert_not_called()
    assert len(inner.requests) == 1
