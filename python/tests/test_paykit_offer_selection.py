"""Regression tests for permission filtering before offer selection."""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from solana_pay_kit._paycore.network import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2
from solana_pay_kit.client import ClientPermissions, PermissionDeniedError, PermissionedPaymentTransport
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.headers import format_www_authenticate
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge

UNKNOWN_MINT = "11111111111111111111111111111111"


def mpp(amount: object = "500000", network: object = "mainnet", currency: str = "USDC") -> str:
    """Build one MPP offer without using a live signer or RPC."""
    challenge = PaymentChallenge.with_secret_key(
        secret_key="secret",
        realm="api",
        method="solana",
        intent="charge",
        request=encode_json(
            {"amount": amount, "currency": currency, "recipient": UNKNOWN_MINT, "methodDetails": {"network": network}}
        ),
    )
    return format_www_authenticate(challenge)


def x402(amount: str, asset: str = "USDC", network: str = SOLANA_MAINNET_CAIP2) -> dict[str, object]:
    """Build one supported exact offer."""
    return {
        "scheme": "exact",
        "network": network,
        "amount": amount,
        "asset": asset,
        "payTo": UNKNOWN_MINT,
        "maxTimeoutSeconds": 60,
        "extra": {},
    }


async def run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mpp_offers: list[str] | None = None,
    x402_offers: list[dict[str, object]] | None = None,
    version: int = 2,
    legacy_source: str = "body",
    permissions: ClientPermissions | None = None,
) -> tuple[httpx.Response, list[httpx.Request], AsyncMock, AsyncMock]:
    """Probe and retry against a local in-memory transport."""
    headers: list[tuple[str, str]] = [("www-authenticate", offer) for offer in mpp_offers or []]
    body: bytes | None = None
    if x402_offers is not None:
        envelope = json.dumps({"x402Version": version, "accepts": x402_offers})
        if version == 2:
            headers.append(("payment-required", base64.b64encode(envelope.encode()).decode()))
        elif legacy_source == "header":
            headers.append(("X-PAYMENT-REQUIRED", envelope))
        else:
            body = envelope.encode()
    requests: list[httpx.Request] = []

    async def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(402, headers=headers, content=body) if len(requests) == 1 else httpx.Response(200)

    mpp_build = AsyncMock(return_value="Payment credential")
    x402_build = AsyncMock(return_value="x402 credential")
    monkeypatch.setattr("solana_pay_kit.client.client.build_credential_header", mpp_build)
    monkeypatch.setattr("solana_pay_kit.client.client.build_payment_header", x402_build)
    monkeypatch.setattr("solana_pay_kit.client.client.build_payment_header_legacy", x402_build)
    transport = PermissionedPaymentTransport(
        MagicMock(),
        MagicMock(),
        network="mainnet",
        permissions=permissions or ClientPermissions.builder().build(),
        protocols=("mpp", "x402"),
        base_transport=httpx.MockTransport(handle),
    )
    result = await transport.handle_async_request(httpx.Request("POST", "https://api.example/paid", content=b"query"))
    return result, requests, mpp_build, x402_build


@pytest.mark.parametrize(
    "denied",
    [
        mpp("2000000"),
        mpp("1", "devnet"),
        mpp("1", "testnet"),
        mpp("bad"),
        mpp(1),
        mpp("1", "mainnet", UNKNOWN_MINT),
    ],
    ids=["over-cap", "denied-network", "unsupported-network", "invalid-amount", "invalid-schema", "unknown-asset"],
)
async def test_mpp_uses_the_next_permitted_offer(monkeypatch: pytest.MonkeyPatch, denied: str) -> None:
    result, requests, mpp_build, x402_build = await run(monkeypatch, mpp_offers=[denied, mpp()])

    assert result.status_code == 200
    assert len(requests) == 2
    assert [request.content for request in requests] == [b"query", b"query"]
    mpp_build.assert_awaited_once()
    assert mpp_build.call_args.kwargs["challenge"].decode_request()["amount"] == "500000"
    assert mpp_build.call_args.kwargs["max_amount_base_units"] == 1_000_000
    x402_build.assert_not_called()


async def test_mpp_preserves_server_order_among_permitted_offers(monkeypatch: pytest.MonkeyPatch) -> None:
    result, requests, build, _ = await run(monkeypatch, mpp_offers=[mpp("800000"), mpp("1")])
    assert result.status_code == 200
    assert len(requests) == 2
    assert build.call_args.kwargs["challenge"].decode_request()["amount"] == "800000"


async def test_mpp_can_fall_back_to_x402_after_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    result, requests, mpp_build, x402_build = await run(
        monkeypatch, mpp_offers=[mpp("2000000"), mpp("1", "devnet")], x402_offers=[x402("500000")]
    )
    assert result.status_code == 200
    assert len(requests) == 2
    mpp_build.assert_not_called()
    x402_build.assert_awaited_once()


@pytest.mark.parametrize("reverse", [False, True])
async def test_x402_filters_denied_assets_before_cheapest_selection(
    monkeypatch: pytest.MonkeyPatch, reverse: bool
) -> None:
    offers = [x402("1", UNKNOWN_MINT), x402("500000")]
    if reverse:
        offers.reverse()
    result, requests, _, build = await run(monkeypatch, x402_offers=offers)

    assert result.status_code == 200
    assert len(requests) == 2
    build.assert_awaited_once()
    assert build.call_args.args[2]["amount"] == "500000"


async def test_x402_keeps_cheapest_preferred_network_among_permitted_offers(monkeypatch: pytest.MonkeyPatch) -> None:
    result, requests, _, build = await run(
        monkeypatch,
        x402_offers=[x402("800000"), x402("1", network=SOLANA_DEVNET_CAIP2), x402("500000")],
        permissions=ClientPermissions.unrestricted(),
    )
    assert result.status_code == 200
    assert len(requests) == 2
    assert build.call_args.args[2]["amount"] == "500000"


async def test_x402_uses_a_permitted_network_when_the_preferred_offer_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    permissions = ClientPermissions.builder().only_network("devnet").build()
    result, requests, _, build = await run(
        monkeypatch, x402_offers=[x402("1"), x402("500000", network=SOLANA_DEVNET_CAIP2)], permissions=permissions
    )
    assert result.status_code == 200
    assert len(requests) == 2
    assert build.call_args.args[2]["network"] == SOLANA_DEVNET_CAIP2


@pytest.mark.parametrize("source", ["header", "body"])
async def test_x402_v1_filters_denied_offers_and_keeps_legacy_header(
    monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    offers = [x402("1", UNKNOWN_MINT, "solana"), x402("500000", network="solana")]
    for offer in offers:
        offer["maxAmountRequired"] = offer.pop("amount")
    result, requests, _, build = await run(monkeypatch, x402_offers=offers, version=1, legacy_source=source)
    assert result.status_code == 200
    assert len(requests) == 2
    build.assert_awaited_once()
    assert requests[1].headers["x-payment"] == "x402 credential"
    assert "payment-signature" not in requests[1].headers


async def test_all_denials_are_reported_without_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(PermissionDeniedError) as raised:
        await run(monkeypatch, mpp_offers=[mpp("2000000"), mpp("1", "devnet")], x402_offers=[x402("1", UNKNOWN_MINT)])
    assert [rejection.code for rejection in raised.value.rejections] == [
        "amount_exceeds_limit",
        "network_not_allowed",
        "asset_not_allowed",
    ]


async def test_invalid_x402_amount_does_not_hide_a_valid_offer(monkeypatch: pytest.MonkeyPatch) -> None:
    result, requests, _, build = await run(monkeypatch, x402_offers=[x402("-1"), x402("500000")])
    assert result.status_code == 200
    assert len(requests) == 2
    assert build.call_args.args[2]["amount"] == "500000"
