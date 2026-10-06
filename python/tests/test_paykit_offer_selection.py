"""Regression tests for permission filtering before offer selection."""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from solana_pay_kit._paycore.network import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2
from solana_pay_kit.client import (
    ClientPermissions,
    PermissionDeniedError,
    PermissionedPaymentTransport,
    PermissionRejection,
)
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.headers import format_www_authenticate
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge

UNKNOWN_MINT = "11111111111111111111111111111111"
OVERSIZED_DECIMAL = "1" * 4301


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


def x402(amount: str, asset: object = "USDC", network: str = SOLANA_MAINNET_CAIP2) -> dict[str, object]:
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
    include_body: bool = False,
    permissions: ClientPermissions | None = None,
) -> tuple[httpx.Response, list[httpx.Request], AsyncMock, AsyncMock]:
    """Probe and retry against a local in-memory transport."""
    headers: list[tuple[str, str]] = [("www-authenticate", offer) for offer in mpp_offers or []]
    body: bytes | None = None
    if x402_offers is not None:
        envelope = json.dumps({"x402Version": version, "accepts": x402_offers})
        if version == 2:
            headers.append(("payment-required", base64.b64encode(envelope.encode()).decode()))
            if include_body:
                body = envelope.encode()
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
        mpp("²"),
        mpp("٢"),
        mpp(OVERSIZED_DECIMAL),
        mpp("0.5"),
    ],
    ids=[
        "over-cap",
        "denied-network",
        "unsupported-network",
        "invalid-amount",
        "invalid-schema",
        "unknown-asset",
        "superscript-digit",
        "unicode-decimal",
        "oversized-decimal",
        "fractional-decimal",
    ],
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


@pytest.mark.parametrize("dual_protocol", [False, True])
@pytest.mark.parametrize("permission_error", [False, True])
async def test_mpp_paid_dispatch_error_does_not_try_another_offer(
    monkeypatch: pytest.MonkeyPatch, dual_protocol: bool, permission_error: bool
) -> None:
    request = httpx.Request("POST", "https://api.example/paid", content=b"query")
    error = (
        PermissionDeniedError((PermissionRejection("invalid_challenge_terms", "inner transport error"),))
        if permission_error
        else httpx.ReadError("paid dispatch failed", request=request)
    )
    headers = [("www-authenticate", mpp("800000")), ("www-authenticate", mpp("500000"))]
    envelope = json.dumps({"x402Version": 2, "accepts": [x402("500000")]})
    headers.append(("payment-required", base64.b64encode(envelope.encode()).decode()))
    requests: list[httpx.Request] = []

    async def handle(sent: httpx.Request) -> httpx.Response:
        requests.append(sent)
        if len(requests) == 1:
            return httpx.Response(402, headers=headers)
        raise error

    mpp_build = AsyncMock(return_value="Payment credential")
    x402_build = AsyncMock(return_value="x402 credential")
    monkeypatch.setattr("solana_pay_kit.client.client.build_credential_header", mpp_build)
    monkeypatch.setattr("solana_pay_kit.client.client.build_payment_header", x402_build)
    transport = PermissionedPaymentTransport(
        MagicMock(),
        MagicMock(),
        network="mainnet",
        permissions=ClientPermissions.builder().build(),
        protocols=("mpp", "x402") if dual_protocol else ("mpp",),
        base_transport=httpx.MockTransport(handle),
    )

    with pytest.raises(type(error)) as raised:
        await transport.handle_async_request(request)

    assert raised.value is error
    assert len(requests) == 2
    assert [sent.content for sent in requests] == [b"query", b"query"]
    mpp_build.assert_awaited_once()
    assert mpp_build.call_args.kwargs["challenge"].decode_request()["amount"] == "800000"
    x402_build.assert_not_called()


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


async def test_header_and_body_offer_copies_do_not_duplicate_denials(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(PermissionDeniedError) as raised:
        await run(monkeypatch, x402_offers=[x402("2000000"), x402("3000000")], include_body=True)
    assert [rejection.code for rejection in raised.value.rejections] == ["amount_exceeds_limit"] * 2
    assert [rejection.actual for rejection in raised.value.rejections] == [2_000_000, 3_000_000]


@pytest.mark.parametrize(
    "amount",
    ["-1", "²", "٢", OVERSIZED_DECIMAL, "0.5"],
    ids=["negative", "superscript-digit", "unicode-decimal", "oversized-decimal", "fractional-decimal"],
)
async def test_invalid_x402_amount_does_not_hide_a_valid_offer(monkeypatch: pytest.MonkeyPatch, amount: str) -> None:
    result, requests, _, build = await run(monkeypatch, x402_offers=[x402(amount), x402("500000")])
    assert result.status_code == 200
    assert len(requests) == 2
    build.assert_awaited_once()
    assert build.call_args.args[2]["amount"] == "500000"


@pytest.mark.parametrize("protocol", ["mpp", "x402"])
async def test_only_noncanonical_amounts_are_denied_without_signing(
    monkeypatch: pytest.MonkeyPatch, protocol: str
) -> None:
    amounts = ["²", OVERSIZED_DECIMAL]
    if protocol == "mpp":
        headers = [("www-authenticate", mpp(amount)) for amount in amounts]
    else:
        envelope = json.dumps({"x402Version": 2, "accepts": [x402(amount) for amount in amounts]})
        headers = [("payment-required", base64.b64encode(envelope.encode()).decode())]
    requests: list[httpx.Request] = []

    async def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(402, headers=headers)

    mpp_build = AsyncMock()
    x402_build = AsyncMock()
    monkeypatch.setattr("solana_pay_kit.client.client.build_credential_header", mpp_build)
    monkeypatch.setattr("solana_pay_kit.client.client.build_payment_header", x402_build)
    transport = PermissionedPaymentTransport(
        MagicMock(),
        MagicMock(),
        network="mainnet",
        permissions=ClientPermissions.builder().build(),
        protocols=(protocol,),
        base_transport=httpx.MockTransport(handle),
    )

    with pytest.raises(PermissionDeniedError) as raised:
        await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))

    assert [rejection.code for rejection in raised.value.rejections] == ["invalid_challenge_terms"] * 2
    assert len(requests) == 1
    mpp_build.assert_not_called()
    x402_build.assert_not_called()


@pytest.mark.parametrize("protocol", ["mpp", "x402"])
@pytest.mark.parametrize("amount", ["500000", "0", "000500000"])
async def test_ascii_decimal_amounts_remain_supported(
    monkeypatch: pytest.MonkeyPatch, protocol: str, amount: str
) -> None:
    result, requests, mpp_build, x402_build = await run(
        monkeypatch,
        mpp_offers=[mpp(amount)] if protocol == "mpp" else None,
        x402_offers=[x402(amount)] if protocol == "x402" else None,
    )
    assert result.status_code == 200
    assert len(requests) == 2
    if protocol == "mpp":
        mpp_build.assert_awaited_once()
        assert mpp_build.call_args.kwargs["challenge"].decode_request()["amount"] == amount
        x402_build.assert_not_called()
    else:
        x402_build.assert_awaited_once()
        assert x402_build.call_args.args[2]["amount"] == amount
        mpp_build.assert_not_called()


@pytest.mark.parametrize("asset", [None, 1, [], {}, True], ids=["null", "integer", "list", "object", "boolean"])
@pytest.mark.parametrize("reverse", [False, True])
async def test_malformed_x402_asset_does_not_hide_a_valid_offer(
    monkeypatch: pytest.MonkeyPatch, asset: object, reverse: bool
) -> None:
    offers = [x402("800000", asset), x402("500000")]
    if reverse:
        offers.reverse()
    result, requests, mpp_build, x402_build = await run(monkeypatch, x402_offers=offers)
    assert result.status_code == 200
    assert len(requests) == 2
    x402_build.assert_awaited_once()
    assert x402_build.call_args.args[2]["asset"] == "USDC"
    mpp_build.assert_not_called()


async def test_all_malformed_x402_assets_are_denied_without_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    envelope = json.dumps({"x402Version": 2, "accepts": [x402("1", asset) for asset in [None, 1, [], {}, True]]})
    headers = {"payment-required": base64.b64encode(envelope.encode()).decode()}
    requests: list[httpx.Request] = []

    async def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(402, headers=headers)

    build = AsyncMock()
    monkeypatch.setattr("solana_pay_kit.client.client.build_payment_header", build)
    transport = PermissionedPaymentTransport(
        MagicMock(),
        MagicMock(),
        network="mainnet",
        permissions=ClientPermissions.builder().build(),
        protocols=("x402",),
        base_transport=httpx.MockTransport(handle),
    )

    with pytest.raises(PermissionDeniedError) as raised:
        await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))

    assert [rejection.code for rejection in raised.value.rejections] == ["invalid_challenge_terms"] * 5
    assert len(requests) == 1
    build.assert_not_called()
