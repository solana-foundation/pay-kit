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
    PaymentDestination,
    PermissionConfigurationError,
    PermissionDeniedError,
    PermissionedPaymentTransport,
    usd,
)
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.headers import format_www_authenticate
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge

UNKNOWN_MINT = "11111111111111111111111111111111"
PAYEE = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
SPLIT = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


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


def candidate(
    *,
    amount: int,
    origin: str = "https://api.example/path",
    mint: str = "USDC",
    destinations: tuple[PaymentDestination, ...] | None = None,
) -> PaymentCandidate:
    """Build a mainnet candidate for policy tests, paying ``PAYEE`` by default."""
    return PaymentCandidate(
        amount=amount,
        mint=mint,
        network="mainnet",
        origin=origin,
        destinations=destinations if destinations is not None else (PaymentDestination(PAYEE, amount),),
    )


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


def test_recipient_allowlist_covers_the_primary_recipient_and_every_split() -> None:
    permissions = ClientPermissions.builder().allow_recipient(PAYEE).build()
    assert permissions.authorize(candidate(amount=1_000)).max_amount_atomic == 1_000_000

    with_split = (PaymentDestination(PAYEE, 900), PaymentDestination(SPLIT, 100))
    with pytest.raises(PermissionDeniedError) as raised:
        permissions.authorize(candidate(amount=1_000, destinations=with_split))
    assert raised.value.rejections[0].code == "recipient_not_allowed"
    with pytest.raises(PermissionDeniedError) as raised:
        permissions.authorize(candidate(amount=1_000, destinations=(PaymentDestination(SPLIT, 1_000),)))
    assert raised.value.rejections[0].code == "recipient_not_allowed"

    both = ClientPermissions.builder().allow_recipient(PAYEE).allow_recipient(SPLIT).build()
    assert both.authorize(candidate(amount=1_000, destinations=with_split)).max_amount_atomic == 1_000_000
    anyone = ClientPermissions.builder().allow_recipient(PAYEE).allow_any_recipient().build()
    assert anyone.authorize(candidate(amount=1_000, destinations=with_split)).max_amount_atomic == 1_000_000
    with pytest.raises(PermissionConfigurationError):
        ClientPermissions.builder().allow_recipient("not-an-address")


@pytest.mark.parametrize(
    "destinations",
    [(), (PaymentDestination(PAYEE, 999),), (PaymentDestination("not-an-address", 1_000),)],
)
def test_destinations_must_be_valid_and_add_up_to_the_amount(destinations: tuple[PaymentDestination, ...]) -> None:
    with pytest.raises(PermissionDeniedError) as raised:
        ClientPermissions.builder().build().authorize(candidate(amount=1_000, destinations=destinations))
    assert raised.value.rejections[0].code == "invalid_challenge_terms"


async def test_mpp_split_to_an_unapproved_recipient_is_not_signed(monkeypatch: pytest.MonkeyPatch) -> None:
    challenge = PaymentChallenge.with_secret_key(
        secret_key="secret",
        realm="api",
        method="solana",
        intent="charge",
        request=encode_json(
            {
                "amount": "1000",
                "currency": "USDC",
                "recipient": PAYEE,
                "methodDetails": {"network": "mainnet", "splits": [{"recipient": SPLIT, "amount": "400"}]},
            }
        ),
    )
    build = MagicMock()
    monkeypatch.setattr("solana_pay_kit.client.client.build_credential_header", build)
    for permissions, signed in (
        (ClientPermissions.builder().allow_recipient(PAYEE).build(), False),
        (ClientPermissions.builder().allow_recipient(PAYEE).allow_recipient(SPLIT).build(), True),
    ):
        build.reset_mock()
        inner = MockTransport(
            [
                httpx.Response(402, headers={"www-authenticate": format_www_authenticate(challenge)}),
                httpx.Response(200),
            ]
        )

        async def credential(**_kwargs: object) -> str:
            build()
            return "Payment credential"

        monkeypatch.setattr("solana_pay_kit.client.client.build_credential_header", credential)
        transport = PermissionedPaymentTransport(
            MagicMock(),
            MagicMock(),
            network="mainnet",
            permissions=permissions,
            protocols=("mpp",),
            base_transport=inner,
        )
        if signed:
            response = await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))
            assert response.status_code == 200
            build.assert_called_once()
        else:
            with pytest.raises(PermissionDeniedError) as raised:
                await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))
            assert raised.value.rejections[0].code == "recipient_not_allowed"
            assert SPLIT in raised.value.rejections[0].message
            build.assert_not_called()
            assert len(inner.requests) == 1


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


@pytest.mark.parametrize("network", [None, SOLANA_MAINNET_CAIP2])
async def test_x402_offer_without_network_is_not_signed(monkeypatch: pytest.MonkeyPatch, network: str | None) -> None:
    mint = resolve_stablecoin_mint("USDC", "mainnet")
    offer: dict[str, object] = {"scheme": "exact", "asset": mint, "amount": "1000", "payTo": PAYEE}
    if network is not None:
        offer["network"] = network
    # Hand the transport the offer directly: the selector already skips
    # network-less offers, and the permission layer must not rely on that.
    monkeypatch.setattr("solana_pay_kit.client.client.parse_x402_challenge_with_version", lambda *_args: (offer, 2))

    async def x402_credential(*_args: object, **_kwargs: object) -> str:
        return "x402 credential"

    monkeypatch.setattr("solana_pay_kit.client.client.build_payment_header", x402_credential)
    inner = MockTransport([httpx.Response(402, headers={"payment-required": "e30="}), httpx.Response(200)])
    transport = PermissionedPaymentTransport(
        MagicMock(),
        MagicMock(),
        network="mainnet",
        permissions=ClientPermissions.builder().build(),
        protocols=("x402",),
        base_transport=inner,
    )

    if network is None:
        with pytest.raises(PermissionDeniedError) as raised:
            await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))
        assert raised.value.rejections[0].code == "invalid_challenge_terms"
        assert "missing network" in raised.value.rejections[0].message
        assert len(inner.requests) == 1
    else:
        response = await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))
        assert response.status_code == 200
        assert inner.requests[1].headers["payment-signature"] == "x402 credential"


async def test_x402_recipient_alias_is_ignored_by_the_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    # RULINGS X1: only payTo names the destination. An allowlisted legacy
    # `recipient` beside an unlisted payTo does not approve the payment.
    mint = resolve_stablecoin_mint("USDC", "mainnet")
    offer = {
        "scheme": "exact",
        "network": SOLANA_MAINNET_CAIP2,
        "asset": mint,
        "amount": "1000",
        "payTo": PAYEE,
        "recipient": SPLIT,
        "maxTimeoutSeconds": 60,
        "extra": {},
    }
    payment_required = base64.b64encode(json.dumps({"x402Version": 2, "accepts": [offer]}).encode()).decode()

    async def x402_credential(*_args: object, **_kwargs: object) -> str:
        return "x402 credential"

    monkeypatch.setattr("solana_pay_kit.client.client.build_payment_header", x402_credential)

    def transport(allowed: str) -> tuple[PermissionedPaymentTransport, MockTransport]:
        inner = MockTransport(
            [httpx.Response(402, headers={"payment-required": payment_required}), httpx.Response(200)]
        )
        return (
            PermissionedPaymentTransport(
                MagicMock(),
                MagicMock(),
                network="mainnet",
                permissions=ClientPermissions.builder().allow_recipient(allowed).build(),
                protocols=("x402",),
                base_transport=inner,
            ),
            inner,
        )

    denied, inner = transport(SPLIT)
    with pytest.raises(PermissionDeniedError) as raised:
        await denied.handle_async_request(httpx.Request("GET", "https://api.example/paid"))
    assert raised.value.rejections[0].code == "recipient_not_allowed"
    assert len(inner.requests) == 1

    allowed, _ = transport(PAYEE)
    response = await allowed.handle_async_request(httpx.Request("GET", "https://api.example/paid"))
    assert response.status_code == 200


@pytest.mark.parametrize(
    ("amount_field", "cap_allows"),
    [("amount", True), ("maxAmountRequired", True), ("maxAmountRequired", False)],
)
async def test_x402_v1_offer_is_approved_on_max_amount_required(
    monkeypatch: pytest.MonkeyPatch, amount_field: str, cap_allows: bool
) -> None:
    # RULINGS X1: the amount falls back to the v1 `maxAmountRequired`, the same
    # value the legacy builder signs, so the approval covers that amount.
    mint = resolve_stablecoin_mint("USDC", "mainnet")
    amount = "1000" if cap_allows else "2000000"
    offer: dict[str, object] = {
        "scheme": "exact",
        "network": SOLANA_MAINNET_CAIP2,
        "asset": mint,
        amount_field: amount,
        "payTo": PAYEE,
    }
    monkeypatch.setattr("solana_pay_kit.client.client.parse_x402_challenge_with_version", lambda *_args: (offer, 1))

    async def x402_credential(*_args: object, **_kwargs: object) -> str:
        return "x402 credential"

    monkeypatch.setattr("solana_pay_kit.client.client.build_payment_header_legacy", x402_credential)
    inner = MockTransport([httpx.Response(402, headers={"payment-required": "e30="}), httpx.Response(200)])
    transport = PermissionedPaymentTransport(
        MagicMock(),
        MagicMock(),
        network="mainnet",
        permissions=ClientPermissions.builder().build(),
        protocols=("x402",),
        base_transport=inner,
    )

    if cap_allows:
        response = await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))
        assert response.status_code == 200
        assert inner.requests[1].headers["x-payment"] == "x402 credential"
    else:
        with pytest.raises(PermissionDeniedError) as raised:
            await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))
        assert raised.value.rejections[0].code != "invalid_challenge_terms"
        assert len(inner.requests) == 1
