"""Permission checks must cover the asset used by the credential builder."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from solders.keypair import Keypair
from solders.message import to_bytes_versioned
from solders.transaction import VersionedTransaction

from solana_pay_kit import Gate, Price, Protocol, Stablecoin
from solana_pay_kit._middleware import PayCore
from solana_pay_kit._paycore.mints import resolve_stablecoin_mint
from solana_pay_kit._paycore.network import SOLANA_MAINNET_CAIP2
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.client import (
    AssetPermission,
    ClientPermissions,
    PermissionDeniedError,
    PermissionedPaymentTransport,
    usd,
)
from solana_pay_kit.config import Config, MppConfig
from solana_pay_kit.operator import Operator
from solana_pay_kit.signer import LocalSigner

BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"
OTHER_MINT = str(Keypair.from_seed(bytes([31] * 32)).pubkey())
USDC_MINT = resolve_stablecoin_mint("USDC", "mainnet") or ""
if not USDC_MINT:
    raise RuntimeError("missing mainnet USDC mint")


class TrackingSigner(LocalSigner):
    """Count local signatures; this signer never submits transactions."""

    def __init__(self) -> None:
        super().__init__(Keypair())
        self.sign_calls = 0

    def sign(self, message: bytes) -> bytes:
        self.sign_calls += 1
        return super().sign(message)


class NoRpc:
    """Fail if a test reaches an RPC operation."""

    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"unexpected RPC operation: {name}")


def offer(amount: str = "10", *, asset: object = USDC_MINT, currency: object = None) -> dict[str, object]:
    """Build a complete offer for the real, offline exact credential builder."""
    return {
        "scheme": "exact",
        "network": SOLANA_MAINNET_CAIP2,
        "amount": amount,
        "asset": asset,
        "currency": currency,
        "payTo": OTHER_MINT,
        "maxTimeoutSeconds": 60,
        "extra": {"decimals": 6, "tokenProgram": TOKEN_PROGRAM, "recentBlockhash": BLOCKHASH, "memo": "asset-test"},
    }


async def request_offers(
    offers: list[dict[str, object]],
    *,
    version: int = 2,
    source: str = "header",
    permissions: ClientPermissions | None = None,
) -> tuple[httpx.Response | PermissionDeniedError, list[httpx.Request], TrackingSigner]:
    """Use real parsing, policy, transaction building and local signing."""
    signer = TrackingSigner()
    if version == 1:
        offers = [{**item, "network": "solana", "maxAmountRequired": item["amount"]} for item in offers]
        for item in offers:
            del item["amount"]
    envelope = json.dumps({"x402Version": version, "accepts": offers})
    headers: dict[str, str] = {}
    body: bytes | None = None
    if version == 2:
        headers["payment-required"] = base64.b64encode(envelope.encode()).decode()
    elif source == "header":
        headers["x-payment-required"] = envelope
    else:
        body = envelope.encode()
    requests: list[httpx.Request] = []

    async def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(402, headers=headers, content=body) if len(requests) == 1 else httpx.Response(200)

    transport = PermissionedPaymentTransport(
        signer,
        NoRpc(),
        network="mainnet",
        permissions=permissions or ClientPermissions.builder().build(),
        protocols=("x402",),
        base_transport=httpx.MockTransport(handle),
        recent_blockhash_provider=lambda: BLOCKHASH,
    )
    try:
        result = await transport.handle_async_request(httpx.Request("GET", "https://api.example/paid"))
    except PermissionDeniedError as exc:
        return exc, requests, signer
    return result, requests, signer


def assert_signed_asset(request: httpx.Request, signer: TrackingSigner, mint: str) -> None:
    """Verify the transaction signature and TransferChecked mint account."""
    header = request.headers.get("payment-signature") or request.headers["x-payment"]
    envelope = json.loads(base64.b64decode(header))
    tx = VersionedTransaction.from_bytes(base64.b64decode(envelope["payload"]["transaction"]))
    keys = list(tx.message.account_keys)
    signer_index = keys.index(signer.keypair.pubkey())
    assert tx.signatures[signer_index].verify(signer.keypair.pubkey(), to_bytes_versioned(tx.message))
    transfer = next(ix for ix in tx.message.instructions if str(keys[ix.program_id_index]) == TOKEN_PROGRAM)
    assert bytes(transfer.data)[0] == 12
    assert str(keys[transfer.accounts[1]]) == mint


@pytest.mark.parametrize("version,source", [(2, "header"), (1, "header"), (1, "body")])
@pytest.mark.parametrize("currency,code", [(OTHER_MINT, "asset_not_allowed"), ("SOL", "invalid_challenge_terms")])
async def test_denied_currency_override_is_not_signed(version: int, source: str, currency: str, code: str) -> None:
    result, requests, signer = await request_offers([offer(currency=currency)], version=version, source=source)
    assert isinstance(result, PermissionDeniedError)
    assert result.rejections[0].code == code
    assert len(requests) == 1
    assert signer.sign_calls == 0


@pytest.mark.parametrize("version,source", [(2, "header"), (1, "header"), (1, "body")])
async def test_allowed_currency_override_signs_the_authorized_asset(version: int, source: str) -> None:
    permissions = ClientPermissions.builder().allow_asset(AssetPermission.with_cap("mainnet", OTHER_MINT, 10)).build()
    result, requests, signer = await request_offers(
        [offer(currency=OTHER_MINT)],
        version=version,
        source=source,
        permissions=permissions,
    )
    assert isinstance(result, httpx.Response)
    assert result.status_code == 200
    assert len(requests) == 2
    assert signer.sign_calls == 1
    assert_signed_asset(requests[1], signer, OTHER_MINT)


@pytest.mark.parametrize("version,source", [(2, "header"), (1, "header"), (1, "body")])
async def test_currency_override_uses_its_actual_asset_cap(version: int, source: str) -> None:
    permissions = ClientPermissions.builder().allow_asset(AssetPermission.with_cap("mainnet", OTHER_MINT, 9)).build()
    result, requests, signer = await request_offers(
        [offer(currency=OTHER_MINT)],
        version=version,
        source=source,
        permissions=permissions,
    )
    assert isinstance(result, PermissionDeniedError)
    assert result.rejections[0].code == "amount_exceeds_limit"
    assert result.rejections[0].limit == 9
    assert len(requests) == 1
    assert signer.sign_calls == 0


async def test_stablecoin_currency_override_uses_stablecoin_cap() -> None:
    permissions = (
        ClientPermissions.builder().allow_asset(AssetPermission.with_cap("mainnet", OTHER_MINT, 3_000_000)).build()
    )
    result, requests, signer = await request_offers(
        [offer("2000000", asset=OTHER_MINT, currency=USDC_MINT)],
        permissions=permissions,
    )
    assert isinstance(result, PermissionDeniedError)
    assert result.rejections[0].code == "amount_exceeds_limit"
    assert result.rejections[0].limit == 1_000_000
    assert len(requests) == 1
    assert signer.sign_calls == 0


async def test_allowed_stablecoin_currency_can_override_a_denied_advertised_asset() -> None:
    result, requests, signer = await request_offers([offer(asset=OTHER_MINT, currency=USDC_MINT)])
    assert isinstance(result, httpx.Response)
    assert result.status_code == 200
    assert len(requests) == 2
    assert signer.sign_calls == 1
    assert_signed_asset(requests[1], signer, USDC_MINT)


async def test_denied_effective_asset_does_not_block_a_later_permitted_offer() -> None:
    result, requests, signer = await request_offers([offer("1", currency=OTHER_MINT), offer("500000")])
    assert isinstance(result, httpx.Response)
    assert result.status_code == 200
    assert len(requests) == 2
    assert signer.sign_calls == 1
    assert_signed_asset(requests[1], signer, USDC_MINT)


@pytest.mark.parametrize("currency", [None, "", 1, [], {}], ids=["missing", "empty", "integer", "list", "object"])
async def test_empty_or_nonstring_currency_keeps_builder_asset_fallback(currency: object) -> None:
    result, requests, signer = await request_offers([offer(currency=currency)])
    assert isinstance(result, httpx.Response)
    assert result.status_code == 200
    assert signer.sign_calls == 1
    assert_signed_asset(requests[1], signer, USDC_MINT)


@pytest.mark.parametrize("asset", [None, 1, [], {}], ids=["null", "integer", "list", "object"])
async def test_currency_override_does_not_bypass_raw_asset_shape_guard(asset: object) -> None:
    result, requests, signer = await request_offers([offer(asset=asset, currency=USDC_MINT)])
    assert isinstance(result, PermissionDeniedError)
    assert result.rejections[0].code == "invalid_challenge_terms"
    assert len(requests) == 1
    assert signer.sign_calls == 0


@pytest.mark.parametrize("distinct_offer", [False, True])
async def test_real_server_resource_annotation_does_not_duplicate_denials(distinct_offer: bool) -> None:
    signer = TrackingSigner()
    cfg = Config(
        preflight=False,
        accept=(Protocol.X402,),
        operator=Operator(signer=signer),
        mpp=MppConfig(challenge_binding_secret="permission-offer-selection-test-secret"),
    )
    core = PayCore(cfg)
    request = httpx.Request("GET", "https://api.example/paid")
    gate = Gate.build(name="report", amount=Price.usd("0.10", Stablecoin.USDC), default_pay_to=signer.pubkey())
    headers, body = core.build_402(gate, request)
    assert isinstance(json.loads(base64.b64decode(headers["payment-required"]))["resource"], dict)
    assert isinstance(body["resource"], str)
    if distinct_offer:
        other_gate = Gate.build(name="other", amount=Price.usd("0.20", Stablecoin.USDC), default_pay_to=signer.pubkey())
        _, other_body = core.build_402(other_gate, request)
        body["accepts"].extend(other_body["accepts"])
    requests: list[httpx.Request] = []

    async def handle(incoming: httpx.Request) -> httpx.Response:
        requests.append(incoming)
        return httpx.Response(402, headers=headers, json=body)

    permissions = ClientPermissions.builder().only_network("localnet").max_amount_per_payment(usd("0.01")).build()
    transport = PermissionedPaymentTransport(
        signer,
        NoRpc(),
        network="localnet",
        permissions=permissions,
        protocols=("x402",),
        base_transport=httpx.MockTransport(handle),
    )
    with pytest.raises(PermissionDeniedError) as raised:
        await transport.handle_async_request(request)
    assert [rejection.code for rejection in raised.value.rejections] == ["amount_exceeds_limit"] * (
        2 if distinct_offer else 1
    )
    assert [rejection.actual for rejection in raised.value.rejections] == (
        [100000, 200000] if distinct_offer else [100000]
    )
    assert len(requests) == 1
    assert signer.sign_calls == 0
