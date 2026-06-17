"""Smoke tests for the playground-api example (mirrors Go's main_test.go).

Boots the FastAPI app against an unreachable RPC (no network, no funding) and
asserts the surface the playground web app depends on: the config catalog, the
free routes, and that every paid route fires a 402 challenge before its handler.
Charge gating runs before the handler, so these never reach yfinance.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from solders.keypair import Keypair

from examples.playground_api.app import AppState, create_app
from pay_kit.signer import LocalSigner


@pytest.fixture
def client() -> TestClient:
    state = AppState(
        network="localnet",
        rpc_url="http://127.0.0.1:1",  # unreachable: health balance is best-effort, challenges are local
        recipient=str(Keypair().pubkey()),
        secret_key="a" * 64,
        fee_payer=LocalSigner.from_keypair(Keypair()),
        repo_root=None,
    )
    return TestClient(create_app(state))


def test_config_catalog_lists_the_advertised_endpoints(client: TestClient) -> None:
    body = client.get("/api/v1/config").json()
    assert {"recipient", "network", "feePayer", "endpoints"} <= body.keys()
    ids = {e["id"] for e in body["endpoints"]}
    assert ids == {"stocks-quote", "marketplace-buy", "sessions-stream", "sessions-compute"}


def test_health_ok_without_rpc(client: TestClient) -> None:
    body = client.get("/api/v1/health").json()
    assert body["ok"] is True
    # Balance is best-effort; the unreachable RPC means it is simply absent.
    assert "feePayerBalance" not in body


def test_marketplace_products_is_free(client: TestClient) -> None:
    resp = client.get("/api/v1/marketplace/products")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/v1/stocks/quote/AAPL"),
        ("GET", "/api/v1/marketplace/buy/sol-hoodie"),
        ("GET", "/sessions/stream"),
        ("POST", "/sessions/compute"),
    ],
)
def test_paid_route_challenges_before_handler(client: TestClient, method: str, path: str) -> None:
    resp = client.request(method, path)
    assert resp.status_code == 402
    assert resp.headers.get("www-authenticate", "").startswith("Payment ")


def test_unknown_product_404s_before_payment(client: TestClient) -> None:
    # The product guard runs ahead of the payment dependency.
    resp = client.get("/api/v1/marketplace/buy/does-not-exist")
    assert resp.status_code == 404


def test_receipt_unknown_channel_404(client: TestClient) -> None:
    resp = client.get("/sessions/receipt/not-a-real-channel")
    assert resp.status_code == 404
