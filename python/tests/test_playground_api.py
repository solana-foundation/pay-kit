"""Smoke tests for the playground-api example.

Boots the FastAPI app (zero-config, unreachable settlement) with the TestClient
and asserts the free routes serve and every paid route fires a 402 challenge
before its handler. Charge/session gating runs before the handler, so these
never touch the network; the faucet auto-funding is opt-in (off here).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from examples.playground_api import sessions
from examples.playground_api.app import app


@pytest.fixture
def client() -> TestClient:
    sessions.session.core().with_blockhash_cache(lambda: ("4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs", 1))
    return TestClient(app)


def test_health_is_free(client: TestClient) -> None:
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_discovery_advertises_offers(client: TestClient) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["openapi"] == "3.1.0"
    fortune = doc["paths"]["/api/v1/fortune"]["get"]
    offers = fortune["x-payment-info"]["offers"]
    # The dual-protocol charge gate offers both rails; the split gate is MPP-only.
    assert {offer["method"] for offer in offers} == {"x402", "mpp"}
    joke_offers = doc["paths"]["/api/v1/joke"]["get"]["x-payment-info"]["offers"]
    assert {offer["method"] for offer in joke_offers} == {"mpp"}
    # The x402 upto usage gate is advertised so the playground UI renders it.
    summarize_offers = doc["paths"]["/api/v1/summarize"]["post"]["x-payment-info"]["offers"]
    assert summarize_offers[0]["scheme"] == "upto"
    assert summarize_offers[0]["intent"] == "usage"


def test_docs_index_is_free(client: TestClient) -> None:
    resp = client.get("/api/v1/docs")
    assert resp.status_code == 200
    assert "available" in resp.json()


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/v1/fortune"),  # charge-gated, dual protocol
        ("GET", "/api/v1/quote/AAPL"),  # charge-gated, dual protocol
        ("GET", "/api/v1/joke"),  # charge-gated, MPP-only split
        ("GET", "/api/v1/stream"),  # session-gated
    ],
)
def test_paid_route_challenges_before_handler(client: TestClient, method: str, path: str) -> None:
    resp = client.request(method, path)
    assert resp.status_code == 402
    assert resp.headers.get("www-authenticate", "").startswith("Payment ")


def test_summarize_route_challenges_with_upto(client: TestClient) -> None:
    """The x402 ``upto`` summarize route returns a 402 with the upto challenge.

    x402-only, so it advertises the ``payment-required`` header (not the MPP
    ``www-authenticate``) and an ``upto`` accepts entry.
    """
    resp = client.post("/api/v1/summarize", content="summarize this text please")
    assert resp.status_code == 402
    assert any(k.lower() == "payment-required" for k in resp.headers)
    accepts = resp.json()["accepts"]
    assert accepts[0]["scheme"] == "upto"
    extra = accepts[0]["extra"]
    assert extra["feePayer"]
    assert extra["receiverAuthorizer"]
    assert extra["withdrawDelay"] == 900
    assert "assetTransferMethod" not in extra
    assert "facilitatorAddress" not in extra
