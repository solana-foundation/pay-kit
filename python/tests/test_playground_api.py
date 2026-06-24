"""Smoke tests for the playground-api example.

Boots the FastAPI app (zero-config, unreachable settlement) with the TestClient
and asserts the free routes serve and every paid route fires a 402 challenge
before its handler. Charge/session gating runs before the handler, so these
never touch the network; the faucet auto-funding is opt-in (off here).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from examples.playground_api.app import app


@pytest.fixture
def client() -> TestClient:
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
