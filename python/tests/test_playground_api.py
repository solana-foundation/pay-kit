"""Smoke tests for the playground-api example.

Boots the FastAPI app (zero-config, unreachable settlement) with the TestClient
and asserts the free route serves and every paid route fires a 402 challenge
before its handler. Charge/session gating runs before the handler, so these
never touch the network.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from examples.playground_api.app import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_health_is_free(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/report"),  # charge-gated
        ("POST", "/compute"),  # session-gated
    ],
)
def test_paid_route_challenges_before_handler(client: TestClient, method: str, path: str) -> None:
    resp = client.request(method, path)
    assert resp.status_code == 402
    assert resp.headers.get("www-authenticate", "").startswith("Payment ")
