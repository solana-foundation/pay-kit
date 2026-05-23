"""Shared test fixtures."""

from __future__ import annotations

import pytest

from solana_mpp._base64url import encode_json
from solana_mpp._types import PaymentChallenge
from solana_mpp.server.mpp import Config, Mpp
from solana_mpp.store import MemoryStore

TEST_SECRET_KEY = "test-secret-key-that-is-long-enough-for-hmac-sha256"


@pytest.fixture
def test_secret_key() -> str:
    return TEST_SECRET_KEY


@pytest.fixture
def test_challenge() -> PaymentChallenge:
    request = encode_json({"amount": "1000000", "currency": "USDC"})
    return PaymentChallenge.with_secret_key(
        secret_key=TEST_SECRET_KEY,
        realm="api.example.com",
        method="solana",
        intent="charge",
        request=request,
    )


@pytest.fixture
def memory_store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def test_mpp(monkeypatch: pytest.MonkeyPatch) -> Mpp:
    monkeypatch.setenv("MPP_SECRET_KEY", TEST_SECRET_KEY)
    config = Config(
        recipient="11111111111111111111111111111112",
        currency="USDC",
        decimals=6,
        network="devnet",
        secret_key=TEST_SECRET_KEY,
        store=MemoryStore(),
    )
    return Mpp(config)
