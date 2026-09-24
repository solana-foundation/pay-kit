"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from solana_pay_kit._paycore.store import MemoryStore
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge
from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

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


@pytest.fixture
def reset_batch_globals() -> Iterator[None]:
    """Drop the process globals a batch test leaves behind: the configured Config and its engines.

    ``configure()`` sets a module global and ``batch_engine()`` caches one
    engine per Config, so without this the next test can find a channel store
    filled in by the last one. Used through ``pytestmark`` in the batch suites.
    """
    yield
    from solana_pay_kit.config import reset as reset_config
    from solana_pay_kit.protocols.x402 import batch_settlement

    batch_settlement._ENGINES.clear()  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    reset_config()
