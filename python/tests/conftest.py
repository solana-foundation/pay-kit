"""Shared test fixtures."""

from __future__ import annotations

import pytest

from solana_pay_kit._paycore.store import MemoryStore
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge
from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

TEST_SECRET_KEY = "test-secret-key-that-is-long-enough-for-hmac-sha256"


@pytest.fixture(autouse=True)
def fast_signature_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink the on-chain confirmation poll for the whole unit suite.

    ``confirm_transaction_signature`` defaults to a 30 second deadline with a
    1 second poll, which is right against a real RPC where a freshly broadcast
    signature returns ``None`` for a while. Against the fake RPCs the unit
    suite uses, a signature that is going to stay unconfirmed stays unconfirmed
    forever, so every test covering the timeout branch waited the full 30
    seconds. Four such tests accounted for 120 of the suite's 130 seconds.

    The timeout branch is what these tests assert on, and it is reached the
    same way at 0.1 seconds as at 30. Tests that need the real deadline can
    still pass ``timeout_seconds`` explicitly, which wins over the values
    bound here.
    """
    from solana_pay_kit.protocols.mpp.server import session_method, session_onchain

    original = session_onchain.confirm_transaction_signature

    async def fast_confirm(rpc_client, signature, label, **kwargs):  # noqa: ANN001, ANN003
        kwargs.setdefault("timeout_seconds", 0.1)
        kwargs.setdefault("poll_interval_seconds", 0.01)
        return await original(rpc_client, signature, label, **kwargs)

    # `session_method` imports the helper by name, so it holds its own
    # reference and has to be patched alongside the defining module.
    monkeypatch.setattr(session_onchain, "confirm_transaction_signature", fast_confirm)
    monkeypatch.setattr(session_method, "confirm_transaction_signature", fast_confirm)


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
