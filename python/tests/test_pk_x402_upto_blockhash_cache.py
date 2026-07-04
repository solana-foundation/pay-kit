"""Short-TTL, single-flight cache for the ``upto`` challenge blockhash.

The unauthenticated 402 challenge stamps ``extra.recentBlockhash``; today every
``accepts_entry`` call hits the (blocking) ``recent_blockhash_provider``, and the
FastAPI shim builds the body (``accepts_entry``) and the header
(``challenge_headers`` -> ``accepts_entry``) with two independent fetches. The
cache must collapse a burst to at most one provider call per TTL and make a
single 402 response fetch exactly once. Clock is injected/frozen - no sleeps.
"""

from __future__ import annotations

import threading
import time

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]

from solana_pay_kit import (
    Config,
    Gate,
    LocalSigner,
    Operator,
    Price,
    Protocol,
    Stablecoin,
    configure,
)
from solana_pay_kit.config import reset
from solana_pay_kit.protocols.x402.upto import X402Upto

BH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


class _CountingProvider:
    """Counts provider calls; optionally latches until released (single-flight)."""

    def __init__(self, *, latch: bool = False) -> None:
        self.calls = 0
        self._lock = threading.Lock()
        self._gate = threading.Event()
        self._latch = latch
        if not latch:
            self._gate.set()

    def release(self) -> None:
        self._gate.set()

    def __call__(self) -> str:
        with self._lock:
            self.calls += 1
            n = self.calls
        # Block outside the counter lock so a burst can pile up here, proving a
        # non-single-flight implementation would already have counted N calls.
        if self._latch:
            self._gate.wait(timeout=5)
        return f"{BH[:-1]}{n % 10}"


class _Clock:
    """Injectable monotonic clock (seconds); the test advances it explicitly."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _cfg() -> Config:
    op = Operator(signer=LocalSigner.from_keypair(Keypair()), recipient=str(Keypair().pubkey()))
    return configure(
        network="solana_localnet",
        preflight=False,
        accept=(Protocol.X402,),
        operator=op,
        rpc_url="http://127.0.0.1:8899",
    )


def _gate(cfg: Config) -> Gate:
    return Gate.build(
        name="usage",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=cfg.effective_recipient(),
        accept=(Protocol.X402,),
    )


def test_single_402_response_fetches_blockhash_once() -> None:
    """One FastAPI 402 = accepts_entry (body) + challenge_headers (header) = 1 fetch."""
    cfg = _cfg()
    provider = _CountingProvider()
    eng = X402Upto(cfg, recent_blockhash_provider=provider, clock=_Clock())
    gate, request = _gate(cfg), {"path": "/usage"}

    # Mirror the FastAPI shim's _usage_challenge: body then header.
    body_entry = eng.accepts_entry(gate, request)
    headers = eng.challenge_headers(gate, request)

    assert provider.calls == 1
    assert "payment-required" in headers
    assert body_entry["extra"].get("recentBlockhash") is not None


def test_challenge_burst_collapses_to_one_fetch_per_ttl() -> None:
    """A concurrent burst of challenges single-flights to exactly one provider call."""
    cfg = _cfg()
    provider = _CountingProvider(latch=True)
    eng = X402Upto(cfg, recent_blockhash_provider=provider, clock=_Clock())
    gate, request = _gate(cfg), {"path": "/usage"}

    results: list[dict] = []
    barrier = threading.Barrier(20)

    def _fire() -> None:
        barrier.wait()  # line every thread up before any fetch resolves
        results.append(eng.accepts_entry(gate, request))

    threads = [threading.Thread(target=_fire) for _ in range(20)]
    for t in threads:
        t.start()
    # Let the threads reach the latched provider, then release the single flight.
    time.sleep(0.05)
    provider.release()
    for t in threads:
        t.join(timeout=5)

    assert provider.calls == 1
    assert len(results) == 20
    blockhashes = {entry["extra"].get("recentBlockhash") for entry in results}
    assert blockhashes == {results[0]["extra"]["recentBlockhash"]}


def test_cache_expires_after_ttl() -> None:
    """Past the TTL the next challenge refetches (frozen clock, no sleep)."""
    cfg = _cfg()
    provider = _CountingProvider()
    clock = _Clock()
    eng = X402Upto(cfg, recent_blockhash_provider=provider, clock=clock)
    gate, request = _gate(cfg), {"path": "/usage"}

    eng.accepts_entry(gate, request)
    eng.accepts_entry(gate, request)
    assert provider.calls == 1  # within TTL -> cached

    clock.now += 3600.0  # well past any sane sub-minute TTL
    eng.accepts_entry(gate, request)
    assert provider.calls == 2  # expired -> refetched
