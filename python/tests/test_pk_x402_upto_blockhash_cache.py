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
from solana_pay_kit.protocols.x402.upto.types import UptoRequirements

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

    results: list[UptoRequirements] = []
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
    expected = results[0]["extra"].get("recentBlockhash")
    assert expected is not None
    assert blockhashes == {expected}


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


class _WorkerAbort(BaseException):
    """A BaseException (not Exception) escaping the provider - e.g. a worker
    timeout/shutdown signal (SystemExit, gevent.Timeout). Uses a custom class,
    not KeyboardInterrupt, to keep pytest sane while still bypassing the
    ``except Exception`` guard.
    """


class _AbortThenValueProvider:
    """Raises a BaseException on the first call, returns a good value after."""

    def __init__(self) -> None:
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            self.calls += 1
            n = self.calls
        if n == 1:
            raise _WorkerAbort("worker aborted mid-fetch")
        return f"{BH[:-1]}{n % 10}"


def test_base_exception_from_provider_does_not_wedge_single_flight() -> None:
    """A BaseException escaping the leader's provider call must reset the fetch
    flag and wake waiters, so later callers refetch instead of blocking forever.
    """
    cfg = _cfg()
    provider = _AbortThenValueProvider()
    eng = X402Upto(cfg, recent_blockhash_provider=provider, clock=_Clock())

    # Leader thread: the provider raises a BaseException that escapes the
    # ``except Exception`` guard. The leader catches it so the thread exits.
    leader_raised: list[BaseException] = []

    def _lead() -> None:
        try:
            eng._fetch_recent_blockhash()
        except _WorkerAbort as exc:  # noqa: SLF001 - exercising the internal seam
            leader_raised.append(exc)

    leader = threading.Thread(target=_lead)
    leader.start()
    leader.join(timeout=5)
    assert not leader.is_alive()
    assert len(leader_raised) == 1

    # The single-flight flag must be cleared once the BaseException escapes;
    # otherwise every later fetch loops on _blockhash_ready.wait forever.
    assert eng._blockhash_fetching is False  # noqa: SLF001

    # A second caller must be able to become leader and get the fresh value
    # rather than block indefinitely. Run it on a thread with a bounded join so
    # a wedge shows up as a still-alive thread (fails today).
    result: list[str | None] = []

    def _follow() -> None:
        result.append(eng._fetch_recent_blockhash())  # noqa: SLF001

    follower = threading.Thread(target=_follow)
    follower.start()
    follower.join(timeout=3)
    assert not follower.is_alive(), "second fetch wedged on the single-flight flag"
    assert result == [f"{BH[:-1]}2"]
