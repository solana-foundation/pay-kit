"""Concurrent-replay regression for MPP charge push-mode (``type="signature"``).

A TOCTOU replay was disclosed in the TypeScript MPP charge push-mode verify:
the fetch of the on-chain transaction (the "check") and the reserve of the
consumed-signature marker (the "use") were two separate store operations, so
N concurrent verifies of the SAME signature credential could all pass the
fetch before any of them reserved, and every one would issue a Receipt.

The Python SDK closes this window: ``_verify_signature`` fetches the tx and
then reserves in a single atomic ``await self._store.put_if_absent(...)``
(``solana_pay_kit/protocols/mpp/server/charge.py``); ``MemoryStore.put_if_absent``
is guarded by an ``asyncio.Lock`` (``solana_pay_kit/_paycore/store.py``). There
is no separate ``get`` on the consumed key.

This test drives the push-mode verify path with a stubbed RPC that yields the
event loop (``await asyncio.sleep(0)``) inside the tx fetch, forcing every
coroutine to interleave between fetch and reserve. It fires N (>= 8) concurrent
verifies of the same signature credential and asserts EXACTLY ONE Receipt is
issued while the rest raise ``ReplayError``.
"""

from __future__ import annotations

import asyncio

import pytest

from solana_pay_kit._paycore.errors import ReplayError
from solana_pay_kit._paycore.store import MemoryStore
from solana_pay_kit.protocols.mpp.core.types import PaymentCredential
from solana_pay_kit.protocols.mpp.intents.charge import ChargeRequest
from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp

TEST_SECRET = "test-secret-key-that-is-long-enough-for-hmac-sha256"
TEST_RECIPIENT = "11111111111111111111111111111112"
VALID_SIGNATURE = "1111111111111111111111111111111111111111111111111111111111111111"


class _FakeResponse:
    def __init__(self, value):
        self.value = value


class _InterleavingRPC:
    """Stub RPC that returns a fixed confirmed SOL-transfer transaction.

    The ``await asyncio.sleep(0)`` in ``get_transaction`` forces the running
    coroutine to yield the event loop between the check (fetch) and the use
    (reserve), so all N gathered verifies interleave at exactly the window the
    TOCTOU replay would exploit. ``get_transaction`` also counts its calls so
    the test can confirm every coroutine really reached the fetch.
    """

    def __init__(self, tx):
        self._tx = tx
        self.get_transaction_calls = 0

    async def get_transaction(self, *_args, **_kwargs):
        self.get_transaction_calls += 1
        await asyncio.sleep(0)
        return _FakeResponse(self._tx)

    async def send_raw_transaction(self, *_args, **_kwargs):  # pragma: no cover - push mode never broadcasts
        raise AssertionError("push-mode verify must not broadcast")

    async def await_confirmation(self, *_args, **_kwargs):  # pragma: no cover - push mode never awaits confirmation
        return None


def _confirmed_sol_tx() -> dict:
    """A confirmed SOL transfer to the route recipient, no memo."""
    return {
        "meta": {"err": None},
        "transaction": {
            "message": {
                "instructions": [
                    {
                        "program": "system",
                        "parsed": {
                            "type": "transfer",
                            "info": {"destination": TEST_RECIPIENT, "lamports": "1000"},
                        },
                    }
                ]
            }
        },
    }


def _build_mpp(rpc) -> Mpp:
    return Mpp(
        Config(
            recipient=TEST_RECIPIENT,
            currency="SOL",
            decimals=9,
            network="devnet",
            secret_key=TEST_SECRET,
            rpc=rpc,
            store=MemoryStore(),
            # Push-mode (signature) credentials are opt-in (spec §13.5).
            accept_push_mode=True,
        )
    )


async def test_concurrent_signature_replay_yields_exactly_one_receipt():
    n = 8
    rpc = _InterleavingRPC(_confirmed_sol_tx())
    mpp = _build_mpp(rpc)

    challenge = mpp.charge("0.000001")
    expected = ChargeRequest.from_dict(challenge.decode_request())

    def _fresh_credential() -> PaymentCredential:
        # Each coroutine gets its own credential object, but they all carry
        # the SAME on-chain signature — the value the consumed-key is derived
        # from. Distinct objects rule out any accidental sharing of mutable
        # per-credential state masking the race.
        return PaymentCredential(
            challenge=challenge.to_echo(),
            payload={"type": "signature", "signature": VALID_SIGNATURE},
        )

    results = await asyncio.gather(
        *(mpp.verify_credential_with_expected(_fresh_credential(), expected) for _ in range(n)),
        return_exceptions=True,
    )

    receipts = [r for r in results if not isinstance(r, BaseException)]
    replays = [r for r in results if isinstance(r, ReplayError)]
    other = [r for r in results if isinstance(r, BaseException) and not isinstance(r, ReplayError)]

    assert not other, f"unexpected errors from concurrent verify: {other!r}"
    assert len(receipts) == 1, f"expected exactly one receipt, got {len(receipts)}: {results!r}"
    assert len(replays) == n - 1, f"expected {n - 1} replay errors, got {len(replays)}: {results!r}"

    receipt = receipts[0]
    assert receipt.is_success()
    assert receipt.reference == VALID_SIGNATURE

    # Sanity: every coroutine really passed through the fetch (the "check"),
    # so the single-receipt outcome is enforced by the atomic reserve, not by
    # some coroutine short-circuiting before it ever raced.
    assert rpc.get_transaction_calls == n


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
