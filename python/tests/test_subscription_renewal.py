"""Tests for lazy renewal on access: one puller-signed charge per unpaid period.

Spec Renewal section: collect before serving, at most one successful charge
per period, never partial, never send past the period the transaction was
built for. The attempt keys serialize submits; ``ChainSim`` enforces the
program's per-period cap.
"""

from __future__ import annotations

import asyncio
import struct
from typing import Any

import pytest
from solders.hash import Hash
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.rpc import RpcResponseError
from solana_pay_kit.protocols.mpp._subscriptions import decode_delegation
from solana_pay_kit.protocols.mpp.client.subscription import SubscriptionActivation
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, Receipt
from solana_pay_kit.protocols.mpp.server.subscription import (
    _MAX_FAILED_RENEWALS,  # pyright: ignore[reportPrivateUsage]
    _RENEWAL_BUCKET_SECONDS,  # pyright: ignore[reportPrivateUsage]
)
from tests._subscription_fixtures import (
    AMOUNT,
    NOW,
    PERIOD_SECONDS,
    PLAN,
    PROGRAM_ID,
    SERVER,
    install_plan,
    ok_status,
)
from tests.test_subscription_server import DELEGATION, Harness

DUE = NOW + PERIOD_SECONDS + 10
WINDOW = _RENEWAL_BUCKET_SECONDS
BUCKET = DUE // WINDOW
CLAIM = f"solana-subscription:renewal:{DELEGATION}:{NOW}:1:t{{}}"  # delegation, anchor, period, bucket
FAILED = f"solana-subscription:renewal:{DELEGATION}:{NOW}:1:err:{{}}"
PAID = f"solana-subscription:renewal:{DELEGATION}:{NOW}:1"
SEEDED_SIGNATURE = "5" * 88


@pytest.fixture
def h(monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(monkeypatch)


async def due(h: Harness) -> tuple[PaymentChallenge, SubscriptionActivation]:
    challenge, activation, _ = await h.activate()
    h.now = DUE
    return challenge, activation


def renewals(h: Harness) -> list[VersionedTransaction]:
    return [VersionedTransaction.from_bytes(raw) for raw in h.rpc.sent[1:]]


def landed_behind_a_lagging_replica(h: Harness) -> None:
    """The period is paid on chain, but the first delegation read still serves the unpaid state."""
    stale = h.rpc.accounts[str(DELEGATION)]
    h.set_delegation(current_period_start_ts=NOW + PERIOD_SECONDS, amount_pulled_in_period=AMOUNT)
    read, lagged = h.rpc.get_account_info, []

    async def lagging(address: str, commitment: str = "confirmed") -> Any:
        if address == str(DELEGATION) and not lagged:
            lagged.append(address)
            return stale
        return await read(address, commitment)

    h.rpc.get_account_info = lagging  # type: ignore[method-assign]


@pytest.mark.parametrize("sponsor", [None, Keypair.from_seed(bytes([8] * 32))], ids=["puller-pays", "sponsor-pays"])
async def test_renews_unpaid_period_once(monkeypatch: pytest.MonkeyPatch, sponsor: Keypair | None) -> None:
    h = Harness(monkeypatch, **({"fee_payer": True, "fee_payer_signer": sponsor} if sponsor else {}))
    challenge, activation = await due(h)
    receipt = await h.access(challenge, activation)
    [renewal] = renewals(h)
    assert all(renewal.verify_with_results())
    assert renewal.message.account_keys[0] == (sponsor or SERVER).pubkey()
    [ix] = renewal.message.instructions
    assert bytes(ix.data)[0] == 10 and struct.unpack_from("<Q", bytes(ix.data), 1)[0] == AMOUNT
    assert (receipt.reference, receipt.period_index) == (str(renewal.signatures[0]), 1)
    state = decode_delegation(*h.rpc.accounts[str(DELEGATION)], PROGRAM_ID)
    assert (state.current_period_start_ts, state.amount_pulled_in_period) == (NOW + PERIOD_SECONDS, AMOUNT)

    again = await h.access(challenge, activation)
    assert len(renewals(h)) == 1
    assert (again.reference, again.period_index) == (receipt.reference, 1)


async def test_missed_periods_charge_only_the_current_one(h: Harness) -> None:
    challenge, activation, _ = await h.activate()
    h.now = NOW + 3 * PERIOD_SECONDS + 5
    receipt = await h.access(challenge, activation)
    assert len(renewals(h)) == 1 and receipt.period_index == 3


async def test_renewal_disabled_answers_402(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch, renew_on_access=False)
    challenge, activation = await due(h)
    with pytest.raises(PaymentError, match="not paid"):
        await h.access(challenge, activation)
    assert renewals(h) == []


def _cancel(h: Harness) -> None:
    h.set_delegation(expires_at_ts=NOW + PERIOD_SECONDS)


def _plan_ended(h: Harness) -> None:
    install_plan(h.rpc, status=0, end_ts=DUE)


def _plan_deleted(h: Harness) -> None:
    del h.rpc.accounts[str(PLAN)]


def _partial_pull(h: Harness) -> None:
    h.set_delegation(amount_pulled_in_period=AMOUNT - 1)
    h.now = NOW + 10  # still inside the current chain period


@pytest.mark.parametrize(
    ("block", "match"),
    [
        (_cancel, "cancellation"),
        (_plan_ended, "ended"),
        (_plan_deleted, "no longer exists"),
        (_partial_pull, "not paid"),
    ],
    ids=["cancelled", "plan-ended", "plan-deleted", "partial-pull-never-topped-up"],
)
async def test_no_renewal_when_blocked(h: Harness, block: Any, match: str) -> None:
    challenge, activation = await due(h)
    block(h)
    with pytest.raises(PaymentError, match=match):
        await h.access(challenge, activation)
    assert renewals(h) == []


async def test_sunset_plan_keeps_renewing_until_end_ts(h: Harness) -> None:
    # subscribe needs an Active plan; transfer_subscription does not check status.
    challenge, activation = await due(h)
    install_plan(h.rpc, status=0, end_ts=DUE + 1)
    assert (await h.access(challenge, activation)).period_index == 1
    assert len(renewals(h)) == 1


async def test_local_clock_ahead_of_chain_does_not_submit(h: Harness) -> None:
    challenge, activation = await due(h)
    h.chain.clock = lambda: NOW + PERIOD_SECONDS - 5  # the chain is still in the paid period
    with pytest.raises(PaymentError, match="chain period has not ended"):
        await h.access(challenge, activation)
    assert renewals(h) == []


async def test_rejected_claim_is_not_resent_in_its_window(h: Harness) -> None:
    challenge, activation = await due(h)
    h.rpc.send_error = RpcResponseError("Transaction simulation failed", code="payment_invalid")
    with pytest.raises(RpcResponseError):
        await h.access(challenge, activation)
    assert await h.store.get(CLAIM.format(BUCKET) + ":rejected") == {"rejected": True}
    h.rpc.send_error = None
    with pytest.raises(PaymentError, match="retry later"):
        await h.access(challenge, activation)
    assert renewals(h) == []


async def test_rejections_never_lock_the_period(h: Harness) -> None:
    # A short ATA: every window's attempt is refused at preflight and costs nothing.
    challenge, activation = await due(h)
    h.rpc.send_error = RpcResponseError("insufficient funds", code="payment_invalid")
    for n in range(60):
        h.rpc.blockhash = str(Hash(bytes([n + 1] * 32)))  # each window signs over its own blockhash
        with pytest.raises(RpcResponseError):
            await h.access(challenge, activation)
        h.now += WINDOW
    h.rpc.send_error = None  # funds arrive
    receipt = await h.access(challenge, activation)
    assert receipt.period_index == 1 and len(renewals(h)) == 1


async def test_no_renewal_after_subscription_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch, subscription_expires="2025-07-01T00:00:00Z")  # before DUE, after NOW
    challenge, activation = await due(h)
    with pytest.raises(PaymentError, match="expired"):
        await h.access(challenge, activation)
    assert renewals(h) == []


async def test_in_flight_claim_of_the_last_window_blocks_a_submit(h: Harness) -> None:
    challenge, activation = await due(h)
    await h.store.put(CLAIM.format(BUCKET - 1), {"signature": SEEDED_SIGNATURE, "blockhash": h.rpc.blockhash})
    with pytest.raises(PaymentError, match="in flight"):
        await h.access(challenge, activation)
    assert renewals(h) == []


@pytest.mark.parametrize("death", ["landed-with-error", "expired-unseen"])
async def test_dead_claim_of_the_last_window_allows_a_submit(h: Harness, death: str) -> None:
    challenge, activation = await due(h)
    await h.store.put(CLAIM.format(BUCKET - 1), {"signature": SEEDED_SIGNATURE, "blockhash": "old"})
    if death == "landed-with-error":
        h.rpc.statuses[SEEDED_SIGNATURE] = {"err": {"Custom": 1}, "confirmationStatus": "confirmed"}
    else:
        h.rpc.blockhash_valid = False
    receipt = await h.access(challenge, activation)
    assert len(renewals(h)) == 1
    assert await h.store.get(CLAIM.format(BUCKET)) == {"signature": receipt.reference, "blockhash": h.rpc.blockhash}


async def test_processed_claim_is_in_flight_not_dead(h: Harness) -> None:
    # The blockhash is gone but the cluster has the transaction: it can still be
    # confirmed, so the period must not be charged a second time.
    challenge, activation = await due(h)
    await h.store.put(CLAIM.format(BUCKET - 1), {"signature": SEEDED_SIGNATURE, "blockhash": "old"})
    h.rpc.expired_blockhashes.add("old")
    h.rpc.statuses[SEEDED_SIGNATURE] = {"err": None, "confirmationStatus": "processed"}
    with pytest.raises(PaymentError, match="in flight"):
        await h.access(challenge, activation)
    assert renewals(h) == []


async def test_landed_claim_of_the_last_window_grants_without_a_new_send(h: Harness) -> None:
    challenge, activation = await due(h)
    await h.store.put(CLAIM.format(BUCKET - 1), {"signature": SEEDED_SIGNATURE, "blockhash": h.rpc.blockhash})
    h.rpc.statuses[SEEDED_SIGNATURE] = ok_status()
    landed_behind_a_lagging_replica(h)
    receipt = await h.access(challenge, activation)
    assert renewals(h) == [] and (receipt.reference, receipt.period_index) == (SEEDED_SIGNATURE, 1)


async def test_landed_claim_the_replica_does_not_show_yet_is_not_resent(h: Harness) -> None:
    challenge, activation = await due(h)
    await h.store.put(CLAIM.format(BUCKET - 1), {"signature": SEEDED_SIGNATURE, "blockhash": h.rpc.blockhash})
    h.rpc.statuses[SEEDED_SIGNATURE] = ok_status()
    # A replica still shows the old period: answer 402, never charge again.
    with pytest.raises(PaymentError, match="does not show the period paid"):
        await h.access(challenge, activation)
    assert renewals(h) == []


async def test_paid_marker_grants_without_a_new_send(h: Harness) -> None:
    challenge, activation = await due(h)
    await h.store.put(PAID, {"signature": SEEDED_SIGNATURE})
    landed_behind_a_lagging_replica(h)
    receipt = await h.access(challenge, activation)
    assert renewals(h) == [] and (receipt.reference, receipt.period_index) == (SEEDED_SIGNATURE, 1)


async def test_concurrent_accesses_submit_once(h: Harness) -> None:
    challenge, activation = await due(h)
    fetch = h.rpc.get_latest_blockhash
    both_read_the_claim = asyncio.Event()
    waiting = 0

    async def barrier(commitment: str = "confirmed") -> Any:
        # Hold each request here until both have read "no claim for this window",
        # so the claim is the only thing that can serialize them.
        nonlocal waiting
        waiting += 1
        if waiting == 2:
            both_read_the_claim.set()
        await both_read_the_claim.wait()
        return await fetch(commitment)

    h.rpc.get_latest_blockhash = barrier  # type: ignore[method-assign]
    results = await asyncio.gather(
        h.access(challenge, activation), h.access(challenge, activation), return_exceptions=True
    )
    assert len(renewals(h)) == 1
    assert sorted(type(result).__name__ for result in results) == ["PaymentError", "Receipt"]
    assert any("in flight" in str(result) for result in results if not isinstance(result, Receipt))


async def test_period_end_before_submit_does_not_send(h: Harness) -> None:
    challenge, activation = await due(h)
    fetch = h.rpc.get_latest_blockhash

    async def slow_blockhash(commitment: str = "confirmed") -> Any:
        h.chain.clock = lambda: NOW + 2 * PERIOD_SECONDS  # the chain period ends while the renewal is built
        return await fetch(commitment)

    h.rpc.get_latest_blockhash = slow_blockhash  # type: ignore[method-assign]
    with pytest.raises(PaymentError, match="period ended"):
        await h.access(challenge, activation)
    assert renewals(h) == []


async def test_landed_errors_are_capped_per_period(h: Harness) -> None:
    challenge, activation = await due(h)
    h.rpc.on_send = None  # every renewal lands with an error and moves nothing

    async def lands_with_error(signature: str) -> None:
        h.rpc.statuses[signature] = {"err": {"Custom": 1}, "confirmationStatus": "confirmed"}
        raise PaymentError(f"transaction {signature} failed on-chain", code="transaction-failed")

    h.rpc.await_confirmation = lands_with_error  # type: ignore[method-assign]
    for n in range(_MAX_FAILED_RENEWALS):
        h.rpc.blockhash = str(Hash(bytes([30 + n] * 32)))  # each window signs over its own blockhash
        with pytest.raises(PaymentError, match="failed on-chain"):
            await h.access(challenge, activation)
        h.now += WINDOW
    sent = [str(tx.signatures[0]) for tx in renewals(h)]
    recorded = [(await h.store.get(FAILED.format(n)) or {}).get("signature") for n in range(_MAX_FAILED_RENEWALS)]
    assert recorded == sent
    h.now += WINDOW  # no claim in the last window: only the recorded failures can refuse this
    with pytest.raises(PaymentError, match="too many times"):
        await h.access(challenge, activation)
    assert len(renewals(h)) == _MAX_FAILED_RENEWALS


async def test_landed_error_seen_only_in_history_still_counts(h: Harness) -> None:
    challenge, activation = await due(h)
    for n in range(_MAX_FAILED_RENEWALS - 1):
        await h.store.put(FAILED.format(n), {"signature": str(n + 1) * 88})
    await h.store.put(CLAIM.format(BUCKET - 1), {"signature": SEEDED_SIGNATURE, "blockhash": "old"})
    h.rpc.history_statuses[SEEDED_SIGNATURE] = {"err": {"Custom": 1}, "confirmationStatus": "finalized"}
    h.rpc.blockhash_valid = False  # the status cache dropped it long after its blockhash expired
    with pytest.raises(PaymentError, match="too many times"):
        await h.access(challenge, activation)
    last = await h.store.get(FAILED.format(_MAX_FAILED_RENEWALS - 1))
    assert renewals(h) == [] and last == {"signature": SEEDED_SIGNATURE}


async def test_marker_store_failure_still_grants(h: Harness, caplog: pytest.LogCaptureFixture) -> None:
    challenge, activation = await due(h)
    put_if_absent = h.store.put_if_absent

    async def flaky(key: str, value: Any) -> bool:
        if key == PAID:
            raise OSError("store down")
        return await put_if_absent(key, value)

    h.store.put_if_absent = flaky  # type: ignore[method-assign]
    receipt = await h.access(challenge, activation)
    assert receipt.period_index == 1 and len(renewals(h)) == 1
    assert "ALERT" in caplog.text


async def test_misaligned_binding_is_refused_before_charging(h: Harness) -> None:
    challenge, activation = await due(h)
    key = f"solana-subscription:authentication:{DELEGATION}"
    # Off by less than a period: the anchor no longer divides the billing periods.
    await h.store.put(key, {**await h.store.get(key), "periodStartTs": NOW - 7})  # type: ignore[dict-item]
    with pytest.raises(PaymentError, match="align"):
        await h.access(challenge, activation)
    assert renewals(h) == []


async def test_reactivated_delegation_renews_with_fresh_keys(h: Harness) -> None:
    # Same delegation address, new lifecycle: period 1 again, never mistaken for the old one.
    challenge, activation = await due(h)
    assert (await h.access(challenge, activation)).period_index == 1
    del h.rpc.accounts[str(DELEGATION)]  # cancelled and revoked on chain
    h.now = DUE + 100
    challenge, activation, _ = await h.activate()
    h.now = DUE + 100 + PERIOD_SECONDS + 10
    receipt = await h.access(challenge, activation)
    assert len(h.rpc.sent) == 4 and receipt.period_index == 1
    assert receipt.reference == str(VersionedTransaction.from_bytes(h.rpc.sent[-1]).signatures[0])
