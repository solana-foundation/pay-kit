"""MemoryChannelStore coverage.

Mirrors the Go ``session_store_test.go`` behaviors one-for-one: insert-on-missing
updates, prior-write visibility, concurrent update serialization, mutator error
handling (state unchanged, no poisoning), list filtering, delete, finalization,
and clone isolation.
"""

from __future__ import annotations

import asyncio

import pytest

from solana_pay_kit.protocols.mpp.server.session_store import (
    ChannelState,
    CommittedDelivery,
    ListChannelsFilter,
    MemoryChannelStore,
    PendingDelivery,
)


def _test_channel_state(channel_id: str, deposit: int) -> ChannelState:
    return ChannelState(
        channel_id=channel_id,
        authorized_signer="11111111111111111111111111111111",
        deposit=deposit,
    )


@pytest.mark.asyncio
async def test_update_channel_inserts_when_missing() -> None:
    """Mirrors TestMemoryChannelStoreUpdateChannelInsertsWhenMissing."""
    store = MemoryChannelStore()

    def mutator(current: ChannelState | None) -> ChannelState:
        assert current is None
        return _test_channel_state("c1", 5)

    result = await store.update_channel("c1", mutator)
    assert result.deposit == 5

    stored = await store.get_channel("c1")
    assert stored is not None
    assert stored.deposit == 5


@pytest.mark.asyncio
async def test_update_channel_sees_prior_writes() -> None:
    """Mirrors TestMemoryChannelStoreUpdateChannelSeesPriorWrites."""
    store = MemoryChannelStore()

    await store.update_channel("c1", lambda _current: _test_channel_state("c1", 1))

    def mutator(current: ChannelState | None) -> ChannelState:
        assert current is not None and current.deposit == 1
        current.deposit = 2
        return current

    nxt = await store.update_channel("c1", mutator)
    assert nxt.deposit == 2


@pytest.mark.asyncio
async def test_serializes_concurrent_updates() -> None:
    """Mirrors TestMemoryChannelStoreSerializesConcurrentUpdates.

    Fires 50 concurrent increments; each must see the previous value, so the
    final cumulative equals the worker count. The per-channel lock makes the
    read-modify-write atomic.
    """
    store = MemoryChannelStore()
    await store.update_channel("c1", lambda _current: _test_channel_state("c1", 1_000_000))

    workers = 50

    def increment(current: ChannelState | None) -> ChannelState:
        assert current is not None
        current.cumulative += 1
        return current

    async def run() -> None:
        await store.update_channel("c1", increment)

    await asyncio.gather(*(run() for _ in range(workers)))

    stored = await store.get_channel("c1")
    assert stored is not None
    assert stored.cumulative == workers


@pytest.mark.asyncio
async def test_mutator_error_leaves_state_unchanged() -> None:
    """Mirrors TestMemoryChannelStoreMutatorErrorLeavesStateUnchanged.

    A raised mutator error must leave the stored state intact and must not
    poison subsequent updates on the same channel.
    """
    store = MemoryChannelStore()

    def seed(_current: ChannelState | None) -> ChannelState:
        state = _test_channel_state("c1", 1_000_000)
        state.cumulative = 7
        return state

    await store.update_channel("c1", seed)

    sentinel = RuntimeError("nope")

    def boom(_current: ChannelState | None) -> ChannelState:
        raise sentinel

    with pytest.raises(RuntimeError) as exc:
        await store.update_channel("c1", boom)
    assert exc.value is sentinel

    stored = await store.get_channel("c1")
    assert stored is not None
    assert stored.cumulative == 7
    assert stored.deposit == 1_000_000

    def increment(current: ChannelState | None) -> ChannelState:
        assert current is not None
        current.cumulative += 1
        return current

    nxt = await store.update_channel("c1", increment)
    assert nxt.cumulative == 8


@pytest.mark.asyncio
async def test_list_channels_applies_filters() -> None:
    """Mirrors TestMemoryChannelStoreListChannelsAppliesFilters."""
    store = MemoryChannelStore()

    async def must_insert(state: ChannelState) -> None:
        await store.update_channel(state.channel_id, lambda _current: state)

    await must_insert(_test_channel_state("a", 1))
    finalized = _test_channel_state("b", 1)
    finalized.finalized = True
    await must_insert(finalized)
    closing = _test_channel_state("c", 1)
    closing.close_requested_at = 123
    await must_insert(closing)

    all_channels = await store.list_channels(None)
    assert len(all_channels) == 3

    only_finalized = await store.list_channels(ListChannelsFilter(finalized=True))
    assert len(only_finalized) == 1
    assert only_finalized[0].channel_id == "b"

    close_pending = await store.list_channels(ListChannelsFilter(finalized=False, close_pending=True))
    assert len(close_pending) == 1
    assert close_pending[0].channel_id == "c"


@pytest.mark.asyncio
async def test_delete_and_mark_finalized() -> None:
    """Mirrors TestMemoryChannelStoreDeleteAndMarkFinalized."""
    store = MemoryChannelStore()
    await store.update_channel("c1", lambda _current: _test_channel_state("c1", 1))

    state = await store.mark_finalized("c1")
    assert state.finalized

    stored = await store.get_channel("c1")
    assert stored is not None and stored.finalized

    await store.delete_channel("c1")
    missing = await store.get_channel("c1")
    assert missing is None

    with pytest.raises(KeyError):
        await store.mark_finalized("ghost")


@pytest.mark.asyncio
async def test_evicts_idle_locks() -> None:
    """Idle per-channel lock entries are evicted rather than retained for the
    store's lifetime.

    Runs sequential and concurrent update_channel cycles across many distinct
    channel ids; once all updates settle with no waiter remaining, the internal
    lock map must be empty.
    """
    store = MemoryChannelStore()

    sequential_ids = 200
    for i in range(sequential_ids):
        cid = f"seq-{i}"
        await store.update_channel(cid, lambda _current, _cid=cid: _test_channel_state(_cid, 1))

    concurrent_ids = 100
    per_id = 8

    def increment(current: ChannelState | None, cid: str) -> ChannelState:
        if current is None:
            return _test_channel_state(cid, 1)
        current.cumulative += 1
        return current

    async def burst(cid: str) -> None:
        await store.update_channel(cid, lambda current, _cid=cid: increment(current, _cid))

    tasks = [burst(f"con-{i}") for i in range(concurrent_ids) for _ in range(per_id)]
    await asyncio.gather(*tasks)

    assert len(store._locks) == 0

    all_channels = await store.list_channels(None)
    assert len(all_channels) == sequential_ids + concurrent_ids


@pytest.mark.asyncio
async def test_eviction_keeps_updates_serialized() -> None:
    """Eviction must never let two updates for one channel run unserialized.

    Races many concurrent increments for a single channel; the per-channel lock
    makes the read-modify-write atomic, so the final cumulative equals the
    number of increments, and the lock map is empty once the burst settles.
    """
    store = MemoryChannelStore()
    await store.update_channel("c1", lambda _current: _test_channel_state("c1", 0))

    workers = 64

    def increment(current: ChannelState | None) -> ChannelState:
        assert current is not None
        current.cumulative += 1
        return current

    async def run() -> None:
        await store.update_channel("c1", increment)

    await asyncio.gather(*(run() for _ in range(workers)))

    stored = await store.get_channel("c1")
    assert stored is not None
    assert stored.cumulative == workers

    assert len(store._locks) == 0


@pytest.mark.asyncio
async def test_cancelled_waiter_does_not_pin_lock_entry() -> None:
    """A task cancelled while queued on a contended channel lock must not leak
    its refcount.

    Task A holds the per-channel lock for channel X. Task B calls
    ``_acquire_channel_lock`` for X: it bumps the refcount under ``_mu`` and then
    blocks awaiting the held lock. B is cancelled while queued. Once A releases,
    no holder or waiter remains, so the lock-entry map must no longer contain X.
    Without cancellation safety the cancelled waiter's ref is never decremented,
    ``refs`` can never return to 0, and the entry is pinned forever.
    """
    store = MemoryChannelStore()

    # Task A takes and holds the lock for X.
    entry_a = await store._acquire_channel_lock("X")

    b_queued = asyncio.Event()

    async def waiter() -> None:
        # Fence: signal just before we enter the (blocking) acquire so the
        # canceller knows B has bumped refs and is about to queue on the lock.
        b_queued.set()
        await store._acquire_channel_lock("X")

    task_b = asyncio.create_task(waiter())
    await b_queued.wait()
    # Let B run until it is parked inside `await entry.lock.acquire()`; the
    # entry now has refs == 2 (A holds, B queued).
    for _ in range(5):
        await asyncio.sleep(0)
    assert store._locks["X"].refs == 2

    # Cancel B while it is queued on the contended lock.
    task_b.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task_b

    # A releases; with no holder or waiter left the entry must be evicted.
    await store._release_channel_lock("X", entry_a)

    assert "X" not in store._locks


@pytest.mark.asyncio
async def test_cancellation_during_release_does_not_orphan_entry() -> None:
    """Cancellation on the release path's ``_mu`` re-acquisition must not orphan
    the lock entry.

    ``_release_channel_lock`` releases the per-channel lock and then re-acquires
    ``_mu`` to decrement the refcount and evict the entry. If a task is cancelled
    while suspended on that ``_mu`` re-acquisition, the decrement/eviction must
    still complete — otherwise the entry is pinned with a stale refcount forever.
    """
    store = MemoryChannelStore()

    entry = await store._acquire_channel_lock("X")
    assert store._locks["X"].refs == 1

    # Hold _mu from a helper so the release task suspends on `async with _mu`
    # inside _release_channel_lock, right after it has released the channel lock.
    mu_held = asyncio.Event()
    let_go = asyncio.Event()

    async def hold_mu() -> None:
        async with store._mu:
            mu_held.set()
            await let_go.wait()

    holder = asyncio.create_task(hold_mu())
    await mu_held.wait()

    release_task = asyncio.create_task(store._release_channel_lock("X", entry))
    # Let the release task run until it is parked on the contended `_mu`.
    for _ in range(5):
        await asyncio.sleep(0)

    # Cancel while it is suspended acquiring `_mu`.
    release_task.cancel()
    # Now let the _mu holder finish so the shielded bookkeeping can proceed.
    let_go.set()
    await holder

    # The release task observes the cancellation, but the bookkeeping must have
    # completed regardless: no holder or waiter remains, so X is evicted.
    with pytest.raises(asyncio.CancelledError):
        await release_task

    for _ in range(5):
        await asyncio.sleep(0)
    assert "X" not in store._locks


@pytest.mark.asyncio
async def test_returns_clones() -> None:
    """Mirrors TestMemoryChannelStoreReturnsClones.

    Mutating a returned state's optional field or delivery list must not leak
    back into the store.
    """
    store = MemoryChannelStore()

    def seed(_current: ChannelState | None) -> ChannelState:
        state = _test_channel_state("c1", 1)
        state.highest_voucher_signature = "sig"
        state.pending_deliveries = [PendingDelivery(delivery_id="c1:1", amount=1, sequence=1, expires_at=9)]
        return state

    await store.update_channel("c1", seed)

    got = await store.get_channel("c1")
    assert got is not None
    got.highest_voucher_signature = "tampered"
    got.pending_deliveries[0].amount = 99

    fresh = await store.get_channel("c1")
    assert fresh is not None
    assert fresh.highest_voucher_signature == "sig"
    assert fresh.pending_deliveries[0].amount == 1


# ── JSON null-handling parity with Go nil slices ──


def test_from_dict_accepts_null_delivery_lists() -> None:
    """A Go-emitted record serializes nil delivery slices to JSON ``null``.

    ``ChannelState.from_dict`` must treat ``null`` for the delivery lists the
    same as a missing key or an empty list: an empty list, never ``None``. The
    bug iterated ``data.get(key, [])`` which returned ``None`` for an explicit
    ``null`` and raised ``TypeError``.
    """
    go_record = {
        "channel_id": "c1",
        "authorized_signer": "signer1",
        "deposit": 1_000_000,
        "cumulative": 0,
        "finalized": False,
        "highest_voucher_signature": None,
        "highest_voucher_expires_at": None,
        "close_requested_at": None,
        "operator": None,
        "next_delivery_sequence": 0,
        "pending_deliveries": None,
        "committed_deliveries": None,
    }

    state = ChannelState.from_dict(go_record)
    assert state.pending_deliveries == []
    assert state.committed_deliveries == []


def test_from_dict_accepts_missing_and_empty_delivery_lists() -> None:
    """Missing keys and explicit ``[]`` both decode to an empty list."""
    missing = ChannelState.from_dict({"channel_id": "c1", "authorized_signer": "signer1"})
    assert missing.pending_deliveries == []
    assert missing.committed_deliveries == []

    empty = ChannelState.from_dict(
        {
            "channel_id": "c1",
            "authorized_signer": "signer1",
            "pending_deliveries": [],
            "committed_deliveries": [],
        }
    )
    assert empty.pending_deliveries == []
    assert empty.committed_deliveries == []


def test_to_dict_emits_null_for_empty_delivery_lists() -> None:
    """A fresh-open channel has no deliveries; Go serializes its nil slices to
    JSON ``null``, so ``to_dict`` must emit ``None`` (not ``[]``) for
    byte-for-byte cross-SDK durable records."""
    state = ChannelState(channel_id="c1", authorized_signer="signer1")

    d = state.to_dict()
    assert d["pending_deliveries"] is None
    assert d["committed_deliveries"] is None


def test_to_dict_emits_lists_when_deliveries_present() -> None:
    """Non-empty delivery lists still serialize as JSON arrays."""
    state = ChannelState(
        channel_id="c1",
        authorized_signer="signer1",
        pending_deliveries=[PendingDelivery(delivery_id="c1:1", amount=1, sequence=1, expires_at=9)],
        committed_deliveries=[CommittedDelivery(delivery_id="c1:1", amount=1, cumulative=1, voucher_signature="sig")],
    )

    d = state.to_dict()
    assert d["pending_deliveries"] == [{"deliveryId": "c1:1", "amount": 1, "sequence": 1, "expiresAt": 9}]
    assert d["committed_deliveries"] == [
        {
            "deliveryId": "c1:1",
            "amount": 1,
            "cumulative": 1,
            "voucherSignature": "sig",
        }
    ]


def test_round_trips_go_style_null_record() -> None:
    """A Go-style record with ``null`` delivery lists round-trips: decode then
    re-encode reproduces ``null`` for the empty lists, matching Go's nil-slice
    serialization."""
    go_record = {
        "channel_id": "c1",
        "authorized_signer": "signer1",
        "deposit": 1_000_000,
        "cumulative": 0,
        "finalized": False,
        "highest_voucher_signature": None,
        "highest_voucher_expires_at": None,
        "close_requested_at": None,
        "operator": None,
        "next_delivery_sequence": 0,
        "pending_deliveries": None,
        "committed_deliveries": None,
    }

    re_encoded = ChannelState.from_dict(go_record).to_dict()
    assert re_encoded["pending_deliveries"] is None
    assert re_encoded["committed_deliveries"] is None
