"""MemoryChannelStore coverage.

Mirrors the Go ``session_store_test.go`` behaviors one-for-one: insert-on-missing
updates, prior-write visibility, concurrent update serialization, mutator error
handling (state unchanged, no poisoning), list filtering, delete, sealing,
and clone isolation.
"""

from __future__ import annotations

import asyncio

import pytest

from solana_pay_kit.protocols.mpp.server.session_store import (
    CHANNEL_STATE_SCHEMA_VERSION,
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
    sealed = _test_channel_state("b", 1)
    sealed.sealed = True
    await must_insert(sealed)
    closing = _test_channel_state("c", 1)
    closing.close_requested_at = 123
    await must_insert(closing)

    all_channels = await store.list_channels(None)
    assert len(all_channels) == 3

    only_sealed = await store.list_channels(ListChannelsFilter(sealed=True))
    assert len(only_sealed) == 1
    assert only_sealed[0].channel_id == "b"

    close_pending = await store.list_channels(ListChannelsFilter(sealed=False, close_pending=True))
    assert len(close_pending) == 1
    assert close_pending[0].channel_id == "c"


@pytest.mark.asyncio
async def test_delete_and_mark_sealed() -> None:
    """Mirrors TestMemoryChannelStoreDeleteAndMarkSealed."""
    store = MemoryChannelStore()
    await store.update_channel("c1", lambda _current: _test_channel_state("c1", 1))

    state = await store.mark_sealed("c1")
    assert state.sealed

    stored = await store.get_channel("c1")
    assert stored is not None and stored.sealed

    await store.delete_channel("c1")
    missing = await store.get_channel("c1")
    assert missing is None

    with pytest.raises(KeyError):
        await store.mark_sealed("ghost")


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
        "sealed": False,
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


def test_from_dict_rejects_legacy_finalized_record() -> None:
    """Records persisted before the finalize->seal rename are not supported:
    the epoch-addressed migration is pre-1.0 breaking, so a legacy record
    fails loudly instead of silently reloading a closed channel as unsealed."""
    with pytest.raises(ValueError, match="legacy pre-seal channel record"):
        ChannelState.from_dict({"channel_id": "c1", "authorized_signer": "signer1", "finalized": True})


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
        "sealed": False,
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


def test_round_trips_unknown_fields_and_stamps_schema_version() -> None:
    """A record written by a newer schema, then read and re-encoded by this
    writer: the unknown field must survive, not vanish (the 2026-08-01
    proof-binding wipe)."""
    state = ChannelState.from_dict(
        {
            "channel_id": "c1",
            "authorized_signer": "signer1",
            "proof_binding_v9": {"k": 1},
        }
    )
    assert state.extra == {"proof_binding_v9": {"k": 1}}
    encoded = state.to_dict()
    assert encoded["proof_binding_v9"] == {"k": 1}
    assert encoded["schema_version"] == CHANNEL_STATE_SCHEMA_VERSION


def test_from_dict_refuses_newer_schema_version() -> None:
    with pytest.raises(ValueError, match="newer"):
        ChannelState.from_dict(
            {
                "channel_id": "c1",
                "authorized_signer": "signer1",
                "schema_version": CHANNEL_STATE_SCHEMA_VERSION + 1,
            }
        )
