"""Channel and operation stores for x402 ``batch-settlement``.

Every contract runs against the memory store and the ``Store``-backed one
(over the durable ``FileReplayStore``). Operation tests mirror the x402 PR #23
``batch.operation-store.test.ts``.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from solana_pay_kit._paycore.store import FileReplayStore, MemoryStore
from solana_pay_kit.protocols.x402.batch_settlement.store import (
    MAX_PROCESSED_SETUP_SIGNATURES,
    BatchChannelStore,
    BatchOperationStore,
    ChannelRecord,
    MemoryBatchChannelStore,
    MemoryBatchOperationStore,
    Reservation,
    StoreBackedBatchChannelStore,
    StoreBackedBatchOperationStore,
    StoreInvariantError,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchChannelConfig

CONFIG = cast(
    "BatchChannelConfig",
    {
        "payer": "Payer",
        "payerAuthorizer": "Payer",
        "receiver": "PayTo",
        "token": "Mint",
        "withdrawDelay": 900,
        "salt": "0",
        "openSlot": 1,
    },
)

NOW = 1_700_000_000.0
LATER = NOW + 300


def _record(channel_id: str = "chan", **overrides: Any) -> ChannelRecord:
    base = ChannelRecord(channel_id, CONFIG, "solana:devnet", "FeePayer", "Tokenkeg", deposit=100_000)
    return replace(base, **overrides)


@pytest.fixture(params=["memory", "store"])
def channels(request: pytest.FixtureRequest, tmp_path: Path) -> BatchChannelStore:
    if request.param == "memory":
        return MemoryBatchChannelStore()
    return StoreBackedBatchChannelStore(FileReplayStore(tmp_path / "batch.json"))


@pytest.fixture(params=["memory", "store"])
def operations(request: pytest.FixtureRequest, tmp_path: Path) -> BatchOperationStore:
    if request.param == "memory":
        return MemoryBatchOperationStore()
    return StoreBackedBatchOperationStore(FileReplayStore(tmp_path / "ops.json"))


def _set(**fields: Any) -> Callable[[ChannelRecord | None], ChannelRecord]:
    def mutate(current: ChannelRecord | None) -> ChannelRecord:
        return replace(current or _record(), **fields)

    return mutate


# -- operations ----------------------------------------------------------------------


async def test_atomically_reserves_one_operation_per_request_id(operations: BatchOperationStore) -> None:
    first, second = await asyncio.gather(
        operations.reserve("chan", "request", 1_000, expires_at=LATER, now=NOW),
        operations.reserve("chan", "request", 1_000, expires_at=LATER, now=NOW),
    )
    assert sorted([first[0], second[0]]) == [False, True]
    with pytest.raises(StoreInvariantError, match="ceiling changed"):
        await operations.reserve("chan", "request", 999, expires_at=LATER, now=NOW)
    # Another channel's identical request id is a different operation.
    assert (await operations.reserve("other", "request", 1_000, expires_at=LATER, now=NOW))[0] is True


async def test_permanently_rejects_failed_and_completed_request_ids(operations: BatchOperationStore) -> None:
    await operations.reserve("chan", "failed", 1_000, expires_at=LATER, now=NOW)
    await operations.release("chan", "failed")
    created, tombstone = await operations.reserve("chan", "failed", 1_000, expires_at=LATER, now=NOW)
    assert (created, tombstone.status) == (False, "released")

    await operations.reserve("chan", "done", 1_000, expires_at=LATER, now=NOW)
    await operations.complete("chan", "done", ceiling=1_000, actual=500, cumulative=500)
    created, replay = await operations.reserve("chan", "done", 1_000, expires_at=LATER, now=NOW)
    assert (created, replay.status, replay.actual) == (False, "completed", 500)
    await operations.release("chan", "done")
    completed = await operations.get("chan", "done")
    assert completed is not None and completed.status == "completed"


async def test_completion_needs_a_live_reservation_and_an_actual_within_its_ceiling(
    operations: BatchOperationStore,
) -> None:
    with pytest.raises(StoreInvariantError):
        await operations.complete("chan", "never", ceiling=1_000, actual=1, cumulative=1)
    await operations.reserve("chan", "r", 1_000, expires_at=LATER, now=NOW)
    for kwargs in (
        {"ceiling": 999, "actual": 1},
        {"ceiling": 1_000, "actual": 1_001},
        {"ceiling": 1_000, "actual": -1},
    ):
        with pytest.raises(StoreInvariantError):
            await operations.complete("chan", "r", cumulative=1, **kwargs)
    await operations.complete("chan", "r", ceiling=1_000, actual=1_000, cumulative=1_000)
    with pytest.raises(StoreInvariantError):  # completing twice
        await operations.complete("chan", "r", ceiling=1_000, actual=0, cumulative=1_000)
    await operations.reserve("chan", "released", 1_000, expires_at=LATER, now=NOW)
    await operations.release("chan", "released")
    with pytest.raises(StoreInvariantError):  # a tombstone cannot be completed
        await operations.complete("chan", "released", ceiling=1_000, actual=0, cumulative=0)


# -- channels ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field", ["deposit", "settled", "payout_watermark", "charged_cumulative", "signed_max_claimable"]
)
async def test_a_mutator_that_lowers_a_watermark_raises_and_writes_nothing(
    channels: BatchChannelStore, field: str
) -> None:
    await channels.update("chan", _set(settled=10, payout_watermark=10, charged_cumulative=10, signed_max_claimable=10))
    before = await channels.get("chan")
    assert before is not None
    with pytest.raises(StoreInvariantError, match=field):
        await channels.update("chan", _set(**{field: getattr(before, field) - 1}))
    assert await channels.get("chan") == before
    # Raising is fine; so is standing still.
    await channels.update("chan", _set(**{field: getattr(before, field) + 1}))


@pytest.mark.parametrize(
    "fields",
    [
        {"channel_config": {**CONFIG, "salt": "1"}},
        {"network": "solana:mainnet"},
        {"fee_payer": "Other"},
        {"token_program": "Token22"},
        {"channel_id": "elsewhere"},
    ],
    ids=["config", "network", "fee-payer", "token-program", "channel-id"],
)
async def test_channel_identity_is_immutable_once_written(channels: BatchChannelStore, fields: dict[str, Any]) -> None:
    await channels.update("chan", _set())
    with pytest.raises(StoreInvariantError):
        await channels.update("chan", _set(**fields))


async def test_the_first_write_must_carry_the_channel_id_it_is_stored_under(channels: BatchChannelStore) -> None:
    with pytest.raises(StoreInvariantError):
        await channels.update("chan", lambda _: _record("elsewhere"))
    assert await channels.get("chan") is None


async def test_concurrent_updates_to_one_channel_are_serialized(channels: BatchChannelStore) -> None:
    def charge(current: ChannelRecord | None) -> ChannelRecord:
        record = current or _record()
        return replace(record, charged_cumulative=record.charged_cumulative + 1)

    await asyncio.gather(*(channels.update("chan", charge) for _ in range(25)))
    stored = await channels.get("chan")
    assert stored is not None and stored.charged_cumulative == 25


def _in_threads(work: Callable[[], None], count: int = 4) -> None:
    threads = [threading.Thread(target=work) for _ in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def test_updates_from_separate_event_loops_are_serialized(channels: BatchChannelStore) -> None:
    # The Flask and Django shims run one event loop per request thread, so an
    # asyncio lock would not serialize them: it binds to the first loop that
    # contends it and refuses the second. The mutator yields the GIL to widen
    # the read-modify-write window a missing lock would lose updates in.
    def charge(current: ChannelRecord | None) -> ChannelRecord:
        record = current or _record()
        time.sleep(0.0005)
        return replace(record, charged_cumulative=record.charged_cumulative + 1)

    def worker() -> None:
        for _ in range(25):
            asyncio.run(channels.update("chan", charge))

    _in_threads(worker)
    stored = asyncio.run(channels.get("chan"))
    assert stored is not None and stored.charged_cumulative == 100


def test_one_reservation_per_request_id_across_event_loops(operations: BatchOperationStore) -> None:
    # Same shims, same race, on the single-use record a server-signed request
    # depends on: exactly one thread may be told it created the reservation.
    created: list[str] = []
    tally = threading.Lock()

    def worker() -> None:
        for index in range(10):
            fresh, _ = asyncio.run(operations.reserve("chan", f"req-{index}", 10_000, expires_at=LATER, now=NOW))
            if fresh:
                with tally:
                    created.append(f"req-{index}")

    _in_threads(worker)
    assert sorted(created) == sorted(f"req-{index}" for index in range(10))


async def test_records_are_copies_and_round_trip_through_a_durable_store(tmp_path: Path) -> None:
    record = _record(
        reservations={"r1": Reservation(10_000, "server", 1_700_000_300.5, "req-1")},
        voucher_signature="sig",
        onchain_synced_at=1_700_000_000.25,
        processed_setup_signatures=["s1"],
        status="closing",
    )
    path = tmp_path / "batch.json"
    await StoreBackedBatchChannelStore(FileReplayStore(path)).update("chan", lambda _: record)
    # A fresh process reading the same file sees the same record.
    reread = await StoreBackedBatchChannelStore(FileReplayStore(path)).get("chan")
    assert reread == record

    # Neither the record written nor a record read shares memory with the store.
    expected = record.clone()
    memory = MemoryBatchChannelStore()
    written = await memory.update("chan", lambda _: record)
    written.reservations.clear()
    got = await memory.get("chan")
    assert got == expected
    assert got is not None
    got.reservations.clear()
    assert (await memory.get("chan")) == expected


async def test_list_and_delete(channels: BatchChannelStore) -> None:
    await channels.update("a", lambda _: _record("a"))
    await channels.update("b", lambda _: _record("b"))
    await channels.update("a", _set(settled=1))
    assert sorted(r.channel_id for r in await channels.list()) == ["a", "b"]
    await channels.delete("a")
    await channels.delete("missing")
    assert [r.channel_id for r in await channels.list()] == ["b"]
    assert await channels.get("a") is None


async def test_setup_signature_memory_is_bounded(channels: BatchChannelStore) -> None:
    signatures = [f"sig-{i}" for i in range(MAX_PROCESSED_SETUP_SIGNATURES + 5)]
    stored = await channels.update("chan", _set(processed_setup_signatures=signatures))
    assert stored.processed_setup_signatures == signatures[-MAX_PROCESSED_SETUP_SIGNATURES:]


def test_live_reservations_drop_expired_ones() -> None:
    record = _record(
        reservations={"old": Reservation(1, "client", 100.0), "live": Reservation(2, "server", 200.0, "r")}
    )
    assert list(record.live_reservations(150.0)) == ["live"]
    assert record.live_reservations(200.0) == {}


async def test_operation_keys_are_namespaced_away_from_other_protocols() -> None:
    backing = MemoryStore()
    await StoreBackedBatchOperationStore(backing).reserve("chan", "req", 1, expires_at=LATER, now=NOW)
    await StoreBackedBatchChannelStore(backing).update("chan", lambda _: _record())
    assert all(key.startswith("x402-batch:") for key in backing._data)  # noqa: SLF001


async def test_expired_operations_are_pruned_and_a_reclaimed_channel_forgets_its_own(
    operations: BatchOperationStore,
) -> None:
    await operations.reserve("chan", "old", 1_000, expires_at=NOW - 1, now=NOW - 10)
    await operations.reserve("chan", "live", 1_000, expires_at=LATER, now=NOW)
    await operations.reserve("other", "kept", 1_000, expires_at=NOW - 1, now=NOW - 10)
    # The expired proof can never be presented again: its record went with the next reserve.
    assert await operations.get("chan", "old") is None
    assert await operations.get("chan", "live") is not None
    assert await operations.get("other", "kept") is not None  # another channel is not touched
    await operations.drop_channel("chan")
    assert await operations.get("chan", "live") is None
    assert await operations.get("other", "kept") is not None


async def test_the_channel_index_never_lists_a_channel_twice() -> None:
    backing = MemoryStore()
    channels = StoreBackedBatchChannelStore(backing)
    original = backing.put
    fail_record = [True]

    async def flaky_put(key: str, value: Any) -> None:
        if key.endswith("channel:a") and fail_record[0]:
            fail_record[0] = False
            raise RuntimeError("disk full")
        await original(key, value)

    backing.put = flaky_put  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await channels.update("a", lambda _: _record("a"))
    await channels.update("a", lambda _: _record("a"))  # the retry
    assert [r.channel_id for r in await channels.list()] == ["a"]
    await backing.put("x402-batch:channels", ["a", "a"])  # an index written twice by an older version
    assert [r.channel_id for r in await channels.list()] == ["a"]


async def test_delete_if_forgets_only_a_matching_record(channels: BatchChannelStore) -> None:
    await channels.update("chan", lambda _: _record())
    assert await channels.delete_if("chan", lambda record: record.deposit == 0) is False
    assert await channels.delete_if("missing", lambda record: True) is False
    assert await channels.delete_if("chan", lambda record: record.deposit == 100_000) is True
    assert await channels.get("chan") is None and await channels.list() == []
