"""Channel and operation stores for the SVM x402 ``batch-settlement`` server.

``batch-settlement`` is stateful: per channel the server tracks the escrow it
has seen confirmed, the charge watermark it accepted, the voucher it can
redeem, and the ceilings reserved by requests still being served. Server-signed
requests additionally get a single-use operation record per ``requestId``. That
is the state the SVM ``batch-settlement`` spec requires a server to hold
(section 6.3, reference storage boundaries).

Every write goes through ``update(channel_id, mutator)``, an atomic
read-modify-write, and every write is checked: the watermarks ``deposit``,
``settled``, ``payoutWatermark``, ``chargedCumulative`` and
``signedMaxClaimable`` never decrease, and the channel's identity never
changes once written. A mutator that breaks either raises
:class:`StoreInvariantError` and leaves the stored record untouched.

Memory stores lock with ``threading.Lock`` around synchronous mutators, so they
stay correct when the Flask and Django shims run one event loop per request
thread. The ``Store``-backed variants persist through the pluggable replay
:class:`~solana_pay_kit._paycore.store.Store` under keys namespaced
``x402-batch:`` so they never collide with MPP keys.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field, replace
from typing import Any, Literal, Protocol, cast

from solana_pay_kit._paycore.store import Store
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchChannelConfig

__all__ = [
    "MAX_PROCESSED_SETUP_SIGNATURES",
    "BatchChannelStore",
    "BatchOperationStore",
    "ChannelMutator",
    "ChannelRecord",
    "ChannelStatus",
    "MemoryBatchChannelStore",
    "MemoryBatchOperationStore",
    "OperationRecord",
    "Reservation",
    "StoreBackedBatchChannelStore",
    "StoreBackedBatchOperationStore",
    "StoreInvariantError",
]

#: Setup signatures remembered per channel, so a retried open/top-up is never counted twice.
MAX_PROCESSED_SETUP_SIGNATURES = 64

ChannelStatus = Literal["open", "closing", "sealed", "distributed"]
ReservationKind = Literal["client", "server", "close"]
OperationStatus = Literal["reserved", "completed", "released"]

_KEY_PREFIX = "x402-batch:"
_MONOTONIC = ("deposit", "settled", "payout_watermark", "charged_cumulative", "signed_max_claimable")
_IMMUTABLE = ("channel_id", "channel_config", "network", "fee_payer", "token_program")


class StoreInvariantError(RuntimeError):
    """A write would lower a money watermark, rewrite a channel's identity, or misuse an operation."""


@dataclass
class Reservation:
    """A ceiling held against the deposit while a verified request is being served."""

    ceiling: int
    kind: ReservationKind
    expires_at: float
    request_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize with camelCase keys."""
        return {"ceiling": self.ceiling, "kind": self.kind, "expiresAt": self.expires_at, "requestId": self.request_id}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Reservation:
        """Inverse of :meth:`to_dict`."""
        return cls(int(data["ceiling"]), data["kind"], float(data["expiresAt"]), data.get("requestId"))


def _no_reservations() -> dict[str, Reservation]:
    return {}


def _no_signatures() -> list[str]:
    return []


@dataclass
class ChannelRecord:
    """Server state for one channel. All amounts are atomic-unit ``int``.

    Identity (``channel_id``, ``channel_config``, ``network``, ``fee_payer``,
    ``token_program``) is fixed at the first write; mint, receiver, withdraw
    delay, open slot and voucher-signing mode are read from ``channel_config``.
    ``deposit``/``settled``/``payout_watermark``/``closure_started_at`` mirror
    the chain. ``charged_cumulative`` is the accepted charge watermark and
    ``signed_max_claimable`` + ``voucher_signature`` the redeemable voucher; both
    move only at commit.
    """

    channel_id: str
    channel_config: BatchChannelConfig
    network: str
    fee_payer: str
    token_program: str
    status: ChannelStatus = "open"
    deposit: int = 0
    settled: int = 0
    payout_watermark: int = 0
    closure_started_at: int = 0
    onchain_synced_at: float | None = None
    charged_cumulative: int = 0
    signed_max_claimable: int = 0
    voucher_signature: str | None = None
    reservations: dict[str, Reservation] = field(default_factory=_no_reservations)
    processed_setup_signatures: list[str] = field(default_factory=_no_signatures)
    last_activity_at: float | None = None
    open_signature: str | None = None
    close_signature: str | None = None

    def live_reservations(self, now: float) -> dict[str, Reservation]:
        """Reservations that have not expired at ``now``."""
        return {rid: r for rid, r in self.reservations.items() if r.expires_at > now}

    def clone(self) -> ChannelRecord:
        """A deep copy, so callers never share memory with the store."""
        return deepcopy(self)

    def to_dict(self) -> dict[str, Any]:
        """Serialize with camelCase keys for a durable store."""
        return {
            "channelId": self.channel_id,
            "channelConfig": dict(self.channel_config),
            "network": self.network,
            "feePayer": self.fee_payer,
            "tokenProgram": self.token_program,
            "status": self.status,
            "deposit": self.deposit,
            "settled": self.settled,
            "payoutWatermark": self.payout_watermark,
            "closureStartedAt": self.closure_started_at,
            "onchainSyncedAt": self.onchain_synced_at,
            "chargedCumulative": self.charged_cumulative,
            "signedMaxClaimable": self.signed_max_claimable,
            "voucherSignature": self.voucher_signature,
            "reservations": {rid: r.to_dict() for rid, r in self.reservations.items()},
            "processedSetupSignatures": list(self.processed_setup_signatures),
            "lastActivityAt": self.last_activity_at,
            "openSignature": self.open_signature,
            "closeSignature": self.close_signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChannelRecord:
        """Inverse of :meth:`to_dict`."""
        reservations = cast("dict[str, dict[str, Any]]", data.get("reservations") or {})
        return cls(
            channel_id=data["channelId"],
            channel_config=cast("BatchChannelConfig", dict(data["channelConfig"])),
            network=data["network"],
            fee_payer=data["feePayer"],
            token_program=data["tokenProgram"],
            status=data["status"],
            deposit=int(data["deposit"]),
            settled=int(data["settled"]),
            payout_watermark=int(data["payoutWatermark"]),
            closure_started_at=int(data["closureStartedAt"]),
            onchain_synced_at=data.get("onchainSyncedAt"),
            charged_cumulative=int(data["chargedCumulative"]),
            signed_max_claimable=int(data["signedMaxClaimable"]),
            voucher_signature=data.get("voucherSignature"),
            reservations={rid: Reservation.from_dict(r) for rid, r in reservations.items()},
            processed_setup_signatures=list(data.get("processedSetupSignatures") or []),
            last_activity_at=data.get("lastActivityAt"),
            open_signature=data.get("openSignature"),
            close_signature=data.get("closeSignature"),
        )


#: Receives the current record (``None`` when absent) and returns the record to store.
ChannelMutator = Callable[[ChannelRecord | None], ChannelRecord]


def _checked(channel_id: str, before: ChannelRecord | None, after: ChannelRecord) -> ChannelRecord:
    """Enforce the write invariants and bound the setup-signature memory."""
    if after.channel_id != channel_id:
        raise StoreInvariantError(f"record for {after.channel_id} written under {channel_id}")
    if before is not None:
        for name in _IMMUTABLE:
            if getattr(after, name) != getattr(before, name):
                raise StoreInvariantError(f"channel {channel_id} {name} is immutable")
        for name in _MONOTONIC:
            if getattr(after, name) < getattr(before, name):
                raise StoreInvariantError(
                    f"channel {channel_id} {name} would drop from {getattr(before, name)} to {getattr(after, name)}"
                )
    after.processed_setup_signatures = after.processed_setup_signatures[-MAX_PROCESSED_SETUP_SIGNATURES:]
    return after


class BatchChannelStore(Protocol):
    """Per-channel server state with an atomic, invariant-checked read-modify-write."""

    async def get(self, channel_id: str) -> ChannelRecord | None:
        """Read a channel, or ``None`` when unknown."""
        ...

    async def update(self, channel_id: str, mutator: ChannelMutator) -> ChannelRecord:
        """Atomically apply ``mutator`` and return the stored record; a raising mutator writes nothing."""
        ...

    async def delete(self, channel_id: str) -> None:
        """Forget a channel (after reclaim); deleting an unknown channel is a no-op."""
        ...

    async def delete_if(self, channel_id: str, predicate: Callable[[ChannelRecord], bool]) -> bool:
        """Atomically forget a channel whose record satisfies ``predicate``; ``True`` when it was deleted."""
        ...

    async def list(self) -> list[ChannelRecord]:
        """Every stored channel, for the redemption worker."""
        ...


class MemoryBatchChannelStore:
    """Process-local :class:`BatchChannelStore`; updates to one channel run strictly one at a time."""

    def __init__(self) -> None:
        self._data: dict[str, ChannelRecord] = {}
        self._lock = threading.Lock()

    async def get(self, channel_id: str) -> ChannelRecord | None:
        with self._lock:
            record = self._data.get(channel_id)
            return None if record is None else record.clone()

    async def update(self, channel_id: str, mutator: ChannelMutator) -> ChannelRecord:
        # One lock for every channel, held only while the synchronous mutator
        # runs; per-channel locks if mutators ever get slow.
        with self._lock:
            before = self._data.get(channel_id)
            after = _checked(channel_id, before, mutator(None if before is None else before.clone()))
            self._data[channel_id] = after.clone()
            return after

    async def delete(self, channel_id: str) -> None:
        with self._lock:
            self._data.pop(channel_id, None)

    async def delete_if(self, channel_id: str, predicate: Callable[[ChannelRecord], bool]) -> bool:
        with self._lock:
            record = self._data.get(channel_id)
            if record is None or not predicate(record.clone()):
                return False
            del self._data[channel_id]
            return True

    async def list(self) -> list[ChannelRecord]:
        with self._lock:
            return [record.clone() for record in self._data.values()]


class StoreBackedBatchChannelStore:
    """:class:`BatchChannelStore` persisted through a replay :class:`Store` (e.g. ``FileReplayStore``)."""

    def __init__(self, store: Store) -> None:
        self._store = store
        # Single-process CAS: the lock serializes this process only; a
        # multi-replica deployment needs a compare-and-set Store (Store has
        # put_if_absent but no conditional put).
        self._lock = asyncio.Lock()

    @staticmethod
    def _key(channel_id: str) -> str:
        return f"{_KEY_PREFIX}channel:{channel_id}"

    # The channel index is a read-modify-write list, so concurrent updates from
    # several processes are last-writer-wins and can drop an id; a Store with a
    # list or compare-and-set primitive is the upgrade path.
    _INDEX = f"{_KEY_PREFIX}channels"

    async def _read(self, channel_id: str) -> ChannelRecord | None:
        raw = await self._store.get(self._key(channel_id))
        return None if raw is None else ChannelRecord.from_dict(cast("dict[str, Any]", raw))

    async def get(self, channel_id: str) -> ChannelRecord | None:
        return await self._read(channel_id)

    async def _index(self) -> list[str]:
        return list(dict.fromkeys(cast("list[str]", await self._store.get(self._INDEX) or [])))

    async def update(self, channel_id: str, mutator: ChannelMutator) -> ChannelRecord:
        async with self._lock:
            before = await self._read(channel_id)
            after = _checked(channel_id, before, mutator(None if before is None else before.clone()))
            # Index first, idempotently: a retry after a failed record write
            # finds the id already listed, never twice.
            index = await self._index()
            if channel_id not in index:
                await self._store.put(self._INDEX, [*index, channel_id])
            await self._store.put(self._key(channel_id), after.to_dict())
            return after

    async def delete(self, channel_id: str) -> None:
        async with self._lock:
            await self._delete(channel_id)

    async def _delete(self, channel_id: str) -> None:
        await self._store.delete(self._key(channel_id))
        await self._store.put(self._INDEX, [cid for cid in await self._index() if cid != channel_id])

    async def delete_if(self, channel_id: str, predicate: Callable[[ChannelRecord], bool]) -> bool:
        async with self._lock:
            record = await self._read(channel_id)
            if record is None or not predicate(record):
                return False
            await self._delete(channel_id)
            return True

    async def list(self) -> list[ChannelRecord]:
        records = [await self._read(channel_id) for channel_id in await self._index()]
        return [record for record in records if record is not None]


@dataclass
class OperationRecord:
    """One server-signed request: reserved at verify, then completed or released; never reusable."""

    channel_id: str
    request_id: str
    ceiling: int
    status: OperationStatus = "reserved"
    actual: int | None = None
    cumulative: int | None = None
    #: The payer proof's expiry: past it the id can never be presented again, so the record may be pruned.
    expires_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize with camelCase keys."""
        return {
            "channelId": self.channel_id,
            "requestId": self.request_id,
            "ceiling": self.ceiling,
            "status": self.status,
            "actual": self.actual,
            "cumulative": self.cumulative,
            "expiresAt": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OperationRecord:
        """Inverse of :meth:`to_dict`."""
        return cls(
            data["channelId"],
            data["requestId"],
            int(data["ceiling"]),
            data["status"],
            data["actual"],
            data["cumulative"],
            float(data.get("expiresAt") or 0.0),
        )


def _completed(record: OperationRecord, ceiling: int, actual: int, cumulative: int) -> OperationRecord:
    if record.status != "reserved" or record.ceiling != ceiling:
        raise StoreInvariantError(f"operation {record.request_id} is {record.status}, not a reservation of {ceiling}")
    if not 0 <= actual <= ceiling:
        raise StoreInvariantError(f"operation {record.request_id} actual {actual} is outside 0..={ceiling}")
    return replace(record, status="completed", actual=actual, cumulative=cumulative)


def _released(record: OperationRecord) -> OperationRecord:
    # The tombstone keeps the request id consumed: a failed request cannot be replayed.
    return record if record.status != "reserved" else replace(record, status="released")


class BatchOperationStore(Protocol):
    """Single-use server-signed request records keyed by ``(channelId, requestId)``."""

    async def get(self, channel_id: str, request_id: str) -> OperationRecord | None:
        """Read an operation, or ``None``."""
        ...

    async def reserve(
        self, channel_id: str, request_id: str, ceiling: int, *, expires_at: float, now: float
    ) -> tuple[bool, OperationRecord]:
        """Create a reservation unless one exists; ``(created, record)``. A changed ceiling raises.

        Records of this channel whose proof expired before ``now`` are pruned:
        verification refuses an expired proof, so their ids cannot come back.
        """
        ...

    async def complete(
        self, channel_id: str, request_id: str, *, ceiling: int, actual: int, cumulative: int
    ) -> OperationRecord:
        """Mark a reservation completed with ``0 <= actual <= ceiling``."""
        ...

    async def release(self, channel_id: str, request_id: str) -> None:
        """End failed work, keeping the request id consumed."""
        ...

    async def drop_channel(self, channel_id: str) -> None:
        """Forget every operation of a channel (after its rent is reclaimed)."""
        ...


def _existing(record: OperationRecord, ceiling: int) -> tuple[bool, OperationRecord]:
    if record.ceiling != ceiling:
        raise StoreInvariantError(f"operation {record.request_id} ceiling changed from {record.ceiling} to {ceiling}")
    return False, record


class MemoryBatchOperationStore:
    """Process-local :class:`BatchOperationStore`."""

    def __init__(self) -> None:
        self._data: dict[tuple[str, str], OperationRecord] = {}
        self._lock = threading.Lock()

    async def get(self, channel_id: str, request_id: str) -> OperationRecord | None:
        with self._lock:
            record = self._data.get((channel_id, request_id))
            return None if record is None else deepcopy(record)

    async def reserve(
        self, channel_id: str, request_id: str, ceiling: int, *, expires_at: float, now: float
    ) -> tuple[bool, OperationRecord]:
        with self._lock:
            existing = self._data.get((channel_id, request_id))
            if existing is not None:
                return _existing(deepcopy(existing), ceiling)
            for key in [k for k, r in self._data.items() if k[0] == channel_id and r.expires_at < now]:
                del self._data[key]
            record = OperationRecord(channel_id, request_id, ceiling, expires_at=expires_at)
            self._data[(channel_id, request_id)] = record
            return True, deepcopy(record)

    async def complete(
        self, channel_id: str, request_id: str, *, ceiling: int, actual: int, cumulative: int
    ) -> OperationRecord:
        with self._lock:
            record = self._data.get((channel_id, request_id))
            if record is None:
                raise StoreInvariantError(f"operation {request_id} was never reserved")
            self._data[(channel_id, request_id)] = _completed(record, ceiling, actual, cumulative)
            return deepcopy(self._data[(channel_id, request_id)])

    async def release(self, channel_id: str, request_id: str) -> None:
        with self._lock:
            record = self._data.get((channel_id, request_id))
            if record is not None:
                self._data[(channel_id, request_id)] = _released(record)

    async def drop_channel(self, channel_id: str) -> None:
        with self._lock:
            for key in [k for k in self._data if k[0] == channel_id]:
                del self._data[key]


class StoreBackedBatchOperationStore:
    """:class:`BatchOperationStore` over a replay :class:`Store`.

    ``reserve`` is ``put_if_absent``, so one-operation-per-request holds across
    processes whenever the underlying store's ``put_if_absent`` is atomic.
    """

    def __init__(self, store: Store) -> None:
        self._store = store
        # complete/release are get-then-put under a process-local lock; a
        # multi-replica deployment needs a compare-and-set Store.
        self._lock = asyncio.Lock()

    @staticmethod
    def _key(channel_id: str, request_id: str) -> str:
        # Channel ids are base58 and never contain ":", so a client-chosen
        # requestId cannot make one (channel, request) key alias another.
        return f"{_KEY_PREFIX}op:{channel_id}:{request_id}"

    async def get(self, channel_id: str, request_id: str) -> OperationRecord | None:
        raw = await self._store.get(self._key(channel_id, request_id))
        return None if raw is None else OperationRecord.from_dict(cast("dict[str, Any]", raw))

    @staticmethod
    def _index_key(channel_id: str) -> str:
        return f"{_KEY_PREFIX}ops:{channel_id}"

    async def reserve(
        self, channel_id: str, request_id: str, ceiling: int, *, expires_at: float, now: float
    ) -> tuple[bool, OperationRecord]:
        record = OperationRecord(channel_id, request_id, ceiling, expires_at=expires_at)
        if not await self._store.put_if_absent(self._key(channel_id, request_id), record.to_dict()):
            existing = await self.get(channel_id, request_id)
            if existing is None:
                raise StoreInvariantError(f"operation {request_id} vanished during reserve")
            return _existing(existing, ceiling)
        # The per-channel index is read-modify-write under a process-local
        # lock; a compare-and-set Store is the multi-replica fix.
        async with self._lock:
            index = cast("dict[str, float]", await self._store.get(self._index_key(channel_id)) or {})
            for expired in [rid for rid, at in index.items() if at < now and rid != request_id]:
                await self._store.delete(self._key(channel_id, expired))
                del index[expired]
            index[request_id] = expires_at
            await self._store.put(self._index_key(channel_id), index)
        return True, record

    async def complete(
        self, channel_id: str, request_id: str, *, ceiling: int, actual: int, cumulative: int
    ) -> OperationRecord:
        async with self._lock:
            record = await self.get(channel_id, request_id)
            if record is None:
                raise StoreInvariantError(f"operation {request_id} was never reserved")
            done = _completed(record, ceiling, actual, cumulative)
            await self._store.put(self._key(channel_id, request_id), done.to_dict())
            return done

    async def drop_channel(self, channel_id: str) -> None:
        async with self._lock:
            index = cast("dict[str, float]", await self._store.get(self._index_key(channel_id)) or {})
            for request_id in index:
                await self._store.delete(self._key(channel_id, request_id))
            await self._store.delete(self._index_key(channel_id))

    async def release(self, channel_id: str, request_id: str) -> None:
        async with self._lock:
            record = await self.get(channel_id, request_id)
            if record is not None and record.status == "reserved":
                await self._store.put(self._key(channel_id, request_id), _released(record).to_dict())
