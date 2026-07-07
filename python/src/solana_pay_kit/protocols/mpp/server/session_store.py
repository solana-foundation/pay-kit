"""Per-channel state store for the MPP session server.

The in-memory implementation serializes :meth:`MemoryChannelStore.update_channel`
calls per channel id with a per-channel lock, so the read-modify-write sequence
inside the mutator is atomic from the perspective of any other caller targeting
the same channel while updates to different channels run concurrently.

The voucher verifier is intentionally side-effect-free: it computes a verdict,
and the caller persists any accepted delta through
:meth:`ChannelStore.update_channel`.

The ``ChannelState`` JSON tags are the shared snake_case wire names so durable
stores interoperate across the language SDKs; the per-delivery records use the
camelCase ``deliveryId``/``expiresAt``/``voucherSignature`` keys.

The module uses plain dataclasses with ``to_dict()``/``from_dict()``,
``asyncio`` locking for concurrent access, and explicit type hints.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

__all__ = [
    "PendingDelivery",
    "CommittedDelivery",
    "ChannelState",
    "ListChannelsFilter",
    "ChannelMutator",
    "ChannelStore",
    "MemoryChannelStore",
]


@dataclass
class PendingDelivery:
    """One delivery the server has reserved against a channel but not yet
    received a signed voucher for.

    The wire keys are camelCase (``deliveryId``/``expiresAt``).
    """

    # DeliveryID is the idempotency key for this delivery.
    delivery_id: str
    # Amount reserved for this delivery in base units.
    amount: int = 0
    # Sequence is the monotonic per-channel delivery sequence.
    sequence: int = 0
    # ExpiresAt is the Unix timestamp after which the delivery should not be
    # committed.
    expires_at: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "deliveryId": self.delivery_id,
            "amount": self.amount,
            "sequence": self.sequence,
            "expiresAt": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PendingDelivery:
        return cls(
            delivery_id=data.get("deliveryId", ""),
            amount=int(data.get("amount", 0)),
            sequence=int(data.get("sequence", 0)),
            expires_at=int(data.get("expiresAt", 0)),
        )


@dataclass
class CommittedDelivery:
    """A delivery that has been committed by a signed voucher. Kept for
    idempotent commit replay.
    """

    # DeliveryID is the idempotency key for this delivery.
    delivery_id: str
    # Amount committed for this delivery in base units.
    amount: int = 0
    # Cumulative is the channel watermark after this commit.
    cumulative: int = 0
    # VoucherSignature is the signature of the committing voucher (base58).
    voucher_signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "deliveryId": self.delivery_id,
            "amount": self.amount,
            "cumulative": self.cumulative,
            "voucherSignature": self.voucher_signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommittedDelivery:
        return cls(
            delivery_id=data.get("deliveryId", ""),
            amount=int(data.get("amount", 0)),
            cumulative=int(data.get("cumulative", 0)),
            voucher_signature=data.get("voucherSignature", ""),
        )


@dataclass
class ChannelState:
    """Persisted state of a single payment channel from the server's point of
    view.

    The JSON tags are the shared snake_case wire names, so durable stores can
    interoperate across the language SDKs.
    """

    # ChannelID is the on-chain channel address (base58).
    #
    # Push sessions: the payment-channel address.
    # Pull sessions: the FixedDelegation PDA address.
    channel_id: str

    # AuthorizedSigner is the public key authorized to sign vouchers for this
    # session (base58).
    authorized_signer: str

    # Deposit is the total deposit / approved amount locked for this session
    # (base units).
    deposit: int = 0

    # Cumulative is the highest cumulative amount accepted by the server (the
    # settled watermark).
    cumulative: int = 0

    # Finalized is true once the channel has been finalized on-chain.
    finalized: bool = False

    # HighestVoucherSignature is the signature of the highest accepted voucher
    # (base58). Stored for idempotent replay detection.
    highest_voucher_signature: str | None = None

    # HighestVoucherExpiresAt is the expiry timestamp from the highest accepted
    # voucher. Needed when the server later settles that voucher on-chain.
    highest_voucher_expires_at: int | None = None

    # CloseRequestedAt is the Unix timestamp (seconds) when cooperative close
    # was requested. Once set, no further vouchers are accepted.
    close_requested_at: int | None = None

    # SettledSignature is the signature (base58) of the broadcast
    # settle-and-distribute transaction. A close-pending channel with no settled
    # signature is re-drivable: a close retry may attempt settlement again.
    #
    # An extension beyond the core channel-state shape, recorded only when this
    # server drives on-chain settlement. Serialized with omit-empty so a channel
    # state without a settlement round-trips cleanly.
    settled_signature: str | None = None

    # Settling is an in-flight guard set atomically (under the per-channel
    # store lock) before the settle broadcast starts, so a concurrent close
    # retry or idle-watchdog fire cannot both pass the finalize check and
    # broadcast duplicate settle transactions. Cleared by the finalize mutator
    # (which sets ``finalized``), or by a failed settle path on its next retry.
    # Not serialized: it is transient server state and round-trips as absent.
    settling: bool = False

    # Operator is the client wallet pubkey (base58) for pull-mode sessions;
    # None for push sessions.
    operator: str | None = None

    # NextDeliverySequence is the next server-side metered delivery sequence.
    next_delivery_sequence: int = 0

    # PendingDeliveries are reserved by the server but not yet committed.
    pending_deliveries: list[PendingDelivery] = field(default_factory=list)

    # CommittedDeliveries are recently committed deliveries, kept for idempotent
    # commit replay.
    committed_deliveries: list[CommittedDelivery] = field(default_factory=list)

    def clone(self) -> ChannelState:
        """Return a deep copy so callers can never alias store-internal state.

        Scalar/optional fields copy by value; the two delivery slices copy
        element-wise with their own dataclass copies so a returned list cannot
        mutate the stored one.
        """
        return replace(
            self,
            pending_deliveries=[replace(d) for d in self.pending_deliveries],
            committed_deliveries=[replace(d) for d in self.committed_deliveries],
        )

    def to_dict(self) -> dict[str, Any]:
        # An empty, never-populated delivery slice serializes to JSON ``null``
        # (a fresh-open channel marshals ``"pending_deliveries":null``), while a
        # populated slice serializes to an array. Python has no nil/empty
        # distinction, so an empty list emits ``None`` to keep durable records
        # byte-for-byte identical across SDKs; a decoder treating absent/null as
        # an empty list round-trips it cleanly.
        d: dict[str, Any] = {
            "channel_id": self.channel_id,
            "authorized_signer": self.authorized_signer,
            "deposit": self.deposit,
            "cumulative": self.cumulative,
            "finalized": self.finalized,
            "highest_voucher_signature": self.highest_voucher_signature,
            "highest_voucher_expires_at": self.highest_voucher_expires_at,
            "close_requested_at": self.close_requested_at,
            "operator": self.operator,
            "next_delivery_sequence": self.next_delivery_sequence,
            "pending_deliveries": ([p.to_dict() for p in self.pending_deliveries] if self.pending_deliveries else None),
            "committed_deliveries": (
                [c.to_dict() for c in self.committed_deliveries] if self.committed_deliveries else None
            ),
        }
        # settled_signature is omitted from the wire form when unset.
        if self.settled_signature is not None:
            d["settled_signature"] = self.settled_signature
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChannelState:
        return cls(
            channel_id=data.get("channel_id", ""),
            authorized_signer=data.get("authorized_signer", ""),
            deposit=int(data.get("deposit", 0)),
            cumulative=int(data.get("cumulative", 0)),
            finalized=bool(data.get("finalized", False)),
            highest_voucher_signature=data.get("highest_voucher_signature"),
            highest_voucher_expires_at=(
                None if data.get("highest_voucher_expires_at") is None else int(data["highest_voucher_expires_at"])
            ),
            close_requested_at=(None if data.get("close_requested_at") is None else int(data["close_requested_at"])),
            settled_signature=data.get("settled_signature"),
            operator=data.get("operator"),
            next_delivery_sequence=int(data.get("next_delivery_sequence", 0)),
            # A missing key, explicit JSON ``null``, and an empty array all
            # decode to an empty list. ``data.get(key) or []`` folds ``None``
            # and ``[]`` together; ``from_dict`` never iterates ``None``.
            pending_deliveries=[PendingDelivery.from_dict(p) for p in (data.get("pending_deliveries") or [])],
            committed_deliveries=[CommittedDelivery.from_dict(c) for c in (data.get("committed_deliveries") or [])],
        )


@dataclass
class ListChannelsFilter:
    """Optional filter for :meth:`ChannelStore.list_channels`."""

    # finalized, when non-None, only includes channels matching this finalized
    # state.
    finalized: bool | None = None

    # close_pending, when non-None, only includes channels whose
    # close_requested_at presence matches.
    close_pending: bool | None = None


# ChannelMutator is handed to update_channel. It receives the current state
# (None if no channel exists) and returns the next state, or raises, in which
# case the stored state is left unchanged.
#
# Implementations MUST guarantee the mutator runs without interleaving with
# other update_channel calls for the same channel id.
ChannelMutator = Callable[["ChannelState | None"], "ChannelState"]


class ChannelStore:
    """Pluggable store for per-channel session state.

    ``update_channel`` is the only way to mutate a channel: the voucher verifier
    always needs an atomic read-modify-write to avoid double-spend under
    concurrent vouchers, so no direct put is exposed.

    Defined as an abstract base so pyright can check structural conformance of
    implementations.
    """

    async def get_channel(self, channel_id: str) -> ChannelState | None:
        """Read a channel. Returns None when it does not exist."""
        raise NotImplementedError

    async def update_channel(self, channel_id: str, mutator: ChannelMutator) -> ChannelState:
        """Atomically read-modify-write a channel's state and return the stored
        result."""
        raise NotImplementedError

    async def delete_channel(self, channel_id: str) -> None:
        """Remove a channel from the store. Deleting a missing channel is a
        no-op."""
        raise NotImplementedError

    async def list_channels(self, filter: ListChannelsFilter | None = None) -> list[ChannelState]:
        """Return a snapshot list. The filter is applied after read; None means
        no filter."""
        raise NotImplementedError

    async def mark_finalized(self, channel_id: str) -> ChannelState:
        """Flip finalized to True. Raises when the channel is not found."""
        raise NotImplementedError


class MemoryChannelStore(ChannelStore):
    """In-memory :class:`ChannelStore` with per-channel locking.

    ``update_channel`` calls for the same channel id run strictly sequentially
    while calls for different ids run concurrently. Values are cloned on the way
    in and out so callers never share memory with the store.
    """

    def __init__(self) -> None:
        # _data maps channel id to stored state.
        self._data: dict[str, ChannelState] = {}
        # _locks holds the per-channel lock serializing update_channel calls
        # for the same channel id.
        self._locks: dict[str, asyncio.Lock] = {}
        # _mu guards _data and _locks.
        self._mu = asyncio.Lock()

    async def _channel_lock(self, channel_id: str) -> asyncio.Lock:
        """Return the lock serializing updates for ``channel_id``."""
        async with self._mu:
            lock = self._locks.get(channel_id)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[channel_id] = lock
            return lock

    async def get_channel(self, channel_id: str) -> ChannelState | None:
        async with self._mu:
            state = self._data.get(channel_id)
            return None if state is None else state.clone()

    async def update_channel(self, channel_id: str, mutator: ChannelMutator) -> ChannelState:
        lock = await self._channel_lock(channel_id)
        async with lock:
            async with self._mu:
                current = self._data.get(channel_id)
                current_snapshot = None if current is None else current.clone()

            # A mutator error leaves the stored state unchanged and does not
            # poison later updates: we only write back on success.
            next_state = mutator(current_snapshot)

            async with self._mu:
                self._data[channel_id] = next_state.clone()
            return next_state

    async def delete_channel(self, channel_id: str) -> None:
        # Take the per-channel lock before mutating _data, in the same
        # lock -> _mu order as update_channel, so a delete cannot race an
        # in-flight mutator that would otherwise write the channel back after
        # the pop. Matching the order means no deadlock.
        #
        # The lock entry is intentionally NOT removed: popping it while another
        # task is still queued on it would let a later operation create a fresh
        # lock for the same id and run unserialized against the queued one. Locks
        # persist for the store's lifetime (as they already do for update_channel).
        lock = await self._channel_lock(channel_id)
        async with lock, self._mu:
            self._data.pop(channel_id, None)

    async def list_channels(self, filter: ListChannelsFilter | None = None) -> list[ChannelState]:
        async with self._mu:
            out: list[ChannelState] = []
            for state in self._data.values():
                if filter is not None:
                    if filter.finalized is not None and state.finalized != filter.finalized:
                        continue
                    if filter.close_pending is not None:
                        close_pending = state.close_requested_at is not None
                        if close_pending != filter.close_pending:
                            continue
                out.append(state.clone())
            return out

    async def mark_finalized(self, channel_id: str) -> ChannelState:
        def mutator(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise KeyError(f"channel {channel_id} not found")
            return replace(current, finalized=True)

        return await self.update_channel(channel_id, mutator)
