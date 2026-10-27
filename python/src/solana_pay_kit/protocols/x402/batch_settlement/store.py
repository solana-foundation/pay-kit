"""Channel records for the ``batch-settlement`` resource server.

The store holds the only record of what a client has been charged
(``chargedCumulativeAmount``), so production servers must back it durably. A
record also carries the deployment binding it was written under, the confirmed
grace period, the newest onchain observation, and the durable authorization
stages that give one voucher exactly one outcome across crashes:

* a *reservation* (taken before the handler runs, with a lease);
* *handler succeeded* (the crash boundary: past it a retry only finishes);
* *committed* (watermark advanced, response stored).

Mirrors the batch half of the Rust kit's ``core::store::ChannelState``.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "MAX_COMMITTED_AUTHORIZATIONS",
    "AuthorizationRequest",
    "BatchChannelRecord",
    "BatchChannelStore",
    "BatchStoreError",
    "ChannelBinding",
    "CommittedAuthorization",
    "MemoryBatchChannelStore",
    "PendingAuthorization",
    "PendingSetup",
    "Reservation",
    "ReservationToken",
]

#: Most committed authorizations retained per channel. Dropping one only costs
#: its cached response: the watermark rule still refuses the stale voucher.
MAX_COMMITTED_AUTHORIZATIONS = 64


class BatchStoreError(Exception):
    """A store transition the record refuses."""


@dataclass(frozen=True)
class ChannelBinding:
    """The deployment a record was written under."""

    scheme: str
    pay_to: str | None = None
    network: str | None = None
    program_id: str | None = None

    def is_complete(self) -> bool:
        return self.pay_to is not None and self.network is not None and self.program_id is not None

    def mismatch(self, current: ChannelBinding) -> str | None:
        def differs(ours: str | None, theirs: str | None) -> bool:
            return ours is not None and theirs is not None and ours != theirs

        if self.scheme != current.scheme:
            return "scheme"
        if differs(self.pay_to, current.pay_to):
            return "payTo"
        if differs(self.network, current.network):
            return "network"
        if differs(self.program_id, current.program_id):
            return "programId"
        return None

    def filled_from(self, current: ChannelBinding) -> ChannelBinding:
        return ChannelBinding(
            scheme=self.scheme,
            pay_to=self.pay_to if self.pay_to is not None else current.pay_to,
            network=self.network if self.network is not None else current.network,
            program_id=self.program_id if self.program_id is not None else current.program_id,
        )


@dataclass
class PendingSetup:
    """A setup (open / top-up) transaction recorded before it is broadcast."""

    payer_signature: str
    deposit: int
    opens_channel: bool
    expires_at: int


@dataclass
class PendingAuthorization:
    """A reserved authorization whose handler has not finished committing."""

    authorization_id: str
    request_fingerprint: str
    amount: int
    cumulative: int
    sequence: int
    expires_at: int
    handler_succeeded: bool = False


@dataclass
class CommittedAuthorization:
    """A committed authorization and the response that answered it."""

    authorization_id: str
    request_fingerprint: str
    amount: int
    cumulative: int
    voucher_signature: str
    settlement_response: dict[str, Any] | None = None


@dataclass(frozen=True)
class ReservationToken:
    """Proof that a transition reserved one authorization stepping to ``cumulative``."""

    authorization_id: str
    request_fingerprint: str
    cumulative: int
    sequence: int


class Reservation(Enum):
    """Outcome of :meth:`BatchChannelRecord.reserve_authorization`."""

    RESERVED = "reserved"
    IN_PROGRESS = "in_progress"
    HANDLER_SUCCEEDED = "handler_succeeded"
    COMMITTED = "committed"
    CONFLICT = "conflict"
    ABANDONED = "abandoned"
    STALE = "stale"
    CLOSING = "closing"


@dataclass(frozen=True)
class AuthorizationRequest:
    """One request asking to step the watermark by ``amount`` to ``cumulative``."""

    authorization_id: str
    request_fingerprint: str
    amount: int
    cumulative: int
    lease_seconds: int
    now: int


def _empty_strs() -> list[str]:
    return []


def _empty_pending() -> list[PendingAuthorization]:
    return []


def _empty_committed() -> list[CommittedAuthorization]:
    return []


@dataclass
class BatchChannelRecord:
    """The server's record of one payment channel."""

    channel_id: str
    payer_authorizer: str
    payer: str = ""
    rent_payer: str = ""
    deposit: int = 0
    cumulative: int = 0
    sealed: bool = False
    close_requested_at: int | None = None
    final_cumulative: int | None = None
    highest_voucher_signature: str | None = None
    highest_voucher_expires_at: int | None = None
    open_slot: int | None = None
    settled_on_chain: int = 0
    distributed_on_chain: int = 0
    last_activity_at: int = 0
    processed_topup_signatures: list[str] = field(default_factory=_empty_strs)
    pending_setup: PendingSetup | None = None
    pending: list[PendingAuthorization] = field(default_factory=_empty_pending)
    committed: list[CommittedAuthorization] = field(default_factory=_empty_committed)
    next_sequence: int = 0
    binding: ChannelBinding | None = None
    grace_period: int | None = None
    observed_slot: int = 0
    observed_at: int = 0
    #: The receiver authorizer the channel's ``open`` bound (spec section 3).
    receiver_binding: str | None = None
    #: The result of a completed cooperative close, replayed to a retried refund.
    cooperative_close: dict[str, Any] | None = None
    #: When this server first saw the channel sealed (unix seconds).
    sealed_at: int | None = None

    # ── binding ──

    def check_binding(self, current: ChannelBinding) -> None:
        """Refuse a record bound to another deployment (an unbound record passes)."""
        if self.binding is None:
            return
        field_name = self.binding.mismatch(current)
        if field_name is not None:
            raise BatchStoreError(f"channel {self.channel_id} belongs to another deployment ({field_name} differs)")

    def check_binding_complete(self, current: ChannelBinding) -> None:
        """Require the record to be bound to exactly ``current``, every field recorded."""
        self.check_binding(current)
        if self.binding != current or not current.is_complete():
            raise BatchStoreError(f"channel {self.channel_id} has no complete deployment binding")

    def adopt_binding(self, current: ChannelBinding) -> None:
        self.binding = current if self.binding is None else self.binding.filled_from(current)

    def check_grace_period(self, withdraw_delay: int) -> None:
        if self.grace_period is None:
            raise BatchStoreError(f"channel {self.channel_id} has no recorded grace period")
        if self.grace_period != withdraw_delay:
            raise BatchStoreError(
                f"channel {self.channel_id} has a {self.grace_period}s grace period, not the {withdraw_delay}s "
                "this server requires"
            )

    # ── lifecycle ──

    def is_empty_tombstone(self) -> bool:
        """A record left by a released opening deposit: it authorizes nothing."""
        return (
            self.deposit == 0
            and self.cumulative == 0
            and self.pending_setup is None
            and not self.pending
            and not self.committed
        )

    def has_in_flight_authorization(self) -> bool:
        return bool(self.pending) or self.pending_setup is not None

    def has_blocking_authorization(self, now: int) -> bool:
        """Whether a reservation (of any stage, served or not) or a setup is
        still inside its lease at ``now``, which holds the close finalizer's
        seal. A dead lease never blocks: nobody else can release it, and the
        seal's fence refuses its late commit."""
        if self.pending_setup is not None and self.pending_setup.expires_at > now:
            return True
        return any(p.expires_at > now for p in self.pending)

    def record_observation(self, lifecycle: str, started_at: int | None, slot: int | None, now: int) -> bool:
        """Apply an onchain observation; ``False`` when the read is behind the
        recorded slot (its close fences still apply, the snapshot is not renewed).

        ``lifecycle`` is ``"open"``, ``"closing"`` or ``"terminal"``.
        """
        if lifecycle == "closing" and started_at is not None:
            self.close_requested_at = self.close_requested_at or started_at
        elif lifecycle == "terminal":
            self.sealed = True
            if started_at is not None:
                self.close_requested_at = self.close_requested_at or started_at
        if slot is not None:
            if slot < self.observed_slot:
                return False
            self.observed_slot = slot
        self.observed_at = now
        return True

    # ── authorizations ──

    def committed_authorization(self, authorization_id: str) -> CommittedAuthorization | None:
        return next((entry for entry in self.committed if entry.authorization_id == authorization_id), None)

    def _pending_index(self, authorization_id: str) -> int | None:
        return next((i for i, entry in enumerate(self.pending) if entry.authorization_id == authorization_id), None)

    def _classify(self, request: AuthorizationRequest) -> Reservation | None:
        committed = self.committed_authorization(request.authorization_id)
        if committed is not None:
            if committed.request_fingerprint != request.request_fingerprint:
                return Reservation.CONFLICT
            return Reservation.COMMITTED
        index = self._pending_index(request.authorization_id)
        if index is None:
            return None
        pending = self.pending[index]
        if pending.request_fingerprint != request.request_fingerprint:
            return Reservation.CONFLICT
        if pending.handler_succeeded:
            return Reservation.HANDLER_SUCCEEDED
        if pending.expires_at <= request.now:
            return Reservation.ABANDONED
        return Reservation.IN_PROGRESS

    def refuse_reservation(self, request: AuthorizationRequest) -> Reservation | None:
        """The outcome when ``request`` cannot take a new reservation; ``None`` when it can."""
        if self.sealed or self.close_requested_at is not None:
            return Reservation.CLOSING
        classified = self._classify(request)
        if classified is not None:
            return classified
        others = [p for p in self.pending if p.authorization_id != request.authorization_id]
        if any(not p.handler_succeeded and p.expires_at <= request.now for p in others):
            return Reservation.ABANDONED
        if any(p.handler_succeeded or p.expires_at > request.now for p in others):
            return Reservation.IN_PROGRESS
        if self.cumulative + request.amount != request.cumulative:
            return Reservation.STALE
        return None

    def take_reservation(self, request: AuthorizationRequest) -> ReservationToken:
        self.next_sequence += 1
        self.pending.append(
            PendingAuthorization(
                authorization_id=request.authorization_id,
                request_fingerprint=request.request_fingerprint,
                amount=request.amount,
                cumulative=request.cumulative,
                sequence=self.next_sequence,
                expires_at=request.now + request.lease_seconds,
            )
        )
        return ReservationToken(
            authorization_id=request.authorization_id,
            request_fingerprint=request.request_fingerprint,
            cumulative=request.cumulative,
            sequence=self.next_sequence,
        )

    def token_for_pending(self, request: AuthorizationRequest) -> ReservationToken | None:
        index = self._pending_index(request.authorization_id)
        if index is None:
            return None
        pending = self.pending[index]
        return ReservationToken(
            pending.authorization_id, pending.request_fingerprint, pending.cumulative, pending.sequence
        )

    def _token_index(self, token: ReservationToken) -> int:
        index = self._pending_index(token.authorization_id)
        if index is None or self.pending[index].sequence != token.sequence:
            raise BatchStoreError(f"authorization {token.authorization_id} is not reserved by this request")
        return index

    def mark_handler_succeeded(self, token: ReservationToken) -> None:
        if self.committed_authorization(token.authorization_id) is not None:
            return
        self.pending[self._token_index(token)].handler_succeeded = True

    def release_authorization(self, authorization_id: str, request_fingerprint: str) -> None:
        index = self._pending_index(authorization_id)
        if index is None:
            return
        pending = self.pending[index]
        if pending.request_fingerprint != request_fingerprint:
            raise BatchStoreError(f"authorization {authorization_id} is held by a different request")
        if pending.handler_succeeded:
            raise BatchStoreError(f"authorization {authorization_id} already served its handler")
        del self.pending[index]

    def commit_authorization(
        self,
        token: ReservationToken,
        voucher_signature: str,
        voucher_expires_at: int,
        response: Callable[[BatchChannelRecord], dict[str, Any]],
    ) -> bool:
        """Advance the watermark and store the response in one transition.

        Idempotent: ``False`` when the authorization was already committed.
        """
        committed = self.committed_authorization(token.authorization_id)
        if committed is not None:
            if committed.request_fingerprint != token.request_fingerprint or committed.cumulative != token.cumulative:
                raise BatchStoreError(f"authorization {token.authorization_id} was committed by a different request")
            return False
        index = self._token_index(token)
        if self.sealed:
            raise BatchStoreError(f"authorization {token.authorization_id} cannot be charged: the channel is sealed")
        if self.final_cumulative is not None:
            raise BatchStoreError(
                f"authorization {token.authorization_id} cannot be charged: the channel's final watermark is "
                f"fixed at {self.final_cumulative} for sealing"
            )
        reserved = self.pending[index].amount
        if self.cumulative + reserved != token.cumulative:
            raise BatchStoreError(
                f"authorization {token.authorization_id} reserved {reserved} above the watermark, which is now "
                f"{self.cumulative} and does not step to {token.cumulative}"
            )
        charged = token.cumulative - self.cumulative
        del self.pending[index]
        self.cumulative = token.cumulative
        self.highest_voucher_signature = voucher_signature
        self.highest_voucher_expires_at = voucher_expires_at
        entry = CommittedAuthorization(
            authorization_id=token.authorization_id,
            request_fingerprint=token.request_fingerprint,
            amount=charged,
            cumulative=token.cumulative,
            voucher_signature=voucher_signature,
        )
        self.committed.append(entry)
        del self.committed[:-MAX_COMMITTED_AUTHORIZATIONS]
        entry.settlement_response = response(self)
        return True


#: Store mutators receive a copy of the current record (or ``None``) and
#: return the record to write, or ``None`` to delete it.
ChannelMutator = Callable[[BatchChannelRecord | None], BatchChannelRecord | None]


@runtime_checkable
class BatchChannelStore(Protocol):
    """Async channel store. ``update`` must be atomic per channel."""

    async def get(self, channel_id: str) -> BatchChannelRecord | None: ...

    async def update(self, channel_id: str, mutator: ChannelMutator) -> BatchChannelRecord | None: ...

    async def list_channels(self) -> list[BatchChannelRecord]: ...


class MemoryBatchChannelStore:
    """Process-local store for tests and single-instance development.

    A restart drops every charged watermark, so it must not back production.
    """

    def __init__(self) -> None:
        self._records: dict[str, BatchChannelRecord] = {}
        self._lock = asyncio.Lock()

    async def get(self, channel_id: str) -> BatchChannelRecord | None:
        record = self._records.get(channel_id)
        return copy.deepcopy(record) if record is not None else None

    async def put(self, record: BatchChannelRecord) -> None:
        async with self._lock:
            self._records[record.channel_id] = copy.deepcopy(record)

    async def update(self, channel_id: str, mutator: ChannelMutator) -> BatchChannelRecord | None:
        async with self._lock:
            current = self._records.get(channel_id)
            updated = mutator(copy.deepcopy(current) if current is not None else None)
            if updated is None:
                self._records.pop(channel_id, None)
                return None
            self._records[channel_id] = copy.deepcopy(updated)
            return copy.deepcopy(updated)

    async def list_channels(self) -> list[BatchChannelRecord]:
        return [copy.deepcopy(record) for record in self._records.values()]
