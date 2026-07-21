"""Server-side session intent: challenge issuance, voucher verification, and
channel lifecycle management.

1. The server calls :meth:`SessionServer.build_challenge_request` to produce
   the ``SessionRequest`` embedded in a 402 challenge.
2. The client responds with an open action; the server calls
   :meth:`SessionServer.process_open` to record the channel.
3. For each subsequent API call the client attaches a voucher action; the
   server calls :meth:`SessionServer.verify_voucher` to validate and advance
   the settled watermark atomically.
4. At session end the client (or server) triggers close via
   :meth:`SessionServer.process_close`; on-chain settlement is driven by the
   host once the close-pending state is recorded.

On-chain verification is a seam in this layer: when
:attr:`SessionConfig.verify_open_tx` / :attr:`SessionConfig.verify_top_up_tx`
are set, :meth:`process_open` (push mode) and :meth:`process_top_up` invoke
them before persisting channel state, binding the payload to the attached
transaction and confirming the signature on-chain. When ``None``, the
transaction signature and deposit amount are trusted as provided, which is
suitable only for unit tests or deployments that verify transactions out of
band.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TypeVar

from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    ClosePayload,
    CommitPayload,
    CommitReceipt,
    CommitStatus,
    MeteringDirective,
    OpenPayload,
    SessionMode,
    SessionPullVoucherStrategy,
    SessionRequest,
    SessionSettlementAuthority,
    SessionSplit,
    TopUpPayload,
    VoucherPayload,
)
from solana_pay_kit.protocols.mpp.server.session_store import (
    ChannelState,
    ChannelStore,
    CommittedDelivery,
    PendingDelivery,
)
from solana_pay_kit.protocols.mpp.server.session_voucher import (
    ChannelState as VoucherChannelState,
)
from solana_pay_kit.protocols.mpp.server.session_voucher import (
    VerifyVoucherArgs,
    VoucherVerifyStatus,
    verify_session_voucher,
    verify_voucher_for_channel,
)

__all__ = [
    "Split",
    "SessionTxVerifier",
    "SessionConfig",
    "DeliveryRequest",
    "SessionServer",
]

_U64_MAX = (1 << 64) - 1

_P = TypeVar("_P")

# SessionTxVerifier confirms an on-chain transaction referenced by a session
# payload before channel state is persisted. Implementations typically decode
# the attached transaction, bind the payload signature to it, and confirm the
# signature on-chain. This is the seam the on-chain layer plugs into; ``None``
# skips verification. Raising signals a verification failure.
SessionTxVerifier = Callable[[_P], Awaitable[None]]


@dataclass
class Split:
    """A payment split committed at channel open; distributed at close.

    ``recipient`` is a public key carried in its base58 string form.
    """

    # Recipient of this split (base58).
    recipient: str
    # BPS is the share in basis points.
    bps: int = 0


@dataclass
class SessionConfig:
    """Server configuration for the session intent."""

    # Operator public key (base58). Shown to clients in the challenge.
    operator: str = ""

    # Recipient is the primary payment recipient (base58).
    recipient: str = ""

    # MaxCap is the maximum cap the server will offer per session (base units).
    # Clients may request a lower cap but not a higher one.
    max_cap: int = 0

    # Currency identifier (e.g. "USDC", mint address).
    currency: str = ""

    # Decimals is the token decimals (default 6 for USDC).
    decimals: int = 0

    # Network is the Solana network: "mainnet", "devnet", "localnet".
    network: str = ""

    # Splits are optional splits routed to specific recipients at close.
    splits: list[Split] = field(default_factory=list)

    # ProgramID is the payment-channel program ID. None defaults to the
    # canonical program.
    program_id: str | None = None

    # MinVoucherDelta is the minimum voucher increment (base units). 0 = no
    # minimum.
    min_voucher_delta: int = 0

    # SettlementWindow is the forced-close grace period (seconds) the server
    # must survive between accepting a voucher and landing the on-chain close
    # settlement. A non-zero voucher expiry must outlast ``now +
    # settlement_window`` or the voucher is rejected, so a voucher cannot expire
    # on-chain after the request has been served but before settle lands. It
    # should match the channel ``grace_period`` granted at open (the on-chain
    # forced-close window). 0 disables the outlast check (backward compatible),
    # leaving only the ``expires_at <= now`` rejection for non-zero expiries.
    settlement_window: int = 0

    # Modes are the session modes this server accepts, advertised to clients in
    # the 402 challenge. An empty list or [push] means only the payment-channel
    # push mode is supported.
    modes: list[SessionMode] = field(default_factory=list)

    # PullVoucherStrategy is the voucher authority used for pull sessions.
    # Required when modes includes pull.
    pull_voucher_strategy: SessionPullVoucherStrategy | None = None

    # Voucher signing authority advertised to clients.
    settlement_authority: SessionSettlementAuthority = "clientVoucher"

    # VerifyOpenTx, when set, confirms the open transaction on-chain (push
    # mode) before process_open persists channel state.
    verify_open_tx: SessionTxVerifier[OpenPayload] | None = None

    # VerifyTopUpTx, when set, confirms the top-up transaction on-chain before
    # process_top_up raises the deposit.
    verify_top_up_tx: SessionTxVerifier[TopUpPayload] | None = None


@dataclass
class DeliveryRequest:
    """A request to reserve a metered delivery for client-side ack/commit.

    Zero/empty values mean "absent" for the optional fields.
    """

    # SessionID is the channel/session ID that will pay for the delivery.
    session_id: str

    # Amount owed for this delivery in base units.
    amount: int = 0

    # DeliveryID is an optional idempotency key. When empty the server derives
    # "<sessionId>:<sequence>".
    delivery_id: str = ""

    # CommitURL is an optional commit endpoint hint surfaced to the client.
    commit_url: str = ""

    # Proof is an optional opaque proof surfaced to the client.
    proof: str = ""

    # ExpiresAt is an optional directive expiry (Unix seconds). Zero defaults to
    # DEFAULT_SESSION_EXPIRES_AT.
    expires_at: int = 0


def _fits_in_deposit(cumulative: int, pending_total: int, amount: int, deposit: int) -> bool:
    """Report whether cumulative + pending_total + amount <= deposit without
    overflowing u64; any overflow is treated as exceeding the deposit.
    """
    if pending_total > _U64_MAX - cumulative:
        return False
    reserved = cumulative + pending_total
    if amount > _U64_MAX - reserved:
        return False
    return reserved + amount <= deposit


def _parse_u64(raw: str) -> int:
    """Parse a canonical unsigned base-10 ``u64``: the string must be all ASCII
    decimal digits and fit within the 64-bit unsigned range. Raises
    ``ValueError`` otherwise."""
    if not (raw.isascii() and raw.isdigit()):
        raise ValueError(f"invalid u64: {raw}")
    value = int(raw, 10)
    if value > _U64_MAX:
        raise ValueError(f"u64 out of range: {raw}")
    return value


def _find_pending(deliveries: list[PendingDelivery], delivery_id: str) -> PendingDelivery | None:
    """Return the pending delivery with the given id, or None."""
    for delivery in deliveries:
        if delivery.delivery_id == delivery_id:
            return delivery
    return None


def _find_committed(deliveries: list[CommittedDelivery], delivery_id: str) -> CommittedDelivery | None:
    """Return the committed delivery with the given id, or None."""
    for delivery in deliveries:
        if delivery.delivery_id == delivery_id:
            return delivery
    return None


def _commit_receipt(
    delivery_id: str, session_id: str, amount: int, cumulative: int, status: CommitStatus
) -> CommitReceipt:
    """Build a CommitReceipt with stringified amounts."""
    return CommitReceipt(
        delivery_id=delivery_id,
        session_id=session_id,
        amount=str(amount),
        cumulative=str(cumulative),
        status=status,
    )


class SessionServer:
    """Server-side session manager. Pluggable over the channel store to support
    in-memory testing and production persistence backends.
    """

    def __init__(self, config: SessionConfig, store: ChannelStore) -> None:
        # config is the immutable server configuration captured at construction.
        self._config = config
        # store persists per-channel state; every mutation goes through its
        # atomic update_channel so voucher watermarks stay double-spend safe.
        self._store = store

    @property
    def config(self) -> SessionConfig:
        """The immutable server configuration captured at construction.

        Exposed read-only so the HTTP-facing session method can inspect the
        configured currency/decimals/network without reaching into a private
        field."""
        return self._config

    def store(self) -> ChannelStore:
        """Return the channel store backing this server, so hosts can share it
        with metering side channels."""
        return self._store

    def build_challenge_request(self, cap: int) -> SessionRequest:
        """Build the ``SessionRequest`` to embed in a 402 challenge.

        ``cap`` is the maximum this session will allow, clamped to
        ``SessionConfig.max_cap``. ``min_voucher_delta`` is included only when
        positive, ``modes`` is omitted when push-only, and
        ``pull_voucher_strategy`` is included only when pull is offered.
        """
        effective_cap = min(cap, self._config.max_cap)

        request = SessionRequest(
            cap=str(effective_cap),
            currency=self._config.currency,
            operator=self._config.operator,
            recipient=self._config.recipient,
            decimals=self._config.decimals,
            settlement_authority=self._config.settlement_authority,
        )
        if self._config.network != "":
            request.network = self._config.network
        for split in self._config.splits:
            request.splits.append(SessionSplit(recipient=split.recipient, bps=split.bps))
        if self._config.program_id is not None:
            request.program_id = self._config.program_id
        if self._config.min_voucher_delta > 0:
            request.min_voucher_delta = str(self._config.min_voucher_delta)
        # Omit modes when only push is supported; clients assume push when modes
        # is absent.
        if not self._push_only():
            request.modes = list(self._config.modes)
        if self._supports_mode("pull") and self._config.pull_voucher_strategy is not None:
            request.pull_voucher_strategy = self._config.pull_voucher_strategy
        return request

    def _push_only(self) -> bool:
        """Report whether the configured modes reduce to push-only."""
        modes = self._config.modes
        return len(modes) == 0 or (len(modes) == 1 and modes[0] == "push")

    def _supports_mode(self, mode: SessionMode) -> bool:
        """Report whether the server accepts ``mode``. Empty configured modes
        mean push-only."""
        modes = self._config.modes
        if len(modes) == 0:
            return mode == "push"
        return mode in modes

    async def process_open(self, payload: OpenPayload) -> ChannelState:
        """Process an open action and persist the channel state.

        The channel is keyed by ``OpenPayload.session_id`` (channelId first,
        then tokenAccount for pull opens). Replayed opens are idempotent: when a
        channel already exists for the session id with the same authorized
        signer, the existing state is returned unchanged and the voucher
        watermark is never reset. Opens for an existing channel are rejected
        when the channel is sealed or when the payload's authorized signer
        differs from the stored one.
        """
        if not self._supports_mode(payload.mode):
            raise ValueError(f"session mode {payload.mode!r} is not supported by this challenge")

        session_id = payload.session_id()
        deposit = payload.deposit_amount()
        if deposit == 0:
            raise ValueError("deposit must be greater than zero")
        if deposit > self._config.max_cap:
            raise ValueError(f"deposit {deposit} exceeds max cap {self._config.max_cap}")

        if (
            self._config.settlement_authority == "delegated"
            and payload.authorized_signer != self._config.operator
        ):
            raise ValueError("delegated settlement requires authorizedSigner to match the operator")

        # On-chain verification seam (push mode only; pull-mode host
        # integrations submit server-broadcast transactions or validate
        # delegated-token state before invoking this lower-level store method).
        if payload.mode == "push" and self._config.verify_open_tx is not None:
            try:
                await self._config.verify_open_tx(payload)
            except Exception as exc:
                raise _wrap("open tx verification failed", exc) from exc

        operator = payload.owner
        if operator is None:
            operator = payload.payer
        fresh = ChannelState(
            channel_id=session_id,
            authorized_signer=payload.authorized_signer,
            deposit=deposit,
            operator=operator,
            # The payload's recentSlot is the channel openSlot (a channel PDA
            # seed); persist it so the channel address can be re-derived and
            # the rent reclaimed later. Zero when the payload does not carry
            # one (pull opens, trusted opens).
            open_slot=payload.recent_slot or 0,
        )

        def mutator(existing: ChannelState | None) -> ChannelState:
            # Atomic check-and-insert: a replayed open re-passes all checks
            # above (the referenced tx is genuinely confirmed), so it MUST NOT
            # overwrite existing state; that would reset the voucher watermark
            # and erase accepted vouchers before close.
            if existing is not None:
                if existing.sealed:
                    raise ValueError(f"channel {session_id} is already sealed")
                if existing.authorized_signer != payload.authorized_signer:
                    raise ValueError(f"channel {session_id} already exists with a different authorized signer")
                # Idempotent replay: keep existing state untouched.
                return existing
            return fresh

        return await self._store.update_channel(session_id, mutator)

    async def verify_voucher(self, payload: VoucherPayload) -> int:
        """Verify a voucher, advance the watermark, and return the new
        cumulative.

        The full ordered check sequence runs as a preflight outside the store
        lock (see :func:`verify_voucher_for_channel`), then the state-dependent
        checks are re-applied inside the atomic mutator before the watermark is
        persisted.
        """
        voucher = payload.voucher
        channel_id = voucher.data.channel_id

        state = await self._store.get_channel(channel_id)
        if state is None:
            raise ValueError(f"channel {channel_id} not found")

        # Preflight outside the lock (expensive signature check happens before
        # touching the store).
        result = verify_voucher_for_channel(
            VerifyVoucherArgs(
                state=_voucher_state(state),
                signed=voucher,
                deposit=state.deposit,
                min_voucher_delta=self._config.min_voucher_delta,
                settlement_window=self._config.settlement_window,
            )
        )
        if result.status == VoucherVerifyStatus.REJECTED:
            # Surface the stable reject tag ahead of the detail
            # ("<reason>: <detail>").
            raise ValueError(f"{result.reason}: {result.detail}")
        if result.status == VoucherVerifyStatus.REPLAYED:
            return result.new_cumulative

        new_cumulative = result.new_cumulative
        new_signature = result.new_signature
        new_expires_at = result.new_expires_at

        def mutator(current: ChannelState | None) -> ChannelState:
            # Atomic read-modify-write: re-check everything state-dependent
            # inside the mutator.
            if current is None:
                raise ValueError(f"channel {channel_id} not found")
            if current.sealed:
                raise ValueError(f"channel {channel_id} is already sealed")
            if current.close_requested_at is not None:
                raise ValueError(f"channel {channel_id} close is pending; no further vouchers accepted")
            # Idempotent replay inside the mutator.
            if (
                new_cumulative == current.cumulative
                and current.highest_voucher_signature is not None
                and current.highest_voucher_signature == new_signature
            ):
                return current
            # Concurrent watermark advancement check.
            if new_cumulative <= current.cumulative:
                raise ValueError("concurrent update: watermark advanced")
            nxt = current.clone()
            nxt.cumulative = new_cumulative
            nxt.highest_voucher_signature = new_signature
            nxt.highest_voucher_expires_at = new_expires_at
            return nxt

        new_state = await self._store.update_channel(channel_id, mutator)
        return new_state.cumulative

    async def process_top_up(self, payload: TopUpPayload) -> ChannelState:
        """Process a topUp action: atomically raise the channel's deposit cap.

        The new deposit must exceed the current deposit and must not exceed the
        configured max cap. Top-ups are rejected once the channel is sealed
        or a close has been requested.
        """
        try:
            new_deposit = _parse_u64(payload.new_deposit)
        except ValueError as exc:
            raise ValueError(f"invalid newDeposit: {payload.new_deposit}") from exc

        # On-chain verification seam (same shape as process_open).
        if self._config.verify_top_up_tx is not None:
            try:
                await self._config.verify_top_up_tx(payload)
            except Exception as exc:
                raise _wrap("top-up tx verification failed", exc) from exc

        max_cap = self._config.max_cap
        channel_id = payload.channel_id

        def mutator(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise ValueError(f"channel {channel_id} not found")
            if current.sealed:
                raise ValueError(f"channel {channel_id} is already sealed")
            if current.close_requested_at is not None:
                raise ValueError(f"channel {channel_id} close is pending; no further top-ups accepted")
            if new_deposit <= current.deposit:
                raise ValueError(f"new deposit {new_deposit} must exceed current deposit {current.deposit}")
            if new_deposit > max_cap:
                raise ValueError(f"new deposit {new_deposit} exceeds max cap {max_cap}")
            nxt = current.clone()
            nxt.deposit = new_deposit
            return nxt

        return await self._store.update_channel(channel_id, mutator)

    async def begin_delivery(self, request: DeliveryRequest) -> MeteringDirective:
        """Reserve capacity for a delivered message/response and return the
        metering directive the client must commit after processing it.

        The reservation requires cumulative + pendingTotal + amount <= deposit,
        assigns the next sequence, and defaults the delivery id to
        "<sessionId>:<sequence>".
        """
        if request.amount == 0:
            raise ValueError("delivery amount must be greater than zero")

        session_id = request.session_id
        amount = request.amount
        expires_at = request.expires_at
        if expires_at == 0:
            expires_at = DEFAULT_SESSION_EXPIRES_AT

        directive: MeteringDirective | None = None

        def mutator(current: ChannelState | None) -> ChannelState:
            nonlocal directive
            if current is None:
                raise ValueError(f"channel {session_id} not found")
            if current.sealed:
                raise ValueError(f"channel {session_id} is already sealed")
            if current.close_requested_at is not None:
                raise ValueError(f"channel {session_id} close is pending; no further deliveries accepted")
            pending_total = sum(d.amount for d in current.pending_deliveries)
            if not _fits_in_deposit(current.cumulative, pending_total, amount, current.deposit):
                raise ValueError(f"delivery amount {amount} exceeds available deposit")

            sequence = current.next_delivery_sequence + 1
            delivery_id = request.delivery_id
            if delivery_id == "":
                delivery_id = f"{session_id}:{sequence}"
            for delivery in current.pending_deliveries:
                if delivery.delivery_id == delivery_id:
                    raise ValueError(f"delivery {delivery_id} already exists")
            for delivery in current.committed_deliveries:
                if delivery.delivery_id == delivery_id:
                    raise ValueError(f"delivery {delivery_id} already exists")

            nxt = current.clone()
            nxt.next_delivery_sequence = sequence
            nxt.pending_deliveries.append(
                PendingDelivery(
                    delivery_id=delivery_id,
                    amount=amount,
                    sequence=sequence,
                    expires_at=expires_at,
                )
            )

            built = MeteringDirective(
                delivery_id=delivery_id,
                session_id=session_id,
                amount=str(amount),
                currency=self._config.currency,
                sequence=sequence,
                expires_at=expires_at,
            )
            if request.commit_url != "":
                built.commit_url = request.commit_url
            if request.proof != "":
                built.proof = request.proof
            directive = built
            return nxt

        await self._store.update_channel(session_id, mutator)
        assert directive is not None
        return directive

    async def process_commit(self, payload: CommitPayload) -> CommitReceipt:
        """Commit a reserved delivery by verifying the attached voucher and
        advancing the settled watermark.

        Replaying a commit for an already-committed delivery (same cumulative
        and same signature) returns the cached receipt with status replayed
        after re-verifying the voucher signature.
        """
        channel_id = payload.voucher.data.channel_id
        try:
            new_cumulative = _parse_u64(payload.voucher.data.cumulative)
        except ValueError as exc:
            raise ValueError(f"invalid cumulative in commit voucher: {payload.voucher.data.cumulative}") from exc

        state = await self._store.get_channel(channel_id)
        if state is None:
            raise ValueError(f"channel {channel_id} not found")

        # Preflight outside the lock.
        committed = _find_committed(state.committed_deliveries, payload.delivery_id)
        if committed is not None:
            if committed.cumulative == new_cumulative and committed.voucher_signature == payload.voucher.signature:
                _raise_voucher_error(
                    verify_session_voucher(payload.voucher, state.authorized_signer, self._config.settlement_window)
                )
                return _commit_receipt(
                    payload.delivery_id, channel_id, committed.amount, committed.cumulative, "replayed"
                )
            raise ValueError(f"delivery {payload.delivery_id} was already committed with different voucher")
        pending = _find_pending(state.pending_deliveries, payload.delivery_id)
        if pending is None:
            raise ValueError(f"delivery {payload.delivery_id} not found")
        now = int(time.time())
        if pending.expires_at <= now:
            raise ValueError(f"delivery {payload.delivery_id} has expired")
        if new_cumulative <= state.cumulative:
            raise ValueError(f"commit cumulative {new_cumulative} must exceed watermark {state.cumulative}")
        _raise_voucher_error(
            verify_session_voucher(payload.voucher, state.authorized_signer, self._config.settlement_window)
        )

        delivery_id = payload.delivery_id
        signature = payload.voucher.signature
        voucher_expires_at = payload.voucher.data.expires_at

        receipt: list[CommitReceipt] = []

        def mutator(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise ValueError(f"channel {channel_id} not found")
            if current.sealed:
                raise ValueError(f"channel {channel_id} is already sealed")
            if current.close_requested_at is not None:
                raise ValueError(f"channel {channel_id} close is pending; no further commits accepted")
            existing = _find_committed(current.committed_deliveries, delivery_id)
            if existing is not None:
                if existing.cumulative == new_cumulative and existing.voucher_signature == signature:
                    receipt.append(
                        _commit_receipt(delivery_id, channel_id, existing.amount, existing.cumulative, "replayed")
                    )
                    return current
                raise ValueError(f"delivery {delivery_id} was already committed with different voucher")
            pending_index = -1
            for i, delivery in enumerate(current.pending_deliveries):
                if delivery.delivery_id == delivery_id:
                    pending_index = i
                    break
            if pending_index < 0:
                raise ValueError(f"delivery {delivery_id} not found")
            reserved = current.pending_deliveries[pending_index]
            if reserved.expires_at <= now:
                raise ValueError(f"delivery {delivery_id} has expired")
            if new_cumulative <= current.cumulative:
                raise ValueError(f"commit cumulative {new_cumulative} must exceed watermark {current.cumulative}")
            actual_amount = new_cumulative - current.cumulative
            if actual_amount > reserved.amount:
                raise ValueError(f"commit amount {actual_amount} exceeds reserved amount {reserved.amount}")

            nxt = current.clone()
            nxt.pending_deliveries = (
                nxt.pending_deliveries[:pending_index] + nxt.pending_deliveries[pending_index + 1 :]
            )
            nxt.cumulative = new_cumulative
            nxt.highest_voucher_signature = signature
            nxt.highest_voucher_expires_at = voucher_expires_at
            nxt.committed_deliveries.append(
                CommittedDelivery(
                    delivery_id=delivery_id,
                    amount=actual_amount,
                    cumulative=new_cumulative,
                    voucher_signature=signature,
                )
            )
            receipt.append(_commit_receipt(delivery_id, channel_id, actual_amount, new_cumulative, "committed"))
            return nxt

        await self._store.update_channel(channel_id, mutator)
        return receipt[0]

    async def process_close(self, payload: ClosePayload) -> ChannelState:
        """Process a close action: atomically set close-pending and accept a
        final voucher if provided.

        Once close_requested_at is set, vouchers, deliveries, commits, and
        top-ups are all rejected, and a second close is rejected with "close
        already requested". A non-monotonic final voucher is a hard error
        (unless it is an idempotent replay of the current highest voucher) and
        leaves the state unchanged.
        """
        now = int(time.time())
        channel_id = payload.channel_id
        voucher = payload.voucher

        def mutator(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise ValueError(f"channel {channel_id} not found")
            if current.sealed:
                raise ValueError(f"channel {channel_id} is already sealed")
            if current.close_requested_at is not None:
                raise ValueError("close already requested")

            nxt = current.clone()
            if voucher is not None:
                try:
                    cumulative = _parse_u64(voucher.data.cumulative)
                except ValueError as exc:
                    raise ValueError(f"invalid cumulative in final voucher: {voucher.data.cumulative}") from exc
                if cumulative <= current.cumulative:
                    # Idempotent replay of the current highest voucher is
                    # allowed; any other non-monotonic final voucher is a hard
                    # error.
                    replay = (
                        cumulative == current.cumulative
                        and current.highest_voucher_signature is not None
                        and current.highest_voucher_signature == voucher.signature
                    )
                    if not replay:
                        raise ValueError(
                            f"final voucher cumulative {cumulative} must exceed watermark {current.cumulative}"
                        )
                    # Recheck expiry/window even on idempotent replay so a close is
                    # not recorded against a voucher that no longer outlasts the
                    # settlement window (the async settle would then fail on-chain).
                    _raise_voucher_error(
                        verify_session_voucher(voucher, current.authorized_signer, self._config.settlement_window)
                    )
                    if nxt.highest_voucher_expires_at is None:
                        nxt.highest_voucher_expires_at = voucher.data.expires_at
                else:
                    if cumulative > current.deposit:
                        raise ValueError("final voucher exceeds deposit")
                    _raise_voucher_error(
                        verify_session_voucher(voucher, current.authorized_signer, self._config.settlement_window)
                    )
                    nxt.cumulative = cumulative
                    nxt.highest_voucher_signature = voucher.signature
                    nxt.highest_voucher_expires_at = voucher.data.expires_at
            nxt.close_requested_at = now
            return nxt

        return await self._store.update_channel(channel_id, mutator)

    async def mark_sealed(self, channel_id: str) -> None:
        """Mark a channel as sealed. Call after the on-chain seal
        transaction confirms."""
        await self._store.mark_sealed(channel_id)


def _voucher_state(state: ChannelState) -> VoucherChannelState:
    """Project the full store ``ChannelState`` onto the verifier's read-only
    subset. The verifier module defines its own ``ChannelState`` carrying only
    the fields it reads."""
    return VoucherChannelState(
        channel_id=state.channel_id,
        authorized_signer=state.authorized_signer,
        deposit=state.deposit,
        cumulative=state.cumulative,
        sealed=state.sealed,
        highest_voucher_signature=state.highest_voucher_signature,
        highest_voucher_expires_at=state.highest_voucher_expires_at,
        close_requested_at=state.close_requested_at,
    )


def _raise_voucher_error(err: str | None) -> None:
    """Raise when the voucher verifier (string-returning) reports a failure.

    ``verify_session_voucher`` returns an error string (or None); convert the
    string form to a raised ``ValueError`` so the session paths surface
    verification failures as exceptions.
    """
    if err is not None:
        raise ValueError(err)


def _wrap(message: str, exc: Exception) -> Exception:
    """Wrap a seam error with a message prefix: the prefixed message is
    surfaced and the original error is preserved as the exception cause, so
    callers can inspect ``__cause__`` to recover the underlying failure."""
    return ValueError(f"{message}: {exc}")
