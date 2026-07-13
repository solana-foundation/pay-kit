"""HTTP-facing MPP session method handler.

A :class:`Session` issues HMAC-bound 402 challenges carrying a
:class:`~solana_pay_kit.protocols.mpp.intents.session.SessionRequest`
(:meth:`Session.challenge`), verifies Authorization credentials whose payload is
one of the five session actions (:meth:`Session.verify_credential` dispatching
to open / voucher / commit / topUp / close), and drives the channel lifecycle by
composing the lower-level building blocks: the :class:`SessionServer` core, the
:class:`ChannelStore`, the voucher verifier, the on-chain verifier seams, and
the idle-close watchdog.

Trust model / on-chain seam: the RPC client is optional. With no RPC client the
transaction signature and deposit amount are trusted as provided (offline
core); with an RPC client an open's confirmation signature is checked on-chain
before the channel is persisted, and a top-up's confirmed instruction is bound
to its exact channel and deposit delta before the deposit is raised. The
on-chain check is wired through the
:class:`SessionServer` config seams
(:func:`~solana_pay_kit.protocols.mpp.server.session_onchain.new_open_tx_verifier` /
:func:`~solana_pay_kit.protocols.mpp.server.session_onchain.new_top_up_tx_verifier`).

On-chain settlement at close (settle_and_seal + distribute, populating
``settledSignature``) runs when both a signer and an RPC client are configured;
without them, close is a pure state-flip. The idle-close watchdog settles the
same way. The server-broadcast open path (``openTxSubmitter=server``) runs only
when an open carries an attached transaction (push opens and clientVoucher pull
opens whose deposit lives in an on-chain payment channel): the server completes
the fee-payer signature and broadcasts the open. A pull open with no
transaction skips the server-broadcast path and trusts the channel id / deposit
even when ``openTxSubmitter=server`` is configured, mirroring the TS open
dispatch.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    PaymentError,
    payment_required_response,
)
from solana_pay_kit._paycore.solana import MAX_SPLITS, _canonical_network, validate_network
from solana_pay_kit.protocols.mpp.core.expires import minutes
from solana_pay_kit.protocols.mpp.core.headers import (
    PAYMENT_RECEIPT_HEADER,
    format_receipt,
    format_www_authenticate,
    parse_authorization,
)
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential, Receipt
from solana_pay_kit.protocols.mpp.intents.session import (
    ClosePayload,
    CommitPayload,
    OpenPayload,
    SessionAction,
    SessionMode,
    SessionPullVoucherStrategy,
    TopUpPayload,
    VoucherPayload,
)
from solana_pay_kit.protocols.mpp.server.defaults import detect_realm
from solana_pay_kit.protocols.mpp.server.session import SessionConfig, SessionServer, Split
from solana_pay_kit.protocols.mpp.server.session_lifecycle import SessionLifecycle
from solana_pay_kit.protocols.mpp.server.session_onchain import (
    PreparedTransaction,
    RpcClient,
    VerifyOpenTxExpected,
    VerifyOpenTxResult,
    _require_account_info_rpc,
    broadcast_prepared_transaction,
    complete_open_transaction,
    confirm_transaction_signature,
    new_top_up_state_tx_verifier,
    settle_and_seal_channel,
    verify_open_tx,
)
from solana_pay_kit.protocols.mpp.server.session_store import ChannelState, ChannelStore, MemoryChannelStore
from solana_pay_kit.signer import LocalSigner

logger = logging.getLogger(__name__)

_SECRET_KEY_ENV_VAR = "MPP_SECRET_KEY"
_ALLOW_INMEMORY_REPLAY_STORE_ENV = "PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE"
_U64_MAX = (1 << 64) - 1
_OPEN_OUTBOX_PREFIX = "__pay_kit_session_open_outbox__:"
_OPEN_OUTBOX_LEASE_SECONDS = 60
_OPEN_OUTBOX_RECORD_VERSION = 1


class _AlreadySealed(Exception):
    """Raised by the settle-claim mutator when the channel is already sealed."""

    __slots__ = ("signature",)

    def __init__(self, signature: str | None) -> None:
        super().__init__("already sealed")
        self.signature = signature


class _AlreadySettling(Exception):
    """Raised by the settle-claim mutator when another caller is mid-settle."""


class _SettlementPhase(Enum):
    """Persisted settlement states derived from the channel record."""

    READY = "ready"
    IN_PROGRESS = "in_progress"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    SEALED = "sealed"


@dataclass(frozen=True)
class _SettlementStatus:
    """Typed view of the settlement fields persisted on a channel."""

    phase: _SettlementPhase
    signature: str | None = None


@dataclass(frozen=True)
class _ServerOpenOutbox:
    """The immutable signed open transaction and facts it was verified against."""

    prepared: PreparedTransaction
    authorized_signer: str
    deposit: int
    payer: str
    open_slot: int


def _settlement_status(state: ChannelState) -> _SettlementStatus:
    """Classify settlement without conflating a broadcast with a receipt."""
    if state.sealed:
        return _SettlementStatus(_SettlementPhase.SEALED, state.settled_signature)
    if state.settled_signature is not None:
        # ``settling`` is transient and may reset after process restart. The
        # durable broadcast signature is sufficient to reconcile safely.
        return _SettlementStatus(_SettlementPhase.AWAITING_CONFIRMATION, state.settled_signature)
    if state.settling:
        return _SettlementStatus(_SettlementPhase.IN_PROGRESS)
    return _SettlementStatus(_SettlementPhase.READY)


def _open_outbox_key(channel_id: str) -> str:
    """Return the private store key for a server-broadcast open outbox."""
    return f"{_OPEN_OUTBOX_PREFIX}{channel_id}"


def _open_outbox_from_state(state: ChannelState, channel_id: str) -> _ServerOpenOutbox:
    """Decode a private server-open outbox record stored through ChannelStore.

    The public channel-state schema intentionally has no open outbox fields.
    A private record under an opaque store key keeps the exact signed wire and
    its verified facts durable without changing the shared state schema. Its
    otherwise-unused fields are a private format: ``cumulative`` is the format
    version and ``next_delivery_sequence`` is the current lease owner token.
    """
    if state.channel_id != _open_outbox_key(channel_id):
        raise ValueError(f"invalid server-open outbox key for channel {channel_id}")
    if state.cumulative != _OPEN_OUTBOX_RECORD_VERSION:
        raise ValueError(f"legacy or invalid server-open outbox for channel {channel_id}; refusing recovery")
    if not state.authorized_signer or state.deposit <= 0 or not state.operator:
        raise ValueError(f"server-open outbox for channel {channel_id} is missing verified open facts")
    if state.next_delivery_sequence <= 0:
        raise ValueError(f"server-open outbox for channel {channel_id} is missing its lease owner")
    if state.settled_signature is None:
        raise ValueError(f"server-open outbox for channel {channel_id} is missing its signature")
    if state.highest_voucher_signature is None:
        raise ValueError(f"server-open outbox for channel {channel_id} is missing signed wire")
    try:
        wire = base64.b64decode(state.highest_voucher_signature, validate=True)
    except Exception as exc:
        raise ValueError(f"invalid server-open outbox wire for channel {channel_id}: {exc}") from exc
    if not wire:
        raise ValueError(f"server-open outbox for channel {channel_id} has empty signed wire")
    return _ServerOpenOutbox(
        prepared=PreparedTransaction(wire=wire, signature=state.settled_signature),
        authorized_signer=state.authorized_signer,
        deposit=state.deposit,
        payer=state.operator,
        open_slot=state.open_slot,
    )


def _server_open_outbox_matches_verified(
    outbox: _ServerOpenOutbox, payload: OpenPayload, verified: VerifyOpenTxResult
) -> bool:
    """Report whether a recovery request has the outbox transaction's facts."""
    return (
        outbox.authorized_signer == payload.authorized_signer
        and outbox.deposit == verified.deposit
        and outbox.payer == verified.payer
        and outbox.open_slot == verified.open_slot
    )


async def _finish_store_update(awaitable):
    """Finish a store write even if the caller is cancelled mid-write.

    Returns whether cancellation was observed. The caller records its durable
    state transition before re-raising cancellation, so an accepted broadcast
    is never followed by a rollback of the only recovery marker.
    """
    task = asyncio.create_task(awaitable)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    task.result()
    return cancelled


__all__ = [
    "OpenTxSubmitter",
    "SessionOptions",
    "SessionChallengeOptions",
    "SessionGateResult",
    "Session",
    "new_session",
]


# OpenTxSubmitter selects who broadcasts a push-mode payment-channel open
# transaction.
OpenTxSubmitter = str

# The client broadcasts the open transaction itself and the server only verifies
# it. Default.
OPEN_TX_SUBMITTER_CLIENT: OpenTxSubmitter = "client"

# The server completes the fee-payer signature, broadcasts the client-built open
# transaction, and waits for confirmation before persisting channel state.
OPEN_TX_SUBMITTER_SERVER: OpenTxSubmitter = "server"


@dataclass
class SessionOptions:
    """Options for :func:`new_session`."""

    # Operator public key (base58), shown to clients in the challenge.
    operator: str = ""
    # Recipient is the primary payment recipient (base58). Required.
    recipient: str = ""
    # Cap is the maximum session cap the server will offer (base units).
    # Required, must be positive.
    cap: int = 0
    # Currency identifier (e.g. "USDC" or an SPL mint address). Default USDC.
    currency: str = ""
    # Decimals is the token decimals. Default 6.
    decimals: int = 0
    # Network is the Solana network. Default "mainnet".
    network: str = ""
    # SecretKey is the challenge HMAC secret. Defaults to MPP_SECRET_KEY.
    secret_key: str = ""
    # Realm is the challenge realm. Defaults to detect_realm().
    realm: str = ""
    # ProgramID overrides the payment-channels program id. None defaults to the
    # canonical program.
    program_id: Pubkey | None = None
    # MinVoucherDelta is the minimum voucher increment (base units). 0 = no
    # minimum.
    min_voucher_delta: int = 0
    # Modes are the funding modes advertised to clients. Empty means push only.
    modes: list[SessionMode] = field(default_factory=list)
    # PullVoucherStrategy is the voucher authority for pull-mode sessions.
    # Required when modes includes pull.
    pull_voucher_strategy: SessionPullVoucherStrategy | None = None
    # Splits are optional basis-point splits distributed at close. Max 8.
    splits: list[Split] = field(default_factory=list)
    # CloseDelay arms the idle-close watchdog (seconds); zero disables it.
    close_delay: float = 0
    # OpenTxSubmitter selects who broadcasts push-mode open transactions.
    # Default "client".
    open_tx_submitter: OpenTxSubmitter = ""
    # Store is the pluggable channel store. Localnet defaults to in-memory;
    # off-localnet requires a durable store unless the development escape hatch
    # PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1 is set explicitly.
    store: ChannelStore | None = None
    # RPC is the optional RPC client used for on-chain checks. None skips every
    # on-chain check and trusts payload claims as provided. When signer is also
    # configured, settlement requires get_account_info in addition to RpcClient.
    rpc: RpcClient | None = None
    # RecentStateProvider pre-fetches ``(recentBlockhash, recentSlot)`` for
    # challenge issuance from a single ``getLatestBlockhash`` call (the
    # response context carries the slot), WITHOUT granting the method an RPC
    # client — on-chain open verification and settle-at-close stay off, so
    # payload claims are trusted exactly as with ``rpc=None``. When set it
    # wins over ``rpc`` at challenge time. Mirrors
    # ``X402Upto(recent_state_provider=...)``.
    recent_state_provider: Callable[[], tuple[str | None, int | None] | None] | None = None
    # Signer is the operator/merchant local signer that funds and signs the
    # on-chain settle-at-close (and the server-broadcast open) transactions.
    # None (or no RPC) leaves close a pure state-flip with settledSignature unset.
    signer: LocalSigner | None = None


@dataclass
class SessionChallengeOptions:
    """Customize a single 402 session challenge."""

    # Cap is the requested session cap (base units, decimal string). Empty uses
    # the server maximum; larger requests are clamped to it.
    cap: str = ""
    # Description is a human-readable challenge description.
    description: str = ""
    # ExternalID is a merchant reference id echoed on the receipt.
    external_id: str = ""
    # Expires is the challenge expiry (RFC 3339). Default five minutes.
    expires: str = ""


@dataclass
class SessionGateResult:
    """Outcome of :meth:`Session.handle`: verified credential or 402 challenge.

    Framework-agnostic so any host (FastAPI, ASGI, a test) can render it. On
    success ``ok`` is True, ``status`` is 200, ``headers`` carries the receipt
    header, and ``body`` is None. On a missing or invalid credential ``ok`` is
    False, ``status`` is 402, ``headers`` carries the ``WWW-Authenticate``
    challenge, and ``body`` is the ``application/problem+json`` problem document.
    """

    # ok is True when a credential verified, False when answering 402.
    ok: bool
    # status is 200 on success, 402 on a payment-required challenge.
    status: int
    # headers are the receipt headers on success, else the 402 challenge headers.
    headers: dict[str, str]
    # body is None on success, else the 402 problem document.
    body: dict[str, Any] | None = None


def _parse_session_u64(value: str, name: str) -> int:
    """Parse a non-negative decimal string into a u64, naming the field on
    error."""
    if not isinstance(value, str) or not (value.isascii() and value.isdigit()):
        raise ValueError(f"{name} is not an unsigned integer string: {value}")
    parsed = int(value, 10)
    if parsed > _U64_MAX:
        raise ValueError(f"{name} is not an unsigned integer string: {value}")
    return parsed


async def _try_recent_blockhash_and_slot(rpc: Any) -> tuple[str | None, int | None]:
    """Best-effort fetch of a recent blockhash plus the current slot from the
    injected RPC client, in one ``getLatestBlockhash`` call.

    The response envelope already carries the current slot in its context, so
    the challenge's ``recentSlot`` comes from the same response as the
    blockhash rather than a separate ``getSlot`` round-trip (a duck-typed RPC
    whose response lacks ``context.slot`` falls back to ``get_slot`` when it
    has one). Returns ``(None, None)`` on any error/absence; the prefetch is
    non-fatal because the client fetches its own blockhash when the challenge
    omits one — but never the slot, so a push open without a challenge
    ``recentSlot`` fails client-side.
    """
    getter: Any = getattr(rpc, "get_latest_blockhash", None)
    if not callable(getter):
        return None, None
    try:
        pending: Any = getter("confirmed")
        out = await pending
    except Exception:
        return None, None
    value: Any = getattr(out, "value", None)
    blockhash: Any = getattr(value, "blockhash", None)
    if not isinstance(blockhash, str) or not blockhash:
        blockhash = None
    slot: Any = getattr(getattr(out, "context", None), "slot", None)
    if isinstance(slot, bool) or not isinstance(slot, int) or slot < 0:
        slot = await _try_current_slot(rpc)
    return blockhash, slot


async def _try_current_slot(rpc: Any) -> int | None:
    """Best-effort ``getSlot`` fallback for RPC clients whose
    ``get_latest_blockhash`` response does not expose ``context.slot``."""
    getter: Any = getattr(rpc, "get_slot", None)
    if not callable(getter):
        return None
    try:
        pending: Any = getter("confirmed")
        out = await pending
    except Exception:
        return None
    if isinstance(out, bool):
        return None
    return out if isinstance(out, int) and out >= 0 else None


def _success_receipt(reference: str, challenge_id: str, external_id: str) -> Receipt:
    """Build a success receipt for a session action."""
    return Receipt.success(
        method="solana",
        reference=reference,
        challenge_id=challenge_id,
        external_id=external_id,
    )


class Session:
    """The server-side session method handler. Create with :func:`new_session`."""

    def __init__(
        self,
        *,
        core: SessionServer,
        secret_key: str,
        realm: str,
        cap: int,
        currency: str,
        recipient: str,
        network: str,
        open_tx_submitter: OpenTxSubmitter,
        rpc: RpcClient | None,
        lifecycle: SessionLifecycle | None,
        signer: LocalSigner | None = None,
        recent_state_provider: Callable[[], tuple[str | None, int | None] | None] | None = None,
    ) -> None:
        # core is the lower-level SessionServer dispatching open / voucher /
        # commit / topUp / close against the channel store.
        self._core = core
        self._secret_key = secret_key
        self._realm = realm
        # cap is the maximum session cap offered in challenges (base units);
        # per-challenge requested caps are clamped to it.
        self._cap = cap
        self._currency = currency
        self._recipient = recipient
        self._network = network
        self._open_tx_submitter = open_tx_submitter
        # rpc is the optional RPC client for on-chain checks; None trusts payload
        # claims as provided.
        self._rpc = rpc
        # recent_state_provider stamps challenge (recentBlockhash, recentSlot)
        # without an RPC client; wins over rpc at challenge time.
        self._recent_state_provider = recent_state_provider
        # lifecycle is the idle-close watchdog; None when close_delay is zero.
        self._lifecycle = lifecycle
        # signer settles the channel on-chain at close (and broadcasts server
        # opens); None or no rpc leaves close a state-flip with no settlement.
        self._signer = signer

    def core(self) -> SessionServer:
        """Return the underlying :class:`SessionServer` so hosts can reach the
        channel store and the lower-level lifecycle methods."""
        return self._core

    def shutdown(self) -> None:
        """Cancel the idle-close watchdog timers. Hosts should call it when
        tearing the session method down."""
        if self._lifecycle is not None:
            self._lifecycle.shutdown()

    def _touch(self, channel_id: str) -> None:
        """Reset the idle-close timer for ``channel_id`` when the watchdog is
        armed."""
        if self._lifecycle is not None:
            self._lifecycle.touch(channel_id)

    def _supports_mode(self, mode: SessionMode) -> bool:
        """Report whether the configured modes accept ``mode``; empty modes mean
        push-only. Checked before resolving the channel facts in an open."""
        modes = self._core.config.modes
        if not modes:
            return mode == "push"
        return mode in modes

    async def challenge(self, options: SessionChallengeOptions | None = None) -> PaymentChallenge:
        """Build the HMAC-bound 402 challenge embedding a ``SessionRequest``.

        The requested cap is clamped to the server maximum, ``min_voucher_delta``
        is included only when positive, ``modes`` are omitted when push-only,
        ``pull_voucher_strategy`` is included only when pull is offered, and a
        recent blockhash plus the current slot (``recentSlot``, the channel
        ``openSlot``) are prefetched (non-fatally) when a recent-state
        provider or an RPC client is configured.
        """
        if options is None:
            options = SessionChallengeOptions()
        cap_value = self._cap
        if options.cap != "":
            try:
                cap_value = _parse_session_u64(options.cap, "cap")
            except ValueError as exc:
                raise PaymentError(f"invalid requested cap: {exc}", code="invalid-payload") from exc
        request = self._core.build_challenge_request(cap_value)
        if options.description != "":
            request.description = options.description
        if options.external_id != "":
            request.external_id = options.external_id
        # Non-fatal: the client fetches its own blockhash when absent (recentSlot
        # is server-provided — the client derives the channel PDA from it and
        # never fetches the slot itself; both come from the same
        # getLatestBlockhash response). The provider wins over the RPC client so
        # hosts can stamp challenge state without enabling on-chain checks.
        blockhash: str | None = None
        recent_slot: int | None = None
        if self._recent_state_provider is not None:
            try:
                value = self._recent_state_provider()
            except Exception:  # noqa: BLE001 - provider failures are non-fatal at challenge time
                value = None
            if value is not None:
                blockhash, recent_slot = value
                if not isinstance(blockhash, str) or blockhash == "":
                    blockhash = None
                if isinstance(recent_slot, bool) or not isinstance(recent_slot, int) or recent_slot < 0:
                    recent_slot = None
        elif self._rpc is not None:
            blockhash, recent_slot = await _try_recent_blockhash_and_slot(self._rpc)
        if blockhash:
            request.recent_blockhash = blockhash
        if recent_slot is not None:
            request.recent_slot = recent_slot

        expires = options.expires or minutes(5)
        return PaymentChallenge.with_secret_key(
            secret_key=self._secret_key,
            realm=self._realm,
            method="solana",
            intent="session",
            request=PaymentChallenge.encode_request(request.to_dict()),
            expires=expires,
            description=options.description,
        )

    async def verify_credential(self, credential: PaymentCredential) -> Receipt:
        """Verify a session Authorization credential: Tier-1 HMAC and expiry, the
        Tier-2 pinned-field backstop, then dispatch on the payload action (open /
        voucher / commit / topUp / close).
        """
        challenge = PaymentChallenge(
            id=credential.challenge.id,
            realm=credential.challenge.realm,
            method=credential.challenge.method,
            intent=credential.challenge.intent,
            request=credential.challenge.request,
            expires=credential.challenge.expires,
            digest=credential.challenge.digest,
            opaque=credential.challenge.opaque,
        )
        if not challenge.verify(self._secret_key):
            raise ChallengeMismatchError()
        if challenge.is_expired():
            raise ChallengeExpiredError(f"challenge expired at {challenge.expires}")

        from solana_pay_kit.protocols.mpp.intents.session import SessionRequest

        request = SessionRequest.from_dict(challenge.decode_request())
        self._verify_pinned_session_fields(credential, request)

        try:
            action = SessionAction.from_dict(credential.payload)
        except Exception as exc:
            raise PaymentError(f"decode session action: {exc}", code="invalid-payload") from exc

        if action.open is not None:
            # Challenge-bound recentSlot sanity check: the server stamped the
            # challenge's recentSlot, so an open that claims a different one is
            # rejected here alongside the other pinned-field checks (the
            # attached transaction's own openSlot is bound in verify_open_tx).
            if (
                request.recent_slot is not None
                and action.open.recent_slot is not None
                and action.open.recent_slot != request.recent_slot
            ):
                raise PaymentError(
                    f"open payload recentSlot {action.open.recent_slot} does not match "
                    f"the challenge recentSlot {request.recent_slot}",
                    code="invalid-payload",
                )
            reference = await self._handle_open(action.open, challenge_recent_slot=request.recent_slot)
        elif action.voucher is not None:
            reference = await self._handle_voucher(action.voucher)
        elif action.commit is not None:
            reference = await self._handle_commit(action.commit)
        elif action.top_up is not None:
            reference = await self._handle_top_up(action.top_up)
        elif action.close is not None:
            reference = await self._handle_close(action.close)
        else:
            raise PaymentError("unknown session action", code="invalid-payload")

        external_id = request.external_id or ""
        return _success_receipt(reference, credential.challenge.id, external_id)

    async def handle(self, authorization: str | None, challenge_options: SessionChallengeOptions) -> SessionGateResult:
        """Framework-agnostic 402 session gate: verify an Authorization credential
        or answer 402 with a fresh challenge.

        When ``authorization`` is present it is parsed and verified; on success the
        result carries the receipt header and status 200. A
        :class:`~solana_pay_kit._paycore.errors.PaymentError` (or any other exception,
        mapped to ``invalid-payload``) falls through to a 402 carrying the
        ``WWW-Authenticate`` challenge built from ``challenge_options``. Mirrors
        the per-route gate a charge route gets for free from ``RequirePayment``.
        """
        error: PaymentError | None = None
        if authorization:
            try:
                receipt = await self.verify_credential(parse_authorization(authorization))
                return SessionGateResult(
                    ok=True,
                    status=200,
                    headers={PAYMENT_RECEIPT_HEADER: format_receipt(receipt)},
                    body=None,
                )
            except PaymentError as err:
                error = err
            except Exception as err:  # noqa: BLE001 (parse/framework errors map to 402)
                error = PaymentError(str(err), code="invalid-payload")
        problem = payment_required_response(
            str(error) if error else "Payment required",
            code=(error.code if error and error.code else "payment_invalid"),
            challenge_header=format_www_authenticate(await self.challenge(challenge_options)),
        )
        return SessionGateResult(
            ok=False,
            status=problem["status_code"],
            headers=problem["headers"],
            body=problem["body"],
        )

    def _verify_pinned_session_fields(self, credential: PaymentCredential, request: Any) -> None:
        """Tier-2 backstop for session credentials: after Tier-1 HMAC confirms
        the challenge was issued by this server, fields fixed at construction
        time are compared so a credential issued for a different
        method/intent/realm or for a different recipient/currency cannot reach
        the action handlers.
        """
        method_name = "solana"
        if credential.challenge.method != method_name:
            raise PaymentError(
                f"credential method '{credential.challenge.method}' does not match this server "
                f"(expected '{method_name}')",
                code="challenge-route-mismatch",
            )
        if credential.challenge.intent.lower() != "session":
            raise PaymentError(
                f"credential intent '{credential.challenge.intent}' is not a session",
                code="challenge-route-mismatch",
            )
        if credential.challenge.realm != self._realm:
            raise PaymentError(
                f"credential realm '{credential.challenge.realm}' does not match this server "
                f"(expected '{self._realm}')",
                code="challenge-route-mismatch",
            )
        if request.currency != self._currency:
            raise PaymentError(
                f"credential currency '{request.currency}' does not match this server (expected '{self._currency}')",
                code="challenge-route-mismatch",
            )
        if request.recipient != self._recipient:
            raise PaymentError(
                "credential recipient does not match this server",
                code="recipient-mismatch",
            )

    def _open_tx_expected(self, payload: OpenPayload, challenge_recent_slot: int | None = None) -> VerifyOpenTxExpected:
        """Build the on-chain open verification facts for a transaction-carrying
        open. Only the paths that attach a transaction call this, keeping the
        ``program_id`` pubkey parse (and its failure surface) off the
        trust-the-channel-id paths. ``challenge_recent_slot`` is the recentSlot
        the verified challenge was issued with; when present the attached
        transaction's own openSlot must equal it.
        """
        return VerifyOpenTxExpected(
            authorized_signer=payload.authorized_signer,
            currency=self._currency,
            recipient=self._recipient,
            network=self._network,
            max_cap=self._core.config.max_cap,
            operator=self._core.config.operator,
            program_id=(Pubkey.from_string(self._core.config.program_id) if self._core.config.program_id else None),
            recent_slot=challenge_recent_slot,
            recipients=[(split.recipient, split.bps) for split in self._core.config.splits],
        )

    @staticmethod
    def _validate_server_open_replay(state: ChannelState, payload: OpenPayload, verified: VerifyOpenTxResult) -> None:
        """Check that an already-recorded server open matches this replay."""
        channel_id = verified.channel_id
        if state.sealed:
            raise PaymentError(f"channel {channel_id} is already sealed", code="invalid-payload")
        if state.authorized_signer != payload.authorized_signer:
            raise PaymentError(
                f"channel {channel_id} already exists with a different authorized signer",
                code="invalid-payload",
            )
        if (
            state.deposit != verified.deposit
            or state.operator != verified.payer
            or state.open_slot != verified.open_slot
        ):
            raise PaymentError(
                f"channel {channel_id} already exists with different verified open facts",
                code="invalid-payload",
            )

    async def _claim_server_open_outbox(
        self, channel_id: str, prepared: PreparedTransaction, payload: OpenPayload, verified: VerifyOpenTxResult
    ) -> tuple[_ServerOpenOutbox, int | None]:
        """Atomically claim or recover a server-open signed transaction.

        The main channel record is created only after confirmation, so it cannot
        protect the check-then-broadcast gap across workers. This private
        outbox record does: it persists the exact signed wire before send and
        grants one short lease to broadcast it. A crashed owner can be taken
        over later, but only to submit the same transaction/signature.
        """
        outbox_key = _open_outbox_key(channel_id)
        owner = secrets.randbits(63) + 1
        now = int(time.time())
        owns_claim = False

        def claim(current: ChannelState | None) -> ChannelState:
            nonlocal owns_claim
            if current is None:
                owns_claim = True
                return ChannelState(
                    channel_id=outbox_key,
                    authorized_signer=payload.authorized_signer,
                    deposit=verified.deposit,
                    cumulative=_OPEN_OUTBOX_RECORD_VERSION,
                    open_slot=verified.open_slot,
                    settled_signature=prepared.signature,
                    highest_voucher_signature=base64.b64encode(prepared.wire).decode("ascii"),
                    operator=verified.payer,
                    close_requested_at=now + _OPEN_OUTBOX_LEASE_SECONDS,
                    next_delivery_sequence=owner,
                )

            persisted = _open_outbox_from_state(current, channel_id)
            if not _server_open_outbox_matches_verified(persisted, payload, verified):
                raise ValueError(f"server-open outbox for channel {channel_id} has different verified open facts")
            lease_expires_at = current.close_requested_at
            if lease_expires_at is None:
                raise ValueError(f"server-open outbox for channel {channel_id} is missing its lease")
            if lease_expires_at > now:
                return current.clone()

            # The previous owner may have crashed before or during send. A
            # takeover submits only the exact persisted transaction and its
            # verified facts, never values derived from a racing request.
            nxt = current.clone()
            nxt.next_delivery_sequence = owner
            nxt.close_requested_at = now + _OPEN_OUTBOX_LEASE_SECONDS
            owns_claim = True
            return nxt

        state = await self._core.store().update_channel(outbox_key, claim)
        return _open_outbox_from_state(state, channel_id), (owner if owns_claim else None)

    async def _discard_server_open_outbox(self, channel_id: str, signature: str, owner: int) -> None:
        """Best-effort cleanup after the active channel record is persisted."""
        outbox_key = _open_outbox_key(channel_id)
        try:
            state = await self._core.store().get_channel(outbox_key)
            if state is None or state.next_delivery_sequence != owner or state.settled_signature != signature:
                return
            await self._core.store().delete_channel(outbox_key)
        except Exception:
            logger.warning("failed to remove completed server-open outbox", extra={"channel_id": channel_id})

    async def _handle_open(self, payload: OpenPayload, challenge_recent_slot: int | None = None) -> str:
        """Process an open action: resolve the channel facts, enforce the deposit
        invariants, and insert the channel state atomically and idempotently.

        Three submitter paths, selected by transaction presence then submitter:

        - a ``transaction`` is attached with ``openTxSubmitter=server``: the
          server completes the fee-payer signature and broadcasts the open
          (requires a signer + RPC), then persists.
        - a ``transaction`` is attached with ``openTxSubmitter=client``: it is
          validated against the challenge (structural always; on-chain liveness
          when an RPC client is configured) before persisting.
        - no ``transaction`` is attached: the client asserts a previously
          broadcast open (push) or a server-opened pull channel; the open
          signature is confirmed on-chain when an RPC is present (push only),
          otherwise the channel id / token account and deposit are trusted as
          provided. The server-broadcast path is skipped even when
          ``openTxSubmitter=server`` is configured, so a pull open with no
          transaction is never hard-rejected for a missing transaction.

        The receipt reference is the open signature when one exists, else the
        channel id.
        """
        mode = payload.mode
        if not self._supports_mode(mode):
            raise PaymentError(f"session mode {mode!r} is not supported by this challenge", code="invalid-payload")
        if mode == "pull" and self._core.config.pull_voucher_strategy is None:
            raise PaymentError(
                "pull-mode open requires a pullVoucherStrategy on the server config",
                code="invalid-config",
            )

        # Empty strings count as missing.
        has_transaction = payload.transaction is not None and payload.transaction != ""
        has_channel_id = payload.channel_id is not None and payload.channel_id != ""

        # A push open must carry a transaction or a channel id. A pull open may
        # carry a transaction (a clientVoucher payment-channel open, server- or
        # client-broadcast) or carry only the channel id / token account (a
        # server-opened pull). This mirrors the TS open dispatch
        # ``if (payload.transaction) { ... } else if (mode === 'push') { ... } else
        # { ... }``: the server-broadcast path is entered only when a transaction
        # is attached, so a pull open with no transaction falls through to the
        # trust-the-channel-id path instead of being hard-rejected by
        # verify_open_tx's transaction requirement (which would make every
        # pull-mode open against an ``openTxSubmitter=server`` server fail).
        if mode == "push" and not has_transaction and not has_channel_id:
            raise PaymentError("open payload missing transaction or channelId", code="invalid-payload")

        server_open_outbox_owner: tuple[str, str, int] | None = None
        if has_transaction and self._open_tx_submitter == OPEN_TX_SUBMITTER_SERVER:
            if self._signer is None or self._rpc is None:
                raise PaymentError(
                    "openTxSubmitter=server requires a signer and an RPC client",
                    code="invalid-config",
                )
            # Decode before claiming so the durable key is the authoritative
            # PDA, not an attacker-controlled payload field. The server is the
            # sole path allowed to receive a placeholder fee-payer signature.
            expected = self._open_tx_expected(payload, challenge_recent_slot)
            try:
                verified = await verify_open_tx(expected, payload, None, allow_fee_payer_placeholder=True)
                prepared = complete_open_transaction(payload, self._signer.keypair)
            except PaymentError:
                raise
            except Exception as exc:
                raise PaymentError(f"server-broadcast open preparation failed: {exc}", code="invalid-payload") from exc

            payload.payer = verified.payer
            payload.deposit = str(verified.deposit)
            payload.recent_slot = verified.open_slot
            channel_id = verified.channel_id
            payload.channel_id = channel_id

            existing = await self._core.store().get_channel(channel_id)
            if existing is not None:
                self._validate_server_open_replay(existing, payload, verified)
                self._touch(channel_id)
                return prepared.signature

            try:
                outbox, owner = await self._claim_server_open_outbox(channel_id, prepared, payload, verified)
            except ValueError as exc:
                raise PaymentError(str(exc), code="invalid-payload") from exc

            existing = await self._core.store().get_channel(channel_id)
            if existing is not None:
                self._validate_server_open_replay(existing, payload, verified)
                self._touch(channel_id)
                return outbox.prepared.signature
            if owner is None:
                raise PaymentError(
                    f"server-broadcast open for channel {channel_id} is already in progress",
                    code="invalid-payload",
                    retryable=True,
                )

            try:
                await broadcast_prepared_transaction(outbox.prepared, rpc=self._rpc, label="open")
            except BaseException:
                # The signed wire is already durable. Retain it on every
                # ambiguous failure or cancellation so a later lease owner can
                # retry this exact transaction rather than make a new one.
                raise

            # Process exactly the transaction and verified facts that the
            # outbox has durably bound together, including after lease takeover.
            payload.authorized_signer = outbox.authorized_signer
            payload.payer = outbox.payer
            payload.deposit = str(outbox.deposit)
            payload.recent_slot = outbox.open_slot
            payload.transaction = base64.b64encode(outbox.prepared.wire).decode("ascii")
            payload.signature = outbox.prepared.signature
            server_open_outbox_owner = (channel_id, outbox.prepared.signature, owner)
        elif has_transaction:
            expected = self._open_tx_expected(payload, challenge_recent_slot)
            try:
                verified = await verify_open_tx(expected, payload, self._rpc)
            except PaymentError:
                raise
            except Exception as exc:
                raise PaymentError(f"open transaction verification failed: {exc}", code="invalid-payload") from exc
            # Propagate the on-chain payer (open account slot 0) so process_open
            # records state.operator when the attached transaction is the source
            # of truth. Without it, settle-at-close refunds the unspent balance
            # to the recipient's ATA instead of the channel opener's. The
            # verified openSlot is propagated the same way so it is persisted.
            if not payload.payer:
                payload.payer = verified.payer
            payload.deposit = str(verified.deposit)
            payload.recent_slot = verified.open_slot
        elif mode == "push" and self._signer is not None and self._rpc is not None and not payload.payer:
            raise PaymentError(
                "push open requires payer or transaction when settle-at-close is configured",
                code="invalid-payload",
            )
        elif mode == "push" and self._rpc is not None:
            await confirm_transaction_signature(self._rpc, payload.signature, "open")
        # else: no transaction is attached. Reachable by a pull open (the channel
        # id / token account and deposit are trusted as provided, mirroring the TS
        # `else` branch) or by a push open with a channel id and no RPC (trusted
        # as previously broadcast). The server-broadcast path is skipped even when
        # openTxSubmitter=server is configured.

        try:
            state = await self._core.process_open(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        self._touch(state.channel_id)
        if server_open_outbox_owner is not None:
            await self._discard_server_open_outbox(*server_open_outbox_owner)
        if payload.signature != "":
            return payload.signature
        return state.channel_id

    async def _handle_voucher(self, payload: VoucherPayload) -> str:
        """Verify a cumulative voucher and advance the watermark. The receipt
        reference is "<channelId>:<cumulative>"."""
        channel_id = payload.voucher.data.channel_id
        try:
            cumulative = await self._core.verify_voucher(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        self._touch(channel_id)
        return f"{channel_id}:{cumulative}"

    async def _handle_commit(self, payload: CommitPayload) -> str:
        """Commit a reserved metered delivery. The receipt reference is
        "<sessionId>:<deliveryId>:<cumulative>"."""
        try:
            receipt = await self._core.process_commit(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        self._touch(receipt.session_id)
        return f"{receipt.session_id}:{receipt.delivery_id}:{receipt.cumulative}"

    async def _handle_top_up(self, payload: TopUpPayload) -> str:
        """Raise a channel's deposit after optional confirmed-transaction
        value binding. The receipt reference is the top-up transaction signature."""
        try:
            new_deposit = _parse_session_u64(payload.new_deposit, "newDeposit")
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        if new_deposit > self._cap:
            raise PaymentError(f"newDeposit {new_deposit} exceeds cap {self._cap}", code="invalid-payload")

        # Cheap store pre-checks before touching the network.
        existing = await self._core.store().get_channel(payload.channel_id)
        if existing is None:
            raise PaymentError(f"channel {payload.channel_id} not found", code="invalid-payload")
        if existing.sealed:
            raise PaymentError(f"channel {payload.channel_id} is already sealed", code="invalid-payload")
        if existing.close_requested_at is not None:
            raise PaymentError(
                f"channel {payload.channel_id} close is pending; no further top-ups accepted",
                code="invalid-payload",
            )
        try:
            await self._core.process_top_up(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        self._touch(payload.channel_id)
        return payload.signature

    async def _handle_close(self, payload: ClosePayload) -> str:
        """Accept the optional final voucher and flip close-pending atomically.
        The receipt reference is the channel id (the on-chain settlement path is
        not implemented here).

        Unlike :meth:`SessionServer.process_close`, the close here is
        re-drivable. A prior pre-broadcast failure may be retried, while a
        prior broadcast is reconciled using its persisted signature before any
        caller can build another settlement transaction. The fund-safety final
        voucher validation is unchanged from the core path.
        """
        import time

        from solana_pay_kit.protocols.mpp.server.session import _parse_u64
        from solana_pay_kit.protocols.mpp.server.session_voucher import verify_session_voucher

        channel_id = payload.channel_id
        now = int(time.time())
        voucher = payload.voucher

        def mutator(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise ValueError(f"channel {channel_id} not found")
            if current.sealed:
                raise ValueError(f"channel {channel_id} is already sealed")
            if current.close_requested_at is not None:
                if current.settled_signature is not None and (self._signer is None or self._rpc is None):
                    # A persisted broadcast can only be retried through the
                    # reconciliation path. Never acknowledge it as closed when
                    # this instance cannot confirm the recorded signature.
                    raise ValueError("close already requested")
                # Re-drive failed pre-broadcast closes and reconcile an
                # already-broadcast signature. A sealed channel was rejected
                # above; the settlement state machine decides whether this
                # caller can proceed or must receive a retryable failure.
                return current.clone()

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
                    # Recheck expiry/window even on idempotent replay so the HTTP
                    # close path doesn't record close-pending against a voucher that
                    # no longer outlasts the settlement window (mirrors process_close).
                    err = verify_session_voucher(
                        voucher, current.authorized_signer, self._core.config.settlement_window
                    )
                    if err is not None:
                        raise ValueError(err)
                    if nxt.highest_voucher_expires_at is None:
                        nxt.highest_voucher_expires_at = voucher.data.expires_at
                else:
                    if cumulative > current.deposit:
                        raise ValueError("final voucher exceeds deposit")
                    err = verify_session_voucher(
                        voucher, current.authorized_signer, self._core.config.settlement_window
                    )
                    if err is not None:
                        raise ValueError(err)
                    nxt.cumulative = cumulative
                    nxt.highest_voucher_signature = voucher.signature
                    nxt.highest_voucher_expires_at = voucher.data.expires_at
            nxt.close_requested_at = now
            return nxt

        try:
            await self._core.store().update_channel(channel_id, mutator)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        if self._lifecycle is not None:
            self._lifecycle.remove_channel(payload.channel_id)
        settled = await self._settle_channel(channel_id)
        # On a successful settle the reference is the on-chain signature; without
        # a signer/RPC the close is a state-flip and the channel id stands in.
        return settled or payload.channel_id

    async def _settle_channel(self, channel_id: str) -> str | None:
        """Settle once, persist intent before send, and reconcile ambiguity."""
        if self._signer is None or self._rpc is None:
            return None

        claimed = False
        reconcile_signature: str | None = None

        def claim(current: ChannelState | None) -> ChannelState:
            nonlocal claimed, reconcile_signature
            if current is None:
                raise ValueError(f"channel {channel_id} disappeared during settle-claim")
            status = _settlement_status(current)
            if status.phase is _SettlementPhase.SEALED:
                raise _AlreadySealed(status.signature)
            if status.phase is _SettlementPhase.AWAITING_CONFIRMATION:
                # A durable signature is an immutable settlement intent. It
                # may be reconciled by multiple callers, but never replaced.
                reconcile_signature = status.signature
                claimed = True
                return current.clone()
            if status.phase is _SettlementPhase.IN_PROGRESS:
                raise _AlreadySettling()
            nxt = current.clone()
            nxt.settling = True
            claimed = True
            return nxt

        try:
            state = await self._core.store().update_channel(channel_id, claim)
        except _AlreadySealed as exc:
            return exc.signature
        except _AlreadySettling:
            raise PaymentError(
                f"channel {channel_id} settlement is already in progress",
                code="invalid-payload",
                retryable=True,
            ) from None

        if not claimed:
            return None

        async def release_prebroadcast_claim() -> None:
            def release(current: ChannelState | None) -> ChannelState:
                if current is None:
                    raise ValueError(f"channel {channel_id} disappeared while releasing settle-claim")
                if current.sealed or current.settled_signature is not None:
                    return current
                nxt = current.clone()
                nxt.settling = False
                return nxt

            await _finish_store_update(self._core.store().update_channel(channel_id, release))

        async def retire_failed_intent(signature: str) -> None:
            def release(current: ChannelState | None) -> ChannelState:
                if current is None:
                    raise ValueError(f"channel {channel_id} disappeared while retiring settlement intent")
                if current.sealed or current.settled_signature != signature:
                    return current
                nxt = current.clone()
                nxt.settling = False
                nxt.settled_signature = None
                return nxt

            await self._core.store().update_channel(channel_id, release)

        async def seal(signature: str) -> str:
            def mark_sealed(current: ChannelState | None) -> ChannelState:
                if current is None:
                    raise ValueError(f"channel {channel_id} disappeared during settle")
                if current.sealed:
                    return current
                if current.settled_signature != signature:
                    raise ValueError(f"channel {channel_id} settlement signature changed during confirmation")
                nxt = current.clone()
                nxt.sealed = True
                nxt.settled_signature = signature
                nxt.settling = False
                return nxt

            await self._core.store().update_channel(channel_id, mark_sealed)
            return signature

        if reconcile_signature is not None:
            try:
                await confirm_transaction_signature(
                    self._rpc,
                    reconcile_signature,
                    "settle",
                    search_transaction_history=True,
                )
            except PaymentError as exc:
                # Only a confirmed execution failure proves that a fresh
                # settlement is safe. Timeouts and transport failures keep the
                # claim and deterministic signature for later reconciliation.
                if exc.code == "transaction-failed":
                    await retire_failed_intent(reconcile_signature)
                raise
            return await seal(reconcile_signature)

        intent_signature: str | None = None
        intent_persisted = False

        async def persist_intent(prepared: PreparedTransaction) -> None:
            nonlocal intent_persisted, intent_signature
            intent_signature = prepared.signature

            def persist(current: ChannelState | None) -> ChannelState:
                if current is None:
                    raise ValueError(f"channel {channel_id} disappeared before settlement broadcast")
                if current.sealed:
                    return current
                if not current.settling:
                    raise ValueError(f"channel {channel_id} settle claim was released before intent persistence")
                if current.settled_signature not in (None, prepared.signature):
                    raise ValueError(f"channel {channel_id} settlement signature changed before broadcast")
                nxt = current.clone()
                nxt.settled_signature = prepared.signature
                return nxt

            # Finish persistence despite cancellation before propagating it.
            # From this point a send may have happened, so the claim must stay.
            cancelled = await _finish_store_update(self._core.store().update_channel(channel_id, persist))
            intent_persisted = True
            if cancelled:
                raise asyncio.CancelledError

        try:
            signature = await settle_and_seal_channel(
                state,
                merchant=self._signer.keypair,
                rpc=self._rpc,
                config=self._core.config,
                on_prepared=persist_intent,
            )
        except BaseException as exc:
            if not intent_persisted:
                await release_prebroadcast_claim()
            elif isinstance(exc, PaymentError) and exc.code == "transaction-failed" and intent_signature is not None:
                await retire_failed_intent(intent_signature)
            # All other post-intent failures are ambiguous. Keep the claim and
            # signature so a retry can query transaction history instead of
            # issuing a second settlement.
            raise
        return await seal(signature)

    async def _close_on_idle(self, channel_id: str) -> None:
        """Idle-close watchdog handler: close the channel and settle on-chain.

        The close state-flip always runs so the idle timeout takes effect even
        without a signer/RPC (e.g. the playground); only the on-chain settle in
        ``_settle_channel`` is gated on the signer/RPC pair. A transient failure
        is swallowed (logged) so it cannot crash the timer, and the channel stays
        re-drivable with ``settledSignature`` unset.
        """
        try:
            await self._handle_close(ClosePayload(channel_id=channel_id, voucher=None))
        except Exception:
            logging.getLogger(__name__).warning("idle-close settle failed for channel %s", channel_id, exc_info=True)
        return None


def new_session(options: SessionOptions) -> Session:
    """Create the server-side session method."""
    if options.cap == 0:
        raise PaymentError("cap must be positive", code="invalid-config")
    if options.recipient == "":
        raise PaymentError("recipient is required", code="invalid-config")
    try:
        Pubkey.from_string(options.recipient)
    except (ValueError, TypeError) as exc:
        raise PaymentError(f"invalid recipient pubkey: {exc}", code="invalid-config") from exc
    if len(options.splits) > MAX_SPLITS:
        raise PaymentError(f"splits cannot exceed {MAX_SPLITS} entries", code="invalid-config")
    split_recipients: set[str] = set()
    total_split_bps = 0
    for index, split in enumerate(options.splits):
        try:
            canonical_recipient = str(Pubkey.from_string(split.recipient))
        except (ValueError, TypeError) as exc:
            raise PaymentError(f"splits[{index}] has invalid recipient pubkey: {exc}", code="invalid-config") from exc
        if split.bps <= 0:
            raise PaymentError(f"splits[{index}] bps must be positive", code="invalid-config")
        total_split_bps += split.bps
        if total_split_bps > 10_000:
            raise PaymentError("split bps total cannot exceed 10000", code="invalid-config")
        if canonical_recipient in split_recipients:
            raise PaymentError(f"splits[{index}] duplicates recipient {canonical_recipient}", code="invalid-config")
        split_recipients.add(canonical_recipient)

    if options.signer is not None and options.rpc is not None:
        _require_account_info_rpc(options.rpc)

    secret_key = options.secret_key
    if secret_key == "":
        secret_key = os.environ.get(_SECRET_KEY_ENV_VAR, "")
    if secret_key == "":
        raise PaymentError("missing secret key", code="invalid-config")

    raw_network = options.network or "mainnet"
    try:
        validate_network(raw_network)
    except ValueError as exc:
        raise PaymentError(str(exc), code="invalid-config") from exc
    network = _canonical_network(raw_network)
    currency = options.currency or "USDC"
    decimals = options.decimals or 6
    realm = options.realm or detect_realm()

    open_tx_submitter = options.open_tx_submitter
    if open_tx_submitter == "":
        open_tx_submitter = OPEN_TX_SUBMITTER_CLIENT
    elif open_tx_submitter not in (OPEN_TX_SUBMITTER_CLIENT, OPEN_TX_SUBMITTER_SERVER):
        raise PaymentError(
            f"openTxSubmitter must be '{OPEN_TX_SUBMITTER_CLIENT}' or '{OPEN_TX_SUBMITTER_SERVER}', "
            f"got '{open_tx_submitter}'",
            code="invalid-config",
        )

    supports_pull = any(mode == "pull" for mode in options.modes)
    if supports_pull and options.pull_voucher_strategy is None:
        raise PaymentError(
            "pullVoucherStrategy is required when modes includes pull",
            code="invalid-config",
        )

    uses_memory_store = options.store is None or isinstance(options.store, MemoryChannelStore)
    allows_devnet_memory_store = network == "devnet" and os.getenv(_ALLOW_INMEMORY_REPLAY_STORE_ENV) == "1"
    if uses_memory_store and network != "localnet" and not allows_devnet_memory_store:
        raise PaymentError(
            "a durable channel store is required outside localnet; set "
            f"{_ALLOW_INMEMORY_REPLAY_STORE_ENV}=1 to explicitly allow a process-local "
            "MemoryChannelStore only for devnet development",
            code="invalid-config",
        )

    store = options.store if options.store is not None else MemoryChannelStore()

    config = SessionConfig(
        operator=options.operator,
        recipient=options.recipient,
        splits=options.splits,
        max_cap=options.cap,
        currency=currency,
        decimals=decimals,
        network=network,
        program_id=None if options.program_id is None else str(options.program_id),
        min_voucher_delta=options.min_voucher_delta,
        modes=options.modes,
        pull_voucher_strategy=options.pull_voucher_strategy,
    )
    # Open verification remains in the method layer because server-broadcast
    # opens need request-specific signing. Top-ups use the state-aware core
    # seam so it can bind the confirmed transaction's delta to the exact
    # channel snapshot and recheck that snapshot atomically after the RPC await.
    config.verify_top_up_state_tx = new_top_up_state_tx_verifier(config, options.rpc)
    core = SessionServer(config, store)
    session = Session(
        core=core,
        secret_key=secret_key,
        realm=realm,
        cap=options.cap,
        currency=currency,
        recipient=options.recipient,
        network=network,
        open_tx_submitter=open_tx_submitter,
        rpc=options.rpc,
        lifecycle=None,
        signer=options.signer,
        recent_state_provider=options.recent_state_provider,
    )
    if options.close_delay > 0:
        session._lifecycle = SessionLifecycle(session._close_on_idle, options.close_delay)
    return session
