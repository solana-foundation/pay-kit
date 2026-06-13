"""HTTP-facing MPP session method handler.

A :class:`Session` issues HMAC-bound 402 challenges carrying a
:class:`~pay_kit.protocols.mpp.intents.session.SessionRequest`
(:meth:`Session.challenge`), verifies Authorization credentials whose payload is
one of the five session actions (:meth:`Session.verify_credential` dispatching
to open / voucher / commit / topUp / close), and drives the channel lifecycle by
composing the lower-level building blocks: the :class:`SessionServer` core, the
:class:`ChannelStore`, the voucher verifier, the on-chain verifier seams, and
the idle-close watchdog.

Ports the offline-core surface of ``go/protocols/mpp/server/session_method.go``
(snake_case of the Go names); the field semantics are pinned by
``rust/crates/mpp/src/server/session.rs``.

Trust model / on-chain seam: exactly as in the Go port, the RPC client is
optional. With no RPC client the transaction signature and deposit amount are
trusted as provided (offline core); with an RPC client an open's confirmation
signature is checked on-chain before the channel is persisted, and a top-up
signature is confirmed before the deposit is raised. The on-chain check is wired
through the :class:`SessionServer` config seams
(:func:`~pay_kit.protocols.mpp.server.session_onchain.new_open_tx_verifier` /
:func:`~pay_kit.protocols.mpp.server.session_onchain.new_top_up_tx_verifier`),
matching how the Python on-chain layer composes verification.

Not ported here (their lower-level Python building blocks do not yet exist): the
server-broadcast open path (``OpenTxSubmitterServer`` / ``SubmitOpenTx``), the
on-chain settlement at close (``closeAndSettleChannel`` /
``SettlementInstructions``), and the metering side-channel HTTP routes
(``SessionRoutes``). The idle-close watchdog is wired but, without a settlement
path, its handler is a no-op when no RPC settlement is configured, exactly as
the Go ``closeOnIdle`` returns early when no signer/RPC is set.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from pay_kit._paycore.errors import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    PaymentError,
)
from pay_kit._paycore.solana import MAX_SPLITS
from pay_kit.protocols.mpp.core.expires import minutes
from pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential, Receipt
from pay_kit.protocols.mpp.intents.session import (
    ClosePayload,
    CommitPayload,
    OpenPayload,
    SessionAction,
    SessionMode,
    SessionPullVoucherStrategy,
    TopUpPayload,
    VoucherPayload,
)
from pay_kit.protocols.mpp.server.defaults import detect_realm
from pay_kit.protocols.mpp.server.session import SessionConfig, SessionServer, Split
from pay_kit.protocols.mpp.server.session_lifecycle import SessionLifecycle
from pay_kit.protocols.mpp.server.session_onchain import (
    RpcClient,
    confirm_transaction_signature,
)
from pay_kit.protocols.mpp.server.session_store import ChannelStore, MemoryChannelStore

logger = logging.getLogger(__name__)

_SECRET_KEY_ENV_VAR = "MPP_SECRET_KEY"
_U64_MAX = (1 << 64) - 1

__all__ = [
    "OpenTxSubmitter",
    "SessionOptions",
    "SessionChallengeOptions",
    "Session",
    "new_session",
]


# OpenTxSubmitter selects who broadcasts a push-mode payment-channel open
# transaction. Mirrors Go ``OpenTxSubmitter``.
OpenTxSubmitter = str

# The client broadcasts the open transaction itself and the server only verifies
# it. Default. Mirrors Go ``OpenTxSubmitterClient``.
OPEN_TX_SUBMITTER_CLIENT: OpenTxSubmitter = "client"

# The server completes the fee-payer signature, broadcasts the client-built open
# transaction, and waits for confirmation before persisting channel state.
# Mirrors Go ``OpenTxSubmitterServer``.
OPEN_TX_SUBMITTER_SERVER: OpenTxSubmitter = "server"


@dataclass
class SessionOptions:
    """Options for :func:`new_session`. Mirrors Go ``SessionOptions``."""

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
    # Store is the pluggable channel store. Defaults to in-memory.
    store: ChannelStore | None = None
    # RPC is the optional RPC client used for on-chain checks. None skips every
    # on-chain check and trusts payload claims as provided.
    rpc: RpcClient | None = None


@dataclass
class SessionChallengeOptions:
    """Customize a single 402 session challenge. Mirrors Go
    ``SessionChallengeOptions``."""

    # Cap is the requested session cap (base units, decimal string). Empty uses
    # the server maximum; larger requests are clamped to it.
    cap: str = ""
    # Description is a human-readable challenge description.
    description: str = ""
    # ExternalID is a merchant reference id echoed on the receipt.
    external_id: str = ""
    # Expires is the challenge expiry (RFC 3339). Default five minutes.
    expires: str = ""


def _parse_session_u64(value: str, name: str) -> int:
    """Parse a non-negative decimal string into a u64, naming the field on
    error. Mirrors Go ``parseSessionU64``."""
    if not (value.isascii() and value.isdigit()):
        raise ValueError(f"{name} is not an unsigned integer string: {value}")
    parsed = int(value, 10)
    if parsed > _U64_MAX:
        raise ValueError(f"{name} is not an unsigned integer string: {value}")
    return parsed


async def _try_recent_blockhash(rpc: Any) -> str | None:
    """Best-effort fetch of a recent blockhash from the injected RPC client.

    Returns the blockhash string on success or ``None`` on any error/absence;
    the prefetch is non-fatal because the client fetches its own blockhash when
    the challenge omits one. Mirrors the non-fatal ``GetLatestBlockhash`` branch
    in Go ``Challenge``.
    """
    getter: Any = getattr(rpc, "get_latest_blockhash", None)
    if not callable(getter):
        return None
    try:
        pending: Any = getter("confirmed")
        out = await pending
    except Exception:
        return None
    value: Any = getattr(out, "value", None)
    blockhash: Any = getattr(value, "blockhash", None)
    if isinstance(blockhash, str) and blockhash:
        return blockhash
    return None


def _success_receipt(reference: str, challenge_id: str, external_id: str) -> Receipt:
    """Build a success receipt for a session action. Mirrors Go
    ``successReceipt``."""
    return Receipt.success(
        method="solana",
        reference=reference,
        challenge_id=challenge_id,
        external_id=external_id,
    )


class Session:
    """The server-side session method handler. Create with :func:`new_session`.

    Mirrors Go ``Session``.
    """

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
        # lifecycle is the idle-close watchdog; None when close_delay is zero.
        self._lifecycle = lifecycle

    def core(self) -> SessionServer:
        """Return the underlying :class:`SessionServer` so hosts can reach the
        channel store and the lower-level lifecycle methods. Mirrors Go
        ``Core``."""
        return self._core

    def shutdown(self) -> None:
        """Cancel the idle-close watchdog timers. Hosts should call it when
        tearing the session method down. Mirrors Go ``Shutdown``."""
        if self._lifecycle is not None:
            self._lifecycle.shutdown()

    def _touch(self, channel_id: str) -> None:
        """Reset the idle-close timer for ``channel_id`` when the watchdog is
        armed. Mirrors Go ``touch``."""
        if self._lifecycle is not None:
            self._lifecycle.touch(channel_id)

    def _supports_mode(self, mode: SessionMode) -> bool:
        """Report whether the configured modes accept ``mode``; empty modes mean
        push-only. Mirrors the ``core.supportsMode`` check the Go ``handleOpen``
        runs before resolving the channel facts."""
        modes = self._core.config.modes
        if not modes:
            return mode == "push"
        return mode in modes

    async def challenge(self, options: SessionChallengeOptions | None = None) -> PaymentChallenge:
        """Build the HMAC-bound 402 challenge embedding a ``SessionRequest``.

        The requested cap is clamped to the server maximum, ``min_voucher_delta``
        is included only when positive, ``modes`` are omitted when push-only,
        ``pull_voucher_strategy`` is included only when pull is offered, and a
        recent blockhash is prefetched (non-fatally) when an RPC client is
        configured. Mirrors Go ``Challenge``.
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
        if self._rpc is not None:
            # Non-fatal: the client fetches its own blockhash when absent. The
            # blockhash source is the injected RPC client, so unit tests stay
            # offline.
            blockhash = await _try_recent_blockhash(self._rpc)
            if blockhash:
                request.recent_blockhash = blockhash

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
        voucher / commit / topUp / close). Mirrors Go ``VerifyCredential``.
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

        from pay_kit.protocols.mpp.intents.session import SessionRequest

        request = SessionRequest.from_dict(challenge.decode_request())
        self._verify_pinned_session_fields(credential, request)

        try:
            action = SessionAction.from_dict(credential.payload)
        except Exception as exc:
            raise PaymentError(f"decode session action: {exc}", code="invalid-payload") from exc

        if action.open is not None:
            reference = await self._handle_open(action.open)
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

    def _verify_pinned_session_fields(self, credential: PaymentCredential, request: Any) -> None:
        """Tier-2 backstop for session credentials: after Tier-1 HMAC confirms
        the challenge was issued by this server, fields fixed at construction
        time are compared so a credential issued for a different
        method/intent/realm or for a different recipient/currency cannot reach
        the action handlers. Mirrors Go ``verifyPinnedSessionFields``.
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

    async def _handle_open(self, payload: OpenPayload) -> str:
        """Process an open action: resolve the channel facts, enforce the deposit
        invariants, and insert the channel state atomically and idempotently. The
        receipt reference is the open signature when one exists, else the channel
        id. Mirrors the trusted / client-broadcast path of Go ``handleOpen``.
        """
        if self._open_tx_submitter == OPEN_TX_SUBMITTER_SERVER:
            # The server-broadcast open requires the SubmitOpenTx building block,
            # which is not yet ported to Python.
            raise PaymentError(
                "openTxSubmitter=server is not supported by this port",
                code="invalid-config",
            )

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

        if has_transaction:
            # Payment-channel-backed open verification needs the on-chain open-tx
            # verifier seam, which decodes and binds the attached transaction.
            # That path lands with the on-chain settlement port.
            raise PaymentError(
                "open with an attached transaction is not supported by this port",
                code="invalid-payload",
            )
        if mode == "push" and not has_channel_id:
            raise PaymentError("open payload missing transaction or channelId", code="invalid-payload")

        # No transaction in the payload: the client asserts a previously
        # broadcast open. With an RPC client the open signature is confirmed
        # on-chain before persisting; without one the channelId/deposit fields
        # are trusted as-is. (Pull mode without a tx trusts the
        # channelId/tokenAccount + approvedAmount.)
        if mode == "push" and self._rpc is not None:
            await confirm_transaction_signature(self._rpc, payload.signature, "open")

        try:
            state = await self._core.process_open(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        self._touch(state.channel_id)
        if payload.signature != "":
            return payload.signature
        return state.channel_id

    async def _handle_voucher(self, payload: VoucherPayload) -> str:
        """Verify a cumulative voucher and advance the watermark. The receipt
        reference is "<channelId>:<cumulative>". Mirrors Go ``handleVoucher``."""
        channel_id = payload.voucher.data.channel_id
        try:
            cumulative = await self._core.verify_voucher(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        self._touch(channel_id)
        return f"{channel_id}:{cumulative}"

    async def _handle_commit(self, payload: CommitPayload) -> str:
        """Commit a reserved metered delivery. The receipt reference is
        "<sessionId>:<deliveryId>:<cumulative>". Mirrors Go ``handleCommit``."""
        try:
            receipt = await self._core.process_commit(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        self._touch(receipt.session_id)
        return f"{receipt.session_id}:{receipt.delivery_id}:{receipt.cumulative}"

    async def _handle_top_up(self, payload: TopUpPayload) -> str:
        """Raise a channel's deposit after optional on-chain confirmation of the
        top-up signature. The receipt reference is the top-up transaction
        signature. Mirrors Go ``handleTopUp``."""
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
        if existing.finalized:
            raise PaymentError(f"channel {payload.channel_id} is already finalized", code="invalid-payload")
        if existing.close_requested_at is not None:
            raise PaymentError(
                f"channel {payload.channel_id} close is pending; no further top-ups accepted",
                code="invalid-payload",
            )
        if self._rpc is not None:
            await confirm_transaction_signature(self._rpc, payload.signature, "topUp")
        try:
            await self._core.process_top_up(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        self._touch(payload.channel_id)
        return payload.signature

    async def _handle_close(self, payload: ClosePayload) -> str:
        """Accept the optional final voucher and flip close-pending atomically.
        The receipt reference is the channel id (the on-chain settlement path is
        not ported). Mirrors Go ``handleClose``.

        Unlike :meth:`SessionServer.process_close`, where a second close is
        always rejected, the close here is re-drivable: when a prior close
        flipped the close-pending flag but settlement never recorded a signature
        (``settled_signature is None``), the retry proceeds so a transient
        settlement failure cannot strand the channel. A close-pending channel
        that already recorded a settled signature is not re-drivable and
        hard-rejects with "close already requested". The fund-safety final
        voucher validation is unchanged from the core path.
        """
        import time

        from pay_kit.protocols.mpp.server.session import _parse_u64
        from pay_kit.protocols.mpp.server.session_store import ChannelState
        from pay_kit.protocols.mpp.server.session_voucher import verify_session_voucher

        channel_id = payload.channel_id
        now = int(time.time())
        voucher = payload.voucher

        def mutator(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise ValueError(f"channel {channel_id} not found")
            if current.finalized:
                raise ValueError(f"channel {channel_id} is already finalized")
            if current.close_requested_at is not None:
                if current.settled_signature is None:
                    # Re-drivable close: leave state untouched and let the
                    # settlement retry proceed.
                    return current.clone()
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
                    if nxt.highest_voucher_expires_at is None:
                        nxt.highest_voucher_expires_at = voucher.data.expires_at
                else:
                    if cumulative > current.deposit:
                        raise ValueError("final voucher exceeds deposit")
                    err = verify_session_voucher(voucher, current.authorized_signer)
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
        reference = payload.channel_id
        if self._lifecycle is not None:
            self._lifecycle.remove_channel(payload.channel_id)
        return reference

    async def _close_on_idle(self, channel_id: str) -> None:
        """Idle-close watchdog handler. Without a ported on-chain settlement
        path there is nothing to broadcast, so this is a no-op, exactly as the
        Go ``closeOnIdle`` returns early when no signer/RPC is configured.
        """
        return None


def new_session(options: SessionOptions) -> Session:
    """Create the server-side session method. Mirrors Go ``NewSession``."""
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

    secret_key = options.secret_key
    if secret_key == "":
        import os

        secret_key = os.environ.get(_SECRET_KEY_ENV_VAR, "")
    if secret_key == "":
        raise PaymentError("missing secret key", code="invalid-config")

    currency = options.currency or "USDC"
    decimals = options.decimals or 6
    network = options.network or "mainnet"
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
    # The method layer performs the optional on-chain liveness confirm inline in
    # its open / topUp handlers (mirroring Go's NewSession, which leaves the core
    # SessionConfig verifier seams unset and confirms in the method), so the core
    # is left to trust payload claims; the seam stays available for hosts that
    # drive the lower-level SessionServer directly.
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
    )
    if options.close_delay > 0:
        session._lifecycle = SessionLifecycle(session._close_on_idle, options.close_delay)
    return session
