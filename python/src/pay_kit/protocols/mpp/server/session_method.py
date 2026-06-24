"""HTTP-facing MPP session method handler.

A :class:`Session` issues HMAC-bound 402 challenges carrying a
:class:`~pay_kit.protocols.mpp.intents.session.SessionRequest`
(:meth:`Session.challenge`), verifies Authorization credentials whose payload is
one of the five session actions (:meth:`Session.verify_credential` dispatching
to open / voucher / commit / topUp / close), and drives the channel lifecycle by
composing the lower-level building blocks: the :class:`SessionServer` core, the
:class:`ChannelStore`, the voucher verifier, the on-chain verifier seams, and
the idle-close watchdog.

Trust model / on-chain seam: the RPC client is optional. With no RPC client the
transaction signature and deposit amount are trusted as provided (offline
core); with an RPC client an open's confirmation signature is checked on-chain
before the channel is persisted, and a top-up signature is confirmed before the
deposit is raised. The on-chain check is wired through the
:class:`SessionServer` config seams
(:func:`~pay_kit.protocols.mpp.server.session_onchain.new_open_tx_verifier` /
:func:`~pay_kit.protocols.mpp.server.session_onchain.new_top_up_tx_verifier`).

On-chain settlement at close (settle_and_finalize + distribute, populating
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

import logging
from dataclasses import dataclass, field
from typing import Any

from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from pay_kit._paycore.errors import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    PaymentError,
    payment_required_response,
)
from pay_kit._paycore.solana import MAX_SPLITS
from pay_kit.protocols.mpp.core.expires import minutes
from pay_kit.protocols.mpp.core.headers import (
    PAYMENT_RECEIPT_HEADER,
    format_receipt,
    format_www_authenticate,
    parse_authorization,
)
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
    VerifyOpenTxExpected,
    confirm_transaction_signature,
    cosign_and_broadcast_open,
    settle_and_finalize_channel,
    verify_open_tx,
)
from pay_kit.protocols.mpp.server.session_store import ChannelStore, MemoryChannelStore
from pay_kit.signer import LocalSigner

logger = logging.getLogger(__name__)

_SECRET_KEY_ENV_VAR = "MPP_SECRET_KEY"
_U64_MAX = (1 << 64) - 1


class _AlreadyFinalized(Exception):
    """Raised by the settle-claim mutator when the channel is already finalized."""

    __slots__ = ("signature",)

    def __init__(self, signature: str | None) -> None:
        super().__init__("already finalized")
        self.signature = signature


class _AlreadySettling(Exception):
    """Raised by the settle-claim mutator when another caller is mid-settle."""

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
    # Store is the pluggable channel store. Defaults to in-memory.
    store: ChannelStore | None = None
    # RPC is the optional RPC client used for on-chain checks. None skips every
    # on-chain check and trusts payload claims as provided.
    rpc: RpcClient | None = None
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


async def _try_recent_blockhash(rpc: Any) -> str | None:
    """Best-effort fetch of a recent blockhash from the injected RPC client.

    Returns the blockhash string on success or ``None`` on any error/absence;
    the prefetch is non-fatal because the client fetches its own blockhash when
    the challenge omits one.
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
        recent blockhash is prefetched (non-fatally) when an RPC client is
        configured.
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

    async def handle(self, authorization: str | None, challenge_options: SessionChallengeOptions) -> SessionGateResult:
        """Framework-agnostic 402 session gate: verify an Authorization credential
        or answer 402 with a fresh challenge.

        When ``authorization`` is present it is parsed and verified; on success the
        result carries the receipt header and status 200. A
        :class:`~pay_kit._paycore.errors.PaymentError` (or any other exception,
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

    def _open_tx_expected(self, payload: OpenPayload) -> VerifyOpenTxExpected:
        """Build the on-chain open verification facts for a transaction-carrying
        open. Only the paths that attach a transaction call this, keeping the
        ``program_id`` pubkey parse (and its failure surface) off the
        trust-the-channel-id paths.
        """
        return VerifyOpenTxExpected(
            authorized_signer=payload.authorized_signer,
            currency=self._currency,
            recipient=self._recipient,
            network=self._network,
            max_cap=self._core.config.max_cap,
            program_id=(Pubkey.from_string(self._core.config.program_id) if self._core.config.program_id else None),
        )

    async def _handle_open(self, payload: OpenPayload) -> str:
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

        if has_transaction and self._open_tx_submitter == OPEN_TX_SUBMITTER_SERVER:
            if self._signer is None or self._rpc is None:
                raise PaymentError(
                    "openTxSubmitter=server requires a signer and an RPC client",
                    code="invalid-config",
                )
            # Idempotent replay guard: the store check-and-insert is the final
            # source of truth (process_open below), but a replayed open must
            # NOT re-broadcast the (already-landed) open transaction. TS
            # checks the store before submitOpenTx; we mirror that here so a
            # replay short-circuits the broadcast instead of sending it
            # again and then no-opping in process_open.
            session_id = payload.session_id()
            existing = await self._core.store().get_channel(session_id)
            if existing is not None:
                if existing.finalized:
                    raise PaymentError(
                        f"channel {session_id} is already finalized", code="invalid-payload"
                    )
                if existing.authorized_signer != payload.authorized_signer:
                    raise PaymentError(
                        f"channel {session_id} already exists with a different authorized signer",
                        code="invalid-payload",
                    )
            else:
                # Built lazily: only the transaction-carrying paths verify
                # the open on-chain, so the on-chain expected facts (and the
                # program_id pubkey parse) stay off the trust-the-channel-id
                # paths.
                expected = self._open_tx_expected(payload)
                try:
                    verified = await verify_open_tx(expected, payload, None)
                    if not payload.payer:
                        payload.payer = verified.payer
                    payload.deposit = str(verified.deposit)
                    payload.signature = await cosign_and_broadcast_open(
                        payload, fee_payer=self._signer.keypair, rpc=self._rpc
                    )
                except PaymentError:
                    raise
                except Exception as exc:
                    raise PaymentError(f"server-broadcast open failed: {exc}", code="invalid-payload") from exc
        elif has_transaction:
            expected = self._open_tx_expected(payload)
            try:
                verified = await verify_open_tx(expected, payload, self._rpc)
            except PaymentError:
                raise
            except Exception as exc:
                raise PaymentError(f"open transaction verification failed: {exc}", code="invalid-payload") from exc
            # Propagate the on-chain payer (open slot 0) so process_open records
            # state.operator when the attached transaction is the source of truth.
            # Without it, settle-at-close refunds the unspent balance to the
            # recipient's ATA instead of the channel opener's.
            if not payload.payer:
                payload.payer = verified.payer
            payload.deposit = str(verified.deposit)
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
        """Raise a channel's deposit after optional on-chain confirmation of the
        top-up signature. The receipt reference is the top-up transaction
        signature."""
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
        not implemented here).

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
        if self._lifecycle is not None:
            self._lifecycle.remove_channel(payload.channel_id)
        settled = await self._settle_channel(channel_id)
        # On a successful settle the reference is the on-chain signature; without
        # a signer/RPC the close is a state-flip and the channel id stands in.
        return settled or payload.channel_id

    async def _settle_channel(self, channel_id: str) -> str | None:
        """Settle and finalize the channel on-chain, returning the settlement
        signature. A no-op (returns ``None``) when no signer or RPC is configured;
        returns the recorded signature when the channel is already finalized.
        Mirrors the gated settle in the Go/TS servers.
        """
        if self._signer is None or self._rpc is None:
            return None

        from pay_kit.protocols.mpp.server.session_store import ChannelState

        # Atomic settle-in-progress guard: claim the channel under the
        # per-channel store lock so a concurrent close retry or idle-watchdog
        # fire cannot both pass the finalize check and broadcast duplicate
        # settle transactions. The winning caller flips ``settling`` to True
        # and continues to the broadcast; losing callers see ``settling`` is
        # already True and bail out (the winner will finalize, a loser may
        # retry if the winner's broadcast fails).
        claimed = False

        def claim(current: ChannelState | None) -> ChannelState:
            nonlocal claimed
            if current is None:
                raise ValueError(f"channel {channel_id} disappeared during settle-claim")
            if current.finalized:
                raise _AlreadyFinalized(current.settled_signature)
            if current.settling:
                raise _AlreadySettling()
            nxt = current.clone()
            nxt.settling = True
            claimed = True
            return nxt

        settled_signature: str | None = None
        try:
            await self._core.store().update_channel(channel_id, claim)
        except _AlreadyFinalized as exc:
            return exc.signature
        except _AlreadySettling:
            return None

        if not claimed:
            return None

        state = await self._core.store().get_channel(channel_id)
        if state is None:
            return None

        try:
            signature = await settle_and_finalize_channel(
                state, merchant=self._signer.keypair, rpc=self._rpc, config=self._core.config
            )
        except Exception:
            # Broadcast/confirm failed: release the settle-in-progress guard
            # so a retry can claim again, re-raise for the caller.
            def release(current: ChannelState | None) -> ChannelState:
                if current is not None and current.settling and not current.finalized:
                    nxt = current.clone()
                    nxt.settling = False
                    return nxt
                return current  # type: ignore[return-value]

            await self._core.store().update_channel(channel_id, release)
            raise

        def finalize(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise ValueError(f"channel {channel_id} disappeared during settle")
            # Idempotent against a concurrent re-drive (e.g. a client close
            # racing the idle-close watchdog): if another caller already
            # finalized under the per-channel lock, keep its signature rather
            # than overwriting with this call's, which may be a rejected second
            # on-chain finalize.
            if current.finalized:
                return current
            nxt = current.clone()
            nxt.finalized = True
            nxt.settled_signature = signature
            nxt.settling = False
            return nxt

        await self._core.store().update_channel(channel_id, finalize)
        settled_signature = signature
        return settled_signature

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
    # its open / topUp handlers, leaving the core SessionConfig verifier seams
    # unset and confirming in the method, so the core is left to trust payload
    # claims; the seam stays available for hosts that drive the lower-level
    # SessionServer directly.
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
    )
    if options.close_delay > 0:
        session._lifecycle = SessionLifecycle(session._close_on_idle, options.close_delay)
    return session
