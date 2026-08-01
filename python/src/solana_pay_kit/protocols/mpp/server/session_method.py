"""HTTP-facing MPP session method handler.

A :class:`Session` issues HMAC-bound 402 challenges carrying a
:class:`~solana_pay_kit.protocols.mpp.intents.session.SessionRequest`
(:meth:`Session.challenge`), verifies Authorization credentials whose payload is
one of the five session actions (:meth:`Session.verify_credential` dispatching
to open / voucher / use / topUp / close), and drives the channel lifecycle by
composing the lower-level building blocks: the :class:`SessionServer` core, the
:class:`ChannelStore`, the voucher verifier, the on-chain verifier seams, and
the idle-close watchdog.

Trust model / on-chain seam: an RPC client is required. Opens and top-ups are
decoded and bound to the credential, submitted, confirmed, and checked against
the resulting on-chain account before local state changes. The checks are wired
through the
:class:`SessionServer` config seams
(:func:`~solana_pay_kit.protocols.mpp.server.session_onchain.new_open_tx_verifier` /
:func:`~solana_pay_kit.protocols.mpp.server.session_onchain.new_top_up_tx_verifier`).

On-chain settlement at close (settle_and_seal + distribute, populating
``settledSignature``) runs when a signer is configured. The idle-close watchdog
uses the same settlement path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    PaymentError,
    payment_required_response,
)
from solana_pay_kit._paycore.solana import MAX_SPLITS
from solana_pay_kit.protocols.mpp._paymentchannels import PROGRAM_ID
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
    OpenPayload,
    SessionAction,
    TopUpPayload,
    UsePayload,
    VoucherPayload,
)
from solana_pay_kit.protocols.mpp.server.defaults import detect_realm
from solana_pay_kit.protocols.mpp.server.session import SessionConfig, SessionServer, Split
from solana_pay_kit.protocols.mpp.server.session_lifecycle import SessionLifecycle
from solana_pay_kit.protocols.mpp.server.session_onchain import (
    RpcClient,
    new_open_tx_verifier,
    new_top_up_tx_verifier,
    settle_and_seal_channel,
)
from solana_pay_kit.protocols.mpp.server.session_store import ChannelStore, MemoryChannelStore
from solana_pay_kit.signer import LocalSigner

logger = logging.getLogger(__name__)

_SECRET_KEY_ENV_VAR = "MPP_SECRET_KEY"
_U64_MAX = (1 << 64) - 1
# Watchdog retry delay after a failed idle-close settle.
_SETTLE_RETRY_SECONDS = 60.0


class _AlreadySealed(Exception):
    """Raised by the settle-claim mutator when the channel is already sealed."""

    __slots__ = ("signature",)

    def __init__(self, signature: str | None) -> None:
        super().__init__("already sealed")
        self.signature = signature


class _AlreadySettling(Exception):
    """Raised by the settle-claim mutator when another caller is mid-settle."""


__all__ = [
    "SessionOptions",
    "SessionChallengeOptions",
    "SessionGateResult",
    "Session",
    "new_session",
]


@dataclass
class SessionOptions:
    """Options for :func:`new_session`."""

    # Operator public key (base58), shown to clients in the challenge.
    operator: str = ""
    # Recipient is the primary payment recipient (base58). Required.
    recipient: str = ""
    # Amount charged per use/voucher action. Required, must be positive.
    amount: int = 0
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
    # Payment-channel program advertised under methodDetails.channelProgram.
    channel_program: Pubkey | None = None
    token_program: str | None = None
    suggested_deposit: int | None = None
    minimum_deposit: int | None = None
    grace_period_seconds: int = 900
    fee_payer: bool = False
    voucher_signer: str = "client"
    idle_timeout_options_seconds: list[int] | None = None
    idle_timeout_seconds: int = 300
    # MinVoucherDelta is the minimum voucher increment (base units). 0 = no
    # minimum.
    min_voucher_delta: int = 0
    # Splits are optional basis-point splits distributed at close. Max 8.
    splits: list[Split] = field(default_factory=list)
    # Store is the pluggable channel store. Defaults to in-memory.
    store: ChannelStore | None = None
    # RPC is required: session funding verification always fails closed.
    rpc: RpcClient | None = None
    # Signer is the operator/merchant local signer that funds and signs the
    # on-chain settle-at-close (and the server-broadcast open) transactions.
    # None (or no RPC) leaves close a pure state-flip with settledSignature unset.
    signer: LocalSigner | None = None


@dataclass
class SessionChallengeOptions:
    """Customize a single 402 session challenge."""

    # Amount overrides the configured price for this challenge.
    amount: str = ""
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
        amount: int,
        currency: str,
        recipient: str,
        network: str,
        rpc: RpcClient | None,
        lifecycle: SessionLifecycle | None,
        signer: LocalSigner | None = None,
    ) -> None:
        # core is the lower-level SessionServer dispatching open / voucher /
        # commit / topUp / close against the channel store.
        self._core = core
        self._secret_key = secret_key
        self._realm = realm
        self._amount = amount
        self._currency = currency
        self._recipient = recipient
        self._network = network
        self._rpc = rpc
        # lifecycle is the idle-close watchdog; None when close_delay is zero.
        self._lifecycle = lifecycle
        # signer settles the channel on-chain at close (and broadcasts server
        # opens); None or no rpc leaves close a state-flip with no settlement.
        self._signer = signer
        self._lifecycle_reconciled = False

    def core(self) -> SessionServer:
        """Return the underlying :class:`SessionServer` so hosts can reach the
        channel store and the lower-level lifecycle methods."""
        return self._core

    def shutdown(self) -> None:
        """Cancel the idle-close watchdog timers. Hosts should call it when
        tearing the session method down."""
        if self._lifecycle is not None:
            self._lifecycle.shutdown()

    async def _touch(self, channel_id: str) -> None:
        """Reset the idle-close timer for ``channel_id`` when the watchdog is
        armed."""
        if self._lifecycle is not None:
            state = await self._core.store().get_channel(channel_id)
            self._lifecycle.touch(channel_id, state.idle_timeout_seconds if state else None)

    async def challenge(self, options: SessionChallengeOptions | None = None) -> PaymentChallenge:
        """Build the HMAC-bound 402 challenge embedding a ``SessionRequest``.

        The request follows the exact PR #309 session schema.
        """
        if options is None:
            options = SessionChallengeOptions()
        await self._reconcile_lifecycle()
        request = await self._core.build_challenge_request()
        if options.amount != "":
            try:
                _parse_session_u64(options.amount, "amount")
            except ValueError as exc:
                raise PaymentError(f"invalid requested amount: {exc}", code="invalid-payload") from exc
            request.amount = options.amount
        if options.description != "":
            request.description = options.description
        if options.external_id != "":
            request.external_id = options.external_id
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

    async def verify_credential(self, credential: PaymentCredential, *, idempotency_key: str = "") -> Receipt:
        """Verify a session Authorization credential: Tier-1 HMAC, the Tier-2
        pinned-field backstop, then dispatch on the payload action. Challenge
        expiry gates ``open`` only; an opened channel's stored authentication
        proof remains valid until idle timeout or closure.
        """
        await self._reconcile_lifecycle()
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
        from solana_pay_kit.protocols.mpp.intents.session import SessionRequest

        request = SessionRequest.from_dict(challenge.decode_request())
        self._verify_pinned_session_fields(credential, request)

        try:
            action = SessionAction.from_dict(credential.payload)
        except Exception as exc:
            raise PaymentError(f"decode session action: {exc}", code="invalid-payload") from exc

        if action.open is not None:
            if challenge.is_expired():
                raise ChallengeExpiredError(f"challenge expired at {challenge.expires}")
            reference = await self._handle_open(action.open, challenge=challenge)
        elif action.use is not None:
            reference = await self._handle_use(action.use, challenge.id, idempotency_key, int(request.amount))
        elif action.voucher is not None:
            reference = await self._handle_voucher(action.voucher)
        elif action.top_up is not None:
            reference = await self._handle_top_up(action.top_up)
        elif action.close is not None:
            reference = await self._handle_close(action.close)
        else:
            raise PaymentError("unknown session action", code="invalid-payload")

        external_id = request.external_id or ""
        return _success_receipt(reference, credential.challenge.id, external_id)

    async def handle(
        self,
        authorization: str | None,
        challenge_options: SessionChallengeOptions,
        *,
        idempotency_key: str = "",
    ) -> SessionGateResult:
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
                receipt = await self.verify_credential(
                    parse_authorization(authorization), idempotency_key=idempotency_key
                )
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

    async def _handle_open(
        self,
        payload: OpenPayload,
        challenge: PaymentChallenge,
    ) -> str:
        """Verify, submit, confirm, and persist an exact channel open."""
        try:
            state = await self._core.process_open(payload, challenge)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        await self._touch(state.channel_id)
        return state.channel_id

    async def _handle_use(
        self,
        payload: UsePayload,
        challenge_id: str,
        idempotency_key: str,
        amount: int,
    ) -> str:
        """Charge an authenticated operator-mode request exactly once."""
        try:
            voucher = await self._core.process_use(payload, challenge_id, idempotency_key, amount)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        await self._touch(payload.channel_id)
        return f"{payload.channel_id}:{voucher.data.cumulative_amount}:{voucher.signature}"

    async def _handle_voucher(self, payload: VoucherPayload) -> str:
        """Verify a cumulative voucher and advance the watermark. The receipt
        reference is "<channelId>:<cumulative>"."""
        channel_id = payload.voucher.data.channel_id
        try:
            cumulative = await self._core.verify_voucher(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        await self._touch(channel_id)
        return f"{channel_id}:{cumulative}"

    async def _handle_top_up(self, payload: TopUpPayload) -> str:
        """Verify and apply an exact signed top-up transaction."""
        try:
            await self._core.process_top_up(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        await self._touch(payload.channel_id)
        return payload.channel_id

    async def _handle_close(self, payload: ClosePayload) -> str:
        """Accept the optional final voucher and flip close-pending atomically.

        The close is re-drivable (see :meth:`SessionServer.process_close`):
        when a prior close flipped the close-pending flag but settlement never
        recorded a signature, a matching retry proceeds so a transient
        settlement failure cannot strand the channel.
        """
        channel_id = payload.channel_id
        try:
            await self._core.process_close(payload)
        except ValueError as exc:
            raise PaymentError(str(exc), code="invalid-payload") from exc
        settled = await self._settle_channel(channel_id)
        # The idle watchdog may only forget the channel once the settle
        # attempt is behind us: after a failed settle it is the sole actor
        # left that can re-drive the close.
        if self._lifecycle is not None:
            self._lifecycle.remove_channel(payload.channel_id)
        # On a successful settle the reference is the on-chain signature; without
        # a signer/RPC the close is a state-flip and the channel id stands in.
        return settled or payload.channel_id

    async def _settle_channel(self, channel_id: str) -> str | None:
        """Settle and seal the channel on-chain, returning the settlement
        signature. A no-op (returns ``None``) when no signer or RPC is configured;
        returns the recorded signature when the channel is already sealed.
        Mirrors the gated settle in the Go/TS servers.
        """
        if self._signer is None or self._rpc is None:
            return None

        from solana_pay_kit.protocols.mpp.server.session_store import ChannelState

        # Atomic settle-in-progress guard: claim the channel under the
        # per-channel store lock so a concurrent close retry or idle-watchdog
        # fire cannot both pass the seal check and broadcast duplicate
        # settle transactions. The winning caller flips ``settling`` to True
        # and continues to the broadcast; losing callers see ``settling`` is
        # already True and bail out (the winner will seal, a loser may
        # retry if the winner's broadcast fails).
        claimed = False

        def claim(current: ChannelState | None) -> ChannelState:
            nonlocal claimed
            if current is None:
                raise ValueError(f"channel {channel_id} disappeared during settle-claim")
            if current.sealed:
                raise _AlreadySealed(current.settled_signature)
            if current.settling:
                raise _AlreadySettling()
            nxt = current.clone()
            nxt.settling = True
            claimed = True
            return nxt

        settled_signature: str | None = None
        try:
            await self._core.store().update_channel(channel_id, claim)
        except _AlreadySealed as exc:
            return exc.signature
        except _AlreadySettling:
            return None

        if not claimed:
            return None

        state = await self._core.store().get_channel(channel_id)
        if state is None:
            return None

        try:
            signature = await settle_and_seal_channel(
                state, merchant=self._signer.keypair, rpc=self._rpc, config=self._core.config
            )
        except Exception:
            # Broadcast/confirm failed: release the settle-in-progress guard
            # so a retry can claim again, re-raise for the caller.
            def release(current: ChannelState | None) -> ChannelState:
                if current is not None and current.settling and not current.sealed:
                    nxt = current.clone()
                    nxt.settling = False
                    return nxt
                return current  # type: ignore[return-value]

            await self._core.store().update_channel(channel_id, release)
            raise

        def seal(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise ValueError(f"channel {channel_id} disappeared during settle")
            # Idempotent against a concurrent re-drive (e.g. a client close
            # racing the idle-close watchdog): if another caller already
            # sealed under the per-channel lock, keep its signature rather
            # than overwriting with this call's, which may be a rejected second
            # on-chain seal.
            if current.sealed:
                return current
            nxt = current.clone()
            nxt.sealed = True
            nxt.settled_signature = signature
            nxt.settling = False
            return nxt

        await self._core.store().update_channel(channel_id, seal)
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
        import time

        from solana_pay_kit.protocols.mpp.server.session_store import ChannelState

        due = False
        remaining: float | None = None

        def close_if_due(current: ChannelState | None) -> ChannelState:
            nonlocal due, remaining
            if current is None or current.sealed:
                return current  # type: ignore[return-value]
            if current.close_requested_at is not None:
                # Close-pending with no settlement signature is a stranded
                # settle (a prior close's broadcast failed): re-drive it.
                due = current.settled_signature is None
                return current
            timeout = current.idle_timeout_seconds
            if timeout is None or timeout <= 0:
                return current
            now_ms = int(time.time() * 1000)
            elapsed_ms = max(0, now_ms - current.last_activity_at)
            timeout_ms = timeout * 1000
            if elapsed_ms < timeout_ms:
                remaining = (timeout_ms - elapsed_ms) / 1000
                return current
            nxt = current.clone()
            nxt.close_requested_at = int(time.time())
            due = True
            return nxt

        try:
            await self._core.store().update_channel(channel_id, close_if_due)
            if remaining is not None and self._lifecycle is not None:
                self._lifecycle.touch(channel_id, remaining)
            if due:
                await self._settle_channel(channel_id)
        except Exception:
            logging.getLogger(__name__).warning("idle-close settle failed for channel %s", channel_id, exc_info=True)
            # Re-arm the timer: after a failed settle the watchdog is the
            # only actor guaranteed to retry the close.
            if self._lifecycle is not None:
                self._lifecycle.touch(channel_id, _SETTLE_RETRY_SECONDS)
        return None

    async def _reconcile_lifecycle(self) -> None:
        """Restore idle timers from durable channel state once per process."""
        if self._lifecycle is None or self._lifecycle_reconciled:
            return
        self._lifecycle_reconciled = True
        import time

        now_ms = int(time.time() * 1000)
        for state in await self._core.store().list_channels():
            if state.sealed:
                continue
            if state.close_requested_at is not None:
                # A settle stranded by a previous process: retry promptly.
                if state.settled_signature is None:
                    self._lifecycle.touch(state.channel_id, 0.001)
                continue
            if not state.idle_timeout_seconds:
                continue
            elapsed = max(0, now_ms - state.last_activity_at) / 1000
            self._lifecycle.touch(state.channel_id, max(0.001, state.idle_timeout_seconds - elapsed))


def new_session(options: SessionOptions) -> Session:
    """Create the server-side session method."""
    if options.amount == 0:
        raise PaymentError("amount must be positive", code="invalid-config")
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

    if options.rpc is None:
        raise PaymentError("session requires an RPC client for funding verification", code="invalid-config")
    if options.voucher_signer not in ("client", "operator"):
        raise PaymentError("voucherSigner must be 'client' or 'operator'", code="invalid-config")
    if options.voucher_signer == "operator" and options.signer is None:
        raise PaymentError("operator voucher signing requires signer", code="invalid-config")
    if options.fee_payer and options.signer is None:
        raise PaymentError("fee payer mode requires signer", code="invalid-config")

    store = options.store if options.store is not None else MemoryChannelStore()

    channel_program = options.channel_program or PROGRAM_ID
    operator = options.operator
    if not operator and options.signer is not None:
        operator = str(options.signer.pubkey())
    config = SessionConfig(
        operator=operator,
        recipient=options.recipient,
        splits=options.splits,
        amount=options.amount,
        currency=currency,
        decimals=decimals,
        network=network,
        channel_program=str(channel_program),
        token_program=options.token_program,
        suggested_deposit=options.suggested_deposit,
        minimum_deposit=options.minimum_deposit,
        grace_period_seconds=options.grace_period_seconds,
        fee_payer=options.fee_payer,
        fee_payer_key=(str(options.signer.pubkey()) if options.fee_payer and options.signer is not None else None),
        min_voucher_delta=options.min_voucher_delta,
        voucher_signer=options.voucher_signer,  # type: ignore[arg-type]
        operator_signer=(options.signer.keypair if options.voucher_signer == "operator" and options.signer else None),
        idle_timeout_options_seconds=options.idle_timeout_options_seconds,
        idle_timeout_seconds=options.idle_timeout_seconds,
    )
    config.verify_open_tx = new_open_tx_verifier(
        config,
        options.rpc,
        fee_payer_signer=(options.signer.keypair if options.fee_payer and options.signer else None),
    )
    config.verify_top_up_tx = new_top_up_tx_verifier(config, store, options.rpc)
    # The RPC doubles as the fallback source of the challenge's
    # recentBlockhash/recentSlot; hosts can avoid the per-402 round-trip by
    # sharing a cache via ``session.core().with_blockhash_cache(...)``.
    core = SessionServer(config, store, rpc=options.rpc)
    session = Session(
        core=core,
        secret_key=secret_key,
        realm=realm,
        amount=options.amount,
        currency=currency,
        recipient=options.recipient,
        network=network,
        rpc=options.rpc,
        lifecycle=None,
        signer=options.signer,
    )
    if options.idle_timeout_seconds > 0:
        session._lifecycle = SessionLifecycle(session._close_on_idle)
    return session
