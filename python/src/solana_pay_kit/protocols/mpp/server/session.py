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

On-chain verification fails closed. ``process_open`` and ``process_top_up``
require their configured RPC verifiers, which decode the attached transaction,
bind every economically significant field, submit it, confirm it, and verify
the resulting channel account before state is persisted.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.mints import resolve_stablecoin_mint
from solana_pay_kit._paycore.paymentchannels import OPEN_SLOT_WINDOW
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge
from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    ClosePayload,
    CommitPayload,
    CommitReceipt,
    CommitStatus,
    MeteringDirective,
    OpenPayload,
    SessionMethodDetails,
    SessionRequest,
    SessionSplit,
    SessionVoucherSigner,
    SignedVoucher,
    TopUpPayload,
    UsePayload,
    VoucherData,
    VoucherPayload,
    resolve_idle_timeout_seconds,
    validate_idle_timeout_options,
    verify_session_authentication,
)
from solana_pay_kit.protocols.mpp.server.session_store import (
    ChannelState,
    ChannelStore,
    CommittedDelivery,
    PendingDelivery,
    ProcessedUse,
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
    "SessionOpenContext",
    "SessionTxVerifier",
    "SessionOpenTxVerifier",
    "BlockhashProvider",
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

# BlockhashProvider returns the host's cached ``(recentBlockhash, recentSlot)``
# pair from one ``getLatestBlockhash`` refresh, or ``None`` when the cache is
# empty/stale (the challenge builder then falls back to a direct RPC fetch).
# Same provider shape as the x402 ``upto`` ``recent_state_provider``.
BlockhashProvider = Callable[[], "tuple[str, int] | None"]


@dataclass(frozen=True)
class SessionOpenContext:
    """Verified outer-challenge facts required while opening a session.

    Mirrors the Rust ``SessionOpenContext``: the challenged
    ``methodDetails.recentBlockhash``/``recentSlot`` flow from the 402
    challenge into open verification so the open transaction is provably
    built against the specific challenge that authorized it.
    """

    # ID of the challenge echoed by the opening credential.
    challenge_id: str
    # Standard challenge expiry from the ``expires`` auth-param ("" = none).
    expires: str
    # The challenged ``methodDetails.recentBlockhash`` (base58). The open
    # transaction's compiled message MUST use exactly this blockhash.
    recent_blockhash: str
    # The challenged ``methodDetails.recentSlot``. The payload's ``openSlot``
    # MUST be no later than it and within ``OPEN_SLOT_WINDOW``.
    recent_slot: int


# SessionOpenTxVerifier is the open-specific verifier seam: unlike the generic
# SessionTxVerifier it also receives the SessionOpenContext so the challenged
# recentBlockhash can be enforced against the decoded transaction before it is
# broadcast.
SessionOpenTxVerifier = Callable[[OpenPayload, SessionOpenContext], Awaitable[None]]


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

    # Price charged by each voucher/use action, in base units.
    amount: int = 0

    # Currency identifier (e.g. "USDC", mint address).
    currency: str = ""

    # Decimals is the token decimals (default 6 for USDC).
    decimals: int = 0

    # Network is the Solana network: "mainnet", "devnet", "localnet".
    network: str = ""

    # Splits are optional splits routed to specific recipients at close.
    splits: list[Split] = field(default_factory=list)

    # Exact payment-channel program advertised under methodDetails.
    channel_program: str = ""

    token_program: str | None = None
    suggested_deposit: int | None = None
    minimum_deposit: int | None = None
    grace_period_seconds: int | None = None
    fee_payer: bool = False
    fee_payer_key: str | None = None

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

    # Voucher signing authority advertised to clients.
    voucher_signer: SessionVoucherSigner = "client"

    # Signing key used to issue cumulative vouchers for operator-mode use.
    operator_signer: Any | None = None

    # Inactivity thresholds offered for a new channel.
    idle_timeout_options_seconds: list[int] | None = None

    # Server-selected inactivity threshold in seconds.
    idle_timeout_seconds: int = 300

    # VerifyOpenTx, when set, confirms the open transaction on-chain (push
    # mode) before process_open persists channel state. It receives the
    # SessionOpenContext so the challenged recentBlockhash is checked against
    # the decoded transaction before broadcast.
    verify_open_tx: SessionOpenTxVerifier | None = None

    # VerifyTopUpTx, when set, confirms the top-up transaction on-chain before
    # process_top_up raises the deposit.
    verify_top_up_tx: SessionTxVerifier[TopUpPayload] | None = None

    # Current slot source used to reject opens that have aged out since the
    # challenge was issued. It may return the slot directly or awaitably.
    current_slot_provider: Callable[[], Awaitable[int] | int] | None = None


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

    def __init__(self, config: SessionConfig, store: ChannelStore, *, rpc: Any | None = None) -> None:
        # config is the immutable server configuration captured at construction.
        self._config = config
        # store persists per-channel state; every mutation goes through its
        # atomic update_channel so voucher watermarks stay double-spend safe.
        self._store = store
        # rpc (duck-typed against the session_onchain RpcClient seam) is the
        # fallback source of the challenge's recentBlockhash/recentSlot when
        # no blockhash cache is shared via with_blockhash_cache.
        self._rpc = rpc
        # blockhash_cache, when set, serves the challenge open-transaction
        # context from the host's shared cache instead of a per-402 RPC call.
        self._blockhash_cache: BlockhashProvider | None = None
        # Transaction verification includes network I/O and therefore cannot
        # run inside the store's synchronous mutator. Serialize the complete
        # verify-and-persist sequence per channel so concurrent open/topUp
        # requests cannot broadcast or apply the same funding operation twice.
        self._channel_locks: dict[str, asyncio.Lock] = {}

    def with_blockhash_cache(self, cache: BlockhashProvider) -> SessionServer:
        """Share the host's recent-blockhash cache with challenge issuance, so
        the challenge's ``recentBlockhash``/``recentSlot`` come from one cached
        ``getLatestBlockhash`` instead of a blocking RPC round-trip per 402.

        ``cache`` returns ``(blockhash, slot)`` from a single
        ``getLatestBlockhash`` refresh, or ``None`` when empty/stale (the
        builder then falls back to a direct RPC fetch). Returns ``self`` for
        chaining, mirroring the Rust ``SessionServer::with_blockhash_cache``.
        """
        self._blockhash_cache = cache
        return self

    def _channel_lock(self, channel_id: str) -> asyncio.Lock:
        lock = self._channel_locks.get(channel_id)
        if lock is None:
            lock = asyncio.Lock()
            self._channel_locks[channel_id] = lock
        return lock

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

    async def build_challenge_request(self) -> SessionRequest:
        """Build the ``SessionRequest`` to embed in a new-channel 402 challenge.

        The result follows the exact session request schema in PR #309.

        Fails loudly (retryable) rather than issuing a challenge without
        ``recentBlockhash``/``recentSlot``: both are REQUIRED for a
        new-channel challenge — the client derives the channel PDA from
        ``recentSlot`` and MUST use the challenged blockhash — so a silent
        omission would surface as a non-retryable payment failure at open
        time.
        """
        blockhash, slot = await self._challenge_open_transaction_context()
        details = SessionMethodDetails(
            network=self._config.network,
            channel_program=self._config.channel_program,
            recent_blockhash=blockhash,
            recent_slot=slot,
            decimals=self._config.decimals,
            token_program=self._config.token_program,
            fee_payer=self._config.fee_payer or None,
            fee_payer_key=self._config.fee_payer_key,
            voucher_signer=self._config.voucher_signer,
            operator=self._config.operator or None,
            min_voucher_delta=(str(self._config.min_voucher_delta) if self._config.min_voucher_delta else None),
            idle_timeout_options_seconds=self._config.idle_timeout_options_seconds,
            grace_period_seconds=self._config.grace_period_seconds,
            distribution_splits=[
                SessionSplit(recipient=split.recipient, share_bps=split.bps) for split in self._config.splits
            ],
        )
        return SessionRequest(
            amount=str(self._config.amount),
            currency=self._wire_currency(),
            recipient=self._config.recipient,
            method_details=details,
            minimum_deposit=(str(self._config.minimum_deposit) if self._config.minimum_deposit is not None else None),
            suggested_deposit=(
                str(self._config.suggested_deposit) if self._config.suggested_deposit is not None else None
            ),
        )

    async def _challenge_open_transaction_context(self) -> tuple[str, int]:
        """Fetch the open-transaction context (``recentBlockhash`` +
        ``recentSlot``) for a new-channel challenge.

        Prefers the shared cache (refreshed out of band) to avoid an RPC
        round-trip per challenge; falls back to one direct
        ``getLatestBlockhash`` call, whose response carries both the blockhash
        and the context slot (with a ``getSlot`` fallback only for
        non-compliant endpoints that omit the context slot).
        """
        if self._blockhash_cache is not None:
            cached = self._blockhash_cache()
            if cached is not None:
                return cached
        if self._rpc is not None:
            try:
                response = await self._rpc.get_latest_blockhash()
                blockhash = response.value.blockhash
                slot = response.context.slot if response.context is not None else None
                if slot is None:
                    slot = await self._rpc.get_slot()
            except Exception as exc:
                raise ValueError(f"failed to fetch recentBlockhash/recentSlot for session challenge: {exc}") from exc
            return str(blockhash), int(slot)
        raise ValueError(
            "session challenge requires recentBlockhash/recentSlot; configure a blockhash cache or an RPC client"
        )

    def _wire_currency(self) -> str:
        mint = resolve_stablecoin_mint(self._config.currency, self._config.network)
        if mint is None:
            raise ValueError("session currency must be an SPL token mint; use wrapped SOL instead of SOL")
        return mint

    async def _current_cluster_slot(self) -> int:
        provider = self._config.current_slot_provider
        try:
            if provider is not None:
                value = provider()
                if isinstance(value, Awaitable):
                    return int(await value)
                return int(value)
            if self._rpc is not None:
                return int(await self._rpc.get_slot())
        except Exception as exc:
            raise ValueError(f"failed to fetch current cluster slot for session open: {exc}") from exc
        raise ValueError("open freshness validation requires an RPC current-slot provider")

    @staticmethod
    def _open_context(challenge: PaymentChallenge) -> SessionOpenContext:
        """Project the HMAC-verified opening challenge onto the
        :class:`SessionOpenContext` open verification enforces.

        The challenged ``recentBlockhash``/``recentSlot`` live in the
        challenge's encoded request; a new-channel challenge without them
        cannot bind the open transaction, so the open is rejected.
        """
        try:
            details = SessionRequest.from_dict(challenge.decode_request()).method_details
        except Exception as exc:
            raise ValueError(f"decode session challenge request: {exc}") from exc
        if not details.recent_blockhash or details.recent_slot is None:
            raise ValueError(
                "session challenge is missing recentBlockhash/recentSlot; a new-channel challenge must provide them"
            )
        return SessionOpenContext(
            challenge_id=challenge.id,
            expires=challenge.expires,
            recent_blockhash=details.recent_blockhash,
            recent_slot=details.recent_slot,
        )

    async def process_open(self, payload: OpenPayload, challenge: PaymentChallenge) -> ChannelState:
        """Process an open action and persist the channel state.

        The channel is keyed by ``OpenPayload.channel_id``. Replayed opens are idempotent: when a
        channel already exists for the session id with the same authorized
        signer, the existing state is returned unchanged and the voucher
        watermark is never reset. Opens for an existing channel are rejected
        when the channel is sealed or when the payload's authorized signer
        differs from the stored one.
        """
        async with self._channel_lock(payload.channel_id):
            return await self._process_open_locked(payload, challenge)

    async def _process_open_locked(self, payload: OpenPayload, challenge: PaymentChallenge) -> ChannelState:
        """Verify and persist an open while holding its channel lock."""
        if challenge.is_expired():
            raise ValueError(f"challenge expired at {challenge.expires}")
        context = self._open_context(challenge)
        session_id = payload.session_id()
        deposit = payload.deposit_base_units()
        if deposit == 0:
            raise ValueError("deposit must be greater than zero")
        if self._config.minimum_deposit is not None and deposit < self._config.minimum_deposit:
            raise ValueError(f"deposit {deposit} is below minimumDeposit {self._config.minimum_deposit}")
        if payload.payee != self._config.recipient:
            raise ValueError("open payee does not match challenge recipient")
        if (
            self._config.grace_period_seconds is None
            or payload.grace_period_seconds != self._config.grace_period_seconds
        ):
            raise ValueError("open gracePeriodSeconds does not match the challenge")

        # The open must encode the *challenged* splits, not merely splits that
        # are self-consistent with its own transaction: the open commits the
        # on-chain distributionHash, and distribute at settle is built from
        # the server's config — a client-substituted list would strand every
        # voucher behind a reverting settleAndSeal+distribute bundle. Mirrors
        # ``payload_splits != self.config.splits`` in the Rust SessionServer.
        payload_splits = [
            Split(recipient=split.recipient, bps=split.share_bps) for split in payload.distribution_splits
        ]
        if payload_splits != self._config.splits:
            raise ValueError("open distributionSplits do not match the challenge")

        # Bind the open to the specific challenge that authorized it: the
        # client takes ``openSlot`` from the challenged ``recentSlot`` (an
        # earlier slot is allowed, a later one never is), so a payload outside
        # this window was not built against this challenge.
        if payload.open_slot > context.recent_slot:
            raise ValueError(
                f"open openSlot {payload.open_slot} is ahead of the challenged recentSlot {context.recent_slot}"
            )
        if context.recent_slot - payload.open_slot > OPEN_SLOT_WINDOW:
            raise ValueError(
                f"open openSlot {payload.open_slot} is outside the {OPEN_SLOT_WINDOW}-slot freshness "
                f"window of the challenged recentSlot {context.recent_slot}"
            )

        existing = await self._store.get_channel(session_id)
        if existing is None:
            current_slot = await self._current_cluster_slot()
            if payload.open_slot > current_slot:
                raise ValueError(
                    f"open openSlot {payload.open_slot} is ahead of the current cluster slot {current_slot}"
                )
            if current_slot - payload.open_slot > OPEN_SLOT_WINDOW:
                raise ValueError(
                    f"open openSlot {payload.open_slot} is outside the {OPEN_SLOT_WINDOW}-slot freshness "
                    f"window of the current cluster slot {current_slot}"
                )

        try:
            authorized_signer = Pubkey.from_string(payload.authorized_signer)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"invalid authorizedSigner: {exc}") from exc
        if not authorized_signer.is_on_curve():
            raise ValueError("open authorizedSigner must be an on-curve Ed25519 public key")

        if self._config.voucher_signer == "operator" and payload.authorized_signer != self._config.operator:
            raise ValueError("operator voucher signing requires authorizedSigner to match the operator")

        if self._config.idle_timeout_options_seconds is not None:
            validate_idle_timeout_options(self._config.idle_timeout_options_seconds)
        if self._config.voucher_signer == "client" and payload.authentication is not None:
            raise ValueError("authentication is only valid when voucherSigner is operator")
        if self._config.voucher_signer == "operator":
            if payload.authentication is None:
                raise ValueError("operator voucher signing requires authentication")
            if payload.authentication.challenge_id != challenge.id:
                raise ValueError("session authentication challengeId does not match the opening challenge")
            if payload.authentication.payer != payload.payer:
                raise ValueError("session authentication payer does not match the channel payer")
            if not verify_session_authentication(payload.authentication, session_id):
                raise ValueError("invalid session authentication signature")

        authentication = payload.authentication.to_dict() if payload.authentication is not None else None
        if existing is not None:
            if existing.sealed:
                raise ValueError(f"channel {session_id} is already sealed")
            if (
                existing.authorized_signer != payload.authorized_signer
                or existing.payer != payload.payer
                or existing.deposit != deposit
                or existing.open_slot != payload.open_slot
                or existing.opening_challenge_id != challenge.id
                or existing.authentication != authentication
            ):
                raise ValueError(f"open replay does not match existing channel {session_id}")
            return existing

        if self._config.verify_open_tx is None:
            raise ValueError("open transaction verification requires a configured RPC verifier")
        # Resolve the negotiated idle timeout BEFORE the verifier broadcasts
        # the funding transaction: an unsupported selection must fail while
        # the deposit is still in the client's wallet, not after the funds are
        # locked in escrow (mirrors the Rust and TS ordering).
        effective_idle_timeout = resolve_idle_timeout_seconds(
            self._config.idle_timeout_seconds,
            self._config.idle_timeout_options_seconds,
            payload.idle_timeout_seconds,
        )
        try:
            await self._config.verify_open_tx(payload, context)
        except Exception as exc:
            raise _wrap("open tx verification failed", exc) from exc

        now_ms = int(time.time() * 1000)
        fresh = ChannelState(
            channel_id=session_id,
            authorized_signer=payload.authorized_signer,
            deposit=deposit,
            open_slot=payload.open_slot,
            payer=payload.payer,
            rent_payer=(self._config.fee_payer_key or "") if self._config.fee_payer else payload.payer,
            opening_challenge_id=challenge.id,
            authentication=authentication,
            voucher_signer=self._config.voucher_signer,
            idle_timeout_seconds=effective_idle_timeout,
            last_activity_at=now_ms,
        )

        def mutator(existing: ChannelState | None) -> ChannelState:
            # Atomic check-and-insert: a replayed open re-passes all checks
            # above (the referenced tx is genuinely confirmed), so it MUST NOT
            # overwrite existing state; that would reset the voucher watermark
            # and erase accepted vouchers before close.
            if existing is not None:
                if existing.sealed:
                    raise ValueError(f"channel {session_id} is already sealed")
                if (
                    existing.authorized_signer != payload.authorized_signer
                    or existing.payer != payload.payer
                    or existing.deposit != deposit
                    or existing.open_slot != payload.open_slot
                    or existing.opening_challenge_id != challenge.id
                    or existing.authentication != fresh.authentication
                ):
                    raise ValueError(f"open replay does not match existing channel {session_id}")
                # Idempotent replay: keep existing state untouched.
                return existing
            return fresh

        return await self._store.update_channel(session_id, mutator)

    async def process_use(
        self,
        payload: UsePayload,
        challenge_id: str,
        idempotency_key: str,
        amount: int | None = None,
    ) -> SignedVoucher:
        """Charge one operator-signed use exactly once for an HTTP idempotency key."""
        if self._config.voucher_signer != "operator" or self._config.operator_signer is None:
            raise ValueError("use is only valid for an operator-signed channel")
        if not idempotency_key:
            raise ValueError("operator-signed use requires an Idempotency-Key header")
        if not verify_session_authentication(payload.authentication, payload.channel_id):
            raise ValueError("invalid session authentication signature")
        price = self._config.amount if amount is None else amount
        if price <= 0 or price > _U64_MAX:
            raise ValueError("use amount must be a positive u64")

        result: list[SignedVoucher] = []

        def mutator(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise ValueError(f"channel {payload.channel_id} not found")
            if current.sealed or current.close_requested_at is not None:
                raise ValueError("channel is closed or close is pending")
            # A record with no binding at all is not a mismatch: it either
            # predates proof binding or was rewritten by a pre-binding
            # writer. Name it so the client knows re-opening — not retrying
            # the proof — is the fix.
            if not current.opening_challenge_id and current.authentication is None:
                raise ValueError("session channel predates proof binding; open a new session")
            if current.voucher_signer != "operator" or current.authentication is None:
                raise ValueError("use is only valid for an operator-signed channel")
            if payload.authentication.to_dict() != current.authentication:
                raise ValueError("session authentication does not match the proof bound at open")
            replay = next(
                (use for use in current.processed_uses if use.idempotency_key == idempotency_key),
                None,
            )
            if replay is not None:
                result.append(
                    SignedVoucher(
                        data=VoucherData(
                            channel_id=current.channel_id,
                            cumulative_amount=str(replay.cumulative),
                            expires_at=DEFAULT_SESSION_EXPIRES_AT,
                        ),
                        signer=current.authorized_signer,
                        signature=replay.voucher_signature,
                    )
                )
                return current
            if price > _U64_MAX - current.cumulative:
                raise ValueError("use cumulative overflows u64")
            cumulative = current.cumulative + price
            if cumulative > current.deposit:
                raise ValueError("insufficient channel availability")
            data = VoucherData(
                channel_id=current.channel_id,
                cumulative_amount=str(cumulative),
                expires_at=DEFAULT_SESSION_EXPIRES_AT,
            )
            signer = self._config.operator_signer
            assert signer is not None
            signature = str(signer.sign_message(data.message_bytes()))
            voucher = SignedVoucher(
                data=data,
                signer=current.authorized_signer,
                signature=signature,
            )
            nxt = current.clone()
            nxt.cumulative = cumulative
            nxt.spent_amount += price
            nxt.highest_voucher_signature = signature
            nxt.highest_voucher_expires_at = DEFAULT_SESSION_EXPIRES_AT
            nxt.last_activity_at = int(time.time() * 1000)
            nxt.processed_uses.append(
                ProcessedUse(
                    challenge_id=challenge_id,
                    idempotency_key=idempotency_key,
                    cumulative=cumulative,
                    voucher_signature=signature,
                )
            )
            result.append(voucher)
            return nxt

        await self._store.update_channel(payload.channel_id, mutator)
        return result[0]

    async def verify_voucher(self, payload: VoucherPayload, amount: int | None = None) -> int:
        """Verify a voucher, advance the watermark, and return the new
        cumulative.

        The full ordered check sequence runs as a preflight outside the store
        lock (see :func:`verify_voucher_for_channel`), then the state-dependent
        checks are re-applied inside the atomic mutator before the watermark is
        persisted.
        """
        voucher = payload.voucher
        # The top-level channelId is the routing key; it must never diverge
        # from the signed voucher's inner channelId (spec: servers MUST reject
        # the action when the two differ).
        if payload.channel_id != voucher.data.channel_id:
            raise ValueError(
                "voucher action channelId "
                f"{payload.channel_id!r} does not match the signed voucher's "
                f"channelId {voucher.data.channel_id!r}"
            )
        channel_id = voucher.data.channel_id
        price = self._config.amount if amount is None else amount
        if price <= 0 or price > _U64_MAX:
            raise ValueError("voucher amount must be a positive u64")

        state = await self._store.get_channel(channel_id)
        if state is None:
            raise ValueError(f"channel {channel_id} not found")
        if state.voucher_signer != "client":
            raise ValueError("voucher is only valid for a client-signed channel")

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
            replayed = result.status == VoucherVerifyStatus.REPLAYED and new_cumulative == current.cumulative
            # Concurrent watermark advancement check.
            if not replayed and new_cumulative <= current.cumulative:
                raise ValueError("concurrent update: watermark advanced")
            nxt = current.clone()
            if replayed:
                # An idempotent replay of the already-accepted highest voucher
                # must not deliver additional service or debit spent_amount
                # again — the client already paid for it.
                nxt.last_activity_at = int(time.time() * 1000)
                return nxt
            if new_cumulative - current.spent_amount < price:
                raise ValueError("insufficient authorized voucher availability")
            nxt.cumulative = new_cumulative
            nxt.highest_voucher_signature = new_signature
            nxt.highest_voucher_expires_at = new_expires_at
            nxt.spent_amount += price
            nxt.last_activity_at = int(time.time() * 1000)
            return nxt

        new_state = await self._store.update_channel(channel_id, mutator)
        return new_state.cumulative

    async def process_top_up(self, payload: TopUpPayload) -> ChannelState:
        """Process a topUp action: atomically raise the channel's deposit cap.

        The additional amount must be positive and must not overflow the
        channel deposit. Top-ups are rejected once the channel is sealed
        or a close has been requested.
        """
        async with self._channel_lock(payload.channel_id):
            return await self._process_top_up_locked(payload)

    async def _process_top_up_locked(self, payload: TopUpPayload) -> ChannelState:
        """Verify and apply a top-up while holding its channel lock."""
        try:
            additional_amount = _parse_u64(payload.additional_amount)
        except ValueError as exc:
            raise ValueError(f"invalid additionalAmount: {payload.additional_amount}") from exc
        if additional_amount == 0:
            raise ValueError("additionalAmount must be greater than zero")

        channel_id = payload.channel_id

        from solana_pay_kit.protocols.mpp.server.session_onchain import top_up_transaction_signature

        topup_signature = top_up_transaction_signature(payload.transaction)
        if topup_signature is not None:
            existing = await self._store.get_channel(channel_id)
            if existing is not None and topup_signature in existing.processed_topup_signatures:
                # Idempotent replay: this exact transaction was already
                # credited, so report the stored state without re-broadcasting
                # (a re-broadcast of a landed transaction fails at preflight).
                return existing

        # On-chain verification seam (same shape as process_open).
        if self._config.verify_top_up_tx is None:
            raise ValueError("top-up transaction verification requires a configured RPC verifier")
        try:
            await self._config.verify_top_up_tx(payload)
        except Exception as exc:
            raise _wrap("top-up tx verification failed", exc) from exc

        def mutator(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise ValueError(f"channel {channel_id} not found")
            # Signature dedupe must live inside the atomic mutator: two
            # in-flight submissions of the same signed top-up both confirm
            # the same landed transaction, so only the first check-and-record
            # may credit the deposit.
            if topup_signature is not None and topup_signature in current.processed_topup_signatures:
                return current.clone()
            if current.sealed:
                raise ValueError(f"channel {channel_id} is already sealed")
            if current.close_requested_at is not None:
                raise ValueError(f"channel {channel_id} close is pending; no further top-ups accepted")
            if additional_amount > _U64_MAX - current.deposit:
                raise ValueError("top-up deposit overflows u64")
            nxt = current.clone()
            nxt.deposit = current.deposit + additional_amount
            nxt.last_activity_at = int(time.time() * 1000)
            if topup_signature is not None:
                nxt.processed_topup_signatures = [*current.processed_topup_signatures, topup_signature]
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
                currency=self._wire_currency(),
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
            new_cumulative = _parse_u64(payload.voucher.data.cumulative_amount)
        except ValueError as exc:
            raise ValueError(f"invalid cumulative in commit voucher: {payload.voucher.data.cumulative_amount}") from exc

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
            # A committed delivery is channel activity: refresh the durable
            # watermark like the voucher/use/top-up paths, or the idle-close
            # recheck (and the post-restart reconcile) closes a channel that is
            # actively paying through the metered-delivery flow.
            nxt.last_activity_at = int(time.time() * 1000)
            nxt.spent_amount += actual_amount
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
        top-ups are all rejected. A second close is rejected with "close
        already requested" only once a settlement signature is recorded;
        before that, a matching close payload re-drives idempotently so a
        transient settlement failure cannot strand the channel close-pending
        with the merchant's accepted vouchers unsettled. A non-monotonic final
        voucher is a hard error (unless it is an idempotent replay of the
        current highest voucher) and leaves the state unchanged.
        """
        now = int(time.time())
        channel_id = payload.channel_id
        voucher = payload.voucher
        # Same routing-key invariant as the voucher action: a final voucher
        # nested in a close must be bound to the channel being closed.
        if voucher is not None and voucher.data.channel_id != channel_id:
            raise ValueError(
                f"close voucher channelId {voucher.data.channel_id!r} does not match the close channelId {channel_id!r}"
            )

        def mutator(current: ChannelState | None) -> ChannelState:
            if current is None:
                raise ValueError(f"channel {channel_id} not found")
            if current.sealed:
                raise ValueError(f"channel {channel_id} is already sealed")
            # Re-drivable close: close-pending with no settlement signature
            # means a prior close's settle never landed. The retry runs the
            # full validation below but must replay the recorded final
            # voucher, and the original close timestamp is preserved.
            redrive = current.close_requested_at is not None
            if redrive and current.settled_signature is not None:
                raise ValueError("close already requested")

            # A close that presents authentication against a record with no
            # proof binding (and no operator marker) is an operator-signed
            # session whose record predates — or was stripped of — the
            # binding fields.
            if (
                payload.authentication is not None
                and current.voucher_signer != "operator"
                and not current.opening_challenge_id
                and current.authentication is None
            ):
                raise ValueError("session channel predates proof binding; the lifecycle worker will close it")
            if current.voucher_signer == "operator":
                if voucher is not None:
                    raise ValueError("operator close must use authentication, not a client voucher")
                if payload.authentication is None:
                    raise ValueError("operator close requires authentication")
                if current.authentication is None:
                    if not current.opening_challenge_id:
                        raise ValueError("session channel predates proof binding; the lifecycle worker will close it")
                    raise ValueError("operator close requires authentication")
                if payload.authentication.to_dict() != current.authentication:
                    raise ValueError("session authentication does not match the proof bound at open")
                if not verify_session_authentication(payload.authentication, channel_id):
                    raise ValueError("invalid session authentication signature")
            else:
                if payload.authentication is not None:
                    raise ValueError("client close must use a final voucher, not authentication")
                if voucher is None:
                    raise ValueError("client close requires a final voucher")

            nxt = current.clone()
            if voucher is not None:
                try:
                    cumulative = _parse_u64(voucher.data.cumulative_amount)
                except ValueError as exc:
                    raise ValueError(f"invalid cumulative in final voucher: {voucher.data.cumulative_amount}") from exc
                if redrive and cumulative != current.cumulative:
                    raise ValueError("close re-drive must replay the recorded final voucher")
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
                        # Record the expiry as encoded in the signed bytes:
                        # None (omitted) encodes as 0 = never-expires. The
                        # watermark is replayed verbatim into the on-chain
                        # settle, and a None here would make the settle
                        # builder reject the channel as misconfigured.
                        nxt.highest_voucher_expires_at = (
                            0 if voucher.data.expires_at is None else voucher.data.expires_at
                        )
                else:
                    if cumulative > current.deposit:
                        raise ValueError("final voucher exceeds deposit")
                    _raise_voucher_error(
                        verify_session_voucher(voucher, current.authorized_signer, self._config.settlement_window)
                    )
                    nxt.cumulative = cumulative
                    nxt.highest_voucher_signature = voucher.signature
                    # None (omitted) encodes as 0 = never-expires in the
                    # signed bytes; the watermark must match what the
                    # signature covers (see _effective_expiry).
                    nxt.highest_voucher_expires_at = 0 if voucher.data.expires_at is None else voucher.data.expires_at
            if not redrive:
                nxt.close_requested_at = now
            nxt.last_activity_at = int(time.time() * 1000)
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
