"""x402 ``batch-settlement`` (Solana) server engine.

Self-facilitated: the server verifies each payment, reserves channel capacity
before the resource handler runs, and commits the charge after it. A
``deposit`` payload's ``open``/``top_up`` is statically validated and simulated
before the handler, and broadcast only after the handler succeeded.

The wire contract a Rust client checks (``client/batch_settlement/payment.rs``
``apply_payment_response``) is reproduced exactly: ``commitmentId`` is
``"{channelId}:{maxClaimableAmount}"`` of the submitted voucher,
``chargedAmount`` is the requirement amount, and
``channelState.chargedCumulativeAmount`` is the submitted cumulative. The
client-signed accept is always listed first, because the Rust client takes the
first ``batch-settlement`` accept.

Money rules: integers only; ``charged`` and ``signed`` move only at commit and
never down (the store enforces it); a channel rebuilt from chain starts at its
settled watermark with no voucher, so no charge is invented; after a confirmed
broadcast a failed store write is logged and alerted, never re-raised.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import logging
import os
import re
import time
import uuid
from collections.abc import AsyncGenerator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from decimal import ROUND_FLOOR, Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, Literal, cast

import pydantic
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.transaction import VersionedTransaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.currency import parse_units
from solana_pay_kit._paycore.mints import resolve, token_program_for
from solana_pay_kit._paycore.paymentchannels import PAYMENT_CHANNELS_PROGRAM_ID, treasury_owner
from solana_pay_kit._paycore.rpc import SolanaRpc, read_with_replica_retry
from solana_pay_kit.errors import ConfigurationError
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.x402.batch_settlement import errors, onchain, tx_policy
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.redemption import BatchRedemption, RedemptionSettings
from solana_pay_kit.protocols.x402.batch_settlement.signatures import sign_voucher
from solana_pay_kit.protocols.x402.batch_settlement.store import (
    BatchChannelStore,
    BatchOperationStore,
    ChannelRecord,
    MemoryBatchChannelStore,
    MemoryBatchOperationStore,
    Reservation,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    BATCH_SETTLEMENT_SCHEME,
    MAX_WITHDRAW_DELAY_SECONDS,
    MIN_WITHDRAW_DELAY_SECONDS,
    BatchChannelConfig,
    BatchChannelState,
    BatchDeposit,
    BatchPaymentPayload,
    BatchRequirements,
    BatchSettlementExtra,
    BatchSettlementResponse,
    BatchVoucher,
    VoucherSigner,
    commitment_id,
    parse_payment_payload,
    parse_u64,
)
from solana_pay_kit.protocols.x402.batch_settlement.verify import (
    CHANNEL_STATUS_CLOSING,
    CHANNEL_STATUS_OPEN,
    check_authorization,
    check_capacity,
    check_channel_binding,
    check_channel_config,
    check_cumulative,
    check_no_cooperative_close,
    check_voucher,
    derive_channel_id,
)
from solana_pay_kit.signer import LocalSigner

if TYPE_CHECKING:
    from solana_pay_kit.config import Config
    from solana_pay_kit.gate import Gate

__all__ = [
    "BatchSettlementConfig",
    "CorrectiveRequired",
    "PendingSetup",
    "VerifiedBatchRequest",
    "X402BatchSettlement",
]

logger = logging.getLogger("solana_pay_kit.x402.batch")

_X402_VERSION = 2
_CHALLENGE_HEADER = "payment-required"
_RESPONSE_HEADER = "payment-response"
_SETTLEMENT_HEADER = "x-payment-settlement-signature"
_PAYMENT_HEADERS = ("payment-signature", "x-payment")
_DECIMALS = 6
_MIN_RESERVATION_SECONDS = 5
# Accept fields a client must echo unchanged. Hints (blockhash, slot), the
# advisory minDeposit/maxIdleSecs and corrective snapshots are left out: a Rust
# client drops the fields it does not know when it echoes ``accepted``.
_BOUND_FIELDS = ("network", "amount", "asset", "payTo", "maxTimeoutSeconds")
_BOUND_EXTRA = (
    "paymentFlow",
    "feePayer",
    "receiverAuthorizer",
    "withdrawDelay",
    "tokenProgram",
    "memo",
    "voucherSigner",
    "operator",
)

AlertHook = Callable[[str, Mapping[str, Any]], None]

_ATOMIC = re.compile(r"[0-9]+")
_USD = re.compile(r"\$[0-9]+(\.[0-9]+)?")
# Multiples of the price advertised as minDeposit. Server mode stays near the
# client's own minimum: that escrow is what the operator could take.
_CLIENT_MIN_DEPOSIT_MULTIPLE = 10
_SERVER_MIN_DEPOSIT_MULTIPLE = 3
# ponytail: recover() matches only the first 1024 distinct payTo values this
# process advertised; persist them if a server settles to more.
_MAX_REMEMBERED_PAY_TO = 1024


def _atomic_min_deposit(value: str) -> int:
    """Atomic units for a ``min_deposit`` of ``"123"`` or ``"$1.5"`` (USD, 6 decimals, floored)."""
    if _ATOMIC.fullmatch(value):
        return int(value)
    if _USD.fullmatch(value):
        try:
            return int((Decimal(value[1:]) * 10**_DECIMALS).to_integral_value(rounding=ROUND_FLOOR))
        except InvalidOperation:  # pragma: no cover - the pattern admits only plain decimals
            pass
    raise ConfigurationError(f"batch min_deposit {value!r} must be atomic units or a USD amount like '$1.50'")


class BatchSettlementConfig(pydantic.BaseModel):
    """Server knobs for ``batch-settlement``; frozen, unknown keys refused."""

    model_config = pydantic.ConfigDict(frozen=True, arbitrary_types_allowed=True, extra="forbid")

    #: Forced-close grace period advertised as ``withdrawDelay``; ``None`` = ``max(900, max_timeout_seconds)``.
    withdraw_delay: int | None = None
    #: HTTP completion window advertised as ``maxTimeoutSeconds``.
    max_timeout_seconds: int = 300
    #: Receiver-authorizer key advertised as ``extra.receiverAuthorizer``; omitted when ``None``.
    receiver_authorizer: str | None = None
    #: How long a channel snapshot read from chain lets vouchers verify without another read.
    onchain_state_ttl_seconds: int = 30
    #: Operator key that signs vouchers for metered requests; enables the server-signed accept.
    operator: LocalSigner | None = None
    #: ``extra.minDeposit`` override: atomic units, or ``"$x"`` (USD, floored to atomic units).
    min_deposit: str | None = None
    #: Refuse a ``deposit`` below the advertised ``minDeposit`` (``deposit_below_min_deposit``).
    enforce_min_deposit: bool = False
    #: Receiver-authorizer key that signs ``CloseAuthorization``s for a seal; ``None`` = the fee payer.
    close_authorizer: LocalSigner | None = None
    #: Seal an open channel idle this long (with its latest voucher), advertised as ``maxIdleSecs``; ``None`` = never.
    max_idle_secs: int | None = None
    #: Channels per claim or distribute transaction; clamped to ``1..=4``.
    max_channels_per_batch: int = 4

    @pydantic.model_validator(mode="after")
    def _check_delay(self) -> BatchSettlementConfig:
        if self.min_deposit is not None and _atomic_min_deposit(self.min_deposit) <= 0:
            raise ConfigurationError(f"batch min_deposit {self.min_deposit!r} must be a positive amount")
        delay = self.effective_withdraw_delay()
        if self.max_timeout_seconds <= 0 or not MIN_WITHDRAW_DELAY_SECONDS <= delay <= MAX_WITHDRAW_DELAY_SECONDS:
            raise ConfigurationError(f"batch withdraw_delay {delay} is outside 900..=2592000 seconds")
        if delay < self.max_timeout_seconds:
            raise ConfigurationError(f"batch withdraw_delay {delay} is shorter than max_timeout_seconds")
        return self

    def effective_withdraw_delay(self) -> int:
        """The advertised grace period."""
        if self.withdraw_delay is not None:
            return self.withdraw_delay
        return max(MIN_WITHDRAW_DELAY_SECONDS, self.max_timeout_seconds)


@dataclass(frozen=True)
class PendingSetup:
    """A validated, co-signed and simulated (unless it already landed) ``open``/``top_up``, sent at commit."""

    form: tx_policy.SetupForm
    amount: int
    amount_string: str
    payer_signature: str
    transaction: VersionedTransaction
    signature: str


@dataclass(frozen=True)
class VerifiedBatchRequest:
    """A verified request holding a capacity reservation until :meth:`X402BatchSettlement.commit` or ``release``."""

    channel_id: str
    payer: str
    kind: Literal["deposit", "voucher", "authorization"]
    server_signed: bool
    requirements: BatchRequirements
    channel_config: BatchChannelConfig
    ceiling: int
    reservation_id: str
    required_deposit: int
    voucher: BatchVoucher | None
    request_id: str | None
    setup: PendingSetup | None


class CorrectiveRequired(BatchSettlementError):
    """A 402 whose ``accepts`` carry the server's channel snapshot for the client to resync from.

    ``cumulative_amount_mismatch`` on a validated voucher off the watermark, or
    ``duplicate_settlement`` on an exact replay of the voucher last charged
    (its response was lost), with the voucher proof attached.
    """

    def __init__(
        self, detail: str, accepts: list[BatchRequirements], code: str = errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH
    ) -> None:
        super().__init__(code, detail)
        self.accepts = accepts


class _ReplayedVoucher(BatchSettlementError):
    """The exact voucher already charged at the watermark came back."""


def _snapshot(record: ChannelRecord) -> BatchChannelState:
    return {
        "channelId": record.channel_id,
        "balance": str(record.deposit),
        "totalClaimed": str(record.settled),
        "withdrawRequestedAt": record.closure_started_at,
        "chargedCumulativeAmount": str(record.charged_cumulative),
    }


class X402BatchSettlement:
    """Server-side x402 ``batch-settlement`` engine (self-facilitated)."""

    def __init__(
        self,
        config: Config,
        *,
        settings: BatchSettlementConfig | None = None,
        channel_store: BatchChannelStore | None = None,
        operation_store: BatchOperationStore | None = None,
        rpc: SolanaRpc | None = None,
        recent_state_provider: Callable[[], tuple[str | None, int | None] | None] | None = None,
        clock: Callable[[], float] = time.time,
        on_alert: AlertHook | None = None,
        program_id: str | None = None,
    ) -> None:
        """Bind the engine to ``config``; delegated x402 mode is not supported."""
        if config.x402.is_delegated():
            raise NotImplementedError("solana_pay_kit: x402 batch-settlement runs self-hosted only")
        self._config = config
        self._settings = settings or BatchSettlementConfig()
        self._store: BatchChannelStore = channel_store or MemoryBatchChannelStore()
        self._operations: BatchOperationStore = operation_store or MemoryBatchOperationStore()
        self._rpc = rpc
        self._recent_state_provider = recent_state_provider
        self._clock = clock
        self._on_alert = on_alert
        # Every payTo a route advertised: recover() matches rebuilt channels against them.
        self._pay_to: set[str] = set()
        # The harness points every SDK at a locally deployed program through
        # this env var; it is never a wire field.
        self._program_id = Pubkey.from_string(
            program_id or os.environ.get("PAYMENT_CHANNELS_PROGRAM_ID") or PAYMENT_CHANNELS_PROGRAM_ID
        )
        operator = self._settings.operator
        if operator is not None and operator.pubkey() == self._fee_payer().pubkey():
            raise ConfigurationError("solana_pay_kit: the batch operator must not be the fee payer")
        advertised = self._settings.receiver_authorizer
        if advertised is not None and advertised != self._close_authorizer().pubkey():
            raise ConfigurationError("solana_pay_kit: receiver_authorizer must be the close authorizer's key")

    # -- challenge -------------------------------------------------------------

    def accepts_entries(
        self, gate: Gate, request: Any, *, voucher_signer: VoucherSigner | None = None
    ) -> list[BatchRequirements]:
        """The route's accepts with fresh blockhash/slot hints, client-signed first.

        With an operator configured the route also offers a server-signed
        accept after the client one: a Rust client takes the first accept and
        signs its own vouchers. ``voucher_signer`` pins the route to one mode.
        """
        del request
        accepts = self._accepts(gate, voucher_signer)
        blockhash, slot = self._recent_state()
        for requirement in accepts:
            if blockhash is not None:
                requirement["extra"]["recentBlockhash"] = blockhash
            if slot is not None:
                requirement["extra"]["recentSlot"] = slot
        return accepts

    def challenge_headers(
        self,
        gate: Gate,
        request: Any,
        *,
        error: str | None = None,
        accepts: list[BatchRequirements] | None = None,
    ) -> dict[str, str]:
        """The ``payment-required`` header: base64 JSON with ``accepts`` and an optional ``error`` code."""
        envelope: dict[str, Any] = {
            "x402Version": _X402_VERSION,
            "resource": {"url": _request_path(request)},
            "accepts": accepts if accepts is not None else self.accepts_entries(gate, request),
        }
        if error is not None:
            envelope["error"] = error
        return {_CHALLENGE_HEADER: _b64json(envelope)}

    def detect_batch(self, request: Any) -> bool:
        """Whether the request carries a ``batch-settlement`` payment header."""
        try:
            envelope = _decode_header(_payment_header(request))
        except BatchSettlementError:
            return False
        accepted = envelope.get("accepted")
        return isinstance(accepted, dict) and cast("dict[str, Any]", accepted).get("scheme") == BATCH_SETTLEMENT_SCHEME

    def settlement_headers(self, response: BatchSettlementResponse) -> dict[str, str]:
        """``PAYMENT-RESPONSE`` plus the settlement-signature header (``""`` for a plain voucher)."""
        return {_RESPONSE_HEADER: _b64json(response), _SETTLEMENT_HEADER: response["transaction"]}

    # -- verify and reserve (before the handler) ------------------------------------

    async def verify_and_reserve(
        self, gate: Gate, request: Any, *, voucher_signer: VoucherSigner | None = None
    ) -> VerifiedBatchRequest | BatchSettlementResponse:
        """Verify the payment and reserve its ceiling against the channel deposit.

        A ``refund`` is a payment operation, not a paid request: it runs here and
        its settlement response comes back directly, so the handler is bypassed.
        Raises :class:`BatchSettlementError` (402) on rejection and
        :class:`CorrectiveRequired` when the voucher is valid but off the
        server's cumulative watermark.
        """
        envelope = parse_payment_payload(_decode_header(_payment_header(request)))
        requirements = self._match_accepted(envelope, self._accepts(gate, voucher_signer))
        payload = envelope["payload"]
        config = payload["channelConfig"]
        fee_payer = self._fee_payer().pubkey()
        operator = self._settings.operator
        check_channel_config(
            config, requirements, fee_payer=fee_payer, operator=None if operator is None else operator.pubkey()
        )
        check_no_cooperative_close(payload)
        channel_id = derive_channel_id(config, fee_payer, self._program_id)
        if payload["type"] == "refund":
            return await self._refund(payload["transaction"], config, requirements, channel_id)
        ceiling = parse_u64(requirements["amount"], "amount")
        server_signed = config.get("voucherSigner") == "server"
        # Every proof is checked before any RPC read, so an unsigned request
        # cannot make the server read the chain.
        voucher: BatchVoucher | None = None
        request_id: str | None = None
        proof_expires_at = 0.0
        max_claimable: int | None = None
        deposit: BatchDeposit | None = None
        if payload["type"] == "voucher":
            voucher = payload["voucher"]
        elif payload["type"] == "authorization":
            proof = payload["authorization"]
            check_authorization(proof, config, channel_id, amount=requirements["amount"], now=int(self._clock()))
            request_id = proof["requestId"]
            proof_expires_at = float(proof["expiresAt"])
        else:
            deposit = payload["deposit"]
            voucher = payload.get("voucher")
            proof = payload.get("authorization")
            if proof is not None:
                check_authorization(proof, config, channel_id, amount=requirements["amount"], now=int(self._clock()))
                request_id = proof["requestId"]
                proof_expires_at = float(proof["expiresAt"])
            self._check_min_deposit(deposit, requirements)
        if voucher is not None:
            max_claimable = check_voucher(voucher, config, channel_id)
        setup = None
        async with self._rpc_scope() as rpc:
            if deposit is None:
                await self._ensure_fresh(rpc, channel_id, config, requirements)
            else:
                form = tx_policy.setup_form(deposit["transaction"], self._program_id)
                exists = await self._ensure_fresh(rpc, channel_id, config, requirements, must_exist=form == "top_up")
                setup = await self._validate_setup(rpc, deposit, form, config, requirements, channel_id, exists)
        if request_id is not None:
            # The record may be pruned once the proof expires: verify refuses an expired proof.
            created, _ = await self._operations.reserve(
                channel_id, request_id, ceiling, expires_at=proof_expires_at, now=self._clock()
            )
            if not created:
                raise BatchSettlementError(errors.DUPLICATE_SETTLEMENT, f"request {request_id} was already used")
        try:
            reservation_id, required = await self._reserve(
                channel_id,
                config,
                requirements,
                kind="server" if server_signed else "client",
                ceiling=ceiling,
                voucher=voucher,
                max_claimable=max_claimable,
                setup=setup,
                request_id=request_id,
            )
        except BaseException:
            if request_id is not None:
                await self._operations.release(channel_id, request_id)
            raise
        return VerifiedBatchRequest(
            channel_id=channel_id,
            payer=config["payer"],
            kind=payload["type"],
            server_signed=server_signed,
            requirements=requirements,
            channel_config=config,
            ceiling=ceiling,
            reservation_id=reservation_id,
            required_deposit=required,
            voucher=voucher,
            request_id=request_id,
            setup=setup,
        )

    async def _ensure_fresh(
        self,
        rpc: SolanaRpc,
        channel_id: str,
        config: BatchChannelConfig,
        requirements: BatchRequirements,
        *,
        must_exist: bool = True,
    ) -> bool:
        """Re-read the channel unless the stored snapshot is fresh; return whether it exists on chain.

        An unknown channel is rebuilt from chain at its settled watermark with
        no voucher: the most this server can honestly claim it charged.
        """
        record = await self._store.get(channel_id)
        now = self._clock()
        synced = None if record is None else record.onchain_synced_at
        if synced is not None and now - synced <= self._settings.onchain_state_ttl_seconds:
            return True
        channel = await onchain.read_channel(rpc, channel_id, self._program_id)
        if channel is None:
            if must_exist:
                raise BatchSettlementError(
                    errors.INVALID_CHANNEL_STATE, f"no channel {channel_id}; open one with a deposit"
                )
            return False
        check_channel_binding(channel, config, requirements, statuses=tuple(onchain.CHANNEL_STATUSES))

        def sync(current: ChannelRecord | None) -> ChannelRecord:
            # A channel rebuilt from chain starts its idle clock now; an existing one keeps its own.
            base = current or replace(self._new_record(channel_id, config, requirements), last_activity_at=now)
            return onchain.fold(base, channel, now)

        await self._store.update(channel_id, sync)
        return True

    async def _validate_setup(
        self,
        rpc: SolanaRpc,
        deposit: BatchDeposit,
        form: tx_policy.SetupForm,
        config: BatchChannelConfig,
        requirements: BatchRequirements,
        channel_id: str,
        exists: bool,
    ) -> PendingSetup:
        """Statically validate, co-sign in memory and simulate the client's ``open``/``top_up``."""
        amount = parse_u64(deposit["amount"], "deposit.amount")
        token_program = requirements["extra"]["tokenProgram"]
        await onchain.check_mint_owner(rpc, requirements["asset"], token_program)
        fee_payer = self._fee_payer()
        expected = tx_policy.TransactionExpectations(
            fee_payer=fee_payer.pubkey(),
            config=config,
            channel_id=channel_id,
            token_program=token_program,
            receiver=requirements["payTo"],
            memo=requirements["extra"].get("memo"),
            program_id=self._program_id,
        )
        # A landed open is not re-checked against the open-slot window: its
        # openSlot falls behind while the client retries the same bytes.
        recent_slot = await self._current_slot(rpc) if form == "open" and not exists else None
        validated = tx_policy.validate_setup(
            deposit["transaction"], form, expected, deposit_amount=amount, recent_slot=recent_slot
        )
        await onchain.check_settlement_accounts(
            rpc,
            mint=requirements["asset"],
            token_program=token_program,
            owners={
                "payee": fee_payer.pubkey(),
                "treasury": str(treasury_owner()),
                "receiver": requirements["payTo"],
                "payer": validated.payer,
            },
        )
        cosigned = onchain.cosign(validated.transaction, fee_payer)
        signature = str(cosigned.signatures[0])
        status, err = await onchain.signature_status(rpc, signature)
        if status == "failed":
            raise BatchSettlementError(errors.INVALID_SETTLEMENT_SIMULATION, f"setup landed but failed: {err}")
        if status == "pending":
            await onchain.simulate(rpc, cosigned)
        return PendingSetup(
            form=form,
            amount=amount,
            amount_string=deposit["amount"],
            payer_signature=str(validated.transaction.signatures[1]),
            transaction=cosigned,
            signature=signature,
        )

    async def _reserve(
        self,
        channel_id: str,
        config: BatchChannelConfig,
        requirements: BatchRequirements,
        *,
        kind: Literal["client", "server"],
        ceiling: int,
        voucher: BatchVoucher | None,
        max_claimable: int | None,
        setup: PendingSetup | None,
        request_id: str | None = None,
    ) -> tuple[str, int]:
        """Atomically check state, cumulative and capacity, and hold ``ceiling``; return (id, required deposit)."""
        now = self._clock()
        reservation_id = uuid.uuid4().hex
        required = [0]

        def reserve(current: ChannelRecord | None) -> ChannelRecord:
            if current is None and setup is None:
                raise BatchSettlementError(errors.INVALID_CHANNEL_STATE, f"no channel {channel_id}")
            record = current or self._new_record(channel_id, config, requirements)
            _require_config(record, config)
            _require_open(record)
            live = record.live_reservations(now)
            # A client-signed (or close) request needs the channel to itself;
            # server-signed requests share it with other server-signed ones.
            if (kind != "server" and live) or any(r.kind != "server" for r in live.values()):
                raise BatchSettlementError(errors.DUPLICATE_SETTLEMENT, f"channel {channel_id} is busy")
            # A server-signed request can reach at most its ceiling on top of
            # what was charged; a client voucher states its cumulative.
            claim = record.charged_cumulative + ceiling if max_claimable is None else max_claimable
            if voucher is not None:
                if claim == record.charged_cumulative and voucher["signature"] == record.voucher_signature:
                    raise _ReplayedVoucher(errors.DUPLICATE_SETTLEMENT, f"voucher for {claim} was already accepted")
                check_cumulative(
                    claim,
                    voucher["signature"],
                    charged=record.charged_cumulative,
                    amount=ceiling,
                    signed_signature=record.voucher_signature,
                )
            deposit = record.deposit
            if setup is not None and setup.payer_signature not in record.processed_setup_signatures:
                deposit += setup.amount
            reserved = sum(r.ceiling for r in live.values())
            check_capacity(
                max_claimable=claim,
                charged=record.charged_cumulative,
                reserved=reserved,
                ceiling=ceiling,
                deposit=deposit,
            )
            required[0] = max(claim, record.charged_cumulative + reserved + ceiling)
            expires_at = now + max(_MIN_RESERVATION_SECONDS, requirements["maxTimeoutSeconds"])
            live[reservation_id] = Reservation(ceiling, kind, expires_at, request_id)
            return replace(record, reservations=live)

        try:
            await self._store.update(channel_id, reserve)
        except _ReplayedVoucher as exc:
            # Its response was lost: prove the charge so the client can confirm it and move on.
            corrective = await self._corrective(channel_id, requirements)
            raise CorrectiveRequired(exc.detail, [corrective], errors.DUPLICATE_SETTLEMENT) from None
        except BatchSettlementError as exc:
            if exc.code != errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH:
                raise
            raise CorrectiveRequired(exc.detail, [await self._corrective(channel_id, requirements)]) from None
        return reservation_id, required[0]

    async def _corrective(self, channel_id: str, requirement: BatchRequirements) -> BatchRequirements:
        """The requirement plus ``channelState`` and, when the server holds one, the ``voucherState`` proof."""
        record = await self._store.get(channel_id)
        corrective = cast("BatchRequirements", json.loads(json.dumps(requirement)))
        if record is None:
            return corrective
        corrective["extra"]["channelState"] = _snapshot(record)
        if record.voucher_signature is not None:
            corrective["extra"]["voucherState"] = {
                "signedMaxClaimable": str(record.signed_max_claimable),
                "expiresAt": 0,
                "signature": record.voucher_signature,
            }
        return corrective

    # -- commit / release (after the handler) ------------------------------------------

    async def commit(self, verified: VerifiedBatchRequest, actual: int | None = None) -> BatchSettlementResponse:
        """Charge the verified request after its handler succeeded; broadcast its setup first, if any.

        Client-signed requests charge exactly the price their voucher covers.
        Server-signed requests charge the metered ``actual`` (``0 <= actual <=
        ceiling``) and get an operator-signed voucher for the new cumulative; a
        missing charge (``None``) fails closed: the reservation is released and
        nothing is served, while an explicit ``0`` serves at the unchanged
        cumulative.
        """
        if verified.server_signed and actual is None:
            await self.release(verified)
            raise BatchSettlementError("settlement_failed", "usage Charge must be called before the handler returns")
        charge_amount = verified.ceiling if actual is None else actual
        exact = verified.server_signed or charge_amount == verified.ceiling
        if not exact or not 0 <= charge_amount <= verified.ceiling:
            await self.release(verified)
            raise BatchSettlementError(
                errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                f"charge {charge_amount} is not allowed for a ceiling of {verified.ceiling}",
            )
        channel: Channel | None = None
        if verified.setup is not None:
            # Nothing irreversible for a request whose lease is already gone.
            await self._require_reservation(verified)
            channel = await self._broadcast_setup(verified)
            # The escrow landed: record it whether or not the charge below can
            # still be made, so a retry of the same bytes is never counted twice.
            await self._record_after_broadcast(
                "setup_after_broadcast",
                verified.channel_id,
                lambda current: self._with_setup(current, verified, channel),
            )
        now = self._clock()
        issued: list[BatchVoucher] = []

        def charge(current: ChannelRecord | None) -> ChannelRecord:
            if current is None:
                raise BatchSettlementError(errors.DUPLICATE_SETTLEMENT, "reservation expired or was released")
            record = current if channel is None else self._with_setup(current, verified, channel)
            reservation = record.reservations.get(verified.reservation_id)
            if reservation is None or reservation.expires_at <= now:
                raise BatchSettlementError(errors.DUPLICATE_SETTLEMENT, "reservation expired or was released")
            if record.status in ("sealed", "distributed"):
                raise BatchSettlementError(
                    errors.INVALID_CLOSE_STATE, f"channel {record.channel_id} is {record.status}"
                )
            cumulative = record.charged_cumulative + charge_amount
            if cumulative > record.deposit:
                raise BatchSettlementError(
                    errors.INVALID_CUMULATIVE_EXCEEDS_DEPOSIT, f"{cumulative} is over the deposit {record.deposit}"
                )
            if verified.server_signed:
                voucher = sign_voucher(self._operator(), verified.channel_id, cumulative)
            else:
                voucher = verified.voucher
                assert voucher is not None  # client-signed requests always carry one
                if int(voucher["maxClaimableAmount"]) != cumulative:
                    raise BatchSettlementError(errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH, "channel moved since verify")
            issued.append(voucher)
            return replace(
                _without(record, verified.reservation_id),
                charged_cumulative=cumulative,
                signed_max_claimable=cumulative,
                voucher_signature=voucher["signature"],
                last_activity_at=now,
            )

        record: ChannelRecord | None
        try:
            record = await self._store.update(verified.channel_id, charge)
        except BatchSettlementError:
            # The request cannot be charged (lease gone, channel sealed or
            # moved): nothing may be served for it.
            await self.release(verified)
            raise
        except Exception as exc:
            if channel is None:
                raise  # nothing irreversible happened: a failed write must not serve
            self._alert("commit_after_deposit", verified.channel_id, exc)  # the escrow landed: alert, never re-raise
            record = None
        if record is None:
            assert channel is not None
            state: BatchChannelState = {
                "channelId": verified.channel_id,
                "balance": str(int(channel.deposit)),
                "totalClaimed": str(int(channel.settlement.settled)),
                "withdrawRequestedAt": int(channel.closureStartedAt),
            }
            if verified.voucher is not None:
                state["chargedCumulativeAmount"] = verified.voucher["maxClaimableAmount"]
            # A server-signed request cannot be given a voucher without the
            # stored cumulative; the client restores its state and resyncs.
            return self._accepted(verified, state, verified.voucher)
        if verified.request_id is not None:
            try:
                await self._operations.complete(
                    verified.channel_id,
                    verified.request_id,
                    ceiling=verified.ceiling,
                    actual=charge_amount,
                    cumulative=record.charged_cumulative,
                )
            except Exception as exc:  # noqa: BLE001 - the charge is recorded; the request id stays consumed
                self._alert("operation_complete", verified.channel_id, exc)
        return self._accepted(verified, _snapshot(record), issued[-1])

    async def _require_reservation(self, verified: VerifiedBatchRequest) -> None:
        """Refuse (release + 402) a request whose reservation expired or was dropped meanwhile."""
        current = await self._store.get(verified.channel_id)
        reservation = None if current is None else current.reservations.get(verified.reservation_id)
        if reservation is None or reservation.expires_at <= self._clock():
            await self.release(verified)
            raise BatchSettlementError(errors.DUPLICATE_SETTLEMENT, "reservation expired or was released")

    def _with_setup(
        self, current: ChannelRecord | None, verified: VerifiedBatchRequest, channel: Channel
    ) -> ChannelRecord:
        """Fold a confirmed setup into the record: the chain's escrow, the payer signature, the open signature."""
        base = current or self._new_record(verified.channel_id, verified.channel_config, verified.requirements)
        record = onchain.fold(base, channel, self._clock())
        setup = verified.setup
        assert setup is not None
        processed = record.processed_setup_signatures
        if setup.payer_signature not in processed:
            processed = [*processed, setup.payer_signature]
        opened = setup.signature if setup.form == "open" else record.open_signature
        return replace(record, processed_setup_signatures=processed, open_signature=opened)

    async def _broadcast_setup(self, verified: VerifiedBatchRequest) -> Channel:
        """Send the co-signed setup, wait for it, and bind the confirmed channel before charging against it."""
        setup = verified.setup
        assert setup is not None
        async with self._rpc_scope() as rpc:
            try:
                await onchain.broadcast_setup(rpc, setup.transaction)
            except onchain.UnconfirmedBroadcast as exc:
                # The same bytes may still land; the client retries them verbatim.
                await self.release(verified)
                raise BatchSettlementError(
                    errors.INVALID_SETTLEMENT_SIMULATION, f"setup not confirmed: {exc}"
                ) from None
            except BatchSettlementError:
                await self.release(verified)
                raise
            channel = await read_with_replica_retry(
                lambda: onchain.read_channel(rpc, verified.channel_id, self._program_id)
            )
        try:
            if channel is None:
                raise BatchSettlementError(errors.INVALID_CHANNEL_STATE, "confirmed channel is not visible")
            check_channel_binding(channel, verified.channel_config, verified.requirements)
            # The escrow must cover what was reserved against it: that is what
            # the program enforces at settle, and it stays true when a retry
            # re-confirms a deposit that had already landed.
            if int(channel.deposit) < verified.required_deposit:
                raise BatchSettlementError(
                    errors.INVALID_CHANNEL_STATE,
                    f"confirmed deposit {channel.deposit} is below the reserved {verified.required_deposit}",
                )
        except BatchSettlementError:
            await self.release(verified)
            raise
        return channel

    async def release(self, verified: VerifiedBatchRequest) -> None:
        """Drop the request's reservation (handler failed or was cancelled); idempotent.

        A server-signed request id stays consumed: its operation is tombstoned.
        """
        with contextlib.suppress(BatchSettlementError):  # already gone
            await self._store.update(verified.channel_id, lambda current: _without(current, verified.reservation_id))
        # A failed open leaves a provisional record that holds nothing: forget it.
        await self._store.delete_if(verified.channel_id, _holds_nothing)
        if verified.request_id is not None:
            await self._operations.release(verified.channel_id, verified.request_id)

    def _accepted(
        self, verified: VerifiedBatchRequest, state: BatchChannelState, voucher: BatchVoucher | None
    ) -> BatchSettlementResponse:
        setup = verified.setup
        extra: BatchSettlementExtra = {"channelState": state}
        if voucher is not None:
            extra["commitmentId"] = commitment_id(verified.channel_id, voucher["maxClaimableAmount"])
            if verified.server_signed:
                extra["voucher"] = voucher
        if not verified.server_signed:
            extra["chargedAmount"] = verified.requirements["amount"]
        return {
            "success": True,
            "transaction": setup.signature if setup is not None else "",
            "network": verified.requirements["network"],
            "amount": setup.amount_string if setup is not None else "",
            "payer": verified.payer,
            "extra": extra,
        }

    # -- refund (handler bypassed) ------------------------------------------------------

    async def _refund(
        self, transaction: str, config: BatchChannelConfig, requirements: BatchRequirements, channel_id: str
    ) -> BatchSettlementResponse:
        """Co-sign the payer's ``request_close``, claiming the latest charged voucher first.

        A channel already ``Closing`` returns its observed state without a
        rebroadcast, so a retried refund is idempotent. The close holds the
        channel to itself: no paid request can be in flight.
        """
        fee_payer = self._fee_payer()
        validated = tx_policy.validate_request_close(
            transaction,
            tx_policy.TransactionExpectations(
                fee_payer=fee_payer.pubkey(),
                config=config,
                channel_id=channel_id,
                token_program=requirements["extra"]["tokenProgram"],
                receiver=requirements["payTo"],
                memo=requirements["extra"].get("memo"),
                program_id=self._program_id,
            ),
        )
        now = self._clock()
        hold = uuid.uuid4().hex
        async with self._rpc_scope() as rpc:
            channel = await onchain.read_channel(rpc, channel_id, self._program_id)
            if channel is None:
                raise BatchSettlementError(errors.INVALID_CHANNEL_STATE, f"channel {channel_id} does not exist")
            if int(channel.status) not in (CHANNEL_STATUS_OPEN, CHANNEL_STATUS_CLOSING):
                raise BatchSettlementError(errors.INVALID_CLOSE_STATE, f"channel status {channel.status} cannot close")
            check_channel_binding(channel, config, requirements, statuses=(CHANNEL_STATUS_OPEN, CHANNEL_STATUS_CLOSING))
            # The close pays out through these accounts once the grace period ends.
            await onchain.check_settlement_accounts(
                rpc,
                mint=requirements["asset"],
                token_program=requirements["extra"]["tokenProgram"],
                owners={
                    "payee": fee_payer.pubkey(),
                    "treasury": str(treasury_owner()),
                    "receiver": requirements["payTo"],
                    "payer": validated.payer,
                },
            )

            seen = channel

            def hold_close(current: ChannelRecord | None) -> ChannelRecord:
                record = onchain.fold(current or self._new_record(channel_id, config, requirements), seen, now)
                _require_config(record, config)
                if record.live_reservations(now):
                    raise BatchSettlementError(errors.DUPLICATE_SETTLEMENT, f"channel {channel_id} is busy")
                expires_at = now + max(_MIN_RESERVATION_SECONDS, requirements["maxTimeoutSeconds"])
                return replace(record, reservations={hold: Reservation(0, "close", expires_at)})

            record = await self._store.update(channel_id, hold_close)
            signature = ""
            try:
                if int(channel.status) == CHANNEL_STATUS_OPEN:
                    await self._claim_before_close(rpc, record, fee_payer)
                    close = onchain.cosign(validated.transaction, fee_payer)
                    await onchain.simulate(rpc, close)
                    signature = await onchain.broadcast_setup(rpc, close)
                    observed = await read_with_replica_retry(
                        lambda: onchain.read_channel(rpc, channel_id, self._program_id)
                    )
                    if observed is None or int(observed.status) != CHANNEL_STATUS_CLOSING:
                        raise BatchSettlementError(
                            errors.INVALID_CLOSE_STATE, "request_close did not move the channel to Closing"
                        )
                    channel = observed
            except onchain.UnconfirmedBroadcast as exc:
                await self._store.update(channel_id, lambda current: _without(current, hold))
                raise BatchSettlementError(
                    errors.INVALID_SETTLEMENT_SIMULATION, f"refund not confirmed; retry the same request_close: {exc}"
                ) from None
            except BaseException:
                await self._store.update(channel_id, lambda current: _without(current, hold))
                raise
        closed = channel

        def mark_closing(current: ChannelRecord | None) -> ChannelRecord:
            record = onchain.fold(_without(current, hold), closed, self._clock())
            return replace(record, close_signature=signature or record.close_signature)

        if signature:
            record = await self._record_after_broadcast("refund", channel_id, mark_closing) or record
        else:
            record = await self._store.update(channel_id, mark_closing)
        return {
            "success": True,
            # The grace period may still be running: nothing has moved back to
            # the payer yet, so no amount is claimed.
            "transaction": signature,
            "network": requirements["network"],
            "amount": "",
            "payer": config["payer"],
            "extra": {"channelState": _snapshot(record)},
        }

    async def _claim_before_close(self, rpc: SolanaRpc, record: ChannelRecord, fee_payer: LocalSigner) -> None:
        """Redeem the latest charged voucher before the payer's close freezes ``settled``."""
        signature = record.voucher_signature
        signed = record.signed_max_claimable
        if signature is None or signed <= record.settled:
            return
        if signed > record.charged_cumulative:
            # Never claim what was not charged.
            self._alert("claim_above_charged", record.channel_id, ValueError(f"{signed} > {record.charged_cumulative}"))
            return
        instructions = onchain.claim_instructions(
            channel_id=record.channel_id,
            payer_authorizer=record.channel_config["payerAuthorizer"],
            signature=signature,
            cumulative=signed,
            program_id=self._program_id,
        )
        await onchain.submit(rpc, fee_payer, instructions)

    async def _record_after_broadcast(
        self, event: str, channel_id: str, mutator: Callable[[ChannelRecord | None], ChannelRecord]
    ) -> ChannelRecord | None:
        """Write after an irreversible broadcast: a failure is logged and alerted, never re-raised."""
        try:
            return await self._store.update(channel_id, mutator)
        except Exception as exc:  # noqa: BLE001 - the broadcast already landed
            self._alert(event, channel_id, exc)
            return None

    # -- internals -------------------------------------------------------------------

    def _fee_payer(self) -> LocalSigner:
        signer = self._config.effective_x402_signer()
        if signer is None:
            raise ConfigurationError("solana_pay_kit: x402 batch-settlement requires a fee payer signer")
        return signer

    def _new_record(
        self, channel_id: str, config: BatchChannelConfig, requirements: BatchRequirements
    ) -> ChannelRecord:
        return ChannelRecord(
            channel_id=channel_id,
            channel_config=config,
            network=requirements["network"],
            fee_payer=requirements["extra"]["feePayer"],
            token_program=requirements["extra"]["tokenProgram"],
        )

    def redemption(self) -> BatchRedemption:
        """The redemption worker over this engine's channel store (claim, distribute, seal, close, reclaim)."""
        self._pay_to.add(self._config.effective_recipient())
        return BatchRedemption(
            store=self._store,
            rpc_scope=self._rpc_scope,
            fee_payer=self._fee_payer(),
            close_authorizer=self._close_authorizer(),
            settings=RedemptionSettings(
                max_timeout_seconds=self._settings.max_timeout_seconds,
                max_idle_secs=self._settings.max_idle_secs,
                batch_size=self._settings.max_channels_per_batch,
                network=self._config.network.caip2(),
                pay_to=self._pay_to,  # live: grows as routes advertise their payTo
                operator=None if self._settings.operator is None else self._settings.operator.pubkey(),
                receiver_authorizer=self._settings.receiver_authorizer,
            ),
            program_id=self._program_id,
            clock=self._clock,
            alert=self._alert,
            operations=self._operations,
        )

    def _close_authorizer(self) -> LocalSigner:
        return self._settings.close_authorizer or self._fee_payer()

    def _operator(self) -> LocalSigner:
        operator = self._settings.operator
        if operator is None:
            raise ConfigurationError("solana_pay_kit: server-signed batch-settlement needs an operator signer")
        return operator

    def _accepts(self, gate: Gate, voucher_signer: VoucherSigner | None) -> list[BatchRequirements]:
        """The route's accepts without hints: client-signed first, then server-signed when an operator is set."""
        operator = self._settings.operator
        if voucher_signer == "server" and operator is None:
            raise ConfigurationError('solana_pay_kit: voucher_signer="server" needs BatchSettlementConfig.operator')
        accepts: list[BatchRequirements] = []
        if voucher_signer != "server":
            accepts.append(self._requirement(gate, server_signed=False))
        if operator is not None and voucher_signer != "client":
            server = self._requirement(gate, server_signed=True)
            server["extra"]["voucherSigner"] = "server"
            server["extra"]["operator"] = operator.pubkey()
            accepts.append(server)
        return accepts

    def _check_min_deposit(self, deposit: BatchDeposit, requirements: BatchRequirements) -> None:
        hint = requirements["extra"].get("minDeposit")
        amount = parse_u64(deposit["amount"], "deposit.amount")
        if self._settings.enforce_min_deposit and hint is not None and amount < int(hint):
            raise BatchSettlementError(errors.INVALID_DEPOSIT_BELOW_MIN_DEPOSIT, f"deposit {amount} is below {hint}")

    def _requirement(self, gate: Gate, *, server_signed: bool = False) -> BatchRequirements:
        """The route's client-signed requirement without construction hints."""
        coin = gate.amount.primary_coin()
        coin_value = coin.value if coin is not None else self._config.stablecoins[0].value
        label = self._config.network.mints_label()
        asset = resolve(coin_value, label)
        if not asset:
            raise ConfigurationError(f"solana_pay_kit: x402 batch-settlement needs an SPL mint for {coin_value!r}")
        try:
            amount = parse_units(gate.total().amount_string(), _DECIMALS)
            amount_units = int(amount)
        except ValueError as exc:
            raise ConfigurationError(f"solana_pay_kit: batch price exceeds {_DECIMALS}-decimal precision") from exc
        pay_to = gate.pay_to or self._config.effective_recipient()
        if len(self._pay_to) < _MAX_REMEMBERED_PAY_TO:
            self._pay_to.add(pay_to)
        requirement: BatchRequirements = {
            "scheme": BATCH_SETTLEMENT_SCHEME,
            "network": self._config.network.caip2(),
            "amount": str(amount),
            "asset": asset,
            "payTo": pay_to,
            "maxTimeoutSeconds": self._settings.max_timeout_seconds,
            "extra": {
                "feePayer": self._fee_payer().pubkey(),
                "withdrawDelay": self._settings.effective_withdraw_delay(),
                "tokenProgram": token_program_for(coin_value, label),
            },
        }
        if self._settings.receiver_authorizer is not None:
            requirement["extra"]["receiverAuthorizer"] = self._settings.receiver_authorizer
        override = self._settings.min_deposit
        multiple = _SERVER_MIN_DEPOSIT_MULTIPLE if server_signed else _CLIENT_MIN_DEPOSIT_MULTIPLE
        minimum = amount_units * multiple if override is None else _atomic_min_deposit(override)
        requirement["extra"]["minDeposit"] = str(max(minimum, amount_units))
        idle = self._settings.max_idle_secs
        if idle is not None and idle > 0:
            # Clients learn how long an unused channel stays open.
            requirement["extra"]["maxIdleSecs"] = idle
        return requirement

    def _match_accepted(self, envelope: BatchPaymentPayload, accepts: list[BatchRequirements]) -> BatchRequirements:
        """The route accept the payload answers; every bound field must match (a foreign offer is refused)."""
        accepted = cast("Mapping[str, Any]", envelope["accepted"])
        extra = cast("Mapping[str, Any]", accepted["extra"])
        for requirement in accepts:
            route = cast("Mapping[str, Any]", requirement)
            route_extra = cast("Mapping[str, Any]", requirement["extra"])
            if all(accepted[f] == route[f] for f in _BOUND_FIELDS) and all(
                extra.get(f) == route_extra.get(f) for f in _BOUND_EXTRA
            ):
                return requirement
        raise BatchSettlementError(errors.INVALID_CHANNEL_STATE, "accepted does not match this route's requirements")

    def _recent_state(self) -> tuple[str | None, int | None]:
        if self._recent_state_provider is None:
            return None, None
        try:
            value = self._recent_state_provider()
        except Exception:  # noqa: BLE001 - hints are optional; never fail a challenge on them
            return None, None
        if value is None:
            return None, None
        blockhash, slot = value
        blockhash = blockhash if isinstance(blockhash, str) and blockhash else None
        slot = slot if isinstance(slot, int) and not isinstance(slot, bool) and slot >= 0 else None
        return blockhash, slot

    async def _current_slot(self, rpc: SolanaRpc) -> int | None:
        # The challenge's recentSlot comes from the getLatestBlockhash context,
        # so the check reads the same source (as Rust does): getSlot can trail
        # it by a slot and refuse the hint this server just issued.
        try:
            context = (await rpc.get_latest_blockhash()).context
            slot = None if context is None else context.slot
            return slot if slot is not None else await rpc.get_slot()
        except Exception:  # noqa: BLE001 - the program still enforces the window at broadcast
            return None

    @asynccontextmanager
    async def _rpc_scope(self) -> AsyncGenerator[SolanaRpc]:
        # One client per operation unless injected: the Flask and Django shims
        # run a fresh event loop per request, and an httpx client is loop-bound.
        if self._rpc is not None:
            yield self._rpc
            return
        rpc = SolanaRpc(self._config.effective_rpc_url())
        try:
            yield rpc
        finally:
            await rpc.aclose()

    def _alert(self, event: str, channel_id: str, exc: BaseException) -> None:
        """Log and report a failure that must not be re-raised (after an irreversible broadcast)."""
        details = {"channelId": channel_id, "error": repr(exc)}
        logger.error("x402 batch-settlement %s failed for %s: %r", event, channel_id, exc)
        if self._on_alert is not None:
            try:
                self._on_alert(event, details)
            except Exception:  # noqa: BLE001 - an alert hook must never break settlement
                logger.exception("x402 batch-settlement alert hook failed")


def _without(current: ChannelRecord | None, reservation_id: str) -> ChannelRecord:
    if current is None:
        raise BatchSettlementError(errors.INVALID_CHANNEL_STATE, "channel vanished")
    return replace(current, reservations={k: v for k, v in current.reservations.items() if k != reservation_id})


def _holds_nothing(record: ChannelRecord) -> bool:
    """A record that never saw escrow, a charge, a voucher, a chain read or a setup, and holds no reservation."""
    return (
        record.deposit == 0
        and record.charged_cumulative == 0
        and record.voucher_signature is None
        and record.onchain_synced_at is None
        and not record.processed_setup_signatures
        and not record.reservations
    )


def _require_config(record: ChannelRecord, config: BatchChannelConfig) -> None:
    if record.channel_config != config:
        raise BatchSettlementError(errors.INVALID_CHANNEL_STATE, "channelConfig differs from the stored one")


def _require_open(record: ChannelRecord) -> None:
    if record.status == "closing":
        raise BatchSettlementError(errors.INVALID_CHANNEL_CLOSING, f"channel {record.channel_id} is closing")
    if record.status != "open":
        raise BatchSettlementError(errors.INVALID_CLOSE_STATE, f"channel {record.channel_id} is {record.status}")


def _b64json(value: object) -> str:
    return base64.b64encode(json.dumps(value, separators=(",", ":")).encode("utf-8")).decode("ascii")


def _decode_header(header: str) -> dict[str, Any]:
    try:
        envelope = json.loads(base64.b64decode(header, validate=True))
    except (binascii.Error, ValueError) as exc:
        raise BatchSettlementError(errors.INVALID_PAYLOAD_TYPE, f"undecodable payment header: {exc}") from None
    if not isinstance(envelope, dict):
        raise BatchSettlementError(errors.INVALID_PAYLOAD_TYPE, "payment header is not a JSON object")
    return cast("dict[str, Any]", envelope)


def _payment_header(request: Any) -> str:
    headers: Any = getattr(request, "headers", None)
    if headers is None and isinstance(request, Mapping):
        headers = cast("Mapping[str, Any]", request).get("headers")
    if isinstance(headers, Mapping) or hasattr(headers, "get"):
        lowered = {str(k).lower(): v for k, v in cast("Mapping[str, Any]", headers).items()}
        for name in _PAYMENT_HEADERS:
            value = lowered.get(name)
            if value:
                return str(value)
    raise BatchSettlementError(errors.INVALID_PAYLOAD_TYPE, "missing PAYMENT-SIGNATURE header")


def _request_path(request: Any) -> str:
    path = getattr(request, "path", None)
    if isinstance(path, str):
        return path
    url_path = getattr(getattr(request, "url", None), "path", None)
    if isinstance(url_path, str):
        return url_path
    if isinstance(request, Mapping):
        candidate = cast("Mapping[str, Any]", request).get("path")
        if isinstance(candidate, str):
            return candidate
    return "/"
