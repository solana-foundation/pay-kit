"""x402 ``batch-settlement`` (Solana) client: channel tracker, payments and refunds.

The client opens one escrow channel per server terms, then pays each request
with a cumulative voucher it signs (client-signed mode) or an expiring payer
proof the operator meters against (server-signed mode, only for operators the
:class:`~.trust.ServerSignedChannelsPolicy` trusts). Mirrors the x402 PR #23
``client/scheme.ts`` and stays byte-compatible with the pay-kit Rust server.

The local watermark advances only on a confirmed ``PAYMENT-RESPONSE``: a payment
payload is an authorization, not a receipt. Payments on one channel run one at
a time: the next waits until the previous one is answered or its lease runs
out. A failed request restores the confirmed state, and a corrective 402 is
adopted only against proof read from the chain: the client's own voucher
signature, or the channel's settled watermark.

Money rules: integers only; the deposit is sized from a configured amount, a
valid ``minDeposit`` hint or ``amount x multiplier``, clamped to the spend
ceiling and, in server-signed mode, to the trust grant. The grant is charged
against every escrow amount this client ever signed for the channel, never only
what was confirmed, so a lost response cannot let an operator push it further.
Salt defaults to 0 and an existing channel is discovered on chain before a
second one is funded.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import secrets
import time
import uuid
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from typing import Any, Protocol, cast

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.paymentchannels import (
    CHANNEL_PAYER_OFFSET,
    PAYMENT_CHANNELS_PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    TopUpParams,
    build_open_instruction,
    build_request_close_instruction,
    build_top_up_instruction,
    distribution_hash,
    find_channel_pda,
)
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.solana import MEMO_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit._paycore.transaction import build_partially_signed_v0_transaction
from solana_pay_kit.errors import ConfigurationError
from solana_pay_kit.protocols.x402.batch_settlement import errors, onchain
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.signatures import (
    sign_authorization,
    sign_voucher,
    verify_voucher,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    PAYMENT_FLOW_AUTHORIZATION,
    U64_MAX,
    BatchChannelConfig,
    BatchPayload,
    BatchPaymentPayload,
    BatchRequirements,
    BatchSettlementResponse,
    VoucherSigner,
    parse_requirements,
    parse_u64,
)
from solana_pay_kit.protocols.x402.batch_settlement.verify import CHANNEL_STATUS_OPEN, check_withdraw_delay
from solana_pay_kit.protocols.x402.client.batch_settlement.trust import (
    ServerSignedChannelsPolicy,
    ServerSignedGrant,
    ServerSignedTrust,
    UntrustedOperatorError,
    client_signed_fallback,
)
from solana_pay_kit.signer import LocalSigner

__all__ = [
    "BatchSettlementClient",
    "ClientChannelRecord",
    "ClientChannelStore",
    "MemoryClientChannelStore",
    "PendingAllocation",
]

_X402_VERSION = 2
_DEFAULT_MULTIPLIER = 5
_MEMO_NONCE_BYTES = 16
# The server holds a client-signed request for max(5, maxTimeoutSeconds).
_MIN_LEASE_SECONDS = 5


@dataclass
class PendingAllocation:
    """A payment sent but not yet confirmed; replayable after a restart until ``expires_at``."""

    amount: str
    cumulative: int
    deposit: int
    operation_key: str
    payment: BatchPaymentPayload
    expires_at: float = 0.0


def _no_pending() -> list[PendingAllocation]:
    return []


@dataclass
class ClientChannelRecord:
    """A channel's confirmed allocation plus any in-flight ones; all amounts atomic ``int``."""

    channel_id: str
    channel_config: BatchChannelConfig
    charged_cumulative: int
    deposit: int
    has_confirmed_state: bool = True
    pending: list[PendingAllocation] = field(default_factory=_no_pending)
    #: Every open/top-up amount this client signed for the channel; never lowered.
    signed_deposit: int = 0
    #: Server mode: ceilings of payer proofs never validly answered (the operator may have charged them).
    unobserved: int = 0
    #: Server mode: blockhash of an open that failed but may still land; blocks a second open until it expires.
    open_blockhash: str | None = None


class ClientChannelStore(Protocol):
    """Durable storage for client channel records, keyed by server terms."""

    async def get(self, key: str) -> ClientChannelRecord | None:
        """The record for ``key``, or ``None``."""
        ...

    async def set(self, key: str, record: ClientChannelRecord) -> None:
        """Store ``record`` under ``key``."""
        ...

    async def delete(self, key: str) -> None:
        """Forget ``key``."""
        ...


class MemoryClientChannelStore:
    """Process-local :class:`ClientChannelStore`."""

    def __init__(self) -> None:
        self.records: dict[str, ClientChannelRecord] = {}

    async def get(self, key: str) -> ClientChannelRecord | None:
        return self.records.get(key)

    async def set(self, key: str, record: ClientChannelRecord) -> None:
        self.records[key] = record

    async def delete(self, key: str) -> None:
        self.records.pop(key, None)


@dataclass(frozen=True)
class _Channel:
    channel_id: str
    config: BatchChannelConfig
    cumulative: int
    deposit: int
    signed_deposit: int = 0
    unobserved: int = 0
    open_blockhash: str | None = None

    def __post_init__(self) -> None:
        # Whatever built the channel (discovery, a corrective, a landed open, a
        # stored record), this client signed at least the escrow the chain holds.
        if self.signed_deposit < self.deposit:
            object.__setattr__(self, "signed_deposit", self.deposit)


@dataclass
class _Pending:
    key: str
    operation_key: str
    amount: str
    cumulative: int
    deposit: int
    channel: _Channel
    confirmed: _Channel | None
    payment: BatchPaymentPayload
    expires_at: float


@dataclass(frozen=True)
class _Terms:
    fee_payer: str
    token_program: str
    withdraw_delay: int
    memo: str | None
    receiver_authorizer: str | None
    voucher_signer: VoucherSigner
    operator: str | None
    grant: ServerSignedGrant | None
    max_timeout: int


class BatchSettlementClient:
    """Pays ``batch-settlement`` routes from one escrow channel per server terms."""

    def __init__(
        self,
        signer: LocalSigner,
        *,
        rpc_url: str | None = None,
        rpc: SolanaRpc | None = None,
        deposit_amount: int | None = None,
        deposit_multiplier: int = _DEFAULT_MULTIPLIER,
        max_amount_per_payment: int | None = None,
        channel_store: ClientChannelStore | None = None,
        salt: int = 0,
        discover_channels: bool = True,
        server_signed_channels_policy: ServerSignedChannelsPolicy | None = None,
        clock: Any = time.time,
        program_id: str | None = None,
    ) -> None:
        """Configure the client; ``rpc`` (or ``rpc_url``) reads the mint owner, blockhash, slot and channels.

        Without ``channel_store`` every record lives in this process only. A
        restart rediscovers the channel on chain (its deposit still counts
        against the trust grant) but forgets a server-signed open that failed
        and may still land, so a second channel can be funded for the same
        terms. Configure a store to keep that memory across restarts.
        """
        if isinstance(deposit_multiplier, bool) or deposit_multiplier < 3:  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ConfigurationError("deposit_multiplier must be an integer >= 3")
        if not 0 <= salt <= U64_MAX:
            raise ConfigurationError("salt must fit in a u64")
        if rpc is None and rpc_url is None:
            raise ConfigurationError("BatchSettlementClient needs rpc or rpc_url")
        self._signer = signer
        self._rpc = rpc
        self._rpc_url = rpc_url
        self._deposit_amount = deposit_amount
        self._multiplier = deposit_multiplier
        self._max_per_payment = max_amount_per_payment
        self._store = channel_store
        self._salt = salt
        self._discover_channels = discover_channels
        self._trust = ServerSignedTrust(server_signed_channels_policy)
        # With a trust policy, trusted metered accepts are preferred over the
        # route's client-signed accept (which a pay-kit server lists first).
        self._trusts_operators = bool(server_signed_channels_policy and server_signed_channels_policy.allowed_operators)
        self._clock = clock
        self._program_id = Pubkey.from_string(
            program_id or os.environ.get("PAYMENT_CHANNELS_PROGRAM_ID") or PAYMENT_CHANNELS_PROGRAM_ID
        )
        self._channels: dict[str, _Channel] = {}
        self._pending: dict[str, _Pending] = {}
        # Server mode: opens that failed but may still land, keyed like _channels.
        self._unlanded: dict[str, _Channel] = {}
        # ponytail: per-process locks; two processes paying one channel still
        # race (the server's duplicate/corrective answers resync them).
        self._locks: dict[str, asyncio.Lock] = {}
        self._resolved: dict[str, asyncio.Event] = {}

    # -- selection -------------------------------------------------------------------------

    def payment_policy(self, accepts: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        """Drop untrusted server-signed accepts and prefer trusted ones (metered pricing) per network."""
        return self._trust.filter_accepts(accepts)

    async def create_payment_header(
        self, payment_required: Mapping[str, Any]
    ) -> tuple[BatchPaymentPayload, Mapping[str, Any]]:
        """Pay the first usable ``batch-settlement`` accept of a 402; return the payload and the accept paid.

        With a trust policy the accepts first go through :meth:`payment_policy`.
        A server-signed accept this client does not trust falls back to the same
        resource's client-signed accept, on the same network and asset and for
        no more than the refused amount.
        """
        accepts = cast("list[Mapping[str, Any]]", payment_required.get("accepts") or [])
        if self._trusts_operators:
            accepts = self.payment_policy(accepts)
        batch = [a for a in accepts if a.get("scheme") == "batch-settlement"]
        if not batch:
            raise BatchSettlementError(errors.INVALID_PAYLOAD_TYPE, "402 offers no batch-settlement accept")
        chosen = batch[0]
        try:
            return await self.create_payment_payload(chosen), chosen
        except UntrustedOperatorError:
            fallback = client_signed_fallback(payment_required, chosen)
            if fallback is None:
                raise
            return await self.create_payment_payload(fallback), fallback

    # -- payments --------------------------------------------------------------------------

    async def create_payment_payload(self, requirements: Mapping[str, Any]) -> BatchPaymentPayload:
        """Build the payment for one request: open, top up, or a plain voucher / payer proof.

        Waits while another payment on the same channel is unanswered: a
        cumulative voucher is only derivable from an exact confirmed watermark.
        """
        req = _parse(requirements)
        async with self._rpc_scope() as rpc:
            terms = await self._terms(rpc, req)
            charge = parse_u64(req["amount"], "amount")
            if charge == 0:
                raise ValueError("batch-settlement amount must be positive")
            if self._max_per_payment is not None and self._max_per_payment > 0 and charge > self._max_per_payment:
                raise ValueError(f"amount {charge} exceeds max_amount_per_payment {self._max_per_payment}")
            key = self._key(req, terms)
            async with self._lock_for(key):
                await self._load(key)
                await self._await_in_flight(key)
                existing = self._channels.get(key) or await self._recover_unlanded(rpc, key)
                if existing is None:
                    found = await self._discover(rpc, req, terms)
                    if found is not None:
                        self._channels[key] = found
                        await self._persist(key, found)
                        existing = found
                if existing is not None:
                    return await self._pay_existing(rpc, requirements, req, terms, key, existing, charge)
                if self._deposit_amount is not None and self._deposit_amount < charge:
                    raise ValueError("deposit_amount must cover the current request")
                deposit = self._deposit_for(req, charge, needed=charge, grant=terms.grant, existing=0)
                channel, transaction = await self._open(rpc, req, terms, deposit)
                payload = self._credential(channel, terms, charge, cumulative=charge)
                payload.update({"type": "deposit", "deposit": {"amount": str(deposit), "transaction": transaction}})
                return await self._hold(
                    key, requirements, terms, channel, None, charge, deposit, cast("BatchPayload", payload), deposit
                )

    async def _pay_existing(
        self,
        rpc: SolanaRpc,
        requirements: Mapping[str, Any],
        req: BatchRequirements,
        terms: _Terms,
        key: str,
        existing: _Channel,
        charge: int,
    ) -> BatchPaymentPayload:
        cumulative = existing.cumulative + charge
        payload = self._credential(existing, terms, charge, cumulative=cumulative)
        # Server mode: ceilings the operator may already have charged without a
        # valid answer are spent escrow too, so a lost response at exhaustion
        # tops up instead of being refused with cumulative_exceeds_deposit. The
        # price is a top-up that was not strictly needed, capped by the grant.
        claimable = cumulative + existing.unobserved
        if claimable <= existing.deposit:
            payload["type"] = "authorization" if terms.voucher_signer == "server" else "voucher"
            return await self._hold(
                key,
                requirements,
                terms,
                existing,
                existing,
                cumulative,
                existing.deposit,
                cast("BatchPayload", payload),
            )
        # The grant is spent by every escrow amount ever signed for the channel.
        escrowed = max(existing.deposit, existing.signed_deposit)
        top_up = self._deposit_for(
            req, charge, needed=claimable - existing.deposit, grant=terms.grant, existing=escrowed
        )
        blockhash = await self._blockhash(rpc, req)
        instruction = build_top_up_instruction(
            TopUpParams(
                payer=Pubkey.from_string(self._signer.pubkey()),
                channel=Pubkey.from_string(existing.channel_id),
                mint=Pubkey.from_string(req["asset"]),
                amount=top_up,
                token_program=Pubkey.from_string(terms.token_program),
                program_id=self._program_id,
            )
        )
        transaction = self._sign([instruction, _memo(terms)], terms, blockhash)
        payload.update({"type": "deposit", "deposit": {"amount": str(top_up), "transaction": transaction}})
        return await self._hold(
            key,
            requirements,
            terms,
            existing,
            existing,
            cumulative,
            existing.deposit + top_up,
            cast("BatchPayload", payload),
            top_up,
        )

    def _credential(self, channel: _Channel, terms: _Terms, charge: int, *, cumulative: int) -> dict[str, Any]:
        """The request's voucher (client mode) or payer proof (server mode) on ``channel``."""
        if terms.voucher_signer == "server":
            assert terms.operator is not None
            proof = sign_authorization(
                self._signer,
                channel_id=channel.channel_id,
                operator=terms.operator,
                request_id=str(uuid.uuid4()),
                authorized_amount=charge,
                expires_at=int(self._clock()) + max(1, terms.max_timeout),
            )
            return {"channelConfig": channel.config, "authorization": proof}
        return {"channelConfig": channel.config, "voucher": sign_voucher(self._signer, channel.channel_id, cumulative)}

    async def _hold(
        self,
        key: str,
        requirements: Mapping[str, Any],
        terms: _Terms,
        channel: _Channel,
        confirmed: _Channel | None,
        cumulative: int,
        deposit: int,
        payload: BatchPayload,
        signed: int = 0,
    ) -> BatchPaymentPayload:
        """Record the payment as in flight (and any escrow it signs) before it leaves this client."""
        if signed:
            channel = replace(channel, signed_deposit=channel.signed_deposit + signed)
            if confirmed is not None:
                confirmed = replace(confirmed, signed_deposit=channel.signed_deposit)
                self._channels[key] = confirmed
        payment = cast(
            "BatchPaymentPayload", {"x402Version": _X402_VERSION, "accepted": dict(requirements), "payload": payload}
        )
        proof = cast("Mapping[str, Any]", payload).get("authorization")
        operation_key = key if proof is None else f"{key}\x00{proof['requestId']}"
        # The server stops honouring the request at its lease (client mode) or proof expiry (server mode).
        expires_at = (
            float(proof["expiresAt"])
            if proof is not None
            else float(int(self._clock()) + max(_MIN_LEASE_SECONDS, terms.max_timeout))
        )
        pending = _Pending(
            key, operation_key, requirements["amount"], cumulative, deposit, channel, confirmed, payment, expires_at
        )
        self._pending[operation_key] = pending
        self._resolved[key] = asyncio.Event()
        await self._persist(key, confirmed)
        return payment

    # -- responses -----------------------------------------------------------------------------

    async def handle_payment_response(
        self,
        sent: BatchPaymentPayload,
        *,
        response: BatchSettlementResponse | None,
        payment_required: Mapping[str, Any] | None = None,
    ) -> bool:
        """Reconcile local state with the server's answer; ``True`` means retry the request.

        Client mode requires ``chargedAmount == amount``; server mode requires an
        operator voucher for this channel whose cumulative moved by at most this
        request's ceiling plus any unobserved ones. ``commitmentId`` is opaque
        but must be non-empty, and a reported ``chargedCumulativeAmount`` must
        equal the locally derived one. A 402 retries after a proven corrective,
        or after a ``duplicate_settlement`` proving this exact voucher was
        already charged (its response was lost).

        Call it with ``response=None`` when no answer arrived (a transport
        error, a timeout, a proxy error without ``PAYMENT-RESPONSE``): the
        channel is released at once instead of at the end of the lease. In
        server mode that request's ceiling stays allowed in the operator's next
        voucher, since it may have been charged.
        """
        pending = await self._find_pending(sent)
        if pending is None:
            return False
        del self._pending[pending.operation_key]
        try:
            return await self._resolve_pending(pending, sent, response, payment_required)
        finally:
            self._wake(pending.key)

    async def _resolve_pending(
        self,
        pending: _Pending,
        sent: BatchPaymentPayload,
        response: BatchSettlementResponse | None,
        payment_required: Mapping[str, Any] | None,
    ) -> bool:
        if response is None or not response.get("success"):
            if payment_required is None:
                # No answer (a transport error, a proxy error without
                # PAYMENT-RESPONSE): the server may still have charged it.
                await self._restore(_unanswered(pending))
                return False
            await self._restore(pending)
            code = payment_required.get("error")
            if code == errors.INVALID_CHANNEL_CLOSING:
                # The payer's forced close started: this channel takes no more payments.
                await self._forget(pending.key)
                return False
            if code == errors.DUPLICATE_SETTLEMENT:
                return await self._confirm_replay(pending, sent, payment_required)
            return await self._adopt_corrective(pending, payment_required)
        extra = cast("Mapping[str, Any]", response.get("extra") or {})
        amount = int(pending.amount)
        prior = 0 if pending.confirmed is None else pending.confirmed.cumulative
        server_mode = pending.channel.config.get("voucherSigner") == "server"
        if server_mode:
            voucher = extra.get("voucher")
            cumulative = _server_voucher_cumulative(voucher, pending.channel)
            if cumulative is None:
                await self._restore(_unanswered(pending))
                raise BatchSettlementError(
                    errors.INVALID_VOUCHER_SIGNATURE, "PAYMENT-RESPONSE server voucher is invalid"
                )
            if not prior <= cumulative <= prior + amount + pending.channel.unobserved:
                await self._restore(_unanswered(pending))
                return False
            confirmed_cumulative = cumulative
        else:
            if extra.get("chargedAmount") != pending.amount:
                await self._restore(pending)
                raise BatchSettlementError(
                    errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH, "PAYMENT-RESPONSE charged an unexpected amount"
                )
            confirmed_cumulative = prior + amount
        commitment = extra.get("commitmentId")
        state = cast("Mapping[str, Any]", extra.get("channelState") or {})
        reported = state.get("chargedCumulativeAmount")
        if (
            not isinstance(commitment, str)
            or not commitment
            or (isinstance(reported, str) and reported != str(confirmed_cumulative))
        ):
            # The server confirmed something this client did not submit.
            await self._restore(_unanswered(pending))
            return False
        await self._confirm(pending, sent, confirmed_cumulative, voucher_adopted=server_mode)
        return False

    async def _confirm(
        self, pending: _Pending, sent: BatchPaymentPayload, cumulative: int, *, voucher_adopted: bool
    ) -> None:
        payload = cast("Mapping[str, Any]", sent["payload"])
        # The escrow is what this client signed, not what the server reports.
        deposited = int(payload["deposit"]["amount"]) if payload["type"] == "deposit" else 0
        base = 0 if pending.confirmed is None else pending.confirmed.deposit
        confirmed = replace(
            pending.channel,
            cumulative=max(pending.channel.cumulative, cumulative),
            deposit=base + deposited,
            # An operator voucher states the whole cumulative: nothing is unobserved any more.
            unobserved=0 if voucher_adopted else pending.channel.unobserved,
            open_blockhash=None,
        )
        self._unlanded.pop(pending.key, None)
        self._channels[pending.key] = confirmed
        await self._persist(pending.key, confirmed)

    async def _confirm_replay(
        self, pending: _Pending, sent: BatchPaymentPayload, payment_required: Mapping[str, Any]
    ) -> bool:
        """A ``duplicate_settlement`` proving this exact voucher was charged: confirm it, then retry.

        ``duplicate_settlement`` also means "busy" or "expired", so only the
        server's own record of this voucher's signature and cumulative counts.
        """
        voucher = cast("Mapping[str, Any]", sent["payload"]).get("voucher")
        if not isinstance(voucher, dict) or pending.channel.config.get("voucherSigner") == "server":
            return False
        sent_voucher = cast("dict[str, Any]", voucher)
        extra = _extra_for(payment_required, pending.channel.channel_id)
        proof = None if extra is None else extra.get("voucherState")
        if not isinstance(proof, dict):
            return False
        fields = cast("dict[str, Any]", proof)
        same_signature = fields.get("signature") == sent_voucher.get("signature")
        same_amount = fields.get("signedMaxClaimable") == sent_voucher.get("maxClaimableAmount")
        if not (same_signature and same_amount):
            return False
        await self._confirm(pending, sent, pending.cumulative, voucher_adopted=False)
        return True

    async def _adopt_corrective(self, pending: _Pending, payment_required: Mapping[str, Any]) -> bool:
        """Adopt a corrective 402's charge only against the chain: the client's own signature, or ``settled``.

        The channel is read first and must be open; the deposit always comes
        from the chain, never from the server's ``balance``.
        """
        if payment_required.get("error") != errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH:
            return False
        channel_id = pending.channel.channel_id
        extra = _extra_for(payment_required, channel_id)
        if extra is None:
            return False
        state = cast("Mapping[str, Any]", extra["channelState"])
        try:
            charged = parse_u64(state.get("chargedCumulativeAmount"), "chargedCumulativeAmount")
        except BatchSettlementError:
            return False
        try:
            async with self._rpc_scope() as rpc:
                channel = await onchain.read_channel(rpc, channel_id, self._program_id)
        except Exception:  # noqa: BLE001 - no chain read, no adoption
            return False
        if channel is None or int(channel.status) != CHANNEL_STATUS_OPEN or int(channel.closureStartedAt) != 0:
            return False
        settled = int(channel.settlement.settled)
        # Never below what the chain settled.
        if charged < settled:
            return False
        if pending.channel.config.get("voucherSigner") == "server":
            # The operator signs server-mode proofs, so a signature proves
            # nothing about what this client authorized: bound the claim by its
            # confirmed watermark plus the ceilings of its own unresolved and
            # unanswered requests.
            unresolved = sum(int(p.amount) for p in self._pending.values() if p.key == pending.key)
            prior = 0 if pending.confirmed is None else pending.confirmed.cumulative
            if charged > prior + int(pending.amount) + unresolved + pending.channel.unobserved:
                return False
        proof = extra.get("voucherState")
        if isinstance(proof, dict):
            fields = cast("dict[str, Any]", proof)
            try:
                signed = parse_u64(fields.get("signedMaxClaimable"), "signedMaxClaimable")
            except BatchSettlementError:
                return False
            voucher: Any = {
                "channelId": channel_id,
                "maxClaimableAmount": str(signed),
                "expiresAt": fields.get("expiresAt"),
                "signature": fields.get("signature"),
            }
            if charged > signed or fields.get("expiresAt") != 0 or not isinstance(fields.get("signature"), str):
                return False
            if not verify_voucher(voucher, pending.channel.config["payerAuthorizer"]):
                return False
        elif charged != settled:
            # Unproven, the only base a client may adopt is the chain's own.
            return False
        adopted = replace(pending.channel, cumulative=charged, deposit=int(channel.deposit), unobserved=0)
        self._channels[pending.key] = adopted
        await self._persist(pending.key, adopted)
        return True

    # -- refunds --------------------------------------------------------------------------------

    async def create_refund_payload(self, requirements: Mapping[str, Any]) -> BatchPaymentPayload:
        """Build the payer-signed ``request_close`` for the cached (or discovered) channel of these terms.

        The transaction always carries a Memo: the Rust server requires one.
        """
        req = _parse(requirements)
        async with self._rpc_scope() as rpc:
            terms = await self._terms(rpc, req)
            key = self._key(req, terms)
            channel = await self._load(key) or await self._discover(rpc, req, terms)
            if channel is None:
                raise ValueError("no batch-settlement channel to refund")
            blockhash = await self._blockhash(rpc, req)
        instruction = build_request_close_instruction(
            payer=Pubkey.from_string(self._signer.pubkey()),
            channel=Pubkey.from_string(channel.channel_id),
            program_id=self._program_id,
        )
        transaction = self._sign([instruction, _memo(terms)], terms, blockhash)
        payload: Any = {"type": "refund", "channelConfig": channel.config, "transaction": transaction}
        return cast(
            "BatchPaymentPayload", {"x402Version": _X402_VERSION, "accepted": dict(requirements), "payload": payload}
        )

    # -- terms, sizing, transactions --------------------------------------------------------------

    async def _terms(self, rpc: SolanaRpc, req: BatchRequirements) -> _Terms:
        """Check the challenge terms the client owes itself, including the mint owner and the trust grant."""
        extra = req["extra"]
        if extra.get("paymentFlow", PAYMENT_FLOW_AUTHORIZATION) != PAYMENT_FLOW_AUTHORIZATION:
            raise BatchSettlementError(errors.INVALID_PAYMENT_FLOW, 'extra.paymentFlow must be "authorization"')
        check_withdraw_delay(extra["withdrawDelay"], req["maxTimeoutSeconds"])
        token_program = extra["tokenProgram"]
        if token_program not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
            raise BatchSettlementError(errors.INVALID_TOKEN_PROGRAM, f"unsupported tokenProgram {token_program}")
        # A server-declared token program is not evidence: every ATA in the
        # open derives from it.
        await onchain.check_mint_owner(rpc, req["asset"], token_program)
        fee_payer = extra["feePayer"]
        if fee_payer == self._signer.pubkey():
            raise BatchSettlementError(errors.INVALID_FEE_PAYER_MISMATCH, "the payer must not be the sponsor")
        voucher_signer: VoucherSigner = extra.get("voucherSigner", "client")
        operator = extra.get("operator")
        if (voucher_signer == "server") != (operator is not None):
            raise BatchSettlementError(
                errors.INVALID_CHANNEL_STATE, "extra.operator is required exactly in server mode"
            )
        # Server mode is never implied by a 402: the operator must be trusted.
        grant = self._trust.grant_for(cast("Mapping[str, Any]", req)) if voucher_signer == "server" else None
        return _Terms(
            fee_payer=fee_payer,
            token_program=token_program,
            withdraw_delay=extra["withdrawDelay"],
            memo=extra.get("memo"),
            receiver_authorizer=extra.get("receiverAuthorizer"),
            voucher_signer=voucher_signer,
            operator=operator,
            grant=grant,
            max_timeout=req["maxTimeoutSeconds"],
        )

    def _deposit_for(
        self, req: BatchRequirements, amount: int, *, needed: int, grant: ServerSignedGrant | None, existing: int
    ) -> int:
        """Escrow to add: configured, else a valid ``minDeposit``, else ``amount x multiplier``; clamped by caps."""
        hint = req["extra"].get("minDeposit")
        target = amount * self._multiplier
        if self._deposit_amount is not None:
            target = self._deposit_amount
        elif hint is not None and int(hint) >= amount:
            target = int(hint)
        proposed = max(target, needed)
        if self._max_per_payment is not None and self._max_per_payment > 0:
            ceiling = self._max_per_payment * self._multiplier
            if needed > ceiling:
                raise ValueError(
                    f"Required deposit {needed} exceeds deposit_multiplier x max_amount_per_payment ({ceiling})"
                )
            proposed = min(proposed, ceiling)
        # In server mode the escrow is what a dishonest operator could take:
        # the grant caps every hint, including minDeposit and deposit_amount.
        if grant is not None and grant.max_deposit is not None:
            room = grant.max_deposit - existing
            if needed > room:
                raise ValueError(
                    f"Required deposit {needed} exceeds the remaining trust max_deposit "
                    f"({grant.max_deposit} total, {existing} already escrowed)"
                )
            proposed = min(proposed, room)
        return proposed

    async def _open(self, rpc: SolanaRpc, req: BatchRequirements, terms: _Terms, deposit: int) -> tuple[_Channel, str]:
        payer = self._signer.pubkey()
        authorized_signer = terms.operator or payer
        open_slot = req["extra"].get("recentSlot")
        if open_slot is None:
            open_slot = await rpc.get_slot()
        blockhash = await self._blockhash(rpc, req)
        params = OpenChannelParams(
            payer=Pubkey.from_string(payer),
            rent_payer=Pubkey.from_string(terms.fee_payer),
            # The sponsor holds the zero-share payee seat; payTo gets 100%.
            payee=Pubkey.from_string(terms.fee_payer),
            mint=Pubkey.from_string(req["asset"]),
            authorized_signer=Pubkey.from_string(authorized_signer),
            salt=self._salt,
            deposit=deposit,
            grace_period=terms.withdraw_delay,
            open_slot=open_slot,
            recipients=[Distribution(Pubkey.from_string(req["payTo"]), 10_000)],
            token_program=Pubkey.from_string(terms.token_program),
            program_id=self._program_id,
        )
        channel_id, _ = find_channel_pda(
            params.payer, params.payee, params.mint, params.authorized_signer, self._salt, open_slot, self._program_id
        )
        config = self._config(req, terms, authorized_signer, self._salt, open_slot)
        transaction = self._sign([build_open_instruction(params), _memo(terms)], terms, blockhash)
        return _Channel(str(channel_id), config, 0, 0, open_blockhash=blockhash), transaction

    def _config(
        self, req: BatchRequirements, terms: _Terms, authorized_signer: str, salt: int, open_slot: int
    ) -> BatchChannelConfig:
        config: dict[str, Any] = {
            "payer": self._signer.pubkey(),
            "payerAuthorizer": authorized_signer,
            "receiver": req["payTo"],
            "token": req["asset"],
            "withdrawDelay": terms.withdraw_delay,
            "salt": str(salt),
            "openSlot": open_slot,
        }
        if terms.receiver_authorizer is not None:
            config["receiverAuthorizer"] = terms.receiver_authorizer
        if terms.voucher_signer == "server":
            config["voucherSigner"] = "server"
        return cast("BatchChannelConfig", config)

    def _sign(self, instructions: list[Instruction], terms: _Terms, blockhash: str) -> str:
        """A v0 transaction paid by the sponsor, signed in the payer's slot only (base64)."""
        wire = build_partially_signed_v0_transaction(
            instructions,
            Pubkey.from_string(terms.fee_payer),
            Hash.from_string(blockhash),
            Pubkey.from_string(self._signer.pubkey()),
            self._signer.sign,
        )
        return base64.b64encode(wire).decode("ascii")

    async def _blockhash(self, rpc: SolanaRpc, req: BatchRequirements) -> str:
        hint = req["extra"].get("recentBlockhash")
        return hint if hint is not None else (await rpc.get_latest_blockhash()).value.blockhash

    async def _discover(self, rpc: SolanaRpc, req: BatchRequirements, terms: _Terms) -> _Channel | None:
        """The newest open channel this wallet already funded under these terms, adopted at its settled watermark.

        Every row is re-derived to its PDA before it is trusted. Discovery is an
        optimization over opening a new channel, never a precondition for paying.
        """
        if not self._discover_channels:
            return None
        payer = self._signer.pubkey()
        try:
            found = await onchain.discover(rpc, self._program_id, payer, offset=CHANNEL_PAYER_OFFSET)
        except Exception:  # noqa: BLE001 - a failed scan is a cache miss
            return None
        split = list(distribution_hash([Distribution(Pubkey.from_string(req["payTo"]), 10_000)]))
        usable = [
            (channel_id, channel)
            for channel_id, channel in found
            if int(channel.status) == CHANNEL_STATUS_OPEN
            and int(channel.closureStartedAt) == 0
            and str(channel.payee) == terms.fee_payer
            and str(channel.mint) == req["asset"]
            and str(channel.authorizedSigner) == (terms.operator or payer)
            and int(channel.gracePeriod) == terms.withdraw_delay
            and int(channel.salt) == self._salt
            and list(channel.distributionHash) == split
        ]
        if not usable:
            return None
        channel_id, channel = max(usable, key=lambda row: int(row[1].openSlot))
        config = self._config(req, terms, str(channel.authorizedSigner), int(channel.salt), int(channel.openSlot))
        # The charges above the settled watermark exist only in vouchers this
        # client no longer has; the server rebuilds from the same watermark.
        return _Channel(channel_id, config, int(channel.settlement.settled), int(channel.deposit))

    # -- local state ------------------------------------------------------------------------------

    def _key(self, req: BatchRequirements, terms: _Terms) -> str:
        return ":".join(
            [
                req["network"],
                req["asset"],
                req["payTo"],
                terms.fee_payer,
                str(terms.withdraw_delay),
                terms.receiver_authorizer or "",
                terms.voucher_signer,
                terms.operator or "",
            ]
        )

    async def _load(self, key: str) -> _Channel | None:
        cached = self._channels.get(key)
        if cached is not None or key in self._unlanded or self._store is None:
            return cached
        record = await self._store.get(key)
        if record is None:
            return None
        channel = _Channel(
            record.channel_id,
            record.channel_config,
            record.charged_cumulative,
            record.deposit,
            record.signed_deposit,
            record.unobserved,
            record.open_blockhash,
        )
        confirmed = replace(channel, open_blockhash=None) if record.has_confirmed_state else None
        if confirmed is not None:
            self._channels[key] = confirmed
        elif record.open_blockhash is not None and not record.pending:
            self._unlanded[key] = channel
        for item in record.pending:
            self._pending[item.operation_key] = _Pending(
                key,
                item.operation_key,
                item.amount,
                item.cumulative,
                item.deposit,
                confirmed or channel,
                confirmed,
                item.payment,
                item.expires_at,
            )
        return confirmed

    def _lock_for(self, key: str) -> asyncio.Lock:
        return self._locks.setdefault(key, asyncio.Lock())

    def _wake(self, key: str) -> None:
        event = self._resolved.get(key)
        if event is not None:
            event.set()

    async def _await_in_flight(self, key: str) -> None:
        """Wait until the channel's unanswered payment resolves or its lease runs out (then drop it)."""
        while (blocking := next((p for p in self._pending.values() if p.key == key), None)) is not None:
            remaining = blocking.expires_at - self._clock()
            if remaining <= 0:
                await self._expire(blocking)
                continue
            event = self._resolved.setdefault(key, asyncio.Event())
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(event.wait(), remaining)
            if event.is_set():
                event.clear()

    async def _expire(self, pending: _Pending) -> None:
        """Drop a payment the server no longer honours without an answer."""
        del self._pending[pending.operation_key]
        await self._restore(_unanswered(pending))
        self._wake(pending.key)

    async def _recover_unlanded(self, rpc: SolanaRpc, key: str) -> _Channel | None:
        """Server mode: settle an open that failed but may have landed before funding a second channel."""
        unlanded = self._unlanded.get(key)
        if unlanded is None:
            return None
        channel = await onchain.read_channel(rpc, unlanded.channel_id, self._program_id)
        if channel is not None:
            adopted = replace(
                unlanded,
                cumulative=int(channel.settlement.settled),
                deposit=int(channel.deposit),
                open_blockhash=None,
            )
            del self._unlanded[key]
            self._channels[key] = adopted
            await self._persist(key, adopted)
            return adopted
        if unlanded.open_blockhash is not None and await rpc.is_blockhash_valid(unlanded.open_blockhash):
            raise ValueError(
                "batch-settlement: a signed open for these terms may still land; retry after its blockhash expires"
            )
        del self._unlanded[key]
        await self._persist(key, None)
        return None

    async def _forget(self, key: str) -> None:
        """Drop a channel this client can no longer pay from (closing or refunded)."""
        self._channels.pop(key, None)
        self._unlanded.pop(key, None)
        for operation_key in [k for k, p in self._pending.items() if p.key == key]:
            del self._pending[operation_key]
        self._wake(key)
        if self._store is not None:
            await self._store.delete(key)

    async def _key_with_channel(self, requirements: Mapping[str, Any]) -> str | None:
        """The terms key of ``requirements`` when this client holds (or finds) a channel under it."""
        req = _parse(requirements)
        async with self._rpc_scope() as rpc:
            try:
                terms = await self._terms(rpc, req)
            except UntrustedOperatorError:
                return None
            key = self._key(req, terms)
            if await self._load(key) is not None or await self._discover(rpc, req, terms) is not None:
                return key
        return None

    async def _find_pending(self, sent: BatchPaymentPayload) -> _Pending | None:
        payload = cast("Mapping[str, Any]", sent["payload"])
        proof = payload.get("authorization")
        voucher = payload.get("voucher")

        def matches(p: _Pending) -> bool:
            held = cast("Mapping[str, Any]", p.payment["payload"])
            if proof is not None:
                other = held.get("authorization")
                return isinstance(other, dict) and cast("dict[str, Any]", other).get("requestId") == proof["requestId"]
            return isinstance(voucher, dict) and p.channel.channel_id == cast("dict[str, Any]", voucher).get(
                "channelId"
            )

        found = next((p for p in self._pending.values() if matches(p)), None)
        if found is None and self._store is not None:
            # A recovered response can be the first call on a fresh client.
            async with self._rpc_scope() as rpc:
                req = _parse(sent["accepted"])
                await self._load(self._key(req, await self._terms(rpc, req)))
            found = next((p for p in self._pending.values() if matches(p)), None)
        return found

    async def _restore(self, pending: _Pending) -> None:
        """Back to the confirmed state; a server-mode open that may still land is remembered."""
        if pending.confirmed is not None:
            self._channels[pending.key] = pending.confirmed
        elif pending.channel.config.get("voucherSigner") == "server" and pending.channel.open_blockhash is not None:
            self._unlanded[pending.key] = pending.channel
        await self._persist(pending.key, pending.confirmed)

    async def _persist(self, key: str, confirmed: _Channel | None) -> None:
        if self._store is None:
            return
        held = [p for p in self._pending.values() if p.key == key]
        channel = confirmed or (held[0].channel if held else None) or self._unlanded.get(key)
        if channel is None:
            await self._store.delete(key)
            return
        await self._store.set(
            key,
            ClientChannelRecord(
                channel_id=channel.channel_id,
                channel_config=channel.config,
                charged_cumulative=0 if confirmed is None else confirmed.cumulative,
                deposit=0 if confirmed is None else confirmed.deposit,
                has_confirmed_state=confirmed is not None,
                pending=[
                    PendingAllocation(p.amount, p.cumulative, p.deposit, p.operation_key, p.payment, p.expires_at)
                    for p in held
                ],
                signed_deposit=channel.signed_deposit,
                unobserved=channel.unobserved,
                open_blockhash=None if confirmed is not None else channel.open_blockhash,
            ),
        )

    @asynccontextmanager
    async def _rpc_scope(self) -> AsyncGenerator[SolanaRpc]:
        if self._rpc is not None:
            yield self._rpc
            return
        assert self._rpc_url is not None
        rpc = SolanaRpc(self._rpc_url)
        try:
            yield rpc
        finally:
            await rpc.aclose()


def _parse(requirements: Mapping[str, Any]) -> BatchRequirements:
    """Parse a requirement strictly, except that a malformed advisory ``minDeposit`` is ignored (as in TS)."""
    extra = requirements.get("extra")
    if isinstance(extra, dict) and "minDeposit" in extra:
        fields = cast("dict[str, Any]", extra)
        try:
            parse_u64(fields["minDeposit"], "minDeposit")
        except BatchSettlementError:
            requirements = {**requirements, "extra": {k: v for k, v in fields.items() if k != "minDeposit"}}
    return parse_requirements(requirements)


def _extra_for(payment_required: Mapping[str, Any], channel_id: str) -> Mapping[str, Any] | None:
    """The accept ``extra`` whose ``channelState`` names ``channel_id``."""
    for accept in cast("list[Mapping[str, Any]]", payment_required.get("accepts") or []):
        extra = cast("Mapping[str, Any]", accept.get("extra") or {})
        state = extra.get("channelState")
        if isinstance(state, dict) and cast("dict[str, Any]", state).get("channelId") == channel_id:
            return extra
    return None


def _unanswered(pending: _Pending) -> _Pending:
    """Server mode: keep the ceiling of a proof the operator got but never validly answered.

    The operator may still have charged it, so the corrective and response
    bounds allow it until an operator voucher states the whole cumulative.
    """
    if pending.channel.config.get("voucherSigner") != "server":
        return pending
    ceiling = int(pending.amount)
    if pending.confirmed is not None:
        return replace(pending, confirmed=replace(pending.confirmed, unobserved=pending.confirmed.unobserved + ceiling))
    return replace(pending, channel=replace(pending.channel, unobserved=pending.channel.unobserved + ceiling))


def _memo(terms: _Terms) -> Instruction:
    """The Memo every setup and refund carries: the declared ``extra.memo``, else a 16-byte hex nonce."""
    text = terms.memo if terms.memo is not None else secrets.token_hex(_MEMO_NONCE_BYTES)
    return Instruction(Pubkey.from_string(MEMO_PROGRAM), text.encode("utf-8"), [])


def _server_voucher_cumulative(voucher: object, channel: _Channel) -> int | None:
    """The cumulative of a valid operator voucher for ``channel``, else ``None``."""
    if not isinstance(voucher, dict):
        return None
    fields = cast("dict[str, Any]", voucher)
    amount = fields.get("maxClaimableAmount")
    try:
        cumulative = parse_u64(amount, "voucher.maxClaimableAmount")
    except BatchSettlementError:
        return None
    if fields.get("channelId") != channel.channel_id or fields.get("expiresAt") != 0:
        return None
    if not isinstance(fields.get("signature"), str) or not verify_voucher(
        cast(Any, fields), channel.config["payerAuthorizer"]
    ):
        return None
    return cumulative
