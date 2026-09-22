"""Redemption worker for the SVM x402 ``batch-settlement`` server.

Vouchers accumulate off-chain and are worth nothing until claimed: a server
that never redeems forfeits what it earned once a payer's forced close runs out
its grace period. One pass, serialized, does in order:

1. **claim**: ``[ed25519, settle]`` pairs, at most four channels per transaction,
   for every open channel whose charged voucher is above ``settled``. A channel
   the payer is closing is sealed with its latest voucher instead, while the
   grace period allows.
2. **settle**: ``distribute`` the settled delta to ``payTo``.
3. **finalize**: after the grace period, the permissionless ``seal`` plus a
   sealed ``distribute``.
4. **reclaim**: return the channel rent once ``slot > openSlot + 1500``.
5. **close idle** (off unless ``max_idle_secs`` is set): seal an idle open
   channel *with* its latest voucher, so nothing earned is forfeited.

A seal first takes the channel for itself: it never runs while a request can
still be charged, and a charge is refused once the channel is sealed. After a
lost store, :meth:`BatchRedemption.recover` rebuilds the channels this fee
payer sponsors from the chain.

A claim submits only what was charged (``settled < signed <= charged``). After a
confirmed broadcast a failed store write is alerted, never re-raised, and an
unconfirmed broadcast is never rebuilt: the next pass reads the chain, and the
program's monotonic watermarks make a repeat harmless.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable, Collection
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field, replace
from typing import Any, TypeVar, cast

from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.paymentchannels import (
    OPEN_SLOT_WINDOW,
    Distribution,
    build_reclaim_instruction,
    build_seal_instruction,
    build_settle_and_seal_instructions,
    distribution_hash,
)
from solana_pay_kit._paycore.rpc import MalformedAccountError, SolanaRpc, read_with_replica_retry
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.x402.batch_settlement import onchain
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.signatures import (
    sign_close_authorization,
    verify_close_authorization,
)
from solana_pay_kit.protocols.x402.batch_settlement.store import (
    BatchChannelStore,
    BatchOperationStore,
    ChannelRecord,
    Reservation,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import MAX_CLAIMS_PER_BATCH, BatchChannelConfig
from solana_pay_kit.protocols.x402.batch_settlement.verify import (
    CHANNEL_STATUS_CLOSING,
    CHANNEL_STATUS_DISTRIBUTED,
    CHANNEL_STATUS_OPEN,
    CHANNEL_STATUS_SEALED,
    decode_channel,
)
from solana_pay_kit.signer import LocalSigner

__all__ = ["BatchRedemption", "RedemptionResult", "RedemptionSettings"]

_READ_CHUNK = 100  # getMultipleAccounts address cap
_HOLD = "redemption"
_RECOVER_EVERY = 10  # passes between two recovery scans in the loop
_FULL_SHARE_BPS = 10_000

AlertFn = Callable[[str, str, BaseException], None]
_T = TypeVar("_T")


@dataclass(frozen=True)
class RedemptionSettings:
    """Worker knobs taken from the engine's ``BatchSettlementConfig``."""

    max_timeout_seconds: int
    max_idle_secs: int | None
    batch_size: int
    #: For :meth:`BatchRedemption.recover`: the network, the payTo values this
    #: server settles to (read at each recover), and the fields a rebuilt
    #: channelConfig must carry.
    network: str = ""
    pay_to: Collection[str] = ()
    operator: str | None = None
    receiver_authorizer: str | None = None


def _no_ids() -> list[str]:
    return []


def _no_errors() -> list[tuple[str, str]]:
    return []


@dataclass
class RedemptionResult:
    """What one pass moved; ``errors`` holds ``(channel_id, detail)`` for channels left to the next pass."""

    claimed: list[str] = field(default_factory=_no_ids)
    sealed: list[str] = field(default_factory=_no_ids)
    distributed: list[str] = field(default_factory=_no_ids)
    finalized: list[str] = field(default_factory=_no_ids)
    reclaimed: list[str] = field(default_factory=_no_ids)
    idle_closed: list[str] = field(default_factory=_no_ids)
    errors: list[tuple[str, str]] = field(default_factory=_no_errors)


class _Skip(Exception):  # noqa: N818 - control flow for one channel
    """Leave this channel for the next pass."""


class BatchRedemption:
    """Claims, distributes, seals, finalizes and reclaims the channels in a store."""

    def __init__(
        self,
        *,
        store: BatchChannelStore,
        rpc_scope: Callable[[], AbstractAsyncContextManager[SolanaRpc]],
        fee_payer: LocalSigner,
        close_authorizer: LocalSigner,
        settings: RedemptionSettings,
        program_id: Pubkey,
        clock: Callable[[], float],
        alert: AlertFn,
        operations: BatchOperationStore | None = None,
    ) -> None:
        """Wire the worker; normally built by ``X402BatchSettlement.redemption()``."""
        self._store = store
        self._operations = operations
        self._rpc_scope = rpc_scope
        self._fee_payer = fee_payer
        self._close_authorizer = close_authorizer
        self._settings = settings
        self._program_id = program_id
        self._clock = clock
        self._alert = alert
        # One lock per worker instance; a second worker process over the same
        # store needs a store-level lease.
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._interval = 0.0
        # Sponsored channels with no known payTo: never charged here, only reclaimed.
        self._reclaim_only: set[str] = set()
        # Channels whose account did not read back; alerted once, kept, re-read next pass.
        self._absent: set[str] = set()

    # -- passes ---------------------------------------------------------------------------

    async def run_pass(self) -> RedemptionResult:
        """One serialized pass: claim, distribute, finalize, reclaim, then idle close."""
        async with self._lock, self._rpc_scope() as rpc:
            result = RedemptionResult()
            await self._claim(rpc, result, None)
            await self._settle(rpc, result, None)
            await self._finalize(rpc, result)
            await self._reclaim(rpc, result, None)
            await self._close_idle(rpc, result)
            return result

    async def claim(self, channel_ids: list[str] | None = None) -> RedemptionResult:
        """Claim the charged vouchers of ``channel_ids`` (default: every stored channel)."""
        async with self._lock, self._rpc_scope() as rpc:
            result = RedemptionResult()
            await self._claim(rpc, result, channel_ids)
            return result

    async def settle(self, channel_ids: list[str] | None = None) -> RedemptionResult:
        """Distribute the settled delta of ``channel_ids`` (default: every stored channel)."""
        async with self._lock, self._rpc_scope() as rpc:
            result = RedemptionResult()
            await self._settle(rpc, result, channel_ids)
            return result

    async def finalize_close(self) -> RedemptionResult:
        """Seal and pay out every channel whose forced-close grace period has ended."""
        async with self._lock, self._rpc_scope() as rpc:
            result = RedemptionResult()
            await self._finalize(rpc, result)
            return result

    async def close_idle(self) -> RedemptionResult:
        """Seal idle open channels with their latest voucher (only when ``max_idle_secs`` is set)."""
        async with self._lock, self._rpc_scope() as rpc:
            result = RedemptionResult()
            await self._close_idle(rpc, result)
            return result

    async def reclaim(self, channel_ids: list[str] | None = None) -> RedemptionResult:
        """Reclaim rent for distributed channels; ``channel_ids`` may add ones found by :meth:`discover`."""
        async with self._lock, self._rpc_scope() as rpc:
            result = RedemptionResult()
            await self._reclaim(rpc, result, channel_ids)
            return result

    async def discover(self) -> list[str]:
        """Every channel whose rent the fee payer fronted, re-derived to its PDA (for use after a lost store)."""
        async with self._rpc_scope() as rpc:
            found = await onchain.discover(rpc, self._program_id, self._fee_payer.pubkey())
        sponsor = self._fee_payer.pubkey()
        # The sponsor holds both the rent-payer and the zero-share payee seat.
        return [cid for cid, channel in found if str(channel.rentPayer) == sponsor and str(channel.payee) == sponsor]

    async def recover(self) -> list[str]:
        """Rebuild the records of sponsored channels the store does not know (after a lost store).

        Each is rebuilt at its settled watermark with no voucher, the most the
        chain proves was charged. ``channelConfig.receiver`` is not on chain:
        the distribution hash is matched against this server's payTo values,
        and a channel that matches none is only reclaimed once distributed.
        The token program is the mint's owner. Returns the rebuilt ids.
        """
        async with self._lock, self._rpc_scope() as rpc:
            known = {record.channel_id for record in await self._store.list()}
            sponsor = self._fee_payer.pubkey()
            by_hash = {
                bytes(distribution_hash([Distribution(Pubkey.from_string(pay_to), _FULL_SHARE_BPS)])): pay_to
                for pay_to in self._settings.pay_to
            }
            rebuilt: list[str] = []
            for channel_id, channel in await onchain.discover(rpc, self._program_id, sponsor):
                if channel_id in known or str(channel.rentPayer) != sponsor or str(channel.payee) != sponsor:
                    continue
                pay_to = by_hash.get(bytes(channel.distributionHash))
                mint = await rpc.get_account_info(str(channel.mint))
                if pay_to is None or mint is None:
                    self._reclaim_only.add(channel_id)
                    continue
                record = onchain.fold(
                    self._rebuilt(channel_id, channel, pay_to, token_program=mint[1]), channel, self._clock()
                )
                await self._store.update(channel_id, lambda current, record=record: current or record)
                rebuilt.append(channel_id)
            return rebuilt

    def _rebuilt(self, channel_id: str, channel: Channel, pay_to: str, *, token_program: str) -> ChannelRecord:
        signer = str(channel.authorizedSigner)
        config: dict[str, Any] = {
            "payer": str(channel.payer),
            "payerAuthorizer": signer,
            "receiver": pay_to,
            "token": str(channel.mint),
            "withdrawDelay": int(channel.gracePeriod),
            "salt": str(int(channel.salt)),
            "openSlot": int(channel.openSlot),
        }
        if self._settings.receiver_authorizer is not None:
            config["receiverAuthorizer"] = self._settings.receiver_authorizer
        if signer != config["payer"]:
            # Server-signed is what the chain says: a signer that is not the
            # payer is an operator key. Matching it against the operator key
            # configured now would rebuild a channel opened under a rotated key
            # as client-signed, and every request for it would then be refused
            # for a channelConfig that differs from the stored one.
            config["voucherSigner"] = "server"
        return ChannelRecord(
            channel_id=channel_id,
            channel_config=cast("BatchChannelConfig", config),
            network=self._settings.network,
            fee_payer=self._fee_payer.pubkey(),
            token_program=token_program,
            last_activity_at=self._clock(),
        )

    def start(self, interval_seconds: float) -> None:
        """Run a pass every ``interval_seconds`` on the running loop; claim well inside the grace period.

        Every few passes it first runs :meth:`recover`.
        """
        if self._task is None:
            self._interval = interval_seconds
            self._task = asyncio.get_running_loop().create_task(self._loop(interval_seconds))

    async def stop(self, *, flush: bool = False) -> None:
        """Stop the loop after any pass under way; ``flush`` runs one final pass."""
        task, self._task = self._task, None
        if task is not None:
            async with self._lock:
                task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if flush:
            await self.run_pass()

    async def _loop(self, interval_seconds: float) -> None:
        passes = 0
        while True:
            if passes % _RECOVER_EVERY == 0:
                try:
                    await self.recover()
                except Exception as exc:  # noqa: BLE001 - a failed scan must not skip the pass
                    self._alert("redemption_recover", "*", exc)
            try:
                await self.run_pass()
            except Exception as exc:  # noqa: BLE001 - one failed pass must not stop the worker
                self._alert("redemption_pass", "*", exc)
            passes += 1
            await asyncio.sleep(interval_seconds)

    # -- claim ------------------------------------------------------------------------------

    async def _claim(self, rpc: SolanaRpc, result: RedemptionResult, only: list[str] | None) -> None:
        eligible: list[ChannelRecord] = []
        for record in await self._records(only):
            # A closing channel stays eligible: its claim becomes a seal while
            # the grace period allows, and a failed seal is retried next pass.
            if record.status not in ("open", "closing") or record.voucher_signature is None:
                continue
            if record.signed_max_claimable <= record.settled:
                continue
            if record.signed_max_claimable > record.charged_cumulative:
                # Never claim what was not charged.
                self._alert(
                    "claim_above_charged",
                    record.channel_id,
                    ValueError(f"{record.signed_max_claimable} > {record.charged_cumulative}"),
                )
                continue
            eligible.append(record)
        for chunk in _chunks(eligible, self._batch_size()):
            await self._claim_chunk(rpc, result, chunk, split_on_failure=True)

    async def _claim_chunk(
        self, rpc: SolanaRpc, result: RedemptionResult, chunk: list[ChannelRecord], *, split_on_failure: bool
    ) -> None:
        batch: list[ChannelRecord] = []
        for record, channel in zip(chunk, await self._read(rpc, chunk), strict=True):
            if channel is None:
                continue
            record = await self._sync(record, channel)
            if int(channel.status) == CHANNEL_STATUS_CLOSING:
                await self._seal(rpc, result, record, channel)
            elif int(channel.status) == CHANNEL_STATUS_OPEN and record.signed_max_claimable > record.settled:
                batch.append(record)
        if not batch:
            return
        instructions = [
            ix
            for record in batch
            for ix in onchain.claim_instructions(
                channel_id=record.channel_id,
                payer_authorizer=record.channel_config["payerAuthorizer"],
                signature=_voucher_signature(record),
                cumulative=record.signed_max_claimable,
                program_id=self._program_id,
            )
        ]
        try:
            await onchain.submit(rpc, self._fee_payer, instructions)
        except onchain.UnconfirmedBroadcast as exc:
            _fail(result, batch, f"claim not confirmed: {exc}")
            return
        except (BatchSettlementError, PaymentError) as exc:
            # A payer may have started a forced close since the read: program
            # settle is gone for that channel, so claim the others alone and
            # seal the closing one while the grace period allows.
            if split_on_failure:
                for record in batch:
                    await self._claim_chunk(rpc, result, [record], split_on_failure=False)
            else:
                _fail(result, batch, f"claim failed: {exc}")
            return
        observed = await self._read_visible(rpc, batch)
        now = self._clock()
        for record, channel in zip(batch, observed, strict=True):
            if channel is None or int(channel.settlement.settled) < record.signed_max_claimable:
                result.errors.append((record.channel_id, "claim confirmed but its settled watermark is not visible"))
                continue
            await self._record_after_broadcast(
                "claim",
                record.channel_id,
                _touched(channel, now),
            )
            result.claimed.append(record.channel_id)

    # -- seal (a channel the payer is closing) ------------------------------------------------

    async def _seal(self, rpc: SolanaRpc, result: RedemptionResult, record: ChannelRecord, channel: Channel) -> None:
        """Apply the latest charged voucher to a ``Closing`` channel and pay out, inside its grace period.

        The channel is taken for the seal first: a request still in flight
        could otherwise be charged above the sealed amount, which can never be
        redeemed. While the grace period leaves room, the seal waits for it.
        """
        now = self._clock()
        settled = int(channel.settlement.settled)
        grace_end = int(channel.closureStartedAt) + int(channel.gracePeriod)
        if settled >= record.signed_max_claimable:
            # Nothing left to apply (the store lags the chain): sealing now
            # would spend a transaction on what the permissionless post-grace
            # close does anyway, as in the Rust finalize_close.
            return
        if not (now < grace_end and record.signed_max_claimable <= int(channel.deposit)):
            result.errors.append((record.channel_id, "channel is outside its seal window"))
            return
        wait = self._settings.max_timeout_seconds + self._interval
        try:
            held = await self._store.update(
                record.channel_id,
                lambda current: _seal_hold(
                    current, now, room=grace_end - now, wait=wait, ttl=self._settings.max_timeout_seconds
                ),
            )
        except _Skip as exc:
            result.errors.append((record.channel_id, str(exc)))
            return
        signed = held.signed_max_claimable
        fee_payer = self._fee_payer.pubkey()
        valid_before = int(now) + self._settings.max_timeout_seconds
        authorization = sign_close_authorization(
            self._close_authorizer,
            network=held.network,
            fee_payer=fee_payer,
            channel_id=held.channel_id,
            max_claimable_amount=signed,
            voucher_expires_at=0,
            valid_before=valid_before,
            program_id=str(self._program_id),
        )
        # The server is its own facilitator: the close is authorized by the
        # receiver authorizer and checked here exactly as a facilitator would.
        if signed > int(channel.deposit) or not verify_close_authorization(
            authorization,
            network=held.network,
            fee_payer=fee_payer,
            channel_id=held.channel_id,
            max_claimable_amount=signed,
            voucher_expires_at=0,
            receiver_authorizer=self._close_authorizer.pubkey(),
            max_timeout_seconds=self._settings.max_timeout_seconds,
            now=int(now),
            program_id=str(self._program_id),
        ):
            await self._drop_hold(held.channel_id)
            result.errors.append((held.channel_id, "close authorization did not verify"))
            return
        instructions = [
            *self._settle_and_seal(held, signed, settled=settled),
            self._distribute(held, channel),
        ]
        if await self._submit_final(rpc, result, held, instructions, signed):
            result.sealed.append(held.channel_id)
        else:
            await self._drop_hold(held.channel_id)

    async def _drop_hold(self, channel_id: str) -> None:
        try:
            await self._store.update(channel_id, _release_hold)
        except Exception as exc:  # noqa: BLE001 - the hold also expires on its own
            self._alert("release_hold", channel_id, exc)

    # -- distribute -------------------------------------------------------------------------------

    async def _settle(self, rpc: SolanaRpc, result: RedemptionResult, only: list[str] | None) -> None:
        payable = [r for r in await self._records(only) if r.status == "open" and r.settled > r.payout_watermark]
        # Channels sharing mint, token program and payTo share most accounts:
        # mixing them would outgrow one transaction.
        groups: dict[tuple[str, str, str], list[ChannelRecord]] = {}
        for record in payable:
            config = record.channel_config
            groups.setdefault((config["token"], record.token_program, config["receiver"]), []).append(record)
        for group in groups.values():
            for chunk in _chunks(group, self._batch_size()):
                await self._settle_chunk(rpc, result, chunk, split_on_failure=True)

    async def _settle_chunk(
        self, rpc: SolanaRpc, result: RedemptionResult, chunk: list[ChannelRecord], *, split_on_failure: bool
    ) -> None:
        batch: list[tuple[ChannelRecord, Channel]] = []
        for record, channel in zip(chunk, await self._read(rpc, chunk), strict=True):
            if channel is None:
                continue
            record = await self._sync(record, channel)
            # A closing channel's distributable watermark is frozen; one
            # program rejection would fail every neighbour in the batch.
            open_now = int(channel.status) == CHANNEL_STATUS_OPEN and int(channel.closureStartedAt) == 0
            if open_now and int(channel.settlement.settled) > int(channel.settlement.payoutWatermark):
                batch.append((record, channel))
        if not batch:
            return
        try:
            await onchain.submit(rpc, self._fee_payer, [self._distribute(r, c) for r, c in batch])
        except onchain.UnconfirmedBroadcast as exc:
            _fail(result, [r for r, _ in batch], f"distribute not confirmed: {exc}")
            return
        except (BatchSettlementError, PaymentError) as exc:
            if split_on_failure and len(batch) > 1:
                for record, _ in batch:
                    await self._settle_chunk(rpc, result, [record], split_on_failure=False)
            else:
                _fail(result, [r for r, _ in batch], f"distribute failed: {exc}")
            return
        observed = await self._read_visible(rpc, [r for r, _ in batch])
        now = self._clock()
        for (record, before), channel in zip(batch, observed, strict=True):
            paid = None if channel is None else int(channel.settlement.payoutWatermark)
            if channel is None or paid is None or not 0 <= paid <= int(channel.deposit):
                result.errors.append((record.channel_id, "distribute confirmed but the payout is not visible"))
                continue
            # A confirmed distribute is activity: it resets the idle clock.
            await self._record_after_broadcast(
                "distribute",
                record.channel_id,
                _touched(channel, now),
            )
            if paid >= int(before.settlement.settled):
                result.distributed.append(record.channel_id)

    # -- finalize, reclaim, idle close -----------------------------------------------------------------

    async def _finalize(self, rpc: SolanaRpc, result: RedemptionResult) -> None:
        """After the grace period: permissionless ``seal`` plus a sealed ``distribute``, one channel per transaction."""
        records = [r for r in await self._records(None) if r.status != "distributed"]
        now = self._clock()
        for chunk in _chunks(records, _READ_CHUNK):
            for record, channel in zip(chunk, await self._read(rpc, chunk), strict=True):
                if channel is None:
                    await self._vanished(rpc, record)
                    continue
                record = await self._sync(record, channel)
                status = int(channel.status)
                due = int(channel.closureStartedAt) + int(channel.gracePeriod)
                if status == CHANNEL_STATUS_CLOSING and now >= due:
                    channel_key = Pubkey.from_string(record.channel_id)
                    instructions = [build_seal_instruction(channel=channel_key, program_id=self._program_id)]
                elif status == CHANNEL_STATUS_SEALED:
                    instructions = []
                else:
                    continue
                instructions.append(self._distribute(record, channel))
                if await self._submit_final(rpc, result, record, instructions, int(channel.settlement.settled)):
                    result.finalized.append(record.channel_id)

    async def _reclaim(self, rpc: SolanaRpc, result: RedemptionResult, extra: list[str] | None) -> None:
        records = {r.channel_id: r for r in await self._records(None) if r.status == "distributed"}
        extra_ids: list[str] = [*(extra or []), *sorted(self._reclaim_only)]
        ids = list(dict.fromkeys([*records, *extra_ids]))
        if not ids:
            return
        slot = await rpc.get_slot()
        eligible: list[str] = []
        for chunk in _chunks(ids, _READ_CHUNK):
            for channel_id, channel in zip(chunk, await self._read_ids(rpc, chunk), strict=True):
                if channel is None:
                    if channel_id in records:  # already reclaimed: drop the record
                        await self._record_after_broadcast("reclaim", channel_id, None)
                    self._reclaim_only.discard(channel_id)
                    continue
                window_passed = slot > int(channel.openSlot) + OPEN_SLOT_WINDOW
                if int(channel.status) == CHANNEL_STATUS_DISTRIBUTED and window_passed:
                    eligible.append(channel_id)
        rent_payer = Pubkey.from_string(self._fee_payer.pubkey())
        for chunk in _chunks(eligible, self._batch_size()):
            instructions = [
                build_reclaim_instruction(
                    channel=Pubkey.from_string(channel_id), rent_payer=rent_payer, program_id=self._program_id
                )
                for channel_id in chunk
            ]
            try:
                await onchain.submit(rpc, self._fee_payer, instructions)
            except (onchain.UnconfirmedBroadcast, BatchSettlementError, PaymentError) as exc:
                result.errors.extend((channel_id, f"reclaim failed: {exc}") for channel_id in chunk)
                continue
            for channel_id in chunk:
                await self._record_after_broadcast("reclaim", channel_id, None)
                self._reclaim_only.discard(channel_id)
                await self._drop_operations(channel_id)
                result.reclaimed.append(channel_id)

    async def _close_idle(self, rpc: SolanaRpc, result: RedemptionResult) -> None:
        """Seal open channels idle for ``max_idle_secs`` with their latest charged voucher (off by default)."""
        idle = self._settings.max_idle_secs
        if idle is None or idle <= 0:
            return
        now = self._clock()
        for record in await self._records(None):
            last = record.last_activity_at
            if record.status != "open" or last is None or now - last < idle or record.live_reservations(now):
                continue
            if record.signed_max_claimable > record.charged_cumulative:
                self._alert("idle_above_charged", record.channel_id, ValueError("signed above charged"))
                continue
            try:
                held = await self._store.update(
                    record.channel_id, lambda current: _hold(current, now, idle, self._settings.max_timeout_seconds)
                )
            except _Skip:
                continue
            channel = await onchain.read_channel(rpc, held.channel_id, self._program_id)
            if channel is None or int(channel.status) != CHANNEL_STATUS_OPEN or int(channel.closureStartedAt) != 0:
                await self._store.update(held.channel_id, _release_hold)
                continue
            signed = held.signed_max_claimable
            instructions = [
                *self._settle_and_seal(held, signed, settled=int(channel.settlement.settled)),
                self._distribute(held, channel),
            ]
            # On failure the hold stays until it expires: the close may still
            # land, and no request should be charged on a channel being sealed.
            if await self._submit_final(rpc, result, held, instructions, signed):
                result.idle_closed.append(held.channel_id)

    # -- helpers -----------------------------------------------------------------------------------

    async def _submit_final(
        self,
        rpc: SolanaRpc,
        result: RedemptionResult,
        record: ChannelRecord,
        instructions: list[Instruction],
        final: int,
    ) -> bool:
        """Send a seal-and-distribute; on confirmation record the channel paid out at ``final``."""
        try:
            await onchain.submit(rpc, self._fee_payer, instructions)
        except (onchain.UnconfirmedBroadcast, BatchSettlementError, PaymentError) as exc:
            result.errors.append((record.channel_id, f"close failed: {exc}"))
            return False
        now = self._clock()

        def paid_out(current: ChannelRecord | None) -> ChannelRecord:
            base = _release_hold(current)
            return replace(
                base,
                status="distributed",
                settled=max(base.settled, final),
                payout_watermark=max(base.payout_watermark, final),
                last_activity_at=now,
            )

        await self._record_after_broadcast("close", record.channel_id, paid_out)
        return True

    def _settle_and_seal(self, record: ChannelRecord, signed: int, *, settled: int) -> list[Instruction]:
        """``[ed25519, settle_and_seal]`` at ``signed``, or a bare seal at ``settled`` when nothing is above it."""
        signature = record.voucher_signature
        # An equal voucher would fail the program's strictly increasing check.
        has_voucher = signed > settled and signature is not None
        return build_settle_and_seal_instructions(
            payee=Pubkey.from_string(self._fee_payer.pubkey()),
            channel=Pubkey.from_string(record.channel_id),
            authorized_signer=Pubkey.from_string(record.channel_config["payerAuthorizer"]),
            signature=bytes(Signature.from_string(signature)) if has_voucher and signature is not None else None,
            cumulative=signed,
            expires_at=0,
            program_id=self._program_id,
        )

    def _distribute(self, record: ChannelRecord, channel: Channel) -> Instruction:
        return onchain.distribute_instruction(
            channel_id=record.channel_id,
            channel=channel,
            fee_payer=self._fee_payer.pubkey(),
            pay_to=record.channel_config["receiver"],
            token_program=record.token_program,
            program_id=self._program_id,
        )

    async def _records(self, only: list[str] | None) -> list[ChannelRecord]:
        records = await self._store.list()
        return records if only is None else [r for r in records if r.channel_id in set(only)]

    async def _read(self, rpc: SolanaRpc, records: list[ChannelRecord]) -> list[Channel | None]:
        return await self._read_ids(rpc, [r.channel_id for r in records])

    async def _read_ids(self, rpc: SolanaRpc, channel_ids: list[str]) -> list[Channel | None]:
        """Read and decode each account on its own: a foreign or malformed one reads as absent and is alerted."""
        try:
            accounts: list[tuple[bytes, str] | None] = await rpc.get_multiple_accounts(channel_ids)
        except MalformedAccountError:
            accounts = []
            for channel_id in channel_ids:
                try:
                    accounts.append(await rpc.get_account_info(channel_id))
                except MalformedAccountError as exc:
                    self._alert("channel_account_unreadable", channel_id, exc)
                    accounts.append(None)
        channels: list[Channel | None] = []
        for channel_id, account in zip(channel_ids, accounts, strict=True):
            if account is None:
                channels.append(None)
                continue
            try:
                channels.append(decode_channel(account[0], account[1], self._program_id))
            except BatchSettlementError as exc:
                self._alert("channel_account_unreadable", channel_id, exc)
                channels.append(None)
        return channels

    async def _vanished(self, rpc: SolanaRpc, record: ChannelRecord) -> None:
        """A stored channel whose account did not read back.

        An absent read is not evidence that the channel is gone: a lagging
        replica, an outage or a rate limit answers null for a channel that is
        still open, and this record holds the voucher and the charge watermark
        this server has yet to redeem. So a record is dropped only where
        nothing can be lost: a failed open that never confirmed a setup, or a
        channel ``reclaim`` itself freed, which it drops there. Anything else is
        kept and alerted once, for the next pass to read again.
        """
        opened = record.deposit > 0 or record.onchain_synced_at is not None or record.processed_setup_signatures
        if not opened:
            await self._record_after_broadcast("vanished", record.channel_id, None)
            return
        if record.live_reservations(self._clock()):
            return  # an open or a request is still in flight
        if await self._visible_again(rpc, record.channel_id):
            self._absent.discard(record.channel_id)
            return
        if record.channel_id not in self._absent:
            self._absent.add(record.channel_id)
            self._alert("channel_account_absent", record.channel_id, ValueError(f"status {record.status}"))

    async def _visible_again(self, rpc: SolanaRpc, channel_id: str) -> bool:
        """Re-read an account that looked absent; short, because the next pass reads it again anyway."""
        try:
            account = await read_with_replica_retry(
                lambda: rpc.get_account_info(channel_id), attempts=3, backoff_step_seconds=0.1
            )
        except MalformedAccountError as exc:
            self._alert("channel_account_unreadable", channel_id, exc)
            return False
        return account is not None

    async def _drop_operations(self, channel_id: str) -> None:
        if self._operations is None:
            return
        try:
            await self._operations.drop_channel(channel_id)
        except Exception as exc:  # noqa: BLE001 - stale operation records are harmless
            self._alert("drop_operations", channel_id, exc)

    async def _read_visible(self, rpc: SolanaRpc, records: list[ChannelRecord]) -> list[Channel | None]:
        """Re-read after a confirmed broadcast, absorbing replica lag on accounts not yet visible."""

        async def read() -> list[Channel | None] | None:
            channels = await self._read(rpc, records)
            return None if any(channel is None for channel in channels) else channels

        return await read_with_replica_retry(read) or await self._read(rpc, records)

    async def _sync(self, record: ChannelRecord, channel: Channel) -> ChannelRecord:
        """Fold a fresh read into the record (not after a broadcast: a failure skips this channel)."""
        now = self._clock()
        try:
            return await self._store.update(record.channel_id, lambda current: _fold(current, channel, now))
        except Exception as exc:  # noqa: BLE001 - leave this channel for the next pass
            self._alert("sync", record.channel_id, exc)
            return record

    async def _record_after_broadcast(
        self, event: str, channel_id: str, mutator: Callable[[ChannelRecord | None], ChannelRecord] | None
    ) -> None:
        """Store write after a confirmed broadcast (``None`` deletes): alerted, never re-raised."""
        try:
            if mutator is None:
                await self._store.delete(channel_id)
            else:
                await self._store.update(channel_id, mutator)
        except Exception as exc:  # noqa: BLE001 - the broadcast already landed
            self._alert(event, channel_id, exc)

    def _batch_size(self) -> int:
        return min(MAX_CLAIMS_PER_BATCH, max(1, self._settings.batch_size))


def _touched(channel: Channel, now: float) -> Callable[[ChannelRecord | None], ChannelRecord]:
    """Fold a confirmed read and reset the idle clock: a confirmed claim or distribute is activity."""
    return lambda current: replace(_fold(current, channel, now), last_activity_at=now)


def _fold(current: ChannelRecord | None, channel: Channel, now: float) -> ChannelRecord:
    if current is None:
        raise _Skip("channel record vanished")
    return onchain.fold(current, channel, now)


def _hold(current: ChannelRecord | None, now: float, idle: int, ttl: int) -> ChannelRecord:
    """Take the channel for an idle close unless a request arrived meanwhile."""
    last = None if current is None else current.last_activity_at
    if current is None or current.status != "open" or last is None or now - last < idle:
        raise _Skip("channel is no longer idle")
    if current.live_reservations(now):
        raise _Skip("channel has a request in flight")
    return replace(current, reservations={_HOLD: Reservation(0, "close", now + ttl)})


def _seal_hold(current: ChannelRecord | None, now: float, *, room: float, wait: float, ttl: int) -> ChannelRecord:
    """Take a closing channel for its seal; wait for requests in flight while the grace period allows."""
    if current is None:
        raise _Skip("channel record vanished")
    if current.live_reservations(now) and room > wait:
        raise _Skip("request in flight")
    # Near the end of the grace period the seal wins: dropping the (possibly
    # expired) reservations makes their late commits fail instead of charging.
    return replace(current, reservations={_HOLD: Reservation(0, "close", now + ttl)})


def _release_hold(current: ChannelRecord | None) -> ChannelRecord:
    if current is None:
        raise _Skip("channel record vanished")
    return replace(current, reservations={k: v for k, v in current.reservations.items() if k != _HOLD})


def _voucher_signature(record: ChannelRecord) -> str:
    signature = record.voucher_signature
    assert signature is not None  # claim eligibility requires one
    return signature


def _fail(result: RedemptionResult, records: list[ChannelRecord], detail: str) -> None:
    result.errors.extend((record.channel_id, detail) for record in records)


def _chunks(items: list[_T], size: int) -> list[list[_T]]:
    return [items[i : i + size] for i in range(0, len(items), size)]
