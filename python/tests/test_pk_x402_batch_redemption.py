"""x402 ``batch-settlement`` redemption worker over a fake chain.

Names follow the x402 PR #23 ``batch.channelManager*.test.ts``, ``batch.seal.test.ts``
and ``payment-channels.rentCleanup.test.ts`` cases they mirror.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.paymentchannels import (
    CHANNEL_RENT_PAYER_OFFSET,
    ED25519_PROGRAM_ID,
    PAYMENT_CHANNELS_PROGRAM_ID,
    find_channel_pda,
)
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.protocols.x402.batch_settlement.engine import (
    BatchSettlementConfig,
    VerifiedBatchRequest,
    X402BatchSettlement,
)
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.redemption import BatchRedemption
from solana_pay_kit.protocols.x402.batch_settlement.signatures import sign_voucher
from solana_pay_kit.protocols.x402.batch_settlement.store import ChannelRecord, MemoryBatchChannelStore, Reservation
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchChannelConfig
from solana_pay_kit.signer import LocalSigner
from tests.batch_chain import CLOSING, DISTRIBUTED, MINT, PRICE, SLOT, World, channel_account, make_world

NOW = 1_700_000_000.0
GRACE = 900


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    return make_world(monkeypatch)


class _Harness:
    def __init__(self, world: World, clock: list[float], **settings: Any) -> None:
        self.world = world
        self.store = MemoryBatchChannelStore()
        self.alerts: list[str] = []
        self.engine = X402BatchSettlement(
            world.config,
            settings=BatchSettlementConfig(**settings),
            channel_store=self.store,
            rpc=world.chain,  # type: ignore[arg-type]
            clock=lambda: clock[0],
            on_alert=lambda event, _details: self.alerts.append(event),
        )
        self.worker: BatchRedemption = self.engine.redemption()

    async def seed(
        self,
        salt: int = 0,
        *,
        charged: int = 2 * PRICE,
        deposit: int = 5 * PRICE,
        settled: int = 0,
        signed: int | None = None,
        last: float | None = NOW,
        receiver: str | None = None,
        **chain: Any,
    ) -> str:
        """A charged channel in the store and its account on chain."""
        overrides = {} if receiver is None else {"receiver": receiver}
        config: BatchChannelConfig = self.world.channel_config(salt=str(salt), **overrides)
        channel_id = self.world.put_channel(config, deposit=deposit, settled=settled, **chain)
        signed = charged if signed is None else signed
        record = ChannelRecord(
            channel_id,
            config,
            self.world.config.network.caip2(),
            self.world.fee_payer.pubkey(),
            TOKEN_PROGRAM,
            deposit=deposit,
            settled=settled,
            charged_cumulative=charged,
            signed_max_claimable=signed,
            voucher_signature=sign_voucher(self.world.payer, channel_id, signed)["signature"],
            last_activity_at=last,
        )
        await self.store.update(channel_id, lambda _: record)
        return channel_id

    def lands(self, channel_id: str, salt: int = 0, **fields: Any) -> None:
        config = self.world.channel_config(salt=str(salt))

        def land(_tx: VersionedTransaction) -> None:
            data = channel_account(config, self.world.fee_payer.pubkey(), self.world.pay_to, **fields)
            self.world.chain.accounts[channel_id] = (data, PAYMENT_CHANNELS_PROGRAM_ID)

        self.world.chain.effects.append(land)

    async def record(self, channel_id: str) -> ChannelRecord:
        record = await self.store.get(channel_id)
        assert record is not None
        return record


def _programs(tx: VersionedTransaction) -> list[str]:
    keys = [str(k) for k in tx.message.account_keys]
    return [keys[ix.program_id_index] for ix in tx.message.instructions]


def _data(tx: VersionedTransaction) -> list[int]:
    """First data byte of each payment-channels instruction (the discriminator)."""
    keys = [str(k) for k in tx.message.account_keys]
    return [
        bytes(ix.data)[0] for ix in tx.message.instructions if keys[ix.program_id_index] == PAYMENT_CHANNELS_PROGRAM_ID
    ]


SETTLE, SETTLE_AND_SEAL, SEAL, DISTRIBUTE, RECLAIM = 2, 4, 6, 7, 9


# -- claim and distribute ----------------------------------------------------------------------


async def test_a_pass_claims_the_charged_voucher_then_distributes_it(world: World) -> None:
    clock = [NOW]
    h = _Harness(world, clock)
    channel_id = await h.seed(last=NOW - 50)
    h.lands(channel_id, deposit=5 * PRICE, settled=2 * PRICE)
    h.lands(channel_id, deposit=5 * PRICE, settled=2 * PRICE, payout=2 * PRICE)
    result = await h.worker.run_pass()
    claim, distribute = world.chain.sent
    assert _programs(claim)[0] == ED25519_PROGRAM_ID and _data(claim) == [SETTLE]
    assert bytes(claim.message.instructions[0].data)[146:154] == (2 * PRICE).to_bytes(8, "little")
    assert _data(distribute) == [DISTRIBUTE]
    assert (result.claimed, result.distributed) == ([channel_id], [channel_id])
    record = await h.record(channel_id)
    assert (record.settled, record.payout_watermark, record.last_activity_at) == (2 * PRICE, 2 * PRICE, NOW)


async def test_at_most_four_channels_share_a_claim_and_the_size_is_clamped(world: World) -> None:
    for size, expected in ((10, [4, 1]), (0, [1, 1, 1, 1, 1]), (2, [2, 2, 1])):
        world.chain.sent.clear()
        h = _Harness(world, [NOW], max_channels_per_batch=size)
        for salt in range(5):
            await h.seed(salt)
        await h.worker.claim()
        assert [_data(tx).count(SETTLE) for tx in world.chain.sent] == expected, size


async def test_a_failed_claim_is_left_for_the_next_pass(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed()
    world.chain.send_error = PaymentError("node down", code="payment_invalid")
    result = await h.worker.claim()
    assert result.claimed == [] and result.errors and (await h.record(channel_id)).settled == 0
    world.chain.send_error = None
    h.lands(channel_id, deposit=5 * PRICE, settled=2 * PRICE)
    assert (await h.worker.claim()).claimed == [channel_id]


async def test_an_unconfirmed_claim_is_not_rebuilt(world: World) -> None:
    h = _Harness(world, [NOW])
    await h.seed()
    world.chain.confirm_error = PaymentError("timed out", code="transaction-not-found")
    result = await h.worker.claim()
    assert len(world.chain.sent) == 1 and result.errors and result.claimed == []


async def test_only_what_was_charged_is_ever_claimed(world: World) -> None:
    h = _Harness(world, [NOW])
    await h.seed(charged=2 * PRICE, signed=3 * PRICE)
    result = await h.worker.claim()
    assert world.chain.sent == [] and result.claimed == [] and h.alerts == ["claim_above_charged"]


async def test_a_claim_is_recorded_only_once_its_settled_watermark_is_visible(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed()
    h.lands(channel_id, deposit=5 * PRICE, settled=PRICE)  # stale replica: below the claim
    result = await h.worker.claim()
    assert result.claimed == [] and result.errors and (await h.record(channel_id)).settled == 0


async def test_a_vanished_channel_is_skipped(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed()
    del world.chain.accounts[channel_id]
    result = await h.worker.run_pass()
    assert world.chain.sent == [] and result.claimed == []


async def test_a_distribute_needs_a_sane_payout_watermark(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed(settled=2 * PRICE)
    h.lands(channel_id, deposit=5 * PRICE, settled=2 * PRICE, payout=6 * PRICE)  # above the deposit
    result = await h.worker.settle()
    assert result.distributed == [] and result.errors


async def test_a_store_failure_after_a_confirmed_claim_is_alerted_not_raised(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed()
    h.lands(channel_id, deposit=5 * PRICE, settled=2 * PRICE)
    original = h.store.update
    calls = [0]

    async def fail_after_sync(channel_id: str, mutator: Any) -> ChannelRecord:
        calls[0] += 1
        if calls[0] > 1:
            raise RuntimeError("disk full")
        return await original(channel_id, mutator)

    h.store.update = fail_after_sync  # type: ignore[method-assign]
    result = await h.worker.claim()
    assert result.claimed == [channel_id] and h.alerts == ["claim"]


# -- seal ------------------------------------------------------------------------------------------


async def test_a_closing_channel_is_sealed_with_its_latest_voucher(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed(status=CLOSING, closure_started_at=int(NOW) - 10)
    h.lands(channel_id, deposit=5 * PRICE, settled=2 * PRICE, payout=2 * PRICE, status=DISTRIBUTED)
    result = await h.worker.claim()
    (tx,) = world.chain.sent
    assert _programs(tx)[0] == ED25519_PROGRAM_ID and _data(tx) == [SETTLE_AND_SEAL, DISTRIBUTE]
    assert result.sealed == [channel_id]
    record = await h.record(channel_id)
    assert (record.status, record.settled, record.payout_watermark) == ("distributed", 2 * PRICE, 2 * PRICE)


async def test_a_closing_channel_with_nothing_left_to_apply_waits_for_the_post_grace_close(world: World) -> None:
    # The store lags the chain: the voucher is already fully settled, so an
    # equal voucher would fail the program's strictly increasing check and a
    # bare seal would only do the permissionless path's work early.
    clock = [NOW]
    h = _Harness(world, clock)
    channel_id = await h.seed(charged=3 * PRICE, settled=2 * PRICE)
    world.put_channel(
        world.channel_config(salt="0"),
        deposit=5 * PRICE,
        settled=3 * PRICE,
        status=CLOSING,
        closure_started_at=int(NOW) - 10,
    )
    result = await h.worker.claim()
    assert world.chain.sent == [] and (result.sealed, result.errors) == ([], [])
    clock[0] = NOW - 10 + GRACE  # the grace period ran out; the close needs no voucher
    finalized = await h.worker.finalize_close()
    (tx,) = world.chain.sent
    assert ED25519_PROGRAM_ID not in _programs(tx) and _data(tx) == [SEAL, DISTRIBUTE]
    assert finalized.finalized == [channel_id]


async def test_a_seal_outside_the_grace_period_is_refused(world: World) -> None:
    h = _Harness(world, [NOW])
    await h.seed(status=CLOSING, closure_started_at=int(NOW) - GRACE)
    result = await h.worker.claim()
    assert world.chain.sent == [] and result.sealed == [] and result.errors


class _MisconfiguredSigner(LocalSigner):
    """A remote signer whose key does not match the key it reports."""

    def sign(self, message: bytes) -> bytes:
        return bytes(Keypair().sign_message(message))


async def test_a_close_authorization_that_does_not_verify_is_never_broadcast(world: World) -> None:
    wrong = _MisconfiguredSigner.from_keypair(Keypair())
    h = _Harness(world, [NOW], close_authorizer=wrong)
    await h.seed(status=CLOSING, closure_started_at=int(NOW) - 10)
    result = await h.worker.claim()
    assert world.chain.sent == [] and result.sealed == [] and result.errors


async def test_a_claim_that_meets_a_close_splits_and_seals_the_closing_channel(world: World) -> None:
    h = _Harness(world, [NOW])
    a = await h.seed(0)
    b = await h.seed(1)

    original = world.chain.send_raw_transaction
    first = [True]

    async def refuse_first(raw: bytes) -> Any:
        if first[0]:
            first[0] = False
            world.put_channel(
                world.channel_config(salt="1"), deposit=5 * PRICE, status=CLOSING, closure_started_at=int(NOW)
            )
            raise PaymentError("channel is closing", code="payment_invalid")
        return await original(raw)

    world.chain.send_raw_transaction = refuse_first  # type: ignore[method-assign]
    h.lands(a, 0, deposit=5 * PRICE, settled=2 * PRICE)
    h.lands(b, 1, deposit=5 * PRICE, settled=2 * PRICE, payout=2 * PRICE, status=DISTRIBUTED)
    result = await h.worker.claim()
    assert result.claimed == [a] and result.sealed == [b]


# -- finalize, reclaim, idle close -------------------------------------------------------------------


async def test_finalize_waits_out_the_grace_period(world: World) -> None:
    h = _Harness(world, [NOW])
    await h.seed(charged=0, signed=0, status=CLOSING, closure_started_at=int(NOW) - GRACE + 1)
    assert (await h.worker.finalize_close()).finalized == [] and world.chain.sent == []


async def test_finalize_after_the_grace_period_seals_and_distributes(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed(charged=0, signed=0, status=CLOSING, closure_started_at=int(NOW) - GRACE)
    result = await h.worker.run_pass()
    (tx,) = world.chain.sent
    assert _data(tx) == [SEAL, DISTRIBUTE] and result.finalized == [channel_id]
    assert (await h.record(channel_id)).status == "distributed"


async def test_reclaim_waits_for_the_open_slot_window(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed(status=DISTRIBUTED, settled=2 * PRICE, payout=2 * PRICE)
    await h.store.update(channel_id, lambda current: replace(current, status="distributed"))  # type: ignore[arg-type]
    world.chain.slot = SLOT + 1_500
    assert (await h.worker.reclaim()).reclaimed == []
    world.chain.slot = SLOT + 1_501
    result = await h.worker.reclaim()
    (tx,) = world.chain.sent
    assert _data(tx) == [RECLAIM] and result.reclaimed == [channel_id]
    assert await h.store.get(channel_id) is None


async def test_idle_close_is_off_by_default_and_advertised_only_when_on(world: World) -> None:
    h = _Harness(world, [NOW])
    await h.seed(last=NOW - 10**9, settled=2 * PRICE, payout=2 * PRICE)
    assert (await h.worker.run_pass()).idle_closed == [] and world.chain.sent == []
    assert "maxIdleSecs" not in h.engine.accepts_entries(world.gate, {})[0]["extra"]
    on = _Harness(world, [NOW], max_idle_secs=3600)
    assert on.engine.accepts_entries(world.gate, {})[0]["extra"].get("maxIdleSecs") == 3600


async def test_idle_close_seals_with_the_latest_voucher_at_the_window(world: World) -> None:
    clock = [NOW]
    h = _Harness(world, clock, max_idle_secs=3600)
    channel_id = await h.seed(last=NOW - 3599)
    assert (await h.worker.close_idle()).idle_closed == [] and world.chain.sent == []
    clock[0] += 1
    result = await h.worker.close_idle()
    (tx,) = world.chain.sent
    # Sealed at the charged voucher, not at the on-chain settled watermark.
    assert _programs(tx)[0] == ED25519_PROGRAM_ID and _data(tx) == [SETTLE_AND_SEAL, DISTRIBUTE]
    assert result.idle_closed == [channel_id] and (await h.record(channel_id)).status == "distributed"


async def test_idle_close_waits_for_requests_in_flight(world: World) -> None:
    h = _Harness(world, [NOW], max_idle_secs=60)
    channel_id = await h.seed(last=NOW - 3600, settled=2 * PRICE, payout=2 * PRICE)
    await h.store.update(
        channel_id,
        lambda current: replace(current, reservations={"r": Reservation(PRICE, "client", NOW + 60)}),  # type: ignore[arg-type]
    )
    assert (await h.worker.run_pass()).idle_closed == [] and world.chain.sent == []


async def test_a_confirmed_distribute_resets_the_idle_clock(world: World) -> None:
    h = _Harness(world, [NOW], max_idle_secs=60)
    channel_id = await h.seed(last=NOW - 3600, settled=2 * PRICE)
    h.lands(channel_id, deposit=5 * PRICE, settled=2 * PRICE, payout=2 * PRICE)
    result = await h.worker.run_pass()
    assert result.distributed == [channel_id] and result.idle_closed == []
    assert (await h.record(channel_id)).last_activity_at == NOW


# -- discovery and the loop --------------------------------------------------------------------------


async def test_discovery_trusts_only_channels_that_rederive_to_their_address(world: World) -> None:
    h = _Harness(world, [NOW])
    config = world.channel_config()
    good = world.channel_id(config)
    data = channel_account(config, world.fee_payer.pubkey(), world.pay_to, deposit=PRICE)
    world.chain.program_accounts = [(good, data), (str(Pubkey.new_unique()), data), (good, b"\x00" * 256)]
    # Correctly derived, but the sponsor holds only one of its two seats.
    stranger, sponsor = Pubkey.new_unique(), bytes(Pubkey.from_string(world.fee_payer.pubkey()))
    foreign_config = world.channel_config(salt="1")
    foreign_id = find_channel_pda(
        Pubkey.from_string(world.payer.pubkey()),
        stranger,
        Pubkey.from_string(MINT),
        Pubkey.from_string(world.payer.pubkey()),
        1,
        SLOT,
    )[0]
    foreign_payee = bytearray(channel_account(foreign_config, str(stranger), world.pay_to, deposit=PRICE))
    foreign_payee[CHANNEL_RENT_PAYER_OFFSET : CHANNEL_RENT_PAYER_OFFSET + 32] = sponsor
    foreign_rent = bytearray(data)
    foreign_rent[CHANNEL_RENT_PAYER_OFFSET : CHANNEL_RENT_PAYER_OFFSET + 32] = bytes(stranger)
    world.chain.program_accounts += [(str(foreign_id), bytes(foreign_payee)), (good, bytes(foreign_rent))]
    assert await h.worker.discover() == [good]


async def test_the_worker_loop_runs_passes_until_stopped(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed(settled=2 * PRICE)
    h.lands(channel_id, deposit=5 * PRICE, settled=2 * PRICE, payout=2 * PRICE)
    h.worker.start(0.01)
    for _ in range(50):
        if world.chain.sent:
            break
        await asyncio.sleep(0.01)
    await h.worker.stop(flush=True)
    assert world.chain.sent and (await h.record(channel_id)).payout_watermark == 2 * PRICE


async def test_a_failing_recovery_scan_does_not_skip_the_loops_pass(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed(settled=2 * PRICE)
    h.lands(channel_id, deposit=5 * PRICE, settled=2 * PRICE, payout=2 * PRICE)

    async def scan_down(*_: Any, **__: Any) -> Any:
        raise PaymentError("getProgramAccounts is down")

    world.chain.get_program_accounts = scan_down  # type: ignore[method-assign]
    h.worker.start(60)  # the first pass runs at once, the next only a minute later
    for _ in range(50):
        if world.chain.sent:
            break
        await asyncio.sleep(0.01)
    await h.worker.stop()
    assert world.chain.sent and h.alerts == ["redemption_recover"]


async def test_one_channel_that_keeps_failing_does_not_block_its_batch(world: World) -> None:
    h = _Harness(world, [NOW])
    good = await h.seed(0)
    bad = await h.seed(1)
    original = world.chain.send_raw_transaction

    async def refuse_the_bad_channel(raw: bytes) -> Any:
        tx = VersionedTransaction.from_bytes(raw)
        if Pubkey.from_string(bad) in tx.message.account_keys:
            raise PaymentError("custom program error", code="payment_invalid")
        return await original(raw)

    world.chain.send_raw_transaction = refuse_the_bad_channel  # type: ignore[method-assign]
    h.lands(good, 0, deposit=5 * PRICE, settled=2 * PRICE)
    result = await h.worker.claim()
    assert result.claimed == [good] and [channel for channel, _ in result.errors] == [bad]


async def test_idle_close_never_seals_above_what_was_charged(world: World) -> None:
    h = _Harness(world, [NOW], max_idle_secs=60)
    await h.seed(charged=2 * PRICE, signed=3 * PRICE, last=NOW - 3600)
    assert (await h.worker.close_idle()).idle_closed == [] and world.chain.sent == []
    assert h.alerts == ["idle_above_charged"]


async def test_idle_close_loses_the_race_to_a_request_that_just_arrived(world: World) -> None:
    # The pass listed the channel as idle; a request reserved it before the
    # close took the channel. The close must back off, not seal under it.
    h = _Harness(world, [NOW], max_idle_secs=60)
    channel_id = await h.seed(last=NOW - 3600, settled=2 * PRICE, payout=2 * PRICE)
    stale = await h.store.list()
    await h.store.update(
        channel_id,
        lambda current: replace(current, reservations={"r": Reservation(PRICE, "client", NOW + 60)}),  # type: ignore[arg-type]
    )

    async def stale_list() -> list[ChannelRecord]:
        return stale

    h.store.list = stale_list  # type: ignore[method-assign]
    assert (await h.worker.close_idle()).idle_closed == [] and world.chain.sent == []


# -- the seal takes the channel first -----------------------------------------------------------


async def test_a_seal_waits_for_a_request_in_flight_until_the_grace_period_runs_short(world: World) -> None:
    clock = [NOW]
    h = _Harness(world, clock)
    channel_id = await h.seed(charged=PRICE, signed=PRICE, deposit=5 * PRICE)
    request = world.header(
        h.engine.accepts_entries(world.gate, {})[0], world.voucher_payload(2 * PRICE, world.channel_config())
    )
    in_flight = await h.engine.verify_and_reserve(world.gate, request)
    assert isinstance(in_flight, VerifiedBatchRequest)
    # The payer starts a forced close while the request is being served.
    world.put_channel(deposit=5 * PRICE, status=CLOSING, closure_started_at=int(NOW) - 10)
    result = await h.worker.claim()
    assert world.chain.sent == [] and result.errors == [(channel_id, "request in flight")]
    # Near the end of the grace period the seal wins; the late charge is refused.
    clock[0] = NOW - 10 + GRACE - 100
    h.lands(channel_id, deposit=5 * PRICE, settled=PRICE, payout=PRICE, status=DISTRIBUTED)
    result = await h.worker.claim()
    assert result.sealed == [channel_id] and len(world.chain.sent) == 1
    with pytest.raises(BatchSettlementError):
        await h.engine.commit(in_flight)
    record = await h.record(channel_id)
    assert (record.status, record.charged_cumulative) == ("distributed", PRICE)


async def test_an_unconfirmed_seal_gives_the_channel_back(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed(status=CLOSING, closure_started_at=int(NOW) - 10)
    world.chain.send_error = PaymentError("node down", code="payment_invalid")
    result = await h.worker.claim()
    assert result.sealed == [] and result.errors
    assert (await h.record(channel_id)).reservations == {}


# -- distribute batches, unreadable accounts --------------------------------------------------


async def test_distribute_batches_group_channels_by_mint_token_program_and_pay_to(world: World) -> None:
    h = _Harness(world, [NOW])
    await h.seed(0, settled=2 * PRICE)
    await h.seed(1, settled=2 * PRICE)
    await h.seed(2, settled=2 * PRICE, receiver=str(Pubkey.new_unique()))
    await h.worker.settle()
    # One transaction for the two channels paying the same payTo, one for the other.
    assert sorted(len(_data(tx)) for tx in world.chain.sent) == [1, 2]


async def test_a_failed_distribute_batch_is_retried_one_channel_at_a_time(world: World) -> None:
    h = _Harness(world, [NOW])
    good = await h.seed(0, settled=2 * PRICE)
    bad = await h.seed(1, settled=2 * PRICE)
    original = world.chain.send_raw_transaction

    async def refuse_the_bad_channel(raw: bytes) -> Any:
        if Pubkey.from_string(bad) in VersionedTransaction.from_bytes(raw).message.account_keys:
            raise PaymentError("custom program error", code="payment_invalid")
        return await original(raw)

    world.chain.send_raw_transaction = refuse_the_bad_channel  # type: ignore[method-assign]
    h.lands(good, 0, deposit=5 * PRICE, settled=2 * PRICE, payout=2 * PRICE)
    result = await h.worker.settle()
    assert result.distributed == [good] and [channel for channel, _ in result.errors] == [bad]


async def test_a_foreign_account_at_a_stored_address_does_not_stop_the_pass(world: World) -> None:
    h = _Harness(world, [NOW])
    foreign = await h.seed(0)
    good = await h.seed(1)
    world.chain.accounts[foreign] = (bytes(256), TOKEN_PROGRAM)  # not a payment-channels account
    h.lands(good, 1, deposit=5 * PRICE, settled=2 * PRICE)
    result = await h.worker.run_pass()
    assert result.claimed == [good]
    assert "channel_account_unreadable" in h.alerts


async def test_a_vanished_account_drops_a_failed_open_and_alerts_for_an_opened_channel(world: World) -> None:
    h = _Harness(world, [NOW])
    opened = await h.seed(0)
    del world.chain.accounts[opened]
    provisional = world.channel_id(world.channel_config(salt="7"))
    await h.store.update(
        provisional,
        lambda _: ChannelRecord(
            provisional,
            world.channel_config(salt="7"),
            world.config.network.caip2(),
            world.fee_payer.pubkey(),
            TOKEN_PROGRAM,
        ),
    )
    await h.worker.finalize_close()
    assert await h.store.get(provisional) is None and await h.store.get(opened) is None
    assert h.alerts == ["channel_account_vanished"]


async def test_a_reclaimed_channel_forgets_its_operations(world: World) -> None:
    h = _Harness(world, [NOW])
    channel_id = await h.seed(status=DISTRIBUTED, settled=2 * PRICE, payout=2 * PRICE)
    await h.store.update(channel_id, lambda current: replace(current, status="distributed"))  # type: ignore[arg-type]
    operations = h.engine._operations  # noqa: SLF001
    await operations.reserve(channel_id, "req", PRICE, expires_at=NOW + 60, now=NOW)
    world.chain.slot = SLOT + 1_501
    assert (await h.worker.reclaim()).reclaimed == [channel_id]
    assert await operations.get(channel_id, "req") is None


# -- recovery after a lost store ------------------------------------------------------------


async def test_recover_rebuilds_sponsored_channels_at_their_settled_watermark(world: World) -> None:
    clock = [NOW]
    h = _Harness(world, clock)
    config = world.channel_config()
    channel_id = world.put_channel(config, deposit=5 * PRICE, settled=2 * PRICE)
    world.chain.program_accounts.append((channel_id, world.chain.accounts[channel_id][0]))
    stranger = world.channel_config(salt="3")
    stranger_id = world.channel_id(stranger)
    data = channel_account(stranger, world.fee_payer.pubkey(), str(Pubkey.new_unique()), deposit=PRICE)
    world.chain.program_accounts.append((stranger_id, data))
    assert await h.worker.recover() == [channel_id]
    record = await h.record(channel_id)
    assert record.channel_config == config and record.token_program == TOKEN_PROGRAM
    assert (record.charged_cumulative, record.signed_max_claimable, record.voucher_signature) == (
        2 * PRICE,
        2 * PRICE,
        None,
    )
    assert record.last_activity_at == NOW
    assert await h.store.get(stranger_id) is None  # an unknown payTo is only reclaimed, never charged
    # The rebuilt config is the one a client sends: its next voucher verifies.
    request = world.header(h.engine.accepts_entries(world.gate, {})[0], world.voucher_payload(3 * PRICE, config))
    assert isinstance(await h.engine.verify_and_reserve(world.gate, request), VerifiedBatchRequest)
    assert await h.worker.recover() == []  # known channels are left alone


async def test_recover_matches_the_pay_to_of_every_route_the_engine_advertised(world: World) -> None:
    h = _Harness(world, [NOW])
    route_pay_to = str(Keypair.from_seed(bytes([9] * 32)).pubkey())
    config = world.channel_config(receiver=route_pay_to)
    channel_id = world.channel_id(config)
    world.chain.program_accounts.append(
        (channel_id, channel_account(config, world.fee_payer.pubkey(), route_pay_to, deposit=5 * PRICE))
    )
    assert await h.worker.recover() == []  # no route pays there yet: reclaim only
    h.engine.accepts_entries(world.gate.model_copy(update={"pay_to": route_pay_to}), {})
    assert await h.worker.recover() == [channel_id]
    assert (await h.record(channel_id)).channel_config == config
