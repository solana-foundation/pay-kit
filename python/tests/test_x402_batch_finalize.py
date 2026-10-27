"""x402 ``batch-settlement`` close finalization and redemption submission:
the seal plan chosen in one store transition, the grace deadline, the payer
refund account guard, and per-channel failure isolation. Mirrors the Rust
kit's ``finalize_close`` / ``submit_groups`` tests."""

# pyright: reportOptionalMemberAccess=false, reportPrivateUsage=false

from __future__ import annotations

import dataclasses

import pytest
from solders.instruction import AccountMeta, Instruction
from solders.pubkey import Pubkey
from solders.signature import Signature

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.paymentchannels import build_seal_instruction, find_associated_token_address
from solana_pay_kit._paycore.rpc import PreflightRejectedError
from solana_pay_kit.protocols.x402.batch_settlement.server import (
    BatchAccessKind,
    BatchOutcome,
    BatchServerError,
    GraceSealKind,
    _Group,
    grace_seal_plan,
)
from solana_pay_kit.protocols.x402.batch_settlement.store import (
    BatchChannelRecord,
    PendingAuthorization,
    PendingSetup,
)
from tests._batch_fixture import MINT, PAYER, PROGRAM_ID, TOKEN, channel_account
from tests.test_x402_batch_server import PRICE, Harness

SETTLE = 2
SETTLE_AND_SEAL = 4
SEAL = 6
DISTRIBUTE = 7
NOW = 1_800_000_000


def program_steps(wire: bytes) -> list[int]:
    """The payment-channels instruction discriminators a transaction invokes."""
    tx = txv1.decode_transaction(wire)
    keys = list(tx.message.account_keys)
    return [bytes(ix.data)[0] for ix in tx.message.instructions if keys[ix.program_id_index] == PROGRAM_ID]


def sent_steps(h: Harness) -> list[list[int]]:
    return [program_steps(wire) for wire in h.rpc.sent]


async def paid(h: Harness) -> str:
    """Open a channel (cumulative 1000) and stop simulating chain effects."""
    await h.pay(await h.open())
    h.rpc.on_send = None
    h.rpc.sent.clear()
    return str(h.channel.channel_id)


async def reserve_next(h: Harness) -> BatchOutcome:
    """Reserve the next voucher and run its handler to success, uncommitted."""
    access = await h.server.verify_and_reserve_payment(h.header(await h.voucher()), PRICE)
    assert access.kind is BatchAccessKind.SERVE and access.outcome is not None
    await h.server.mark_handler_succeeded(access.outcome)
    return access.outcome


def closing(h: Harness, *, started: int, settled: int = 0, status: int = 2) -> None:
    h.rpc.put(
        h.channel.channel_id,
        channel_account(status=status, closure_started_at=started, settled=settled),
        PROGRAM_ID,
    )


def drop_payer_refund_account(h: Harness) -> None:
    ata, _ = find_associated_token_address(PAYER.pubkey(), MINT, TOKEN)
    h.rpc.accounts.pop(str(ata))


# ── the seal plan ──


async def test_closing_during_a_handler_keeps_its_charge_redeemable() -> None:
    h = Harness()
    channel = await paid(h)
    outcome = await reserve_next(h)
    # The payer's request_close lands while the served request is uncommitted.
    closing(h, started=NOW - 10)
    assert await h.server.finalize_close([channel]) == []
    assert h.rpc.sent == []
    record = await h.store.get(channel)
    assert record is not None and record.close_requested_at == NOW - 10
    assert record.final_cumulative is None, "a deferred seal fences nothing"
    # Past the deadline the finalizer still does not seal underneath it.
    assert grace_seal_plan(record, 0, True, NOW).kind is GraceSealKind.IN_FLIGHT

    # The handler's charge commits at 2000, then the seal carries it.
    await h.server.finish_commit(outcome)
    assert (await h.store.get(channel)).cumulative == 2000
    assert len(await h.server.finalize_close([channel])) == 1
    assert sent_steps(h) == [[SETTLE_AND_SEAL, DISTRIBUTE]]
    record = await h.store.get(channel)
    assert record is not None and record.final_cumulative == 2000 and record.sealed and record.settled_on_chain == 2000
    # With the chain already at that watermark there is nothing to apply early,
    # and past the deadline the frozen watermark is sealed permissionlessly.
    assert grace_seal_plan(record, 2000, False, NOW).kind is GraceSealKind.NOTHING_TO_APPLY
    assert grace_seal_plan(record, 2000, True, NOW).kind is GraceSealKind.SEAL_FROZEN


async def test_a_commit_delayed_across_its_lease_expiry_is_fenced_out_of_the_seal() -> None:
    h = Harness()
    channel = await paid(h)
    outcome = await reserve_next(h)
    # Wall-clock passes while the commit is stalled: the lease dies, and the
    # finalizer chooses the committed 1000 voucher and fences there.
    h.clock.now = NOW + 3_000
    chosen = await h.server._plan_close(channel, h.clock.now - 30, 0, False, h.clock.now)
    assert chosen is not None
    plan, record = chosen
    assert plan.kind is GraceSealKind.APPLY and plan.cumulative == 1000
    assert record.final_cumulative == 1000
    # The stalled commit resumes and is refused: nothing lands above the seal.
    with pytest.raises(Exception, match="final watermark"):
        await h.server.finish_commit(outcome)
    record = await h.store.get(channel)
    assert record.cumulative == 1000 and record.final_cumulative == 1000


def test_a_dead_reservation_does_not_block_the_seal() -> None:
    record = BatchChannelRecord(
        channel_id="c", payer_authorizer="p", deposit=5000, cumulative=2000, highest_voucher_signature="sig-2000"
    )

    def reservation(expires_at: int, handler_succeeded: bool) -> PendingAuthorization:
        return PendingAuthorization("a", "f", 1000, 3000, 1, expires_at, handler_succeeded)

    # A live lease blocks on both sides of the deadline, served or not.
    for succeeded in (False, True):
        record.pending = [reservation(NOW + 60, succeeded)]
        assert grace_seal_plan(record, 0, False, NOW).kind is GraceSealKind.IN_FLIGHT
        assert grace_seal_plan(record, 0, True, NOW).kind is GraceSealKind.IN_FLIGHT
    # A dead lease is gone whether or not its handler reported.
    for succeeded in (False, True):
        record.pending = [reservation(NOW - 1, succeeded)]
        plan = grace_seal_plan(record, 0, False, NOW)
        assert plan.kind is GraceSealKind.APPLY and plan.cumulative == 2000 and plan.signature == "sig-2000"
        assert grace_seal_plan(record, 0, True, NOW).kind is GraceSealKind.SEAL_FROZEN
    # A live setup blocks too; a dead one does not.
    record.pending = []
    record.pending_setup = PendingSetup("s", 1000, False, NOW + 60)
    assert grace_seal_plan(record, 0, False, NOW).kind is GraceSealKind.IN_FLIGHT
    record.pending_setup = PendingSetup("s", 1000, False, NOW)
    assert grace_seal_plan(record, 0, False, NOW).kind is GraceSealKind.APPLY
    # No voucher, or none above the chain: nothing to apply inside the grace.
    assert grace_seal_plan(record, 2000, False, NOW).kind is GraceSealKind.NOTHING_TO_APPLY
    unsigned = dataclasses.replace(record, highest_voucher_signature=None)
    assert grace_seal_plan(unsigned, 0, False, NOW).kind is GraceSealKind.NOTHING_TO_APPLY


async def test_plan_close_for_an_unknown_channel() -> None:
    h = Harness()
    assert await h.server._plan_close("unknown", 5, 0, True, NOW) is None
    assert await h.server._store.get("unknown") is None


# ── the grace deadline ──


async def test_finalize_close_seals_by_the_grace_deadline() -> None:
    h = Harness()
    channel = await paid(h)
    # Inside the grace period, the voucher above the chain is applied.
    closing(h, started=NOW - 10)
    await h.server.finalize_close([channel])
    assert sent_steps(h) == [[SETTLE_AND_SEAL, DISTRIBUTE]]

    # Inside the grace period with nothing to apply, it is left alone.
    h = Harness()
    channel = await paid(h)
    closing(h, started=NOW - 10, settled=1000)
    assert await h.server.finalize_close([channel]) == []
    record = await h.store.get(channel)
    assert record.close_requested_at == NOW - 10 and record.final_cumulative is None and not record.sealed

    # Past the deadline the program refuses vouchers: permissionless seal at
    # the frozen onchain watermark, then the distribute.
    h = Harness()
    channel = await paid(h)
    closing(h, started=NOW - 3600, settled=400)
    await h.server.finalize_close([channel])
    assert sent_steps(h) == [[SEAL, DISTRIBUTE]]
    sent = txv1.decode_transaction(h.rpc.sent[0])
    seal = build_seal_instruction(channel=h.channel.channel_id)
    assert bytes(sent.message.instructions[-2].data) == bytes(seal.data)
    record = await h.store.get(channel)
    assert record.final_cumulative == 400 and record.sealed and record.sealed_at == NOW

    # A channel this store never knew is sealed past the deadline like any crank.
    h = Harness()
    channel = await paid(h)
    closing(h, started=1)
    await h.store.update(channel, lambda _: None)
    await h.server.finalize_close([channel])
    assert sent_steps(h) == [[SEAL, DISTRIBUTE]]
    h.rpc.sent.clear()
    closing(h, started=NOW - 10)
    assert await h.server.finalize_close([channel]) == []

    # A Distributed channel only has its record finished.
    h = Harness()
    channel = await paid(h)
    closing(h, started=1, status=3)
    assert await h.server.finalize_close([channel]) == []
    assert (await h.store.get(channel)).sealed


# ── the payer refund account ──


async def finalize_once(status: int, payable: bool, sealed_at: int | None = None) -> tuple[list[list[int]], int | None]:
    """``finalize_close`` over a channel past its grace deadline with 9000 of
    the 10000 deposit due back to the payer."""
    h = Harness()
    channel = await paid(h)
    if sealed_at is not None:
        await h.store.update(channel, lambda r: dataclasses.replace(r, sealed_at=sealed_at) if r else None)
    closing(h, started=1, settled=1000, status=status)
    if not payable:
        drop_payer_refund_account(h)
    await h.server.finalize_close([channel])
    return sent_steps(h), (await h.store.get(channel)).sealed_at


@pytest.mark.parametrize(
    ("status", "payable", "expected"),
    [
        (1, True, [[DISTRIBUTE]]),
        (1, False, []),
        (2, True, [[SEAL, DISTRIBUTE]]),
        (2, False, [[SEAL]]),
    ],
)
async def test_finalize_close_never_distributes_into_an_unusable_refund_account(
    status: int, payable: bool, expected: list[list[int]]
) -> None:
    steps, sealed_at = await finalize_once(status, payable)
    assert steps == expected
    assert sealed_at == NOW, "the seal time a deferred distribute's deadline counts from"


async def test_a_deferred_distribute_runs_once_the_grace_period_after_the_seal_ends() -> None:
    inside = NOW - 3_599
    assert await finalize_once(1, False, inside) == ([], inside)
    past = NOW - 3_600
    assert await finalize_once(1, False, past) == ([[DISTRIBUTE]], past)
    assert (await finalize_once(1, True, inside))[0] == [[DISTRIBUTE]]


async def test_a_refund_account_that_cannot_be_paid_is_checked_only_when_a_refund_is_due() -> None:
    h = Harness()
    channel = await paid(h)
    # A frozen account defers the distribute.
    ata, _ = find_associated_token_address(PAYER.pubkey(), MINT, TOKEN)
    data, owner = h.rpc.accounts[str(ata)]
    frozen = bytearray(data)
    frozen[108] = 2
    h.rpc.accounts[str(ata)] = (bytes(frozen), owner)
    closing(h, started=1, settled=1000, status=1)
    await h.server.finalize_close([channel])
    assert sent_steps(h) == []
    # Fully settled: no refund is due, so the account is irrelevant.
    h.rpc.put(h.channel.channel_id, channel_account(status=1, settled=10_000), PROGRAM_ID)
    await h.server.finalize_close([channel])
    assert sent_steps(h) == [[DISTRIBUTE]]
    # An unreadable refund account is an RPC error, not a deferral.
    h.rpc.sent.clear()
    h.rpc.put(h.channel.channel_id, channel_account(status=1, settled=1000), PROGRAM_ID)
    original = h.rpc.get_account_info

    async def flaky(address: str, commitment: str = "confirmed") -> tuple[bytes, str] | None:
        if address == str(ata):
            raise RuntimeError("node down")
        return await original(address, commitment)

    h.rpc.get_account_info = flaky  # type: ignore[method-assign]
    with pytest.raises(BatchServerError, match="payer refund account"):
        await h.server.finalize_close([channel])


async def test_a_withdrawn_payer_needs_no_refund_account() -> None:
    from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel

    h = Harness()
    channel = await paid(h)
    drop_payer_refund_account(h)
    withdrawn = dataclasses.replace(
        Channel.deserialize(channel_account(status=1, settled=1000)), payer_withdrawn_at=NOW - 5
    )
    h.rpc.put(h.channel.channel_id, withdrawn.serialize(), PROGRAM_ID)
    await h.server.finalize_close([channel])
    assert sent_steps(h) == [[DISTRIBUTE]]


# ── submission ──


def _group(channel_id: str, key: Pubkey) -> _Group:
    return _Group(channel_id, [Instruction(PROGRAM_ID, bytes([SETTLE]), [AccountMeta(key, False, True)])])


async def test_a_failing_channel_does_not_fail_the_channels_packed_with_it() -> None:
    h = Harness()
    h.rpc.on_send = None
    keys = [Pubkey.new_unique() for _ in range(3)]
    poison = keys[1]

    def reject(wire: bytes) -> None:
        if poison in list(txv1.decode_transaction(wire).message.account_keys):
            raise PreflightRejectedError("custom program error: 0x1", code="payment_invalid")

    h.rpc.on_send = reject
    submitted = await h.server._submit_groups([_group(f"c{i}", key) for i, key in enumerate(keys)], 3)
    # The packed transaction, then each channel alone.
    assert len(h.rpc.sent) == 4
    assert submitted.landed == ["c0", "c2"] and len(submitted.signatures) == 2
    assert len(submitted.failures) == 1 and "c1" in submitted.failures[0]
    with pytest.raises(BatchServerError, match="1 of 3 settlement submissions failed"):
        submitted.raise_on_failure()
    assert (await h.server._submit_groups([], 3)).signatures == []


async def test_an_unknown_outcome_is_not_resubmitted_and_does_not_stop_the_rest() -> None:
    h = Harness()
    calls: list[int] = []

    def flaky(wire: bytes) -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("connection reset")

    h.rpc.on_send = flaky
    keys = [Pubkey.new_unique() for _ in range(3)]
    submitted = await h.server._submit_groups([_group(f"c{i}", key) for i, key in enumerate(keys)], 2)
    # [c0, c1] failed with an unknown outcome and is not split; [c2] still lands.
    assert len(h.rpc.sent) == 2
    assert submitted.landed == ["c2"] and submitted.total == 2
    assert len(submitted.failures) == 1 and "c0, c1" in submitted.failures[0]


async def _seed_claimable(h: Harness, status: int = 0, started: int = 0) -> list[str]:
    channels = [Pubkey.new_unique() for _ in range(2)]
    for channel in channels:
        h.rpc.put(channel, channel_account(status=status, closure_started_at=started), PROGRAM_ID)
        await h.store.put(
            BatchChannelRecord(
                channel_id=str(channel),
                payer_authorizer=str(PAYER.pubkey()),
                deposit=10_000,
                cumulative=1000,
                highest_voucher_signature=str(Signature.default()),
            )
        )
    return [str(channel) for channel in channels]


async def test_claim_records_the_channels_that_landed_before_reporting_failures() -> None:
    h = Harness()
    good, bad = await _seed_claimable(h)

    def reject(wire: bytes) -> None:
        if Pubkey.from_string(bad) in list(txv1.decode_transaction(wire).message.account_keys):
            raise PreflightRejectedError("channel is closing", code="payment_invalid")

    h.rpc.on_send = reject
    with pytest.raises(BatchServerError, match="1 of 2"):
        await h.server.claim([good, bad])
    assert (await h.store.get(good)).settled_on_chain == 1000
    assert (await h.store.get(bad)).settled_on_chain == 0


async def test_finalize_close_marks_the_channels_that_landed_before_reporting_failures() -> None:
    h = Harness()
    first, second = await _seed_claimable(h, status=2, started=1)
    sends: list[int] = []

    def fail_first(wire: bytes) -> None:
        sends.append(1)
        if len(sends) == 1:
            raise RuntimeError("node down")

    h.rpc.on_send = fail_first
    with pytest.raises(BatchServerError, match="1 of 2"):
        await h.server.finalize_close([first, second])
    assert len(h.rpc.sent) == 2
    assert not (await h.store.get(first)).sealed
    assert (await h.store.get(second)).sealed


async def test_settle_records_the_channels_that_landed_before_reporting_failures() -> None:
    h = Harness(versions=(0, 1))
    channels = [Pubkey.new_unique() for _ in range(2)]
    for channel in channels:
        h.rpc.put(channel, channel_account(settled=1000), PROGRAM_ID)
        await h.store.put(BatchChannelRecord(channel_id=str(channel), payer_authorizer=str(PAYER.pubkey())))
    sends: list[int] = []

    def fail_first(wire: bytes) -> None:
        sends.append(1)
        if len(sends) == 1:
            raise RuntimeError("node down")

    h.rpc.on_send = fail_first
    # Version 1 packs both distributes into one transaction; an unknown
    # outcome is not split, so both stay unrecorded.
    with pytest.raises(BatchServerError, match="1 of 1"):
        await h.server.settle([str(c) for c in channels])
    assert [(await h.store.get(str(c))).distributed_on_chain for c in channels] == [0, 0]
    # The retry lands both.
    assert len(await h.server.settle([str(c) for c in channels])) == 1
    assert [(await h.store.get(str(c))).distributed_on_chain for c in channels] == [1000, 1000]
