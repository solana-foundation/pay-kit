"""x402 ``batch-settlement`` server engine, client-signed vouchers, over a fake chain.

Names follow the Rust ``x402/server/batch_settlement.rs`` tests and the x402
PR #23 ``batch.test.ts`` / lifecycle tests they mirror.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from typing import Any, cast

import pytest
from solders.message import to_bytes_versioned
from solders.pubkey import Pubkey

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.paymentchannels import build_request_close_instruction
from solana_pay_kit.errors import ConfigurationError
from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.engine import (
    BatchSettlementConfig,
    CorrectiveRequired,
    VerifiedBatchRequest,
    X402BatchSettlement,
)
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.onchain import decode_token_account
from solana_pay_kit.protocols.x402.batch_settlement.signatures import verify_voucher
from solana_pay_kit.protocols.x402.batch_settlement.store import ChannelRecord, MemoryBatchChannelStore
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchRequirements
from tests.batch_chain import CLOSING, MINT, PRICE, SLOT, World, make_world, token_account

NOW = 1_700_000_000.0


def _engine(world: World, **kwargs: Any) -> X402BatchSettlement:
    kwargs.setdefault("clock", lambda: NOW)
    return X402BatchSettlement(
        world.config,
        rpc=world.chain,  # type: ignore[arg-type]
        recent_state_provider=lambda: ("hint-blockhash", SLOT),
        **kwargs,
    )


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    return make_world(monkeypatch)


def _requirement(engine: X402BatchSettlement, world: World) -> BatchRequirements:
    return engine.accepts_entries(world.gate, {"path": "/batch"})[0]


async def _verify(engine: X402BatchSettlement, gate: Any, request: Any) -> VerifiedBatchRequest:
    verified = await engine.verify_and_reserve(gate, request)
    assert isinstance(verified, VerifiedBatchRequest)
    return verified


async def _code(coro: Any) -> str:
    with pytest.raises(BatchSettlementError) as exc:
        await coro
    return exc.value.code


async def _open(engine: X402BatchSettlement, world: World, deposit: int = 3 * PRICE) -> Any:
    """Open a channel with a first paid request and commit it."""
    world.lands_as_channel(deposit=deposit)
    request = world.header(_requirement(engine, world), world.deposit_payload(deposit, PRICE))
    verified = await _verify(engine, world.gate, request)
    return await engine.commit(verified)


async def _pay(engine: X402BatchSettlement, world: World, cumulative: int) -> Any:
    request = world.header(_requirement(engine, world), world.voucher_payload(cumulative))
    return await engine.commit(await _verify(engine, world.gate, request))


# -- challenge ---------------------------------------------------------------------


def test_requirements_advertise_the_scheme_wire_contract(world: World) -> None:
    engine = _engine(world)
    accepts = engine.accepts_entries(world.gate, {"path": "/batch"})
    assert len(accepts) == 1
    accept: Any = accepts[0]
    assert (accept["scheme"], accept["amount"], accept["asset"], accept["payTo"]) == (
        "batch-settlement",
        str(PRICE),
        MINT,
        world.pay_to,
    )
    assert accept["extra"]["feePayer"] == world.fee_payer.pubkey()
    assert accept["extra"]["withdrawDelay"] == 900
    assert accept["extra"]["recentSlot"] == SLOT
    # Client-signed mode: no server-signed fields, no program id on the wire.
    assert not {"voucherSigner", "operator", "channelProgram", "paymentFlow"} & set(accept["extra"])
    header = engine.challenge_headers(world.gate, {"path": "/batch"}, error=errors.INVALID_VOUCHER_EXPIRY)
    envelope = json.loads(base64.b64decode(header["payment-required"]))
    assert envelope["x402Version"] == 2 and envelope["error"] == errors.INVALID_VOUCHER_EXPIRY


def test_withdraw_delay_outside_the_conformance_range_is_refused() -> None:
    cases: list[dict[str, Any]] = [
        {"withdraw_delay": 899},
        {"withdraw_delay": 2_592_001},
        {"withdraw_delay": 900, "max_timeout_seconds": 901},
    ]
    for kwargs in cases:
        with pytest.raises(ConfigurationError):
            BatchSettlementConfig(**kwargs)
    assert BatchSettlementConfig(max_timeout_seconds=1200).effective_withdraw_delay() == 1200


def test_payment_headers_must_name_this_scheme(world: World) -> None:
    engine = _engine(world)
    request = world.header(_requirement(engine, world), world.voucher_payload(PRICE))
    assert engine.detect_batch(request)
    assert not engine.detect_batch({"headers": {}})
    other = world.header({**_requirement(engine, world), "scheme": "upto"}, world.voucher_payload(PRICE))  # type: ignore[typeddict-item]
    assert not engine.detect_batch(other)


def test_settlement_headers_round_trip_the_payment_response(world: World) -> None:
    response: Any = {"success": True, "transaction": "", "network": "n", "amount": ""}
    headers = _engine(world).settlement_headers(response)
    assert json.loads(base64.b64decode(headers["payment-response"])) == response
    assert headers["x-payment-settlement-signature"] == ""


# -- deposit -----------------------------------------------------------------------------


async def test_deposit_broadcasts_only_after_the_handler_and_answers_what_the_rust_client_checks(
    world: World,
) -> None:
    engine = _engine(world)
    world.lands_as_channel(deposit=3 * PRICE)
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    verified = await _verify(engine, world.gate, request)
    # Validated and simulated, but nothing escrowed before the handler ran.
    assert world.chain.sent == [] and len(world.chain.simulated) == 1

    response: Any = await engine.commit(verified)
    (sent,) = world.chain.sent
    assert sent.signatures[0].verify(
        Pubkey.from_string(world.fee_payer.pubkey()), bytes(to_bytes_versioned(sent.message))
    )
    channel_id = world.channel_id()
    assert response["success"] and response["transaction"] == str(sent.signatures[0])
    assert response["amount"] == str(3 * PRICE)
    extra = response["extra"]
    # rust/crates/kit/src/x402/client/batch_settlement/payment.rs apply_payment_response
    assert extra["commitmentId"] == f"{channel_id}:{PRICE}"
    assert extra["chargedAmount"] == str(PRICE)
    assert extra["channelState"]["chargedCumulativeAmount"] == str(PRICE)
    assert extra["channelState"]["balance"] == str(3 * PRICE)


async def test_fixed_pricing_binds_the_next_voucher_and_the_deposit_ceiling(world: World) -> None:
    engine = _engine(world)
    await _open(engine, world, deposit=2 * PRICE)
    response = await _pay(engine, world, 2 * PRICE)
    # A plain voucher moves no value: both fields are the empty string.
    assert (response["transaction"], response["amount"]) == ("", "")
    assert response["extra"]["commitmentId"] == f"{world.channel_id()}:{2 * PRICE}"
    requirement = _requirement(engine, world)
    # Skipping ahead is a mismatch, and the next price no longer fits the escrow.
    with pytest.raises(CorrectiveRequired):
        await _verify(engine, world.gate, world.header(requirement, world.voucher_payload(4 * PRICE)))
    code = await _code(
        engine.verify_and_reserve(world.gate, world.header(requirement, world.voucher_payload(3 * PRICE)))
    )
    assert code == errors.INVALID_CUMULATIVE_EXCEEDS_DEPOSIT


async def test_an_exact_replay_is_refused_as_duplicate_settlement(world: World) -> None:
    engine = _engine(world)
    await _open(engine, world)
    request = world.header(_requirement(engine, world), world.voucher_payload(2 * PRICE))
    await engine.commit(await _verify(engine, world.gate, request))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.DUPLICATE_SETTLEMENT


async def test_a_corrective_challenge_proves_what_it_claims_to_have_charged(world: World) -> None:
    engine = _engine(world)
    await _open(engine, world)
    request = world.header(_requirement(engine, world), world.voucher_payload(3 * PRICE))
    with pytest.raises(CorrectiveRequired) as exc:
        await _verify(engine, world.gate, request)
    extra: Any = exc.value.accepts[0]["extra"]
    assert extra["channelState"]["chargedCumulativeAmount"] == str(PRICE)
    proof = extra["voucherState"]
    assert proof["signedMaxClaimable"] == str(PRICE)
    voucher: Any = {
        "channelId": world.channel_id(),
        "maxClaimableAmount": proof["signedMaxClaimable"],
        "expiresAt": 0,
        "signature": proof["signature"],
    }
    assert verify_voucher(voucher, world.payer.pubkey())


async def test_a_rebuilt_channel_starts_at_its_settled_watermark_without_a_proof(world: World) -> None:
    engine = _engine(world)
    world.put_channel(deposit=10 * PRICE, settled=3 * PRICE)
    requirement = _requirement(engine, world)
    with pytest.raises(CorrectiveRequired) as exc:
        await _verify(engine, world.gate, world.header(requirement, world.voucher_payload(PRICE)))
    extra: Any = exc.value.accepts[0]["extra"]
    assert extra["channelState"]["chargedCumulativeAmount"] == str(3 * PRICE)
    assert "voucherState" not in extra  # nothing to prove: the voucher vanished with the store
    response = await _pay(engine, world, 4 * PRICE)
    assert response["extra"]["channelState"]["chargedCumulativeAmount"] == str(4 * PRICE)


async def test_a_voucher_for_an_unknown_channel_is_refused(world: World) -> None:
    engine = _engine(world)
    request = world.header(_requirement(engine, world), world.voucher_payload(PRICE))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_CHANNEL_STATE


async def test_a_closing_channel_refuses_vouchers_with_channel_closing(world: World) -> None:
    engine = _engine(world)
    world.put_channel(deposit=10 * PRICE, status=CLOSING, closure_started_at=int(NOW))
    request = world.header(_requirement(engine, world), world.voucher_payload(PRICE))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_CHANNEL_CLOSING


async def test_a_fresh_snapshot_verifies_locally_and_a_stale_one_rereads(world: World) -> None:
    clock = [NOW]
    engine = _engine(world, clock=lambda: clock[0])
    await _open(engine, world, deposit=5 * PRICE)
    reads = world.chain.account_reads
    await _pay(engine, world, 2 * PRICE)
    assert world.chain.account_reads == reads
    clock[0] += 31
    world.put_channel(deposit=5 * PRICE, status=CLOSING, closure_started_at=int(NOW))
    request = world.header(_requirement(engine, world), world.voucher_payload(3 * PRICE))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_CHANNEL_CLOSING


async def test_a_failed_handler_releases_its_reservation_for_retry(world: World) -> None:
    engine = _engine(world)
    await _open(engine, world)
    request = world.header(_requirement(engine, world), world.voucher_payload(2 * PRICE))
    verified = await _verify(engine, world.gate, request)
    await engine.release(verified)
    await engine.commit(await _verify(engine, world.gate, request))


async def test_a_channel_admits_one_client_request_at_a_time(world: World) -> None:
    engine = _engine(world)
    await _open(engine, world)
    request = world.header(_requirement(engine, world), world.voucher_payload(2 * PRICE))
    await _verify(engine, world.gate, request)
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.DUPLICATE_SETTLEMENT


async def test_a_payload_built_for_other_requirements_is_refused(world: World) -> None:
    engine = _engine(world)
    foreign = {**_requirement(engine, world), "amount": str(PRICE - 1)}
    request = world.header(cast("BatchRequirements", foreign), world.deposit_payload(3 * PRICE, PRICE))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_CHANNEL_STATE


async def test_top_up_escrow_is_recorded_and_a_retry_is_not_counted_twice(world: World) -> None:
    engine = _engine(world)
    await _open(engine, world, deposit=PRICE)
    requirement = _requirement(engine, world)
    top_up = world.deposit_payload(PRICE, 2 * PRICE, transaction=world.top_up_tx(PRICE))
    world.lands_as_channel(deposit=2 * PRICE)
    verified = await _verify(engine, world.gate, world.header(requirement, top_up))
    assert verified.setup is not None and verified.setup.form == "top_up"
    response: Any = await engine.commit(verified)
    assert response["extra"]["channelState"]["balance"] == str(2 * PRICE)
    # The same top-up bytes again: already landed, so not re-sent, and its
    # escrow is not added a second time (the voucher above the deposit fails).
    retry = world.deposit_payload(PRICE, 3 * PRICE, transaction=world.top_up_tx(PRICE))
    retry["deposit"] = top_up["deposit"]
    assert await _code(engine.verify_and_reserve(world.gate, world.header(requirement, retry))) == (
        errors.INVALID_CUMULATIVE_EXCEEDS_DEPOSIT
    )
    assert len(world.chain.sent) == 2


async def test_a_fresh_open_is_bound_to_the_current_slot(world: World) -> None:
    engine = _engine(world)
    world.chain.slot = SLOT + 1_501
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_SETUP_TRANSACTION


async def test_an_open_at_the_hinted_slot_passes_while_get_slot_trails_it(world: World) -> None:
    # The challenge's recentSlot is the getLatestBlockhash context slot; getSlot
    # can lag it by one (seen on surfpool), which must not refuse the hint.
    world.chain.blockhash_slot, world.chain.slot = SLOT, SLOT - 1
    engine = _engine(world)
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    assert (await _verify(engine, world.gate, request)).setup is not None
    world.chain.blockhash_slot = SLOT - 1  # now the hint really is ahead of the chain
    fresh = _engine(world)  # the first engine holds a reservation on this channel
    retry = world.header(_requirement(fresh, world), world.deposit_payload(3 * PRICE, PRICE))
    assert await _code(fresh.verify_and_reserve(world.gate, retry)) == errors.INVALID_SETUP_TRANSACTION


async def test_the_mint_must_be_owned_by_the_declared_token_program(world: World) -> None:
    engine = _engine(world)
    world.chain.accounts[MINT] = (b"\x00" * 82, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_TOKEN_PROGRAM


async def test_an_unusable_settlement_account_refuses_the_escrow(world: World) -> None:
    engine = _engine(world)
    for key, (data, owner) in list(world.chain.accounts.items()):
        if owner == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" and data[32:64] == bytes(
            Pubkey.from_string(world.pay_to)
        ):
            world.chain.accounts[key] = (token_account(MINT, world.pay_to, state=2), owner)  # frozen
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_SETTLEMENT_SIMULATION


def test_settlement_account_decoding_rejects_unusable_token_accounts() -> None:
    owner = str(Pubkey.new_unique())
    assert decode_token_account(b"\x00" * 164) is None
    assert decode_token_account(token_account(MINT, owner)).unsupported_extension is None  # type: ignore[union-attr]
    immutable_owner = bytes([2]) + (7).to_bytes(2, "little") + (0).to_bytes(2, "little")
    assert decode_token_account(token_account(MINT, owner, extra=immutable_owner)).unsupported_extension is None  # type: ignore[union-attr]
    transfer_fee = bytes([2]) + (1).to_bytes(2, "little") + (108).to_bytes(2, "little") + bytes(108)
    assert decode_token_account(token_account(MINT, owner, extra=transfer_fee)).unsupported_extension == 1  # type: ignore[union-attr]
    truncated = bytes([2]) + (7).to_bytes(2, "little") + (9).to_bytes(2, "little")
    assert decode_token_account(token_account(MINT, owner, extra=truncated)).unsupported_extension == 0xFFFF  # type: ignore[union-attr]
    assert decode_token_account(token_account(MINT, owner, extra=bytes([1]))).unsupported_extension == 1  # type: ignore[union-attr]


async def test_a_failed_simulation_refuses_the_deposit_before_the_handler(world: World) -> None:
    engine = _engine(world)
    world.chain.simulation_error = {"InstructionError": [0, "Custom"]}
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_SETTLEMENT_SIMULATION


async def test_a_confirmed_deposit_below_the_reservation_is_refused_and_released(world: World) -> None:
    engine = _engine(world)
    world.lands_as_channel(deposit=PRICE - 1)
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    verified = await _verify(engine, world.gate, request)
    assert await _code(engine.commit(verified)) == errors.INVALID_CHANNEL_STATE
    record = await engine._store.get(world.channel_id())  # noqa: SLF001
    assert record is not None and record.reservations == {} and record.charged_cumulative == 0


async def test_an_ambiguous_deposit_is_released_and_never_rebuilt(world: World) -> None:
    engine = _engine(world)
    world.chain.confirm_error = PaymentError("timed out", code="transaction-not-found")
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    verified = await _verify(engine, world.gate, request)
    assert await _code(engine.commit(verified)) == errors.INVALID_SETTLEMENT_SIMULATION
    # It did land after all: the retry of the same bytes is not re-sent.
    world.chain.confirm_error = None
    world.put_channel(deposit=3 * PRICE)
    response = await engine.commit(await _verify(engine, world.gate, request))
    assert len(world.chain.sent) == 1 and response["transaction"] == str(world.chain.sent[0].signatures[0])


async def test_the_open_is_reread_through_replica_lag(world: World) -> None:
    engine = _engine(world)
    world.lands_as_channel(deposit=3 * PRICE)
    world.chain.lagging_reads = 2
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    verified = await _verify(engine, world.gate, request)
    response = await engine.commit(verified)
    assert response["success"] and world.chain.lagging_reads == 0


class _FailingCommitStore(MemoryBatchChannelStore):
    """Fails the write that records a charge, after a setup broadcast."""

    async def update(self, channel_id: str, mutator: Any) -> ChannelRecord:
        record = await self.get(channel_id)
        if record is not None and record.reservations and record.charged_cumulative == 0 and self.armed:
            raise RuntimeError("disk full")
        return await super().update(channel_id, mutator)

    armed = False


async def test_a_store_failure_after_a_confirmed_deposit_still_answers_and_alerts(world: World) -> None:
    alerts: list[tuple[str, Any]] = []
    store = _FailingCommitStore()
    engine = _engine(world, channel_store=store, on_alert=lambda event, details: alerts.append((event, details)))
    world.lands_as_channel(deposit=3 * PRICE)
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    verified = await _verify(engine, world.gate, request)
    store.armed = True
    response: Any = await engine.commit(verified)
    assert response["success"] and response["extra"]["channelState"]["chargedCumulativeAmount"] == str(PRICE)
    assert [event for event, _ in alerts] == ["commit_after_deposit"]


async def test_a_store_failure_on_a_plain_voucher_is_not_served(world: World) -> None:
    store = _FailingCommitStore()
    engine = _engine(world, channel_store=store)
    await _open(engine, world)
    request = world.header(_requirement(engine, world), world.voucher_payload(2 * PRICE))
    verified = await _verify(engine, world.gate, request)

    async def broken(channel_id: str, mutator: Any) -> ChannelRecord:
        raise RuntimeError("disk full")

    store.update = broken  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await engine.commit(verified)


async def test_a_client_signed_commit_charges_exactly_its_price(world: World) -> None:
    engine = _engine(world)
    await _open(engine, world)
    request = world.header(_requirement(engine, world), world.voucher_payload(2 * PRICE))
    verified = await _verify(engine, world.gate, request)
    assert await _code(engine.commit(verified, PRICE - 1)) == errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH
    record = await engine._store.get(world.channel_id())  # noqa: SLF001
    assert record is not None and record.reservations == {}


async def test_a_stored_config_must_match_the_payload(world: World) -> None:
    # The server once advertised another withdrawDelay (not a PDA seed): the
    # channel it recorded then is not the one this payload describes.
    engine = _engine(world)
    stored = {**world.channel_config(), "withdrawDelay": 1800}
    record = ChannelRecord(
        world.channel_id(),
        cast(Any, stored),
        "n",
        world.fee_payer.pubkey(),
        "t",
        deposit=10 * PRICE,
        onchain_synced_at=NOW,
    )
    await engine._store.update(world.channel_id(), lambda _: record)  # noqa: SLF001
    request = world.header(_requirement(engine, world), world.voucher_payload(PRICE))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_CHANNEL_STATE


async def test_a_commit_refuses_a_voucher_the_channel_moved_past(world: World) -> None:
    # Between verify and commit another writer advanced the charge (a chain
    # refresh folding in a higher settled watermark): the verified voucher no
    # longer advances the channel by exactly one price.
    engine = _engine(world)
    await _open(engine, world)
    request = world.header(_requirement(engine, world), world.voucher_payload(2 * PRICE))
    verified = await _verify(engine, world.gate, request)
    await engine._store.update(  # noqa: SLF001
        world.channel_id(),
        lambda current: None if current is None else replace(current, charged_cumulative=2 * PRICE),  # type: ignore[arg-type,return-value]
    )
    assert await _code(engine.commit(verified)) == errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH


async def test_a_setup_that_landed_and_failed_is_refused(world: World) -> None:
    engine = _engine(world)
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    verified = await _verify(engine, world.gate, request)
    assert verified.setup is not None
    await engine.release(verified)
    world.chain.statuses[verified.setup.signature] = {"err": {"InstructionError": [0, "Custom"]}}
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_SETTLEMENT_SIMULATION


async def test_a_refused_setup_broadcast_is_final_only_when_it_did_not_land(world: World) -> None:
    engine = _engine(world)
    request = world.header(_requirement(engine, world), world.deposit_payload(3 * PRICE, PRICE))
    world.chain.send_error = PaymentError("blockhash not found", code="payment_invalid")
    verified = await _verify(engine, world.gate, request)
    assert await _code(engine.commit(verified)) == errors.INVALID_SETTLEMENT_SIMULATION
    # Preflight refused a retry because the first submission already landed.
    verified = await _verify(engine, world.gate, request)
    assert verified.setup is not None
    world.put_channel(deposit=3 * PRICE)
    original = world.chain.get_signature_statuses
    calls = [0]

    async def landed_on_second_look(signatures: list[str]) -> list[Any]:
        calls[0] += 1
        if calls[0] > 1:
            return [{"confirmationStatus": "confirmed", "err": None}]
        return await original(signatures)

    world.chain.get_signature_statuses = landed_on_second_look  # type: ignore[method-assign]
    response: Any = await engine.commit(verified)
    assert response["transaction"] == verified.setup.signature


async def test_a_sealed_channel_refuses_vouchers_with_close_state(world: World) -> None:
    engine = _engine(world)
    world.put_channel(deposit=10 * PRICE, status=3)
    request = world.header(_requirement(engine, world), world.voucher_payload(PRICE))
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_CLOSE_STATE


async def test_a_malformed_or_missing_header_is_a_payload_type_error(world: World) -> None:
    engine = _engine(world)
    for request in (
        {"headers": {}},
        {"headers": {"payment-signature": "not base64!"}},
        {"headers": {"x-payment": "WzFd"}},
    ):
        assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.INVALID_PAYLOAD_TYPE


def test_the_receiver_authorizer_is_advertised_only_when_configured(world: World) -> None:
    key = world.fee_payer.pubkey()
    engine = _engine(world, settings=BatchSettlementConfig(receiver_authorizer=key))
    assert _requirement(engine, world)["extra"].get("receiverAuthorizer") == key
    assert "receiverAuthorizer" not in _requirement(_engine(world), world)["extra"]


def test_delegated_x402_is_not_supported(world: World) -> None:
    config = world.config.model_copy(
        update={"x402": world.config.x402.model_copy(update={"facilitator_url": "https://f"})}
    )
    with pytest.raises(NotImplementedError):
        X402BatchSettlement(config)


# -- refund ------------------------------------------------------------------------------------


def _refund(world: World, **fields: Any) -> dict[str, Any]:
    return {
        "type": "refund",
        "channelConfig": world.channel_config(),
        "transaction": world.request_close_tx(),
        **fields,
    }


async def _refund_response(engine: X402BatchSettlement, world: World, payload: dict[str, Any]) -> Any:
    return await engine.verify_and_reserve(world.gate, world.header(_requirement(engine, world), payload))


async def test_a_refund_with_an_amount_is_close_amount_unsupported(world: World) -> None:
    engine = _engine(world)
    code = await _code(_refund_response(engine, world, _refund(world, amount="5")))
    assert code == errors.INVALID_CLOSE_AMOUNT_UNSUPPORTED


async def test_a_refund_carrying_a_cooperative_hint_is_refused(world: World) -> None:
    engine = _engine(world)
    voucher = world.voucher_payload(PRICE)["voucher"]
    for hint in ({"voucher": voucher}, {"closeAuthorization": {"validBefore": int(NOW) + 60, "signature": "s"}}):
        assert (
            await _code(_refund_response(engine, world, _refund(world, **hint))) == errors.INVALID_CLOSE_AUTHORIZATION
        )


async def test_a_malformed_refund_transaction_is_refused(world: World) -> None:
    engine = _engine(world)
    world.put_channel(deposit=3 * PRICE)
    payload = _refund(world, transaction=world.top_up_tx(PRICE))
    assert await _code(_refund_response(engine, world, payload)) == errors.INVALID_REFUND_TRANSACTION


async def test_a_refund_claims_the_charged_voucher_before_request_close(world: World) -> None:
    engine = _engine(world)
    await _open(engine, world)
    await _pay(engine, world, 2 * PRICE)
    world.lands_as_channel(deposit=3 * PRICE, settled=2 * PRICE)  # the claim
    world.lands_as_channel(deposit=3 * PRICE, settled=2 * PRICE, status=CLOSING, closure_started_at=int(NOW))
    response = await _refund_response(engine, world, _refund(world))
    claim, close = world.chain.sent[1:]
    # [ed25519, settle] for exactly the charged voucher, then the payer's close.
    assert bytes(claim.message.instructions[0].data)[112:] == bytes.fromhex(
        "5601"
        + bytes(Pubkey.from_string(world.channel_id())).hex()
        + (2 * PRICE).to_bytes(8, "little").hex()
        + "00" * 8
    )
    assert response["transaction"] == str(close.signatures[0]) and response["amount"] == ""
    assert response["extra"]["channelState"]["totalClaimed"] == str(2 * PRICE)
    record = await engine._store.get(world.channel_id())  # noqa: SLF001
    assert record is not None and record.status == "closing" and record.reservations == {}


async def test_a_refund_with_nothing_to_claim_only_closes_and_needs_no_memo(world: World) -> None:
    engine = _engine(world)
    world.put_channel(deposit=3 * PRICE)
    world.lands_as_channel(deposit=3 * PRICE, status=CLOSING, closure_started_at=int(NOW))
    ix = build_request_close_instruction(
        payer=Pubkey.from_string(world.payer.pubkey()), channel=Pubkey.from_string(world.channel_id())
    )
    response = await _refund_response(engine, world, _refund(world, transaction=world.signed([ix])))
    assert len(world.chain.sent) == 1 and response["transaction"] == str(world.chain.sent[0].signatures[0])


async def test_a_refund_of_a_closing_channel_returns_the_observed_state_without_rebroadcast(world: World) -> None:
    engine = _engine(world)
    world.put_channel(deposit=3 * PRICE, status=CLOSING, closure_started_at=int(NOW) - 5)
    response = await _refund_response(engine, world, _refund(world))
    assert response["transaction"] == "" and world.chain.sent == []
    assert response["extra"]["channelState"]["withdrawRequestedAt"] == int(NOW) - 5


async def test_a_refund_needs_an_open_or_closing_channel(world: World) -> None:
    engine = _engine(world)
    assert await _code(_refund_response(engine, world, _refund(world))) == errors.INVALID_CHANNEL_STATE
    world.put_channel(deposit=3 * PRICE, status=3)
    assert await _code(_refund_response(engine, world, _refund(world))) == errors.INVALID_CLOSE_STATE


async def test_a_refund_waits_for_requests_in_flight(world: World) -> None:
    engine = _engine(world)
    await _open(engine, world)
    await _verify(engine, world.gate, world.header(_requirement(engine, world), world.voucher_payload(2 * PRICE)))
    assert await _code(_refund_response(engine, world, _refund(world))) == errors.DUPLICATE_SETTLEMENT


async def test_a_request_close_that_does_not_close_is_refused_and_released(world: World) -> None:
    engine = _engine(world)
    world.put_channel(deposit=3 * PRICE)
    assert await _code(_refund_response(engine, world, _refund(world))) == errors.INVALID_CLOSE_STATE
    record = await engine._store.get(world.channel_id())  # noqa: SLF001
    assert record is not None and record.reservations == {}


async def test_a_failed_claim_stops_the_refund_before_the_close(world: World) -> None:
    engine = _engine(world)
    await _open(engine, world)
    world.chain.send_error = PaymentError("node down", code="payment_invalid")
    with pytest.raises(BatchSettlementError):
        await _refund_response(engine, world, _refund(world))
    assert len(world.chain.sent) == 1  # only the open


async def test_an_unconfirmed_refund_close_is_retryable_and_drops_its_hold(world: World) -> None:
    engine = _engine(world)
    world.put_channel(deposit=3 * PRICE)
    world.chain.confirm_error = PaymentError("timed out", code="transaction-not-found")
    ix = build_request_close_instruction(
        payer=Pubkey.from_string(world.payer.pubkey()), channel=Pubkey.from_string(world.channel_id())
    )
    with pytest.raises(BatchSettlementError, match="retry the same request_close") as exc:
        await _refund_response(engine, world, _refund(world, transaction=world.signed([ix])))
    assert exc.value.code == errors.INVALID_SETTLEMENT_SIMULATION
    record = await engine._store.get(world.channel_id())  # noqa: SLF001
    assert record is not None and record.reservations == {}


async def test_a_refund_never_claims_above_what_was_charged(world: World) -> None:
    alerts: list[str] = []
    engine = _engine(world, on_alert=lambda event, _details: alerts.append(event))
    await _open(engine, world)
    await engine._store.update(  # noqa: SLF001
        world.channel_id(),
        lambda current: None if current is None else replace(current, signed_max_claimable=2 * PRICE),  # type: ignore[arg-type,return-value]
    )
    world.lands_as_channel(deposit=3 * PRICE, status=CLOSING, closure_started_at=int(NOW))
    response = await _refund_response(engine, world, _refund(world))
    assert alerts == ["claim_above_charged"] and response["success"]
    assert len(world.chain.sent) == 2  # the open, then the close: no claim


async def test_a_store_failure_after_request_close_still_answers_and_alerts(world: World) -> None:
    alerts: list[str] = []
    store = MemoryBatchChannelStore()
    engine = _engine(world, channel_store=store, on_alert=lambda event, _details: alerts.append(event))
    world.put_channel(deposit=3 * PRICE)
    world.lands_as_channel(deposit=3 * PRICE, status=CLOSING, closure_started_at=int(NOW))
    original = store.update
    calls = [0]

    async def fail_after_hold(channel_id: str, mutator: Any) -> ChannelRecord:
        calls[0] += 1
        if calls[0] > 1:
            raise RuntimeError("disk full")
        return await original(channel_id, mutator)

    store.update = fail_after_hold  # type: ignore[method-assign]
    response = await _refund_response(engine, world, _refund(world))
    assert response["success"] and response["transaction"] and alerts == ["refund"]
