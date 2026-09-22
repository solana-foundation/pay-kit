"""x402 ``batch-settlement`` server-signed mode: operator vouchers over payer proofs.

Names follow the x402 PR #23 ``batch.server-signer.test.ts`` and ``batch.test.ts``
cases they mirror. Server-signed mode is Python-to-Python only: the Rust SDK has
no ``voucherSigner`` and takes the first (client-signed) accept.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any

import pytest
from solders.keypair import Keypair

from solana_pay_kit.errors import ConfigurationError
from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.engine import (
    BatchSettlementConfig,
    VerifiedBatchRequest,
    X402BatchSettlement,
)
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.signatures import sign_authorization, verify_voucher
from solana_pay_kit.protocols.x402.batch_settlement.store import MemoryBatchOperationStore
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchChannelConfig, BatchRequirements
from solana_pay_kit.signer import LocalSigner
from tests.batch_chain import PRICE, SLOT, World, make_world

NOW = 1_700_000_000.0
OPERATOR = LocalSigner.from_keypair(Keypair.from_seed(bytes([4] * 32)))


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    return make_world(monkeypatch)


def _engine(world: World, **settings: Any) -> X402BatchSettlement:
    settings.setdefault("operator", OPERATOR)
    return X402BatchSettlement(
        world.config,
        settings=BatchSettlementConfig(**settings),
        rpc=world.chain,  # type: ignore[arg-type]
        recent_state_provider=lambda: ("hint", SLOT),
        clock=lambda: NOW,
    )


def _server_config(world: World) -> BatchChannelConfig:
    return world.channel_config(payerAuthorizer=OPERATOR.pubkey(), voucherSigner="server")


def _server_accept(engine: X402BatchSettlement, world: World) -> BatchRequirements:
    return engine.accepts_entries(world.gate, {"path": "/batch"})[1]


def _proof(world: World, request_id: str, amount: int = PRICE, expires_in: int = 60) -> dict[str, Any]:
    return dict(
        sign_authorization(
            world.payer,
            channel_id=world.channel_id(_server_config(world)),
            operator=OPERATOR.pubkey(),
            request_id=request_id,
            authorized_amount=amount,
            expires_at=int(NOW) + expires_in,
        )
    )


def _deposit(world: World, deposit: int, request_id: str) -> dict[str, Any]:
    config = _server_config(world)
    return {
        "type": "deposit",
        "channelConfig": config,
        "deposit": {"amount": str(deposit), "transaction": world.open_tx(deposit, config)},
        "authorization": _proof(world, request_id),
    }


def _metered(world: World, request_id: str, **proof: Any) -> dict[str, Any]:
    return {
        "type": "authorization",
        "channelConfig": _server_config(world),
        "authorization": _proof(world, request_id, **proof),
    }


async def _verify(engine: X402BatchSettlement, world: World, payload: dict[str, Any]) -> VerifiedBatchRequest:
    verified = await engine.verify_and_reserve(world.gate, world.header(_server_accept(engine, world), payload))
    assert isinstance(verified, VerifiedBatchRequest)
    return verified


async def _code(coro: Any) -> str:
    with pytest.raises(BatchSettlementError) as exc:
        await coro
    return exc.value.code


async def _opened(engine: X402BatchSettlement, world: World, deposit: int = 3 * PRICE, actual: int = 4_000) -> Any:
    world.lands_as_channel(_server_config(world), deposit=deposit)
    return await engine.commit(await _verify(engine, world, _deposit(world, deposit, "open")), actual)


# -- challenge -------------------------------------------------------------------------------


def test_the_client_signed_accept_is_listed_first_and_routes_can_pin_a_mode(world: World) -> None:
    engine = _engine(world)
    client, server = engine.accepts_entries(world.gate, {"path": "/batch"})
    assert "voucherSigner" not in client["extra"] and "operator" not in client["extra"]
    assert (server["extra"].get("voucherSigner"), server["extra"].get("operator")) == ("server", OPERATOR.pubkey())
    assert [
        a["extra"].get("voucherSigner") for a in engine.accepts_entries(world.gate, {}, voucher_signer="client")
    ] == [None]
    assert [
        a["extra"].get("voucherSigner") for a in engine.accepts_entries(world.gate, {}, voucher_signer="server")
    ] == ["server"]
    no_operator = X402BatchSettlement(world.config, rpc=world.chain)  # type: ignore[arg-type]
    assert len(no_operator.accepts_entries(world.gate, {})) == 1
    with pytest.raises(ConfigurationError):
        no_operator.accepts_entries(world.gate, {}, voucher_signer="server")


def test_min_deposit_hint_is_ten_prices_client_side_and_three_server_side(world: World) -> None:
    client, server = _engine(world).accepts_entries(world.gate, {})
    assert (client["extra"].get("minDeposit"), server["extra"].get("minDeposit")) == (str(10 * PRICE), str(3 * PRICE))
    for override, expected in (("50000", "50000"), ("$0.05", "50000"), ("$0.0500009", "50000"), ("1", str(PRICE))):
        accepts = _engine(world, min_deposit=override).accepts_entries(world.gate, {})
        assert {a["extra"].get("minDeposit") for a in accepts} == {expected}, override
    for bad in ("0", "$0.0000001", "abc", "$", "1.5"):
        with pytest.raises(ConfigurationError):
            BatchSettlementConfig(min_deposit=bad)


def test_the_operator_must_not_be_the_fee_payer(world: World) -> None:
    with pytest.raises(ConfigurationError):
        _engine(world, operator=world.fee_payer)


async def test_an_enforced_min_deposit_refuses_a_smaller_deposit(world: World) -> None:
    engine = _engine(world, enforce_min_deposit=True)
    assert (
        await _code(_verify(engine, world, _deposit(world, 2 * PRICE, "r"))) == errors.INVALID_DEPOSIT_BELOW_MIN_DEPOSIT
    )
    await _verify(engine, world, _deposit(world, 3 * PRICE, "r2"))


# -- metered requests ---------------------------------------------------------------------


async def test_server_signed_lifecycle_meters_and_signs_the_operator_voucher(world: World) -> None:
    engine = _engine(world)
    opened = await _opened(engine, world, actual=4_000)
    channel_id = world.channel_id(_server_config(world))
    voucher = opened["extra"]["voucher"]
    assert voucher["maxClaimableAmount"] == "4000" and voucher["expiresAt"] == 0
    assert verify_voucher(voucher, OPERATOR.pubkey())
    assert opened["extra"]["commitmentId"] == f"{channel_id}:4000"
    assert "chargedAmount" not in opened["extra"]
    assert opened["extra"]["channelState"]["chargedCumulativeAmount"] == "4000"

    second = await engine.commit(await _verify(engine, world, _metered(world, "r2")), 2_500)
    assert second["transaction"] == "" and second.get("extra", {}).get("commitmentId") == f"{channel_id}:6500"


async def test_an_explicit_zero_charge_serves_at_the_unchanged_cumulative(world: World) -> None:
    engine = _engine(world)
    await _opened(engine, world, actual=4_000)
    response: Any = await engine.commit(await _verify(engine, world, _metered(world, "zero")), 0)
    assert response["success"] and response["extra"]["voucher"]["maxClaimableAmount"] == "4000"


async def test_a_missing_charge_fails_closed_and_consumes_the_request_id(world: World) -> None:
    engine = _engine(world)
    await _opened(engine, world)
    verified = await _verify(engine, world, _metered(world, "missing"))
    assert await _code(engine.commit(verified, None)) == "settlement_failed"
    record = await engine._store.get(verified.channel_id)  # noqa: SLF001
    assert record is not None and record.reservations == {} and record.charged_cumulative == 4_000
    assert await _code(_verify(engine, world, _metered(world, "missing"))) == errors.DUPLICATE_SETTLEMENT


async def test_a_metered_charge_is_bounded_by_its_ceiling(world: World) -> None:
    engine = _engine(world)
    await _opened(engine, world)
    for actual in (PRICE + 1, -1):
        verified = await _verify(engine, world, _metered(world, f"over-{actual}"))
        assert await _code(engine.commit(verified, actual)) == errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH


async def test_every_payer_proof_mismatch_is_refused(world: World) -> None:
    engine = _engine(world)
    await _opened(engine, world)
    for proof in ({"amount": PRICE - 1}, {"expires_in": 0}):
        assert await _code(_verify(engine, world, _metered(world, "bad", **proof))) == errors.INVALID_VOUCHER_SIGNATURE
    forged = _metered(world, "forged")
    forged["authorization"]["signature"] = _proof(world, "other")["signature"]
    assert await _code(_verify(engine, world, forged)) == errors.INVALID_VOUCHER_SIGNATURE


async def test_concurrent_server_ceilings_complete_out_of_order_and_ids_are_single_use(world: World) -> None:
    engine = _engine(world)
    await _opened(engine, world, deposit=3 * PRICE, actual=PRICE)
    first, second = await asyncio.gather(
        _verify(engine, world, _metered(world, "a")), _verify(engine, world, _metered(world, "b"))
    )
    # Charged 1 price + two live ceilings fill the 3-price escrow.
    assert await _code(_verify(engine, world, _metered(world, "c"))) == errors.INVALID_CUMULATIVE_EXCEEDS_DEPOSIT
    refused = await engine._operations.get(first.channel_id, "c")  # noqa: SLF001
    assert refused is not None and refused.status == "released"  # consumed, not left dangling
    await engine.commit(second, 3_000)
    done: Any = await engine.commit(first, 5_000)
    assert done["extra"]["channelState"]["chargedCumulativeAmount"] == str(PRICE + 8_000)
    assert await _code(_verify(engine, world, _metered(world, "a"))) == errors.DUPLICATE_SETTLEMENT


async def test_a_released_request_id_stays_consumed(world: World) -> None:
    operations = MemoryBatchOperationStore()
    engine = X402BatchSettlement(
        world.config,
        settings=BatchSettlementConfig(operator=OPERATOR),
        operation_store=operations,
        rpc=world.chain,  # type: ignore[arg-type]
        clock=lambda: NOW,
    )
    await _opened(engine, world)
    verified = await _verify(engine, world, _metered(world, "failed"))
    await engine.release(verified)
    operation = await operations.get(verified.channel_id, "failed")
    assert operation is not None and operation.status == "released"
    assert await _code(_verify(engine, world, _metered(world, "failed"))) == errors.DUPLICATE_SETTLEMENT


async def test_a_refund_waits_for_server_signed_requests_in_flight(world: World) -> None:
    engine = _engine(world)
    await _opened(engine, world)
    await _verify(engine, world, _metered(world, "in-flight"))
    config = _server_config(world)
    refund = {"type": "refund", "channelConfig": config, "transaction": world.request_close_tx(config)}
    request = world.header(_server_accept(engine, world), refund)
    assert await _code(engine.verify_and_reserve(world.gate, request)) == errors.DUPLICATE_SETTLEMENT


async def test_a_route_pinned_to_client_signing_refuses_the_server_accept(world: World) -> None:
    engine = _engine(world)
    request = world.header(_server_accept(engine, world), _deposit(world, 3 * PRICE, "r"))
    code = await _code(engine.verify_and_reserve(world.gate, request, voucher_signer="client"))
    assert code == errors.INVALID_CHANNEL_STATE


async def test_a_commit_never_signs_past_the_deposit(world: World) -> None:
    # Another writer moved the charge after this request reserved its ceiling
    # (a chain refresh folding in a higher settled watermark): the operator
    # must not sign a voucher the escrow cannot pay.
    engine = _engine(world)
    await _opened(engine, world, deposit=3 * PRICE, actual=PRICE)
    verified = await _verify(engine, world, _metered(world, "late"))
    await engine._store.update(  # noqa: SLF001
        verified.channel_id,
        lambda current: None if current is None else replace(current, charged_cumulative=3 * PRICE - 1),  # type: ignore[arg-type,return-value]
    )
    assert await _code(engine.commit(verified, PRICE)) == errors.INVALID_CUMULATIVE_EXCEEDS_DEPOSIT


class _BrokenOperations(MemoryBatchOperationStore):
    async def complete(self, channel_id: str, request_id: str, **_: Any) -> Any:
        raise RuntimeError("operation store down")


async def test_a_failed_operation_record_does_not_withhold_a_recorded_charge(world: World) -> None:
    alerts: list[str] = []
    engine = X402BatchSettlement(
        world.config,
        settings=BatchSettlementConfig(operator=OPERATOR),
        operation_store=_BrokenOperations(),
        rpc=world.chain,  # type: ignore[arg-type]
        clock=lambda: NOW,
        on_alert=lambda event, _details: alerts.append(event),
    )
    response: Any = await _opened(engine, world, actual=4_000)
    assert response["success"] and alerts == ["operation_complete"]


async def test_a_metered_request_past_its_lease_cannot_ride_a_tiny_top_up(world: World) -> None:
    # A long metered request carries a tiny top-up; after its lease a cheap
    # request takes the channel. The long one must not be served for free.
    clock = [NOW]
    engine = X402BatchSettlement(
        world.config,
        settings=BatchSettlementConfig(operator=OPERATOR),
        rpc=world.chain,  # type: ignore[arg-type]
        recent_state_provider=lambda: ("hint", SLOT),
        clock=lambda: clock[0],
    )
    await _opened(engine, world, deposit=3 * PRICE, actual=PRICE)
    config = _server_config(world)
    top_up = {
        "type": "deposit",
        "channelConfig": config,
        "deposit": {"amount": "1", "transaction": world.top_up_tx(1, config)},
        "authorization": _proof(world, "long", expires_in=1_000),
    }
    long = await _verify(engine, world, top_up)
    clock[0] += 301
    cheap = await _verify(engine, world, _metered(world, "cheap", expires_in=1_000))
    await engine.commit(cheap, 100)
    sent = len(world.chain.sent)
    assert await _code(engine.commit(long, PRICE)) == errors.DUPLICATE_SETTLEMENT
    assert len(world.chain.sent) == sent  # the top-up was never broadcast
    record = await engine._store.get(world.channel_id(config))  # noqa: SLF001
    assert record is not None and record.charged_cumulative == PRICE + 100
    # Its request id stays consumed.
    assert await _code(engine.verify_and_reserve(world.gate, world.header(_server_accept(engine, world), top_up))) == (
        errors.DUPLICATE_SETTLEMENT
    )
