"""x402 ``batch-settlement`` resource server: verify, reserve, commit, refund
and redemption, against an in-memory RPC double; plus the channel store."""

from __future__ import annotations

import base64
import dataclasses
import json
from typing import Any

import pytest
from solders.pubkey import Pubkey

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.paymentchannels import find_associated_token_address
from solana_pay_kit._paycore.solana import TOKEN_2022_PROGRAM
from solana_pay_kit.protocols.x402.batch_settlement import errors as codes
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.server import (
    BatchAccessKind,
    BatchServerError,
    InvalidPaymentRequiredError,
    UnsupportedSchemeError,
    X402BatchSettlement,
    caip2_network_for_cluster,
    unusable_settlement_account,
)
from solana_pay_kit.protocols.x402.batch_settlement.store import (
    AuthorizationRequest,
    BatchChannelRecord,
    BatchStoreError,
    ChannelBinding,
    MemoryBatchChannelStore,
    Reservation,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import BatchPayload, BatchRequirements, BatchSettlementResponse
from solana_pay_kit.protocols.x402.client.batch_settlement import (
    BatchChannel,
    build_deposit,
    build_refund,
    build_refund_request_close,
    build_top_up,
    encode_payment_header,
    resolve_terms_with_token_program,
)
from tests._batch_fixture import (
    BLOCKHASH,
    FEE_PAYER,
    MINT,
    NETWORK,
    OPEN_SLOT,
    PAY_TO,
    PAYER,
    PROGRAM_ID,
    STRANGER,
    TOKEN,
    FakeRpc,
    channel_account,
    server,
    signer,
    token_account,
)

PRICE = "0.001"


class Clock:
    def __init__(self, now: int = 1_800_000_000) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


def _code(exc: pytest.ExceptionInfo[BaseException]) -> str:
    assert isinstance(exc.value, BatchSettlementError), exc.value
    return exc.value.code


class Harness:
    """A server, its store and RPC double, and a client channel."""

    def __init__(self, versions: tuple[int, ...] = (0,), **overrides: Any) -> None:
        self.rpc = FakeRpc()
        self.rpc.put_settlement_accounts(PAYER.pubkey())
        self.store = MemoryBatchChannelStore()
        self.clock = Clock()
        self.server = server(self.rpc, store=self.store, versions=versions, clock=self.clock, **overrides)
        self.requirements = self.server.requirements(PRICE)
        self.terms = resolve_terms_with_token_program(self.requirements, TOKEN)
        self.channel: BatchChannel | None = None
        self.rpc.on_send = self._landed

    def _landed(self, wire: bytes) -> None:
        tx = txv1.decode_transaction(wire)
        if self.channel is None:
            return
        keys = list(tx.message.account_keys)
        data = [bytes(ix.data) for ix in tx.message.instructions if keys[ix.program_id_index] == PROGRAM_ID]
        if any(d[:1] == b"\x01" and len(d) > 60 for d in data):  # open
            self.rpc.put(self.channel.channel_id, channel_account(deposit=self.channel.deposit), PROGRAM_ID)
        elif any(d[:1] == b"\x05" and len(d) == 1 for d in data):  # request_close
            self.rpc.put(self.channel.channel_id, channel_account(status=2, closure_started_at=1_800_000_000), PROGRAM_ID)
        elif any(d[:1] == b"\x04" for d in data):  # settle_and_seal (+ distribute) closes the channel
            self.rpc.accounts.pop(str(self.channel.channel_id), None)

    def header(self, payload: BatchPayload, requirements: BatchRequirements | None = None) -> str:
        return encode_payment_header(requirements or self.requirements, payload)

    async def open(self, deposit: int = 10_000) -> Any:
        self.channel, payload = await build_deposit(
            signer(), self.requirements, self.terms, deposit, BLOCKHASH, OPEN_SLOT, salt=42
        )
        return payload

    async def pay(self, payload: BatchPayload) -> BatchSettlementResponse:
        access = await self.server.verify_and_reserve_payment(self.header(payload), PRICE)
        assert access.kind is BatchAccessKind.SERVE, access.kind
        assert access.outcome is not None
        await self.server.mark_handler_succeeded(access.outcome)
        response = await self.server.finish_commit(access.outcome)
        assert self.channel is not None and payload.voucher is not None
        self.channel.apply_payment_response(response, self.requirements, payload.voucher)
        return response

    async def voucher(self) -> BatchPayload:
        assert self.channel is not None
        return await self.channel.voucher_payload(signer(), self.terms.amount)

    async def refusal(self, payload: BatchPayload | str, requirements: BatchRequirements | None = None) -> str:
        header = payload if isinstance(payload, str) else self.header(payload, requirements)
        with pytest.raises(BatchSettlementError) as exc:
            await self.server.verify_and_reserve_payment(header, PRICE)
        return _code(exc)


# ── configuration and challenges ──


def test_construction_guards() -> None:
    rpc = FakeRpc()
    for overrides, message in (
        ({"pay_to": ""}, "pay_to is required"),
        ({"withdraw_delay": 899}, codes.INVALID_WITHDRAW_DELAY_OUT_OF_RANGE),
        ({"channel_snapshot_max_age_seconds": 3400}, "reservation lease"),
        ({"transaction_versions": (2,)}, "unsupported transaction version"),
        ({"transaction_versions": ()}, "at least one"),
        ({"currency": "SOL"}, "SPL token"),
        ({"token_program": "11111111111111111111111111111111"}, codes.INVALID_TOKEN_PROGRAM),
    ):
        with pytest.raises((ValueError, BatchSettlementError), match=message):
            server(rpc, **overrides)
    default_authorizer = server(rpc, receiver_authorizer=None, program_id=str(PROGRAM_ID))
    assert default_authorizer.requirements(PRICE).extra.receiver_authorizer == str(FEE_PAYER.pubkey())
    assert caip2_network_for_cluster("mainnet-beta").startswith("solana:5eyk")
    assert caip2_network_for_cluster("testnet") == "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
    assert X402BatchSettlement  # re-exported engine


async def test_requirements_and_challenges() -> None:
    h = Harness()
    req = h.requirements
    assert (req.amount, req.network, req.extra.transaction_versions, req.extra.max_claim_channels) == ("1000", NETWORK, None, None)
    assert h.server.redemption_capacity() == (4, 4) and h.server.accepted_versions == (0,)
    v1 = Harness(versions=(0, 1))
    assert v1.requirements.extra.transaction_versions == [0, 1]
    assert v1.server.redemption_capacity() == (18, 13)
    challenge = await h.server.challenge(PRICE, "/paid")
    assert challenge.accepts[0].extra.recent_slot == h.rpc.slot and challenge.resource.url == "/paid"
    name, value = await h.server.payment_required_header(PRICE)
    assert name == "PAYMENT-REQUIRED" and json.loads(base64.b64decode(value))["x402Version"] == 2
    response = BatchSettlementResponse(success=True, transaction="", network=NETWORK)
    assert h.server.settlement_header(response)[0] == "PAYMENT-RESPONSE"
    assert h.server.fee_payer == str(FEE_PAYER.pubkey())
    with pytest.raises(BatchSettlementError):
        await h.server.corrective_challenge(PRICE, "unknown")


async def test_parse_payment_refusals() -> None:
    h = Harness()
    with pytest.raises(InvalidPaymentRequiredError):
        h.server.parse_payment("!!")
    with pytest.raises(InvalidPaymentRequiredError):
        h.server.parse_payment(base64.b64encode(b"{}").decode())
    payload = await h.open()
    other = dataclasses.replace(h.requirements, scheme="exact")
    with pytest.raises(UnsupportedSchemeError):
        h.server.parse_payment(h.header(payload, other))


# ── open, voucher, replay ──


async def test_open_then_vouchers_then_replay_and_corrective() -> None:
    h = Harness()
    response = await h.pay(await h.open())
    assert response.transaction and response.amount == "10000"
    assert response.extra is not None and response.extra.commitment_id is not None
    record = await h.store.get(str(h.channel.channel_id))  # type: ignore[union-attr]
    assert record is not None and record.receiver_binding is not None and record.cumulative == 1000
    second = await h.voucher()
    await h.pay(second)
    # An exact repeat of the highest voucher replays the stored response.
    access = await h.server.verify_and_reserve_payment(h.header(second), PRICE)
    assert access.kind is BatchAccessKind.REPLAY and access.response is not None
    assert access.response.extra.commitment_id == second.voucher.commitment_id()  # type: ignore[union-attr]
    # A stale voucher earns a corrective challenge proving the watermark.
    stale = await h.voucher()
    h.channel.charged_cumulative_amount = 0  # type: ignore[union-attr]
    stale = await h.voucher()
    with pytest.raises(BatchSettlementError) as exc:
        await h.server.verify_and_reserve_payment(h.header(stale), PRICE)
    assert _code(exc) == codes.INVALID_CUMULATIVE_AMOUNT_MISMATCH
    _, value = await h.server.challenge_for_failure(h.header(stale), PRICE, exc.value)
    corrective = BatchRequirements.from_dict(json.loads(base64.b64decode(value))["accepts"][0])
    assert h.channel.adopt_corrective_state(corrective) == 2000  # type: ignore[union-attr]
    _, plain = await h.server.challenge_for_failure("!!", PRICE, BatchSettlementError(codes.INVALID_CHANNEL_STATE, "x"))
    assert json.loads(base64.b64decode(plain))["error"] == codes.INVALID_CHANNEL_STATE
    _, unknown = await h.server.challenge_for_failure("!!", PRICE, exc.value)
    assert json.loads(base64.b64decode(unknown))["error"] == codes.INVALID_CUMULATIVE_AMOUNT_MISMATCH


async def test_reservations_release_and_in_flight() -> None:
    h = Harness()
    await h.pay(await h.open())
    payload = await h.voucher()
    outcome = await h.server.verify_payment(h.header(payload), PRICE)
    with pytest.raises(BatchSettlementError) as exc:
        await h.server.verify_payment(h.header(payload), PRICE)
    assert _code(exc) == codes.DUPLICATE_SETTLEMENT
    outcome.release()
    access = await h.server.verify_and_reserve_payment(h.header(payload), PRICE)
    assert access.kind is BatchAccessKind.SERVE and access.outcome is not None
    access.outcome.release()
    # A second request for the same authorization while the first is reserved.
    again = await h.server.verify_and_reserve_payment(h.header(payload), PRICE)
    assert again.kind is BatchAccessKind.IN_PROGRESS
    await h.server.release_authorization(access.outcome)
    retry = await h.server.verify_and_reserve_payment(h.header(payload), PRICE)
    assert retry.kind is BatchAccessKind.SERVE and retry.outcome is not None
    await h.server.mark_handler_succeeded(retry.outcome)
    retry.outcome.release()
    resume = await h.server.verify_and_reserve_payment(h.header(payload), PRICE)
    assert resume.kind is BatchAccessKind.RESUME and resume.outcome is not None
    first = await h.server.finish_commit(resume.outcome)
    with pytest.raises(BatchSettlementError):
        await h.server.release_authorization(dataclasses.replace(resume.outcome, authorization=None))
    unreserved = dataclasses.replace(resume.outcome, reservation=None)
    with pytest.raises(BatchSettlementError):
        await h.server.mark_handler_succeeded(unreserved)
    assert (await h.server.replay_response(resume.outcome)).to_dict() == first.to_dict()


async def test_voucher_refusals() -> None:
    h = Harness()
    await h.pay(await h.open())
    payload = await h.voucher()
    channel = str(h.channel.channel_id)  # type: ignore[union-attr]
    assert await h.refusal(dataclasses.replace(payload, voucher=dataclasses.replace(payload.voucher, max_claimable_amount="99999"))) == codes.INVALID_VOUCHER_SIGNATURE  # type: ignore[arg-type]
    over = BatchChannel(h.channel.channel_id, h.channel.config, 1000, 1500)  # type: ignore[union-attr]
    h.channel = over
    big = await over.voucher_payload(signer(), 1000)
    record = await h.store.get(channel)
    assert record is not None
    await h.store.put(dataclasses.replace(record, deposit=1500))
    assert await h.refusal(big) == codes.INVALID_CUMULATIVE_EXCEEDS_DEPOSIT
    await h.store.put(dataclasses.replace(record, close_requested_at=5))
    assert await h.refusal(payload) == codes.INVALID_CHANNEL_CLOSING
    await h.store.put(dataclasses.replace(record, sealed=True))
    assert await h.refusal(payload) == codes.INVALID_CLOSE_STATE
    await h.store.put(dataclasses.replace(record, binding=ChannelBinding("batch-settlement", pay_to=str(STRANGER.pubkey()))))
    assert await h.refusal(payload) == codes.INVALID_CHANNEL_STATE
    await h.store.put(record)
    # Accepted requirements other than the route's.
    assert await h.refusal(payload, dataclasses.replace(h.requirements, amount="2000")) == codes.INVALID_PAYMENT_REQUIREMENTS
    envelope = json.loads(base64.b64decode(h.header(payload)))
    envelope["x402Version"] = 1
    assert await h.refusal(base64.b64encode(json.dumps(envelope).encode()).decode()) == codes.INVALID_X402_VERSION
    # Chain state refreshed past the snapshot age.
    h.clock.now += 60
    h.rpc.put(h.channel.channel_id, channel_account(status=0, closure_started_at=7), PROGRAM_ID)  # type: ignore[union-attr]
    assert await h.refusal(payload) == codes.INVALID_CHANNEL_CLOSING
    await h.store.put(record)
    h.rpc.accounts.pop(channel)
    assert await h.refusal(payload) == codes.INVALID_CHANNEL_STATE
    await h.store.put(record)
    h.rpc.put(h.channel.channel_id, channel_account(discriminator=2), PROGRAM_ID)  # type: ignore[union-attr]
    assert await h.refusal(payload) == codes.INVALID_CHANNEL_STATE
    h.rpc.put(h.channel.channel_id, channel_account(), STRANGER.pubkey())  # type: ignore[union-attr]
    with pytest.raises(BatchServerError, match="owned by"):
        await h.server.verify_and_reserve_payment(h.header(payload), PRICE)
    h.rpc.put(h.channel.channel_id, b"", PROGRAM_ID)  # type: ignore[union-attr]
    with pytest.raises(BatchServerError, match="empty"):
        await h.server.verify_and_reserve_payment(h.header(payload), PRICE)
    h.rpc.put(h.channel.channel_id, b"\x01\x02", PROGRAM_ID)  # type: ignore[union-attr]
    with pytest.raises(BatchServerError, match="decode"):
        await h.server.verify_and_reserve_payment(h.header(payload), PRICE)
    h.rpc.fail.add("getAccountInfo")
    with pytest.raises(BatchServerError, match="fetch failed"):
        await h.server.verify_and_reserve_payment(h.header(payload), PRICE)


async def test_unknown_channel_and_record_without_binding() -> None:
    h = Harness()
    await h.open()
    assert await h.refusal(await h.voucher()) == codes.INVALID_CHANNEL_STATE
    channel = h.channel
    assert channel is not None
    # A legacy record (no binding, no grace period) completes them from the chain.
    await h.store.put(
        BatchChannelRecord(str(channel.channel_id), str(PAYER.pubkey()), payer=str(PAYER.pubkey()), deposit=10_000)
    )
    h.rpc.put(channel.channel_id, channel_account(), PROGRAM_ID)
    access = await h.server.verify_and_reserve_payment(h.header(await h.voucher()), PRICE)
    assert access.kind is BatchAccessKind.SERVE and access.outcome is not None
    access.outcome.release()
    record = await h.store.get(str(channel.channel_id))
    assert record is not None and record.binding == h.server.binding() and record.grace_period == 3600
    # A record whose channel is not onchain cannot be completed.
    await h.store.put(BatchChannelRecord(str(channel.channel_id), str(PAYER.pubkey()), deposit=10_000, observed_at=h.clock.now))
    h.rpc.accounts.pop(str(channel.channel_id))
    assert await h.refusal(await h.voucher()) == codes.INVALID_CHANNEL_STATE
    # A mismatching onchain channel is refused.
    h.rpc.put(channel.channel_id, channel_account(payee=STRANGER.pubkey()), PROGRAM_ID)
    assert await h.refusal(await h.voucher()) == codes.INVALID_CHANNEL_STATE
    await h.store.put(BatchChannelRecord(str(channel.channel_id), str(PAYER.pubkey()), deposit=10_000, grace_period=900, observed_at=h.clock.now))
    assert await h.refusal(await h.voucher()) == codes.INVALID_CHANNEL_STATE


async def test_deposit_refusals_and_top_up() -> None:
    h = Harness()
    payload = await h.open()
    for mutate, code in (
        (lambda: h.rpc.put(MINT, b"\x00" * 82, TOKEN_2022_PROGRAM), codes.INVALID_TOKEN_PROGRAM),
        (lambda: h.rpc.accounts.pop(str(find_associated_token_address(PAY_TO, MINT, TOKEN)[0])), codes.INVALID_SETTLEMENT_SIMULATION),
        (lambda: setattr(h.rpc, "blockhash_valid", False), codes.INVALID_SETTLEMENT_SIMULATION),
        (
            lambda: h.rpc.put(find_associated_token_address(PAYER.pubkey(), MINT, TOKEN)[0], token_account(MINT, PAYER.pubkey(), 5), TOKEN),
            codes.INVALID_SETTLEMENT_SIMULATION,
        ),
        (lambda: h.rpc.put(h.channel.channel_id, channel_account(), PROGRAM_ID), codes.INVALID_CHANNEL_STATE),  # type: ignore[union-attr]
    ):
        h.rpc.put_settlement_accounts(PAYER.pubkey())
        h.rpc.blockhash_valid = True
        h.rpc.accounts.pop(str(h.channel.channel_id), None)  # type: ignore[union-attr]
        mutate()
        assert await h.refusal(payload) == code
    h.rpc.put_settlement_accounts(PAYER.pubkey())
    h.rpc.blockhash_valid = True
    h.rpc.accounts.pop(str(h.channel.channel_id), None)  # type: ignore[union-attr]
    first = dataclasses.replace(payload, voucher=await h.channel.sign_next_voucher(signer(), 2000))  # type: ignore[union-attr]
    assert await h.refusal(first) == codes.INVALID_CUMULATIVE_AMOUNT_MISMATCH
    h.rpc.fail.add("isBlockhashValid")
    assert await h.refusal(payload) == codes.INVALID_SETTLEMENT_SIMULATION
    h.rpc.fail.clear()
    await h.pay(payload)
    channel = h.channel
    assert channel is not None
    channel.deposit = 1000
    top_up = await build_top_up(signer(), channel, h.terms, 6000, BLOCKHASH)
    h.rpc.on_send = lambda wire: h.rpc.put(channel.channel_id, channel_account(deposit=16_000), PROGRAM_ID)
    response = await h.pay(top_up)
    assert response.amount == "6000" and channel.deposit == 16_000
    record = await h.store.get(str(channel.channel_id))
    assert record is not None and len(record.processed_topup_signatures) == 2


async def test_broadcast_paths() -> None:
    h = Harness()
    payload = await h.open()
    access = await h.server.verify_and_reserve_payment(h.header(payload), PRICE)
    assert access.outcome is not None
    await h.server.mark_handler_succeeded(access.outcome)
    h.rpc.simulation = {"err": "InstructionError", "logs": ["boom"]}
    outcome = access.outcome
    outcome.release_hook = None
    with pytest.raises(BatchSettlementError) as exc:
        await h.server.finish_commit(outcome)
    assert _code(exc) == codes.INVALID_SETTLEMENT_SIMULATION and "boom" in str(exc.value)
    h.rpc.simulation = {"err": None}
    h.rpc.fail.add("sendTransaction")
    with pytest.raises(BatchServerError, match="broadcast failed"):
        await h.server.finish_commit(outcome)
    h.rpc.fail.clear()
    tx = txv1.decode_transaction(base64.b64decode(payload.deposit.transaction))
    cosigned = await h.server._cosign(payload.deposit.transaction)  # noqa: SLF001
    signature = str(txv1.decode_transaction(cosigned).signatures[0])
    assert signature != str(tx.signatures[0])
    h.rpc.statuses[signature] = {"err": "failed"}
    with pytest.raises(BatchSettlementError, match="landed but failed"):
        await h.server.finish_commit(outcome)
    h.rpc.statuses[signature] = {"err": None, "confirmationStatus": "confirmed"}
    h.rpc.put(h.channel.channel_id, channel_account(), PROGRAM_ID)  # type: ignore[union-attr]
    response = await h.server.finish_commit(outcome)
    assert response.transaction == signature


async def test_version_1_open_is_cosigned() -> None:
    h = Harness(versions=(0, 1))
    payload = await h.open()
    assert txv1.is_v1(txv1.decode_transaction(base64.b64decode(payload.deposit.transaction)))
    response = await h.pay(payload)
    assert response.success


# ── refunds ──


async def test_cooperative_refund_and_replay() -> None:
    h = Harness()
    await h.pay(await h.open())
    await h.pay(await h.voucher())
    refund = await build_refund(signer(), h.channel, h.terms)  # type: ignore[arg-type]
    access = await h.server.verify_and_reserve_payment(h.header(refund), PRICE)
    assert access.kind is BatchAccessKind.CONTROL and access.outcome is not None
    response = await h.server.settle_payment(access.outcome)
    assert response.amount == "8000" and response.transaction
    # A retry whose response was lost replays the saved close.
    again = await h.server.verify_and_reserve_payment(h.header(refund), PRICE)
    assert again.outcome is not None
    assert (await h.server.settle_payment(again.outcome)).amount == "8000"


async def test_refund_refusals_and_request_close() -> None:
    h = Harness()
    await h.pay(await h.open())
    channel = h.channel
    assert channel is not None
    refund = await build_refund(signer(), channel, h.terms)
    assert await h.refusal(dataclasses.replace(refund, amount="1")) == codes.INVALID_CLOSE_AMOUNT_UNSUPPORTED
    behind = BatchChannel(channel.channel_id, channel.config, 0, 10_000)
    assert await h.refusal(await build_refund(signer(), behind, h.terms)) == codes.INVALID_CLOSE_STATE
    record = await h.store.get(str(channel.channel_id))
    assert record is not None
    await h.store.put(dataclasses.replace(record, receiver_binding=str(STRANGER.pubkey())))
    assert await h.refusal(refund) == codes.INVALID_RECEIVER_AUTHORIZER_MISMATCH
    await h.store.put(dataclasses.replace(record, receiver_binding=None))
    assert await h.refusal(refund) == codes.INVALID_RECEIVER_BINDING_UNAVAILABLE
    h.rpc.put(channel.channel_id, channel_account(status=3), PROGRAM_ID)
    retry = await build_refund_request_close(signer(), channel, h.terms, BLOCKHASH)
    assert await h.refusal(retry) == codes.INVALID_CLOSE_STATE
    h.rpc.put(channel.channel_id, channel_account(settled=5000), PROGRAM_ID)
    assert await h.refusal(retry) == codes.INVALID_CLOSE_STATE
    h.rpc.put(channel.channel_id, channel_account(), PROGRAM_ID)
    await h.store.put(dataclasses.replace(record, receiver_binding=None))
    access = await h.server.verify_and_reserve_payment(h.header(retry), PRICE)
    assert access.outcome is not None
    response = await h.server.settle_payment(access.outcome)
    assert response.extra is not None and response.extra.channel_state.withdraw_requested_at == 1_800_000_000  # type: ignore[union-attr]
    assert len(h.rpc.sent) == 3  # open, claim, request_close
    # A refund for a channel already Closing reports that close.
    h.rpc.put(channel.channel_id, channel_account(status=2, closure_started_at=9), PROGRAM_ID)
    await h.store.put(dataclasses.replace(record, close_requested_at=None))
    access = await h.server.verify_and_reserve_payment(h.header(refund), PRICE)
    assert access.outcome is not None
    assert (await h.server.settle_payment(access.outcome)).transaction == ""
    retry_access = await h.server.verify_payment(h.header(retry), PRICE)
    assert (await h.server.settle_payment(retry_access)).transaction == ""
    await h.store.update(str(channel.channel_id), lambda r: None)
    assert await h.refusal(refund) == codes.INVALID_CHANNEL_STATE
    unknown = dataclasses.replace(retry_access, payload=dataclasses.replace(refund, type="authorization"))
    with pytest.raises(BatchSettlementError):
        await h.server.settle_payment(unknown)


async def test_cooperative_close_refusals() -> None:
    h = Harness()
    await h.pay(await h.open())
    refund = await build_refund(signer(), h.channel, h.terms)  # type: ignore[arg-type]
    outcome = await h.server.verify_payment(h.header(refund), PRICE)
    outcome.release()
    channel = h.channel
    assert channel is not None
    for account, message in (
        (channel_account(status=1), "cannot be closed"),
        (channel_account(payee=STRANGER.pubkey()), "payee"),
    ):
        h.rpc.put(channel.channel_id, account, PROGRAM_ID)
        with pytest.raises(BatchSettlementError, match=message):
            await h.server.settle_payment(outcome)
    h.rpc.put(channel.channel_id, channel_account(), PROGRAM_ID)
    h.rpc.on_send = None
    with pytest.raises(BatchSettlementError, match="status 0"):
        await h.server.settle_payment(outcome)
    record = await h.store.get(str(channel.channel_id))
    assert record is not None and record.final_cumulative == 1000
    await h.store.put(dataclasses.replace(record, cumulative=2000))
    with pytest.raises(BatchSettlementError, match="moved"):
        await h.server.settle_payment(outcome)
    await h.store.put(dataclasses.replace(record, final_cumulative=500))
    with pytest.raises(BatchSettlementError, match="already closing"):
        await h.server.settle_payment(outcome)


# ── redemption ──


async def test_claim_settle_and_finalize() -> None:
    h = Harness()
    await h.pay(await h.open())
    await h.pay(await h.voucher())
    channel = str(h.channel.channel_id)  # type: ignore[union-attr]
    h.rpc.on_send = None
    assert len(await h.server.claim([channel])) == 1
    record = await h.store.get(channel)
    assert record is not None and record.settled_on_chain == 2000
    h.rpc.put(h.channel.channel_id, channel_account(settled=2000), PROGRAM_ID)  # type: ignore[union-attr]
    assert await h.server.claim([channel]) == []
    assert len(await h.server.settle([channel])) == 1
    h.rpc.put(h.channel.channel_id, channel_account(settled=2000, payout=2000), PROGRAM_ID)  # type: ignore[union-attr]
    assert await h.server.settle([channel, str(STRANGER.pubkey())]) == []
    assert await h.server.finalize_close([channel, str(STRANGER.pubkey())]) == []
    h.rpc.put(h.channel.channel_id, channel_account(status=2, closure_started_at=5, settled=2000), PROGRAM_ID)  # type: ignore[union-attr]
    assert len(await h.server.finalize_close([channel])) == 1
    record = await h.store.get(channel)
    assert record is not None and record.sealed and record.final_cumulative == 2000
    h.rpc.put(h.channel.channel_id, channel_account(status=1, settled=2000), PROGRAM_ID)  # type: ignore[union-attr]
    assert len(await h.server.finalize_close([channel])) == 1
    h.rpc.put(STRANGER.pubkey(), channel_account(), PROGRAM_ID)
    with pytest.raises(BatchSettlementError, match="unknown channel"):
        await h.server.claim([str(STRANGER.pubkey())])
    v1 = Harness(versions=(0, 1))
    await v1.pay(await v1.open())
    await v1.pay(await v1.voucher())
    v1.rpc.on_send = None
    assert len(await v1.server.claim([str(v1.channel.channel_id)])) == 1  # type: ignore[union-attr]
    assert txv1.is_v1(txv1.decode_transaction(v1.rpc.sent[-1]))


# ── settlement accounts ──


def test_unusable_settlement_account() -> None:
    owner = PAYER.pubkey()
    good = token_account(MINT, owner, 1)
    assert unusable_settlement_account(TOKEN, good, owner, MINT, TOKEN) is None
    immutable_owner = good + bytes([2]) + (7).to_bytes(2, "little") + (0).to_bytes(2, "little")
    assert unusable_settlement_account(TOKEN, immutable_owner, owner, MINT, TOKEN) is None
    assert unusable_settlement_account(TOKEN, immutable_owner + bytes(8), owner, MINT, TOKEN) is None
    cases = [
        (Pubkey.from_string(TOKEN_2022_PROGRAM), good, "declared token program"),
        (TOKEN, good[:100], "not an initialized"),
        (TOKEN, token_account(STRANGER.pubkey(), owner, 1), "holds mint"),
        (TOKEN, token_account(MINT, STRANGER.pubkey(), 1), "is owned by"),
        (TOKEN, token_account(MINT, owner, 1, state=2), "frozen"),
        (TOKEN, token_account(MINT, owner, 1, state=0), "account state 0"),
        (TOKEN, good + bytes([1]), "extension 1"),
        (TOKEN, good + bytes([2]) + (12).to_bytes(2, "little") + (0).to_bytes(2, "little"), "extension 12"),
        (TOKEN, good + bytes([2, 7]), "extension 65535"),
        (TOKEN, good + bytes([2]) + (7).to_bytes(2, "little") + (9).to_bytes(2, "little"), "extension 65535"),
    ]
    for program, data, message in cases:
        problem = unusable_settlement_account(program, data, owner, MINT, TOKEN)
        assert problem is not None and message in problem, (message, problem)


# ── store ──


def _request(cumulative: int, now: int = 100, auth: str = "a", fp: str = "f") -> AuthorizationRequest:
    return AuthorizationRequest(auth, fp, 1000, cumulative, 60, now)


def test_store_reservation_outcomes() -> None:
    record = BatchChannelRecord("c", "p")
    assert record.refuse_reservation(_request(2000)) is Reservation.STALE
    token = record.take_reservation(_request(1000))
    assert record.refuse_reservation(_request(1000)) is Reservation.IN_PROGRESS
    assert record.refuse_reservation(_request(1000, fp="other")) is Reservation.CONFLICT
    assert record.refuse_reservation(_request(1000, auth="b")) is Reservation.IN_PROGRESS
    assert record.refuse_reservation(_request(1000, now=1000)) is Reservation.ABANDONED
    assert record.refuse_reservation(_request(1000, now=1000, auth="b")) is Reservation.ABANDONED
    record.mark_handler_succeeded(token)
    assert record.refuse_reservation(_request(1000)) is Reservation.HANDLER_SUCCEEDED
    assert record.token_for_pending(_request(1000)) == token
    assert record.token_for_pending(_request(1000, auth="z")) is None
    with pytest.raises(BatchStoreError):
        record.release_authorization("a", "f")
    with pytest.raises(BatchStoreError):
        record.release_authorization("a", "other")
    record.release_authorization("missing", "f")
    assert record.commit_authorization(token, "sig", 0, lambda r: {"ok": r.cumulative})
    assert record.committed_authorization("a").settlement_response == {"ok": 1000}  # type: ignore[union-attr]
    assert not record.commit_authorization(token, "sig", 0, lambda r: {})
    record.mark_handler_succeeded(token)
    assert record.refuse_reservation(_request(1000)) is Reservation.COMMITTED
    assert record.refuse_reservation(_request(1000, fp="x")) is Reservation.CONFLICT
    with pytest.raises(BatchStoreError):
        record.commit_authorization(dataclasses.replace(token, cumulative=5), "sig", 0, lambda r: {})
    with pytest.raises(BatchStoreError):
        record.mark_handler_succeeded(dataclasses.replace(token, authorization_id="zz"))
    closing = BatchChannelRecord("c", "p", close_requested_at=1)
    assert closing.refuse_reservation(_request(1000)) is Reservation.CLOSING


def test_store_commit_fences() -> None:
    record = BatchChannelRecord("c", "p")
    token = record.take_reservation(_request(1000))
    record.sealed = True
    with pytest.raises(BatchStoreError, match="sealed"):
        record.commit_authorization(token, "s", 0, lambda r: {})
    record.sealed = False
    record.final_cumulative = 0
    with pytest.raises(BatchStoreError, match="final watermark"):
        record.commit_authorization(token, "s", 0, lambda r: {})
    record.final_cumulative = None
    record.cumulative = 500
    with pytest.raises(BatchStoreError, match="does not step"):
        record.commit_authorization(token, "s", 0, lambda r: {})


def test_store_bindings_and_observations() -> None:
    current = ChannelBinding("batch-settlement", "pay", "net", "prog")
    record = BatchChannelRecord("c", "p")
    record.check_binding(current)
    with pytest.raises(BatchStoreError):
        record.check_binding_complete(current)
    record.adopt_binding(current)
    record.check_binding_complete(current)
    record.binding = ChannelBinding("batch-settlement", pay_to="pay")
    record.adopt_binding(current)
    assert record.binding == current
    for other, field_name in (
        (ChannelBinding("session", "pay", "net", "prog"), "scheme"),
        (ChannelBinding("batch-settlement", "x", "net", "prog"), "payTo"),
        (ChannelBinding("batch-settlement", "pay", "x", "prog"), "network"),
        (ChannelBinding("batch-settlement", "pay", "net", "x"), "programId"),
    ):
        with pytest.raises(BatchStoreError, match=field_name):
            record.check_binding(other)
    with pytest.raises(BatchStoreError):
        record.check_grace_period(900)
    record.grace_period = 3600
    with pytest.raises(BatchStoreError):
        record.check_grace_period(900)
    assert record.is_empty_tombstone() and not record.has_in_flight_authorization()
    assert record.record_observation("open", None, 10, 1)
    assert not record.record_observation("closing", 5, 9, 2)
    assert record.close_requested_at == 5
    assert record.record_observation("terminal", 7, None, 3)
    assert record.sealed and record.close_requested_at == 5


async def test_memory_store_copies_records() -> None:
    store = MemoryBatchChannelStore()
    record = BatchChannelRecord("c", "p")
    await store.put(record)
    record.deposit = 5
    fetched = await store.get("c")
    assert fetched is not None and fetched.deposit == 0
    assert len(await store.list_channels()) == 1
    assert await store.update("c", lambda r: None) is None
    assert await store.get("c") is None
