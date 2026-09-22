"""x402 ``batch-settlement`` lifecycle on a surfpool fork of mainnet, against the deployed payment-channels program.

Opt-in: point ``PAYKIT_SURFNET_RPC_URL`` at a surfnet that forks mainnet, e.g.
``surfpool start --network mainnet --no-tui`` then
``PAYKIT_SURFNET_RPC_URL=http://127.0.0.1:8899``. Skipped otherwise, so the
offline suite and its coverage gate never depend on it. Every test funds fresh
keys through the ``surfnet_setAccount`` / ``surfnet_setTokenAccount`` cheatcodes
and pays through the real client, transport and server engine.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_pay_kit import Gate, LocalSigner, Operator, Price, Protocol, Stablecoin, configure
from solana_pay_kit._paycore.paymentchannels import (
    PAYMENT_CHANNELS_PROGRAM_ID,
    build_request_close_instruction,
    find_associated_token_address,
    treasury_owner,
)
from solana_pay_kit._paycore.rpc import SolanaRpc, read_with_replica_retry
from solana_pay_kit._paycore.solana import MEMO_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit.config import BatchSettlementConfig
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.x402.batch_settlement import onchain
from solana_pay_kit.protocols.x402.batch_settlement.engine import VerifiedBatchRequest, X402BatchSettlement
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.client.batch_settlement import (
    BatchPaymentTransport,
    BatchSettlementClient,
    MemoryClientChannelStore,
    ServerSignedChannelsPolicy,
)
from solana_pay_kit.usage import fetch_recent_blockhash_and_slot

RPC = os.environ.get("PAYKIT_SURFNET_RPC_URL", "")
pytestmark = [
    pytest.mark.skipif(not RPC, reason="set PAYKIT_SURFNET_RPC_URL to a surfnet forking mainnet"),
    pytest.mark.usefixtures("reset_batch_globals"),
]

USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # localnet resolves USDC to the mainnet mint
PRICE = 10_000
URL = "http://paid.test/batch"
OPEN, CLOSING, DISTRIBUTED = 0, 2, 3
PROGRAM = Pubkey.from_string(PAYMENT_CHANNELS_PROGRAM_ID)


async def _rpc(method: str, params: list[Any]) -> Any:
    async with httpx.AsyncClient(timeout=30) as http:
        body = (await http.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})).json()
    if "error" in body:
        raise RuntimeError(f"{method}: {body['error']}")
    return body["result"]


async def _fund_sol(owner: str) -> None:
    await _rpc("surfnet_setAccount", [owner, {"lamports": 10 * 10**9}])


async def _fund_usdc(owner: str, amount: int) -> None:
    await _rpc("surfnet_setTokenAccount", [owner, USDC, {"amount": amount, "state": "initialized"}, TOKEN_PROGRAM])


async def _chain_now() -> int:
    """The surfnet's ``Clock`` unix timestamp (it drifts from wall time after a time travel)."""
    clock = await _rpc("getAccountInfo", ["SysvarC1ock11111111111111111111111111111111", {"encoding": "base64"}])
    return struct.unpack_from("<q", base64.b64decode(clock["value"]["data"][0]), 32)[0]


async def _travel_to(unix: int) -> None:
    await _rpc("surfnet_timeTravel", [{"absoluteTimestamp": unix * 1000}])


async def _usdc(owner: str) -> int:
    ata, _ = find_associated_token_address(
        Pubkey.from_string(owner), Pubkey.from_string(USDC), Pubkey.from_string(TOKEN_PROGRAM)
    )
    return int((await _rpc("getTokenAccountBalance", [str(ata)]))["value"]["amount"])


class Server:
    """The route: verify and reserve, run the "handler", commit (``meter`` in server-signed mode)."""

    def __init__(self, engine: X402BatchSettlement, gate: Gate, meter: int) -> None:
        self.engine, self.gate, self.meter = engine, gate, meter
        self.transport = httpx.MockTransport(self.handle)

    async def handle(self, request: httpx.Request) -> httpx.Response:
        engine = self.engine
        if not engine.detect_batch(request):
            return httpx.Response(402, headers=engine.challenge_headers(self.gate, request))
        try:
            verified = await engine.verify_and_reserve(self.gate, request)
            if not isinstance(verified, VerifiedBatchRequest):
                return httpx.Response(200, headers=engine.settlement_headers(verified), text="channel close initiated")
            settled = await engine.commit(verified, self.meter if verified.server_signed else None)
            return httpx.Response(200, headers=engine.settlement_headers(settled), text="ok")
        except BatchSettlementError as exc:
            accepts = getattr(exc, "accepts", None)
            return httpx.Response(
                402, headers=engine.challenge_headers(self.gate, request, error=exc.code, accepts=accepts)
            )


@dataclass
class Stack:
    payer: LocalSigner
    pay_to: str
    engine: X402BatchSettlement
    server: Server
    client: BatchSettlementClient
    store: MemoryClientChannelStore
    http: httpx.AsyncClient

    opened: str | None = None

    def channel_id(self) -> str:
        # The client forgets a channel once it is refunded; remember the one it opened.
        if self.opened is None:
            (record,) = self.store.records.values()
            self.opened = record.channel_id
        return self.opened

    async def channel(self) -> Channel:
        rpc = SolanaRpc(RPC)
        try:
            # Right after a confirmed transaction, and again after a time
            # travel, the surfnet can answer one read before the account is
            # visible: the same lag the SDK absorbs on a replica.
            channel = await read_with_replica_retry(lambda: onchain.read_channel(rpc, self.channel_id(), PROGRAM))
        finally:
            await rpc.aclose()
        assert channel is not None
        return channel

    async def pay(self, times: int) -> list[Any]:
        settled: list[Any] = []
        for _ in range(times):
            response = await self.http.get(URL)
            assert response.status_code == 200, response.headers.get("payment-required")
            settled.append(json.loads(base64.b64decode(response.headers["payment-response"])))
        self.channel_id()
        return settled


async def _stack(
    monkeypatch: pytest.MonkeyPatch,
    *,
    operator: LocalSigner | None = None,
    clock: Callable[[], float] = time.time,
    **client: Any,
) -> Stack:
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    fee_payer = LocalSigner.from_keypair(Keypair())
    payer = LocalSigner.from_keypair(Keypair())
    pay_to = str(Keypair().pubkey())
    await _fund_sol(fee_payer.pubkey())
    await _fund_sol(payer.pubkey())  # only for the payer's own forced close below
    for owner in (fee_payer.pubkey(), pay_to, str(treasury_owner())):
        await _fund_usdc(owner, 0)
    await _fund_usdc(payer.pubkey(), 1_000_000)
    config = configure(
        network="solana_localnet",
        preflight=False,
        accept=(Protocol.X402,),
        operator=Operator(signer=fee_payer, recipient=pay_to),
        rpc_url=RPC,
    )
    engine = X402BatchSettlement(
        config,
        settings=BatchSettlementConfig(operator=operator),
        recent_state_provider=lambda: fetch_recent_blockhash_and_slot(RPC),
        clock=clock,
    )
    gate = Gate.build(name="batch", amount=Price.usd("0.01", Stablecoin.USDC), default_pay_to=pay_to)
    server = Server(engine, gate, meter=4_000)
    store = MemoryClientChannelStore()
    paying = BatchSettlementClient(payer, rpc_url=RPC, channel_store=store, discover_channels=False, **client)
    http = httpx.AsyncClient(transport=BatchPaymentTransport(paying, base_transport=server.transport))
    return Stack(payer, pay_to, engine, server, paying, store, http)


@pytest.fixture
async def stack(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Stack]:
    built = await _stack(monkeypatch)
    yield built
    await built.http.aclose()


async def test_opens_a_channel_and_pays_with_vouchers(stack: Stack) -> None:
    payer_before = await _usdc(stack.payer.pubkey())
    receipts = await stack.pay(3)
    assert [r["extra"]["channelState"]["chargedCumulativeAmount"] for r in receipts] == ["10000", "20000", "30000"]
    assert receipts[0]["transaction"] and receipts[1]["transaction"] == ""  # the open lands once
    channel = await stack.channel()
    assert (int(channel.status), int(channel.deposit), int(channel.settlement.settled)) == (OPEN, 10 * PRICE, 0)
    assert payer_before - await _usdc(stack.payer.pubkey()) == 10 * PRICE


async def test_tops_up_an_exhausted_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    stack = await _stack(monkeypatch, deposit_amount=PRICE)
    try:
        receipts = await stack.pay(3)
        assert all(r["transaction"] for r in receipts)  # the open, then two top-ups
        channel = await stack.channel()
        assert (int(channel.deposit), int(channel.settlement.settled)) == (3 * PRICE, 0)
    finally:
        await stack.http.aclose()


async def test_claims_and_distributes_what_was_charged_to_pay_to(stack: Stack) -> None:
    await stack.pay(3)
    worker = stack.engine.redemption()
    claimed = await worker.claim()
    assert (claimed.claimed, claimed.errors) == ([stack.channel_id()], [])
    assert int((await stack.channel()).settlement.settled) == 3 * PRICE
    distributed = await worker.settle()
    assert (distributed.distributed, distributed.errors) == ([stack.channel_id()], [])
    assert await _usdc(stack.pay_to) == 3 * PRICE


async def test_a_refund_claims_first_then_starts_the_close(stack: Stack) -> None:
    await stack.pay(2)
    async with httpx.AsyncClient(transport=stack.server.transport) as http:
        (settled,) = await stack.client.refund(URL, http=http)
    assert settled["success"]
    channel = await stack.channel()
    assert (int(channel.status), int(channel.settlement.settled)) == (CLOSING, 2 * PRICE)
    assert int(channel.closureStartedAt) > 0


async def test_a_payer_forced_close_is_sealed_in_grace_with_the_latest_voucher(stack: Stack) -> None:
    await stack.pay(3)
    # The payer closes on its own, paying its own fee: the server holds 3 unclaimed vouchers.
    rpc = SolanaRpc(RPC)
    try:
        blockhash = (await rpc.get_latest_blockhash()).value.blockhash
        close = build_request_close_instruction(
            payer=Pubkey.from_string(stack.payer.pubkey()), channel=Pubkey.from_string(stack.channel_id())
        )
        memo = Instruction(Pubkey.from_string(MEMO_PROGRAM), b"forced close", [])
        message = MessageV0.try_compile(
            Pubkey.from_string(stack.payer.pubkey()), [close, memo], [], Hash.from_string(blockhash)
        )
        signature = Signature.from_bytes(stack.payer.sign(bytes(to_bytes_versioned(message))))
        sent = await rpc.send_raw_transaction(bytes(VersionedTransaction.populate(message, [signature])))
        await rpc.await_confirmation(sent.value)
    finally:
        await rpc.aclose()
    closing = await stack.channel()
    assert (int(closing.status), int(closing.settlement.settled)) == (CLOSING, 0)
    # One transaction: settle_and_seal with the latest voucher inside the grace period, plus distribute.
    result = await stack.engine.redemption().run_pass()
    assert (result.sealed, result.errors) == ([stack.channel_id()], [])
    channel = await stack.channel()
    assert (int(channel.status), int(channel.settlement.settled)) == (DISTRIBUTED, 3 * PRICE)
    assert await _usdc(stack.pay_to) == 3 * PRICE


async def test_a_trusted_operator_meters_and_redeems_its_own_vouchers(monkeypatch: pytest.MonkeyPatch) -> None:
    operator = LocalSigner.from_keypair(Keypair())
    trust = ServerSignedChannelsPolicy(allowed_operators=(operator.pubkey(),))
    stack = await _stack(monkeypatch, operator=operator, server_signed_channels_policy=trust)
    try:
        receipts = await stack.pay(2)
        assert [r["extra"]["voucher"]["maxClaimableAmount"] for r in receipts] == ["4000", "8000"]
        channel = await stack.channel()
        assert str(channel.authorizedSigner) == operator.pubkey()
        worker = stack.engine.redemption()
        assert (await worker.claim()).errors == [] and (await worker.settle()).errors == []
        assert int((await stack.channel()).settlement.settled) == 8_000
        assert await _usdc(stack.pay_to) == 8_000
    finally:
        await stack.http.aclose()


# Last on purpose: this one time-travels the surfnet past a grace period, and
# the slots it jumps are shared by everything that runs after it.
async def test_after_the_grace_period_the_close_is_finalized_and_the_rent_reclaimed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skew = [0.0]  # the server's clock follows the surfnet's after the time travel
    stack = await _stack(monkeypatch, clock=lambda: time.time() + skew[0])
    try:
        await stack.pay(2)
        async with httpx.AsyncClient(transport=stack.server.transport) as http:
            (settled,) = await stack.client.refund(URL, http=http)
            assert settled["success"]
        closing = await stack.channel()
        # Past the grace period, which also clears the 1500-slot rent window (400 ms slots).
        target = int(closing.closureStartedAt) + int(closing.gracePeriod) + 5
        await _travel_to(target)
        assert await _chain_now() >= target - 1
        skew[0] = target - time.time()
        worker = stack.engine.redemption()
        rent_payer = worker._fee_payer.pubkey()  # noqa: SLF001
        lamports_before = (await _rpc("getBalance", [rent_payer]))["value"]
        finalized = await worker.finalize_close()
        assert (finalized.finalized, finalized.errors) == ([stack.channel_id()], [])
        assert await _usdc(stack.pay_to) == 2 * PRICE
        assert await _usdc(stack.payer.pubkey()) == 1_000_000 - 2 * PRICE  # the unused escrow went back
        # The sealed ``distribute`` frees the PDA in place once the channel is
        # past its 1500-slot open window, and marks it Distributed for
        # ``reclaim`` otherwise. The time travel can land on either side.
        distributed = (await _rpc("getAccountInfo", [stack.channel_id(), {"encoding": "base64"}]))["value"] is not None
        if distributed:
            channel = await stack.channel()
            assert (int(channel.status), int(channel.settlement.settled)) == (DISTRIBUTED, 2 * PRICE)
        reclaimed = await worker.reclaim()
        assert (reclaimed.reclaimed, reclaimed.errors) == ([stack.channel_id()] if distributed else [], [])
        assert (await _rpc("getAccountInfo", [stack.channel_id(), {"encoding": "base64"}]))["value"] is None
        assert (await _rpc("getBalance", [rent_payer]))["value"] > lamports_before  # the rent came back
    finally:
        await stack.http.aclose()
