"""x402 ``batch-settlement`` httpx transport and refund driver, against the Python server engine."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from typing import Any, cast

import httpx
import pytest
from solders.keypair import Keypair

from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.engine import (
    BatchSettlementConfig,
    CorrectiveRequired,
    VerifiedBatchRequest,
    X402BatchSettlement,
)
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.client.batch_settlement import (
    BatchPaymentTransport,
    BatchSettlementClient,
    ServerSignedChannelsPolicy,
    parse_payment_required,
)
from solana_pay_kit.signer import LocalSigner
from tests.batch_chain import BLOCKHASH, CLOSING, MINT, PRICE, SLOT, World, make_world

pytestmark = pytest.mark.usefixtures("reset_batch_globals")

NOW = 1_700_000_000.0
OPERATOR = LocalSigner.from_keypair(Keypair.from_seed(bytes([4] * 32)))
URL = "https://api.example/batch"


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    return make_world(monkeypatch)


class Server:
    """A ``batch-settlement`` route over the engine, as an ``httpx.MockTransport``; ``paid`` counts paid requests."""

    def __init__(self, world: World, operator: LocalSigner | None = None) -> None:
        self.world = world
        self.engine = X402BatchSettlement(
            world.config,
            settings=BatchSettlementConfig(operator=operator),
            rpc=world.chain,  # type: ignore[arg-type]
            recent_state_provider=lambda: (BLOCKHASH, SLOT),
            clock=lambda: NOW,
        )
        self.paid = 0
        self.transport = httpx.MockTransport(self.handle)

    async def handle(self, request: httpx.Request) -> httpx.Response:
        gate, engine = self.world.gate, self.engine
        if not engine.detect_batch(request):
            return httpx.Response(402, headers=engine.challenge_headers(gate, request))
        self.paid += 1
        try:
            verified = await engine.verify_and_reserve(gate, request)
            if not isinstance(verified, VerifiedBatchRequest):  # a refund answers directly
                return httpx.Response(200, headers=engine.settlement_headers(verified))
            actual = verified.ceiling if verified.server_signed else None  # a metered route charges its ceiling
            settled = await engine.commit(verified, actual)
            return httpx.Response(200, headers=engine.settlement_headers(settled), text="ok")
        except CorrectiveRequired as exc:
            return httpx.Response(
                402, headers=engine.challenge_headers(gate, request, error=exc.code, accepts=exc.accepts)
            )
        except BatchSettlementError as exc:
            return httpx.Response(402, headers=engine.challenge_headers(gate, request, error=exc.code))


def _client(world: World, **kwargs: Any) -> BatchSettlementClient:
    return BatchSettlementClient(world.payer, rpc=world.chain, discover_channels=False, clock=lambda: NOW, **kwargs)  # type: ignore[arg-type]


def _http(client: BatchSettlementClient, transport: httpx.AsyncBaseTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=BatchPaymentTransport(client, base_transport=transport))


def _settlement(response: httpx.Response) -> Any:
    return json.loads(base64.b64decode(response.headers["payment-response"]))


async def test_passes_through_responses_that_are_not_a_batch_challenge(world: World) -> None:
    responses = iter([httpx.Response(200, text="free"), httpx.Response(402, json={"accepts": [{"scheme": "exact"}]})])
    upstream = httpx.MockTransport(lambda request: next(responses))
    async with _http(_client(world), upstream) as http:
        assert (await http.get(URL)).text == "free"
        assert (await http.get(URL)).status_code == 402


async def test_pays_a_challenge_and_advances_the_channel_per_request(world: World) -> None:
    server = Server(world)
    world.lands_as_channel(deposit=10 * PRICE)
    async with _http(_client(world), server.transport) as http:
        first = await http.get(URL)
        second = await http.get(URL)
    assert (first.status_code, first.text, second.status_code) == (200, "ok", 200)
    assert _settlement(second)["extra"]["channelState"]["chargedCumulativeAmount"] == str(2 * PRICE)
    assert server.paid == 2 and len(world.chain.sent) == 1  # one open, then a plain voucher


async def test_retries_once_after_adopting_a_proven_corrective(world: World) -> None:
    server = Server(world)
    world.lands_as_channel(deposit=10 * PRICE)
    accepted = server.engine.accepts_entries(world.gate, {})[0]
    async with _http(_client(world), server.transport) as http:
        assert (await http.get(URL)).status_code == 200
        # The same wallet pays twice from another process: this client falls behind.
        for cumulative in (2 * PRICE, 3 * PRICE):
            other = world.header(accepted, world.voucher_payload(cumulative))
            assert (await server.handle(httpx.Request("GET", URL, headers=other["headers"]))).status_code == 200
        caught_up = await http.get(URL)
    assert caught_up.status_code == 200
    assert _settlement(caught_up)["extra"]["channelState"]["chargedCumulativeAmount"] == str(4 * PRICE)
    assert server.paid == 5  # open, two from the other process, the stale voucher, the resynced retry


@pytest.mark.parametrize(("charged", "requests"), [("0", 3), ("5", 2)])
async def test_retries_a_corrective_once_and_only_when_adopted(world: World, charged: str, requests: int) -> None:
    server = Server(world)
    sent: list[httpx.Request] = []

    def corrective(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        headers = server.engine.challenge_headers(world.gate, request)
        if "payment-signature" not in request.headers:
            return httpx.Response(402, headers=headers)
        payment = json.loads(base64.b64decode(request.headers["payment-signature"]))
        channel_id = payment["payload"]["voucher"]["channelId"]
        accept = server.engine.accepts_entries(world.gate, request)[0]
        # "0" is the settled watermark itself, adoptable without a proof every time; "5" never is.
        state = {"balance": "50000", "channelId": channel_id, "chargedCumulativeAmount": charged, "totalClaimed": "0"}
        accept["extra"]["channelState"] = {**state, "withdrawRequestedAt": 0}  # type: ignore[typeddict-unknown-key]
        mismatch = errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH
        return httpx.Response(
            402, headers=server.engine.challenge_headers(world.gate, request, error=mismatch, accepts=[accept])
        )

    world.put_channel(deposit=50_000)  # a corrective is only ever adopted off the chain
    async with _http(_client(world), httpx.MockTransport(corrective)) as http:
        assert (await http.get(URL)).status_code == 402
    assert len(sent) == requests  # the probe, the payment, at most one retry


async def test_a_payment_the_client_cannot_build_surfaces_the_original_challenge(world: World) -> None:
    server = Server(world)
    world.chain.accounts.pop(MINT)  # the client cannot check the mint owner
    async with _http(_client(world), server.transport) as http:
        response = await http.get(URL)
    assert response.status_code == 402 and server.paid == 0


async def test_a_rejected_payment_response_keeps_the_confirmed_state(world: World) -> None:
    server = Server(world)
    world.lands_as_channel(deposit=10 * PRICE)
    forged = base64.b64encode(json.dumps({"success": True, "extra": {"chargedAmount": "1"}}).encode()).decode()
    responses = iter([None, httpx.Response(200, headers={"payment-response": forged})])

    async def lying(request: httpx.Request) -> httpx.Response:
        response = next(responses)
        return response if response is not None else await server.handle(request)

    client = _client(world)
    async with _http(client, httpx.MockTransport(lying)) as http:
        assert (await http.get(URL)).status_code == 200
    # Not advanced: the open is still unconfirmed, so the next payment opens again.
    payment: Any = await client.create_payment_payload(server.engine.accepts_entries(world.gate, {})[0])
    assert payment["payload"]["type"] == "deposit"


@pytest.mark.parametrize("failure", ["reset", "cancelled"])
async def test_a_lost_answer_releases_the_channel_and_the_next_request_resyncs(world: World, failure: str) -> None:
    server = Server(world)
    world.lands_as_channel(deposit=10 * PRICE)
    paid = [0]

    async def losing(request: httpx.Request) -> httpx.Response:
        response = await server.handle(request)
        if "payment-signature" in request.headers:
            paid[0] += 1
            if paid[0] == 2:  # charged, but the answer never arrives
                if failure == "reset":
                    raise httpx.ReadError("connection reset")
                await asyncio.Event().wait()  # hangs until the caller gives up
        return response

    async with _http(_client(world), httpx.MockTransport(losing)) as http:
        assert (await http.get(URL)).status_code == 200
        if failure == "reset":
            with pytest.raises(httpx.ReadError):
                await http.get(URL)
        else:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(http.get(URL), 0.05)
        # No wait for the 300 s lease: the identical voucher is re-signed and
        # the server's proof of it confirms the lost charge before the retry.
        resumed = await asyncio.wait_for(http.get(URL), 2)
    assert resumed.status_code == 200
    assert _settlement(resumed)["extra"]["channelState"]["chargedCumulativeAmount"] == str(3 * PRICE)


async def test_a_streaming_post_body_survives_the_paid_retry(world: World) -> None:
    # The 402 costs the body: an async-generator body is consumed by the first
    # send, and the paid request would carry nothing without buffering.
    server = Server(world)
    world.lands_as_channel(deposit=10 * PRICE)
    bodies: list[bytes] = []

    class Draining(httpx.AsyncBaseTransport):
        """Consumes the request stream, the way a real transport does.

        ``httpx.MockTransport`` buffers every request it is handed, which would
        hide the bug this test is about.
        """

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            bodies.append(b"".join([chunk async for chunk in request.stream]))  # type: ignore[union-attr]
            return await server.handle(request)

    async def chunks() -> AsyncIterator[bytes]:
        yield b"summarize "
        yield b"this text"

    async with _http(_client(world), Draining()) as http:
        paid = await http.post(URL, content=chunks())
    assert paid.status_code == 200
    assert bodies == [b"summarize this text", b"summarize this text"]  # unpaid, then paid


def test_challenge_parsing_surfaces_the_corrective_error_code(world: World) -> None:
    server = Server(world)
    mismatch = errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH
    headers = server.engine.challenge_headers(world.gate, {}, error=mismatch)
    required = parse_payment_required(headers, None)
    assert required is not None and required["error"] == mismatch and required["accepts"][0]["amount"] == str(PRICE)
    body = base64.b64decode(headers["payment-required"]).decode()
    assert parse_payment_required({}, body) == required  # a JSON body works too
    assert parse_payment_required({}, None) is None
    assert parse_payment_required({"payment-required": "%%%"}, "not json") is None


async def test_refund_probes_the_route_and_starts_the_close(world: World) -> None:
    server = Server(world)
    world.lands_as_channel(deposit=10 * PRICE)
    client = _client(world)
    async with _http(client, server.transport) as paying:
        assert (await paying.get(URL)).status_code == 200
    world.lands_as_channel(deposit=10 * PRICE, settled=PRICE)  # the claim
    world.lands_as_channel(deposit=10 * PRICE, settled=PRICE, status=CLOSING, closure_started_at=int(NOW))
    async with httpx.AsyncClient(transport=server.transport) as http:
        (settled,) = await client.refund(URL, http=http)
        assert settled["success"] and server.paid == 2
        # The closing channel is forgotten: nothing is left to refund or pay from.
        with pytest.raises(ValueError, match="no batch-settlement channel"):
            await client.refund(URL, http=http)


async def test_refund_closes_the_server_signed_channel_behind_a_dual_accept_route(world: World) -> None:
    server = Server(world, operator=OPERATOR)
    trust = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),))
    client = _client(world, server_signed_channels_policy=trust)
    config = world.channel_config(payerAuthorizer=OPERATOR.pubkey(), voucherSigner="server")
    world.lands_as_channel(config, deposit=3 * PRICE)
    async with _http(client, server.transport) as paying:
        assert (await paying.get(URL)).status_code == 200
    world.lands_as_channel(config, deposit=3 * PRICE, settled=PRICE)  # the claim
    world.lands_as_channel(config, deposit=3 * PRICE, settled=PRICE, status=CLOSING, closure_started_at=int(NOW))
    async with httpx.AsyncClient(transport=server.transport) as http:
        (settled,) = await client.refund(URL, http=http)
    assert settled["success"]
    assert cast(Any, settled).get("extra")["channelState"]["channelId"] == world.channel_id(config)


async def test_refund_raises_with_the_servers_reason(world: World) -> None:
    server = Server(world)
    world.lands_as_channel(deposit=10 * PRICE)
    client = _client(world)
    async with _http(client, server.transport) as paying:
        assert (await paying.get(URL)).status_code == 200
    world.chain.simulation_error = {"InstructionError": [0, "Custom"]}  # the close would fail on chain
    async with httpx.AsyncClient(transport=server.transport) as http:
        with pytest.raises(BatchSettlementError, match="refund refused") as exc:
            await client.refund(URL, http=http)
    assert exc.value.code == errors.INVALID_SETTLEMENT_SIMULATION


@pytest.mark.parametrize(
    ("responses", "message"),
    [
        ([httpx.Response(200)], "expected 402"),
        ([httpx.Response(402, json={"accepts": []})], "does not offer"),
        ([httpx.Response(500)], "no PAYMENT-RESPONSE"),
        ([httpx.Response(402)], "no reason given"),
    ],
)
async def test_refund_reports_a_route_that_cannot_refund(
    world: World, responses: list[httpx.Response], message: str
) -> None:
    server = Server(world)
    world.lands_as_channel(deposit=10 * PRICE)
    client = _client(world)
    async with _http(client, server.transport) as paying:
        assert (await paying.get(URL)).status_code == 200
    # Probe failures come first; the send failures skip the probe.
    probing = message in ("expected 402", "does not offer")
    requirements = None if probing else server.engine.accepts_entries(world.gate, {})[0]
    feed = iter(responses)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: next(feed))) as http:
        with pytest.raises((ValueError, BatchSettlementError), match=message):
            await client.refund(URL, http=http, requirements=requirements)
