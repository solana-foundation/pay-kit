"""x402 ``batch-settlement`` client lifecycle, and its output against the server policy.

The first part covers the cases of the x402 PR #23
``batch.client.lifecycle.test.ts``; the second proves the client's transactions
pass the sponsor policy, as the Rust client tests
(``client/batch_settlement/payment.rs``) do, here by paying the Python server
engine end to end over the fake chain.
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any, cast

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.paymentchannels import find_channel_pda
from solana_pay_kit._paycore.solana import MEMO_PROGRAM, TOKEN_2022_PROGRAM
from solana_pay_kit.errors import ConfigurationError
from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.engine import (
    BatchSettlementConfig,
    CorrectiveRequired,
    VerifiedBatchRequest,
    X402BatchSettlement,
)
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.signatures import sign_voucher
from solana_pay_kit.protocols.x402.batch_settlement.tx_policy import TransactionExpectations, validate_request_close
from solana_pay_kit.protocols.x402.batch_settlement.types import parse_payment_payload
from solana_pay_kit.protocols.x402.client.batch_settlement import (
    BatchSettlementClient,
    ClientChannelRecord,
    MemoryClientChannelStore,
    ServerSignedChannelsPolicy,
)
from solana_pay_kit.signer import LocalSigner
from tests.batch_chain import (
    BLOCKHASH,
    CLOSING,
    MINT,
    OPEN,
    PRICE,
    SEALED,
    SLOT,
    World,
    channel_account,
    make_world,
)

NOW = 1_700_000_000.0
OPERATOR = LocalSigner.from_keypair(Keypair.from_seed(bytes([4] * 32)))
STRANGER = LocalSigner.from_keypair(Keypair.from_seed(bytes([5] * 32)))
MISMATCH = errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    return make_world(monkeypatch)


def requirements(world: World, **overrides: Any) -> dict[str, Any]:
    extra = {
        "feePayer": world.fee_payer.pubkey(),
        "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "withdrawDelay": 900,
        "recentBlockhash": BLOCKHASH,
        "recentSlot": SLOT,
        **overrides.pop("extra", {}),
    }
    accept: dict[str, Any] = {
        "scheme": "batch-settlement",
        "network": world.config.network.caip2(),
        "amount": "1000",
        "asset": MINT,
        "payTo": world.pay_to,
        "maxTimeoutSeconds": 300,
        "extra": extra,
    }
    accept.update(overrides)
    return accept


def _client(world: World, **kwargs: Any) -> BatchSettlementClient:
    kwargs.setdefault("discover_channels", False)
    return BatchSettlementClient(world.payer, rpc=world.chain, clock=lambda: NOW, **kwargs)  # type: ignore[arg-type]


def _accepted(channel_id: str, cumulative: int, charged: str = "1000") -> Any:
    return {
        "success": True,
        "transaction": "",
        "network": "n",
        "amount": "",
        "extra": {
            "chargedAmount": charged,
            "channelState": {"chargedCumulativeAmount": str(cumulative)},
            "commitmentId": f"{channel_id}:{cumulative}",
        },
    }


async def _seed(
    client: BatchSettlementClient,
    world: World,
    req: dict[str, Any],
    *,
    cumulative: int,
    deposit: int,
    store: MemoryClientChannelStore | None = None,
) -> str:
    """Give the client a confirmed channel, as a restart from its store would."""
    store = store or MemoryClientChannelStore()
    config = world.channel_config()
    channel_id = world.channel_id(config)
    store.records[_key(client, world, req)] = ClientChannelRecord(channel_id, config, cumulative, deposit)
    client._store = store  # noqa: SLF001
    return channel_id


def _key(client: BatchSettlementClient, world: World, req: dict[str, Any]) -> str:
    extra = req["extra"]
    return ":".join(
        [
            req["network"],
            req["asset"],
            req["payTo"],
            extra["feePayer"],
            str(extra["withdrawDelay"]),
            extra.get("receiverAuthorizer", ""),
            extra.get("voucherSigner", "client"),
            extra.get("operator", ""),
        ]
    )


def _tx(payment: Any, field: str = "deposit") -> VersionedTransaction:
    raw = payment["payload"][field]["transaction"] if field == "deposit" else payment["payload"]["transaction"]
    return VersionedTransaction.from_bytes(base64.b64decode(raw))


def _memo(tx: VersionedTransaction) -> bytes:
    keys = [str(k) for k in tx.message.account_keys]
    (memo,) = [bytes(ix.data) for ix in tx.message.instructions if keys[ix.program_id_index] == MEMO_PROGRAM]
    return memo


# -- lifecycle (x402 PR #23 batch.client.lifecycle.test.ts) ---------------------------------------


@pytest.mark.parametrize("restart", [False, True])
async def test_commits_a_signed_server_voucher_without_allocating_again(world: World, restart: bool) -> None:
    store = MemoryClientChannelStore()
    trust = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),))
    client = _client(world, channel_store=store, deposit_amount=3000, server_signed_channels_policy=trust)
    req = requirements(world, extra={"operator": OPERATOR.pubkey(), "voucherSigner": "server"})
    opened: Any = await client.create_payment_payload(req)
    assert opened["payload"]["type"] == "deposit" and "maxClaimableAmount" not in opened["payload"]
    channel_id = opened["payload"]["authorization"]["channelId"]
    if restart:
        client = _client(world, channel_store=store, server_signed_channels_policy=trust)

    def served(cumulative: int) -> Any:
        return {
            "success": True,
            "transaction": "",
            "network": "n",
            "amount": "",
            "extra": {
                "channelState": {"chargedCumulativeAmount": str(cumulative)},
                "commitmentId": f"{channel_id}:{cumulative}",
                "voucher": sign_voucher(OPERATOR, channel_id, cumulative),
            },
        }

    await client.handle_payment_response(opened, response=served(400))
    (record,) = store.records.values()
    assert (record.charged_cumulative, record.deposit) == (400, 3000)
    first: Any = await client.create_payment_payload(req)
    assert first["payload"]["type"] == "authorization"
    waiting = asyncio.create_task(client.create_payment_payload(req))  # one payment per channel at a time
    await asyncio.sleep(0)
    assert not waiting.done()
    await client.handle_payment_response(first, response=served(900))
    third: Any = await waiting
    assert third["payload"]["authorization"]["requestId"] != first["payload"]["authorization"]["requestId"]
    await client.handle_payment_response(third, response=served(1200))
    assert next(iter(store.records.values())).charged_cumulative == 1200


async def test_opens_replays_confirms_and_advances_a_persisted_channel(world: World) -> None:
    store = MemoryClientChannelStore()
    client = _client(world, channel_store=store, deposit_amount=3000)
    req = requirements(world)
    opened: Any = await client.create_payment_payload(req)
    assert opened["payload"]["deposit"]["amount"] == "3000"
    assert opened["payload"]["voucher"]["maxClaimableAmount"] == "1000"
    # A second payment waits for the first answer instead of sharing its payload.
    waiting = asyncio.create_task(client.create_payment_payload(req))
    await asyncio.sleep(0)
    assert not waiting.done()
    channel_id = opened["payload"]["voucher"]["channelId"]
    await client.handle_payment_response(opened, response=_accepted(channel_id, 1000))
    assert (
        store.records[_key(client, world, req)].charged_cumulative,
        store.records[_key(client, world, req)].deposit,
    ) == (1000, 3000)
    nxt: Any = await waiting
    assert (nxt["payload"]["type"], nxt["payload"]["voucher"]["maxClaimableAmount"]) == ("voucher", "2000")
    await client.handle_payment_response(nxt, response=_accepted(channel_id, 2000))
    assert store.records[_key(client, world, req)].charged_cumulative == 2000
    bad = await client.create_payment_payload(req)
    with pytest.raises(BatchSettlementError, match="unexpected amount"):
        await client.handle_payment_response(bad, response=_accepted(channel_id, 3000, charged="bad"))


async def test_treats_the_commitment_identifier_as_opaque_and_requires_only_that_it_is_non_empty(world: World) -> None:
    store = MemoryClientChannelStore()
    client = _client(world, channel_store=store, deposit_amount=3000)
    req = requirements(world)
    opened: Any = await client.create_payment_payload(req)
    receipt: Any = {
        "success": True,
        "transaction": "",
        "network": "n",
        "amount": "",
        "extra": {"chargedAmount": "1000", "commitmentId": "receipt-7f3a"},
    }
    await client.handle_payment_response(opened, response=receipt)
    assert store.records[_key(client, world, req)].charged_cumulative == 1000
    nxt = await client.create_payment_payload(req)
    empty: Any = {**receipt, "extra": {"chargedAmount": "1000", "commitmentId": ""}}
    await client.handle_payment_response(nxt, response=empty)
    assert store.records[_key(client, world, req)].charged_cumulative == 1000


async def test_tops_up_an_exhausted_channel_and_commits_only_the_signed_deposit(world: World) -> None:
    client = _client(world, deposit_amount=1500)
    req = requirements(world)
    channel_id = await _seed(client, world, req, cumulative=1000, deposit=1000)
    top_up: Any = await client.create_payment_payload(req)
    assert top_up["payload"]["type"] == "deposit" and top_up["payload"]["deposit"]["amount"] == "1500"
    assert top_up["payload"]["voucher"]["maxClaimableAmount"] == "2000"
    lying = _accepted(channel_id, 2000)
    lying["extra"]["channelState"]["balance"] = "999999"
    await client.handle_payment_response(top_up, response=lying)
    record = await client._store.get(_key(client, world, req))  # type: ignore[union-attr]  # noqa: SLF001
    assert record is not None and (record.charged_cumulative, record.deposit) == (2000, 2500)


async def test_tops_up_by_the_exact_shortfall_when_the_configured_increment_is_smaller(world: World) -> None:
    client = _client(world, deposit_amount=500)
    req = requirements(world)
    await _seed(client, world, req, cumulative=1000, deposit=1000)
    payment: Any = await client.create_payment_payload(req)
    assert payment["payload"]["deposit"]["amount"] == "1000"


async def test_uses_five_request_charges_as_the_default_top_up_target(world: World) -> None:
    client = _client(world)
    req = requirements(world)
    await _seed(client, world, req, cumulative=1000, deposit=1000)
    payment: Any = await client.create_payment_payload(req)
    assert payment["payload"]["deposit"]["amount"] == "5000"


async def test_honors_a_valid_min_deposit_hint_within_the_local_spend_ceiling(world: World) -> None:
    hinted = requirements(world, extra={"minDeposit": "15000"})
    payment: Any = await _client(world).create_payment_payload(hinted)
    assert payment["payload"]["deposit"]["amount"] == "15000"
    capped: Any = await _client(world, max_amount_per_payment=2000).create_payment_payload(hinted)
    assert capped["payload"]["deposit"]["amount"] == "10000"


async def test_falls_back_from_a_malformed_min_deposit_and_validates_the_multiplier(world: World) -> None:
    for hint in ("500", "not-an-amount"):  # below the price, or not an amount: ignored
        payment: Any = await _client(world, deposit_multiplier=3).create_payment_payload(
            requirements(world, extra={"minDeposit": hint})
        )
        assert payment["payload"]["deposit"]["amount"] == "3000"
    with pytest.raises(ConfigurationError, match=">= 3"):
        _client(world, deposit_multiplier=2)


async def test_refuses_a_request_above_max_amount_per_payment(world: World) -> None:
    capped = _client(world, max_amount_per_payment=999)
    with pytest.raises(ValueError, match="amount 1000 exceeds max_amount_per_payment 999"):
        await capped.create_payment_payload(requirements(world))
    # The same cap binds a client-signed fallback from an untrusted operator.
    server = requirements(world, extra={"operator": OPERATOR.pubkey(), "voucherSigner": "server"})
    with pytest.raises(ValueError, match="exceeds max_amount_per_payment"):
        await capped.create_payment_header({"accepts": [server, requirements(world)]})
    at_cap: Any = await _client(world, max_amount_per_payment=1000).create_payment_payload(requirements(world))
    assert at_cap["payload"]["deposit"]["amount"] == "5000"


async def test_treats_empty_and_failed_discovery_scans_as_cache_misses(world: World) -> None:
    client = _client(world, discover_channels=True)
    payment: Any = await client.create_payment_payload(requirements(world))
    assert payment["payload"]["type"] == "deposit"

    async def broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("rpc down")

    world.chain.get_program_accounts = broken  # type: ignore[method-assign]
    payment = await _client(world, discover_channels=True).create_payment_payload(requirements(world))
    assert payment["payload"]["type"] == "deposit"


def _discoverable(world: World, *, settled: int, deposit: int, **overrides: Any) -> str:
    config = world.channel_config(**overrides)
    channel_id = world.channel_id(config)
    data = channel_account(config, world.fee_payer.pubkey(), world.pay_to, deposit=deposit, settled=settled)
    world.chain.program_accounts.append((channel_id, data))
    return channel_id


async def test_adopts_a_discovered_channel_before_allocating_a_voucher(world: World) -> None:
    store = MemoryClientChannelStore()
    client = _client(world, discover_channels=True, channel_store=store)
    _discoverable(world, settled=1000, deposit=5000, openSlot=SLOT - 5)
    newest = _discoverable(world, settled=1000, deposit=5000)
    _discoverable(world, settled=0, deposit=5000, salt="7")  # another salt: not this client's
    world.chain.program_accounts.append((newest, b"\x00" * 256))  # undecodable rows are skipped
    payment: Any = await client.create_payment_payload(requirements(world))
    assert payment["payload"]["type"] == "voucher"
    assert payment["payload"]["voucher"] == sign_voucher(world.payer, newest, 2000)
    assert store.records[_key(client, world, requirements(world))].charged_cumulative == 1000


@pytest.mark.parametrize(
    "differs",
    [
        {"pay_to": str(Pubkey.new_unique())},
        {"payee": str(Pubkey.new_unique())},
        {"status": SEALED},
        {"closure_started_at": 5},
        {"salt": "7"},
        {"token": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"},
        {"payerAuthorizer": OPERATOR.pubkey()},
        {"withdrawDelay": 1800},
    ],
)
async def test_discovery_adopts_only_a_channel_on_these_exact_terms(world: World, differs: dict[str, Any]) -> None:
    fields = {k: differs.pop(k) for k in ("pay_to", "payee", "status", "closure_started_at") if k in differs}
    config = world.channel_config(openSlot=SLOT + 1, **differs)  # newer than the matching channel below
    payee = fields.get("payee", world.fee_payer.pubkey())
    pda, _ = find_channel_pda(
        Pubkey.from_string(config["payer"]),
        Pubkey.from_string(payee),
        Pubkey.from_string(config["token"]),
        Pubkey.from_string(config["payerAuthorizer"]),
        int(config["salt"]),
        config["openSlot"],
    )
    data = channel_account(
        config,
        payee,
        fields.get("pay_to", world.pay_to),
        deposit=5000,
        status=fields.get("status", OPEN),
        closure_started_at=fields.get("closure_started_at", 0),
    )
    world.chain.program_accounts.append((str(pda), data))
    matching = _discoverable(world, settled=0, deposit=5000)
    payment: Any = await _client(world, discover_channels=True).create_payment_payload(requirements(world))
    assert payment["payload"]["voucher"]["channelId"] == matching


async def test_preserves_the_spend_derived_deposit_ceiling_after_channel_discovery(world: World) -> None:
    _discoverable(world, settled=0, deposit=0)
    client = _client(world, discover_channels=True, max_amount_per_payment=1000, deposit_amount=50_000)
    top_up: Any = await client.create_payment_payload(requirements(world))
    assert (top_up["payload"]["type"], top_up["payload"]["deposit"]["amount"]) == ("deposit", "5000")  # 5 x 1000


async def test_restores_confirmed_state_after_a_failed_request(world: World) -> None:
    client = _client(world)
    req = requirements(world)
    await _seed(client, world, req, cumulative=1000, deposit=5000)
    payment = await client.create_payment_payload(req)
    assert await client.handle_payment_response(payment, response={"success": False}) is False  # type: ignore[typeddict-item]
    record = await client._store.get(_key(client, world, req))  # type: ignore[union-attr]  # noqa: SLF001
    assert record is not None and (record.charged_cumulative, record.deposit, record.pending) == (1000, 5000, [])


@pytest.mark.parametrize(
    ("error", "state", "proof", "adopted"),
    [
        ("other", {}, None, False),
        (MISMATCH, None, None, False),  # no state for this channel
        (MISMATCH, {"chargedCumulativeAmount": "1"}, ("payer", 1, 0), False),  # proven, but below what settled
        (MISMATCH, {"chargedCumulativeAmount": "3"}, None, False),  # unproven above it
        (MISMATCH, {"chargedCumulativeAmount": "x"}, None, False),
        (MISMATCH, {"chargedCumulativeAmount": "3"}, ("payer", 2, 0), False),  # proof below the claim
        (MISMATCH, {"chargedCumulativeAmount": "3"}, ("payer", 3, 5), False),  # an expiring proof
        (MISMATCH, {"chargedCumulativeAmount": "3"}, ("stranger", 3, 0), False),
        # The 402 claims more settled than the chain shows: only the chain's watermark counts.
        (MISMATCH, {"chargedCumulativeAmount": "5", "totalClaimed": "5"}, None, False),
        # The chain's settled watermark, whatever the 402's totalClaimed says.
        (MISMATCH, {"totalClaimed": "0"}, None, True),
        (MISMATCH, {"chargedCumulativeAmount": "3"}, ("payer", 3, 0), True),
    ],
)
async def test_rejects_corrective_responses_without_the_required_trustworthy_state(
    world: World, error: str, state: dict[str, str] | None, proof: tuple[str, int, int] | None, adopted: bool
) -> None:
    store = MemoryClientChannelStore()
    client = _client(world, channel_store=store)
    payment: Any = await client.create_payment_payload(requirements(world))
    channel_id = payment["payload"]["voucher"]["channelId"]
    world.put_channel(payment["payload"]["channelConfig"], deposit=10_000, settled=2)
    extra: dict[str, Any] = {}
    if state is not None:
        # balance 0: the deposit must come from the chain, never from the 402.
        base = {"balance": "0", "chargedCumulativeAmount": "2", "totalClaimed": "2", "withdrawRequestedAt": 0}
        extra["channelState"] = {**base, "channelId": channel_id, **state}
    if proof is not None:
        signer, signed, expires_at = proof
        voucher = sign_voucher(world.payer if signer == "payer" else STRANGER, channel_id, signed)
        extra["voucherState"] = {
            "signedMaxClaimable": str(signed),
            "expiresAt": expires_at,
            "signature": voucher["signature"],
        }
    required = {"error": error, "accepts": [requirements(world, extra=extra)]}
    assert await client.handle_payment_response(payment, response=None, payment_required=required) is adopted
    if adopted:
        (record,) = store.records.values()
        assert record.deposit == 10_000


@pytest.mark.parametrize("chain", ["missing", "closing"])
async def test_a_corrective_is_never_adopted_off_an_unusable_channel(world: World, chain: str) -> None:
    client = _client(world)
    payment: Any = await client.create_payment_payload(requirements(world))
    channel_id = payment["payload"]["voucher"]["channelId"]
    if chain == "closing":
        world.put_channel(payment["payload"]["channelConfig"], deposit=10_000, status=CLOSING, closure_started_at=5)
    voucher = sign_voucher(world.payer, channel_id, 3)
    extra = {
        "channelState": {
            "balance": "10000",
            "channelId": channel_id,
            "chargedCumulativeAmount": "3",
            "totalClaimed": "0",
            "withdrawRequestedAt": 0,
        },
        "voucherState": {"signedMaxClaimable": "3", "expiresAt": 0, "signature": voucher["signature"]},
    }
    required = {"error": MISMATCH, "accepts": [requirements(world, extra=extra)]}
    assert await client.handle_payment_response(payment, response=None, payment_required=required) is False


SERVER_VOUCHERS: dict[str, Any] = {
    "missing": lambda channel_id: None,
    "another signer": lambda channel_id: sign_voucher(STRANGER, channel_id, 500),
    "another channel": lambda channel_id: sign_voucher(OPERATOR, str(Pubkey.new_unique()), 500),
    "expiring": lambda channel_id: {**sign_voucher(OPERATOR, channel_id, 500), "expiresAt": 5},
    "malformed amount": lambda channel_id: {**sign_voucher(OPERATOR, channel_id, 500), "maxClaimableAmount": "5e2"},
    "above the request ceiling": lambda channel_id: sign_voucher(OPERATOR, channel_id, 1001),
}


@pytest.mark.parametrize("case", SERVER_VOUCHERS)
async def test_a_server_voucher_must_be_the_operators_and_within_the_request_ceiling(world: World, case: str) -> None:
    store = MemoryClientChannelStore()
    trust = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),))
    client = _client(world, channel_store=store, deposit_amount=3000, server_signed_channels_policy=trust)
    req = requirements(world, extra={"operator": OPERATOR.pubkey(), "voucherSigner": "server"})
    opened: Any = await client.create_payment_payload(req)
    channel_id = opened["payload"]["authorization"]["channelId"]
    extra = {"commitmentId": "c", "voucher": SERVER_VOUCHERS[case](channel_id)}
    response: Any = {"success": True, "transaction": "", "network": "n", "amount": "", "extra": extra}
    if case == "above the request ceiling":
        assert await client.handle_payment_response(opened, response=response) is False
    else:
        with pytest.raises(BatchSettlementError):
            await client.handle_payment_response(opened, response=response)
    # Nothing confirmed: the open is unpaid, but it may still land, so the
    # escrow it signed is remembered against the trust grant.
    (record,) = store.records.values()
    assert (record.has_confirmed_state, record.pending, record.signed_deposit) == (False, [], 3000)


async def test_hydrates_confirmed_and_pending_records_and_ignores_unrelated_responses(world: World) -> None:
    store = MemoryClientChannelStore()
    first = _client(world, channel_store=store)
    req = requirements(world)
    channel_id = await _seed(first, world, req, cumulative=1000, deposit=5000, store=store)
    pending = await first.create_payment_payload(req)
    # A fresh process sees the same pending allocation, and its response lands.
    second = _client(world, channel_store=store)
    await second.handle_payment_response(pending, response=_accepted(channel_id, 2000))
    assert store.records[_key(first, world, req)].charged_cumulative == 2000
    unrelated: Any = {
        "x402Version": 2,
        "accepted": req,
        "payload": world.voucher_payload(9000, world.channel_config(salt="9")),
    }
    assert await second.handle_payment_response(unrelated, response={"success": False}) is False  # type: ignore[typeddict-item]


async def test_validates_client_terms_and_configuration_boundaries(world: World) -> None:
    for overrides in (
        {"extra": {"paymentFlow": "upfront"}},
        {"extra": {"feePayer": ""}},
        {"extra": {"withdrawDelay": 899}},
        {"extra": {"tokenProgram": world.payer.pubkey()}},
        {"extra": {"receiverAuthorizer": 1}},
        {"extra": {"memo": 1}},
        {"extra": {"voucherSigner": "other"}},
        {"extra": {"voucherSigner": "server"}},
        {"extra": {"operator": world.fee_payer.pubkey()}},
        {"extra": {"feePayer": world.payer.pubkey()}},  # the payer may not be the sponsor
    ):
        with pytest.raises(BatchSettlementError):
            await _client(world).create_payment_payload(requirements(world, **overrides))
    world.chain.accounts[MINT] = (b"\x00" * 82, TOKEN_2022_PROGRAM)
    with pytest.raises(BatchSettlementError, match="does not own"):
        await _client(world).create_payment_payload(requirements(world))
    world.chain.accounts[MINT] = (b"\x00" * 82, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    with pytest.raises(ConfigurationError):
        _client(world, salt=2**64)
    with pytest.raises(ValueError, match="must cover"):
        await _client(world, deposit_amount=999).create_payment_payload(requirements(world))
    with pytest.raises(ValueError, match="must be positive"):
        await _client(world).create_payment_payload(requirements(world, amount="0"))
    with pytest.raises(ConfigurationError):
        BatchSettlementClient(world.payer)


async def test_builds_a_refund_from_a_cached_channel_and_rejects_a_missing_one(world: World) -> None:
    client = _client(world)
    req = requirements(world)
    await _seed(client, world, req, cumulative=1000, deposit=5000)
    refund: Any = await client.create_refund_payload(req)
    assert refund["x402Version"] == 2 and refund["payload"]["type"] == "refund"
    # The Memo is always there: the Rust server requires one on request_close.
    assert len(_memo(_tx(refund, "refund"))) == 32
    with pytest.raises(ValueError, match="no batch-settlement channel"):
        await _client(world).create_refund_payload(req)


# -- against the server policy (Rust client tests) ----------------------------------------------------


def _engine(world: World, **settings: Any) -> X402BatchSettlement:
    return X402BatchSettlement(
        world.config,
        settings=BatchSettlementConfig(**settings),
        rpc=world.chain,  # type: ignore[arg-type]
        recent_state_provider=lambda: (BLOCKHASH, SLOT),
        clock=lambda: NOW,
    )


def _request(payment: Any) -> Any:
    return {"headers": {"payment-signature": base64.b64encode(json.dumps(payment).encode()).decode()}}


async def _serve(engine: X402BatchSettlement, world: World, payment: Any, actual: int | None = None) -> Any:
    verified = await engine.verify_and_reserve(world.gate, _request(payment))
    assert isinstance(verified, VerifiedBatchRequest)
    return await engine.commit(verified, actual)


async def test_terms_reject_a_token_program_the_mint_does_not_own(world: World) -> None:
    world.chain.accounts[MINT] = (b"\x00" * 82, TOKEN_2022_PROGRAM)
    with pytest.raises(BatchSettlementError) as exc:
        await _client(world).create_payment_payload(requirements(world))
    assert exc.value.code == errors.INVALID_TOKEN_PROGRAM


async def test_terms_supply_a_hex_nonce_when_the_seller_declares_no_memo(world: World) -> None:
    nonce = _memo(_tx(await _client(world).create_payment_payload(requirements(world))))
    assert len(nonce) == 32 and all(c in b"0123456789abcdef" for c in nonce)
    declared = _memo(_tx(await _client(world).create_payment_payload(requirements(world, extra={"memo": "invoice-9"}))))
    assert declared == b"invoice-9"


async def test_deposit_builds_a_sponsored_open_the_server_policy_accepts(world: World) -> None:
    engine = _engine(world)
    accept = engine.accepts_entries(world.gate, {})[0]
    client = _client(world)
    payment: Any = await client.create_payment_payload(cast(Any, accept))
    assert payment["payload"]["deposit"]["amount"] == str(10 * PRICE)  # the server's minDeposit hint
    world.lands_as_channel(deposit=10 * PRICE)
    response = await _serve(engine, world, payment)
    assert await client.handle_payment_response(payment, response=response) is False
    nxt: Any = await client.create_payment_payload(cast(Any, accept))
    assert nxt["payload"]["voucher"]["maxClaimableAmount"] == str(2 * PRICE)


async def test_top_up_and_refund_pass_the_sponsor_policy(world: World) -> None:
    engine = _engine(world)
    accept = cast(Any, engine.accepts_entries(world.gate, {})[0])
    client = _client(world, deposit_amount=PRICE)
    opened: Any = await client.create_payment_payload(accept)
    world.lands_as_channel(deposit=PRICE)
    await client.handle_payment_response(opened, response=await _serve(engine, world, opened))
    top_up: Any = await client.create_payment_payload(accept)
    assert top_up["payload"]["type"] == "deposit"
    world.lands_as_channel(deposit=2 * PRICE)
    response = await _serve(engine, world, top_up)
    await client.handle_payment_response(top_up, response=response)
    refund: Any = await client.create_refund_payload(accept)
    expected = TransactionExpectations(
        fee_payer=world.fee_payer.pubkey(),
        config=refund["payload"]["channelConfig"],
        channel_id=world.channel_id(),
        token_program=accept["extra"]["tokenProgram"],
        receiver=world.pay_to,
    )
    assert validate_request_close(refund["payload"]["transaction"], expected).payer == world.payer.pubkey()
    world.lands_as_channel(deposit=2 * PRICE, settled=2 * PRICE)
    world.lands_as_channel(deposit=2 * PRICE, settled=2 * PRICE, status=CLOSING, closure_started_at=int(NOW))
    settled = await engine.verify_and_reserve(world.gate, _request(refund))
    assert not isinstance(settled, VerifiedBatchRequest) and settled["success"]


async def test_the_watermark_advances_only_on_a_matching_payment_response(world: World) -> None:
    engine = _engine(world)
    accept = cast(Any, engine.accepts_entries(world.gate, {})[0])
    client = _client(world)
    opened: Any = await client.create_payment_payload(accept)
    world.lands_as_channel(deposit=10 * PRICE)
    response: Any = await _serve(engine, world, opened)
    forged: Any = {
        **response,
        "extra": {
            **response["extra"],
            "channelState": {**response["extra"]["channelState"], "chargedCumulativeAmount": "1"},
        },
    }
    assert await client.handle_payment_response(opened, response=forged) is False
    # Not advanced: the next payment is still the first voucher, on the open.
    retried: Any = await client.create_payment_payload(accept)
    assert retried["payload"]["type"] == "deposit"


async def test_corrective_state_is_adopted_only_with_a_self_signed_proof(world: World) -> None:
    engine = _engine(world)
    accept = cast(Any, engine.accepts_entries(world.gate, {})[0])
    client = _client(world)
    opened: Any = await client.create_payment_payload(accept)
    world.lands_as_channel(deposit=10 * PRICE)
    await client.handle_payment_response(opened, response=await _serve(engine, world, opened))
    config, channel_id = opened["payload"]["channelConfig"], opened["payload"]["voucher"]["channelId"]
    for cumulative in (2 * PRICE, 3 * PRICE):  # the same wallet paid from another process
        voucher = sign_voucher(world.payer, channel_id, cumulative)
        await _serve(
            engine, world, {**opened, "payload": {"type": "voucher", "channelConfig": config, "voucher": voucher}}
        )
    stale: Any = await client.create_payment_payload(accept)
    with pytest.raises(CorrectiveRequired) as exc:
        await engine.verify_and_reserve(world.gate, _request(stale))
    corrective = cast(Any, exc.value.accepts[0])
    forged = json.loads(json.dumps(corrective))
    forged["extra"]["voucherState"]["signature"] = sign_voucher(OPERATOR, channel_id, 3 * PRICE)["signature"]
    required = {"error": exc.value.code, "accepts": [forged]}
    assert await client.handle_payment_response(stale, response=None, payment_required=required) is False
    stale = await client.create_payment_payload(accept)
    assert stale["payload"]["voucher"]["maxClaimableAmount"] == str(2 * PRICE)  # nothing adopted
    required = {"error": exc.value.code, "accepts": [corrective]}
    assert await client.handle_payment_response(stale, response=None, payment_required=required) is True
    resynced: Any = await client.create_payment_payload(accept)
    assert resynced["payload"]["voucher"]["maxClaimableAmount"] == str(4 * PRICE)
    assert (await _serve(engine, world, resynced))["success"]


async def test_payment_header_round_trips_through_the_server_envelope(world: World) -> None:
    payment: Any = await _client(world).create_payment_payload(requirements(world))
    parsed = parse_payment_payload(payment)
    assert parsed["payload"] == payment["payload"] and parsed["accepted"]["amount"] == "1000"
    with pytest.raises(BatchSettlementError, match="no batch-settlement accept"):
        await _client(world).create_payment_header({"accepts": [{**requirements(world), "scheme": "exact"}]})


async def test_open_reads_slot_and_blockhash_from_rpc_and_binds_the_receiver_authorizer(world: World) -> None:
    authorizer = str(Pubkey.new_unique())
    req = requirements(world, extra={"receiverAuthorizer": authorizer})
    del req["extra"]["recentSlot"], req["extra"]["recentBlockhash"]
    payment: Any = await _client(world).create_payment_payload(req)
    config = payment["payload"]["channelConfig"]
    assert (config["openSlot"], config["receiverAuthorizer"]) == (world.chain.slot, authorizer)
    assert str(_tx(payment).message.recent_blockhash) == BLOCKHASH


async def test_a_trusted_operator_meters_and_the_client_checks_its_voucher(world: World) -> None:
    engine = _engine(world, operator=OPERATOR)
    server = cast(Any, engine.accepts_entries(world.gate, {})[1])
    trust = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),))
    client = _client(world, server_signed_channels_policy=trust)
    payment, paid = await client.create_payment_header(
        {"x402Version": 2, "accepts": engine.accepts_entries(world.gate, {})}
    )
    assert paid["extra"].get("voucherSigner") == "server"  # the trusted metered accept is preferred
    world.lands_as_channel(
        world.channel_config(payerAuthorizer=OPERATOR.pubkey(), voucherSigner="server"), deposit=3 * PRICE
    )
    response = await _serve(engine, world, payment, actual=4_000)
    assert await client.handle_payment_response(payment, response=response) is False
    metered: Any = await client.create_payment_payload(server)
    assert metered["payload"]["type"] == "authorization"


# -- one payment per channel at a time; lost responses; closing channels -------------------------


async def test_a_lost_response_is_confirmed_by_the_servers_proof_of_the_same_voucher(world: World) -> None:
    engine = _engine(world)
    accept = cast(Any, engine.accepts_entries(world.gate, {})[0])
    client = _client(world)
    opened: Any = await client.create_payment_payload(accept)
    world.lands_as_channel(deposit=10 * PRICE)
    await client.handle_payment_response(opened, response=await _serve(engine, world, opened))
    served: Any = await client.create_payment_payload(accept)
    await _serve(engine, world, served)  # charged, but the response never arrives
    await client.handle_payment_response(served, response=None)
    again: Any = await client.create_payment_payload(accept)
    assert again["payload"]["voucher"] == served["payload"]["voucher"]  # re-signed: the identical voucher
    with pytest.raises(CorrectiveRequired) as exc:
        await engine.verify_and_reserve(world.gate, _request(again))
    required = {"error": exc.value.code, "accepts": exc.value.accepts}
    assert await client.handle_payment_response(again, response=None, payment_required=required) is True
    nxt: Any = await client.create_payment_payload(accept)
    assert nxt["payload"]["voucher"]["maxClaimableAmount"] == str(3 * PRICE)
    assert (await _serve(engine, world, nxt))["success"]


@pytest.mark.parametrize("forged", ["signature", "amount"])
async def test_a_duplicate_without_this_vouchers_proof_confirms_nothing(world: World, forged: str) -> None:
    client = _client(world)
    req = requirements(world)
    await _seed(client, world, req, cumulative=1000, deposit=5000)
    payment: Any = await client.create_payment_payload(req)
    channel_id = payment["payload"]["voucher"]["channelId"]
    sent = payment["payload"]["voucher"]
    # "duplicate_settlement" also means busy or expired: only this voucher's own record counts.
    signature = sign_voucher(world.payer, channel_id, 1000)["signature"] if forged == "signature" else sent["signature"]
    signed = "1000" if forged == "amount" else sent["maxClaimableAmount"]
    state = {"balance": "5000", "channelId": channel_id, "chargedCumulativeAmount": "1000", "totalClaimed": "0"}
    proof = {"signedMaxClaimable": signed, "expiresAt": 0, "signature": signature}
    extra = {"channelState": {**state, "withdrawRequestedAt": 0}, "voucherState": proof}
    required = {"error": errors.DUPLICATE_SETTLEMENT, "accepts": [requirements(world, extra=extra)]}
    assert await client.handle_payment_response(payment, response=None, payment_required=required) is False
    nxt: Any = await client.create_payment_payload(req)
    assert nxt["payload"]["voucher"]["maxClaimableAmount"] == "2000"  # still at the confirmed 1000


@pytest.mark.parametrize("lost", ["expired", "no_answer", "forged_voucher", "out_of_bound", "no_commitment"])
async def test_an_unanswered_server_proof_becomes_an_allowance_for_the_next_voucher(world: World, lost: str) -> None:
    clock = [NOW]
    store = MemoryClientChannelStore()
    trust = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),))
    client = BatchSettlementClient(
        world.payer,
        rpc=world.chain,  # type: ignore[arg-type]
        discover_channels=False,
        channel_store=store,
        server_signed_channels_policy=trust,
        deposit_amount=5000,
        clock=lambda: clock[0],
    )
    req = requirements(world, extra={"operator": OPERATOR.pubkey(), "voucherSigner": "server"})
    opened: Any = await client.create_payment_payload(req)
    channel_id = opened["payload"]["authorization"]["channelId"]

    def served(cumulative: int, signer: LocalSigner = OPERATOR) -> Any:
        voucher = sign_voucher(signer, channel_id, cumulative)
        extra = {"commitmentId": f"{channel_id}:{cumulative}", "voucher": voucher}
        return {"success": True, "transaction": "", "network": "n", "amount": "", "extra": extra}

    await client.handle_payment_response(opened, response=served(1000))
    second: Any = await client.create_payment_payload(req)
    # The operator may have charged it, but no valid answer says so.
    if lost == "expired":
        clock[0] += 301  # past the proof's expiry
    elif lost == "no_answer":  # a proxy 504 without PAYMENT-RESPONSE, a reset connection
        await client.handle_payment_response(second, response=None)
    elif lost == "forged_voucher":
        with pytest.raises(BatchSettlementError):
            await client.handle_payment_response(second, response=served(2000, STRANGER))
    else:
        answer = served(9000) if lost == "out_of_bound" else served(2000)
        if lost == "no_commitment":
            del answer["extra"]["commitmentId"]
        assert await client.handle_payment_response(second, response=answer) is False
    third: Any = await client.create_payment_payload(req)
    (record,) = store.records.values()
    assert record.unobserved == 1000
    # The operator's voucher includes the unanswered request: 1000 + 1000 + 1000.
    await client.handle_payment_response(third, response=served(3000))
    (record,) = store.records.values()
    assert (record.charged_cumulative, record.unobserved) == (3000, 0)


async def test_a_lost_answer_at_deposit_exhaustion_tops_up_instead_of_stalling(world: World) -> None:
    engine = _engine(world, operator=OPERATOR)
    accept = cast(Any, engine.accepts_entries(world.gate, {})[1])
    trust = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),))
    client = _client(world, server_signed_channels_policy=trust)
    config = world.channel_config(payerAuthorizer=OPERATOR.pubkey(), voucherSigner="server")
    opened: Any = await client.create_payment_payload(accept)
    world.lands_as_channel(config, deposit=3 * PRICE)
    await client.handle_payment_response(opened, response=await _serve(engine, world, opened, actual=PRICE))
    second: Any = await client.create_payment_payload(accept)
    await client.handle_payment_response(second, response=await _serve(engine, world, second, actual=PRICE))
    lost: Any = await client.create_payment_payload(accept)
    await _serve(engine, world, lost, actual=PRICE)  # metered to the whole escrow; the answer is lost
    await client.handle_payment_response(lost, response=None)
    # 2 x PRICE confirmed plus the unanswered ceiling is the escrow: without
    # counting it the server would refuse with cumulative_exceeds_deposit.
    nxt: Any = await client.create_payment_payload(accept)
    assert nxt["payload"]["type"] == "deposit"
    world.lands_as_channel(config, deposit=3 * PRICE + int(nxt["payload"]["deposit"]["amount"]))
    assert await client.handle_payment_response(nxt, response=await _serve(engine, world, nxt, actual=PRICE)) is False
    paid: Any = await client.create_payment_payload(accept)
    assert paid["payload"]["type"] == "authorization"  # resynced at 4 x PRICE, with room again


async def test_concurrent_first_payments_fund_one_channel(world: World) -> None:
    client = _client(world)
    req = requirements(world)
    first = asyncio.create_task(client.create_payment_payload(req))
    second = asyncio.create_task(client.create_payment_payload(req))
    opened: Any = await first
    await asyncio.sleep(0)
    assert not second.done() and opened["payload"]["type"] == "deposit"
    channel_id = opened["payload"]["voucher"]["channelId"]
    await client.handle_payment_response(opened, response=_accepted(channel_id, 1000))
    paid: Any = await second
    assert (paid["payload"]["type"], paid["payload"]["voucher"]["channelId"]) == ("voucher", channel_id)


async def test_a_closing_channel_is_forgotten(world: World) -> None:
    store = MemoryClientChannelStore()
    client = _client(world, channel_store=store)
    req = requirements(world)
    await _seed(client, world, req, cumulative=1000, deposit=5000, store=store)
    payment: Any = await client.create_payment_payload(req)
    required = {"error": errors.INVALID_CHANNEL_CLOSING, "accepts": [req]}
    assert await client.handle_payment_response(payment, response=None, payment_required=required) is False
    assert store.records == {}
    fresh: Any = await client.create_payment_payload(req)
    assert fresh["payload"]["type"] == "deposit"


async def test_a_top_up_needing_more_than_the_spend_ceiling_is_refused(world: World) -> None:
    # Adopted state above the local escrow (e.g. a top-up that never landed).
    client = _client(world, max_amount_per_payment=1000)
    req = requirements(world)
    await _seed(client, world, req, cumulative=5000, deposit=0)
    with pytest.raises(ValueError, match="Required deposit 6000 exceeds"):
        await client.create_payment_payload(req)
