"""Server-signed trust policy for the x402 ``batch-settlement`` client.

One test per case of the x402 PR #23 ``batch.client.trust.test.ts``, in order.
"""

from __future__ import annotations

from typing import Any

import pytest
from solders.keypair import Keypair

from solana_pay_kit._paycore.paymentchannels import PAYMENT_CHANNELS_PROGRAM_ID
from solana_pay_kit.errors import ConfigurationError
from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.signatures import sign_voucher
from solana_pay_kit.protocols.x402.client.batch_settlement import (
    BatchSettlementClient,
    MemoryClientChannelStore,
    ServerSignedChannelsPolicy,
    ServerSignedGrant,
    ServerSignedTrust,
    UntrustedOperatorError,
    is_server_signed_accept,
)
from solana_pay_kit.signer import LocalSigner
from tests.batch_chain import BLOCKHASH, MINT, SLOT, FakeChain, channel_account, make_world

USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
PAYER = LocalSigner.from_keypair(Keypair.from_seed(bytes([1] * 32)))
FEE_PAYER = str(Keypair.from_seed(bytes([2] * 32)).pubkey())
OPERATOR = LocalSigner.from_keypair(Keypair.from_seed(bytes([4] * 32)))
OTHER = str(Keypair.from_seed(bytes([5] * 32)).pubkey())
PAY_TO = str(Keypair.from_seed(bytes([3] * 32)).pubkey())


def client_accept(**overrides: Any) -> dict[str, Any]:
    accept: dict[str, Any] = {
        "scheme": "batch-settlement",
        "network": NETWORK,
        "amount": "1000",
        "asset": MINT,
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 300,
        "extra": {
            "feePayer": FEE_PAYER,
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "withdrawDelay": 900,
            "recentBlockhash": BLOCKHASH,
            "recentSlot": SLOT,
        },
    }
    accept.update(overrides)
    return accept


def server_accept(
    operator: str = OPERATOR.pubkey(), extra: dict[str, Any] | None = None, **overrides: Any
) -> dict[str, Any]:
    accept = client_accept(**overrides)
    accept["extra"] = {**accept["extra"], "operator": operator, "voucherSigner": "server", **(extra or {})}
    return accept


def evm_accept() -> dict[str, Any]:
    return {
        "scheme": "batch-settlement",
        "network": "eip155:84532",
        "amount": "1000",
        "asset": "0x036C",
        "payTo": "0x1",
        "extra": {},
    }


def policy(**kwargs: Any) -> ServerSignedTrust:
    return ServerSignedTrust(ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),), **kwargs))


@pytest.fixture
def chain(monkeypatch: pytest.MonkeyPatch) -> FakeChain:
    return make_world(monkeypatch).chain


def _client(chain: FakeChain, **kwargs: Any) -> BatchSettlementClient:
    kwargs.setdefault("discover_channels", False)
    return BatchSettlementClient(PAYER, rpc=chain, **kwargs)  # type: ignore[arg-type]


# -- the policy ------------------------------------------------------------------------------


def test_rejects_malformed_policies() -> None:
    with pytest.raises(ConfigurationError, match="non-empty"):
        ServerSignedTrust(ServerSignedChannelsPolicy(allowed_operators=("",)))
    with pytest.raises(ConfigurationError, match="positive"):
        policy(max_deposit="$0")
    with pytest.raises(ConfigurationError, match="integer atomic amount, not a dollar value"):
        policy(allowed_assets=({"asset": USDC_DEVNET, "maxDeposit": "$1", "network": NETWORK},))
    assert is_server_signed_accept(server_accept()) and not is_server_signed_accept(client_accept())


def test_grants_only_listed_operators_and_refuses_everything_without_a_policy() -> None:
    with pytest.raises(UntrustedOperatorError):
        ServerSignedTrust(None).grant_for(server_accept())
    with pytest.raises(UntrustedOperatorError, match=f"{OTHER}.*allowed_operators"):
        policy().grant_for(server_accept(OTHER))
    with pytest.raises(UntrustedOperatorError):
        policy().grant_for(client_accept())


def test_resolves_the_escrow_cap_like_the_core_spend_controls() -> None:
    assert policy().grant_for(server_accept()) == ServerSignedGrant(OPERATOR.pubkey(), 1_000_000)  # default $1
    assert policy(max_deposit="$0.05").grant_for(server_accept()) == ServerSignedGrant(OPERATOR.pubkey(), 50_000)
    assert policy(max_deposit="$0.0000019").grant_for(server_accept()).max_deposit == 1  # floored, never rounded up
    assert policy(max_deposit=False).grant_for(server_accept()) == ServerSignedGrant(OPERATOR.pubkey(), None)
    exotic = server_accept(asset=FEE_PAYER)
    with pytest.raises(UntrustedOperatorError, match="not a known stablecoin.*allowed_assets"):
        policy().grant_for(exotic)
    capped = policy(allowed_assets=({"asset": FEE_PAYER, "maxDeposit": "777", "network": "solana:*"},))
    assert capped.grant_for(exotic) == ServerSignedGrant(OPERATOR.pubkey(), 777)
    uncapped = policy(allowed_assets=({"asset": FEE_PAYER, "network": NETWORK},))
    assert uncapped.grant_for(exotic) == ServerSignedGrant(OPERATOR.pubkey(), None)
    symbol = policy(allowed_assets=({"asset": "usdc", "maxDeposit": "42", "network": NETWORK},))
    assert symbol.grant_for(server_accept()) == ServerSignedGrant(OPERATOR.pubkey(), 42)
    # A mint is never matched case-insensitively.
    lowered = policy(allowed_assets=({"asset": FEE_PAYER.lower(), "maxDeposit": "1", "network": NETWORK},))
    with pytest.raises(UntrustedOperatorError):
        lowered.grant_for(exotic)


def test_filters_accepts_dropping_untrusted_server_signed_ones_and_preferring_trusted_ones() -> None:
    trust = policy()
    evm, client, trusted, untrusted = evm_accept(), client_accept(), server_accept(), server_accept(OTHER)
    assert trust.filter_accepts([untrusted, client, evm]) == [client, evm]
    assert trust.filter_accepts([evm, client, trusted]) == [evm, trusted, client]
    assert trust.filter_accepts([client, evm]) == [client, evm]
    with pytest.raises(UntrustedOperatorError, match=f"{OTHER}.*allowed_operators"):
        trust.filter_accepts([untrusted])


# -- the client ----------------------------------------------------------------------------------


async def test_never_opens_a_server_signed_channel_without_a_grant(chain: FakeChain) -> None:
    with pytest.raises(UntrustedOperatorError):
        await _client(chain).create_payment_payload(server_accept())
    other = _client(chain, server_signed_channels_policy=ServerSignedChannelsPolicy(allowed_operators=(OTHER,)))
    with pytest.raises(UntrustedOperatorError, match="Trust it explicitly"):
        await other.create_payment_payload(server_accept())


async def test_opens_a_server_signed_channel_for_a_listed_operator(chain: FakeChain) -> None:
    trusted = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),))
    payment: Any = await _client(chain, server_signed_channels_policy=trusted).create_payment_payload(server_accept())
    assert payment["payload"]["type"] == "deposit" and "voucher" not in payment["payload"]
    assert payment["payload"]["channelConfig"]["payerAuthorizer"] == OPERATOR.pubkey()
    assert payment["payload"]["channelConfig"]["voucherSigner"] == "server"


async def test_falls_back_to_the_client_signed_accept(chain: FakeChain) -> None:
    client = _client(chain, max_amount_per_payment=1000)
    server, fallback = server_accept(), client_accept()
    payment: Any
    payment, paid = await client.create_payment_header({"x402Version": 2, "accepts": [server, fallback]})
    assert paid is fallback and payment["accepted"] == fallback
    assert payment["payload"]["channelConfig"]["payerAuthorizer"] == PAYER.pubkey()
    # The client-signed twin keeps the spend ceiling: 5 x 1000.
    assert payment["payload"]["deposit"]["amount"] == "5000"
    # No fallback onto another server-signed accept, a dearer one, another asset, or nothing.
    other_asset = client_accept(asset="Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB")
    for accepts in (
        [server],
        [server, server_accept(OTHER)],
        [server, client_accept(amount="2000")],
        [server, other_asset],
    ):
        with pytest.raises(UntrustedOperatorError):
            await _client(chain).create_payment_header({"x402Version": 2, "accepts": accepts})
    # Other failures are not turned into a fallback.
    chain.accounts.pop(MINT)
    with pytest.raises(Exception) as exc:
        await _client(chain).create_payment_header({"x402Version": 2, "accepts": [server, fallback]})
    assert getattr(exc.value, "code", None) == errors.INVALID_TOKEN_PROGRAM


async def test_caps_the_escrow_at_the_grant_ignoring_larger_hints_and_fixed_deposits(chain: FakeChain) -> None:
    trust = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),), max_deposit="$0.0025")
    hinted = server_accept(extra={"minDeposit": "100000"})
    payment: Any = await _client(chain, server_signed_channels_policy=trust).create_payment_payload(hinted)
    assert payment["payload"]["deposit"]["amount"] == "2500"
    fixed: Any = await _client(
        chain, server_signed_channels_policy=trust, deposit_amount=50_000
    ).create_payment_payload(hinted)
    assert fixed["payload"]["deposit"]["amount"] == "2500"
    with pytest.raises(ValueError, match="exceeds the remaining trust max_deposit"):
        await _client(chain, server_signed_channels_policy=trust).create_payment_payload(server_accept(amount="3000"))


def _server_response(channel_id: str, cumulative: int) -> Any:
    return {
        "success": True,
        "transaction": "",
        "network": NETWORK,
        "amount": "",
        "extra": {
            "channelState": {"chargedCumulativeAmount": str(cumulative)},
            "commitmentId": f"{channel_id}:{cumulative}",
            "voucher": sign_voucher(OPERATOR, channel_id, cumulative),
        },
    }


async def test_refuses_a_top_up_that_would_push_the_escrow_past_the_grant(chain: FakeChain) -> None:
    trust = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),), max_deposit="$0.0025")
    client = _client(chain, server_signed_channels_policy=trust)
    accept = server_accept()
    opened: Any = await client.create_payment_payload(accept)
    channel_id = opened["payload"]["authorization"]["channelId"]
    await client.handle_payment_response(opened, response=_server_response(channel_id, 1000))
    second = await client.create_payment_payload(accept)
    await client.handle_payment_response(second, response=_server_response(channel_id, 2000))
    # 2000 charged of 2500 escrowed: the next 1000 ceiling needs 500 more.
    with pytest.raises(ValueError, match="2500 total, 2500 already escrowed"):
        await client.create_payment_payload(accept)


@pytest.mark.parametrize(("corrective", "adopted"), [(2000, True), (5000, False)])
async def test_adopts_a_corrective_only_up_to_what_this_client_authorized(
    chain: FakeChain, corrective: int, adopted: bool
) -> None:
    trust = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),))
    client = _client(chain, server_signed_channels_policy=trust, deposit_amount=10_000)
    accept = server_accept()
    opened: Any = await client.create_payment_payload(accept)
    channel_id = opened["payload"]["authorization"]["channelId"]
    await client.handle_payment_response(opened, response=_server_response(channel_id, 1000))
    config = opened["payload"]["channelConfig"]
    chain.accounts[channel_id] = (
        channel_account(config, FEE_PAYER, PAY_TO, deposit=10_000),
        PAYMENT_CHANNELS_PROGRAM_ID,
    )
    nxt = await client.create_payment_payload(accept)
    proof = sign_voucher(OPERATOR, channel_id, corrective)
    required = {
        "x402Version": 2,
        "error": errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH,
        "accepts": [
            {
                **accept,
                "extra": {
                    **accept["extra"],
                    "channelState": {
                        "balance": "10000",
                        "channelId": channel_id,
                        "chargedCumulativeAmount": str(corrective),
                        "totalClaimed": "0",
                        "withdrawRequestedAt": 0,
                    },
                    "voucherState": {
                        "expiresAt": 0,
                        "signature": proof["signature"],
                        "signedMaxClaimable": str(corrective),
                    },
                },
            }
        ],
    }
    failed: Any = {"success": False, "errorReason": errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH}
    # Confirmed 1000 plus this request's 1000 ceiling is the most the operator
    # can legitimately claim; its own signature proves nothing beyond that.
    assert await client.handle_payment_response(nxt, response=failed, payment_required=required) is adopted


# -- the grant is spent by every escrow amount this client signed (fails closed) --------------


def _grant(chain: FakeChain, max_deposit: str, **kwargs: Any) -> BatchSettlementClient:
    trust = ServerSignedChannelsPolicy(allowed_operators=(OPERATOR.pubkey(),), max_deposit=max_deposit)
    return _client(chain, server_signed_channels_policy=trust, **kwargs)


async def test_a_corrective_cannot_lower_the_escrow_counted_against_the_grant(chain: FakeChain) -> None:
    client = _grant(chain, "$0.0025")
    accept = server_accept()
    opened: Any = await client.create_payment_payload(accept)
    channel_id = opened["payload"]["authorization"]["channelId"]
    await client.handle_payment_response(opened, response=_server_response(channel_id, 1000))
    config = opened["payload"]["channelConfig"]
    chain.accounts[channel_id] = (
        channel_account(config, FEE_PAYER, PAY_TO, deposit=2500, settled=1000),
        PAYMENT_CHANNELS_PROGRAM_ID,
    )
    nxt = await client.create_payment_payload(accept)
    state = {"balance": "0", "channelId": channel_id, "chargedCumulativeAmount": "1000", "totalClaimed": "1000"}
    extra = {**accept["extra"], "channelState": {**state, "withdrawRequestedAt": 0}}
    required = {"error": errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH, "accepts": [{**accept, "extra": extra}]}
    assert await client.handle_payment_response(nxt, response=None, payment_required=required) is True
    second = await client.create_payment_payload(accept)
    await client.handle_payment_response(second, response=_server_response(channel_id, 2000))
    # A "balance: 0" in the 402 would have made room for another 2500.
    with pytest.raises(ValueError, match="2500 total, 2500 already escrowed"):
        await client.create_payment_payload(accept)


async def test_a_top_up_with_a_lost_response_still_counts_against_the_grant(chain: FakeChain) -> None:
    client = _grant(chain, "$0.003", deposit_amount=2000)
    accept = server_accept()
    opened: Any = await client.create_payment_payload(accept)
    channel_id = opened["payload"]["authorization"]["channelId"]
    await client.handle_payment_response(opened, response=_server_response(channel_id, 1000))
    second = await client.create_payment_payload(accept)
    await client.handle_payment_response(second, response=_server_response(channel_id, 2000))
    top_up: Any = await client.create_payment_payload(accept)
    assert top_up["payload"]["deposit"]["amount"] == "1000"
    # Broadcast, then a 5xx: the top-up may have landed.
    await client.handle_payment_response(top_up, response=None)
    with pytest.raises(ValueError, match="3000 total, 3000 already escrowed"):
        await client.create_payment_payload(accept)


async def test_a_discovered_channel_counts_its_chain_deposit_against_the_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The default setup after a restart (no client store): the channel is rediscovered on chain.
    world = make_world(monkeypatch)
    client = _grant(world.chain, "$0.003", discover_channels=True)
    config = world.channel_config(payerAuthorizer=OPERATOR.pubkey())
    data = channel_account(config, FEE_PAYER, PAY_TO, deposit=2000, settled=2000)
    world.chain.program_accounts.append((world.channel_id(config), data))
    top_up: Any = await client.create_payment_payload(server_accept())
    assert top_up["payload"]["deposit"]["amount"] == "1000"
    # Broadcast, then a 5xx: the top-up may have landed (2000 + 1000 = the whole grant).
    await client.handle_payment_response(top_up, response=None)
    with pytest.raises(ValueError, match="3000 total, 3000 already escrowed"):
        await client.create_payment_payload(server_accept())


async def test_an_unanswered_ceiling_cannot_push_the_escrow_past_the_grant(chain: FakeChain) -> None:
    client = _grant(chain, "$0.0025", deposit_amount=2000)
    accept = server_accept()
    opened: Any = await client.create_payment_payload(accept)
    channel_id = opened["payload"]["authorization"]["channelId"]
    await client.handle_payment_response(opened, response=_server_response(channel_id, 1000))
    lost = await client.create_payment_payload(accept)
    await client.handle_payment_response(lost, response=None)  # the operator may have charged 2000
    # The next 1000 needs 1000 more escrow; the grant has 500 left.
    with pytest.raises(ValueError, match="Required deposit 1000 exceeds the remaining trust max_deposit"):
        await client.create_payment_payload(accept)


@pytest.mark.parametrize("restart", [False, True])
async def test_a_failed_open_blocks_a_second_one_while_it_may_still_land(chain: FakeChain, restart: bool) -> None:
    store = MemoryClientChannelStore() if restart else None
    client = _grant(chain, "$0.0025", channel_store=store)
    accept = server_accept()
    opened: Any = await client.create_payment_payload(accept)
    channel_id = opened["payload"]["authorization"]["channelId"]
    await client.handle_payment_response(opened, response=None)
    if restart:
        client = _grant(chain, "$0.0025", channel_store=store)  # the store keeps the failed open
    with pytest.raises(ValueError, match="may still land"):
        await client.create_payment_payload(accept)
    # It landed after all: adopt it at the chain's watermark instead of funding another.
    config = opened["payload"]["channelConfig"]
    chain.accounts[channel_id] = (channel_account(config, FEE_PAYER, PAY_TO, deposit=2500), PAYMENT_CHANNELS_PROGRAM_ID)
    paid: Any = await client.create_payment_payload(accept)
    assert (paid["payload"]["type"], paid["payload"]["authorization"]["channelId"]) == ("authorization", channel_id)


async def test_a_failed_open_whose_blockhash_expired_unblocks_a_new_channel(chain: FakeChain) -> None:
    client = _grant(chain, "$0.0025")
    accept = server_accept()
    opened: Any = await client.create_payment_payload(accept)
    await client.handle_payment_response(opened, response=None)
    chain.blockhash_valid = False  # the open can no longer land, and it never did
    again: Any = await client.create_payment_payload(accept)
    assert again["payload"]["type"] == "deposit" and again["payload"]["deposit"]["amount"] == "2500"
