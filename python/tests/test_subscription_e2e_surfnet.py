"""Opt-in Surfnet end-to-end subscription lifecycle against the real subscriptions program.

Creates a plan, activates with the authority initialized in the same
transaction (the ``UNKNOWN_INIT_ID`` sentinel), accesses with the bearer proof,
time-travels past the period so access triggers exactly one lazy renewal,
checks a second access in the same period charges nothing, then cancels and
expects a 402 once ``expires_at_ts`` passes. Skips explicitly (never silently
passes) unless enabled and the RPC answers.

Run against a local surfpool that forks mainnet, so the deployed
``De1eg...`` program executes:

    surfpool start --network mainnet --ci --no-deploy --airdrop-amount 0 &
    MPP_RUN_SUBSCRIPTION_E2E=1 uv run pytest tests/test_subscription_e2e_surfnet.py
"""

from __future__ import annotations

import base64
import os
import secrets
import struct

import pytest
from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.paymentchannels import find_associated_token_address
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit._paycore.store import MemoryStore
from solana_pay_kit.protocols.mpp._subscriptions import (
    SUBSCRIPTIONS_PROGRAM_ID,
    UNKNOWN_INIT_ID,
    DelegationView,
    build_create_plan_ix,
    decode_delegation,
    find_event_authority_pda,
    find_plan_pda,
    find_subscription_pda,
)
from solana_pay_kit.protocols.mpp.client.subscription import (
    build_subscription_access_credential,
    build_subscription_activation,
)
from solana_pay_kit.protocols.mpp.server.subscription import SubscriptionConfig, SubscriptionServer
from solana_pay_kit.protocols.programs.subscriptions.instructions.cancelSubscription import CancelSubscription
from solana_pay_kit.signer import LocalSigner

_RPC_URL = os.environ.get("MPP_SUBSCRIPTION_E2E_RPC_URL", "http://127.0.0.1:8899")
_USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
_PROGRAM = Pubkey.from_string(SUBSCRIPTIONS_PROGRAM_ID)
_TOKEN = Pubkey.from_string(TOKEN_PROGRAM)
_AMOUNT = 250_000
_PERIOD = 24 * 3600
pytestmark = pytest.mark.asyncio


async def _reachable(rpc: SolanaRpc) -> bool:
    if os.environ.get("MPP_RUN_SUBSCRIPTION_E2E") != "1":
        return False
    try:
        await rpc._call("getHealth", [])
        return True
    except Exception:
        return False


async def _fund(rpc: SolanaRpc, owner: Pubkey, usdc: int) -> None:
    system = {"lamports": 10_000_000_000, "data": "", "executable": False, "rentEpoch": 0}
    await rpc._call("surfnet_setAccount", [str(owner), {**system, "owner": "11111111111111111111111111111111"}])
    token = {"amount": usdc, "state": "initialized"}
    await rpc._call("surfnet_setTokenAccount", [str(owner), _USDC, token, TOKEN_PROGRAM])


async def _balance(rpc: SolanaRpc, owner: Pubkey) -> int:
    ata = find_associated_token_address(owner, Pubkey.from_string(_USDC), _TOKEN)[0]
    account = await rpc.get_account_info(str(ata))
    assert account is not None
    return struct.unpack_from("<Q", account[0], 64)[0]


async def _chain_time(rpc: SolanaRpc) -> int:
    account = await rpc.get_account_info("SysvarC1ock11111111111111111111111111111111")
    assert account is not None
    return struct.unpack_from("<q", account[0], 32)[0]


async def _time_travel(rpc: SolanaRpc, unix_seconds: int) -> None:
    await rpc._call("surfnet_timeTravel", [{"absoluteTimestamp": unix_seconds * 1000}])


async def _delegation(rpc: SolanaRpc, address: Pubkey) -> DelegationView:
    account = await rpc.get_account_info(str(address))
    assert account is not None
    return decode_delegation(account[0], account[1], SUBSCRIPTIONS_PROGRAM_ID)


async def _send(rpc: SolanaRpc, ixs: list[Instruction], signer: Keypair) -> str:
    blockhash = (await rpc.get_latest_blockhash()).value.blockhash
    message = MessageV0.try_compile(signer.pubkey(), ixs, [], Hash.from_string(blockhash))
    tx = VersionedTransaction(message, [signer])
    await rpc.send_raw_transaction(bytes(tx))
    signature = str(tx.signatures[0])
    await rpc.await_confirmation(signature)
    return signature


async def test_subscription_lifecycle_on_chain() -> None:
    rpc = SolanaRpc(_RPC_URL)
    try:
        if not await _reachable(rpc):
            pytest.skip("MPP_RUN_SUBSCRIPTION_E2E not set or the surfnet RPC is unreachable")

        owner, subscriber, recipient = Keypair(), Keypair(), Keypair()
        await _fund(rpc, owner.pubkey(), 0)
        await _fund(rpc, subscriber.pubkey(), 10 * _AMOUNT)
        await _fund(rpc, recipient.pubkey(), 0)

        plan_id = secrets.randbits(63)
        await _send(
            rpc,
            [
                build_create_plan_ix(
                    program=_PROGRAM,
                    owner=owner.pubkey(),
                    plan_id=plan_id,
                    mint=Pubkey.from_string(_USDC),
                    token_program=_TOKEN,
                    amount=_AMOUNT,
                    period_hours=24,
                    created_at=0,
                    destinations=[recipient.pubkey()],
                )
            ],
            owner,
        )
        plan = find_plan_pda(owner.pubkey(), plan_id, _PROGRAM)[0]
        clock = {"now": await _chain_time(rpc)}
        server = SubscriptionServer(
            SubscriptionConfig(
                plan=str(plan),
                mint=_USDC,
                recipient=str(recipient.pubkey()),
                amount=_AMOUNT,
                puller_signer=LocalSigner(owner),
                store=MemoryStore(),
                period_count=1,
                network="localnet",
                rpc=rpc,
                secret_key="subscription-e2e-secret-key-32-bytes!!",
                realm="subscriptions.e2e",
            )
        )
        server._now = lambda: clock["now"]  # type: ignore[method-assign]  # the server follows the chain clock

        async def access() -> tuple[int, str]:
            clock["now"] = await _chain_time(rpc)
            credential = build_subscription_access_credential(
                challenge.to_echo(), activation.subscription_delegation, activation.authentication
            )
            receipt = await server.verify_credential(credential)
            assert receipt.period_index is not None
            return receipt.period_index, receipt.reference

        # Activation: the authority is missing, so it is initialized in the same
        # transaction and subscribe carries the UNKNOWN_INIT_ID sentinel.
        challenge = await server.challenge()
        activation = await build_subscription_activation(subscriber, rpc, challenge)
        tx = VersionedTransaction.from_bytes(base64.b64decode(activation.credential.payload["transaction"]))
        datas = [bytes(ix.data) for ix in tx.message.instructions]
        assert [data[0] for data in datas if len(data) in (1, 74)][:2] == [0, 11]
        assert struct.unpack_from("<q", next(d for d in datas if d[0] == 11 and len(d) == 74), 66)[0] == UNKNOWN_INIT_ID
        start = await _balance(rpc, recipient.pubkey())
        activated = await server.verify_credential(activation.credential)
        assert activated.period_index == 0
        assert await _balance(rpc, recipient.pubkey()) == start + _AMOUNT

        assert await access() == (0, activated.reference)
        assert await _balance(rpc, recipient.pubkey()) == start + _AMOUNT

        # Lazy renewal: past the period, the next access collects exactly one charge.
        delegation = find_subscription_pda(plan, subscriber.pubkey(), _PROGRAM)
        state = await _delegation(rpc, delegation)
        await _time_travel(rpc, state.current_period_start_ts + _PERIOD + 5)
        index, renewal = await access()
        assert index == 1 and renewal != activated.reference
        assert await _balance(rpc, recipient.pubkey()) == start + 2 * _AMOUNT
        assert await access() == (1, renewal)
        assert await _balance(rpc, recipient.pubkey()) == start + 2 * _AMOUNT

        # Cancel: access still works until expires_at_ts, then answers 402.
        cancel = CancelSubscription(
            {
                "subscriber": subscriber.pubkey(),
                "planPda": plan,
                "subscriptionPda": delegation,
                "eventAuthority": find_event_authority_pda(_PROGRAM),
                "selfProgram": _PROGRAM,
            },
            program_id=_PROGRAM,
        )
        await _send(rpc, [cancel], subscriber)
        state = await _delegation(rpc, delegation)
        assert state.expires_at_ts == state.current_period_start_ts + _PERIOD
        assert (await access())[0] == 1
        await _time_travel(rpc, state.expires_at_ts + 5)
        with pytest.raises(PaymentError, match="cancellation"):
            await access()
        assert await _balance(rpc, recipient.pubkey()) == start + 2 * _AMOUNT
    finally:
        await rpc.aclose()
