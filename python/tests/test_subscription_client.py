"""Tests for the subscription activation and access credential builders.

Mirrors the Rust ``client/subscription.rs`` and TS ``subscription-client``
tests, plus the spec rules the references skip: plan checks before signing,
same-transaction authority init, and no ATA instruction.
"""

from __future__ import annotations

import base64
import struct
from typing import Any

import pytest
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
    SYSTEM_PROGRAM,
)
from solana_pay_kit.protocols.mpp._subscriptions import (
    UNKNOWN_INIT_ID,
    find_subscription_authority_pda,
    find_subscription_pda,
)
from solana_pay_kit.protocols.mpp.client.subscription import (
    build_subscription_access_credential,
    build_subscription_activation,
)
from solana_pay_kit.protocols.mpp.intents import parse_subscription_payload, verify_subscription_authentication
from solana_pay_kit.signer import LocalSigner
from tests._subscription_fixtures import (
    BLOCKHASH,
    MINT,
    PLAN,
    PROGRAM,
    PROGRAM_ID,
    SUBSCRIBER,
    FakeRpc,
    authority_bytes,
    challenge_for,
    install_plan,
    pk,
    request_dict,
)

SUBSCRIBER_KEY = SUBSCRIBER.pubkey()
AUTHORITY = find_subscription_authority_pda(SUBSCRIBER_KEY, MINT, PROGRAM)


def chain(*, authority_init_id: int | None = None) -> FakeRpc:
    rpc = FakeRpc()
    install_plan(rpc)
    if authority_init_id is not None:
        rpc.put(AUTHORITY, authority_bytes(user=SUBSCRIBER_KEY, mint=MINT, init_id=authority_init_id))
    return rpc


async def activate(rpc: FakeRpc, request: dict[str, Any] | None = None, **kwargs: Any) -> VersionedTransaction:
    activation = await build_subscription_activation(
        SUBSCRIBER, rpc, challenge_for(request or request_dict()), **kwargs
    )
    payload = parse_subscription_payload(activation.credential.payload)
    return VersionedTransaction.from_bytes(base64.b64decode(payload.transaction))  # type: ignore[union-attr]


def programs(tx: VersionedTransaction) -> list[str]:
    keys = tx.message.account_keys
    return [str(keys[ix.program_id_index]) for ix in tx.message.instructions]


def subscription_ixs(tx: VersionedTransaction) -> list[bytes]:
    keys = tx.message.account_keys
    return [bytes(ix.data) for ix in tx.message.instructions if keys[ix.program_id_index] == PROGRAM]


async def test_missing_authority_prepends_init_with_sentinel() -> None:
    tx = await activate(chain())
    assert programs(tx) == [COMPUTE_BUDGET_PROGRAM, COMPUTE_BUDGET_PROGRAM, PROGRAM_ID, PROGRAM_ID, PROGRAM_ID]
    init, subscribe, transfer = subscription_ixs(tx)
    assert (init, subscribe[0], transfer[0]) == (bytes([0]), 11, 10)
    assert struct.unpack_from("<q", subscribe, 66)[0] == UNKNOWN_INIT_ID


async def test_existing_authority_uses_live_init_id() -> None:
    tx = await activate(chain(authority_init_id=4242))
    subscribe, transfer = subscription_ixs(tx)
    assert struct.unpack_from("<q", subscribe, 66)[0] == 4242
    assert transfer[0] == 10


async def test_no_ata_create_emitted() -> None:
    tx = await activate(chain())
    assert ASSOCIATED_TOKEN_PROGRAM not in programs(tx)


async def test_memo_for_external_id() -> None:
    tx = await activate(chain(authority_init_id=1), request_dict(externalId="order-42"))
    assert programs(tx)[-1] == MEMO_PROGRAM
    assert bytes(tx.message.instructions[-1].data) == b"order-42"


async def test_sponsored_fee_payer_slot() -> None:
    sponsor = pk(30)
    request = request_dict(methodDetails={"feePayer": True, "feePayerKey": str(sponsor)})
    tx = await activate(chain(authority_init_id=1), request)
    keys = tx.message.account_keys
    assert keys[0] == sponsor
    # Only the subscriber signs; the sponsor and puller slots stay empty for the server.
    signed = [keys[i] for i, sig in enumerate(tx.signatures) if bytes(sig) != bytes(64)]
    assert signed == [SUBSCRIBER_KEY]
    subscribe = next(ix for ix in tx.message.instructions if bytes(ix.data)[0] == 11)
    assert keys[subscribe.accounts[8]] == sponsor


async def test_uses_challenge_blockhash_else_rpc() -> None:
    challenged = "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT"
    tx = await activate(chain(authority_init_id=1), request_dict(methodDetails={"recentBlockhash": challenged}))
    assert str(tx.message.recent_blockhash) == challenged
    tx = await activate(chain(authority_init_id=1))
    assert str(tx.message.recent_blockhash) == BLOCKHASH


@pytest.mark.parametrize(
    ("plan_changes", "detail_changes", "match"),
    [
        (None, {}, "does not exist"),
        ({"destinations": [pk(40)]}, {}, "destinations"),
        ({"amount": 5}, {}, "amount"),
        ({}, {"merchant": str(pk(40))}, "merchant"),
        ({}, {"planBump": 1}, "planBump"),
        ({}, {"expectedCreatedAt": 1}, "expectedCreatedAt"),
    ],
)
async def test_rejects_bad_plan(
    plan_changes: dict[str, Any] | None, detail_changes: dict[str, Any], match: str
) -> None:
    rpc = FakeRpc()
    if plan_changes is not None:
        install_plan(rpc, **plan_changes)
    with pytest.raises(ValueError, match=match):
        await activate(rpc, request_dict(methodDetails=detail_changes))
    assert rpc.sent == []


async def test_rejects_plan_owned_by_another_program() -> None:
    rpc = chain()
    rpc.accounts[str(PLAN)] = (rpc.accounts[str(PLAN)][0], str(pk(41)))
    with pytest.raises(ValueError, match="owned by"):
        await activate(rpc)


async def test_rejects_unexpected_program() -> None:
    rpc = chain()
    with pytest.raises(ValueError, match="trusted"):
        await activate(rpc, request_dict(methodDetails={"subscriptionProgram": str(pk(42))}))


async def test_rejects_expired_challenge() -> None:
    with pytest.raises(ValueError, match="expired"):
        await build_subscription_activation(
            SUBSCRIBER, chain(), challenge_for(request_dict(), expires="2020-01-01T00:00:00Z")
        )


async def test_credential_carries_source_and_proof() -> None:
    challenge = challenge_for(request_dict())
    activation = await build_subscription_activation(LocalSigner(SUBSCRIBER), chain(authority_init_id=1), challenge)
    delegation = str(find_subscription_pda(PLAN, SUBSCRIBER_KEY, PROGRAM))
    assert activation.credential.source == f"did:pkh:solana:localnet:{SUBSCRIBER_KEY}"
    assert activation.subscription_delegation == delegation
    assert activation.authentication.challenge_id == challenge.id
    assert verify_subscription_authentication(activation.authentication, delegation)
    tx = VersionedTransaction.from_bytes(base64.b64decode(activation.credential.payload["transaction"]))
    assert tx.verify_with_results()[list(tx.message.account_keys).index(SUBSCRIBER_KEY)]

    access = build_subscription_access_credential(challenge.to_echo(), delegation, activation.authentication)
    assert access.challenge.id == challenge.id
    assert access.payload == {
        "type": "proof",
        "subscriptionDelegation": delegation,
        "authentication": activation.authentication.to_dict(),
    }


async def test_prefunded_authority_pda_is_initialized_with_sentinel() -> None:
    # Lamports sent to the authority PDA leave it system-owned with no data; the
    # program still initializes it, so the client must too.
    rpc = chain()
    rpc.put(AUTHORITY, b"", SYSTEM_PROGRAM)
    init, subscribe, _ = subscription_ixs(await activate(rpc))
    assert init == bytes([0]) and struct.unpack_from("<q", subscribe, 66)[0] == UNKNOWN_INIT_ID


@pytest.mark.parametrize(
    ("guard", "match"),
    [
        ({"max_amount_base_units": 999_999}, "amount"),
        ({"expected_currency": str(pk(43))}, "currency"),
        ({"expected_recipient": str(pk(44))}, "recipient"),
        ({"expected_period_unit": "week"}, "periodUnit"),
        ({"expected_period_count": 7}, "periodCount"),
    ],
)
async def test_expectation_guards_refuse_before_any_rpc(guard: dict[str, Any], match: str) -> None:
    # object() has no RPC methods: reaching the chain would raise AttributeError.
    with pytest.raises(ValueError, match=match):
        await build_subscription_activation(SUBSCRIBER, object(), challenge_for(request_dict()), **guard)


async def test_matching_guards_sign() -> None:
    guards = {
        "max_amount_base_units": 1_000_000,
        "expected_currency": str(MINT),
        "expected_recipient": request_dict()["recipient"],
        "expected_period_unit": "day",
        "expected_period_count": 30,
    }
    assert await activate(chain(authority_init_id=1), **guards)


async def test_refuses_passed_subscription_expires() -> None:
    with pytest.raises(ValueError, match="subscriptionExpires"):
        await build_subscription_activation(
            SUBSCRIBER, object(), challenge_for(request_dict(subscriptionExpires="2020-01-01T00:00:00Z"))
        )
