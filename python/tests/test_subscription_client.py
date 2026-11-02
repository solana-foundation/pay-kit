"""Subscription activation client: plan verification and the activation build."""

from __future__ import annotations

import base64
from typing import Any

import pytest
from solders.pubkey import Pubkey

from solana_pay_kit._paycore.errors import InvalidChallengeError, PaymentError
from solana_pay_kit._paycore.txv1 import MessageV1, decode_transaction
from solana_pay_kit.protocols.mpp.client.subscription import (
    BuildSubscriptionActivationOptions,
    VerifiedPlan,
    build_subscription_access_credential,
    build_subscription_activation_credential,
    build_subscription_activation_transaction,
)
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge
from solana_pay_kit.protocols.mpp.intents.subscription import SubscriptionRequest, SubscriptionTerms
from solana_pay_kit.protocols.mpp.program.subscriptions import SUBSCRIPTIONS_PROGRAM_ID
from tests import _subscription_fixture as fx


def _challenge(body: dict[str, Any] | None = None) -> PaymentChallenge:
    return PaymentChallenge(
        id="cid",
        realm=fx.REALM,
        method="solana",
        intent="subscription",
        request=encode_json(body or fx.request()),
    )


def _terms(**overrides: Any) -> SubscriptionTerms:
    return SubscriptionRequest.from_dict(fx.request(**overrides)).terms()


def _programs(raw_b64: str) -> list[str]:
    tx = decode_transaction(base64.b64decode(raw_b64))
    keys = list(tx.message.account_keys)
    return [str(keys[ix.program_id_index]) for ix in tx.message.instructions]


async def test_activation_credential_shape() -> None:
    rpc = fx.world()
    activation = await build_subscription_activation_credential(fx.signer(), rpc, _challenge())
    payload = activation.credential.payload
    assert payload["type"] == "transaction"
    assert activation.credential.source == f"did:pkh:solana:devnet:{fx.SUBSCRIBER.pubkey()}"
    assert activation.subscription_delegation == str(fx.delegation_address())
    assert activation.authentication.verify(activation.subscription_delegation)
    programs = _programs(payload["transaction"])
    assert programs[:2] == ["ComputeBudget111111111111111111111111111111"] * 2
    assert programs[2:] == [
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        SUBSCRIPTIONS_PROGRAM_ID,
        SUBSCRIPTIONS_PROGRAM_ID,
    ]
    tx = decode_transaction(base64.b64decode(payload["transaction"]))
    assert tx.message.account_keys[0] == fx.SUBSCRIBER.pubkey()
    assert rpc.sent == []


async def test_activation_sponsored_with_memo_and_rpc_blockhash() -> None:
    details = fx.method_details(feePayer=True, feePayerKey=str(fx.SPONSOR.pubkey()), recentBlockhash=None)
    activation = await build_subscription_activation_credential(
        fx.signer(), fx.world(), _challenge(fx.request(methodDetails=details, externalId="order-1"))
    )
    raw = activation.credential.payload["transaction"]
    tx = decode_transaction(base64.b64decode(raw))
    assert tx.message.account_keys[0] == fx.SPONSOR.pubkey()
    assert _programs(raw)[-1] == "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"


async def test_activation_version_one_when_advertised() -> None:
    details = fx.method_details(transactionVersions=[0, 1])
    activation = await build_subscription_activation_credential(
        fx.signer(), fx.world(), _challenge(fx.request(methodDetails=details))
    )
    tx = decode_transaction(base64.b64decode(activation.credential.payload["transaction"]))
    assert isinstance(tx.message, MessageV1)
    assert tx.message.config.compute_unit_limit == 400_000
    plan = await VerifiedPlan.fetch(fx.world(), _terms(methodDetails=details))
    capped = await build_subscription_activation_transaction(
        fx.signer(),
        fx.world(),
        plan,
        BuildSubscriptionActivationOptions(max_tx_version=0, subscription_authority_init_id=1),
    )
    assert not isinstance(decode_transaction(base64.b64decode(capped)).message, MessageV1)
    with pytest.raises(InvalidChallengeError, match="advertises no transaction version"):
        await build_subscription_activation_transaction(
            fx.signer(),
            fx.world(),
            await VerifiedPlan.fetch(fx.world(), _terms(methodDetails=fx.method_details(transactionVersions=[]))),
        )


async def test_missing_authority_is_initialized_first() -> None:
    rpc = fx.world(authority=False)
    await build_subscription_activation_credential(fx.signer(), rpc, _challenge())
    assert len(rpc.sent) == 1
    init = decode_transaction(rpc.sent[0])
    assert bytes(init.message.instructions[0].data) == bytes([0])


async def test_authority_failures() -> None:
    stuck = fx.world(authority=False)
    stuck.create_on_send = False
    with pytest.raises(PaymentError, match="still missing"):
        await build_subscription_activation_credential(fx.signer(), stuck, _challenge())

    class Failing(fx.FakeRpc):
        async def send_raw_transaction(self, raw_tx: bytes) -> Any:
            raise PaymentError("boom", code="payment_invalid")

    failing = Failing(accounts=dict(fx.world(authority=False).accounts))
    with pytest.raises(PaymentError, match="Failed to broadcast SubscriptionAuthority init: boom"):
        await build_subscription_activation_credential(fx.signer(), failing, _challenge())
    foreign = fx.world()
    foreign.accounts[str(fx.authority_address())] = (fx.authority_data(), "11111111111111111111111111111111")
    with pytest.raises(InvalidChallengeError, match="not owned by the subscriptions program"):
        await build_subscription_activation_credential(fx.signer(), foreign, _challenge())
    short = fx.world()
    short.accounts[str(fx.authority_address())] = (b"\x00", SUBSCRIPTIONS_PROGRAM_ID)
    with pytest.raises(InvalidChallengeError, match="Unexpected SubscriptionAuthority length"):
        await build_subscription_activation_credential(fx.signer(), short, _challenge())


@pytest.mark.parametrize(
    ("plan", "match"),
    [
        ({"discriminator": 2}, "account is not a Plan"),
        ({"status": 0}, "plan is not active"),
        ({"bump": 1}, "planAddress is not the plan's PDA"),
        ({"plan_id": 8}, "planAddress is not the plan's PDA"),
        ({"mint": Pubkey.default()}, "plan.mint differs"),
        ({"amount": 1}, "plan amount differs"),
        ({"period_hours": 24}, "plan period differs"),
        ({"owner": fx.SPONSOR.pubkey()}, "planAddress is not the plan's PDA"),
        ({"destinations": []}, "exactly one address"),
        ({"destinations": [fx.RECIPIENT.pubkey(), fx.SPONSOR.pubkey()]}, "exactly one address"),
        ({"destinations": [fx.SPONSOR.pubkey()]}, "exactly one address"),
    ],
)
async def test_plan_mismatches_are_refused(plan: dict[str, Any], match: str) -> None:
    with pytest.raises(InvalidChallengeError, match=match):
        await build_subscription_activation_credential(fx.signer(), fx.world(**plan), _challenge())


async def test_plan_puller_and_program_checks() -> None:
    listed = _terms(methodDetails=fx.method_details(puller=str(fx.SPONSOR.pubkey())))
    plan = VerifiedPlan.verify(listed, None, fx.PROGRAM, fx.plan_data(pullers=[fx.SPONSOR.pubkey()]))
    assert plan.owner == fx.MERCHANT.pubkey()
    with pytest.raises(InvalidChallengeError, match="neither plan.owner nor in plan.pullers"):
        VerifiedPlan.verify(listed, None, fx.PROGRAM, fx.plan_data())
    with pytest.raises(InvalidChallengeError, match="not owned by methodDetails.subscriptionProgram"):
        VerifiedPlan.verify(_terms(), None, Pubkey.default(), fx.plan_data())
    with pytest.raises(InvalidChallengeError, match="Invalid Plan account"):
        VerifiedPlan.verify(_terms(), None, fx.PROGRAM, b"\x01")
    foreign = _terms(methodDetails=fx.method_details(subscriptionProgram=str(fx.SPONSOR.pubkey())))
    with pytest.raises(InvalidChallengeError, match="Untrusted subscription program"):
        await VerifiedPlan.fetch(fx.world(), foreign)
    # A caller-trusted deployment passes the trust check; the plan PDA is then
    # derived under that program, which this fixture's plan address is not.
    with pytest.raises(InvalidChallengeError, match="planAddress is not the plan's PDA"):
        await VerifiedPlan.fetch(
            fx.FakeRpc(accounts={str(fx.PLAN): (fx.plan_data(), str(fx.SPONSOR.pubkey()))}),
            foreign,
            fx.SPONSOR.pubkey(),
        )
    with pytest.raises(InvalidChallengeError, match="Plan account not found"):
        await VerifiedPlan.fetch(fx.FakeRpc(), _terms())


async def test_invalid_challenges_are_refused() -> None:
    with pytest.raises(InvalidChallengeError, match="Invalid amount"):
        await build_subscription_activation_credential(fx.signer(), fx.world(), _challenge(fx.request(amount="0")))
    bad = PaymentChallenge(id="c", realm="r", method="solana", intent="subscription", request="!!!")
    with pytest.raises(InvalidChallengeError):
        await build_subscription_activation_credential(fx.signer(), fx.world(), bad)


def test_access_credential() -> None:
    from solana_pay_kit.protocols.mpp.intents.subscription import SubscriptionAuthentication

    auth = SubscriptionAuthentication("cid", str(fx.SUBSCRIBER.pubkey()), "sig")
    credential = build_subscription_access_credential(_challenge(), "deleg", auth)
    assert credential.payload == {"type": "proof", "subscriptionDelegation": "deleg", "authentication": auth.to_dict()}
    assert credential.challenge.id == "cid"
