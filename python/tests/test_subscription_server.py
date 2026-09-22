"""Tests for SubscriptionServer: config, challenge, activation, replay and access.

Mirrors the Rust ``server/subscription.rs`` and TS ``subscription-server``
tests. The real Python client builds every activation, and ``ChainSim``
applies it to the fake chain the way the program would.
"""

from __future__ import annotations

import base64
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.errors import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    PaymentError,
    ReplayError,
)
from solana_pay_kit._paycore.solana import SYSTEM_PROGRAM
from solana_pay_kit._paycore.store import MemoryStore
from solana_pay_kit.protocols.mpp._subscriptions import (
    decode_delegation,
    find_subscription_authority_pda,
    find_subscription_pda,
)
from solana_pay_kit.protocols.mpp.client import subscription as client_subscription
from solana_pay_kit.protocols.mpp.client.subscription import (
    SubscriptionActivation,
    build_subscription_access_credential,
    build_subscription_activation,
)
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.headers import format_authorization, parse_receipt
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential, Receipt
from solana_pay_kit.protocols.mpp.intents import sign_subscription_authentication
from solana_pay_kit.protocols.mpp.server._subscription_scope import cosign
from solana_pay_kit.protocols.mpp.server.subscription import (
    SubscriptionChallengeOptions,
    SubscriptionConfig,
    SubscriptionServer,
    _rfc3339,  # pyright: ignore[reportPrivateUsage]
)
from tests._subscription_fixtures import (
    AMOUNT,
    MINT,
    NOW,
    PERIOD_SECONDS,
    PLAN,
    PROGRAM,
    PROGRAM_ID,
    RECIPIENT,
    SECRET,
    SERVER,
    SUBSCRIBER,
    TOKEN,
    ChainSim,
    FakeRpc,
    authority_bytes,
    delegation_bytes,
    install_chain,
    install_plan,
    mint_bytes,
    pk,
)

REALM = "subscriptions.test"
SUB = SUBSCRIBER.pubkey()
DELEGATION = find_subscription_pda(PLAN, SUB, PROGRAM)
AUTHORITY = find_subscription_authority_pda(SUB, MINT, PROGRAM)


class CountingSigner:
    """Wraps the server key and counts signatures, to prove nothing is signed before validation."""

    def __init__(self, keypair: Keypair) -> None:
        self.keypair = keypair
        self.calls = 0

    def pubkey(self) -> str:
        return str(self.keypair.pubkey())

    def sign(self, message: bytes) -> bytes:
        self.calls += 1
        return bytes(self.keypair.sign_message(message))


class Harness:
    """A server over a simulated chain, with one clock shared by the server and the chain."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> None:
        self.now = NOW
        self.rpc = FakeRpc()
        install_chain(self.rpc)
        self.chain = ChainSim(self.rpc, lambda: self.now)
        self.store = MemoryStore()
        self.puller = CountingSigner(SERVER)
        self.config = replace(config(self.rpc, self.store, self.puller), **overrides)
        self.server = SubscriptionServer(self.config)
        monkeypatch.setattr(self.server, "_now", lambda: self.now)
        # The client checks subscriptionExpires and plan end on the same simulated clock.
        monkeypatch.setattr(client_subscription, "time", SimpleNamespace(time=lambda: self.now))

    async def activation(
        self, options: SubscriptionChallengeOptions | None = None, signer: Keypair = SUBSCRIBER
    ) -> tuple[PaymentChallenge, SubscriptionActivation]:
        challenge = await self.server.challenge(options)
        return challenge, await build_subscription_activation(signer, self.rpc, challenge)

    async def activate(self) -> tuple[PaymentChallenge, SubscriptionActivation, Receipt]:
        challenge, activation = await self.activation()
        return challenge, activation, await self.server.verify_credential(activation.credential)

    async def access(self, challenge: PaymentChallenge, activation: SubscriptionActivation) -> Receipt:
        credential = build_subscription_access_credential(
            challenge.to_echo(), activation.subscription_delegation, activation.authentication
        )
        return await self.server.verify_credential(credential)

    def set_delegation(self, **fields: Any) -> None:
        state = decode_delegation(*self.rpc.accounts[str(DELEGATION)], PROGRAM_ID)
        values: dict[str, Any] = {
            "subscriber": state.subscriber,
            "plan": state.plan,
            "init_id": state.init_id,
            "amount": state.amount,
            "period_hours": state.period_hours,
            "created_at": state.created_at,
            "amount_pulled_in_period": state.amount_pulled_in_period,
            "current_period_start_ts": state.current_period_start_ts,
            "expires_at_ts": state.expires_at_ts,
        }
        values.update(fields)
        self.rpc.put(DELEGATION, delegation_bytes(**values))


def config(rpc: Any, store: Any, puller: Any) -> SubscriptionConfig:
    return SubscriptionConfig(
        plan=str(PLAN),
        mint=str(MINT),
        recipient=str(RECIPIENT),
        amount=AMOUNT,
        puller_signer=puller,
        store=store,
        network="localnet",
        rpc=rpc,
        secret_key=SECRET,
        realm=REALM,
        read_backoff_step_ms=1,
    )


@pytest.fixture
def h(monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(monkeypatch)


# -- configuration and challenge -----------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"store": None},
        {"secret_key": "short"},
        {"realm": ""},
        {"plan": "not-a-pubkey"},
        {"period_count": 366},
        {"period_unit": "month"},
        {"amount": 0},
        {"token_program": str(pk(70))},
        {"network": "testnet"},
        {"subscription_expires": "tomorrow"},
        {"puller_signer": object()},
        {"rpc": object()},
    ],
)
def test_config_rejects(overrides: dict[str, Any]) -> None:
    with pytest.raises(PaymentError) as err:
        SubscriptionServer(replace(config(FakeRpc(), MemoryStore(), SERVER), **overrides))
    assert err.value.code == "invalid-config"


async def test_challenge_method_details(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch, fee_payer=True)
    challenge = await h.server.challenge(SubscriptionChallengeOptions(external_id="order-9"))
    assert challenge.verify(SECRET)
    assert (challenge.method, challenge.intent, challenge.realm) == ("solana", "subscription", REALM)
    request = challenge.decode_request()
    assert request["externalId"] == "order-9"
    assert request["methodDetails"] == {
        "planAddress": str(PLAN),
        "mint": str(MINT),
        "decimals": 6,
        "tokenProgram": str(TOKEN),
        "puller": str(SERVER.pubkey()),
        "subscriptionProgram": PROGRAM_ID,
        "network": "localnet",
        "feePayer": True,
        "feePayerKey": str(SERVER.pubkey()),
        "recentBlockhash": h.rpc.blockhash,
        "merchant": str(SERVER.pubkey()),
        "recipient": str(RECIPIENT),
        "amount": str(AMOUNT),
        "planIdNumeric": 7,
        "planBump": request["methodDetails"]["planBump"],
        "expectedPeriodHours": 720,
        "expectedCreatedAt": 1_700_000_000,
    }


async def test_challenges_are_unique(h: Harness) -> None:
    first, second = await h.server.challenge(), await h.server.challenge()
    assert first.id != second.id and first.opaque != second.opaque


async def test_challenge_tolerates_blockhash_failure(h: Harness) -> None:
    async def fail(commitment: str = "confirmed") -> Any:
        raise RuntimeError("rpc down")

    h.rpc.get_latest_blockhash = fail  # type: ignore[method-assign]
    challenge = await h.server.challenge()
    assert "recentBlockhash" not in challenge.decode_request()["methodDetails"]


def _break(rpc: FakeRpc, change: str) -> None:
    if change == "missing-plan":
        del rpc.accounts[str(PLAN)]
    elif change == "foreign-owner":
        rpc.accounts[str(PLAN)] = (rpc.accounts[str(PLAN)][0], str(pk(71)))
    elif change == "sunset":
        install_plan(rpc, status=0, end_ts=NOW + PERIOD_SECONDS)
    elif change == "terms":
        install_plan(rpc, amount=AMOUNT + 1)
    elif change == "destinations":
        install_plan(rpc, destinations=[RECIPIENT, pk(72)])
    elif change == "puller":
        install_plan(rpc, owner=pk(73))
    elif change == "mint-owner":
        rpc.put(MINT, mint_bytes(), pk(74))
    elif change == "decimals":
        rpc.put(MINT, mint_bytes(decimals=9), TOKEN)
    elif change == "recipient-ata":
        rpc.accounts = {k: v for k, v in rpc.accounts.items() if v[1] != str(TOKEN) or k == str(MINT)}


@pytest.mark.parametrize(
    "change",
    [
        "missing-plan",
        "foreign-owner",
        "sunset",
        "terms",
        "destinations",
        "puller",
        "mint-owner",
        "decimals",
        "recipient-ata",
    ],
)
async def test_plan_preflight_rejects(h: Harness, change: str) -> None:
    _break(h.rpc, change)
    with pytest.raises(PaymentError) as err:
        await h.server.challenge()
    assert err.value.code == "invalid-config"


# -- activation ------------------------------------------------------------------


async def test_activation_receipt_and_binding(h: Harness) -> None:
    challenge, activation, receipt = await h.activate()
    assert len(h.rpc.sent) == 1
    assert receipt.intent == "subscription" and receipt.period_index == 0
    assert receipt.subscription_delegation == str(DELEGATION)
    assert (receipt.period_start, receipt.period_end) == (_rfc3339(NOW), _rfc3339(NOW + PERIOD_SECONDS))
    assert receipt.timestamp == _rfc3339(NOW)
    assert receipt.reference == str(VersionedTransaction.from_bytes(h.rpc.sent[0]).signatures[0])
    binding = await h.store.get(f"solana-subscription:authentication:{DELEGATION}")
    assert binding == {
        "activationSignature": receipt.reference,
        "authentication": activation.authentication.to_dict(),
        "challengeId": challenge.id,
        "periodStartTs": NOW,
        "subscriptionId": receipt.subscription_id,
        "subscriptionExpires": None,
    }
    assert await h.store.get(f"solana-subscription:consumed:{receipt.reference}") == {"challengeId": challenge.id}


async def test_sponsored_activation_signs_as_puller_and_fee_payer(monkeypatch: pytest.MonkeyPatch) -> None:
    sponsor = Keypair.from_seed(bytes([5] * 32))
    h = Harness(monkeypatch, fee_payer=True, fee_payer_signer=sponsor)
    await h.activate()
    tx = VersionedTransaction.from_bytes(h.rpc.sent[0])
    assert tx.message.account_keys[0] == sponsor.pubkey()
    assert all(tx.verify_with_results())


@pytest.mark.parametrize(
    "change",
    [
        {"id": "tampered"},
        {"realm": "other.test"},
        {"method": "other"},
        {"intent": "charge"},
        {"amount": str(AMOUNT + 1)},
        {"recipient": str(pk(75))},
        {"periodCount": "31"},
        {"planAddress": str(pk(76))},
        {"subscriptionProgram": str(pk(77))},
        {"network": "devnet"},
    ],
)
async def test_rejects_hmac_and_each_pin(h: Harness, change: dict[str, Any]) -> None:
    challenge = await h.server.challenge()
    request = challenge.decode_request()
    field, value = next(iter(change.items()))
    if field in request:
        request[field] = value
    elif field in request["methodDetails"]:
        request["methodDetails"][field] = value
    forged = PaymentChallenge.with_secret_key(
        secret_key=SECRET,
        realm=change.get("realm", REALM),
        method=change.get("method", "solana"),
        intent=change.get("intent", "subscription"),
        request=encode_json(request),
        expires=challenge.expires,
    )
    if field == "id":
        forged.id = "tampered"
    credential = PaymentCredential(challenge=forged.to_echo(), payload={})
    expected = ChallengeMismatchError if field == "id" else PaymentError
    with pytest.raises(expected) as err:
        await h.server.verify_credential(credential)
    assert err.value.code in {"challenge-mismatch", "challenge-route-mismatch", f"{field}-mismatch"}


async def test_expired_challenge(h: Harness) -> None:
    challenge, activation = await h.activation()
    expired = PaymentChallenge.with_secret_key(
        secret_key=SECRET,
        realm=REALM,
        method="solana",
        intent="subscription",
        request=challenge.request,
        expires="2020-01-01T00:00:00Z",
    )
    activation.credential.challenge = expired.to_echo()
    with pytest.raises(ChallengeExpiredError):
        await h.server.verify_credential(activation.credential)
    assert h.rpc.sent == []


async def test_expired_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch, subscription_expires=_rfc3339(NOW))
    h.now = NOW - 10  # the client signs just before expiry; the server sees it after
    _, activation = await h.activation()
    h.now = NOW
    with pytest.raises(PaymentError, match="expired"):
        await h.server.verify_credential(activation.credential)
    assert h.rpc.sent == []


@pytest.mark.parametrize("breakage", ["challenge", "payer", "delegation"])
async def test_auth_proof_failures(h: Harness, breakage: str) -> None:
    challenge, activation = await h.activation()
    if breakage == "challenge":
        proof = sign_subscription_authentication("other-challenge", str(DELEGATION), SUBSCRIBER)
    elif breakage == "payer":
        proof = sign_subscription_authentication(challenge.id, str(DELEGATION), Keypair.from_seed(bytes([6] * 32)))
    else:
        proof = sign_subscription_authentication(challenge.id, str(pk(78)), SUBSCRIBER)
    activation.credential.payload["authentication"] = proof.to_dict()
    with pytest.raises(PaymentError, match="proof does not bind"):
        await h.server.verify_credential(activation.credential)
    assert h.puller.calls == 0 and h.rpc.sent == []


@pytest.mark.parametrize(
    ("source", "ok"),
    [
        (None, True),
        (f"did:pkh:solana:localnet:{SUB}", True),
        (f"did:pkh:eip155:1:{SUB}", False),
        (f"did:pkh:solana:localnet:{pk(79)}", False),
        (f"did:pkh:solana:{SUB}", False),
    ],
)
async def test_source_did(h: Harness, source: str | None, ok: bool) -> None:
    _, activation = await h.activation()
    activation.credential.source = source
    if ok:
        assert (await h.server.verify_credential(activation.credential)).period_index == 0
    else:
        with pytest.raises(PaymentError, match="source"):
            await h.server.verify_credential(activation.credential)


async def test_init_with_existing_authority_rejected(h: Harness) -> None:
    _, activation = await h.activation()  # built while the authority is missing, so it inits one
    h.rpc.put(AUTHORITY, authority_bytes(user=SUB, mint=MINT, init_id=1))
    with pytest.raises(PaymentError, match="already exists"):
        await h.server.verify_credential(activation.credential)
    assert h.puller.calls == 0


async def test_no_sign_before_validation(h: Harness) -> None:
    _, activation = await h.activation()
    raw = bytearray(base64.b64decode(activation.credential.payload["transaction"]))
    raw[-1] ^= 1  # corrupt the last instruction's data
    activation.credential.payload["transaction"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(PaymentError):
        await h.server.verify_credential(activation.credential)
    assert h.puller.calls == 0 and h.rpc.sent == []


async def test_matching_retry_allowed_without_rebroadcast(h: Harness) -> None:
    _, activation = await h.activation()
    first = await h.server.verify_credential(activation.credential)
    second = await h.server.verify_credential(activation.credential)
    assert first.reference == second.reference
    assert len(h.rpc.sent) == 1


async def test_forged_confirmed_signature_mints_nothing(h: Harness) -> None:
    # Unsponsored, slot 0 is the transaction id. A lapsed subscriber must not be
    # able to name another confirmed transaction and collect a receipt.
    await h.activate()
    binding = await h.store.get(f"solana-subscription:authentication:{DELEGATION}")
    h.now = NOW + 2 * PERIOD_SECONDS
    _, activation = await h.activation()
    forged = Keypair().sign_message(b"someone else's confirmed transaction")
    h.rpc.statuses[str(forged)] = {"err": None, "confirmationStatus": "confirmed"}
    raw = bytearray(base64.b64decode(activation.credential.payload["transaction"]))
    raw[1:65] = bytes(forged)
    activation.credential.payload["transaction"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(PaymentError):
        await h.server.verify_credential(activation.credential)
    assert len(h.rpc.sent) == 1
    assert await h.store.get(f"solana-subscription:authentication:{DELEGATION}") == binding


async def test_confirmed_retry_after_its_period_mints_nothing(h: Harness) -> None:
    # A real activation retried after its period: the broadcast is skipped and
    # the delegation is stale, so the retry must not produce a receipt.
    _, activation = await h.activation(SubscriptionChallengeOptions(expires="2099-01-01T00:00:00Z"))
    await h.server.verify_credential(activation.credential)
    binding = await h.store.get(f"solana-subscription:authentication:{DELEGATION}")
    h.now = NOW + 2 * PERIOD_SECONDS
    with pytest.raises(PaymentError, match="no longer covers"):
        await h.server.verify_credential(activation.credential)
    assert len(h.rpc.sent) == 1
    assert await h.store.get(f"solana-subscription:authentication:{DELEGATION}") == binding


async def test_reserved_retry_searches_status_history(h: Harness) -> None:
    _, activation = await h.activation()
    receipt = await h.server.verify_credential(activation.credential)
    status = h.rpc.statuses.pop(receipt.reference)  # aged out of the recent status cache
    assert status is not None
    h.rpc.history_statuses[receipt.reference] = status
    assert (await h.server.verify_credential(activation.credential)).reference == receipt.reference
    assert len(h.rpc.sent) == 1


async def test_prefunded_authority_pda_still_takes_the_init(h: Harness) -> None:
    # Lamports sent to the authority PDA must not block activation: the program
    # initializes an empty, system-owned PDA, so the server accepts the init.
    h.rpc.put(AUTHORITY, b"", SYSTEM_PROGRAM)
    _, activation = await h.activation()
    assert (await h.server.verify_credential(activation.credential)).period_index == 0


async def test_old_proof_with_the_new_challenge_is_rejected(h: Harness) -> None:
    _, old, _ = await h.activate()
    del h.rpc.accounts[str(DELEGATION)]  # cancelled and revoked on chain
    new_challenge, _, _ = await h.activate()
    credential = PaymentCredential(
        challenge=new_challenge.to_echo(),
        payload={
            "type": "proof",
            "subscriptionDelegation": str(DELEGATION),
            "authentication": old.authentication.to_dict(),
        },
    )
    with pytest.raises(PaymentError, match="bound at activation"):
        await h.server.verify_credential(credential)


async def test_same_challenge_other_tx_rejected(h: Harness) -> None:
    h.rpc.put(AUTHORITY, authority_bytes(user=SUB, mint=MINT, init_id=1))  # no init, so only replay can reject
    challenge, activation = await h.activation()
    await h.server.verify_credential(activation.credential)
    other = await build_subscription_activation(Keypair.from_seed(bytes([7] * 32)), h.rpc, challenge)
    with pytest.raises(ReplayError):
        await h.server.verify_credential(other.credential)
    assert len(h.rpc.sent) == 1


async def test_same_tx_other_challenge_rejected(h: Harness) -> None:
    h.rpc.put(AUTHORITY, authority_bytes(user=SUB, mint=MINT, init_id=1))  # no init, so only replay can reject
    _, activation = await h.activation()
    await h.server.verify_credential(activation.credential)
    second = await h.server.challenge()
    proof = sign_subscription_authentication(second.id, str(DELEGATION), SUBSCRIBER)
    replayed = PaymentCredential(
        challenge=second.to_echo(),
        payload={**activation.credential.payload, "authentication": proof.to_dict()},
    )
    with pytest.raises(ReplayError):
        await h.server.verify_credential(replayed)
    assert len(h.rpc.sent) == 1


async def test_failed_signature_status_is_not_rebroadcast(h: Harness) -> None:
    _, activation = await h.activation()
    raw = base64.b64decode(activation.credential.payload["transaction"])
    _, signature = cosign(raw, [SERVER], fee_payer=None)
    h.rpc.statuses[signature] = {"err": {"InstructionError": [3, {"Custom": 517}]}, "confirmationStatus": "confirmed"}
    with pytest.raises(PaymentError, match="failed on-chain"):
        await h.server.verify_credential(activation.credential)
    assert h.rpc.sent == []


def _after_send(h: Harness, mutate: Any) -> None:
    def on_send(raw: bytes) -> None:
        h.chain(raw)
        mutate()

    h.rpc.on_send = on_send


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("first-charge-not-executed", "first period"),
        ("delegation-wrong-plan", "does not match"),
        ("delegation-absent", "not visible"),
    ],
)
async def test_post_settle_checks(h: Harness, mutation: str, match: str) -> None:
    _, activation = await h.activation()
    if mutation == "first-charge-not-executed":
        _after_send(h, lambda: h.set_delegation(amount_pulled_in_period=0))
    elif mutation == "delegation-wrong-plan":
        _after_send(h, lambda: h.set_delegation(plan=pk(80)))
    else:
        _after_send(h, lambda: h.rpc.accounts.pop(str(DELEGATION)))
    with pytest.raises(PaymentError, match=match):
        await h.server.verify_credential(activation.credential)
    assert await h.store.get(f"solana-subscription:authentication:{DELEGATION}") is None


async def test_delegation_read_through_replica_lag(h: Harness) -> None:
    _, activation = await h.activation()
    h.rpc.hidden_reads[str(DELEGATION)] = 3
    assert (await h.server.verify_credential(activation.credential)).period_index == 0


async def test_settled_after_subscription_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch, subscription_expires=_rfc3339(NOW + 10))
    _, activation = await h.activation()
    h.chain.clock = lambda: NOW + 10  # the chain clock runs ahead of the server's
    with pytest.raises(PaymentError, match="at or after subscriptionExpires"):
        await h.server.verify_credential(activation.credential)


async def test_binding_store_failure_still_grants(h: Harness, caplog: pytest.LogCaptureFixture) -> None:
    _, activation = await h.activation()

    async def broken_put(key: str, value: Any) -> None:
        raise OSError("disk full")

    h.store.put = broken_put  # type: ignore[method-assign]
    receipt = await h.server.verify_credential(activation.credential)
    assert receipt.period_index == 0
    assert "ALERT" in caplog.text


async def test_reactivation_rotates_binding(h: Harness) -> None:
    old_challenge, old, _ = await h.activate()
    del h.rpc.accounts[str(DELEGATION)]  # cancelled and revoked on chain
    new_challenge, new, _ = await h.activate()
    with pytest.raises(PaymentError, match="bound at activation"):
        await h.access(old_challenge, old)
    assert (await h.access(new_challenge, new)).period_index == 0


# -- access ----------------------------------------------------------------------


async def test_proof_reusable_after_challenge_expiry(h: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    challenge, activation, receipt = await h.activate()
    monkeypatch.setattr(PaymentChallenge, "is_expired", lambda self, now=None: True)
    h.now = NOW + 60
    first, again = await h.access(challenge, activation), await h.access(challenge, activation)
    for access in (first, again):
        assert (access.reference, access.subscription_id, access.period_index) == (
            receipt.reference,
            receipt.subscription_id,
            0,
        )
    assert first.timestamp == _rfc3339(NOW + 60)
    assert len(h.rpc.sent) == 1


@pytest.mark.parametrize(
    ("setup", "match"),
    [
        (lambda h: setattr(h, "now", NOW - 121), "not paid"),
        (lambda h: h.set_delegation(amount_pulled_in_period=AMOUNT - 1), "not paid"),
        (lambda h: (h.set_delegation(expires_at_ts=NOW + 100), setattr(h, "now", NOW + 100)), "cancellation"),
        (lambda h: h.rpc.put(AUTHORITY, authority_bytes(user=SUB, mint=MINT, init_id=999)), "re-initialized"),
        (lambda h: h.rpc.accounts.pop(str(AUTHORITY)), "authority is missing"),
        (lambda h: h.rpc.accounts.pop(str(DELEGATION)), "delegation is missing"),
        (lambda h: h.set_delegation(plan=pk(81)), "delegation is missing"),
        (
            lambda h: (
                h.set_delegation(current_period_start_ts=NOW + PERIOD_SECONDS + 7),
                setattr(h, "now", NOW + PERIOD_SECONDS + 10),
            ),
            "align",
        ),
        (lambda h: h.store._data.pop(f"solana-subscription:authentication:{DELEGATION}"), "bound at activation"),  # noqa: SLF001
    ],
)
async def test_access_rejects(h: Harness, setup: Any, match: str) -> None:
    challenge, activation, _ = await h.activate()
    setup(h)
    with pytest.raises(PaymentError, match=match):
        await h.access(challenge, activation)


async def test_access_subscription_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch, subscription_expires=_rfc3339(NOW + 50))
    challenge, activation, receipt = await h.activate()
    assert receipt.expires_at == _rfc3339(NOW + 50)
    h.now = NOW + 50
    with pytest.raises(PaymentError, match="expired"):
        await h.access(challenge, activation)


async def test_access_cancel_scheduled_ok(h: Harness) -> None:
    challenge, activation, _ = await h.activate()
    h.set_delegation(expires_at_ts=NOW + 100)
    h.now = NOW + 99
    assert (await h.access(challenge, activation)).expires_at == _rfc3339(NOW + 100)


async def test_access_period_index_two(h: Harness) -> None:
    challenge, activation, _ = await h.activate()
    h.set_delegation(current_period_start_ts=NOW + 2 * PERIOD_SECONDS)
    h.now = NOW + 2 * PERIOD_SECONDS + 5
    receipt = await h.access(challenge, activation)
    assert (receipt.period_index, receipt.period_start) == (2, _rfc3339(NOW + 2 * PERIOD_SECONDS))


async def test_access_proof_for_another_delegation(h: Harness) -> None:
    challenge, activation, _ = await h.activate()
    credential = build_subscription_access_credential(challenge.to_echo(), str(pk(82)), activation.authentication)
    with pytest.raises(PaymentError, match="proof does not bind"):
        await h.server.verify_credential(credential)
    other = await h.server.challenge()
    credential = build_subscription_access_credential(
        other.to_echo(), activation.subscription_delegation, activation.authentication
    )
    with pytest.raises(PaymentError, match="bound at activation"):
        await h.server.verify_credential(credential)


async def test_handle_headers(h: Harness) -> None:
    challenge, activation, _ = await h.activate()
    access = build_subscription_access_credential(
        challenge.to_echo(), activation.subscription_delegation, activation.authentication
    )
    ok = await h.server.handle(format_authorization(access))
    assert (ok.ok, ok.status, ok.headers["cache-control"]) == (True, 200, "private")
    assert parse_receipt(ok.headers["payment-receipt"]).period_index == 0
    h.set_delegation(expires_at_ts=NOW + 1)  # cancellation takes effect
    h.now = NOW + 1
    denied = await h.server.handle(format_authorization(access))
    assert (denied.ok, denied.status, denied.headers["cache-control"]) == (False, 402, "no-store")
    assert "payment-receipt" not in denied.headers and denied.headers["www-authenticate"].startswith("Payment ")
    missing = await h.server.handle(None)
    assert missing.status == 402 and missing.body is not None
