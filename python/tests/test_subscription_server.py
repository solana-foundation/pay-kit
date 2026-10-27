"""Subscription server: challenge issuance, offline activation verification, active check."""

from __future__ import annotations

import base64
from dataclasses import replace
from typing import Any

import pytest
from solders.instruction import Instruction
from solders.pubkey import Pubkey

from solana_pay_kit._paycore.errors import PaymentError, VerificationError
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit._paycore.transaction import build_partially_signed_transaction
from solana_pay_kit._paycore.txv1 import MessageV1, TransactionV1, signed_message_bytes, v1_config
from solana_pay_kit.protocols.mpp.client.subscription import (
    build_subscription_access_credential,
    build_subscription_activation_credential,
    sign_subscription_authentication,
)
from solana_pay_kit.protocols.mpp.core.base64url import decode_json, encode_json
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, PaymentCredential
from solana_pay_kit.protocols.mpp.intents.subscription import ActivatePayload, SubscriptionAuthentication
from solana_pay_kit.protocols.mpp.program.subscriptions import (
    SUBSCRIPTIONS_PROGRAM_ID,
    SubscribeData,
    TransferData,
    build_create_idempotent_ata_ix,
    build_initialize_subscription_authority_ix,
    build_memo_ix,
    build_subscribe_ix,
    build_transfer_subscription_ix,
    find_associated_token_address,
    find_event_authority_pda,
)
from solana_pay_kit.protocols.mpp.server.subscription import (
    PreparedAccess,
    PreparedActivation,
    SubscriptionConfig,
    SubscriptionServer,
    co_sign_as_fee_payer,
    ensure_live_delegation,
    verify_credential_source,
)
from tests import _subscription_fixture as fx

_EXPIRES = "2031-01-01T00:00:00Z"
_COMPUTE = Pubkey.from_string("ComputeBudget111111111111111111111111111111")


def _config(**overrides: Any) -> SubscriptionConfig:
    config = SubscriptionConfig(
        plan_id=str(fx.PLAN),
        mint=str(fx.MINT),
        token_program=TOKEN_PROGRAM,
        puller=str(fx.MERCHANT.pubkey()),
        recipient=str(fx.RECIPIENT.pubkey()),
        amount_base_units=str(fx.AMOUNT),
        challenge_binding_secret=fx.SECRET,
        realm=fx.REALM,
        network="devnet",
        rpc=fx.world(delegation=True),
    )
    return replace(config, **overrides)


def _server(**overrides: Any) -> SubscriptionServer:
    return SubscriptionServer(_config(**overrides))


def _sponsored(**overrides: Any) -> SubscriptionServer:
    return _server(fee_payer=True, fee_payer_signer=fx.signer(fx.SPONSOR), **overrides)


def _challenge(server: SubscriptionServer, **request: Any) -> PaymentChallenge:
    challenge = server.subscription_challenge(str(fx.AMOUNT), recent_blockhash=fx.BLOCKHASH, expires=_EXPIRES)
    if not request:
        return challenge
    body = {**decode_json(challenge.request), **request}
    return PaymentChallenge.with_secret_key(
        fx.SECRET, fx.REALM, "solana", "subscription", encode_json(body), expires=_EXPIRES
    )


async def _activation(server: SubscriptionServer, challenge: PaymentChallenge | None = None) -> PaymentCredential:
    activation = await build_subscription_activation_credential(
        fx.signer(), fx.world(), challenge or _challenge(server)
    )
    return activation.credential


def _ixs(*, sponsor: Pubkey | None = None, amount: int = fx.AMOUNT) -> list[Instruction]:
    subscriber = fx.SUBSCRIBER.pubkey()
    program = fx.PROGRAM
    token = Pubkey.from_string(TOKEN_PROGRAM)
    event = find_event_authority_pda(program)[0]
    sub_ata = find_associated_token_address(subscriber, fx.MINT, token)
    return [
        Instruction(_COMPUTE, bytes([2]) + (400_000).to_bytes(4, "little"), []),
        Instruction(_COMPUTE, bytes([3]) + (1).to_bytes(8, "little"), []),
        build_create_idempotent_ata_ix(sponsor or subscriber, sub_ata, subscriber, fx.MINT, token),
        build_subscribe_ix(
            program,
            subscriber=subscriber,
            merchant=fx.MERCHANT.pubkey(),
            plan_pda=fx.PLAN,
            subscription_pda=fx.delegation_address(),
            subscription_authority_pda=fx.authority_address(),
            event_authority=event,
            payer=sponsor,
            data=SubscribeData(fx.PLAN_ID, fx.PLAN_BUMP, fx.MINT, fx.AMOUNT, 720, fx.CREATED_AT, fx.INIT_ID),
        ),
        build_transfer_subscription_ix(
            program,
            subscription_pda=fx.delegation_address(),
            plan_pda=fx.PLAN,
            subscription_authority=fx.authority_address(),
            delegator_ata=sub_ata,
            receiver_ata=find_associated_token_address(fx.RECIPIENT.pubkey(), fx.MINT, token),
            caller=fx.MERCHANT.pubkey(),
            token_mint=fx.MINT,
            token_program=token,
            event_authority=event,
            data=TransferData(amount, subscriber, fx.MINT),
        ),
    ]


async def _credential(
    server: SubscriptionServer,
    ixs: list[Instruction],
    *,
    fee_payer: Pubkey | None = None,
    challenge: PaymentChallenge | None = None,
    source: str | None = "",
    version: int = 0,
) -> PaymentCredential:
    challenge = challenge or _challenge(server)
    signer = fx.signer()
    if version == 1:
        ixs = [ix for ix in ixs if ix.program_id != _COMPUTE]
        raw = await build_partially_signed_transaction(
            ixs, fee_payer or signer.pubkey, fx.blockhash(), signer, version=1, config=v1_config(400_000, 1)
        )
    else:
        raw = await build_partially_signed_transaction(ixs, fee_payer or signer.pubkey, fx.blockhash(), signer)
    auth = await sign_subscription_authentication(signer, challenge.id, str(fx.delegation_address()))
    payload = ActivatePayload(type="transaction", transaction=base64.b64encode(raw).decode(), authentication=auth)
    return PaymentCredential(
        challenge=challenge.to_echo(),
        payload=payload.to_dict(),
        source=f"did:pkh:solana:devnet:{signer.pubkey}" if source == "" else source,
    )


async def _reject(server: SubscriptionServer, credential: PaymentCredential, match: str) -> PaymentError:
    with pytest.raises(PaymentError, match=match) as info:
        await server.verify_activation(credential, now=fx.NOW)
    return info.value


# ── Challenge ──


def test_challenge_issuance() -> None:
    server = _server(plan_id_numeric=7, plan_bump=fx.PLAN_BUMP, plan_created_at=fx.CREATED_AT, description="Pro")
    challenge = server.subscription_challenge(str(fx.AMOUNT))
    assert challenge.verify(fx.SECRET) and challenge.intent == "subscription" and challenge.expires
    request = decode_json(challenge.request)
    details = request["methodDetails"]
    assert details["subscriptionProgram"] == SUBSCRIPTIONS_PROGRAM_ID and details["expectedPeriodHours"] == 720
    assert "transactionVersions" not in details and "feePayer" not in details
    assert request["description"] == "Pro" and challenge.description == "Pro"
    sponsored = _sponsored(transaction_versions=[0, 1]).subscription_challenge(str(fx.AMOUNT))
    details = decode_json(sponsored.request)["methodDetails"]
    assert details["feePayerKey"] == str(fx.SPONSOR.pubkey()) and details["transactionVersions"] == [0, 1]
    for amount, match in (("", "required"), ("x", "Invalid amount"), ("5", "does not match the configured")):
        with pytest.raises(ValueError, match=match):
            server.subscription_challenge(amount)
    assert server.realm == fx.REALM and server.plan_id == str(fx.PLAN)
    assert server.program_id == SUBSCRIPTIONS_PROGRAM_ID and server.accepted_versions == (0,)


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"plan_id": ""}, "plan_id is required"),
        ({"realm": ""}, "realm is required"),
        ({"mint": "bad"}, "Invalid mint pubkey"),
        ({"period_count": 0}, "positive"),
        ({"amount_base_units": "0"}, "positive integer"),
        ({"amount_base_units": "1.5"}, "positive integer"),
        ({"subscription_expires": "tomorrow"}, "RFC3339"),
        ({"subscription_expires": "2001-01-01T00:00:00Z"}, "in the future"),
        ({"program_id": "bad"}, "Invalid program_id pubkey"),
        ({"transaction_versions": [2]}, "unsupported transaction version"),
    ],
)
def test_config_validation(overrides: dict[str, Any], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        _server(**overrides)


# ── Activation ──


async def test_activation_built_by_the_client_verifies() -> None:
    server = _server()
    prepared = await server.verify_activation(await _activation(server), now=fx.NOW)
    assert isinstance(prepared, PreparedActivation) and prepared.subscriber == fx.SUBSCRIBER.pubkey()
    assert prepared.transaction_base64()


async def test_sponsored_activation_is_cosigned() -> None:
    server = _sponsored()
    prepared = await server.verify_activation(await _activation(server), now=fx.NOW)
    assert isinstance(prepared, PreparedActivation)
    message = prepared.transaction.message
    assert prepared.transaction.signatures[0].verify(message.account_keys[0], signed_message_bytes(message))


async def test_pubkey_only_sponsor_cannot_produce_a_verified_fee_payer_signature() -> None:
    server = _server(fee_payer=True, fee_payer_pubkey=str(fx.SPONSOR.pubkey()))
    await _reject(server, await _activation(server), "signature does not verify against its message")


async def test_version_one_activation() -> None:
    server = _sponsored(transaction_versions=[0, 1])
    prepared = await server.verify_activation(await _activation(server), now=fx.NOW)
    assert isinstance(prepared, PreparedActivation) and isinstance(prepared.transaction.message, MessageV1)
    assert prepared.transaction.signatures[0].verify(
        fx.SPONSOR.pubkey(), signed_message_bytes(prepared.transaction.message)
    )
    v0_only = _server()
    await _reject(v0_only, await _credential(v0_only, _ixs(), version=1), "transaction version 1 is not accepted")


async def test_wall_clock_default() -> None:
    server = _server()
    assert isinstance(await server.verify_activation(await _activation(server)), PreparedActivation)


async def test_challenge_binding_rejects() -> None:
    server = _server()
    credential = await _activation(server)
    echo = credential.challenge

    def with_echo(**changes: Any) -> PaymentCredential:
        return replace(credential, challenge=replace(echo, **changes))

    error = await _reject(server, with_echo(id="forged"), "HMAC mismatch")
    assert error.code == "challenge-mismatch"

    def rebound(**changes: Any) -> PaymentCredential:
        fields = {"realm": fx.REALM, "method": "solana", "intent": "subscription", **changes}
        challenge = PaymentChallenge.with_secret_key(
            fx.SECRET, fields["realm"], fields["method"], fields["intent"], echo.request, expires=_EXPIRES
        )
        return replace(credential, challenge=challenge.to_echo())

    await _reject(server, rebound(method="stripe"), "method `stripe` does not match")
    await _reject(server, rebound(intent="charge"), "is not a subscription")
    # The route's realm keys the HMAC, so another realm is an unissued challenge.
    await _reject(server, rebound(realm="other"), "HMAC mismatch")


@pytest.mark.parametrize(
    ("request_changes", "match"),
    [
        ({"currency": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"}, "mint `Es9v"),
        ({"recipient": str(fx.SPONSOR.pubkey())}, "recipient does not match"),
        ({"amount": "1"}, "terms do not match"),
        ({"periodCount": "7"}, "terms do not match"),
        ({"methodDetails": None}, "missing methodDetails"),
        ({"methodDetails": {"planAddress": 1}}, "Invalid methodDetails"),
        ({"methodDetails": fx.method_details(decimals=None)}, "decimals is required"),
        ({"methodDetails": fx.method_details(subscriptionProgram=str(fx.SPONSOR.pubkey()))}, "subscriptionProgram"),
        ({"methodDetails": fx.method_details(planAddress=str(fx.SPONSOR.pubkey()))}, "planAddress does not match"),
        ({"methodDetails": fx.method_details(network="mainnet")}, "network does not match"),
        ({"methodDetails": fx.method_details(network=None)}, "network does not match"),
        ({"subscriptionExpires": "2030-03-17T17:46:40Z"}, "Subscription has expired"),
        ({"subscriptionExpires": "soon"}, "Invalid subscriptionExpires"),
    ],
)
async def test_route_term_rejects(request_changes: dict[str, Any], match: str) -> None:
    server = _server()
    challenge = _challenge(server, **request_changes)
    if request_changes.get("methodDetails", 1) is None:
        body = decode_json(challenge.request)
        body.pop("methodDetails")
        challenge = PaymentChallenge.with_secret_key(
            fx.SECRET, fx.REALM, "solana", "subscription", encode_json(body), expires=_EXPIRES
        )
    await _reject(server, await _credential(server, _ixs(), challenge=challenge), match)


async def test_undecodable_request_and_expired_challenge() -> None:
    server = _server()
    garbage = PaymentChallenge.with_secret_key(fx.SECRET, fx.REALM, "solana", "subscription", "!!!", expires=_EXPIRES)
    credential = await _credential(server, _ixs())
    await _reject(server, replace(credential, challenge=garbage.to_echo()), "Failed to decode request")
    for expires in ("2030-03-17T17:46:40Z", "not-a-date"):
        stale = PaymentChallenge.with_secret_key(
            fx.SECRET, fx.REALM, "solana", "subscription", credential.challenge.request, expires=expires
        )
        await _reject(server, replace(credential, challenge=stale.to_echo()), "activation challenge has expired")


async def test_payload_rejects() -> None:
    server = _server()
    credential = await _credential(server, _ixs())
    auth = credential.payload["authentication"]
    cases: list[tuple[dict[str, Any], str]] = [
        ({"type": "signature", "signature": "s", "authentication": auth}, "Push-mode"),
        ({"type": "other", "authentication": auth}, "Unsupported payload type `other`"),
        ({"type": "transaction", "authentication": auth}, "missing `transaction`"),
        ({"type": "transaction", "transaction": "AQAB"}, "missing authentication"),
        ({"type": "transaction", "transaction": "@@", "authentication": auth}, "Tx decode"),
    ]
    for payload, match in cases:
        await _reject(server, replace(credential, payload=payload), match)
    sponsored = _sponsored()
    await _reject(
        sponsored,
        replace(credential, payload={"type": "signature", "signature": "s", "authentication": auth}),
        "cannot be used with fee sponsorship",
    )


async def test_access_proof_payload() -> None:
    server = _server()
    challenge = _challenge(server)
    auth = SubscriptionAuthentication(challenge.id, str(fx.SUBSCRIBER.pubkey()), "sig")
    access = build_subscription_access_credential(challenge, str(fx.delegation_address()), auth)
    prepared = await server.verify_activation(access, now=fx.NOW)
    assert isinstance(prepared, PreparedAccess) and prepared.access.authentication == auth
    await _reject(server, replace(access, payload={"type": "proof"}), "Failed to decode proof payload")


async def test_authentication_rejects() -> None:
    server = _server()
    credential = await _credential(server, _ixs())
    auth = credential.payload["authentication"]
    other_payer = str(fx.SPONSOR.pubkey())
    for changes, match in (
        ({"challengeId": "other"}, "proof challengeId does not match"),
        ({"payer": other_payer}, "proof payer does not match"),
        ({"signature": "1" * 64}, "Invalid subscription authentication proof"),
        ({"signature": "bad!"}, "signature must be"),
    ):
        payload = {**credential.payload, "authentication": {**auth, **changes}}
        await _reject(server, replace(credential, payload=payload), match)


async def test_source_rejects() -> None:
    server = _server()
    await _reject(server, await _credential(server, _ixs(), source="did:key:z6Mk"), "did:pkh:solana DID")
    await _reject(
        server,
        await _credential(server, _ixs(), source=f"did:pkh:solana:devnet:{fx.SPONSOR.pubkey()}"),
        "source does not match",
    )
    assert isinstance(
        await server.verify_activation(await _credential(server, _ixs(), source=None), now=fx.NOW), PreparedActivation
    )
    with pytest.raises(VerificationError, match="source does not match"):
        verify_credential_source("did:pkh:solana:devnet:not-a-key", fx.SUBSCRIBER.pubkey())
    with pytest.raises(VerificationError, match="did:pkh:solana DID"):
        verify_credential_source("did:pkh:solana::addr", fx.SUBSCRIBER.pubkey())


def _with(ixs: list[Instruction], index: int, ix: Instruction) -> list[Instruction]:
    return ixs[:index] + [ix] + ixs[index:]


async def test_scope_rejects() -> None:
    server = _server()
    base = _ixs()
    subscriber = fx.SUBSCRIBER.pubkey()
    token = Pubkey.from_string(TOKEN_PROGRAM)
    vote = Pubkey.from_string("Vote111111111111111111111111111111111111111")
    other_ata = build_create_idempotent_ata_ix(subscriber, subscriber, fx.SPONSOR.pubkey(), fx.MINT, token)
    init = build_initialize_subscription_authority_ix(
        fx.PROGRAM,
        owner=subscriber,
        subscription_authority=fx.authority_address(),
        token_mint=fx.MINT,
        user_ata=subscriber,
        token_program=token,
    )
    cases: list[tuple[list[Instruction], str]] = [
        (base + [Instruction(vote, b"\x01", [])], "Unsupported program Vote"),
        (base[:4], "missing transfer_subscription"),
        (base[:3] + base[4:], "missing subscribe"),
        (base + [base[3]], "multiple subscribe"),
        (base + [base[4]], "multiple transfer_subscription"),
        (base[:3] + [base[4], base[3]], "subscribe must precede"),
        (base + [base[2]], "Only one idempotent subscriber ATA creation"),
        (base[:2] + [other_ata] + base[3:], "ATA creation does not match"),
        (base[:2] + base[3:4] + base[2:3] + base[4:], "setup instructions must precede subscribe"),
        (_with(base, 3, init), "initialize_subscription_authority is not allowed"),
        (base + [Instruction(fx.PROGRAM, b"", [])], "empty subscriptions-program instruction"),
        (base + [Instruction(fx.PROGRAM, b"\x0c", [])], "Unsupported subscriptions instruction 12"),
        (base[:4] + _ixs(amount=fx.AMOUNT + 1)[4:], "transfer_subscription data does not match"),
        (base + [build_memo_ix("x")], "memo does not match"),
        (base + [Instruction(_COMPUTE, b"\x02\x00\x00\x00\x00", [])], "multiple compute-unit-limit"),
        (base + [Instruction(_COMPUTE, b"\x03" + bytes(8), [])], "multiple compute-unit-price"),
        (base + [Instruction(_COMPUTE, b"\x04", [])], "Unsupported compute-budget instruction"),
        ([Instruction(_COMPUTE, b"\x02" + (400_001).to_bytes(4, "little"), [])] + base[1:], "limit exceeds"),
        ([base[0], Instruction(_COMPUTE, b"\x03" + (5_000_001).to_bytes(8, "little"), [])] + base[2:], "price exceeds"),
    ]
    for ixs, match in cases:
        await _reject(server, await _credential(server, ixs), match)


async def test_scope_account_rejects() -> None:
    server = _server()
    base = _ixs()
    subscribe, transfer = base[3], base[4]

    def swap(ix: Instruction, position: int, key: Pubkey) -> Instruction:
        accounts = list(ix.accounts)
        accounts[position] = replace_meta(accounts[position], key)
        return Instruction(ix.program_id, bytes(ix.data), accounts)

    other = fx.SPONSOR.pubkey()
    await _reject(
        server, await _credential(server, base[:3] + [swap(subscribe, 2, other), transfer]), "subscribe accounts"
    )
    await _reject(
        server, await _credential(server, base[:4] + [swap(transfer, 4, other)]), "transfer_subscription accounts"
    )
    short = Instruction(transfer.program_id, bytes(transfer.data), list(transfer.accounts)[:9])
    await _reject(server, await _credential(server, base[:4] + [short]), "Codama v0.5 schema")
    unsponsored_payer = _ixs(sponsor=other)
    await _reject(server, await _credential(server, unsponsored_payer), "subscribe accounts|signers must be exactly")


def replace_meta(meta: Any, key: Pubkey) -> Any:
    from solders.instruction import AccountMeta

    return AccountMeta(key, meta.is_signer, meta.is_writable)


async def test_memo_and_signer_rules() -> None:
    server = _server()
    with_memo = _challenge(server, externalId="order-1")
    assert isinstance(
        await server.verify_activation(
            await _credential(server, _ixs() + [build_memo_ix("order-1")], challenge=with_memo), now=fx.NOW
        ),
        PreparedActivation,
    )
    await _reject(server, await _credential(server, _ixs(), challenge=with_memo), "memo does not match")
    await _reject(
        server,
        await _credential(server, _ixs() + [build_memo_ix("order-1"), build_memo_ix("order-1")], challenge=with_memo),
        "memo does not match",
    )
    puller_pays = await _credential(server, _ixs(), fee_payer=fx.MERCHANT.pubkey())
    await _reject(server, puller_pays, "Subscriber cannot equal the server puller")


async def test_sponsor_rules() -> None:
    server = _sponsored()
    sponsor = fx.SPONSOR.pubkey()
    await _reject(server, await _credential(server, _ixs()), "fee payer must be")
    no_subscriber = [ix for ix in _ixs(sponsor=sponsor)][:2]
    await _reject(server, await _credential_raw(server, no_subscriber, sponsor), "Could not identify subscriber")
    pubkey_less = _server(fee_payer=True)
    await _reject(pubkey_less, await _credential(server, _ixs()), "requires a configured fee-payer pubkey")


async def _credential_raw(server: SubscriptionServer, ixs: list[Instruction], fee_payer: Pubkey) -> PaymentCredential:
    """A transaction whose only signer is the sponsor (signed by the sponsor)."""
    challenge = _challenge(server)
    sponsor = fx.signer(fx.SPONSOR)
    raw = await build_partially_signed_transaction(ixs, fee_payer, fx.blockhash(), sponsor)
    auth = await sign_subscription_authentication(fx.signer(), challenge.id, str(fx.delegation_address()))
    payload = ActivatePayload(type="transaction", transaction=base64.b64encode(raw).decode(), authentication=auth)
    return PaymentCredential(challenge=challenge.to_echo(), payload=payload.to_dict())


async def test_cosign_requires_the_fee_payer_slot() -> None:
    server = _server()
    credential = await _credential(server, _ixs())
    prepared = await server.verify_activation(credential, now=fx.NOW)
    assert isinstance(prepared, PreparedActivation)
    with pytest.raises(PaymentError, match="Fee payer pubkey not present"):
        await co_sign_as_fee_payer(prepared.transaction, fx.signer(fx.SPONSOR))
    message = MessageV1.try_compile(
        fx.SPONSOR.pubkey(), _ixs(sponsor=fx.SPONSOR.pubkey())[2:], fx.blockhash(), v1_config(400_000, 1)
    )
    with pytest.raises(PaymentError, match="signatures vec is shorter"):
        await co_sign_as_fee_payer(TransactionV1(message=message, signatures=[]), fx.signer(fx.SPONSOR))


# ── Active subscription ──


async def _active(server: SubscriptionServer, amount: str = str(fx.AMOUNT), now: int = fx.NOW) -> Any:
    return await server.verify_active_subscription(fx.SUBSCRIBER.pubkey(), amount, now=now)


async def test_active_subscription_live() -> None:
    view = await _active(_server())
    assert view.amount_pulled_in_period == fx.AMOUNT
    period_end = fx.NOW - 3600 + 720 * 3600
    assert (await _active(_server(), now=period_end - 1)).period_hours == 720


@pytest.mark.parametrize(
    ("accounts", "now", "match"),
    [
        ({"delegation": None}, fx.NOW, "SubscriptionDelegation account .* not found"),
        ({"authority": None}, fx.NOW, "SubscriptionAuthority account .* not found"),
        ({"delegation": fx.delegation_data(pulled=0)}, fx.NOW, "not paid for the current billing period"),
        ({"delegation": fx.delegation_data(period_start=fx.NOW + 1)}, fx.NOW, "not paid for the current"),
        ({}, fx.NOW - 3600 + 720 * 3600, "not paid for the current billing period"),
        ({"delegation": fx.delegation_data(expires_at=fx.NOW)}, fx.NOW, "cancellation has taken effect"),
        ({"delegation": fx.delegation_data(init_id=1)}, fx.NOW, "authority has been invalidated"),
        ({"delegation": fx.delegation_data(plan=Pubkey.default())}, fx.NOW, "bound plan and payer"),
        ({"delegation": fx.delegation_data(version=2)}, fx.NOW, "discriminator/version"),
        ({"authority": fx.authority_data(discriminator=3)}, fx.NOW, "SubscriptionAuthority discriminator"),
    ],
)
async def test_active_subscription_rejects(accounts: dict[str, Any], now: int, match: str) -> None:
    rpc = fx.world(delegation=True)
    for kind, data in accounts.items():
        address = str(fx.delegation_address() if kind == "delegation" else fx.authority_address())
        if data is None:
            rpc.accounts.pop(address)
        else:
            rpc.accounts[address] = (data, SUBSCRIPTIONS_PROGRAM_ID)
    with pytest.raises(PaymentError, match=match):
        await _active(_server(rpc=rpc), now=now)


async def test_active_subscription_owner_and_amount_checks() -> None:
    for kind in ("delegation", "authority"):
        rpc = fx.world(delegation=True)
        address = str(fx.delegation_address() if kind == "delegation" else fx.authority_address())
        rpc.accounts[address] = (rpc.accounts[address][0], "11111111111111111111111111111111")
        with pytest.raises(PaymentError, match="owner mismatch"):
            await _active(_server(rpc=rpc))
    with pytest.raises(PaymentError, match="unsigned integer"):
        await _active(_server(), amount="ten")
    with pytest.raises(PaymentError, match="not paid"):
        await _active(_server(), amount="1")
    expiry = 2_051_222_400  # 2035-01-01T00:00:00Z
    rpc = fx.world(delegation=True)
    rpc.accounts[str(fx.delegation_address())] = (
        fx.delegation_data(period_start=expiry - 60),
        SUBSCRIPTIONS_PROGRAM_ID,
    )
    expiring = _server(rpc=rpc, subscription_expires="2035-01-01T00:00:00Z")
    assert (await _active(expiring, now=expiry - 1)).period_hours == 720
    with pytest.raises(PaymentError, match="Subscription has expired"):
        await _active(expiring, now=expiry)


def test_ensure_live_delegation_expiry_rules() -> None:
    from solana_pay_kit.protocols.mpp.program.subscriptions import decode_subscription_delegation

    view = decode_subscription_delegation(fx.delegation_data())
    assert ensure_live_delegation(view, fx.AMOUNT, 720, None, fx.NOW) == fx.NOW - 3600 + 720 * 3600
    with pytest.raises(PaymentError, match="Invalid subscriptionExpires"):
        ensure_live_delegation(view, fx.AMOUNT, 720, "later", fx.NOW)
    with pytest.raises(PaymentError, match="Subscription has expired"):
        ensure_live_delegation(view, fx.AMOUNT, 720, "2030-03-17T17:46:40Z", fx.NOW)


def test_default_rpc_is_built_lazily() -> None:
    server = _server(rpc=None, rpc_url="http://127.0.0.1:1")
    assert server._rpc_client() is server._rpc_client()  # noqa: SLF001
