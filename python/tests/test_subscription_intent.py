"""Subscription intent wire types: strict parsing, the period mapping, terms, proofs."""

from __future__ import annotations

from typing import Any

import pytest

from solana_pay_kit._paycore.solana import TOKEN_2022_PROGRAM
from solana_pay_kit.protocols.mpp.core.base64url import encode as b64url
from solana_pay_kit.protocols.mpp.intents.subscription import (
    ActivatePayload,
    SubscriptionAccessPayload,
    SubscriptionAuthentication,
    SubscriptionError,
    SubscriptionMethodDetails,
    SubscriptionRequest,
    billing_period_hours,
    decode_activate_payload,
    parse_period_unit,
    parse_positive_integer,
    period_hours_for,
)
from solana_pay_kit.protocols.mpp.program.subscriptions import SUBSCRIPTIONS_PROGRAM_ID, SubscriptionProgramError
from tests import _subscription_fixture as fx


@pytest.mark.parametrize(
    ("unit", "count", "hours"),
    [("day", "1", 24), ("day", "30", 720), ("day", "365", 8760), ("week", "1", 168), ("week", "52", 8736)],
)
def test_period_mapping(unit: Any, count: str, hours: int) -> None:
    assert billing_period_hours(unit, count) == hours


@pytest.mark.parametrize(
    ("unit", "count", "match"),
    [
        ("day", "366", "exceeds 365"),
        ("week", "53", "exceeds 52"),
        ("day", "0", "no leading zero"),
        ("day", "030", "no leading zero"),
        ("day", "+30", "base-10"),
        ("day", "30.0", "base-10"),
        ("day", "3e1", "base-10"),
        ("day", " 30", "base-10"),
        ("day", "", "empty"),
        ("day", str(1 << 64), "out of range"),
    ],
)
def test_period_mapping_rejects(unit: Any, count: str, match: str) -> None:
    with pytest.raises(SubscriptionError, match=match):
        billing_period_hours(unit, count)


def test_period_hours_for_zero_and_units() -> None:
    with pytest.raises(SubscriptionError, match="positive"):
        period_hours_for("day", 0)
    assert parse_period_unit("week") == "week"
    with pytest.raises(SubscriptionError, match="unknown variant `month`"):
        parse_period_unit("month")
    with pytest.raises(SubscriptionError, match="invalid type"):
        parse_period_unit(1)
    assert parse_positive_integer("42", "amount") == 42


def test_request_round_trip_keeps_method_details_verbatim() -> None:
    body = fx.request(externalId="ref-1", description="Pro", subscriptionExpires="2030-01-01T00:00:00Z")
    body["methodDetails"]["unknownExtension"] = {"kept": True}
    body["ignored"] = 1
    request = SubscriptionRequest.from_dict(body)
    out = request.to_dict()
    assert "ignored" not in out
    assert out["methodDetails"]["unknownExtension"] == {"kept": True}
    assert out["externalId"] == "ref-1" and out["description"] == "Pro"
    assert SubscriptionRequest.from_dict(fx.request(description=None)).description is None


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda b: b.pop("recipient"), "missing field `recipient`"),
        (lambda b: b.pop("periodCount"), "missing field `periodCount`"),
        (lambda b: b.pop("periodUnit"), "missing field `periodUnit`"),
        (lambda b: b.update(periodUnit="month"), "unknown variant"),
        (lambda b: b.update(amount=10), "expected a string"),
        (lambda b: b.update(externalId=5), "expected a string"),
    ],
)
def test_request_rejects(mutate: Any, match: str) -> None:
    body = fx.request()
    mutate(body)
    with pytest.raises(SubscriptionError, match=match):
        SubscriptionRequest.from_dict(body)
    with pytest.raises(SubscriptionError, match="JSON object"):
        SubscriptionRequest.from_dict([])


def test_method_details_parse_and_serialise() -> None:
    details = SubscriptionMethodDetails.from_json(
        fx.method_details(feePayer=True, feePayerKey=str(fx.SPONSOR.pubkey()), transactionVersions=[0, 1], planBump=3)
    )
    assert details.fee_payer and details.transaction_versions == [0, 1] and details.plan_bump == 3
    out = details.to_dict()
    assert out["feePayer"] is True and out["planBump"] == 3
    assert "feePayer" not in SubscriptionMethodDetails.from_json(fx.method_details()).to_dict()


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"planAddress": None}, "missing field `planAddress`"),
        ({"decimals": 256}, "out of range"),
        ({"decimals": True}, "expected an integer"),
        ({"feePayer": None}, "expected a boolean"),
        ({"feePayer": "yes"}, "expected a boolean"),
        ({"transactionVersions": ["legacy"]}, "integers 0 or 1"),
    ],
)
def test_method_details_rejects(overrides: dict[str, Any], match: str) -> None:
    details = fx.method_details()
    for key, value in overrides.items():
        if value is None and key != "feePayer":
            details.pop(key, None)
        else:
            details[key] = value
    with pytest.raises(SubscriptionError, match=f"Invalid methodDetails: .*{match}"):
        SubscriptionMethodDetails.from_json(details)


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"planAddress": ""}, "planAddress is required"),
        ({"mint": ""}, "mint is required"),
        ({"tokenProgram": ""}, "tokenProgram is required"),
        ({"puller": ""}, "puller is required"),
        ({"decimals": None}, "decimals is required"),
        ({"subscriptionProgram": None}, "subscriptionProgram is required"),
        ({"feePayer": True}, "feePayerKey is required"),
    ],
)
def test_method_details_validate(overrides: dict[str, Any], match: str) -> None:
    details = SubscriptionMethodDetails.from_json(fx.method_details(**overrides))
    with pytest.raises(SubscriptionError, match=match):
        details.validate()


def test_terms() -> None:
    terms = SubscriptionRequest.from_dict(fx.request(externalId="ref")).terms()
    assert terms.amount == fx.AMOUNT and terms.period_hours == 720 and terms.mint == fx.MINT
    assert terms.network == "devnet" and terms.fee_payer is None and terms.external_id == "ref"
    assert str(terms.recent_blockhash) == fx.BLOCKHASH
    sponsored = SubscriptionRequest.from_dict(
        fx.request(
            methodDetails=fx.method_details(
                feePayer=True, feePayerKey=str(fx.SPONSOR.pubkey()), network=None, recentBlockhash=None
            )
        )
    ).terms()
    assert sponsored.fee_payer == fx.SPONSOR.pubkey() and sponsored.network == "mainnet"
    assert sponsored.recent_blockhash is None
    token_2022 = SubscriptionRequest.from_dict(
        fx.request(methodDetails=fx.method_details(tokenProgram=TOKEN_2022_PROGRAM))
    ).terms()
    assert str(token_2022.token_program) == TOKEN_2022_PROGRAM


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"amount": "0"}, "Invalid amount"),
        ({"amount": "010"}, "leading zero"),
        ({"periodCount": "53", "periodUnit": "week"}, "exceeds 52"),
        ({"recipient": "nope"}, "Invalid recipient pubkey"),
        ({"methodDetails": None}, "missing methodDetails"),
        ({"currency": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"}, "currency must match"),
        ({"methodDetails": fx.method_details(tokenProgram=SUBSCRIPTIONS_PROGRAM_ID)}, "neither SPL Token"),
        ({"methodDetails": fx.method_details(recentBlockhash="bad")}, "Invalid recentBlockhash"),
        ({"methodDetails": fx.method_details(feePayer=True, feePayerKey="bad")}, "Invalid feePayerKey pubkey"),
    ],
)
def test_terms_rejects(overrides: dict[str, Any], match: str) -> None:
    request = SubscriptionRequest.from_dict(fx.request(**overrides)) if overrides.get("methodDetails", 1) else None
    if request is None:
        body = fx.request()
        body.pop("methodDetails")
        request = SubscriptionRequest.from_dict(body)
    with pytest.raises((SubscriptionError, SubscriptionProgramError), match=match):
        request.terms()


async def test_authentication_signs_and_verifies() -> None:
    signer = fx.signer()
    delegation = str(fx.delegation_address())
    unsigned = SubscriptionAuthentication(challenge_id="cid", payer=str(signer.pubkey), signature="")
    message = unsigned.message_bytes(delegation)
    assert message.startswith(b'{"domain":"mpp-subscription-auth-v1","payer":')
    signed = SubscriptionAuthentication("cid", str(signer.pubkey), str(await signer.sign_message(message)))
    assert signed.verify(delegation)
    assert not signed.verify(str(fx.PLAN))
    assert SubscriptionAuthentication.from_dict(signed.to_dict()) == signed
    with pytest.raises(SubscriptionError, match="payer"):
        SubscriptionAuthentication("cid", "bad", signed.signature).verify(delegation)
    with pytest.raises(SubscriptionError, match="signature"):
        SubscriptionAuthentication("cid", str(signer.pubkey), "bad").verify(delegation)
    with pytest.raises(SubscriptionError, match="expected `proof`"):
        SubscriptionAuthentication.from_dict({**signed.to_dict(), "type": "signature"})


def _auth() -> dict[str, str]:
    return {"type": "proof", "challengeId": "c", "payer": str(fx.SUBSCRIBER.pubkey()), "signature": "s"}


def test_activate_payload() -> None:
    payload = ActivatePayload.from_dict({"type": "transaction", "transaction": "AQAB", "authentication": _auth()})
    assert payload.to_dict()["transaction"] == "AQAB" and "signature" not in payload.to_dict()
    pushed = ActivatePayload.from_dict({"type": "signature", "signature": "sig", "authentication": _auth()})
    assert pushed.to_dict()["signature"] == "sig"
    with pytest.raises(SubscriptionError, match="missing field `authentication`"):
        ActivatePayload.from_dict({"type": "transaction"})
    wrapped = decode_activate_payload({"action": "activate", "type": "transaction", "authentication": _auth()})
    assert wrapped.type == "transaction"
    with pytest.raises(SubscriptionError, match='missing authentication.type="proof"'):
        decode_activate_payload({"type": "transaction"})
    with pytest.raises(SubscriptionError, match="Failed to decode payload"):
        decode_activate_payload({"type": 1, "authentication": _auth()})


def test_access_payload() -> None:
    body = {"type": "proof", "subscriptionDelegation": "d", "authentication": _auth()}
    assert SubscriptionAccessPayload.from_dict(body).to_dict() == body
    with pytest.raises(SubscriptionError, match="expected `proof`"):
        SubscriptionAccessPayload.from_dict({**body, "type": "transaction"})
    with pytest.raises(SubscriptionError, match="missing field `authentication`"):
        SubscriptionAccessPayload.from_dict({"type": "proof", "subscriptionDelegation": "d"})
    with pytest.raises(SubscriptionError, match="expected `proof`"):
        SubscriptionAccessPayload.from_dict({**body, "authentication": {**_auth(), "type": "signature"}})


def test_message_is_canonical_json() -> None:
    # Frozen by harness/vectors/subscription-canonical.json (subscription-auth-message-frozen).
    auth = SubscriptionAuthentication("qT8wErYuI3oPlKjH6gFdSa", "GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB", "")
    encoded = b64url(auth.message_bytes("AwCtiXLhCLxYytJ9Gz5qQBd8GxY6GrwfRdeevPysEgJy"))
    assert encoded.startswith("eyJkb21haW4iOiJtcHAtc3Vic2NyaXB0aW9uLWF1dGgtdjEiLCJwYXllciI6IkdtYURycHBCQzdQNUFSS1Y4")
