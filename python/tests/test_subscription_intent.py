"""Tests for the subscription intent types and bearer proof.

Mirrors ``rust/crates/kit/src/mpp/protocol/intents/subscription.rs`` and
``typescript/packages/mpp/src/__tests__/subscription.test.ts``; the request
example is the one in the Solana subscription spec draft.
"""

from __future__ import annotations

from typing import Any

import pytest
from solders.keypair import Keypair

from solana_pay_kit.protocols.mpp.intents import (
    AccessPayload,
    ActivatePayload,
    SubscriptionAuthentication,
    SubscriptionRequest,
    parse_positive_u64,
    parse_subscription_payload,
    period_hours,
    sign_subscription_authentication,
    verify_subscription_authentication,
)
from solana_pay_kit.signer import LocalSigner

MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
PLAN = "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT"
RECIPIENT = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
PULLER = "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h"


def spec_request() -> dict[str, Any]:
    """The request example from the spec draft (Examples section)."""
    return {
        "amount": "10000000",
        "currency": MINT,
        "periodUnit": "day",
        "periodCount": "30",
        "subscriptionExpires": "2026-07-14T12:00:00Z",
        "recipient": RECIPIENT,
        "description": "Monthly Pro plan",
        "externalId": "merchant-subscription-270",
        "methodDetails": {
            "subscriptionProgram": "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44",
            "planAddress": PLAN,
            "mint": MINT,
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "decimals": 6,
            "puller": PULLER,
            "network": "mainnet",
            "feePayer": True,
            "feePayerKey": PULLER,
        },
    }


# Plan extensions the Rust server emits and the Rust client requires
# (serde camelCase names from SubscriptionMethodDetails).
RUST_EXTENSIONS = {
    "merchant": PULLER,
    "recipient": RECIPIENT,
    "amount": "10000000",
    "planIdNumeric": 7,
    "planBump": 254,
    "expectedPeriodHours": 720,
    "expectedCreatedAt": 1_700_000_000,
}


@pytest.mark.parametrize("extensions", [{}, RUST_EXTENSIONS])
def test_spec_request_round_trips_unchanged(extensions: dict[str, Any]) -> None:
    wire = spec_request()
    wire["methodDetails"].update(extensions)
    request = SubscriptionRequest.from_dict(wire)
    assert request.period_hours() == 720
    assert request.to_dict() == wire


def test_auth_message_is_jcs_and_binds_delegation() -> None:
    signer = Keypair.from_seed(bytes([7] * 32))
    payer = str(signer.pubkey())
    proof = sign_subscription_authentication("challenge-1", PLAN, signer)
    assert (
        proof.message_bytes(PLAN)
        == (
            '{"domain":"mpp-subscription-auth-v1","payer":"'
            + payer
            + '","subscriptionChallengeId":"challenge-1","subscriptionDelegation":"'
            + PLAN
            + '"}'
        ).encode()
    )
    assert verify_subscription_authentication(proof, PLAN)
    # A solana_pay_kit signer (``sign``) produces the same Ed25519 proof.
    assert sign_subscription_authentication("challenge-1", PLAN, LocalSigner(signer)) == proof
    assert not verify_subscription_authentication(proof, RECIPIENT)
    for forged in (
        SubscriptionAuthentication("challenge-2", payer, proof.signature),
        SubscriptionAuthentication("challenge-1", payer, "not-base58!"),
    ):
        assert not verify_subscription_authentication(forged, PLAN)


def test_period_mapping_and_bounds() -> None:
    assert [period_hours("day", n) for n in (1, 30, 365)] == [24, 720, 8760]
    assert [period_hours("week", n) for n in (1, 52)] == [168, 8736]
    for unit, count in (("day", 366), ("week", 53), ("day", 0), ("week", 0)):
        with pytest.raises(ValueError):
            period_hours(unit, count)  # type: ignore[arg-type]


def test_month_rejected() -> None:
    with pytest.raises(ValueError, match="periodUnit"):
        SubscriptionRequest.from_dict({**spec_request(), "periodUnit": "month", "periodCount": "1"})


@pytest.mark.parametrize("raw", ["030", "+1", "1e1", "0", "-1", " 1", "1.0", "\u0661", str(2**64), 10])
def test_non_canonical_integers_rejected(raw: object) -> None:
    with pytest.raises(ValueError):
        parse_positive_u64(raw, "amount")
    with pytest.raises(ValueError):
        SubscriptionRequest.from_dict({**spec_request(), "periodCount": raw})


def test_u64_max_amount_accepted() -> None:
    assert parse_positive_u64(str(2**64 - 1), "amount") == 2**64 - 1


def _without(key: str) -> dict[str, Any]:
    request = spec_request()
    del request["methodDetails"][key]
    return request


def _with(**changes: object) -> dict[str, Any]:
    request = spec_request()
    request["methodDetails"].update(changes)
    return request


@pytest.mark.parametrize(
    "request_json",
    [
        _without("planAddress"),
        _without("mint"),
        _without("decimals"),
        _without("tokenProgram"),
        _without("puller"),
        _without("subscriptionProgram"),
        _without("feePayerKey"),
        _with(decimals=True),
        _with(decimals=256),
        _with(tokenProgram="11111111111111111111111111111111"),
        _with(puller="not-a-pubkey"),
        _with(feePayer="true"),
        _with(network="mainnet-beta"),
        _with(network=None),
        {**spec_request(), "subscriptionExpires": "2026-07-14 12:00:00Z"},
        {**spec_request(), "subscriptionExpires": "2026-02-30T12:00:00Z"},
        {**spec_request(), "currency": RECIPIENT},
        {**spec_request(), "methodDetails": None},
    ],
)
def test_method_details_required_fields(request_json: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        SubscriptionRequest.from_dict(request_json)


def test_payload_rejects_signature_type() -> None:
    proof = SubscriptionAuthentication("challenge-1", PULLER, "sig").to_dict()
    activate = {"type": "transaction", "transaction": "AQAB", "authentication": proof}
    access = {"type": "proof", "subscriptionDelegation": PLAN, "authentication": proof}
    assert isinstance(parse_subscription_payload(activate), ActivatePayload)
    assert isinstance(parse_subscription_payload(access), AccessPayload)
    assert parse_subscription_payload(activate).to_dict() == activate
    assert parse_subscription_payload(access).to_dict() == access
    for bad in (
        {"type": "signature", "signature": "5J8", "transaction": "AQAB", "authentication": proof},
        {"type": "transaction", "transaction": "AQAB"},
        {"type": "transaction", "transaction": "AQAB", "authentication": {**proof, "type": "signature"}},
    ):
        with pytest.raises(ValueError):
            parse_subscription_payload(bad)
