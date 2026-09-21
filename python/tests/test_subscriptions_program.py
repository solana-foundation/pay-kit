"""Tests for the subscriptions program glue.

Layouts are checked against ``struct``-packed program bytes and the IDL-derived
PDA helpers, not against the glue's own encoders. Mirrors
``rust/crates/kit/src/mpp/program/subscriptions.rs`` and the decoder tests in
``rust/crates/kit/src/mpp/server/subscription.rs``.
"""

from __future__ import annotations

import struct
from dataclasses import replace

import pytest
from solders.pubkey import Pubkey

from solana_pay_kit._paycore.paymentchannels import find_associated_token_address
from solana_pay_kit._paycore.solana import SYSTEM_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit.protocols.mpp._subscriptions import (
    SUBSCRIPTIONS_PROGRAM_ID,
    UNKNOWN_INIT_ID,
    PlanView,
    authority_init_id,
    build_create_plan_ix,
    build_init_subscription_authority_ix,
    build_subscribe_ix,
    build_transfer_subscription_ix,
    decode_authority_init_id,
    decode_delegation,
    decode_plan,
    find_event_authority_pda,
    find_plan_pda,
    find_subscription_authority_pda,
    find_subscription_pda,
    plan_problems,
)
from solana_pay_kit.protocols.programs.subscriptions.pdas import index as idl_pdas
from tests._subscription_fixtures import authority_bytes, delegation_bytes, pk, plan_bytes

PROGRAM = Pubkey.from_string(SUBSCRIPTIONS_PROGRAM_ID)
TOKEN = Pubkey.from_string(TOKEN_PROGRAM)
OWNER, MINT, RECIPIENT, SUBSCRIBER, PULLER, SPONSOR = pk(1), pk(2), pk(3), pk(4), pk(5), pk(6)
PLAN_ADDRESS = pk(9)


def plan_view(**overrides: object) -> PlanView:
    view = decode_plan(
        plan_bytes(owner=OWNER, mint=MINT, destinations=[RECIPIENT], pullers=[PULLER]),
        SUBSCRIPTIONS_PROGRAM_ID,
        SUBSCRIPTIONS_PROGRAM_ID,
        PLAN_ADDRESS,
    )
    return replace(view, **overrides)  # type: ignore[arg-type]


def test_pda_vectors() -> None:
    # The generated helpers take their seeds from the IDL, so a typo in a
    # hand-written seed shows up here.
    assert find_plan_pda(OWNER, 42, PROGRAM) == idl_pdas.find_plan_pda(OWNER, 42)
    assert (
        find_subscription_pda(PLAN_ADDRESS, SUBSCRIBER, PROGRAM)
        == (idl_pdas.find_subscription_delegation_pda(PLAN_ADDRESS, SUBSCRIBER)[0])
    )
    assert (
        find_subscription_authority_pda(SUBSCRIBER, MINT, PROGRAM)
        == (idl_pdas.find_subscription_authority_pda(SUBSCRIBER, MINT)[0])
    )
    assert find_event_authority_pda(PROGRAM) == idl_pdas.find_event_authority_pda()[0]


def test_subscribe_data_layout() -> None:
    plan = plan_view()
    ix = build_subscribe_ix(program=PROGRAM, subscriber=SUBSCRIBER, plan=plan, init_id=UNKNOWN_INIT_ID, payer=None)
    assert ix.program_id == PROGRAM
    assert bytes(ix.data) == (
        bytes([11])
        + struct.pack("<QB", 7, 254)
        + bytes(MINT)
        + struct.pack("<QQqq", 1_000_000, 720, 1_700_000_000, -(2**63))
    )
    assert len(ix.data) == 74
    assert [(m.pubkey, m.is_signer, m.is_writable) for m in ix.accounts] == [
        (SUBSCRIBER, True, True),
        (OWNER, False, False),
        (PLAN_ADDRESS, False, False),
        (find_subscription_pda(PLAN_ADDRESS, SUBSCRIBER, PROGRAM), False, True),
        (find_subscription_authority_pda(SUBSCRIBER, MINT, PROGRAM), False, False),
        (Pubkey.from_string(SYSTEM_PROGRAM), False, False),
        (find_event_authority_pda(PROGRAM), False, False),
        (PROGRAM, False, False),
    ]


def test_transfer_data_layout() -> None:
    ix = build_transfer_subscription_ix(
        program=PROGRAM,
        subscriber=SUBSCRIBER,
        plan=plan_view(),
        recipient=RECIPIENT,
        puller=PULLER,
        token_program=TOKEN,
        amount=1_000_000,
    )
    assert bytes(ix.data) == bytes([10]) + struct.pack("<Q", 1_000_000) + bytes(SUBSCRIBER) + bytes(MINT)
    assert [(m.pubkey, m.is_signer, m.is_writable) for m in ix.accounts] == [
        (find_subscription_pda(PLAN_ADDRESS, SUBSCRIBER, PROGRAM), False, True),
        (PLAN_ADDRESS, False, False),
        (find_subscription_authority_pda(SUBSCRIBER, MINT, PROGRAM), False, False),
        (find_associated_token_address(SUBSCRIBER, MINT, TOKEN)[0], False, True),
        (find_associated_token_address(RECIPIENT, MINT, TOKEN)[0], False, True),
        (PULLER, True, False),
        (MINT, False, False),
        (TOKEN, False, False),
        (find_event_authority_pda(PROGRAM), False, False),
        (PROGRAM, False, False),
    ]


def test_optional_payer_meta_dropped() -> None:
    # codama-py ignores isOptional; the program treats any 9th subscribe meta
    # (7th init meta) as the rent payer, so it must be absent unless sponsored.
    plan = plan_view()
    sponsored = build_subscribe_ix(program=PROGRAM, subscriber=SUBSCRIBER, plan=plan, init_id=0, payer=SPONSOR)
    assert len(sponsored.accounts) == 9
    last = sponsored.accounts[8]
    assert (last.pubkey, last.is_signer, last.is_writable) == (SPONSOR, True, True)

    init = build_init_subscription_authority_ix(program=PROGRAM, subscriber=SUBSCRIBER, mint=MINT, token_program=TOKEN)
    assert bytes(init.data) == bytes([0])
    assert [(m.pubkey, m.is_signer, m.is_writable) for m in init.accounts] == [
        (SUBSCRIBER, True, True),
        (find_subscription_authority_pda(SUBSCRIBER, MINT, PROGRAM), False, True),
        (MINT, False, False),
        (find_associated_token_address(SUBSCRIBER, MINT, TOKEN)[0], False, True),
        (Pubkey.from_string(SYSTEM_PROGRAM), False, False),
        (TOKEN, False, False),
    ]


def test_create_plan_round_trips_through_decode_plan() -> None:
    ix = build_create_plan_ix(
        program=PROGRAM,
        owner=OWNER,
        plan_id=42,
        mint=MINT,
        token_program=TOKEN,
        amount=5_000,
        period_hours=24,
        created_at=0,
        destinations=[RECIPIENT],
        pullers=[PULLER],
        end_ts=1_900_000_000,
    )
    address, bump = find_plan_pda(OWNER, 42, PROGRAM)
    assert [(m.pubkey, m.is_signer, m.is_writable) for m in ix.accounts] == [
        (OWNER, True, True),
        (address, False, True),
        (MINT, False, False),
        (Pubkey.from_string(SYSTEM_PROGRAM), False, False),
        (TOKEN, False, False),
    ]
    assert ix.data[0] == 7 and len(ix.data) == 1 + 456
    account = bytes([1]) + bytes(OWNER) + bytes([bump, 1]) + bytes(ix.data[1:])
    plan = decode_plan(account, SUBSCRIPTIONS_PROGRAM_ID, SUBSCRIPTIONS_PROGRAM_ID, address)
    assert (plan.plan_id, plan.mint, plan.amount, plan.period_hours) == (42, MINT, 5_000, 24)
    assert plan.end_ts == 1_900_000_000
    assert (plan.destinations, plan.pullers) == ((RECIPIENT,), (PULLER,))


def test_decode_delegation_offsets() -> None:
    data = delegation_bytes(
        subscriber=SUBSCRIBER,
        plan=PLAN_ADDRESS,
        init_id=77,
        amount=9_990_000,
        period_hours=720,
        created_at=1_780_000_000,
        amount_pulled_in_period=9_990_000,
        current_period_start_ts=1_700_000_000,
        expires_at_ts=1_700_500_000,
    )
    assert len(data) == 155
    view = decode_delegation(data, SUBSCRIPTIONS_PROGRAM_ID, SUBSCRIPTIONS_PROGRAM_ID)
    assert (view.subscriber, view.plan, view.init_id) == (SUBSCRIBER, PLAN_ADDRESS, 77)
    assert (view.amount, view.period_hours, view.created_at) == (9_990_000, 720, 1_780_000_000)
    assert (view.amount_pulled_in_period, view.current_period_start_ts, view.expires_at_ts) == (
        9_990_000,
        1_700_000_000,
        1_700_500_000,
    )


def test_decode_plan_and_authority_offsets() -> None:
    data = plan_bytes(
        owner=OWNER,
        mint=MINT,
        destinations=[RECIPIENT],
        pullers=[PULLER, SPONSOR],
        plan_id=42,
        bump=251,
        status=0,
        amount=5_000,
        period_hours=168,
        created_at=1_700_000_000,
        end_ts=1_800_000_000,
    )
    assert len(data) == 491
    plan = decode_plan(data, SUBSCRIPTIONS_PROGRAM_ID, SUBSCRIPTIONS_PROGRAM_ID, PLAN_ADDRESS)
    assert (plan.address, plan.owner, plan.bump, plan.status, plan.plan_id) == (PLAN_ADDRESS, OWNER, 251, 0, 42)
    assert (plan.mint, plan.amount, plan.period_hours, plan.created_at, plan.end_ts) == (
        MINT,
        5_000,
        168,
        1_700_000_000,
        1_800_000_000,
    )
    assert (plan.destinations, plan.pullers) == ((RECIPIENT,), (PULLER, SPONSOR))

    authority = authority_bytes(user=SUBSCRIBER, mint=MINT, init_id=-5)
    assert decode_authority_init_id(authority, SUBSCRIPTIONS_PROGRAM_ID, SUBSCRIPTIONS_PROGRAM_ID) == -5


_FOREIGN = str(pk(8))
_PLAN = plan_bytes(owner=OWNER, mint=MINT, destinations=[RECIPIENT])
_DELEGATION = delegation_bytes(subscriber=SUBSCRIBER, plan=PLAN_ADDRESS)
_AUTHORITY = authority_bytes(user=SUBSCRIBER, mint=MINT)
_OWNED = SUBSCRIPTIONS_PROGRAM_ID


@pytest.mark.parametrize(
    ("decoder", "data", "owner"),
    [
        ("plan", bytes([4]) + _PLAN[1:], _OWNED),
        ("plan", _PLAN + b"\0", _OWNED),
        ("plan", _PLAN, _FOREIGN),
        ("plan", _PLAN[:-128] + b"\xff" + _PLAN[-127:], _OWNED),  # metadataUri is not UTF-8
        ("delegation", bytes([2]) + _DELEGATION[1:], _OWNED),
        ("delegation", _DELEGATION[:1] + bytes([2]) + _DELEGATION[2:], _OWNED),
        ("delegation", _DELEGATION[:50], _OWNED),
        ("delegation", _DELEGATION, _FOREIGN),
        ("authority", bytes([1]) + _AUTHORITY[1:], _OWNED),
        ("authority", _AUTHORITY + b"\0", _OWNED),
        ("authority", _AUTHORITY, _FOREIGN),
        ("authority", b"", _OWNED),
    ],
)
def test_decoders_reject_wrong_disc_len_owner(decoder: str, data: bytes, owner: str) -> None:
    with pytest.raises(ValueError):
        if decoder == "plan":
            decode_plan(data, owner, SUBSCRIPTIONS_PROGRAM_ID, PLAN_ADDRESS)
        elif decoder == "delegation":
            decode_delegation(data, owner, SUBSCRIPTIONS_PROGRAM_ID)
        else:
            decode_authority_init_id(data, owner, SUBSCRIPTIONS_PROGRAM_ID)


_TERMS = {
    "mint": str(MINT),
    "amount": 1_000_000,
    "period_hours": 720,
    "recipient": str(RECIPIENT),
    "puller": str(PULLER),
    "now": 1_750_000_000,
}


@pytest.mark.parametrize(
    ("plan_changes", "term_changes", "expected"),
    [
        ({}, {}, None),
        ({}, {"puller": str(OWNER)}, None),
        ({"destinations": ()}, {}, "destinations"),
        ({"destinations": (RECIPIENT, SPONSOR)}, {}, "destinations"),
        ({"destinations": (SPONSOR,)}, {}, "destinations"),
        ({}, {"puller": str(SPONSOR)}, "puller"),
        ({"mint": SPONSOR}, {}, "mint"),
        ({"amount": 999_999}, {}, "amount"),
        ({"period_hours": 24}, {}, "period"),
        ({"status": 0}, {}, "not active"),
        ({"end_ts": 1_750_000_000}, {}, "ended"),
    ],
)
def test_plan_problems_each_rule(
    plan_changes: dict[str, object], term_changes: dict[str, object], expected: str | None
) -> None:
    problems = plan_problems(plan_view(**plan_changes), **{**_TERMS, **term_changes})  # type: ignore[arg-type]
    if expected is None:
        assert problems == []
    else:
        assert len(problems) == 1 and expected in problems[0], problems


def test_authority_init_id_treats_a_prefunded_pda_as_missing() -> None:
    # The program initializes an authority PDA with empty data even when it holds lamports.
    assert authority_init_id(None, SUBSCRIPTIONS_PROGRAM_ID) is None
    assert authority_init_id((b"", SYSTEM_PROGRAM), SUBSCRIPTIONS_PROGRAM_ID) is None
    authority = authority_bytes(user=SUBSCRIBER, mint=MINT, init_id=42)
    assert authority_init_id((authority, SUBSCRIPTIONS_PROGRAM_ID), SUBSCRIPTIONS_PROGRAM_ID) == 42
    with pytest.raises(ValueError):
        authority_init_id((b"\x00", SYSTEM_PROGRAM), SUBSCRIPTIONS_PROGRAM_ID)
