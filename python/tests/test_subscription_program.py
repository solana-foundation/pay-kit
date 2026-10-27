"""Subscriptions program helpers: PDAs, instruction data, builders, account decoders."""

from __future__ import annotations

import pytest
from solders.pubkey import Pubkey

from solana_pay_kit.protocols.mpp.program.subscriptions import (
    INSTRUCTION_TRANSFER_SUBSCRIPTION,
    PlanAccount,
    SubscribeData,
    SubscriptionProgramError,
    TransferData,
    build_create_idempotent_ata_ix,
    build_initialize_subscription_authority_ix,
    build_memo_ix,
    build_subscribe_ix,
    build_transfer_subscription_ix,
    decode_subscription_authority_init_id,
    decode_subscription_delegation,
    default_program_id,
    find_event_authority_pda,
    find_subscription_authority_pda,
    find_subscription_pda,
    non_zero,
    parse_pubkey,
    parse_subscription_authority_init_id,
)
from tests import _subscription_fixture as fx

# Frozen by harness/vectors/subscription-canonical.json.
_PLAN = Pubkey.from_string("HwAK86K8LTVqmactps2Dro8oCqBvJyPwVWiZo4FiT6dK")
_SUBSCRIBER = Pubkey.from_string("GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB")


def test_pdas_match_the_frozen_vectors() -> None:
    program = default_program_id()
    assert str(find_subscription_pda(_PLAN, _SUBSCRIBER, program)[0]) == "AwCtiXLhCLxYytJ9Gz5qQBd8GxY6GrwfRdeevPysEgJy"
    assert (
        str(find_subscription_authority_pda(_SUBSCRIBER, fx.MINT, program)[0])
        == "HDfdM5VHN3zD94ZUp9J7tsPKGi8kfsoozfBGGbcAgLkY"
    )


def test_subscribe_data_layout() -> None:
    data = SubscribeData(
        plan_id=7,
        plan_bump=253,
        expected_mint=fx.MINT,
        expected_amount=10_000_000,
        expected_period_hours=720,
        expected_created_at=1_700_000_000,
        expected_subscription_authority_init_id=77,
    ).to_bytes()
    assert len(data) == 74
    assert data[:10] == bytes([11, 7, 0, 0, 0, 0, 0, 0, 0, 253])
    assert data[10:42] == bytes(fx.MINT)
    assert data[-8:] == (77).to_bytes(8, "little")


def test_transfer_data_round_trip_and_length() -> None:
    data = TransferData(amount=5, delegator=_SUBSCRIBER, mint=fx.MINT)
    raw = data.to_bytes()
    assert raw[0] == INSTRUCTION_TRANSFER_SUBSCRIPTION and len(raw) == 73
    assert TransferData.from_bytes(raw) == data
    with pytest.raises(SubscriptionProgramError, match="73"):
        TransferData.from_bytes(raw[:-1])


def test_parse_pubkey_names_the_field() -> None:
    with pytest.raises(SubscriptionProgramError, match="Invalid planAddress pubkey"):
        parse_pubkey("not-a-key", "planAddress")


def test_builders_follow_the_program_account_layouts() -> None:
    program = default_program_id()
    key = fx.SUBSCRIBER.pubkey()
    data = SubscribeData(1, 2, fx.MINT, 3, 24, 0, 0)
    plain = build_subscribe_ix(
        program,
        subscriber=key,
        merchant=key,
        plan_pda=key,
        subscription_pda=key,
        subscription_authority_pda=key,
        event_authority=key,
        data=data,
    )
    sponsored = build_subscribe_ix(
        program,
        subscriber=key,
        merchant=key,
        plan_pda=key,
        subscription_pda=key,
        subscription_authority_pda=key,
        event_authority=key,
        data=data,
        payer=fx.SPONSOR.pubkey(),
    )
    assert len(plain.accounts) == 8 and len(sponsored.accounts) == 9
    assert sponsored.accounts[8].is_signer and sponsored.accounts[8].is_writable
    transfer = build_transfer_subscription_ix(
        program,
        subscription_pda=key,
        plan_pda=key,
        subscription_authority=key,
        delegator_ata=key,
        receiver_ata=key,
        caller=fx.MERCHANT.pubkey(),
        token_mint=fx.MINT,
        token_program=key,
        event_authority=find_event_authority_pda(program)[0],
        data=TransferData(1, key, fx.MINT),
    )
    assert len(transfer.accounts) == 10
    assert transfer.accounts[5].is_signer and not transfer.accounts[5].is_writable
    init = build_initialize_subscription_authority_ix(
        program, owner=key, subscription_authority=key, token_mint=fx.MINT, user_ata=key, token_program=key
    )
    assert bytes(init.data) == bytes([0]) and len(init.accounts) == 6
    ata = build_create_idempotent_ata_ix(key, key, key, fx.MINT, key)
    assert bytes(ata.data) == bytes([1]) and len(ata.accounts) == 6
    assert bytes(build_memo_ix("ref").data) == b"ref"


def test_plan_decoder() -> None:
    plan = PlanAccount.from_bytes(fx.plan_data(pullers=[fx.SPONSOR.pubkey()]))
    assert plan.owner == fx.MERCHANT.pubkey() and plan.plan_id == fx.PLAN_ID
    assert plan.amount == fx.AMOUNT and plan.period_hours == 720 and plan.created_at == fx.CREATED_AT
    assert non_zero(plan.destinations) == [fx.RECIPIENT.pubkey()]
    assert non_zero(plan.pullers) == [fx.SPONSOR.pubkey()]
    with pytest.raises(SubscriptionProgramError, match="at least"):
        PlanAccount.from_bytes(bytes(10))


def test_authority_decoders() -> None:
    assert parse_subscription_authority_init_id(fx.authority_data(init_id=-3)) == -3
    assert decode_subscription_authority_init_id(fx.authority_data()) == fx.INIT_ID
    with pytest.raises(SubscriptionProgramError, match="length"):
        parse_subscription_authority_init_id(bytes(10))
    with pytest.raises(SubscriptionProgramError, match="discriminator"):
        decode_subscription_authority_init_id(fx.authority_data(discriminator=1))


def test_delegation_decoder() -> None:
    view = decode_subscription_delegation(fx.delegation_data(expires_at=9))
    assert view.subscriber == fx.SUBSCRIBER.pubkey() and view.plan_pda == fx.PLAN
    assert view.authority_init_id == fx.INIT_ID and view.amount_per_period == fx.AMOUNT
    assert view.period_hours == 720 and view.amount_pulled_in_period == fx.AMOUNT
    assert view.current_period_start_ts == fx.NOW - 3600 and view.expires_at_ts == 9
    with pytest.raises(SubscriptionProgramError, match="length"):
        decode_subscription_delegation(fx.delegation_data() + b"\x00")
    with pytest.raises(SubscriptionProgramError, match="discriminator/version"):
        decode_subscription_delegation(fx.delegation_data(version=2))
