"""Tests for challenge-driven payment-channel session opens."""

from __future__ import annotations

import base64

import pytest
from solders.hash import Hash  # type: ignore[import-untyped]
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]
from solders.transaction import Transaction  # type: ignore[import-untyped]

from solana_pay_kit._paycore.solana import TOKEN_PROGRAM
from solana_pay_kit.protocols.mpp._paymentchannels import PROGRAM_ID, find_channel_pda
from solana_pay_kit.protocols.mpp.client.payment_channels import (
    PaymentChannelOpenOptions,
    PaymentChannelSessionOpenOptions,
    build_open_payment_channel_transaction,
    create_payment_channel_session_opener,
    derive_payment_channel_open,
    generate_authorized_signer,
    unique_salt,
)
from solana_pay_kit.protocols.mpp.intents.session import SessionMethodDetails, SessionRequest, SessionSplit


def _kp(seed: int) -> Keypair:
    return Keypair.from_seed(bytes([seed] * 32))


def _request(*, fee_payer: Keypair | None = None, operator: Keypair | None = None) -> SessionRequest:
    details = SessionMethodDetails(
        network="localnet",
        channel_program=str(PROGRAM_ID),
        decimals=6,
        token_program=TOKEN_PROGRAM,
        fee_payer=fee_payer is not None,
        fee_payer_key=str(fee_payer.pubkey()) if fee_payer else None,
        voucher_signer="operator" if operator else "client",
        operator=str(operator.pubkey()) if operator else None,
        grace_period_seconds=120,
        idle_timeout_options_seconds=[30, 300],
        distribution_splits=[SessionSplit(str(_kp(9).pubkey()), 100)],
    )
    return SessionRequest(
        amount="25",
        currency="USDC",
        recipient=str(_kp(2).pubkey()),
        suggested_deposit="1000",
        method_details=details,
    )


def test_derive_uses_final_nested_challenge_fields() -> None:
    request = _request()
    payer = _kp(3).pubkey()
    authorized = _kp(4).pubkey()
    derived = derive_payment_channel_open(
        request,
        payer,
        authorized,
        PaymentChannelOpenOptions(salt=7, open_slot=42),
    )
    expected, _ = find_channel_pda(payer, _kp(2).pubkey(), derived.mint, authorized, 7, 42, PROGRAM_ID)
    assert derived.channel_id == expected
    assert derived.deposit == 1000
    assert derived.grace_period == 120
    assert derived.open_slot == 42
    assert derived.program_id == PROGRAM_ID
    assert derived.recipients[0].bps == 100


def test_derive_requires_deposit_and_open_slot() -> None:
    request = _request()
    request.suggested_deposit = None
    with pytest.raises(ValueError, match="suggestedDeposit or minimumDeposit"):
        derive_payment_channel_open(request, _kp(3).pubkey(), _kp(4).pubkey(), PaymentChannelOpenOptions(open_slot=1))
    request.suggested_deposit = "1000"
    # A new-channel challenge without recentSlot cannot derive an open when no
    # explicit openSlot override is given.
    with pytest.raises(ValueError, match="missing recentSlot"):
        derive_payment_channel_open(request, _kp(3).pubkey(), _kp(4).pubkey())


def test_derive_open_slot_defaults_to_challenged_recent_slot() -> None:
    request = _request()
    request.method_details.recent_slot = 42
    derived = derive_payment_channel_open(request, _kp(3).pubkey(), _kp(4).pubkey(), PaymentChannelOpenOptions(salt=7))
    assert derived.open_slot == 42
    # An override may be earlier than the challenged recentSlot, never later.
    earlier = derive_payment_channel_open(
        request, _kp(3).pubkey(), _kp(4).pubkey(), PaymentChannelOpenOptions(salt=7, open_slot=41)
    )
    assert earlier.open_slot == 41
    with pytest.raises(ValueError, match="ahead of the challenged recentSlot"):
        derive_payment_channel_open(
            request, _kp(3).pubkey(), _kp(4).pubkey(), PaymentChannelOpenOptions(salt=7, open_slot=43)
        )


def test_build_open_transaction_is_payer_signed() -> None:
    payer = _kp(3)
    built = build_open_payment_channel_transaction(
        _request(),
        payer,
        _kp(4).pubkey(),
        Hash.default(),
        options=PaymentChannelOpenOptions(salt=7, open_slot=42),
    )
    transaction = Transaction.from_bytes(base64.b64decode(built.transaction, validate=True))
    assert transaction.message.account_keys[0] == payer.pubkey()
    assert transaction.signatures[0] != Signature.default()


def test_sponsored_open_leaves_only_fee_payer_signature_empty() -> None:
    payer = _kp(3)
    sponsor = _kp(5)
    transaction = build_open_payment_channel_transaction(
        _request(fee_payer=sponsor),
        payer,
        _kp(4).pubkey(),
        Hash.default(),
        options=PaymentChannelOpenOptions(salt=7, open_slot=42),
    )
    decoded = Transaction.from_bytes(base64.b64decode(transaction.transaction, validate=True))
    assert decoded.message.account_keys[0] == sponsor.pubkey()
    assert decoded.signatures[0] == Signature.default()
    assert decoded.signatures[1] != Signature.default()


def test_build_open_transaction_defaults_to_challenged_blockhash() -> None:
    # No explicit blockhash: the challenged recentBlockhash is used, and the
    # derived openSlot defaults to the challenged recentSlot.
    challenged = Hash.new_unique()
    request = _request()
    request.method_details.recent_blockhash = str(challenged)
    request.method_details.recent_slot = 42
    payer = _kp(3)
    built = build_open_payment_channel_transaction(
        request,
        payer,
        _kp(4).pubkey(),
        options=PaymentChannelOpenOptions(salt=7),
    )
    decoded = Transaction.from_bytes(base64.b64decode(built.transaction, validate=True))
    assert decoded.message.recent_blockhash == challenged

    # An explicit override still wins.
    override = Hash.new_unique()
    overridden = build_open_payment_channel_transaction(
        request,
        payer,
        _kp(4).pubkey(),
        override,
        options=PaymentChannelOpenOptions(salt=7),
    )
    decoded = Transaction.from_bytes(base64.b64decode(overridden.transaction, validate=True))
    assert decoded.message.recent_blockhash == override


def test_build_open_transaction_requires_challenged_blockhash() -> None:
    # A new-channel challenge without recentBlockhash cannot build the open
    # transaction when no explicit override is given.
    request = _request()
    request.method_details.recent_slot = 42
    with pytest.raises(ValueError, match="missing recentBlockhash"):
        build_open_payment_channel_transaction(
            request,
            _kp(3),
            _kp(4).pubkey(),
            options=PaymentChannelOpenOptions(salt=7),
        )
    request.method_details.recent_blockhash = "not-a-blockhash"
    with pytest.raises(ValueError, match="invalid challenged recentBlockhash"):
        build_open_payment_channel_transaction(
            request,
            _kp(3),
            _kp(4).pubkey(),
            options=PaymentChannelOpenOptions(salt=7),
        )


def test_session_opener_defaults_to_challenged_context() -> None:
    challenged = Hash.new_unique()
    request = _request()
    request.method_details.recent_blockhash = str(challenged)
    request.method_details.recent_slot = 42
    opened = create_payment_channel_session_opener(
        request,
        _kp(3),
        _kp(4),
        options=PaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(salt=7)),
    )
    assert opened.open.open_slot == 42
    payload = opened.action.open
    assert payload is not None
    decoded = Transaction.from_bytes(base64.b64decode(payload.transaction, validate=True))
    assert decoded.message.recent_blockhash == challenged

    request.method_details.recent_blockhash = None
    with pytest.raises(ValueError, match="missing recentBlockhash"):
        create_payment_channel_session_opener(
            request,
            _kp(3),
            _kp(4),
            options=PaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(salt=7)),
        )


def test_session_opener_emits_exact_open_action() -> None:
    payer = _kp(3)
    session_signer = _kp(4)
    opened = create_payment_channel_session_opener(
        _request(),
        payer,
        session_signer,
        Hash.default(),
        PaymentChannelSessionOpenOptions(
            open=PaymentChannelOpenOptions(salt=7, open_slot=42),
            idle_timeout_seconds=30,
        ),
    )
    wire = opened.action.to_dict()
    assert wire["action"] == "open"
    assert wire["channelId"] == str(opened.open.channel_id)
    assert wire["depositAmount"] == "1000"
    assert wire["openSlot"] == "42"
    assert wire["transaction"]
    assert "mode" not in wire
    assert opened.session.channel_id == opened.open.channel_id


def test_operator_opener_requires_and_uses_operator_authority() -> None:
    payer = _kp(3)
    operator = _kp(6)
    with pytest.raises(ValueError, match="authentication"):
        create_payment_channel_session_opener(
            _request(operator=operator),
            payer,
            _kp(4),
            Hash.default(),
            PaymentChannelSessionOpenOptions(open=PaymentChannelOpenOptions(salt=7, open_slot=42)),
        )


def test_unique_salt_and_generated_signer() -> None:
    assert 0 <= unique_salt() <= 2**64 - 1
    signer = generate_authorized_signer()
    assert len(bytes(signer.pubkey())) == 32
