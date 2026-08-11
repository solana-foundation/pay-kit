"""Tests for the final MPP session wire contract."""

from __future__ import annotations

import struct

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]

from solana_pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    ClosePayload,
    OpenPayload,
    SessionAction,
    SessionAuthentication,
    SessionMethodDetails,
    SessionRequest,
    SessionSplit,
    SignedVoucher,
    TopUpPayload,
    UsePayload,
    VoucherData,
    VoucherPayload,
    resolve_idle_timeout_seconds,
    sign_session_authentication,
    verify_session_authentication,
)


def _details() -> SessionMethodDetails:
    return SessionMethodDetails(
        network="devnet",
        channel_program="program",
        decimals=6,
        token_program="token-program",
        voucher_signer="operator",
        operator="operator",
        grace_period_seconds=900,
        idle_timeout_options_seconds=[30, 300],
        distribution_splits=[SessionSplit("split", 100)],
    )


def _open() -> OpenPayload:
    return OpenPayload(
        channel_id="channel",
        payer="payer",
        payee="payee",
        mint="mint",
        authorized_signer="signer",
        salt=7,
        deposit_amount="1000",
        grace_period_seconds=900,
        idle_timeout_seconds=30,
        open_slot=42,
        transaction="transaction",
    )


def _voucher() -> SignedVoucher:
    signer = Keypair.from_seed(bytes([7] * 32))
    data = VoucherData(
        channel_id=str(signer.pubkey()),
        cumulative_amount="500",
        expires_at=DEFAULT_SESSION_EXPIRES_AT,
    )
    return SignedVoucher(
        data=data, signer=str(signer.pubkey()), signature=str(signer.sign_message(data.message_bytes()))
    )


def test_session_request_exact_nested_shape_roundtrips() -> None:
    request = SessionRequest(
        amount="25",
        currency="USDC",
        recipient="recipient",
        method_details=_details(),
        description="metered API",
        external_id="order-1",
        minimum_deposit="100",
        suggested_deposit="1000",
        unit_type="request",
    )

    wire = request.to_dict()
    assert wire == {
        "amount": "25",
        "currency": "USDC",
        "recipient": "recipient",
        "description": "metered API",
        "externalId": "order-1",
        "minimumDeposit": "100",
        "suggestedDeposit": "1000",
        "unitType": "request",
        "methodDetails": {
            "network": "devnet",
            "channelProgram": "program",
            "decimals": 6,
            "tokenProgram": "token-program",
            "voucherSigner": "operator",
            "operator": "operator",
            "idleTimeoutOptionsSeconds": [30, 300],
            "gracePeriodSeconds": 900,
            "distributionSplits": [{"recipient": "split", "shareBps": 100}],
        },
    }
    assert SessionRequest.from_dict(wire) == request
    for stale in ("cap", "programId", "deposit", "recentSlot", "gracePeriod"):
        assert stale not in wire


@pytest.mark.parametrize("missing", ["amount", "currency", "recipient", "methodDetails"])
def test_session_request_rejects_missing_required_fields(missing: str) -> None:
    # The wire parser must refuse a request lacking a required field instead
    # of defaulting it — a pre-e702dd8 draft request (cap/programId, no
    # amount/methodDetails) must fail the parse, matching the Rust spine.
    wire = SessionRequest(amount="25", currency="USDC", recipient="recipient", method_details=_details()).to_dict()
    del wire[missing]
    with pytest.raises(ValueError):
        SessionRequest.from_dict(wire)


@pytest.mark.parametrize("missing", ["network", "channelProgram"])
def test_method_details_rejects_missing_required_fields(missing: str) -> None:
    wire = _details().to_dict()
    del wire[missing]
    with pytest.raises(ValueError):
        SessionMethodDetails.from_dict(wire)


def test_method_details_new_channel_context_is_decimal_string_on_the_wire() -> None:
    # A new-channel challenge (no channelId) carries the open-transaction
    # context: recentBlockhash as base58, recentSlot as a u64 decimal string.
    details = _details()
    details.recent_blockhash = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
    details.recent_slot = 42
    wire = details.to_dict()
    assert wire["recentBlockhash"] == "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
    assert wire["recentSlot"] == "42"
    assert SessionMethodDetails.from_dict(wire) == details


def test_method_details_resume_challenge_omits_open_transaction_context() -> None:
    # A resume challenge (channelId present) MUST NOT carry
    # recentBlockhash/recentSlot; unset fields stay off the wire.
    details = _details()
    details.channel_id = "channel"
    wire = details.to_dict()
    assert wire["channelId"] == "channel"
    assert "recentBlockhash" not in wire
    assert "recentSlot" not in wire
    parsed = SessionMethodDetails.from_dict(wire)
    assert parsed.recent_blockhash is None
    assert parsed.recent_slot is None


def test_open_payload_uses_exact_string_amount_and_slot_fields() -> None:
    payload = _open()
    wire = payload.to_dict()
    assert wire["depositAmount"] == "1000"
    assert wire["salt"] == "7"
    assert wire["openSlot"] == "42"
    assert wire["gracePeriodSeconds"] == 900
    assert OpenPayload.from_dict(wire) == payload

    with pytest.raises(ValueError, match="must not include bump"):
        OpenPayload.from_dict({**wire, "bump": 255})
    for stale in ("deposit", "recentSlot", "programId", "mode"):
        assert stale not in wire


@pytest.mark.parametrize("field", ["depositAmount", "salt", "openSlot", "transaction"])
def test_open_payload_rejects_non_string_wire_fields(field: str) -> None:
    wire = _open().to_dict()
    wire[field] = 1
    with pytest.raises(ValueError):
        OpenPayload.from_dict(wire)


def test_action_union_contains_only_final_actions() -> None:
    authentication = SessionAuthentication("challenge", "payer", "signature")
    voucher = _voucher()
    actions = [
        SessionAction.open_action(_open()),
        SessionAction.voucher_action(VoucherPayload(voucher.data.channel_id, voucher)),
        SessionAction.use_action(UsePayload("channel", authentication)),
        SessionAction.top_up_action(TopUpPayload("channel", "10", "transaction")),
        SessionAction.close_action(ClosePayload("channel", voucher=voucher)),
    ]
    assert [action.to_dict()["action"] for action in actions] == ["open", "voucher", "use", "topUp", "close"]
    assert [SessionAction.from_dict(action.to_dict()) for action in actions] == actions
    with pytest.raises(ValueError, match="unknown action"):
        SessionAction.from_dict({"action": "commit"})


def test_voucher_wire_and_message_layout() -> None:
    voucher = _voucher()
    wire = voucher.to_dict()
    assert wire["signatureType"] == "ed25519"
    # Spec wire shape (mpp-specs e702dd8): the inner data field is named
    # `voucher`, not `data`.
    assert "data" not in wire
    assert wire["voucher"]["cumulativeAmount"] == "500"
    assert "cumulative" not in wire["voucher"]
    message = voucher.data.message_bytes()
    assert len(message) == 50
    assert message[:2] == bytes([0x56, 0x01])
    assert struct.unpack("<Q", message[34:42])[0] == 500
    assert SignedVoucher.from_dict(wire) == voucher


def test_no_expiry_voucher_preimage_encodes_zero_verbatim() -> None:
    """An omitted expiresAt is never-expires and must encode as 0 in the signed
    50-byte preimage, exactly as Rust (``unwrap_or(0)``) and TS (``?? 0``)
    encode it. Substituting a sentinel would reconstruct different bytes than
    the counterparty signed, failing cross-SDK signature verification, and
    would silently turn never-expires into a real on-chain expiry."""
    signer = Keypair.from_seed(bytes([7] * 32))
    omitted = VoucherData(channel_id=str(signer.pubkey()), cumulative_amount="500", expires_at=None)
    explicit_zero = VoucherData(channel_id=str(signer.pubkey()), cumulative_amount="500", expires_at=0)
    message = omitted.message_bytes()
    assert len(message) == 50
    assert struct.unpack("<q", message[42:50])[0] == 0
    # The omitted and explicit-zero forms are the same signed statement.
    assert message == explicit_zero.message_bytes()


def test_authentication_is_bound_to_opening_challenge_and_channel() -> None:
    signer = Keypair.from_seed(bytes([3] * 32))
    authentication = sign_session_authentication("opening-challenge", "channel", signer)
    assert authentication.to_dict()["type"] == "proof"
    assert verify_session_authentication(authentication, "channel")
    assert not verify_session_authentication(authentication, "different-channel")


def test_idle_timeout_selection_must_be_advertised() -> None:
    assert resolve_idle_timeout_seconds(300, [30, 300], 30) == 30
    with pytest.raises(ValueError, match="advertised options"):
        resolve_idle_timeout_seconds(300, [30, 300], 60)
