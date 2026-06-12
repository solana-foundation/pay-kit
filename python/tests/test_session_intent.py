"""Tests for the session intent wire types.

Mirrors the ``#[cfg(test)] mod tests`` in
``rust/crates/mpp/src/protocol/intents/session.rs`` and the parity-verified Go
port. Asserts mode/strategy serde, ``SessionRequest`` omit-empty parity,
``SessionAction`` round-trips for all five actions (including the ``"topUp"``
camelCase tag), salt decimal-string out / string-or-number in, the
``cumulative`` decode alias, push/pull discrimination, the missing-mode error,
and the 48-byte voucher message layout.
"""

from __future__ import annotations

import struct

import pytest

from pay_kit.protocols.mpp.intents.session import (
    DEFAULT_SESSION_EXPIRES_AT,
    ClosePayload,
    CommitPayload,
    CommitReceipt,
    MeteredEnvelope,
    MeteringDirective,
    MeteringUsage,
    OpenPayload,
    SessionAction,
    SessionMode,
    SessionPullVoucherStrategy,
    SessionRequest,
    SessionSplit,
    SignedVoucher,
    TopUpPayload,
    VoucherData,
    VoucherPayload,
)


def _voucher(channel_id: str = "chan1", cumulative: str = "500000", nonce: int | None = 3) -> SignedVoucher:
    return SignedVoucher(
        data=VoucherData(
            channel_id=channel_id,
            cumulative=cumulative,
            expires_at=DEFAULT_SESSION_EXPIRES_AT,
            nonce=nonce,
        ),
        signature="sig_here",
    )


# ── Constants ──


def test_default_session_expires_at():
    assert DEFAULT_SESSION_EXPIRES_AT == 4_102_444_800


# ── SessionMode / SessionPullVoucherStrategy serde ──


@pytest.mark.parametrize("mode", ["push", "pull"])
def test_session_mode_roundtrips_on_request(mode: SessionMode):
    req = SessionRequest(cap="1", currency="USDC", operator="op", recipient="rec", modes=[mode])
    assert req.to_dict()["modes"] == [mode]
    assert SessionRequest.from_dict(req.to_dict()).modes == [mode]


@pytest.mark.parametrize("strategy", ["clientVoucher", "operatedVoucher"])
def test_pull_voucher_strategy_roundtrips(strategy: SessionPullVoucherStrategy):
    req = SessionRequest(
        cap="1",
        currency="USDC",
        operator="op",
        recipient="rec",
        modes=["pull"],
        pull_voucher_strategy=strategy,
    )
    d = req.to_dict()
    assert d["pullVoucherStrategy"] == strategy
    assert SessionRequest.from_dict(d).pull_voucher_strategy == strategy


# ── SessionRequest ──


def test_session_request_full_roundtrip():
    req = SessionRequest(
        cap="10000000",
        currency="USDC",
        operator="CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
        recipient="CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
        decimals=6,
        network="mainnet",
        description="API session",
        modes=["push"],
    )
    back = SessionRequest.from_dict(req.to_dict())
    assert back.cap == "10000000"
    assert back.currency == "USDC"
    assert back.description == "API session"
    assert back.decimals == 6
    assert back.modes == ["push"]


def test_session_request_omits_empty_optionals():
    req = SessionRequest(cap="1000", currency="USDC", operator="op", recipient="rec")
    d = req.to_dict()
    for key in (
        "splits",
        "modes",
        "decimals",
        "network",
        "description",
        "externalId",
        "programId",
        "minVoucherDelta",
        "pullVoucherStrategy",
        "recentBlockhash",
    ):
        assert key not in d
    # Required fields are always present.
    assert d["cap"] == "1000"
    assert d["operator"] == "op"
    assert d["recipient"] == "rec"


def test_session_request_with_modes_push_and_pull():
    req = SessionRequest(
        cap="1000",
        currency="USDC",
        operator="op",
        recipient="rec",
        modes=["push", "pull"],
        pull_voucher_strategy="clientVoucher",
    )
    d = req.to_dict()
    assert d["modes"] == ["push", "pull"]
    assert d["pullVoucherStrategy"] == "clientVoucher"
    back = SessionRequest.from_dict(d)
    assert back.modes == ["push", "pull"]
    assert back.pull_voucher_strategy == "clientVoucher"


def test_session_request_with_splits_and_ids():
    req = SessionRequest(
        cap="1000",
        currency="USDC",
        operator="op",
        recipient="rec",
        splits=[SessionSplit("s1", 100), SessionSplit("s2", 200)],
        program_id="prog123",
        external_id="ref-1",
    )
    d = req.to_dict()
    assert d["splits"] == [{"recipient": "s1", "bps": 100}, {"recipient": "s2", "bps": 200}]
    back = SessionRequest.from_dict(d)
    assert len(back.splits) == 2
    assert back.splits[0].bps == 100
    assert back.program_id == "prog123"
    assert back.external_id == "ref-1"


def test_session_request_min_voucher_delta_present_and_omitted():
    with_delta = SessionRequest(
        cap="1", currency="USDC", operator="op", recipient="rec", min_voucher_delta="500"
    ).to_dict()
    assert with_delta["minVoucherDelta"] == "500"

    without = SessionRequest(cap="1", currency="USDC", operator="op", recipient="rec").to_dict()
    assert "minVoucherDelta" not in without


# ── OpenPayload constructors ──


def test_open_payload_push_fields():
    p = OpenPayload.push("chan1", "1000000", "signer1", "txsig")
    assert p.mode == "push"
    assert p.channel_id == "chan1"
    assert p.deposit == "1000000"
    assert p.token_account is None
    assert p.approved_amount is None
    assert p.authorized_signer == "signer1"
    assert p.signature == "txsig"


def test_open_payload_pull_fields():
    p = OpenPayload.pull("tokacct", "5000000", "wallet1", "signer1", "approvesig")
    assert p.mode == "pull"
    assert p.channel_id is None
    assert p.deposit is None
    assert p.token_account == "tokacct"
    assert p.approved_amount == "5000000"
    assert p.owner == "wallet1"


def test_open_payload_payment_channel_and_tx_helpers():
    p = (
        OpenPayload.payment_channel("chan1", "1000000", "payer1", "payee1", "mint1", 99, 45, "signer1", "txsig")
        .with_transaction("open-tx")
        .with_init_tx("init-tx")
        .with_update_tx("update-tx")
    )
    assert p.mode == "push"
    assert p.session_id() == "chan1"
    assert p.deposit_amount() == 1_000_000
    assert p.payer == "payer1"
    assert p.payee == "payee1"
    assert p.mint == "mint1"
    assert p.salt == 99
    assert p.grace_period == 45
    assert p.transaction == "open-tx"
    assert p.init_multi_delegate_tx == "init-tx"
    assert p.update_delegation_tx == "update-tx"


def test_deposit_amount_rejects_non_u64_values() -> None:
    # Negative, fractional, non-digit, and over-u64 deposits must be rejected
    # like the rust/Go typed u64 parsers, not silently coerced.
    for bad in ("-1", "1.5", "0x10", " 10", "", str(2**64)):
        p = OpenPayload.push("chan1", bad, "signer1", "txsig")
        with pytest.raises(ValueError):
            p.deposit_amount()


def test_open_payload_pull_payment_channel_uses_channel_id_and_deposit():
    p = OpenPayload.payment_channel_with_mode(
        "pull", "chan1", "1000000", "payer1", "payee1", "mint1", 99, 45, "signer1", "pending"
    ).with_transaction("open-tx")
    assert p.mode == "pull"
    assert p.session_id() == "chan1"
    assert p.deposit_amount() == 1_000_000
    assert p.channel_id == "chan1"
    assert p.deposit == "1000000"
    assert p.token_account is None
    assert p.approved_amount is None
    assert p.transaction == "open-tx"


def test_open_payload_push_session_id_and_deposit():
    p = OpenPayload.push("chan1", "2000000", "s", "sig")
    assert p.session_id() == "chan1"
    assert p.deposit_amount() == 2_000_000


def test_open_payload_pull_session_id_and_deposit():
    p = OpenPayload.pull("tokacct", "3000000", "wallet1", "s", "sig")
    assert p.session_id() == "tokacct"
    assert p.deposit_amount() == 3_000_000


def test_open_payload_missing_required_fields_and_invalid_deposit_error():
    push = OpenPayload.push("chan1", "bad", "s", "sig")
    with pytest.raises(ValueError, match="invalid deposit amount"):
        push.deposit_amount()
    push.deposit = None
    with pytest.raises(ValueError, match="push open missing deposit"):
        push.deposit_amount()
    push.channel_id = None
    with pytest.raises(ValueError, match="push open missing channelId"):
        push.session_id()

    pull = OpenPayload.pull("tokacct", "bad", "wallet", "s", "sig")
    with pytest.raises(ValueError, match="invalid deposit amount"):
        pull.deposit_amount()
    pull.approved_amount = None
    with pytest.raises(ValueError, match="pull open missing deposit or approvedAmount"):
        pull.deposit_amount()
    pull.token_account = None
    with pytest.raises(ValueError, match="pull open missing channelId or tokenAccount"):
        pull.session_id()


# ── OpenPayload serde ──


def test_open_payload_push_roundtrip_dict():
    p = OpenPayload.push("chan1", "1000000", "signer1", "txsig")
    d = p.to_dict()
    assert d["mode"] == "push"
    assert d["channelId"] == "chan1"
    assert "tokenAccount" not in d
    back = OpenPayload.from_dict(d)
    assert back.mode == "push"
    assert back.channel_id == "chan1"


def test_open_payload_pull_roundtrip_dict():
    p = OpenPayload.pull("tokacct", "5000000", "wallet1", "signer1", "approvesig")
    d = p.to_dict()
    assert d["mode"] == "pull"
    assert d["tokenAccount"] == "tokacct"
    assert d["owner"] == "wallet1"
    assert "channelId" not in d
    back = OpenPayload.from_dict(d)
    assert back.mode == "pull"
    assert back.token_account == "tokacct"
    assert back.owner == "wallet1"


def test_salt_serializes_as_string_and_accepts_number_and_huge_u64():
    salt = 2**64 - 8  # u64::MAX - 7
    p = OpenPayload.payment_channel("chan1", "1000000", "payer1", "payee1", "mint1", salt, 900, "signer1", "txsig")
    d = p.to_dict()
    assert d["salt"] == str(salt)
    assert isinstance(d["salt"], str)
    back = OpenPayload.from_dict(d)
    assert back.salt == salt

    # Legacy numeric salt: no float precision loss for a huge u64 because the
    # dict carries a Python int (mirrors rust's number branch).
    legacy = {
        "mode": "push",
        "channelId": "chan1",
        "deposit": "1000000",
        "salt": salt,
        "authorizedSigner": "signer1",
        "signature": "txsig",
    }
    assert OpenPayload.from_dict(legacy).salt == salt
    assert OpenPayload.from_dict({**legacy, "salt": 42}).salt == 42


def test_salt_absent_is_none():
    d = {"mode": "push", "channelId": "c", "authorizedSigner": "s", "signature": "sig"}
    assert OpenPayload.from_dict(d).salt is None
    # And a None salt is omitted from the wire dict.
    assert "salt" not in OpenPayload.push("c", "1", "s", "sig").to_dict()


def test_salt_rejects_non_numeric_string_and_bad_type():
    base = {"mode": "push", "channelId": "c", "authorizedSigner": "s", "signature": "sig"}
    with pytest.raises(ValueError, match="salt must be a decimal string"):
        OpenPayload.from_dict({**base, "salt": "not-a-number"})
    with pytest.raises(ValueError, match="salt must be a decimal string or unsigned"):
        OpenPayload.from_dict({**base, "salt": [1, 2]})
    with pytest.raises(ValueError, match="salt must be a decimal string or unsigned"):
        OpenPayload.from_dict({**base, "salt": True})


def test_open_payload_missing_mode_raises():
    d = {"channelId": "chan1", "deposit": "1000", "authorizedSigner": "s", "signature": "sig"}
    with pytest.raises(ValueError, match="missing mode"):
        OpenPayload.from_dict(d)


def test_open_payload_unknown_mode_raises():
    # rust serde rejects unknown SessionMode variants at decode.
    d = {"mode": "stream", "channelId": "chan1", "authorizedSigner": "s", "signature": "sig"}
    with pytest.raises(ValueError, match="unknown mode"):
        OpenPayload.from_dict(d)


def test_session_request_unknown_mode_and_strategy_raise():
    base = {"cap": "1", "currency": "USDC", "operator": "op", "recipient": "rec"}
    with pytest.raises(ValueError, match="unknown mode"):
        SessionRequest.from_dict({**base, "modes": ["push", "stream"]})
    with pytest.raises(ValueError, match="unknown pullVoucherStrategy"):
        SessionRequest.from_dict({**base, "pullVoucherStrategy": "serverVoucher"})


# ── SessionAction round-trips for all five actions ──


def test_session_action_open_push_roundtrip():
    action = SessionAction.open_action(OpenPayload.push("chan123", "5000000", "signer123", "sig456"))
    d = action.to_dict()
    assert d["action"] == "open"
    assert d["mode"] == "push"
    back = SessionAction.from_dict(d)
    assert back.open is not None
    assert back.open.mode == "push"
    assert back.open.session_id() == "chan123"
    assert back.open.deposit_amount() == 5_000_000
    assert back.open.authorized_signer == "signer123"


def test_session_action_open_pull_roundtrip():
    action = SessionAction.open_action(OpenPayload.pull("tokacct", "3000000", "wallet1", "signer1", "approvesig"))
    d = action.to_dict()
    assert d["action"] == "open"
    assert d["mode"] == "pull"
    assert "tokenAccount" in d
    back = SessionAction.from_dict(d)
    assert back.open is not None
    assert back.open.mode == "pull"
    assert back.open.session_id() == "tokacct"
    assert back.open.deposit_amount() == 3_000_000


def test_session_action_voucher_roundtrip():
    action = SessionAction.voucher_action(VoucherPayload(voucher=_voucher()))
    d = action.to_dict()
    assert d["action"] == "voucher"
    back = SessionAction.from_dict(d)
    assert back.voucher is not None
    assert back.voucher.voucher.data.cumulative == "500000"
    assert back.voucher.voucher.data.nonce == 3


def test_session_action_commit_roundtrip():
    action = SessionAction.commit_action(CommitPayload(delivery_id="delivery-1", voucher=_voucher()))
    d = action.to_dict()
    assert d["action"] == "commit"
    assert d["deliveryId"] == "delivery-1"
    back = SessionAction.from_dict(d)
    assert back.commit is not None
    assert back.commit.delivery_id == "delivery-1"
    assert back.commit.voucher.data.cumulative == "500000"


def test_session_action_topup_roundtrip_uses_camelcase_tag():
    action = SessionAction.top_up_action(TopUpPayload(channel_id="chan1", new_deposit="9000000", signature="txsig"))
    d = action.to_dict()
    assert d["action"] == "topUp"  # camelCase, not "topup"
    back = SessionAction.from_dict(d)
    assert back.top_up is not None
    assert back.top_up.new_deposit == "9000000"
    assert back.top_up.signature == "txsig"


def test_session_action_close_no_voucher_roundtrip():
    action = SessionAction.close_action(ClosePayload(channel_id="chan1"))
    d = action.to_dict()
    assert d["action"] == "close"
    assert "voucher" not in d
    back = SessionAction.from_dict(d)
    assert back.close is not None
    assert back.close.voucher is None


def test_session_action_close_with_voucher_roundtrip():
    action = SessionAction.close_action(
        ClosePayload(channel_id="chan1", voucher=_voucher(cumulative="700000", nonce=7))
    )
    d = action.to_dict()
    assert d["action"] == "close"
    back = SessionAction.from_dict(d)
    assert back.close is not None
    assert back.close.voucher is not None
    assert back.close.voucher.data.cumulative == "700000"


@pytest.mark.parametrize(
    ("action", "expected_tag"),
    [
        (SessionAction.open_action(OpenPayload.push("c", "1", "s", "sig")), "open"),
        (SessionAction.voucher_action(VoucherPayload(voucher=_voucher())), "voucher"),
        (SessionAction.commit_action(CommitPayload("d", _voucher())), "commit"),
        (SessionAction.top_up_action(TopUpPayload("c", "1", "sig")), "topUp"),
        (SessionAction.close_action(ClosePayload("c")), "close"),
    ],
)
def test_session_action_tags(action: SessionAction, expected_tag: str):
    assert action.to_dict()["action"] == expected_tag


def test_session_action_no_variant_raises():
    with pytest.raises(ValueError, match="no variant set"):
        SessionAction().to_dict()


def test_session_action_multiple_variants_raises():
    bad = SessionAction(
        open=OpenPayload.push("c", "1", "s", "sig"),
        close=ClosePayload("c"),
    )
    with pytest.raises(ValueError, match="multiple variants set"):
        bad.to_dict()


def test_session_action_missing_discriminator_raises():
    with pytest.raises(ValueError, match="missing action discriminator"):
        SessionAction.from_dict({"channelId": "c"})


def test_session_action_unknown_discriminator_raises():
    with pytest.raises(ValueError, match="unknown action"):
        SessionAction.from_dict({"action": "settle"})


# ── VoucherData ──


def test_voucher_data_cumulative_alias_decode():
    # Primary wire field.
    primary = VoucherData.from_dict({"channelId": "c", "cumulativeAmount": "100", "expiresAt": 42})
    assert primary.cumulative == "100"
    # Legacy "cumulative" alias.
    alias = VoucherData.from_dict({"channelId": "c", "cumulative": "200", "expiresAt": 42})
    assert alias.cumulative == "200"
    # Emits the canonical "cumulativeAmount" wire field.
    assert primary.to_dict()["cumulativeAmount"] == "100"
    assert "cumulative" not in primary.to_dict()


def test_voucher_data_nonce_omitted_when_none():
    d = VoucherData(channel_id="c", cumulative="1", expires_at=1).to_dict()
    assert "nonce" not in d
    d2 = VoucherData(channel_id="c", cumulative="1", expires_at=1, nonce=9).to_dict()
    assert d2["nonce"] == 9


@pytest.mark.parametrize("nonce", [None, 1, 5])
def test_voucher_message_bytes_layout(nonce: int | None):
    channel_bytes = bytes([3] * 32)
    from solders.pubkey import Pubkey

    channel_id = str(Pubkey.from_bytes(channel_bytes))
    data = VoucherData(channel_id=channel_id, cumulative="1000", expires_at=42, nonce=nonce)
    out = data.message_bytes()
    assert len(out) == 48
    assert out[:32] == channel_bytes
    assert out[32:40] == struct.pack("<Q", 1000)
    assert out[40:48] == struct.pack("<q", 42)
    # Deterministic.
    assert data.message_bytes() == data.message_bytes()


def test_voucher_message_bytes_differs_by_cumulative():
    from solders.pubkey import Pubkey

    channel_id = str(Pubkey.from_bytes(bytes([6] * 32)))
    a = VoucherData(channel_id=channel_id, cumulative="100", expires_at=42)
    b = VoucherData(channel_id=channel_id, cumulative="200", expires_at=42)
    assert a.message_bytes() != b.message_bytes()


def test_voucher_message_bytes_negative_expires_at():
    from solders.pubkey import Pubkey

    channel_id = str(Pubkey.from_bytes(bytes([7] * 32)))
    data = VoucherData(channel_id=channel_id, cumulative="1", expires_at=-5)
    out = data.message_bytes()
    assert out[40:48] == struct.pack("<q", -5)


def test_voucher_message_bytes_invalid_channel_and_cumulative():
    with pytest.raises(ValueError, match="invalid channelId"):
        VoucherData(channel_id="not-base58-!!!", cumulative="1", expires_at=1).message_bytes()

    from solders.pubkey import Pubkey

    channel_id = str(Pubkey.from_bytes(bytes([8] * 32)))
    with pytest.raises(ValueError, match="invalid voucher cumulative"):
        VoucherData(channel_id=channel_id, cumulative="nope", expires_at=1).message_bytes()


def test_signed_voucher_roundtrip():
    v = _voucher(cumulative="100", nonce=None)
    d = v.to_dict()
    back = SignedVoucher.from_dict(d)
    assert back.data.cumulative == "100"
    assert back.signature == "sig_here"
    assert back.data.nonce is None


# ── Metering types ──


def test_metering_directive_roundtrip_and_amount_parse():
    directive = MeteringDirective(
        delivery_id="d1",
        session_id="chan1",
        amount="125",
        currency="USDC",
        sequence=7,
        expires_at=DEFAULT_SESSION_EXPIRES_AT,
        commit_url="https://example.test/commit",
    )
    assert directive.amount_base_units() == 125
    d = directive.to_dict()
    assert d["deliveryId"] == "d1"
    assert d["commitUrl"] == "https://example.test/commit"
    assert "proof" not in d
    back = MeteringDirective.from_dict(d)
    assert back.sequence == 7
    assert back.commit_url == "https://example.test/commit"


def test_metering_directive_invalid_amount():
    directive = MeteringDirective(
        delivery_id="d1",
        session_id="chan1",
        amount="not-a-number",
        currency="USDC",
        sequence=1,
        expires_at=DEFAULT_SESSION_EXPIRES_AT,
        proof="proof",
    )
    with pytest.raises(ValueError, match="invalid metering amount"):
        directive.amount_base_units()
    assert directive.to_dict()["proof"] == "proof"


def test_metering_usage_roundtrip_and_invalid():
    usage = MeteringUsage(delivery_id="d1", amount="42")
    d = usage.to_dict()
    assert d["deliveryId"] == "d1"
    back = MeteringUsage.from_dict(d)
    assert back.amount_base_units() == 42
    with pytest.raises(ValueError, match="invalid metering usage amount"):
        MeteringUsage(delivery_id="d1", amount="bad").amount_base_units()


def test_metered_envelope_roundtrip():
    directive = MeteringDirective(
        delivery_id="d1",
        session_id="chan1",
        amount="125",
        currency="USDC",
        sequence=7,
        expires_at=DEFAULT_SESSION_EXPIRES_AT,
    )
    envelope = MeteredEnvelope(payload={"ok": True}, metering=directive)
    d = envelope.to_dict()
    assert d["metering"]["deliveryId"] == "d1"
    assert d["payload"] == {"ok": True}
    back = MeteredEnvelope.from_dict(d)
    assert back.metering.sequence == 7
    assert back.payload["ok"] is True


def test_commit_receipt_roundtrip_and_parsers():
    receipt = CommitReceipt(
        delivery_id="d1",
        session_id="chan1",
        amount="125",
        cumulative="500",
        status="committed",
    )
    d = receipt.to_dict()
    assert d["status"] == "committed"
    back = CommitReceipt.from_dict(d)
    assert back.amount_base_units() == 125
    assert back.cumulative_base_units() == 500
    assert back.status == "committed"

    replayed = CommitReceipt.from_dict({**d, "status": "replayed"})
    assert replayed.status == "replayed"

    # rust deserializes status as the CommitStatus enum: missing or unknown
    # statuses fail at decode and can never advance client state.
    with pytest.raises(ValueError, match="unknown status"):
        CommitReceipt.from_dict({**d, "status": "settled"})
    missing = {k: v for k, v in d.items() if k != "status"}
    with pytest.raises(ValueError, match="unknown status"):
        CommitReceipt.from_dict(missing)

    with pytest.raises(ValueError, match="invalid commit receipt amount"):
        CommitReceipt("d", "s", "bad", "1", "committed").amount_base_units()
    with pytest.raises(ValueError, match="invalid commit receipt cumulative"):
        CommitReceipt("d", "s", "1", "bad", "committed").cumulative_base_units()
