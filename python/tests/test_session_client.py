"""Tests for the client-side session intent (ActiveSession + credential framing).

Mirrors the ``#[cfg(test)] mod tests`` in
``rust/crates/mpp/src/client/session.rs`` and the parity-verified Go port:
monotonicity, expiry control, nonce increment, ``sign_increment`` math, the
prepare/record split, Ed25519 verification over the 48-byte preimage (plus a
tampered negative), every action builder's payload + discriminator, the
credential serialize round-trip through the core parse, and
``parse_session_challenge`` over a session WWW-Authenticate header.
"""

from __future__ import annotations

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from solana_pay_kit.protocols.mpp._paymentchannels import voucher_message_bytes
from solana_pay_kit.protocols.mpp.client.session import (
    DEFAULT_VOUCHER_EXPIRES_AT,
    ActiveSession,
    parse_session_challenge,
    serialize_session_credential,
    session_request_modes,
)
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.headers import format_www_authenticate, parse_authorization
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge
from solana_pay_kit.protocols.mpp.intents.session import (
    SessionAction,
    SessionRequest,
    SignedVoucher,
    VoucherData,
)


class _BytesSigner:
    """A solana_pay_kit-style signer: ``pubkey() -> str``, ``sign(bytes) -> bytes``."""

    def __init__(self, seed: int) -> None:
        self._kp = Keypair.from_seed(bytes([seed] * 32))

    def pubkey(self) -> str:
        return str(self._kp.pubkey())

    def sign(self, message: bytes) -> bytes:
        return bytes(self._kp.sign_message(message))

    @property
    def solders_pubkey(self) -> Pubkey:
        return self._kp.pubkey()


def _signer(seed: int = 42) -> _BytesSigner:
    return _BytesSigner(seed)


def _channel() -> Pubkey:
    return Pubkey.from_string("11111111111111111111111111111112")


def _session(seed: int = 42) -> ActiveSession:
    return ActiveSession(_channel(), _signer(seed))


# ── expiry control ──


def test_at_expiry_and_set_expires_at_control_voucher_expiry() -> None:
    session = ActiveSession.at_expiry(_channel(), _signer(), 1234)
    first = session.prepare_increment(10)
    assert first.data.expires_at == 1234
    assert session.cumulative == 0

    session.set_expires_at(5678)
    second = session.prepare_increment(10)
    assert second.data.expires_at == 5678


def test_default_voucher_expiry() -> None:
    assert DEFAULT_VOUCHER_EXPIRES_AT == 4_102_444_800
    session = _session()
    assert session.expires_at == DEFAULT_VOUCHER_EXPIRES_AT
    voucher = session.prepare_increment(1)
    assert voucher.data.expires_at == DEFAULT_VOUCHER_EXPIRES_AT


# ── increment / absolute math ──


def test_sign_increment_increases_cumulative() -> None:
    s = _session()
    assert s.cumulative == 0
    v = s.sign_increment(100)
    assert s.cumulative == 100
    assert v.data.cumulative == "100"
    assert v.data.nonce == 1


def test_sign_voucher_absolute() -> None:
    s = _session()
    s.sign_increment(50)
    v = s.sign_voucher(200)
    assert s.cumulative == 200
    assert v.data.cumulative == "200"


# ── prepare / record split ──


def test_prepare_and_record_voucher_are_separate_steps() -> None:
    s = _session()
    prepared = s.prepare_increment(75)
    assert prepared.data.cumulative == "75"
    assert prepared.data.nonce == 1
    assert s.cumulative == 0

    s.record_voucher(prepared)
    assert s.cumulative == 75
    with pytest.raises(ValueError):
        s.record_voucher(prepared)


def test_record_voucher_rejects_invalid_cumulative_and_handles_missing_nonce() -> None:
    s = _session()
    bad = SignedVoucher(
        data=VoucherData(
            channel_id=s.channel_id_string,
            cumulative="not-a-number",
            expires_at=DEFAULT_VOUCHER_EXPIRES_AT,
            nonce=None,
        ),
        signature="sig",
    )
    with pytest.raises(ValueError):
        s.record_voucher(bad)

    without_nonce = SignedVoucher(
        data=VoucherData(
            channel_id=s.channel_id_string,
            cumulative="15",
            expires_at=DEFAULT_VOUCHER_EXPIRES_AT,
            nonce=None,
        ),
        signature="sig",
    )
    s.record_voucher(without_nonce)
    assert s.cumulative == 15
    assert s.nonce == 1


def test_record_voucher_honors_larger_voucher_nonce() -> None:
    s = _session()
    voucher = SignedVoucher(
        data=VoucherData(
            channel_id=s.channel_id_string,
            cumulative="42",
            expires_at=DEFAULT_VOUCHER_EXPIRES_AT,
            nonce=9,
        ),
        signature="sig",
    )
    s.record_voucher(voucher)
    assert s.nonce == 9


def test_record_voucher_keeps_current_nonce_for_stale_voucher_nonce() -> None:
    # rust ``record_voucher`` sets ``nonce = max(nonce, voucher.nonce)``: a
    # recorded voucher carrying a nonce at or below the current counter leaves
    # the counter untouched. The TS ActiveSession matches.
    s = _session()
    s.record_voucher(
        SignedVoucher(
            data=VoucherData(
                channel_id=s.channel_id_string,
                cumulative="42",
                expires_at=DEFAULT_VOUCHER_EXPIRES_AT,
                nonce=9,
            ),
            signature="sig",
        )
    )
    s.record_voucher(
        SignedVoucher(
            data=VoucherData(
                channel_id=s.channel_id_string,
                cumulative="50",
                expires_at=DEFAULT_VOUCHER_EXPIRES_AT,
                nonce=3,
            ),
            signature="sig",
        )
    )
    assert s.cumulative == 50
    assert s.nonce == 9
    assert s.prepare_increment(1).data.nonce == 10


# ── monotonicity ──


def test_sign_voucher_rejects_non_increasing() -> None:
    s = _session()
    s.sign_increment(100)
    with pytest.raises(ValueError):
        s.sign_voucher(100)
    with pytest.raises(ValueError):
        s.sign_voucher(50)


def test_sign_voucher_zero_rejected() -> None:
    s = _session()
    with pytest.raises(ValueError):
        s.sign_voucher(0)


def test_add_cumulative_overflow_rejected() -> None:
    s = _session()
    s.sign_voucher((1 << 64) - 2)
    with pytest.raises(ValueError):
        s.sign_increment(5)


# ── nonce ──


def test_nonce_increments_per_voucher() -> None:
    s = _session()
    v1 = s.sign_increment(10)
    v2 = s.sign_increment(10)
    assert v1.data.nonce == 1
    assert v2.data.nonce == 2
    assert s.nonce == 2


def test_voucher_channel_id_matches_session() -> None:
    s = _session()
    expected = s.channel_id_string
    v = s.sign_increment(100)
    assert v.data.channel_id == expected
    assert s.channel_id_string == str(_channel())
    assert s.channel_id == _channel()


# ── Ed25519 signature verification over the 48-byte preimage ──


def test_signature_verifies_against_authorized_signer() -> None:
    signer = _signer()
    s = ActiveSession(_channel(), signer)
    voucher = s.sign_increment(250)

    preimage = voucher_message_bytes(_channel(), 250, s.expires_at)
    assert len(preimage) == 48

    sig = Signature.from_string(voucher.signature)
    assert sig.verify(signer.solders_pubkey, preimage)
    assert s.authorized_signer == str(signer.solders_pubkey)


def test_tampered_preimage_fails_verification() -> None:
    signer = _signer()
    s = ActiveSession(_channel(), signer)
    voucher = s.sign_increment(250)

    sig = Signature.from_string(voucher.signature)
    tampered = voucher_message_bytes(_channel(), 251, s.expires_at)
    assert not sig.verify(signer.solders_pubkey, tampered)


def test_signer_pubkey_accepts_solders_keypair() -> None:
    # A raw solders Keypair (pubkey() -> Pubkey, sign_message) is accepted.
    kp = Keypair.from_seed(bytes([5] * 32))
    s = ActiveSession(_channel(), kp)
    voucher = s.sign_increment(10)
    assert s.authorized_signer == str(kp.pubkey())
    preimage = voucher_message_bytes(_channel(), 10, s.expires_at)
    assert Signature.from_string(voucher.signature).verify(kp.pubkey(), preimage)


# ── action builders ──


def test_voucher_action_fields() -> None:
    s = _session()
    action = s.voucher_action(33)
    assert action.voucher is not None
    assert action.voucher.voucher.data.cumulative == "33"
    assert action.voucher.voucher.data.channel_id == s.channel_id_string
    assert action.to_dict()["action"] == "voucher"


def test_open_action_fields() -> None:
    s = _session()
    action = s.open_action(1_000_000, "txsig123")
    assert action.open is not None
    p = action.open
    assert p.mode == "push"
    assert p.deposit == "1000000"
    assert p.signature == "txsig123"
    assert p.channel_id == s.channel_id_string
    assert p.authorized_signer == s.authorized_signer
    assert action.to_dict()["action"] == "open"


def test_open_payment_channel_action_fields() -> None:
    s = _session()
    action = s.open_payment_channel_action(9_000, "payer", "payee", "mint", 42, 60, "open-sig")
    assert action.open is not None
    p = action.open
    assert p.mode == "push"
    assert p.channel_id == s.channel_id_string
    assert p.deposit == "9000"
    assert p.payer == "payer"
    assert p.payee == "payee"
    assert p.mint == "mint"
    assert p.salt == 42
    assert p.grace_period == 60
    assert p.signature == "open-sig"


def test_open_payment_channel_action_can_use_pull_mode() -> None:
    s = _session()
    action = s.open_payment_channel_action_with_mode("pull", 9_000, "payer", "payee", "mint", 42, 60, "pending")
    assert action.open is not None
    p = action.open
    assert p.mode == "pull"
    assert p.channel_id == s.channel_id_string
    assert p.deposit == "9000"
    assert p.token_account is None
    assert p.approved_amount is None


def test_open_pull_action_fields() -> None:
    s = _session()
    action = s.open_pull_action(5_000_000, "wallet123", "approvesig")
    assert action.open is not None
    p = action.open
    assert p.mode == "pull"
    assert p.approved_amount == "5000000"
    assert p.signature == "approvesig"
    assert p.token_account == s.channel_id_string
    assert p.owner == "wallet123"
    assert p.authorized_signer == s.authorized_signer
    assert p.channel_id is None
    assert p.deposit is None


def test_top_up_action_fields() -> None:
    s = _session()
    action = s.top_up_action(5_000_000, "topuptx")
    assert action.top_up is not None
    p = action.top_up
    assert p.channel_id == s.channel_id_string
    assert p.new_deposit == "5000000"
    assert p.signature == "topuptx"
    assert action.to_dict()["action"] == "topUp"


def test_close_action_no_final_increment() -> None:
    s = _session()
    action = s.close_action()
    assert action.close is not None
    assert action.close.voucher is None
    assert action.close.channel_id == s.channel_id_string


def test_close_action_with_final_increment() -> None:
    s = _session()
    s.sign_increment(100)
    action = s.close_action(50)
    assert action.close is not None
    assert action.close.voucher is not None
    assert action.close.voucher.data.cumulative == "150"


def test_close_action_zero_increment_no_voucher() -> None:
    s = _session()
    action = s.close_action(0)
    assert action.close is not None
    assert action.close.voucher is None


# ── credential serialize round-trip through the core parse ──


def _session_challenge() -> PaymentChallenge:
    request = encode_json(
        {
            "cap": "1000000",
            "currency": "USDC",
            "operator": "op-pubkey",
            "recipient": "recipient-pubkey",
        }
    )
    return PaymentChallenge(
        id="challenge-id-1",
        realm="api.example.com",
        method="solana",
        intent="session",
        request=request,
    )


def test_serialize_session_credential_round_trips() -> None:
    s = _session()
    challenge = _session_challenge()
    action = s.voucher_action(500_000)

    header = s.serialize_session_credential(challenge, action)
    assert header.startswith("Payment ")

    credential = parse_authorization(header)
    assert credential.challenge.id == challenge.id
    assert credential.challenge.intent == "session"
    decoded = SessionAction.from_dict(credential.payload)
    assert decoded.voucher is not None
    assert decoded.voucher.voucher.data.cumulative == "500000"


def test_serialize_session_credential_free_function_matches_method() -> None:
    s = _session()
    challenge = _session_challenge()
    action = s.close_action()
    assert serialize_session_credential(challenge, action) == s.serialize_session_credential(challenge, action)


# ── parse_session_challenge ──


def test_parse_session_challenge_parses_session_header() -> None:
    challenge = _session_challenge()
    header = format_www_authenticate(challenge)

    parsed, request = parse_session_challenge(header)
    assert parsed.intent == "session"
    assert request.cap == "1000000"
    assert request.currency == "USDC"
    assert request.operator == "op-pubkey"
    assert request.recipient == "recipient-pubkey"


def test_parse_session_challenge_rejects_non_session_intent() -> None:
    request = encode_json({"amount": "1000000", "currency": "USDC", "recipient": "r"})
    charge = PaymentChallenge(
        id="cid",
        realm="api.example.com",
        method="solana",
        intent="charge",
        request=request,
    )
    header = format_www_authenticate(charge)
    with pytest.raises(ValueError, match="is not a session"):
        parse_session_challenge(header)


# ── session_request_modes ──


def test_session_request_modes_defaults_to_push_only() -> None:
    # ``modes`` omitted or explicitly empty both mean push-only; serde collapses
    # the two on the wire and the selector encodes the interpretation. Mirrors
    # the TS ``sessionRequestModes`` helper.
    base = {"cap": "1", "currency": "USDC", "operator": "op", "recipient": "rec"}
    omitted = SessionRequest.from_dict(base)
    assert session_request_modes(omitted) == ["push"]
    explicit_empty = SessionRequest.from_dict({**base, "modes": []})
    assert session_request_modes(explicit_empty) == ["push"]


def test_session_request_modes_preserves_advertised_modes() -> None:
    request = SessionRequest(
        cap="1",
        currency="USDC",
        operator="op",
        recipient="rec",
        modes=["pull", "push"],
        pull_voucher_strategy="clientVoucher",
    )
    assert session_request_modes(request) == ["pull", "push"]
