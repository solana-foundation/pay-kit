"""Client-side tests for the final session action model."""

from __future__ import annotations

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit.protocols.mpp.client.session import (
    DEFAULT_VOUCHER_EXPIRES_AT,
    ActiveSession,
    parse_session_challenge,
    serialize_session_credential,
)
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.headers import format_www_authenticate, parse_authorization
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge
from solana_pay_kit.protocols.mpp.intents.session import (
    SessionAuthentication,
    SessionMethodDetails,
    SessionRequest,
)


def _session() -> ActiveSession:
    return ActiveSession(Pubkey.from_string("11111111111111111111111111111112"), Keypair.from_seed(bytes([4] * 32)))


def _challenge(intent: str = "session") -> PaymentChallenge:
    request = SessionRequest(
        amount="25",
        currency="USDC",
        recipient="recipient",
        method_details=SessionMethodDetails(network="devnet", channel_program="program"),
    )
    return PaymentChallenge(
        id="challenge",
        realm="api.example",
        method="solana",
        intent=intent,
        request=encode_json(request.to_dict()),
        expires="2099-01-01T00:00:00Z",
    )


def test_voucher_signing_is_cumulative_and_has_exact_wire_fields() -> None:
    session = _session()
    voucher = session.sign_increment(100)
    assert session.cumulative == 100
    assert voucher.data.cumulative_amount == "100"
    assert voucher.signer == session.authorized_signer
    assert voucher.signature_type == "ed25519"
    assert voucher.data.expires_at == DEFAULT_VOUCHER_EXPIRES_AT
    assert voucher.data.message_bytes()


def test_prepare_and_record_are_separate_retry_safe_steps() -> None:
    session = _session()
    voucher = session.prepare_increment(75)
    assert session.cumulative == 0
    session.record_voucher(voucher)
    assert session.cumulative == 75
    with pytest.raises(ValueError, match="must exceed"):
        session.record_voucher(voucher)


def test_voucher_rejects_non_increasing_and_overflow() -> None:
    session = _session()
    session.sign_voucher(100)
    with pytest.raises(ValueError, match="must exceed"):
        session.sign_voucher(100)
    session = ActiveSession(session.channel_id, Keypair(), cumulative=(1 << 64) - 1)
    with pytest.raises(ValueError, match="overflows"):
        session.sign_increment(1)


def test_open_action_matches_final_schema() -> None:
    session = _session()
    action = session.open_payment_channel_action(
        1_000,
        "payer",
        "payee",
        "mint",
        7,
        900,
        42,
        "transaction",
        idle_timeout_seconds=30,
    )
    wire = action.to_dict()
    assert wire == {
        "action": "open",
        "channelId": session.channel_id_string,
        "payer": "payer",
        "payee": "payee",
        "mint": "mint",
        "authorizedSigner": session.authorized_signer,
        "salt": "7",
        "depositAmount": "1000",
        "gracePeriodSeconds": 900,
        "openSlot": "42",
        "transaction": "transaction",
        "idleTimeoutSeconds": 30,
    }


def test_use_and_operator_close_attach_reusable_authentication() -> None:
    session = _session()
    authentication = SessionAuthentication("opening-challenge", "payer", "signature")
    assert session.use_action(authentication).to_dict() == {
        "action": "use",
        "channelId": session.channel_id_string,
        "authentication": authentication.to_dict(),
    }
    assert session.close_action(authentication=authentication).to_dict() == {
        "action": "close",
        "channelId": session.channel_id_string,
        "authentication": authentication.to_dict(),
    }


def test_top_up_and_client_close_actions() -> None:
    session = _session()
    assert session.top_up_action(250, "transaction").to_dict() == {
        "action": "topUp",
        "channelId": session.channel_id_string,
        "additionalAmount": "250",
        "transaction": "transaction",
    }
    close = session.close_action(final_increment=10).to_dict()
    assert close["action"] == "close"
    assert close["voucher"]["voucher"]["cumulativeAmount"] == "10"


def test_credential_serialization_roundtrips() -> None:
    challenge = _challenge()
    action = _session().close_action()
    header = serialize_session_credential(challenge, action)
    credential = parse_authorization(header)
    assert credential.challenge.id == challenge.id
    assert credential.payload == action.to_dict()


def test_parse_session_challenge_reads_nested_request() -> None:
    challenge = _challenge()
    parsed, request = parse_session_challenge(format_www_authenticate(challenge))
    assert parsed.id == challenge.id
    assert request.amount == "25"
    assert request.method_details.channel_program == "program"


def test_parse_session_challenge_rejects_other_intent() -> None:
    with pytest.raises(ValueError, match="not a session"):
        parse_session_challenge(format_www_authenticate(_challenge("charge")))
