"""Edge-case parse error coverage for solana_mpp._headers."""

from __future__ import annotations

import pytest

from solana_mpp._base64url import encode_json
from solana_mpp._headers import (
    ParseError,
    format_authorization,
    format_receipt,
    parse_authorization,
    parse_receipt,
)
from solana_mpp._types import (
    ChallengeEcho,
    PaymentCredential,
    Receipt,
)


def test_parse_authorization_rejects_non_dict_json():
    # encode_json over a list → base64url-encoded JSON array → parse fails on isinstance(data, dict).
    token = encode_json(["not", "a", "dict"])
    with pytest.raises(ParseError):
        parse_authorization(f"Payment {token}")


def test_parse_authorization_rejects_dict_without_challenge_key():
    token = encode_json({"payload": {}})
    with pytest.raises(ParseError):
        parse_authorization(f"Payment {token}")


def test_parse_receipt_rejects_non_dict_json():
    token = encode_json(["not", "dict"])
    with pytest.raises(ParseError):
        parse_receipt(token)


def test_parse_receipt_rejects_invalid_base64():
    with pytest.raises(ParseError):
        parse_receipt("@@@not-base64@@@")


def test_format_authorization_includes_optional_fields():
    echo = ChallengeEcho(
        id="c1",
        realm="api",
        method="solana",
        intent="charge",
        request="req",
        expires="2030-01-01T00:00:00Z",
        digest="sha256-abc",
        opaque="op",
    )
    cred = PaymentCredential(challenge=echo, payload={"k": "v"}, source="srv")
    header = format_authorization(cred)
    assert header.startswith("Payment ")
    # Round-trip preserves the optional fields.
    parsed = parse_authorization(header)
    assert parsed.challenge.expires == "2030-01-01T00:00:00Z"
    assert parsed.challenge.digest == "sha256-abc"
    assert parsed.challenge.opaque == "op"
    assert parsed.source == "srv"


def test_format_receipt_with_external_id_round_trips():
    r = Receipt(
        status="paid",
        method="solana",
        timestamp="2030-01-01T00:00:00Z",
        reference="sig",
        challenge_id="cid",
        external_id="ext-1",
    )
    token = format_receipt(r)
    parsed = parse_receipt(token)
    assert parsed.external_id == "ext-1"


def test_format_receipt_without_external_id_round_trips():
    r = Receipt(
        status="paid",
        method="solana",
        timestamp="2030-01-01T00:00:00Z",
        reference="sig",
        challenge_id="cid",
    )
    token = format_receipt(r)
    parsed = parse_receipt(token)
    assert parsed.external_id == ""
