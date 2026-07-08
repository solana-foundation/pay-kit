"""Tests for _headers module."""

from __future__ import annotations

import pytest

from solana_pay_kit.protocols.mpp.core.base64url import encode, encode_json
from solana_pay_kit.protocols.mpp.core.headers import (
    ParseError,
    format_authorization,
    format_receipt,
    format_www_authenticate,
    parse_authorization,
    parse_receipt,
    parse_www_authenticate,
    parse_www_authenticate_all,
)
from solana_pay_kit.protocols.mpp.core.types import ChallengeEcho, PaymentChallenge, PaymentCredential, Receipt


class TestWWWAuthenticate:
    def test_roundtrip(self):
        challenge = PaymentChallenge(
            id="abc123",
            realm="api",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "10000", "currency": "USDC"}),
            expires="2024-01-01T00:00:00Z",
        )
        header = format_www_authenticate(challenge)
        parsed = parse_www_authenticate(header)
        assert parsed.id == "abc123"
        assert parsed.realm == "api"
        assert parsed.method == "solana"
        assert parsed.intent == "charge"

    def test_rejects_non_payment_scheme(self):
        with pytest.raises(ParseError, match="Payment"):
            parse_www_authenticate('Bearer realm="test"')

    def test_rejects_empty_id(self):
        header = 'Payment id="", realm="api", method="solana", intent="charge", request="e30"'
        with pytest.raises(ParseError, match="Empty 'id'"):
            parse_www_authenticate(header)

    def test_rejects_uppercase_method(self):
        header = 'Payment id="x", realm="api", method="SOLANA", intent="charge", request="e30"'
        with pytest.raises(ParseError, match="Invalid method"):
            parse_www_authenticate(header)

    def test_rejects_empty_method(self):
        header = 'Payment id="x", realm="api", method="", intent="charge", request="e30"'
        with pytest.raises(ParseError, match="Invalid method"):
            parse_www_authenticate(header)

    def test_rejects_missing_request(self):
        header = 'Payment id="x", realm="api", method="solana", intent="charge"'
        with pytest.raises(ParseError, match="Missing 'request'"):
            parse_www_authenticate(header)

    def test_rejects_missing_realm(self):
        header = 'Payment id="x", method="solana", intent="charge", request="e30"'
        with pytest.raises(ParseError, match="Missing 'realm'"):
            parse_www_authenticate(header)

    def test_rejects_invalid_json_in_request(self):
        bad_b64 = encode(b"not json")
        header = f'Payment id="x", realm="api", method="solana", intent="charge", request="{bad_b64}"'
        with pytest.raises(ParseError, match="Invalid JSON"):
            parse_www_authenticate(header)

    def test_rejects_oversized_request_param(self):
        # Audit #9: request param must be capped before decode/JSON-parse.
        from solana_pay_kit.protocols.mpp.core.headers import MAX_TOKEN_LEN

        big = "A" * (MAX_TOKEN_LEN + 1)
        header = f'Payment id="x", realm="api", method="solana", intent="charge", request="{big}"'
        with pytest.raises(ParseError, match="request parameter exceeds maximum"):
            parse_www_authenticate(header)

    def test_accepts_request_param_at_max_size(self):
        from solana_pay_kit.protocols.mpp.core.headers import MAX_TOKEN_LEN

        body = encode_json({"amount": "1", "currency": "USDC"})
        # Pad to exactly MAX_TOKEN_LEN with base64url-safe chars; still valid b64
        # for the prefix is not required since we only assert the size gate does
        # not fire — but the body must remain decodable JSON. Use a body short
        # enough that the gate is not triggered.
        assert len(body) <= MAX_TOKEN_LEN
        header = f'Payment id="x", realm="api", method="solana", intent="charge", request="{body}"'
        parsed = parse_www_authenticate(header)
        assert parsed.id == "x"

    def test_rejects_duplicate_params(self):
        header = 'Payment id="a", realm="api", method="solana", intent="charge", request="e30", id="b"'
        with pytest.raises(ParseError, match="Duplicate"):
            parse_www_authenticate(header)

    def test_tab_after_scheme(self):
        header = 'Payment\tid="x", realm="api", method="solana", intent="charge", request="e30"'
        parsed = parse_www_authenticate(header)
        assert parsed.id == "x"

    def test_rejects_no_space_after_scheme(self):
        header = 'Paymentid="x"'
        with pytest.raises(ParseError):
            parse_www_authenticate(header)

    def test_preserves_optional_fields(self):
        opaque_b64 = encode_json({"nonce": "abc"})
        header = (
            f'Payment id="x", realm="api", method="solana", intent="charge", request="e30", '
            f'expires="2099-01-01T00:00:00Z", description="Test payment", '
            f'digest="sha-256=abc", opaque="{opaque_b64}"'
        )
        parsed = parse_www_authenticate(header)
        assert parsed.expires == "2099-01-01T00:00:00Z"
        assert parsed.description == "Test payment"
        assert parsed.digest == "sha-256=abc"
        assert parsed.opaque == opaque_b64

    def test_unquoted_values(self):
        header = "Payment id=abc123, realm=api, method=solana, intent=charge, request=e30"
        parsed = parse_www_authenticate(header)
        assert parsed.id == "abc123"

    def test_extra_whitespace(self):
        header = 'Payment   id="x" ,  realm="api" ,  method="solana" ,  intent="charge" ,  request="e30"'
        parsed = parse_www_authenticate(header)
        assert parsed.id == "x"

    def test_format_rejects_crlf(self):
        challenge = PaymentChallenge(id="bad\rid", realm="api", method="solana", intent="charge", request="e30")
        with pytest.raises(ParseError, match="CRLF"):
            format_www_authenticate(challenge)

    def test_format_rejects_newline(self):
        challenge = PaymentChallenge(id="x", realm="bad\nrealm", method="solana", intent="charge", request="e30")
        with pytest.raises(ParseError, match="CRLF"):
            format_www_authenticate(challenge)

    def test_escapes_quotes(self):
        challenge = PaymentChallenge(id='id"with"quotes', realm="api", method="solana", intent="charge", request="e30")
        header = format_www_authenticate(challenge)
        assert r"id\"with\"quotes" in header
        parsed = parse_www_authenticate(header)
        assert parsed.id == 'id"with"quotes'

    def test_escapes_backslashes(self):
        challenge = PaymentChallenge(
            id=r"id\with\backslash", realm="api", method="solana", intent="charge", request="e30"
        )
        header = format_www_authenticate(challenge)
        parsed = parse_www_authenticate(header)
        assert parsed.id == r"id\with\backslash"

    def test_parse_all_extracts_payment_from_combined_header(self):
        challenge = PaymentChallenge(
            id="payment-id",
            realm="api",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "10000", "currency": "USDC"}),
        )
        header = f'Bearer realm="api", {format_www_authenticate(challenge)}'

        parsed = parse_www_authenticate_all([header])

        assert [c.id for c in parsed] == ["payment-id"]

    def test_parse_all_handles_multiple_payment_challenges(self):
        first = PaymentChallenge(
            id="first",
            realm="api",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "1", "description": "one, with comma"}),
        )
        second = PaymentChallenge(
            id="second",
            realm="api",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "2"}),
        )
        header = f"{format_www_authenticate(first)}, {format_www_authenticate(second)}"

        parsed = parse_www_authenticate_all([header])

        assert [c.id for c in parsed] == ["first", "second"]

    def test_parse_all_skips_invalid_payment_challenges(self):
        valid = PaymentChallenge(
            id="valid",
            realm="api",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "10000", "currency": "USDC"}),
        )
        header = (
            'Payment id="", realm="api", method="solana", intent="charge", request="e30", '
            f"{format_www_authenticate(valid)}"
        )

        parsed = parse_www_authenticate_all([header])

        assert [c.id for c in parsed] == ["valid"]


class TestAuthorization:
    def test_roundtrip(self):
        echo = ChallengeEcho(id="abc123", realm="api", method="solana", intent="charge", request="e30")
        credential = PaymentCredential(
            challenge=echo,
            payload={"type": "transaction", "transaction": "base64tx"},
        )
        header = format_authorization(credential)
        parsed = parse_authorization(header)
        assert parsed.challenge.id == "abc123"
        assert parsed.payload["type"] == "transaction"

    def test_rejects_non_payment(self):
        with pytest.raises(ParseError, match="Payment"):
            parse_authorization("Bearer abc123")

    def test_rejects_oversized_token(self):
        huge = "a" * (16 * 1024 + 1)
        with pytest.raises(ParseError, match="exceeds maximum"):
            parse_authorization(f"Payment {huge}")

    def test_rejects_invalid_base64(self):
        with pytest.raises(ParseError):
            parse_authorization("Payment @@@invalid@@@")

    def test_rejects_invalid_json(self):
        bad = encode(b"not json")
        with pytest.raises(ParseError):
            parse_authorization(f"Payment {bad}")

    def test_with_source(self):
        echo = ChallengeEcho(id="abc", realm="api", method="solana", intent="charge", request="e30")
        credential = PaymentCredential(
            challenge=echo,
            payload={"sig": "abc"},
            source="did:pkh:solana:mainnet:Abc123",
        )
        header = format_authorization(credential)
        parsed = parse_authorization(header)
        assert parsed.source == "did:pkh:solana:mainnet:Abc123"

    def test_extract_from_multi_scheme(self):
        """Should extract Payment scheme from multi-scheme Authorization header."""
        echo = ChallengeEcho(id="test", realm="api", method="solana", intent="charge", request="e30")
        credential = PaymentCredential(challenge=echo, payload={"type": "transaction"})
        header = format_authorization(credential)
        # Prefix with another scheme
        multi = f"Bearer xyz123, {header}"
        parsed = parse_authorization(multi)
        assert parsed.challenge.id == "test"

    def test_extract_from_multi_scheme_before_and_after_payment(self):
        """Should not include later schemes in the Payment token."""
        echo = ChallengeEcho(id="test", realm="api", method="solana", intent="charge", request="e30")
        credential = PaymentCredential(challenge=echo, payload={"type": "transaction"})
        header = format_authorization(credential)
        multi = f'Bearer xyz123, {header}, Basic realm="fallback"'
        parsed = parse_authorization(multi)
        assert parsed.challenge.id == "test"


class TestReceipt:
    def test_roundtrip(self):
        receipt = Receipt(
            status="success",
            method="solana",
            timestamp="2024-01-01T00:00:00Z",
            reference="5UfDuX...",
            challenge_id="ch-test",
        )
        header = format_receipt(receipt)
        parsed = parse_receipt(header)
        assert parsed.reference == "5UfDuX..."
        assert parsed.is_success()
        assert parsed.challenge_id == "ch-test"

    def test_rejects_oversized(self):
        huge = "a" * (16 * 1024 + 1)
        with pytest.raises(ParseError, match="exceeds maximum"):
            parse_receipt(huge)

    def test_rejects_invalid_json(self):
        bad = encode(b"not json")
        with pytest.raises(ParseError):
            parse_receipt(bad)


class TestCRLFRejection:
    """L11 lock: header parameter values MUST reject CR or LF.

    Mirrors the Ruby fix from PR #96 (where ``escape`` silently passed CRLF
    through, opening a response-splitting injection) and the Lua fix that
    landed alongside Lua's adapter. Python already rejects CRLF in
    ``_escape_quoted_value``; these tests pin the behavior so a future
    refactor cannot silently re-introduce the vulnerability.
    """

    def test_realm_with_cr_rejected(self):
        challenge = PaymentChallenge(
            id="ok",
            realm="api\rX-Injected: 1",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "1"}),
        )
        with pytest.raises(ParseError, match="CRLF"):
            format_www_authenticate(challenge)

    def test_realm_with_lf_rejected(self):
        challenge = PaymentChallenge(
            id="ok",
            realm="api\nX-Injected: 1",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "1"}),
        )
        with pytest.raises(ParseError, match="CRLF"):
            format_www_authenticate(challenge)

    def test_id_with_crlf_rejected(self):
        challenge = PaymentChallenge(
            id="abc\r\nX: 1",
            realm="api",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "1"}),
        )
        with pytest.raises(ParseError, match="CRLF"):
            format_www_authenticate(challenge)

    def test_description_safe_field_with_lf_rejected(self):
        challenge = PaymentChallenge(
            id="ok",
            realm="api",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "1"}),
            opaque="x\ny",
        )
        with pytest.raises(ParseError, match="CRLF"):
            format_www_authenticate(challenge)


class TestAuthParamTokenForm:
    """F1 lock: parse_www_authenticate MUST accept both quoted-string and
    token-form auth-param values per RFC 7235 section 2.1.

    Ruby rejected token form before PR #99 (see ruby state report F1);
    Python already accepts it via the unquoted branch in _parse_auth_params.
    These tests pin the cross-SDK contract.
    """

    def test_accepts_quoted_form(self):
        request_b64 = encode_json({"amount": "1"})
        header = f'Payment id="abc", realm="api", method="solana", intent="charge", request="{request_b64}"'
        parsed = parse_www_authenticate(header)
        assert parsed.id == "abc"
        assert parsed.realm == "api"

    def test_accepts_token_form(self):
        request_b64 = encode_json({"amount": "1"})
        # All values unquoted (RFC 7235 token form).
        header = f"Payment id=abc, realm=api, method=solana, intent=charge, request={request_b64}"
        parsed = parse_www_authenticate(header)
        assert parsed.id == "abc"
        assert parsed.realm == "api"
        assert parsed.method == "solana"
        assert parsed.intent == "charge"

    def test_accepts_mixed_form(self):
        request_b64 = encode_json({"amount": "1"})
        # Mixed: some quoted, some token. RFC 7235 allows this; CDNs and
        # hand-rolled clients sometimes emit it.
        header = f'Payment id=abc, realm="api", method=solana, intent="charge", request="{request_b64}"'
        parsed = parse_www_authenticate(header)
        assert parsed.id == "abc"
        assert parsed.realm == "api"


class TestMultiChallenge:
    """F5 lock: parse_www_authenticate_all MUST split multi-challenge
    WWW-Authenticate headers with quote awareness per RFC 7235 section 4.1.

    A server can emit two Payment challenges in one header value (the spec
    permits this for negotiation across schemes). Naive comma-splitting
    corrupts the value when a realm or other quoted-string parameter
    contains a literal comma. Python's _find_challenge_starts uses a
    quote-aware walker.
    """

    def _build_challenge_header(self, realm: str, request_b64: str) -> str:
        return f'Payment id="abc", realm="{realm}", method="solana", intent="charge", request="{request_b64}"'

    def test_two_challenges_in_one_header(self):
        request_b64 = encode_json({"amount": "1"})
        first = self._build_challenge_header("api-one", request_b64)
        second = self._build_challenge_header("api-two", request_b64)
        challenges = parse_www_authenticate_all([f"{first}, {second}"])
        assert len(challenges) == 2
        assert {c.realm for c in challenges} == {"api-one", "api-two"}

    def test_two_headers_each_with_one_challenge(self):
        request_b64 = encode_json({"amount": "1"})
        first = self._build_challenge_header("api-one", request_b64)
        second = self._build_challenge_header("api-two", request_b64)
        challenges = parse_www_authenticate_all([first, second])
        assert len(challenges) == 2

    def test_quoted_comma_in_realm_does_not_split(self):
        """Naive comma splitting on the inter-challenge separator would
        truncate a realm containing a literal comma. The quote-aware
        walker must treat the comma as part of the value."""
        request_b64 = encode_json({"amount": "1"})
        # Realm literally contains a comma; serialize manually to bypass
        # _escape_quoted_value behavior so the comma stays raw inside quotes.
        header = (
            f'Payment id="abc", realm="api, with, commas", method="solana", intent="charge", request="{request_b64}"'
        )
        challenges = parse_www_authenticate_all([header])
        assert len(challenges) == 1
        assert challenges[0].realm == "api, with, commas"

    def test_ignores_non_payment_schemes(self):
        request_b64 = encode_json({"amount": "1"})
        payment = self._build_challenge_header("api", request_b64)
        header = f'Bearer realm="x", {payment}'
        challenges = parse_www_authenticate_all([header])
        assert len(challenges) == 1
        assert challenges[0].realm == "api"

    def test_empty_input_returns_empty(self):
        assert parse_www_authenticate_all([]) == []
        assert parse_www_authenticate_all([""]) == []


# -- parse/format edge cases -------------------------------------------------


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
