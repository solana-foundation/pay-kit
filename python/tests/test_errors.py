"""Tests for _errors module."""

from __future__ import annotations

from solana_pay_kit._paycore.errors import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    PaymentError,
    ReplayError,
    VerificationError,
)


def test_payment_error():
    err = PaymentError("test error", code="test-code", retryable=True)
    assert str(err) == "test error"
    assert err.code == "test-code"
    assert err.retryable is True


def test_payment_error_defaults():
    err = PaymentError("msg")
    assert err.code == ""
    assert err.retryable is False


def test_verification_error_is_payment_error():
    err = VerificationError("bad signature")
    assert isinstance(err, PaymentError)
    assert str(err) == "bad signature"


def test_challenge_expired_error():
    err = ChallengeExpiredError()
    assert isinstance(err, PaymentError)
    assert err.code == "challenge-expired"
    assert "expired" in str(err)


def test_challenge_mismatch_error():
    err = ChallengeMismatchError()
    assert isinstance(err, PaymentError)
    assert err.code == "challenge-mismatch"
    assert "mismatch" in str(err)


def test_replay_error():
    err = ReplayError()
    assert isinstance(err, PaymentError)
    assert err.code == "signature-consumed"
    assert "consumed" in str(err)


def test_custom_replay_error():
    err = ReplayError("custom message", code="custom-code")
    assert str(err) == "custom message"
    assert err.code == "custom-code"


class TestCanonicalCodes:
    """L6 / P1 lock: every 402 path emits one of the canonical codes."""

    def test_canonical_codes_set(self):
        from solana_pay_kit._paycore.errors import CANONICAL_CODES

        assert (
            frozenset(
                {
                    "charge_request_mismatch",
                    "challenge_route_mismatch",
                    "challenge_verification_failed",
                    "challenge_expired",
                    "payment_invalid",
                    "wrong_network",
                    "signature_consumed",
                }
            )
            == CANONICAL_CODES
        )

    def test_canonical_code_returns_canonical_unchanged(self):
        from solana_pay_kit._paycore.errors import canonical_code

        assert canonical_code("payment_invalid") == "payment_invalid"
        assert canonical_code("wrong_network") == "wrong_network"

    def test_canonical_code_maps_legacy_kebab(self):
        from solana_pay_kit._paycore.errors import canonical_code

        assert canonical_code("challenge-expired") == "challenge_expired"
        assert canonical_code("signature-consumed") == "signature_consumed"
        assert canonical_code("wrong-network") == "wrong_network"
        assert canonical_code("amount-mismatch") == "charge_request_mismatch"
        assert canonical_code("recipient-mismatch") == "charge_request_mismatch"
        assert canonical_code("challenge-mismatch") == "challenge_verification_failed"
        assert canonical_code("invalid-payload") == "payment_invalid"

    def test_route_mismatch_distinguished_from_hmac_failure(self):
        # L6 lock: a credential with a valid HMAC but pinned to a different
        # route/realm/method/intent/currency MUST surface as
        # ``challenge_route_mismatch``, not as ``challenge_verification_failed``.
        # Codex P2 fix.
        from solana_pay_kit._paycore.errors import canonical_code

        assert canonical_code("challenge-mismatch") == "challenge_verification_failed"
        assert canonical_code("currency-mismatch") == "challenge_route_mismatch"
        assert canonical_code("method-mismatch") == "challenge_route_mismatch"
        assert canonical_code("intent-mismatch") == "challenge_route_mismatch"
        assert canonical_code("realm-mismatch") == "challenge_route_mismatch"

    def test_canonical_code_falls_back_to_payment_invalid(self):
        from solana_pay_kit._paycore.errors import canonical_code

        assert canonical_code("unknown-thing") == "payment_invalid"
        assert canonical_code("") == "payment_invalid"


class TestPaymentRequiredResponseBuilder:
    def test_emits_canonical_code(self):
        from solana_pay_kit._paycore.errors import payment_required_response

        resp = payment_required_response("nope", code="challenge-expired")
        assert resp["status_code"] == 402
        assert resp["body"]["code"] == "challenge_expired"
        assert resp["body"]["error"] == "challenge_expired"
        assert "challenge_expired" in resp["body"]["type"]
        assert resp["body"]["message"] == "nope"
        assert resp["headers"]["cache-control"] == "no-store"
        assert resp["headers"]["content-type"] == "application/problem+json"

    def test_includes_challenge_header_when_provided(self):
        from solana_pay_kit._paycore.errors import payment_required_response

        resp = payment_required_response("challenge", code="payment_invalid", challenge_header='Payment id="x"')
        assert resp["headers"]["www-authenticate"] == 'Payment id="x"'

    def test_omits_challenge_header_by_default(self):
        from solana_pay_kit._paycore.errors import payment_required_response

        resp = payment_required_response("x", code="payment_invalid")
        assert "www-authenticate" not in resp["headers"]

    def test_unknown_code_falls_back_to_payment_invalid(self):
        from solana_pay_kit._paycore.errors import payment_required_response

        resp = payment_required_response("x", code="foo-bar-baz")
        assert resp["body"]["code"] == "payment_invalid"
