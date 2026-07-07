"""Tests for _types module."""

from __future__ import annotations

from datetime import UTC, datetime

from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge, Receipt


class TestPaymentChallenge:
    def test_with_secret_key_creates_challenge(self):
        request = encode_json({"amount": "1000"})
        challenge = PaymentChallenge.with_secret_key(
            secret_key="test-secret",
            realm="api.example.com",
            method="solana",
            intent="charge",
            request=request,
        )
        assert challenge.id != ""
        assert challenge.realm == "api.example.com"
        assert challenge.method == "solana"
        assert challenge.intent == "charge"

    def test_verify_correct_secret(self):
        request = encode_json({"amount": "1000"})
        challenge = PaymentChallenge.with_secret_key(
            secret_key="test-secret",
            realm="api.example.com",
            method="solana",
            intent="charge",
            request=request,
        )
        assert challenge.verify("test-secret")

    def test_verify_wrong_secret(self):
        request = encode_json({"amount": "1000"})
        challenge = PaymentChallenge.with_secret_key(
            secret_key="test-secret",
            realm="api.example.com",
            method="solana",
            intent="charge",
            request=request,
        )
        assert not challenge.verify("wrong-secret")

    def test_verify_with_all_optional_fields(self):
        request = encode_json({"amount": "5000"})
        opaque = encode_json({"context": "xyz"})
        challenge = PaymentChallenge.with_secret_key(
            secret_key="my-secret",
            realm="realm.example.com",
            method="solana",
            intent="charge",
            request=request,
            expires="2099-01-01T00:00:00Z",
            digest="sha-256=abc123",
            description="Pay for coffee",
            opaque=opaque,
        )
        assert challenge.verify("my-secret")
        assert not challenge.verify("other-secret")

    def test_is_expired_no_expires(self):
        request = encode_json({})
        challenge = PaymentChallenge.with_secret_key(
            secret_key="s", realm="r", method="solana", intent="charge", request=request
        )
        assert not challenge.is_expired()

    def test_is_expired_future(self):
        request = encode_json({})
        challenge = PaymentChallenge.with_secret_key(
            secret_key="s",
            realm="r",
            method="solana",
            intent="charge",
            request=request,
            expires="2099-01-01T00:00:00Z",
        )
        assert not challenge.is_expired()

    def test_is_expired_past(self):
        request = encode_json({})
        challenge = PaymentChallenge.with_secret_key(
            secret_key="s",
            realm="r",
            method="solana",
            intent="charge",
            request=request,
            expires="2020-01-01T00:00:00Z",
        )
        assert challenge.is_expired()

    def test_is_expired_invalid_timestamp(self):
        challenge = PaymentChallenge(
            id="x", realm="r", method="solana", intent="charge", request="e30", expires="not-a-date"
        )
        assert challenge.is_expired()

    def test_is_expired_with_custom_now(self):
        request = encode_json({})
        challenge = PaymentChallenge.with_secret_key(
            secret_key="s",
            realm="r",
            method="solana",
            intent="charge",
            request=request,
            expires="2025-06-01T00:00:00Z",
        )
        past = datetime(2025, 1, 1, tzinfo=UTC)
        future = datetime(2025, 12, 1, tzinfo=UTC)
        assert not challenge.is_expired(now=past)
        assert challenge.is_expired(now=future)

    def test_to_echo(self):
        request = encode_json({"x": 1})
        challenge = PaymentChallenge(
            id="id-456",
            realm="realm",
            method="solana",
            intent="charge",
            request=request,
            expires="2099-01-01T00:00:00Z",
            digest="sha-256=deadbeef",
            opaque="opaque-data",
        )
        echo = challenge.to_echo()
        assert echo.id == "id-456"
        assert echo.realm == "realm"
        assert echo.method == "solana"
        assert echo.expires == "2099-01-01T00:00:00Z"
        assert echo.digest == "sha-256=deadbeef"
        assert echo.opaque == "opaque-data"

    def test_decode_request(self):
        obj = {"amount": "1000", "currency": "USDC"}
        request = encode_json(obj)
        challenge = PaymentChallenge(id="x", realm="r", method="solana", intent="charge", request=request)
        assert challenge.decode_request() == obj


class TestReceipt:
    def test_success_receipt(self):
        receipt = Receipt.success(method="solana", reference="sig123", challenge_id="ch-1")
        assert receipt.is_success()
        assert receipt.method == "solana"
        assert receipt.reference == "sig123"
        assert receipt.challenge_id == "ch-1"

    def test_timestamp_is_rfc3339(self):
        receipt = Receipt.success(method="solana", reference="ref")
        # Should end with Z
        assert receipt.timestamp.endswith("Z")
        # Should be parseable
        ts = receipt.timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        assert dt.tzinfo is not None

    def test_is_success_false(self):
        receipt = Receipt(status="failed", method="solana", timestamp="", reference="")
        assert not receipt.is_success()
