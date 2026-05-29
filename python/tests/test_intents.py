"""Tests for protocol/intents module."""

from __future__ import annotations

import pytest

from pay_kit.protocols.mpp.intents.charge import ChargeRequest, parse_units, validate_max_amount


class TestParseUnits:
    def test_whole_number(self):
        assert parse_units("1", 6) == "1000000"

    def test_decimal(self):
        assert parse_units("1.5", 6) == "1500000"

    def test_small_decimal(self):
        assert parse_units("0.01", 2) == "1"

    def test_large_number(self):
        assert parse_units("100", 6) == "100000000"

    def test_zero(self):
        assert parse_units("0", 6) == "0"

    def test_zero_point_zero(self):
        assert parse_units("0.0", 6) == "0"

    def test_leading_decimal(self):
        assert parse_units(".5", 6) == "500000"

    def test_exact_decimals(self):
        assert parse_units("1.000001", 6) == "1000001"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="amount is required"):
            parse_units("", 6)

    def test_negative_raises(self):
        with pytest.raises(ValueError, match="cannot be negative"):
            parse_units("-1", 6)

    def test_too_many_decimals(self):
        with pytest.raises(ValueError, match="too many decimal places"):
            parse_units("1.1234567", 6)

    def test_multiple_dots_raises(self):
        with pytest.raises(ValueError, match="invalid amount"):
            parse_units("1.2.3", 6)

    def test_whitespace_stripped(self):
        assert parse_units("  1.5  ", 6) == "1500000"

    def test_zero_decimals(self):
        assert parse_units("100", 0) == "100"


class TestChargeRequest:
    def test_to_dict(self):
        req = ChargeRequest(amount="1000", currency="USDC", recipient="abc")
        d = req.to_dict()
        assert d["amount"] == "1000"
        assert d["currency"] == "USDC"
        assert d["recipient"] == "abc"

    def test_from_dict(self):
        d = {"amount": "1000", "currency": "USDC", "recipient": "abc", "externalId": "ext-1"}
        req = ChargeRequest.from_dict(d)
        assert req.amount == "1000"
        assert req.external_id == "ext-1"

    def test_optional_fields_omitted(self):
        req = ChargeRequest(amount="1000", currency="USDC")
        d = req.to_dict()
        assert "recipient" not in d
        assert "description" not in d
        assert "externalId" not in d
        assert "methodDetails" not in d


class TestValidateMaxAmount:
    def test_allows_amount_below_maximum(self):
        req = ChargeRequest(amount="1000", currency="USDC")

        validate_max_amount(req, "2000")

    def test_allows_amount_equal_to_maximum(self):
        req = ChargeRequest(amount="1000", currency="USDC")

        validate_max_amount(req, "1000")

    def test_rejects_amount_above_maximum(self):
        req = ChargeRequest(amount="1001", currency="USDC")

        with pytest.raises(ValueError, match="amount 1001 exceeds maximum 1000"):
            validate_max_amount(req, "1000")

    def test_rejects_invalid_amount(self):
        req = ChargeRequest(amount="not-a-number", currency="USDC")

        with pytest.raises(ValueError, match="invalid amount"):
            validate_max_amount(req, "1000")

    def test_rejects_invalid_max_amount(self):
        req = ChargeRequest(amount="1000", currency="USDC")

        with pytest.raises(ValueError, match="invalid max amount"):
            validate_max_amount(req, "not-a-number")
