"""Tests for _challenge module."""

from __future__ import annotations

from pay_kit.protocols.mpp.core.challenge import compute_challenge_id, constant_time_equal


class TestComputeChallengeId:
    def test_deterministic(self):
        id1 = compute_challenge_id("key", "realm", "solana", "charge", "req")
        id2 = compute_challenge_id("key", "realm", "solana", "charge", "req")
        assert id1 == id2

    def test_changes_with_key(self):
        base = compute_challenge_id("key", "realm", "solana", "charge", "req")
        diff = compute_challenge_id("key2", "realm", "solana", "charge", "req")
        assert base != diff

    def test_changes_with_realm(self):
        base = compute_challenge_id("key", "realm", "solana", "charge", "req")
        diff = compute_challenge_id("key", "other", "solana", "charge", "req")
        assert base != diff

    def test_changes_with_method(self):
        base = compute_challenge_id("key", "realm", "solana", "charge", "req")
        diff = compute_challenge_id("key", "realm", "bitcoin", "charge", "req")
        assert base != diff

    def test_changes_with_intent(self):
        base = compute_challenge_id("key", "realm", "solana", "charge", "req")
        diff = compute_challenge_id("key", "realm", "solana", "subscribe", "req")
        assert base != diff

    def test_changes_with_request(self):
        base = compute_challenge_id("key", "realm", "solana", "charge", "req")
        diff = compute_challenge_id("key", "realm", "solana", "charge", "xyz")
        assert base != diff

    def test_changes_with_expires(self):
        base = compute_challenge_id("key", "realm", "solana", "charge", "req")
        diff = compute_challenge_id("key", "realm", "solana", "charge", "req", expires="2099-01-01T00:00:00Z")
        assert base != diff

    def test_changes_with_digest(self):
        base = compute_challenge_id("key", "realm", "solana", "charge", "req")
        diff = compute_challenge_id("key", "realm", "solana", "charge", "req", digest="sha-256=abc")
        assert base != diff

    def test_changes_with_opaque(self):
        base = compute_challenge_id("key", "realm", "solana", "charge", "req")
        diff = compute_challenge_id("key", "realm", "solana", "charge", "req", opaque="opaque-data")
        assert base != diff

    def test_result_is_base64url(self):
        result = compute_challenge_id("key", "realm", "solana", "charge", "req")
        assert "=" not in result
        assert "+" not in result
        assert "/" not in result
        assert len(result) > 0


class TestConstantTimeEqual:
    def test_equal_strings(self):
        assert constant_time_equal("hello", "hello")

    def test_empty_strings(self):
        assert constant_time_equal("", "")

    def test_different_content(self):
        assert not constant_time_equal("hello", "world")

    def test_different_length(self):
        assert not constant_time_equal("short", "longer-string")
