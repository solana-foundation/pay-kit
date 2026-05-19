"""Tests for server/html module."""

from __future__ import annotations

import json
import re

from solana_mpp._base64url import encode_json
from solana_mpp._types import PaymentChallenge
from solana_mpp.server.payment_page import (
    SERVICE_WORKER_PARAM,
    accepts_html,
    challenge_to_html,
    is_service_worker_request,
    service_worker_js,
)


def embedded_payment_data(html: str) -> dict:
    match = re.search(
        r'<script id="__MPP_DATA__" type="application/json">(.*?)</script>',
        html,
        re.DOTALL,
    )
    assert match is not None
    return json.loads(match.group(1))


class TestChallengeToHtml:
    def test_renders_html(self):
        request = encode_json({"amount": "1000000", "currency": "USDC"})
        challenge = PaymentChallenge(
            id="test-id",
            realm="api",
            method="solana",
            intent="charge",
            request=request,
        )
        html = challenge_to_html(challenge, "https://api.devnet.solana.com", "devnet")
        assert "<!doctype html>" in html
        assert "__MPP_DATA__" in html
        data = embedded_payment_data(html)
        assert data["challenge"]["id"] == "test-id"
        assert data["network"] == "devnet"
        assert data["rpcUrl"] == "https://api.devnet.solana.com"

    def test_escapes_xss(self):
        """Embedded challenge data should not inject raw HTML."""
        request = encode_json({"amount": "1000", "description": '<script>alert("xss")</script>'})
        challenge = PaymentChallenge(
            id='<img onerror="alert(1)">',
            realm="api",
            method="solana",
            intent="charge",
            request=request,
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        # Raw XSS should not appear unescaped
        assert '<img onerror="alert(1)">' not in html
        assert "\\u003cimg" in html
        assert embedded_payment_data(html)["challenge"]["id"] == '<img onerror="alert(1)">'

    def test_includes_description(self):
        request = encode_json({"amount": "1000"})
        challenge = PaymentChallenge(
            id="test",
            realm="api",
            method="solana",
            intent="charge",
            request=request,
            description="Test payment",
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        assert "Test payment" in html
        assert embedded_payment_data(html)["challenge"]["description"] == "Test payment"

    def test_embeds_devnet_network(self):
        request = encode_json({"amount": "1000"})
        challenge = PaymentChallenge(id="test", realm="api", method="solana", intent="charge", request=request)
        html = challenge_to_html(challenge, "https://api.devnet.solana.com", "devnet")
        assert embedded_payment_data(html)["network"] == "devnet"

    def test_embeds_mainnet_network(self):
        request = encode_json({"amount": "1000"})
        challenge = PaymentChallenge(id="test", realm="api", method="solana", intent="charge", request=request)
        html = challenge_to_html(challenge, "https://api.mainnet-beta.solana.com", "mainnet-beta")
        assert embedded_payment_data(html)["network"] == "mainnet-beta"


class TestAcceptsHtml:
    def test_accepts_html(self):
        assert accepts_html("text/html,application/json")

    def test_rejects_json_only(self):
        assert not accepts_html("application/json")

    def test_none(self):
        assert not accepts_html(None)


class TestIsServiceWorkerRequest:
    def test_with_param(self):
        assert is_service_worker_request(f"https://example.com/?{SERVICE_WORKER_PARAM}=1")

    def test_without_param(self):
        assert not is_service_worker_request("https://example.com/")

    def test_with_other_params(self):
        assert not is_service_worker_request("https://example.com/?foo=bar")


class TestServiceWorkerJs:
    def test_returns_string(self):
        js = service_worker_js()
        assert isinstance(js, str)
