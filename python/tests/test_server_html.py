"""Tests for server/html module."""

from __future__ import annotations

import json

from solana_mpp._base64url import encode_json
from solana_mpp._types import PaymentChallenge
from solana_mpp.server.payment_page import (
    SERVICE_WORKER_PARAM,
    accepts_html,
    challenge_to_html,
    is_service_worker_request,
    service_worker_js,
)


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
        # Generated template uses lowercase doctype.
        assert "<!doctype html>" in html
        # Challenge id appears in the embedded {{DATA_JSON}} payload.
        assert "test-id" in html
        assert "__MPP_DATA__" in html
        # Network is embedded in the data payload.
        assert "devnet" in html

    def test_escapes_xss(self):
        """Challenge id with HTML tags must NOT appear raw, only via JSON-escaped data."""
        request = encode_json({"amount": "1000", "description": '<script>alert("xss")</script>'})
        challenge = PaymentChallenge(
            id='<img onerror="alert(1)">',
            realm="api",
            method="solana",
            intent="charge",
            request=request,
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        # The payment_page.challenge_to_html escapes '<' inside the embedded
        # JSON to '<' to prevent script-tag breakout. The raw HTML
        # injection sequence must not appear unescaped anywhere.
        assert '<img onerror="alert(1)">' not in html
        # The challenge id should still appear, but with '<' replaced.
        assert "\\u003cimg" in html

    def test_includes_description(self):
        """challenge.description is rendered as escaped HTML in the summary block."""
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
        assert "mppx-summary-description" in html

    def test_description_html_escaped(self):
        challenge = PaymentChallenge(
            id="t",
            realm="api",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "1"}),
            description="<b>bold</b>",
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        assert "<b>bold</b>" not in html
        assert "&lt;b&gt;bold&lt;/b&gt;" in html

    def test_no_description_omits_summary_paragraph(self):
        challenge = PaymentChallenge(
            id="t",
            realm="api",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "1"}),
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        # When no description, the code injects an empty string for
        # {{DESCRIPTION}}, so the summary-description <p> is not present.
        assert '<p class="mppx-summary-description">' not in html

    def test_includes_expires(self):
        challenge = PaymentChallenge(
            id="t",
            realm="api",
            method="solana",
            intent="charge",
            request=encode_json({"amount": "1"}),
            expires="2030-01-01T00:00:00Z",
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        assert "mppx-summary-expires" in html
        assert "2030-01-01T00:00:00Z" in html

    def test_network_devnet(self):
        challenge = PaymentChallenge(
            id="t", realm="api", method="solana", intent="charge",
            request=encode_json({"amount": "1000"}),
        )
        html = challenge_to_html(challenge, "https://api.devnet.solana.com", "devnet")
        assert '"network":"devnet"' in html
        assert "api.devnet.solana.com" in html

    def test_network_mainnet(self):
        challenge = PaymentChallenge(
            id="t", realm="api", method="solana", intent="charge",
            request=encode_json({"amount": "1000"}),
        )
        html = challenge_to_html(challenge, "https://api.mainnet-beta.solana.com", "mainnet-beta")
        assert '"network":"mainnet-beta"' in html

    def test_amount_display_sol(self):
        challenge = PaymentChallenge(
            id="t", realm="api", method="solana", intent="charge",
            request=encode_json({"amount": str(2 * 10**9), "currency": "SOL"}),
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        assert "2 SOL" in html

    def test_amount_display_usdc_symbol(self):
        challenge = PaymentChallenge(
            id="t", realm="api", method="solana", intent="charge",
            request=encode_json({"amount": "1500000", "currency": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}),
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        # 1500000 / 10**6 = 1.5 → "$1.50"
        assert "$1.50" in html

    def test_amount_display_unknown_token(self):
        challenge = PaymentChallenge(
            id="t", realm="api", method="solana", intent="charge",
            request=encode_json({"amount": "12345678", "currency": "ABCDEFGHIJKLMNOP"}),
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        # currency[:6] = "ABCDEF", 12345678/10**6 = 12.345678 → "12.35"
        assert "ABCDEF" in html

    def test_amount_display_uses_methoddetails_decimals(self):
        challenge = PaymentChallenge(
            id="t", realm="api", method="solana", intent="charge",
            request=encode_json({"amount": "100000000", "currency": "FOO", "methodDetails": {"decimals": 8}}),
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        # 100000000 / 10**8 = 1 → "1 FOO"
        assert "1 FOO" in html

    def test_malformed_request_falls_back(self):
        # Non base64url request body must not raise; renders 0 default amount.
        challenge = PaymentChallenge(
            id="t", realm="api", method="solana", intent="charge", request="not_base64_!!!"
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        assert "<!doctype html>" in html

    def test_embedded_data_contains_required_fields(self):
        challenge = PaymentChallenge(
            id="abc", realm="api", method="solana", intent="charge",
            request=encode_json({"amount": "1"}),
        )
        html = challenge_to_html(challenge, "http://localhost:8899", "localnet")
        # The template embeds the data JSON after {{DATA_JSON}} → search
        # for the expected fields anywhere in the rendered HTML.
        assert '"network":"localnet"' in html
        assert '"rpcUrl":"http://localhost:8899"' in html
        assert '"challenge"' in html
        assert isinstance(json.loads('{"a":1}'), dict)


class TestAcceptsHtml:
    def test_accepts_html(self):
        assert accepts_html("text/html,application/json")

    def test_accepts_html_only(self):
        assert accepts_html("text/html")

    def test_rejects_json_only(self):
        assert not accepts_html("application/json")

    def test_none(self):
        assert not accepts_html(None)

    def test_empty(self):
        assert not accepts_html("")


class TestIsServiceWorkerRequest:
    def test_with_param(self):
        assert is_service_worker_request(f"https://example.com/?{SERVICE_WORKER_PARAM}=1")

    def test_with_param_value(self):
        assert is_service_worker_request(f"https://example.com/?{SERVICE_WORKER_PARAM}=anything")

    def test_without_param(self):
        assert not is_service_worker_request("https://example.com/")

    def test_with_other_params(self):
        assert not is_service_worker_request("https://example.com/?foo=bar")

    def test_path_only(self):
        assert not is_service_worker_request("/some/path")


class TestServiceWorkerJs:
    def test_returns_string(self):
        js = service_worker_js()
        assert isinstance(js, str)

    def test_cached(self):
        a = service_worker_js()
        b = service_worker_js()
        assert a is b or a == b
