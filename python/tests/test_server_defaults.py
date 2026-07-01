"""Tests for server/defaults module."""

from __future__ import annotations

import pytest

from solana_pay_kit.protocols.mpp.server.defaults import detect_realm, detect_secret_key


class TestDetectRealm:
    def test_from_mpp_realm(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MPP_REALM", "my-realm.com")
        assert detect_realm() == "my-realm.com"

    def test_from_fly_app_name(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("MPP_REALM", raising=False)
        monkeypatch.setenv("FLY_APP_NAME", "my-fly-app")
        assert detect_realm() == "my-fly-app"

    def test_fallback_to_localhost(self, monkeypatch: pytest.MonkeyPatch):
        for var in [
            "MPP_REALM",
            "FLY_APP_NAME",
            "HEROKU_APP_NAME",
            "HOST",
            "HOSTNAME",
            "RAILWAY_PUBLIC_DOMAIN",
            "RENDER_EXTERNAL_HOSTNAME",
            "VERCEL_URL",
            "WEBSITE_HOSTNAME",
        ]:
            monkeypatch.delenv(var, raising=False)
        assert detect_realm() == "localhost"


class TestDetectSecretKey:
    def test_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MPP_SECRET_KEY", "my-secret")
        assert detect_secret_key() == "my-secret"

    def test_missing_raises(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("MPP_SECRET_KEY", raising=False)
        with pytest.raises(ValueError, match="Missing secret key"):
            detect_secret_key()

    def test_empty_raises(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MPP_SECRET_KEY", "  ")
        with pytest.raises(ValueError, match="Missing secret key"):
            detect_secret_key()
