"""Tests for _expires module."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from solana_pay_kit.protocols.mpp.core.expires import days, hours, minutes, seconds, weeks


def _parse_timestamp(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def test_seconds():
    ts = seconds(60)
    dt = _parse_timestamp(ts)
    now = datetime.now(UTC)
    # Should be about 60 seconds from now (+/- 2 seconds for test execution)
    diff = (dt - now).total_seconds()
    assert 58 < diff < 62


def test_minutes():
    ts = minutes(5)
    dt = _parse_timestamp(ts)
    now = datetime.now(UTC)
    diff = (dt - now).total_seconds()
    assert 298 < diff < 302


def test_hours():
    ts = hours(1)
    dt = _parse_timestamp(ts)
    now = datetime.now(UTC)
    diff = (dt - now).total_seconds()
    assert 3598 < diff < 3602


def test_days():
    ts = days(1)
    dt = _parse_timestamp(ts)
    now = datetime.now(UTC)
    diff = (dt - now).total_seconds()
    assert 86398 < diff < 86402


def test_weeks():
    ts = weeks(1)
    dt = _parse_timestamp(ts)
    now = datetime.now(UTC)
    diff = (dt - now).total_seconds()
    assert 604798 < diff < 604802


def test_format_ends_with_z():
    ts = seconds(10)
    assert ts.endswith("Z")


def test_format_has_milliseconds():
    ts = seconds(10)
    # Should have millisecond precision: ...T12:34:56.789Z
    parts = ts.split(".")
    assert len(parts) == 2
    assert parts[1].endswith("Z")
    assert len(parts[1]) == 4  # "789Z"


class TestStrictRFC3339:
    """F6 lock: PaymentChallenge.is_expired MUST use strict RFC 3339.

    A malformed expires value fails closed (treated as expired) rather than
    silently falling back to epoch. Mirrors the cross-SDK lock that landed
    on Ruby + PHP + Lua in PR #99 / #102.
    """

    def _make_challenge(self, expires: str):
        from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge

        return PaymentChallenge(
            id="x",
            realm="api",
            method="solana",
            intent="charge",
            request="e30",
            expires=expires,
        )

    def test_empty_expires_never_expired(self):
        assert self._make_challenge("").is_expired() is False

    def test_future_iso_accepted(self):
        assert self._make_challenge("2099-01-01T00:00:00Z").is_expired() is False

    def test_past_iso_expired(self):
        assert self._make_challenge("2000-01-01T00:00:00Z").is_expired() is True

    def test_lowercase_t_z_accepted(self):
        # RFC 3339 §4.2 NOTE permits lowercase t and z.
        assert self._make_challenge("2099-01-01t00:00:00z").is_expired() is False

    def test_numeric_offset_accepted(self):
        assert self._make_challenge("2099-01-01T00:00:00+02:00").is_expired() is False

    def test_milliseconds_accepted(self):
        assert self._make_challenge("2099-01-01T00:00:00.123Z").is_expired() is False

    def test_missing_offset_rejected(self):
        # No Z, no +/-HH:MM. Strict grammar fails closed.
        assert self._make_challenge("2099-01-01T00:00:00").is_expired() is True

    def test_space_separator_rejected(self):
        # Space instead of T or t. Lax ISO 8601 accepts this; RFC 3339 does
        # not. Fail closed.
        assert self._make_challenge("2099-01-01 00:00:00Z").is_expired() is True

    def test_garbage_string_rejected(self):
        assert self._make_challenge("tomorrow").is_expired() is True

    def test_missing_seconds_rejected(self):
        # ``2099-01-01T00:00Z`` is valid ISO 8601 but not RFC 3339 (seconds
        # are required by §5.6 ``partial-time``).
        assert self._make_challenge("2099-01-01T00:00Z").is_expired() is True

    def test_two_digit_year_rejected(self):
        # ``99-01-01T00:00:00Z`` is not RFC 3339.
        assert self._make_challenge("99-01-01T00:00:00Z").is_expired() is True

    def test_invalid_month_rejected(self):
        # Lexically valid RFC 3339 shape, but month 13 fails the calendar
        # check delegated to datetime.fromisoformat.
        assert self._make_challenge("2099-13-01T00:00:00Z").is_expired() is True


# ── Cross-SDK RFC 3339 conformance corpus (issue #111) ──

_CORPUS_PATH = (
    Path(__file__).resolve().parents[2]
    / "harness"
    / "vectors"
    / "mpp-protocol"
    / "expires.json"
)


def _load_vectors() -> list[tuple[str, str, bool, str]]:
    """Return every scenario in the shared corpus.

    Yields ``(name, input, expect_accept, description)``. Every scenario in the
    file is an ``expires`` verdict; there is no slice to select and no scenario
    to skip.

    Verdict encoding, identical to the other vector files in the same
    directory: ``"tests": {"parse": true}`` is ACCEPT, and
    ``"tests": {"parse": {"success": false, ...}}`` is REJECT.
    """
    corpus = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
    vectors: list[tuple[str, str, bool, str]] = []
    for scenario in corpus["scenarios"]:
        expectation = scenario["tests"]["parse"]
        expect_accept = expectation is True
        vectors.append(
            (scenario["name"], scenario["input"], expect_accept, scenario["description"])
        )
    return vectors


_VECTORS = _load_vectors()


class TestRFC3339ConformanceCorpus:
    """Every SDK asserts the same ACCEPT/REJECT verdict on the same vectors.

    A divergence between two SDKs then shows up as a failing test in exactly
    one of them rather than as silence.

    This class covers ``_parse_rfc3339`` in
    ``solana_pay_kit.protocols.mpp.core.types`` — the grammar
    ``PaymentChallenge.is_expired`` delegates to, and therefore the one an
    ``expires`` field is actually checked against. It raises ``ValueError`` on
    a reject and returns a ``datetime`` on an accept, so the verdict is
    unambiguous.

    Note for reviewers: this SDK carries a *second* RFC 3339 grammar,
    ``_ISO8601_RE`` in ``solana_pay_kit.protocols.mpp.core.headers``, which
    gates receipt timestamps. It is a different regex and it is not covered
    here. Wiring the same corpus to that surface is a separate change.
    """

    @pytest.mark.parametrize(
        ("name", "value", "expect_accept", "description"),
        _VECTORS,
        ids=[vector[0] for vector in _VECTORS],
    )
    def test_vector(self, name: str, value: str, expect_accept: bool, description: str):
        from solana_pay_kit.protocols.mpp.core.types import _parse_rfc3339

        try:
            _parse_rfc3339(value)
            accepted = True
        except ValueError:
            accepted = False

        assert accepted is expect_accept, (
            f"{name} ({description}): input {value!r} — "
            f"corpus expects {'ACCEPT' if expect_accept else 'REJECT'}, "
            f"_parse_rfc3339 reports {'ACCEPT' if accepted else 'REJECT'}"
        )

    def test_every_corpus_scenario_is_exercised(self):
        """Guard the loader: a regression in it must not go silent.

        A truncated or empty read fails here rather than passing quietly with
        nothing left to run.
        """
        corpus = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
        assert len(_VECTORS) == len(corpus["scenarios"])
        assert len(_VECTORS) > 0
