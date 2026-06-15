"""Timestamp helpers for challenge expiration."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def _to_rfc3339(dt: datetime) -> str:
    """Format a datetime as RFC3339 with Z suffix and millisecond precision."""
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def seconds(n: int) -> str:
    """Return an RFC3339 timestamp `n` seconds from now."""
    return _to_rfc3339(datetime.now(UTC) + timedelta(seconds=n))


def minutes(n: int) -> str:
    """Return an RFC3339 timestamp `n` minutes from now."""
    return _to_rfc3339(datetime.now(UTC) + timedelta(minutes=n))


def hours(n: int) -> str:
    """Return an RFC3339 timestamp `n` hours from now."""
    return _to_rfc3339(datetime.now(UTC) + timedelta(hours=n))


def days(n: int) -> str:
    """Return an RFC3339 timestamp `n` days from now."""
    return _to_rfc3339(datetime.now(UTC) + timedelta(days=n))


def weeks(n: int) -> str:
    """Return an RFC3339 timestamp `n` weeks from now."""
    return _to_rfc3339(datetime.now(UTC) + timedelta(weeks=n))
