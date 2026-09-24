"""Timestamp helpers for challenge expiration."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

# RFC 3339 section 5.6 ``date-time`` grammar. The capture groups are
# year-month-day-T-hh-mm-ss[.frac][offset]. ``T`` and ``Z`` may appear in
# upper or lower case (per RFC 3339 §4.2 note that lowercase is permitted).
# Offset is either ``Z``/``z`` or ``+HH:MM`` / ``-HH:MM``.
_RFC3339_RE = re.compile(
    r"^"
    r"(\d{4})-(\d{2})-(\d{2})"  # full-date
    r"[Tt]"  # time separator
    r"(\d{2}):(\d{2}):(\d{2})"  # partial-time hh:mm:ss
    r"(\.\d+)?"  # optional time-secfrac
    r"(?:[Zz]|([+-])(\d{2}):(\d{2}))"  # time-offset
    r"$"
)


def parse_rfc3339(value: str) -> datetime:
    """Parse a strict RFC 3339 timestamp.

    Raises :class:`ValueError` on anything looser than RFC 3339 (e.g. a space
    instead of ``T``, a missing offset, or an invalid month/day combination).
    Mirrors the F6 lock that landed on Ruby + PHP + Lua in PR #99 / #102.
    """
    match = _RFC3339_RE.match(value)
    if match is None:
        raise ValueError(f"not a valid RFC 3339 timestamp: {value!r}")
    # Delegate the calendar arithmetic to datetime.fromisoformat after we have
    # confirmed the lexical grammar. Normalize the case of the T/Z markers so
    # fromisoformat (Python 3.11+) accepts the value.
    normalized = value.replace("t", "T").replace("z", "Z")
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    return datetime.fromisoformat(normalized)


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
