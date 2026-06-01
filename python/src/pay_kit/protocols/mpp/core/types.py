"""Core protocol types."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pay_kit.protocols.mpp.core.base64url import decode_json, encode_json
from pay_kit.protocols.mpp.core.challenge import compute_challenge_id, constant_time_equal

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


def _parse_rfc3339(value: str) -> datetime:
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


@dataclass
class PaymentChallenge:
    """Payment challenge from server (parsed from WWW-Authenticate header)."""

    id: str
    realm: str
    method: str  # e.g. "solana"
    intent: str  # e.g. "charge"
    request: str  # base64url-encoded JSON
    expires: str = ""
    description: str = ""
    digest: str = ""
    opaque: str | None = None

    @staticmethod
    def with_secret_key(
        secret_key: str,
        realm: str,
        method: str,
        intent: str,
        request: str,
        expires: str = "",
        digest: str = "",
        description: str = "",
        opaque: str | None = None,
    ) -> PaymentChallenge:
        """Create a challenge with an HMAC-bound ID."""
        challenge_id = compute_challenge_id(
            secret_key=secret_key,
            realm=realm,
            method=method,
            intent=intent,
            request=request,
            expires=expires,
            digest=digest,
            opaque=opaque,
        )
        return PaymentChallenge(
            id=challenge_id,
            realm=realm,
            method=method,
            intent=intent,
            request=request,
            expires=expires,
            description=description,
            digest=digest,
            opaque=opaque,
        )

    def verify(self, secret_key: str) -> bool:
        """Verify that this challenge's ID matches the expected HMAC."""
        expected_id = compute_challenge_id(
            secret_key=secret_key,
            realm=self.realm,
            method=self.method,
            intent=self.intent,
            request=self.request,
            expires=self.expires,
            digest=self.digest,
            opaque=self.opaque,
        )
        return constant_time_equal(self.id, expected_id)

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return True if the challenge has expired.

        Uses strict RFC 3339 parsing (F6 lock). A malformed ``expires`` value
        fails closed (treated as expired) rather than silently falling back
        to an epoch timestamp. This matches the cross-SDK behavior that
        landed on Ruby + PHP + Lua in PR #99 / #102 and prevents a tampered
        ``expires="tomorrow"`` from extending a challenge indefinitely.
        """
        if not self.expires:
            return False
        try:
            expires_at = _parse_rfc3339(self.expires)
        except (ValueError, TypeError):
            return True  # fail-closed on invalid RFC 3339
        ref = now if now is not None else datetime.now(UTC)
        return expires_at <= ref

    def to_echo(self) -> ChallengeEcho:
        """Create a challenge echo for use in credentials."""
        return ChallengeEcho(
            id=self.id,
            realm=self.realm,
            method=self.method,
            intent=self.intent,
            request=self.request,
            expires=self.expires,
            digest=self.digest,
            opaque=self.opaque,
        )

    def decode_request(self) -> dict[str, Any]:
        """Decode the base64url request field into a dict."""
        return decode_json(self.request)

    @staticmethod
    def encode_request(obj: dict[str, Any]) -> str:
        """Encode a dict into a base64url request string."""
        return encode_json(obj)


@dataclass
class ChallengeEcho:
    """Challenge echo in credential (echoes server challenge parameters)."""

    id: str
    realm: str
    method: str
    intent: str
    request: str  # raw base64url string
    expires: str = ""
    digest: str = ""
    opaque: str | None = None


@dataclass
class PaymentCredential:
    """Payment credential from client (sent in Authorization header)."""

    challenge: ChallengeEcho
    payload: dict[str, Any] = field(default_factory=dict)
    source: str | None = None


@dataclass
class Receipt:
    """Payment receipt from server (parsed from Payment-Receipt header)."""

    status: str  # "success"
    method: str
    timestamp: str
    reference: str
    challenge_id: str = ""
    external_id: str = ""

    def is_success(self) -> bool:
        """Return True if the receipt indicates success."""
        return self.status == "success"

    @staticmethod
    def success(
        method: str,
        reference: str,
        challenge_id: str = "",
        external_id: str = "",
    ) -> Receipt:
        """Create a successful payment receipt with current timestamp."""
        return Receipt(
            status="success",
            method=method,
            timestamp=datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            reference=reference,
            challenge_id=challenge_id,
            external_id=external_id,
        )
