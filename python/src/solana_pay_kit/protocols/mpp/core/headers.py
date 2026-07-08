"""Header parsing and formatting for Web Payment Auth.

No regex for auth-param parsing -- follows the same hand-rolled parser as the
Rust and Go implementations.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from solana_pay_kit.protocols.mpp.core.base64url import decode, decode_json, encode_json
from solana_pay_kit.protocols.mpp.core.types import ChallengeEcho, PaymentChallenge, PaymentCredential, Receipt

MAX_TOKEN_LEN = 16 * 1024

PAYMENT_SCHEME = "Payment"
WWW_AUTHENTICATE_HEADER = "www-authenticate"
AUTHORIZATION_HEADER = "authorization"
PAYMENT_RECEIPT_HEADER = "payment-receipt"


class ParseError(Exception):
    """Failed to parse a payment header."""


# ISO-8601 / RFC 3339 timestamp: YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM).
# Matches the canonical mpp-tools receipt timestamp validation; rejects loose
# forms like "Jan 29 2026 12:00".
_ISO8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


# ---------------------------------------------------------------------------
# WWW-Authenticate
# ---------------------------------------------------------------------------


def parse_www_authenticate(header: str) -> PaymentChallenge:
    """Parse a WWW-Authenticate header into a PaymentChallenge."""
    rest = _strip_payment_scheme(header)
    if rest is None:
        raise ParseError("Expected 'Payment' scheme")

    # Must have a space or tab separator
    if not rest or (rest[0] != " " and rest[0] != "\t"):
        raise ParseError("Expected space after 'Payment' scheme")

    params = _parse_auth_params(rest.lstrip())

    id_ = _require_param(params, "id")
    if not id_:
        raise ParseError("Empty 'id' parameter")

    realm = _require_param(params, "realm")
    method_raw = _require_param(params, "method")
    if not method_raw or not all(c.islower() and c.isascii() for c in method_raw):
        raise ParseError(f'Invalid method: "{method_raw}". Must be lowercase ASCII.')

    intent = _require_param(params, "intent")
    request_b64 = _require_param(params, "request")

    # Audit #9: cap the ``request`` parameter before base64url-decode + JSON
    # parse, matching ``parse_authorization`` / ``parse_receipt`` which cap the
    # token they decode. ``request`` is the only challenge field that drives
    # O(n) decode+parse cost; every other param is a short pass-through string.
    if len(request_b64) > MAX_TOKEN_LEN:
        raise ParseError(f"request parameter exceeds maximum length of {MAX_TOKEN_LEN} bytes")

    # Validate that request is valid base64url JSON
    try:
        request_bytes = decode(request_b64)
        json.loads(request_bytes)
    except Exception as exc:
        raise ParseError(f"Invalid JSON in request field: {exc}") from exc

    return PaymentChallenge(
        id=id_,
        realm=realm,
        method=method_raw,
        intent=intent,
        request=request_b64,
        expires=params.get("expires", ""),
        description=params.get("description", ""),
        digest=params.get("digest", ""),
        opaque=params.get("opaque"),
    )


def parse_www_authenticate_all(headers: Iterable[str]) -> list[PaymentChallenge]:
    """Parse all Payment challenges from one or more WWW-Authenticate values."""
    challenges: list[PaymentChallenge] = []
    for header in headers:
        for challenge in _extract_challenges(header, PAYMENT_SCHEME):
            try:
                challenges.append(parse_www_authenticate(challenge))
            except ParseError:
                continue
    return challenges


def format_www_authenticate(challenge: PaymentChallenge) -> str:
    """Format a PaymentChallenge as a WWW-Authenticate header value."""
    parts = [
        f'id="{_escape_quoted_value(challenge.id)}"',
        f'realm="{_escape_quoted_value(challenge.realm)}"',
        f'method="{_escape_quoted_value(challenge.method)}"',
        f'intent="{_escape_quoted_value(challenge.intent)}"',
        f'request="{_escape_quoted_value(challenge.request)}"',
    ]
    # Canonical mpp-tools order: description, digest, expires after request.
    # description round-trips as a top-level header param (parse keeps it,
    # format emits it) to match the canonical golden wire.
    if challenge.description:
        parts.append(f'description="{_escape_quoted_value(challenge.description)}"')
    if challenge.digest:
        parts.append(f'digest="{_escape_quoted_value(challenge.digest)}"')
    if challenge.expires:
        parts.append(f'expires="{_escape_quoted_value(challenge.expires)}"')
    if challenge.opaque is not None:
        parts.append(f'opaque="{_escape_quoted_value(challenge.opaque)}"')

    return f"Payment {', '.join(parts)}"


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


def parse_authorization(header: str) -> PaymentCredential:
    """Parse an Authorization header into a PaymentCredential."""
    payment_part = _extract_payment_scheme(header)
    if payment_part is None:
        raise ParseError("Expected 'Payment' scheme")

    token = payment_part[8:].strip() if len(payment_part) > 8 else ""

    if len(token) > MAX_TOKEN_LEN:
        raise ParseError(f"Token exceeds maximum length of {MAX_TOKEN_LEN} bytes")

    try:
        decoded = decode(token)
        data = json.loads(decoded)
    except Exception as exc:
        raise ParseError(f"Invalid credential: {exc}") from exc

    if not isinstance(data, dict) or "challenge" not in data:
        raise ParseError("Invalid credential JSON structure")

    ch = data["challenge"]
    if not isinstance(ch, dict):
        raise ParseError("Invalid credential challenge structure")
    # Canonical: the embedded challenge must carry a non-empty id.
    if not ch.get("id"):
        raise ParseError("Missing 'id' in credential challenge")
    echo = ChallengeEcho(
        id=str(ch.get("id", "")),
        realm=str(ch.get("realm", "")),
        method=str(ch.get("method", "")),
        intent=str(ch.get("intent", "")),
        request=str(ch.get("request", "")),
        expires=str(ch.get("expires", "")),
        digest=str(ch.get("digest", "")),
        opaque=ch.get("opaque"),
    )

    return PaymentCredential(
        challenge=echo,
        payload=data.get("payload", {}),
        source=data.get("source"),
    )


def format_authorization(credential: PaymentCredential) -> str:
    """Format a PaymentCredential as an Authorization header value."""
    challenge_dict: dict[str, Any] = {
        "challenge": {
            "id": credential.challenge.id,
            "intent": credential.challenge.intent,
            "method": credential.challenge.method,
            "realm": credential.challenge.realm,
            "request": credential.challenge.request,
        },
        "payload": credential.payload,
    }
    # Add optional challenge fields
    ch_dict = challenge_dict["challenge"]
    if credential.challenge.expires:
        ch_dict["expires"] = credential.challenge.expires
    if credential.challenge.digest:
        ch_dict["digest"] = credential.challenge.digest
    if credential.challenge.opaque is not None:
        ch_dict["opaque"] = credential.challenge.opaque

    if credential.source:
        challenge_dict["source"] = credential.source

    encoded = encode_json(challenge_dict)
    return f"Payment {encoded}"


# ---------------------------------------------------------------------------
# Payment-Receipt
# ---------------------------------------------------------------------------


def parse_receipt(header: str) -> Receipt:
    """Parse a Payment-Receipt header into a Receipt."""
    token = header.strip()
    if len(token) > MAX_TOKEN_LEN:
        raise ParseError(f"Receipt exceeds maximum length of {MAX_TOKEN_LEN} bytes")

    try:
        data = decode_json(token)
    except Exception as exc:
        raise ParseError(f"Invalid receipt: {exc}") from exc

    if not isinstance(data, dict):
        raise ParseError("Invalid receipt JSON structure")

    # Canonical: status / method / reference / timestamp are required.
    for field in ("status", "method", "reference", "timestamp"):
        if not data.get(field):
            raise ParseError(f"Missing '{field}' in receipt")

    timestamp = str(data["timestamp"])
    if not _ISO8601_RE.match(timestamp):
        raise ParseError(f"Invalid ISO-8601 timestamp in receipt: {timestamp!r}")

    return Receipt(
        status=str(data["status"]),
        method=str(data["method"]),
        timestamp=timestamp,
        reference=str(data["reference"]),
        challenge_id=str(data.get("challengeId", "")),
        external_id=str(data.get("externalId", "")),
    )


def format_receipt(receipt: Receipt) -> str:
    """Format a Receipt as a Payment-Receipt header value."""
    data: dict[str, Any] = {
        "challengeId": receipt.challenge_id,
        "method": receipt.method,
        "reference": receipt.reference,
        "status": receipt.status,
        "timestamp": receipt.timestamp,
    }
    if receipt.external_id:
        data["externalId"] = receipt.external_id
    return encode_json(data)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _strip_payment_scheme(header: str) -> str | None:
    """Strip the 'Payment' scheme prefix, returning the rest or None."""
    header = header.lstrip()
    if len(header) < len(PAYMENT_SCHEME):
        return None
    if header[: len(PAYMENT_SCHEME)].lower() != PAYMENT_SCHEME.lower():
        return None
    return header[len(PAYMENT_SCHEME) :]


def _extract_payment_scheme(header: str) -> str | None:
    """Extract the Payment scheme section from a comma-separated header."""
    for part in _extract_challenges(header, PAYMENT_SCHEME):
        return part
    return None


def _extract_challenges(header: str, scheme: str) -> list[str]:
    """Extract scheme challenges from a WWW-Authenticate header value."""
    all_starts = _find_challenge_starts(header)
    selected_starts = [start for start in all_starts if _scheme_starts_at(header, start, scheme)]
    challenges: list[str] = []
    for start in selected_starts:
        following_starts = [candidate for candidate in all_starts if candidate > start]
        end = following_starts[0] if following_starts else len(header)
        challenge = header[start:end].strip()
        if challenge.endswith(","):
            challenge = challenge[:-1].rstrip()
        if challenge:
            challenges.append(challenge)
    return challenges


def _find_challenge_starts(header: str) -> list[int]:
    starts: list[int] = []
    in_quote = False
    escaped = False
    i = 0
    while i < len(header):
        char = header[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if char == "\\" and in_quote:
            escaped = True
            i += 1
            continue
        if char == '"':
            in_quote = not in_quote
            i += 1
            continue
        if not in_quote and _auth_scheme_starts_at(header, i):
            starts.append(i)
            while i < len(header) and header[i] not in (" ", "\t"):
                i += 1
            continue
        i += 1
    return starts


def _scheme_starts_at(header: str, index: int, scheme: str) -> bool:
    return header[index : index + len(scheme)].lower() == scheme.lower() and _auth_scheme_starts_at(header, index)


def _auth_scheme_starts_at(header: str, index: int) -> bool:
    if index >= len(header) or not header[index].isalpha():
        return False
    next_index = index
    while next_index < len(header) and header[next_index].isalpha():
        next_index += 1
    if next_index == index or next_index >= len(header) or header[next_index] not in (" ", "\t"):
        return False
    if index == 0:
        return True
    previous = index - 1
    while previous >= 0 and header[previous] in (" ", "\t"):
        previous -= 1
    return previous >= 0 and header[previous] == ","


def _escape_quoted_value(s: str) -> str:
    """Escape a string for use in a quoted-string header value."""
    if "\r" in s or "\n" in s:
        raise ParseError("Header value contains invalid CRLF characters")
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _require_param(params: dict[str, str], key: str) -> str:
    """Require a parameter is present in the params dict."""
    if key not in params:
        raise ParseError(f"Missing '{key}' field")
    return params[key]


def _parse_auth_params(params_str: str) -> dict[str, str]:
    """Parse key=value or key="value" pairs from an auth-params string."""
    params: dict[str, str] = {}
    chars = list(params_str)
    i = 0

    while i < len(chars):
        # Skip whitespace and commas
        while i < len(chars) and (chars[i] in (" ", "\t", ",")):
            i += 1
        if i >= len(chars):
            break

        # Read key
        key_start = i
        while i < len(chars) and chars[i] != "=" and chars[i] not in (" ", "\t"):
            i += 1
        if i >= len(chars) or chars[i] != "=":
            # Skip to next comma or whitespace
            while i < len(chars) and chars[i] not in (" ", "\t", ","):
                i += 1
            continue

        key = "".join(chars[key_start:i])
        i += 1  # skip '='

        if i >= len(chars):
            break

        # Read value
        if chars[i] == '"':
            i += 1  # skip opening quote
            value_parts: list[str] = []
            while i < len(chars) and chars[i] != '"':
                if chars[i] == "\\" and i + 1 < len(chars):
                    i += 1
                    value_parts.append(chars[i])
                else:
                    value_parts.append(chars[i])
                i += 1
            if i < len(chars):
                i += 1  # skip closing quote
            value = "".join(value_parts)
        else:
            value_start = i
            while i < len(chars) and chars[i] not in (" ", "\t", ","):
                i += 1
            value = "".join(chars[value_start:i])

        if key in params:
            raise ParseError(f"Duplicate parameter: {key}")
        params[key] = value

    return params
