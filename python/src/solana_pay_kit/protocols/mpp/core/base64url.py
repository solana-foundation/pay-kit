"""Base64URL encoding and decoding utilities."""

from __future__ import annotations

import base64
import json
from typing import Any


def encode(data: bytes) -> str:
    """Encode bytes as URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode(s: str) -> bytes:
    """Decode URL-safe base64, handling missing padding."""
    # Normalize: replace standard base64 chars with URL-safe variants, strip padding
    normalized = s.replace("+", "-").replace("/", "_").replace("=", "")
    # Add back padding
    padded = normalized + "=" * (-len(normalized) % 4)
    return base64.urlsafe_b64decode(padded)


def encode_json(obj: Any) -> str:
    """Encode a Python object as canonical JSON then base64url.

    Uses the RFC 8785 canonical encoder (UTF-16 code-unit key ordering, ES6
    ToString numbers, lone-surrogate rejection) so HMAC inputs and the
    ``request`` field are byte-equal across SDKs. The previous
    ``json.dumps(sort_keys=True)`` path sorted by Unicode code point, which
    diverges from Ruby / PHP / Lua / Rust on supplementary-plane keys.
    """
    from solana_pay_kit.protocols.mpp.core.json import encode_canonical

    return encode(encode_canonical(obj))


def decode_json(s: str) -> Any:
    """Decode a base64url string to a Python object via JSON."""
    return json.loads(decode(s))
