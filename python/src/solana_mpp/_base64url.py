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
    """Encode a Python object as compact JSON then base64url.

    Object keys are sorted (RFC 8785 sec 3.2.3 key ordering); number
    serialization is delegated to ``json.dumps``.

    See:
        - https://datatracker.ietf.org/doc/html/rfc8785 RFC 8785 JCS
        - https://tc39.es/ecma262/multipage/abstract-operations.html#sec-numeric-types-number-tostring
          ECMA-262 Number::toString
    """
    compact = json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return encode(compact.encode("utf-8"))


def decode_json(s: str) -> Any:
    """Decode a base64url string to a Python object via JSON."""
    return json.loads(decode(s))
