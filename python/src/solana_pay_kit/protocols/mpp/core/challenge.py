"""HMAC-based challenge ID computation."""

from __future__ import annotations

import hashlib
import hmac

from solana_pay_kit.protocols.mpp.core.base64url import encode


def compute_challenge_id(
    secret_key: str,
    realm: str,
    method: str,
    intent: str,
    request: str,
    expires: str = "",
    digest: str = "",
    opaque: str | None = None,
) -> str:
    """Compute HMAC-SHA256 challenge ID.

    Fields are joined by '|': realm|method|intent|request|expires|digest|opaque
    """
    message = "|".join([realm, method, intent, request, expires, digest, opaque or ""])
    mac = hmac.new(secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
    return encode(mac)


def constant_time_equal(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
