# BAD: non-constant-time secret compare, and except-as-accept (fails open).

import hmac
import hashlib


def check_mac(payload: bytes, secret_key: bytes, provided_mac: str) -> bool:
    expected_mac = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()
    return expected_mac == provided_mac


def verify_token(token: str) -> bool:
    try:
        assert_signature_valid(token)
        return True
    except Exception:
        return True
