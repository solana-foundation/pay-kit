"""Error types for the Solana MPP SDK.

Canonical structured error codes (L6 / P1 lock from PR #96 / #102, mirrored
across Ruby, PHP, Lua, Rust):

* ``charge_request_mismatch``: the credential's claimed charge does not
  match the route's expected charge (amount, recipient).
* ``challenge_route_mismatch``: the credential was issued for a different
  route than the one being requested (different pinned fields).
* ``challenge_verification_failed``: HMAC verification failed.
* ``challenge_expired``: the challenge's ``expires`` is in the past.
* ``payment_invalid``: the credential payload is malformed or fails
  on-chain verification (decode error, instruction allowlist violation,
  amount mismatch).
* ``wrong_network``: the credential was signed against a different network
  than the one the server is configured for.
* ``signature_consumed``: the on-chain signature has already been used to
  settle a previous charge.

The :class:`PaymentError.code` field carries the legacy or canonical code.
Use :func:`canonical_code` to map a legacy kebab-case code to the L6
canonical snake_case code when emitting a 402 response body.
"""

from __future__ import annotations

# Canonical structured error codes (L6 / P1).
CODE_CHARGE_REQUEST_MISMATCH = "charge_request_mismatch"
CODE_CHALLENGE_ROUTE_MISMATCH = "challenge_route_mismatch"
CODE_CHALLENGE_VERIFICATION_FAILED = "challenge_verification_failed"
CODE_CHALLENGE_EXPIRED = "challenge_expired"
CODE_PAYMENT_INVALID = "payment_invalid"
CODE_WRONG_NETWORK = "wrong_network"
CODE_SIGNATURE_CONSUMED = "signature_consumed"

CANONICAL_CODES = frozenset(
    {
        CODE_CHARGE_REQUEST_MISMATCH,
        CODE_CHALLENGE_ROUTE_MISMATCH,
        CODE_CHALLENGE_VERIFICATION_FAILED,
        CODE_CHALLENGE_EXPIRED,
        CODE_PAYMENT_INVALID,
        CODE_WRONG_NETWORK,
        CODE_SIGNATURE_CONSUMED,
    }
)

# Map legacy kebab-case codes to canonical snake_case codes.
#
# Distinguishing ``challenge-mismatch`` (HMAC verification failed; the
# credential id does not match what the server would compute) from
# ``challenge-route-mismatch`` (HMAC valid but the credential was issued
# for a different route on the same secret key) is the explicit L6
# requirement. The former maps to ``challenge_verification_failed``, the
# latter to ``challenge_route_mismatch``. Verifier call sites in
# ``server/mpp.py`` use the route-specific codes for the pinned-field path.
_LEGACY_TO_CANONICAL = {
    "challenge-expired": CODE_CHALLENGE_EXPIRED,
    "challenge-mismatch": CODE_CHALLENGE_VERIFICATION_FAILED,
    "challenge-route-mismatch": CODE_CHALLENGE_ROUTE_MISMATCH,
    "signature-consumed": CODE_SIGNATURE_CONSUMED,
    "wrong-network": CODE_WRONG_NETWORK,
    "amount-mismatch": CODE_CHARGE_REQUEST_MISMATCH,
    "recipient-mismatch": CODE_CHARGE_REQUEST_MISMATCH,
    "currency-mismatch": CODE_CHALLENGE_ROUTE_MISMATCH,
    "method-mismatch": CODE_CHALLENGE_ROUTE_MISMATCH,
    "intent-mismatch": CODE_CHALLENGE_ROUTE_MISMATCH,
    "realm-mismatch": CODE_CHALLENGE_ROUTE_MISMATCH,
    "splits-exceed-amount": CODE_CHARGE_REQUEST_MISMATCH,
    "invalid-payload": CODE_PAYMENT_INVALID,
    "invalid-payload-type": CODE_PAYMENT_INVALID,
    "invalid-config": CODE_PAYMENT_INVALID,
    "missing-signature": CODE_PAYMENT_INVALID,
    "missing-transaction": CODE_PAYMENT_INVALID,
    "transaction-failed": CODE_PAYMENT_INVALID,
    "transaction-not-found": CODE_PAYMENT_INVALID,
    "no-transfer": CODE_PAYMENT_INVALID,
    # Compute-budget allowlist failures and splits-count cap. Mirrors the
    # Rust / PHP / Ruby pre-broadcast guards: the wire body still surfaces
    # ``payment_invalid`` to the client so the canonical-codes classifier
    # in the interop harness routes the failure the same way every other
    # SDK does.
    "compute-budget-invalid": CODE_PAYMENT_INVALID,
    "compute-budget-cap-exceeded": CODE_PAYMENT_INVALID,
    "too-many-splits": CODE_PAYMENT_INVALID,
}


def canonical_code(code: str) -> str:
    """Return the canonical snake_case code for a legacy or current code.

    Falls back to ``payment_invalid`` for unknown codes so a 402 response
    always carries a canonical L6 code.
    """
    if code in CANONICAL_CODES:
        return code
    return _LEGACY_TO_CANONICAL.get(code, CODE_PAYMENT_INVALID)


class PaymentError(Exception):
    """Base class for all payment-related errors.

    ``code`` is the legacy kebab-case or canonical snake_case structured
    error code. Use :func:`canonical_code` to map to the L6 canonical code
    when emitting a 402 response body.
    """

    def __init__(self, message: str, code: str = "", retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class VerificationError(PaymentError):
    """Payment verification failed."""


class ChallengeExpiredError(PaymentError):
    """Challenge has expired."""

    def __init__(self, message: str = "challenge expired", code: str = "challenge-expired") -> None:
        super().__init__(message, code=code)


class ChallengeMismatchError(PaymentError):
    """Challenge ID does not match the expected HMAC."""

    def __init__(self, message: str = "challenge ID mismatch", code: str = "challenge-mismatch") -> None:
        super().__init__(message, code=code)


class ReplayError(PaymentError):
    """Transaction signature has already been consumed."""

    def __init__(
        self, message: str = "transaction signature already consumed", code: str = "signature-consumed"
    ) -> None:
        super().__init__(message, code=code)


def payment_required_response(
    message: str,
    code: str,
    challenge_header: str | None = None,
) -> dict:
    """Build a structured 402 Payment Required response body and headers.

    Returns a dict with:

    * ``status_code``: 402
    * ``headers``: ``Cache-Control: no-store``, optional ``WWW-Authenticate``,
      ``Content-Type: application/problem+json``
    * ``body``: an ``application/problem+json`` shape with ``type``, ``title``,
      ``status``, ``code`` (canonical), ``error`` (legacy alias of code),
      and ``message`` for backward compatibility.

    Mirrors the cross-SDK L6 / P1 lock from PR #96 / #102: every server
    SDK returns the same canonical ``code`` for the same failure class so a
    polyglot client can route on the code field alone.
    """
    canonical = canonical_code(code)
    headers: dict[str, str] = {
        "content-type": "application/problem+json",
        "cache-control": "no-store",
    }
    if challenge_header:
        headers["www-authenticate"] = challenge_header

    body = {
        "type": f"https://paymentauth.org/problems/{canonical}",
        "title": "Payment Required",
        "status": 402,
        "code": canonical,
        # Backward compatibility: pre-L6 clients read ``error`` and ``message``.
        "error": canonical,
        "message": message,
    }
    return {"status_code": 402, "headers": headers, "body": body}
