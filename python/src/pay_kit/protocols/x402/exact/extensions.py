"""x402 v2 ``extensions`` echo-and-append support.

Mirrors the Rust spine ``PaymentExtensions`` and friends in
``rust/crates/x402/src/protocol/schemes/exact/types.rs`` line-for-line:

* The ``extensions`` object rides on BOTH wire envelopes. The inbound
  ``PAYMENT-REQUIRED`` challenge advertises it (untyped passthrough); the
  outbound ``PAYMENT-SIGNATURE`` credential echoes it back with any required
  client-side fields filled in (e.g. ``payment-identifier.info.id``).
* The client MUST echo at least the info it received, MAY append additional
  info, and MUST NOT delete or overwrite existing info (x402 v2 §5.1.2). Unknown
  extensions are re-emitted verbatim so forward-compatible payloads survive.
* An absent extensions object is OMITTED on the wire, never serialized as
  ``null`` or an empty ``{}`` (rust ``skip_serializing_if = "Option::is_none"``
  plus :func:`extensions_is_empty`).

The spec JSON key for the payment-identifier extension is kebab-case
``payment-identifier`` (rust ``#[serde(rename = "payment-identifier")]``); its
``info`` block is camelCase ``{ required?, id? }`` and the server-published
``schema`` is echoed verbatim.
"""

from __future__ import annotations

import copy
import re
import secrets
from typing import Any, cast

__all__ = [
    "PAYMENT_IDENTIFIER_KEY",
    "PAYMENT_IDENTIFIER_ID_PATTERN",
    "PaymentIdentifierError",
    "generate_payment_identifier_id",
    "echo_extensions",
    "requires_payment_identifier",
    "with_payment_identifier_id",
    "extensions_is_empty",
    "extract_payment_identifier_id",
    "verify_payment_identifier",
]


class PaymentIdentifierError(ValueError):
    """Raised when a route requires a payment-identifier the credential lacks.

    The coinbase x402 v2 payment_identifier spec maps this to HTTP 400. The
    message carries the canonical ``payment-identifier`` token so the
    conformance reject classifier maps it to ``payment-identifier-required``.
    """


#: Wire key for the payment-identifier extension (rust
#: ``#[serde(rename = "payment-identifier")]``).
PAYMENT_IDENTIFIER_KEY = "payment-identifier"

#: Spec pattern for a payment-identifier ``info.id`` (coinbase x402 v2
#: payment_identifier.md). The canonical Solana shape ``pay_`` + 32 hex
#: (36 chars total) satisfies this. Compiled once and reused by the server
#: reject gate.
PAYMENT_IDENTIFIER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


def generate_payment_identifier_id() -> str:
    """Generate a fresh ``pay_``-prefixed idempotency id.

    ``pay_`` + 32 lowercase hex chars (36 total), satisfying the spec pattern
    ``^[A-Za-z0-9_-]{16,128}$`` and the canonical Solana
    ``^pay_[a-zA-Z0-9_-]{10,120}$`` shape. Mirrors rust
    ``generate_payment_identifier_id`` (16 CSPRNG bytes hex-encoded).

    Per the spec, callers MUST reuse the same id across retries of the same
    logical request so the server can return a cached 200 instead of charging
    twice.
    """
    return "pay_" + secrets.token_bytes(16).hex()


def echo_extensions(
    inbound: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Deep-copy the server's advertised extensions for the outbound credential.

    Mirrors rust ``PaymentExtensions::echoing``: returns ``None`` when the
    server advertised nothing (so the build omits the ``extensions`` object
    entirely), else a deep copy so unknown keys round-trip verbatim and the
    caller can mutate the copy without touching the inbound challenge.
    """
    if inbound is None:
        return None
    return cast("dict[str, Any]", copy.deepcopy(inbound))


def requires_payment_identifier(extensions: dict[str, Any] | None) -> bool:
    """``payment-identifier.info.required == True``.

    Mirrors rust ``PaymentExtensions::requires_payment_identifier``.
    """
    if not isinstance(extensions, dict):
        return False
    pid = extensions.get(PAYMENT_IDENTIFIER_KEY)
    if not isinstance(pid, dict):
        return False
    info = pid.get("info")
    if not isinstance(info, dict):
        return False
    return info.get("required") is True


def with_payment_identifier_id(
    extensions: dict[str, Any] | None,
    payment_id: str,
) -> dict[str, Any]:
    """Set the client-side ``payment-identifier.info.id`` without overwriting.

    Mirrors rust ``PaymentExtensions::with_payment_identifier_id``: creates the
    payment-identifier entry if the server did not advertise one (uncommon but
    spec-allowed), preserves the server's ``info.required`` and published
    ``schema`` verbatim, and only appends the client ``id``. Operates on a deep
    copy so the inbound challenge is never mutated.
    """
    next_ext: dict[str, Any] = cast("dict[str, Any]", copy.deepcopy(extensions)) if isinstance(extensions, dict) else {}
    pid = next_ext.get(PAYMENT_IDENTIFIER_KEY)
    if not isinstance(pid, dict):
        pid = {}
    info = pid.get("info")
    if not isinstance(info, dict):
        info = {}
    info["id"] = payment_id
    pid["info"] = info
    next_ext[PAYMENT_IDENTIFIER_KEY] = pid
    return next_ext


def extensions_is_empty(extensions: dict[str, Any] | None) -> bool:
    """True when the extensions object carries no keys.

    Mirrors rust ``PaymentExtensions::is_empty``. Callers use this to avoid
    emitting an empty ``extensions: {}`` on the outbound envelope.
    """
    if not isinstance(extensions, dict):
        return True
    return len(extensions) == 0


def extract_payment_identifier_id(extensions: dict[str, Any] | None) -> str | None:
    """Read ``payment-identifier.info.id`` off a credential's extensions, if any."""
    if not isinstance(extensions, dict):
        return None
    pid = extensions.get(PAYMENT_IDENTIFIER_KEY)
    if not isinstance(pid, dict):
        return None
    info = pid.get("info")
    if not isinstance(info, dict):
        return None
    value = info.get("id")
    return value if isinstance(value, str) else None


def verify_payment_identifier(
    extensions: dict[str, Any] | None,
    *,
    required: bool,
) -> None:
    """Server reject gate: enforce a required, valid payment-identifier id.

    When the route advertised ``payment-identifier`` with ``info.required = true``
    (``required=True`` here), the echoed credential MUST carry a valid
    ``pay_``-shaped ``info.id`` matching ``^[A-Za-z0-9_-]{16,128}$``. A missing,
    empty, or pattern-violating id raises :class:`PaymentIdentifierError`
    (coinbase x402 v2 spec: HTTP 400). A no-op when ``required`` is false.

    Mirrors the rust spine ``PaymentExtensions::requires_payment_identifier`` +
    the server reject layered on the accepted-vs-route checks, and the TS
    reference reject gate in ``harness/src/conformance/x402.ts``.
    """
    if not required:
        return
    payment_id = extract_payment_identifier_id(extensions)
    if payment_id is None or payment_id == "":
        raise PaymentIdentifierError("payment-identifier required but credential echoed no id")
    if not PAYMENT_IDENTIFIER_ID_PATTERN.match(payment_id):
        raise PaymentIdentifierError(
            f"payment-identifier id is invalid: {payment_id} does not match ^[A-Za-z0-9_-]{{16,128}}$"
        )
