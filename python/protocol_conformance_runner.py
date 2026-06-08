"""Python mpp-protocol conformance runner.

Speaks the canonical mpp-tools adapter ABI (see
`harness/src/protocol/README.md`): read one `{ "op": ..., "input": ... }`
request as JSON on stdin, drive the real Python ``pay_kit`` MPP protocol core
(challenge / credential / receipt header codec, base64url, and the
challenge-id HMAC), and write one response as JSON on stdout:

    { "success": true,  "result": <op-specific> }
    { "success": false, "error": "<msg>", "error_type": "<type>" }

This is the protocol-primitive counterpart to the cross-SDK charge/x402
``conformance_runner.py``. It maps each canonical operation onto the SDK
function named in the per-operation map in the PR description:

| op                 | pay_kit function                                   |
|--------------------|----------------------------------------------------|
| challenge.parse    | core.headers.parse_www_authenticate                |
| challenge.format   | core.headers.format_www_authenticate               |
| credential.parse   | core.headers.parse_authorization                   |
| credential.format  | core.headers.format_authorization                  |
| receipt.parse      | core.headers.parse_receipt                         |
| receipt.format     | core.headers.format_receipt                        |
| base64url.encode   | core.base64url.encode                              |
| base64url.decode   | core.base64url.decode                              |
| challenge.id       | core.challenge.compute_challenge_id                |

The runner never fakes a result: it calls the SDK and reports what the SDK
actually does. Where the Python SDK genuinely does not implement an
operation it returns ``error_type="unsupported_operation"`` rather than
inventing behavior.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from pay_kit.protocols.mpp.core.base64url import decode as base64url_decode
from pay_kit.protocols.mpp.core.base64url import decode_json, encode_json
from pay_kit.protocols.mpp.core.base64url import encode as base64url_encode
from pay_kit.protocols.mpp.core.challenge import compute_challenge_id
from pay_kit.protocols.mpp.core.headers import (
    format_authorization,
    format_receipt,
    format_www_authenticate,
    parse_authorization,
    parse_receipt,
    parse_www_authenticate,
)
from pay_kit.protocols.mpp.core.types import (
    ChallengeEcho,
    PaymentChallenge,
    PaymentCredential,
    Receipt,
)

# error_type vocabulary per operation family, from operations.json.
_PARSE_ERROR = "parse_error"
_FORMAT_ERROR = "format_error"
_ENCODING_ERROR = "encoding_error"
_GENERATION_ERROR = "generation_error"


def _ok(result: Any) -> dict[str, Any]:
    return {"success": True, "result": result}


def _fail(error: str, error_type: str) -> dict[str, Any]:
    return {"success": False, "error": error, "error_type": error_type}


def _drop_empty(obj: dict[str, Any]) -> dict[str, Any]:
    """Drop optional fields the canonical golden objects omit when absent.

    The Python dataclasses always carry ``expires`` / ``description`` /
    ``digest`` as ``""`` and ``opaque`` as ``None``; the canonical golden
    objects only include a key when the value is present. The `.parse`
    comparison is exact deep-equal, so emit the same minimal shape.
    """
    return {k: v for k, v in obj.items() if v not in ("", None)}


def _challenge_to_canonical(ch: PaymentChallenge) -> dict[str, Any]:
    """Shape a parsed PaymentChallenge into the canonical challenge object.

    ``request`` is decoded from its base64url string into the JSON object the
    canonical oracle compares against.
    """
    out: dict[str, Any] = {
        "id": ch.id,
        "realm": ch.realm,
        "method": ch.method,
        "intent": ch.intent,
        "request": decode_json(ch.request),
        "expires": ch.expires,
        "description": ch.description,
        "digest": ch.digest,
        "opaque": ch.opaque,
    }
    return _drop_empty(out)


def _echo_to_canonical(echo: ChallengeEcho) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": echo.id,
        "realm": echo.realm,
        "method": echo.method,
        "intent": echo.intent,
        # decode_json so the credential challenge.request compares as an
        # object; the driver also normalizes a string form, but emit the
        # decoded shape for parity with challenge.parse.
        "request": decode_json(echo.request) if echo.request else echo.request,
        "expires": echo.expires,
        "digest": echo.digest,
        "opaque": echo.opaque,
    }
    return _drop_empty(out)


def _credential_to_canonical(cred: PaymentCredential) -> dict[str, Any]:
    out: dict[str, Any] = {
        "challenge": _echo_to_canonical(cred.challenge),
        "payload": cred.payload,
    }
    if cred.source is not None:
        out["source"] = cred.source
    return out


def _receipt_to_canonical(rcpt: Receipt) -> dict[str, Any]:
    out: dict[str, Any] = {
        "status": rcpt.status,
        "method": rcpt.method,
        "timestamp": rcpt.timestamp,
        "reference": rcpt.reference,
        "challengeId": rcpt.challenge_id,
        "externalId": rcpt.external_id,
    }
    return _drop_empty(out)


def _challenge_from_canonical(obj: dict[str, Any]) -> PaymentChallenge:
    """Build a PaymentChallenge from a canonical challenge object.

    ``request`` arrives as a JSON object and is canonically re-encoded
    (RFC 8785 JCS then base64url) into the string form the dataclass holds.
    """
    request = obj.get("request", {})
    request_b64 = encode_json(request) if isinstance(request, dict) else str(request)
    return PaymentChallenge(
        id=str(obj.get("id", "")),
        realm=str(obj.get("realm", "")),
        method=str(obj.get("method", "")),
        intent=str(obj.get("intent", "")),
        request=request_b64,
        expires=str(obj.get("expires", "")),
        description=str(obj.get("description", "")),
        digest=str(obj.get("digest", "")),
        opaque=obj.get("opaque"),
    )


def _echo_from_canonical(obj: dict[str, Any]) -> ChallengeEcho:
    request = obj.get("request", "")
    request_b64 = encode_json(request) if isinstance(request, dict) else str(request)
    return ChallengeEcho(
        id=str(obj.get("id", "")),
        realm=str(obj.get("realm", "")),
        method=str(obj.get("method", "")),
        intent=str(obj.get("intent", "")),
        request=request_b64,
        expires=str(obj.get("expires", "")),
        digest=str(obj.get("digest", "")),
        opaque=obj.get("opaque"),
    )


def _credential_from_canonical(obj: dict[str, Any]) -> PaymentCredential:
    return PaymentCredential(
        challenge=_echo_from_canonical(obj.get("challenge", {})),
        payload=obj.get("payload", {}),
        source=obj.get("source"),
    )


def _receipt_from_canonical(obj: dict[str, Any]) -> Receipt:
    return Receipt(
        status=str(obj.get("status", "")),
        method=str(obj.get("method", "")),
        timestamp=str(obj.get("timestamp", "")),
        reference=str(obj.get("reference", "")),
        challenge_id=str(obj.get("challengeId", "")),
        external_id=str(obj.get("externalId", "")),
    )


def _header(input_: Any) -> str:
    return str(input_["header"])


def _text(input_: Any) -> str:
    return str(input_["text"])


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op", "")
    input_ = request.get("input")
    try:
        if op == "challenge.parse":
            return _ok(_challenge_to_canonical(parse_www_authenticate(_header(input_))))
        if op == "challenge.format":
            challenge = _challenge_from_canonical(input_)
            return _ok({"header": format_www_authenticate(challenge)})
        if op == "credential.parse":
            return _ok(_credential_to_canonical(parse_authorization(_header(input_))))
        if op == "credential.format":
            credential = _credential_from_canonical(input_)
            return _ok({"header": format_authorization(credential)})
        if op == "receipt.parse":
            return _ok(_receipt_to_canonical(parse_receipt(_header(input_))))
        if op == "receipt.format":
            receipt = _receipt_from_canonical(input_)
            return _ok({"header": format_receipt(receipt)})
        if op == "base64url.encode":
            # Canonical base64url.encode takes UTF-8 text -> base64url string.
            return _ok({"text": base64url_encode(_text(input_).encode("utf-8"))})
        if op == "base64url.decode":
            # Canonical base64url.decode yields UTF-8 text.
            return _ok({"text": base64url_decode(_text(input_)).decode("utf-8")})
        if op == "challenge.id":
            return _ok({"id": _challenge_id(input_)})
        return _fail(f"Unknown operation: {op}", "unsupported_operation")
    except Exception as exc:  # noqa: BLE001 - map any SDK error to the ABI shape
        message = str(exc)
        if op.endswith(".parse"):
            return _fail(message, _PARSE_ERROR)
        if op.endswith(".format"):
            return _fail(message, _FORMAT_ERROR)
        if op.startswith("base64url."):
            return _fail(message, _ENCODING_ERROR)
        if op == "challenge.id":
            return _fail(message, _GENERATION_ERROR)
        return _fail(message, "unknown_error")


def _challenge_id(input_: dict[str, Any]) -> str:
    """Canonical challenge-id derivation over the Python SDK HMAC.

    The canonical ABI passes ``request`` as a JSON object; pay_kit's
    ``compute_challenge_id`` takes the already-canonically-encoded base64url
    ``request`` pipe-slot string, so encode it here exactly the way the SDK
    does internally (RFC 8785 JCS -> base64url). ``opaque`` enters the pipe
    as its already-serialized string form.
    """
    request = input_.get("request", {})
    request_b64 = encode_json(request) if isinstance(request, dict) else str(request)
    return compute_challenge_id(
        secret_key=str(input_["secretKey"]),
        realm=str(input_.get("realm", "")),
        method=str(input_.get("method", "")),
        intent=str(input_.get("intent", "")),
        request=request_b64,
        expires=str(input_.get("expires", "")),
        digest=str(input_.get("digest", "")),
        opaque=input_.get("opaque"),
    )


def main() -> int:
    raw = sys.stdin.read().strip()
    try:
        request = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        sys.stdout.write(json.dumps(_fail(f"invalid request JSON: {exc}", "unknown_error")))
        return 1
    response = dispatch(request)
    sys.stdout.write(json.dumps(response))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
