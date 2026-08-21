"""Tests for the mpp-protocol conformance runner's canonical receipt ABI.

Exercises ``protocol_conformance_runner.py`` the same way the cross-language
harness does (see ``harness/protocol-runners/python.json``): spawn it and
speak the stdin/stdout adapter ABI, rather than importing it directly.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_RUNNER = Path(__file__).resolve().parent.parent / "protocol_conformance_runner.py"


def _dispatch(op: str, input_: dict) -> dict:
    proc = subprocess.run(
        [sys.executable, str(_RUNNER)],
        input=json.dumps({"op": op, "input": input_}),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_session_receipt_format_parse_roundtrip():
    session_receipt = {
        "status": "success",
        "method": "solana",
        "timestamp": "2026-01-29T12:00:30Z",
        "reference": "0xabc",
        "intent": "session",
        "acceptedCumulative": "500000",
        "spent": "125000",
        "idleTimeoutSeconds": 300,
        "txHash": "5x7y9z",
        "refunded": "0",
    }

    formatted = _dispatch("receipt.format", session_receipt)
    assert formatted["success"] is True

    parsed = _dispatch("receipt.parse", {"header": formatted["result"]["header"]})
    assert parsed["success"] is True
    assert parsed["result"] == session_receipt


def test_session_receipt_format_rejects_a_malformed_idle_timeout():
    """A malformed ``idleTimeoutSeconds`` must fail the format op.

    ``format_receipt`` omits a ``None`` idle timeout, and ``parse_receipt``
    rejects a session receipt without one — so coercing bad input to ``None``
    would answer with a header our own parser refuses, reporting conformance
    the wire contract does not have.
    """
    base = {
        "status": "success",
        "method": "solana",
        "timestamp": "2026-01-29T12:00:30Z",
        "reference": "0xabc",
        "intent": "session",
        "acceptedCumulative": "500000",
        "spent": "125000",
        "txHash": "5x7y9z",
        "refunded": "0",
    }

    for bad in (True, "300", 300.5, -1):
        result = _dispatch("receipt.format", {**base, "idleTimeoutSeconds": bad})
        assert result["success"] is False, f"{bad!r} must not format"
        assert "idleTimeoutSeconds" in result["error"]
        assert result["error_type"] == "format_error"


def test_session_receipt_format_rejects_malformed_accounting_fields():
    """A malformed ``acceptedCumulative``/``spent`` must fail the format op.

    ``parse_receipt`` requires both to be non-decimal-string-free ASCII digit
    strings on a session receipt. Coercing a bool, int, float, ``None``, or
    non-digit string via ``str(...)`` would let ``receipt.format`` report
    success while emitting a header ``receipt.parse`` refuses to read back.
    """
    base = {
        "status": "success",
        "method": "solana",
        "timestamp": "2026-01-29T12:00:30Z",
        "reference": "0xabc",
        "intent": "session",
        "acceptedCumulative": "500000",
        "spent": "125000",
        "idleTimeoutSeconds": 300,
        "txHash": "5x7y9z",
        "refunded": "0",
    }

    for field in ("acceptedCumulative", "spent"):
        for bad in (True, 500000, 500000.5, "-1", "abc", ""):
            result = _dispatch("receipt.format", {**base, field: bad})
            assert result["success"] is False, f"{field}={bad!r} must not format"
            assert field in result["error"]
            assert result["error_type"] == "format_error"


def test_session_receipt_format_rejects_missing_required_fields():
    """A session receipt must fail the format op when a required accounting or
    timeout field is missing (absent key or explicit ``null``), rather than
    silently formatting a header ``receipt.parse`` then rejects as missing
    that same field.
    """
    base = {
        "status": "success",
        "method": "solana",
        "timestamp": "2026-01-29T12:00:30Z",
        "reference": "0xabc",
        "intent": "session",
        "acceptedCumulative": "500000",
        "spent": "125000",
        "idleTimeoutSeconds": 300,
        "txHash": "5x7y9z",
        "refunded": "0",
    }

    for field in ("acceptedCumulative", "spent", "idleTimeoutSeconds"):
        # Explicit null.
        result = _dispatch("receipt.format", {**base, field: None})
        assert result["success"] is False, f"null {field} must not format"
        assert field in result["error"]
        assert result["error_type"] == "format_error"

        # Key entirely absent.
        without_field = {k: v for k, v in base.items() if k != field}
        result = _dispatch("receipt.format", without_field)
        assert result["success"] is False, f"missing {field} must not format"
        assert field in result["error"]
        assert result["error_type"] == "format_error"

    # A non-session receipt has no such requirement: omitting these fields
    # still formats (and the header carries no accounting/timeout fields).
    non_session = {
        "status": "success",
        "method": "solana",
        "timestamp": "2026-01-29T12:00:30Z",
        "reference": "0xabc",
    }
    result = _dispatch("receipt.format", non_session)
    assert result["success"] is True
