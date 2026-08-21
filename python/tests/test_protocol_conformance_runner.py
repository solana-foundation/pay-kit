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
