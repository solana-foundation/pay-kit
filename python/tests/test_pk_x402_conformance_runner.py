"""x402 exact structural-verifier conformance runner coverage."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

import conformance_runner

_VECTOR_PATH = Path(__file__).resolve().parents[2] / "harness" / "vectors" / "x402-exact-reject.json"
_VECTORS: list[dict[str, Any]] = json.loads(_VECTOR_PATH.read_text())


def _vector(vector_id: str) -> dict[str, Any]:
    return next(vector for vector in _VECTORS if vector["id"] == vector_id)


def _run_vector(
    vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> dict[str, Any]:
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(vector)))
    conformance_runner.main()
    return json.loads(capsys.readouterr().out)


@pytest.mark.parametrize(
    "vector_id",
    ["x402-exact-accept-with-memo", "x402-exact-accept-lighthouse-guard-referencing-fee-payer"],
)
def test_runner_accepts_shared_x402_exact_vectors(
    vector_id: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    result = _run_vector(_vector(vector_id), monkeypatch, capsys)
    assert result == {"id": vector_id, "outcome": "accept", "language": "python"}


def test_runner_surfaces_exact_managed_source_reject_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    result = _run_vector(_vector("x402-exact-fee-payer-as-source-ata"), monkeypatch, capsys)
    assert result["outcome"] == "reject"
    assert result["x402ExactRejectCode"] == "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"
