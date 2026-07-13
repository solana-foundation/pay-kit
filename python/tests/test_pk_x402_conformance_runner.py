"""x402 exact structural-verifier conformance runner coverage."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

import conformance_runner
from solana_pay_kit.errors import InvalidProofError

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


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda vector: str(vector["id"]))
def test_runner_executes_every_shared_x402_exact_vector(
    vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    result = _run_vector(vector, monkeypatch, capsys)
    expected = vector["expect"]

    assert result["id"] == vector["id"]
    assert result["language"] == "python"
    assert result["outcome"] != "unsupported-mode"
    assert not result.get("error", "").startswith("unsupported-mode")
    assert result["outcome"] == expected["outcome"]

    if expected["outcome"] == "reject":
        code = expected["x402ExactRejectCode"]
        assert result["error"] == code
        assert result["x402ExactRejectCode"] == code


def test_verify_x402_dispatch_invokes_production_exact_verifier(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    vector = _vector("x402-exact-accept-with-memo")
    called: dict[str, Any] = {}

    def verify(transaction: str, requirement: dict[str, Any], managed_signers: list[str]) -> dict[str, Any]:
        called["transaction"] = transaction
        called["requirement"] = requirement
        called["managed_signers"] = managed_signers
        return {}

    monkeypatch.setattr(conformance_runner.ExactVerifier, "verify", verify)
    result = _run_vector(vector, monkeypatch, capsys)

    assert result == {"id": vector["id"], "outcome": "accept", "language": "python"}
    assert called == {
        "transaction": vector["input"]["transaction"],
        "requirement": vector["input"]["x402ExactRequirement"],
        "managed_signers": vector["input"]["x402ExactManagedSigners"],
    }


def test_runner_surfaces_exact_managed_source_reject_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    result = _run_vector(_vector("x402-exact-fee-payer-as-source-ata"), monkeypatch, capsys)
    assert result["outcome"] == "reject"
    assert result["error"] == "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"
    assert result["x402ExactRejectCode"] == "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"


def test_runner_uses_exact_error_code_not_diagnostic_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code = "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"

    def reject_with_diagnostic(_vector: dict[str, Any]) -> dict[str, Any]:
        raise InvalidProofError("managed account appears in transfer", code=code)

    monkeypatch.setattr(conformance_runner, "_run_vector", reject_with_diagnostic)
    result = _run_vector({"id": "typed-exact-reject"}, monkeypatch, capsys)

    assert result["error"] == code
    assert result["x402ExactRejectCode"] == code
