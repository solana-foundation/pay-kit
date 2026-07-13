#!/usr/bin/env python3
"""Regression tests for the real Rust coverage gate."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CHECK = ROOT / "check-rust-coverage.py"


def file_record(name: str, covered: int = 10, count: int = 10) -> dict[str, object]:
    metric = {"covered": covered, "count": count}
    return {"filename": name, "summary": {"lines": metric, "regions": metric}}


def report(*files: dict[str, object]) -> dict[str, object]:
    return {"data": [{"files": list(files)}]}


def check_case(name: str, payload: dict[str, object], expected: int, needle: str) -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "coverage.json"
        path.write_text(json.dumps(payload))
        result = subprocess.run(
            [sys.executable, str(CHECK), str(path)],
            text=True,
            capture_output=True,
            check=False,
        )
    output = result.stdout + result.stderr
    if result.returncode != expected or needle not in output:
        raise AssertionError(
            f"{name}: expected rc={expected} and {needle!r}; got rc={result.returncode}: {output}",
        )
    print(f"ok - {name}")


def main() -> None:
    mpp = "/tmp/rust/crates/kit/src/mpp/verify.rs"
    x402 = "/tmp/rust/crates/kit/src/x402/verify.rs"
    covered_x402 = "/tmp/rust/crates/kit/src/x402/server/upto.rs"
    nested_src_covered_x402 = "/tmp/src/work/rust/crates/kit/src/x402/server/upto.rs"
    check_case("healthy report passes", report(file_record(mpp), file_record(x402)), 0, "coverage gate passed")
    check_case("missing x402 scope fails", report(file_record(mpp)), 1, "x402 scope contains no")
    check_case("empty metric fails", report(file_record(mpp, 0, 0), file_record(x402)), 1, "invalid or empty")
    check_case("below-floor file fails", report(file_record(mpp, 7, 10), file_record(x402)), 1, "per-file lines 70.0%")
    check_case(
        "formerly exempt file now fails below floor",
        report(file_record(mpp), file_record(x402, 1_000, 1_000), file_record(covered_x402, 1, 10)),
        1,
        "per-file lines 10.0%",
    )
    check_case(
        "covered file still fails under a checkout path containing src",
        report(
            file_record(mpp),
            file_record(x402, 1_000, 1_000),
            file_record(nested_src_covered_x402, 1, 10),
        ),
        1,
        "per-file lines 10.0%",
    )
    check_case("malformed report fails", {"data": []}, 1, "coverage report is malformed")


if __name__ == "__main__":
    main()
