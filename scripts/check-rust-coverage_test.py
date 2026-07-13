#!/usr/bin/env python3
"""Regression tests for the Rust coverage gate's fail-closed behavior."""

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


def check_case(
    name: str,
    payload: dict[str, object],
    expected: int,
    needle: str,
    sources: tuple[str, ...] = ("mpp/verify.rs", "x402/verify.rs"),
    floor: str = "90",
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "coverage.json"
        source_root = Path(directory) / "crates/kit/src"
        for source in sources:
            source_path = source_root / source
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text("// coverage fixture\n")
        data = payload.get("data")
        records = data[0].get("files", []) if isinstance(data, list) and data else []
        for record in records:
            filename = record.get("filename", "")
            fixture_prefix = "/tmp/rust/crates/kit/src/"
            if isinstance(filename, str) and filename.startswith(fixture_prefix):
                relative = filename.removeprefix(fixture_prefix)
                if relative.startswith(("mpp/", "x402/")):
                    record["filename"] = str(source_root / relative)
        path.write_text(json.dumps(payload))
        result = subprocess.run(
            [sys.executable, str(CHECK), str(path), floor, str(source_root)],
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
    check_case("healthy report passes", report(file_record(mpp), file_record(x402)), 0, "coverage gate passed")
    check_case("empty scope fails", report(file_record(mpp)), 1, "x402 scope contains no")
    check_case("empty metric fails", report(file_record(mpp, 0, 0), file_record(x402)), 1, "invalid or empty")
    check_case("below-floor file fails", report(file_record(mpp, 8, 10), file_record(x402)), 1, "per-file lines 80.0%")
    unrelated = "/tmp/rust/crates/kit/src/lib.rs"
    check_case(
        "unrelated kit files cannot satisfy mpp scope",
        report(file_record(unrelated), file_record(x402)),
        1,
        "mpp scope contains no",
    )
    check_case(
        "truncated report fails inventory check",
        report(file_record(mpp), file_record(x402)),
        1,
        "missing source files: mpp/other.rs",
        sources=("mpp/verify.rs", "mpp/other.rs", "x402/verify.rs"),
    )
    forged = "/tmp/rust/crates/kit/src/not-sdk/src/mpp/verify.rs"
    check_case(
        "forged nested source path cannot satisfy mpp scope",
        report(file_record(forged), file_record(x402)),
        1,
        "mpp scope contains no",
    )
    foreign_root = "/tmp/forged/crates/kit/src/mpp/verify.rs"
    check_case(
        "foreign source root cannot satisfy inventory",
        report(file_record(foreign_root), file_record(x402)),
        1,
        "outside the expected root",
    )
    arbitrary_foreign = "/tmp/vendor/unrelated.rs"
    check_case(
        "arbitrary foreign record fails closed",
        report(file_record(mpp), file_record(x402), file_record(arbitrary_foreign)),
        1,
        "outside the expected root",
    )
    check_case(
        "duplicate source record fails closed",
        report(file_record(mpp), file_record(mpp), file_record(x402)),
        1,
        "duplicate source file: mpp/verify.rs",
    )
    check_case(
        "explicit floor is honored with source root",
        report(file_record(mpp, 90, 100), file_record(x402, 90, 100)),
        1,
        "90.0% < 95.0%",
        floor="95",
    )
    check_case(
        "extra llvm-cov dataset fails closed",
        {
            "data": [
                {"files": [file_record(mpp), file_record(x402)]},
                {"files": [file_record("/foreign/arbitrary.rs")]},
            ]
        },
        1,
        "exactly one llvm-cov dataset",
    )
    check_case("malformed report fails", {"data": []}, 1, "coverage report is malformed")


if __name__ == "__main__":
    main()
