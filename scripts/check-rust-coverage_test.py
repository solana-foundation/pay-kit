#!/usr/bin/env python3
"""Regression tests for the real Rust coverage gate."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent
CHECK = ROOT / "check-rust-coverage.py"


def load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_rust_coverage", CHECK)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Rust coverage checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()
SOURCE_FILES = sorted(CHECKER.source_files())
COVERED_SOURCE_FILES = [
    filename for filename in SOURCE_FILES if filename not in CHECKER.SOURCE_SCOPE_EXCLUSIONS
]
MPP_SOURCE = next(filename for filename in COVERED_SOURCE_FILES if not filename.startswith("x402/"))
X402_SOURCE = next(filename for filename in COVERED_SOURCE_FILES if filename.startswith("x402/"))
LEGACY_SOURCE = next(iter(CHECKER.FILE_EXEMPTIONS))


def file_record(name: str, covered: int = 10, count: int = 10) -> dict[str, object]:
    metric = {"covered": covered, "count": count}
    return {"filename": name, "summary": {"lines": metric, "regions": metric}}


def report(files: list[dict[str, object]]) -> dict[str, object]:
    return {"data": [{"files": files}]}


def complete_report(
    *,
    covered: int = 10,
    count: int = 10,
    overrides: dict[str, tuple[int, int]] | None = None,
    prefix: str = "/tmp/pay-kit/rust/crates/kit/src/",
) -> dict[str, object]:
    overrides = overrides or {}
    return report(
        [
            file_record(f"{prefix}{filename}", *overrides.get(filename, (covered, count)))
            for filename in COVERED_SOURCE_FILES
        ],
    )


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
    check_case("healthy report passes", complete_report(), 0, "coverage gate passed")
    check_case(
        "80 percent per-file still fails the 90 percent aggregate",
        complete_report(covered=8, count=10),
        1,
        "mpp non-exempt aggregate lines 80.00% < 90.0%",
    )
    check_case(
        "below 75 percent per-file fails",
        complete_report(overrides={MPP_SOURCE: (7, 10)}),
        1,
        f"per-file lines 70.0% < 75.0%: {MPP_SOURCE}",
    )
    incomplete = complete_report()
    incomplete["data"][0]["files"] = [
        record
        for record in incomplete["data"][0]["files"]
        if not record["filename"].endswith(MPP_SOURCE)
    ]
    check_case(
        "missing expected source file fails",
        incomplete,
        1,
        f"missing coverage record: {MPP_SOURCE}",
    )
    check_case("malformed report fails", {"data": []}, 1, "coverage report is malformed")
    check_case(
        "empty metrics fail",
        complete_report(overrides={X402_SOURCE: (0, 0)}),
        1,
        f"lines coverage is invalid or empty for {X402_SOURCE}",
    )
    check_case(
        "explicit legacy exemption is omitted from both floors",
        complete_report(overrides={LEGACY_SOURCE: (1, 10_000)}),
        0,
        f"file exemption (omitted from aggregate and per-file floors): {LEGACY_SOURCE}",
    )
    check_case(
        "nested checkout path handling passes",
        complete_report(prefix="/tmp/src/work/pay-kit/rust/crates/kit/src/"),
        0,
        "coverage gate passed",
    )


if __name__ == "__main__":
    main()
