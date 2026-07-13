#!/usr/bin/env python3
"""Fail-closed validator for the Rust llvm-cov JSON report."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

METRICS = ("lines", "regions")
KIT_SOURCE = "/crates/kit/src/"
DEFAULT_FLOOR = 90.0


def number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def main(argv: list[str]) -> int:
    if not 1 <= len(argv) <= 3:
        print("usage: check-rust-coverage.py <coverage.json> [floor] [source-root]", file=sys.stderr)
        return 2

    report_path = Path(argv[0])
    try:
        floor = float(argv[1]) if len(argv) >= 2 else DEFAULT_FLOOR
    except ValueError:
        print(f"invalid coverage floor: {argv[1]}", file=sys.stderr)
        return 2
    if not math.isfinite(floor) or floor < 0 or floor > 100:
        print(f"invalid coverage floor: {floor}", file=sys.stderr)
        return 2
    source_root = Path(argv[2]).resolve() if len(argv) == 3 else None

    try:
        report = json.loads(report_path.read_text())
        datasets = report["data"]
        if not isinstance(datasets, list) or len(datasets) != 1:
            raise ValueError("data must contain exactly one llvm-cov dataset")
        files = datasets[0]["files"]
    except (OSError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"coverage report is malformed: {error}", file=sys.stderr)
        return 1
    if not isinstance(files, list):
        print("coverage report is malformed: data[0].files must be an array", file=sys.stderr)
        return 1

    failures: list[str] = []
    by_surface: dict[str, list[dict[str, Any]]] = {"mpp": [], "x402": []}
    seen_sources: set[str] = set()
    for record in files:
        if not isinstance(record, dict) or not isinstance(record.get("filename"), str):
            failures.append("coverage report contains a file without a filename")
            continue
        filename = record["filename"]
        record_path = Path(filename).resolve()
        if source_root is not None:
            try:
                relative = record_path.relative_to(source_root).as_posix()
            except ValueError:
                failures.append(f"coverage source is outside the expected root: {filename}")
                continue
        else:
            normalized = "/" + record_path.as_posix().lstrip("/")
            if KIT_SOURCE not in normalized:
                continue
            relative = normalized.split(KIT_SOURCE, 1)[1]
        if relative.startswith("mpp/"):
            surface = "mpp"
        elif relative.startswith("x402/"):
            surface = "x402"
        else:
            continue
        if relative in seen_sources:
            failures.append(f"coverage report contains duplicate source file: {relative}")
            continue
        seen_sources.add(relative)
        by_surface[surface].append(record)

    if source_root is not None:
        try:
            expected_sources = {
                path.relative_to(source_root).as_posix()
                for surface in ("mpp", "x402")
                for path in (source_root / surface).rglob("*.rs")
                if "client/multi_delegate" not in path.relative_to(source_root).as_posix()
                and path.relative_to(source_root).as_posix() != "x402/server/mock_rpc.rs"
            }
        except OSError as error:
            print(f"source inventory is unreadable: {error}", file=sys.stderr)
            return 1
        if not expected_sources:
            failures.append("source inventory contains no MPP/x402 Rust files")
        missing_sources = sorted(expected_sources - seen_sources)
        unexpected_sources = sorted(seen_sources - expected_sources)
        if missing_sources:
            failures.append("coverage report is missing source files: " + ", ".join(missing_sources))
        if unexpected_sources:
            failures.append("coverage report contains unexpected source files: " + ", ".join(unexpected_sources))

    totals: dict[tuple[str, str], list[float]] = {
        (surface, metric): [0.0, 0.0] for surface in by_surface for metric in METRICS
    }
    for surface, records in by_surface.items():
        if not records:
            failures.append(f"{surface} scope contains no Rust SDK source files")
        for record in records:
            filename = record["filename"]
            summary = record.get("summary")
            if not isinstance(summary, dict):
                failures.append(f"coverage summary missing for {filename}")
                continue
            for metric in METRICS:
                value = summary.get(metric)
                if not isinstance(value, dict):
                    failures.append(f"{metric} coverage missing for {filename}")
                    continue
                count = number(value.get("count"))
                covered = number(value.get("covered"))
                if count is None or covered is None or count <= 0 or covered < 0 or covered > count:
                    failures.append(f"{metric} coverage is invalid or empty for {filename}")
                    continue
                totals[(surface, metric)][0] += covered
                totals[(surface, metric)][1] += count
                rate = 100.0 * covered / count
                if rate < floor:
                    relative_name = filename.split("/src/", 1)[-1]
                    failures.append(f"per-file {metric} {rate:.1f}% < {floor:.1f}%: {relative_name}")

    for (surface, metric), (covered, count) in totals.items():
        if count <= 0:
            failures.append(f"{surface} aggregate {metric} coverage is empty")
            continue
        rate = 100.0 * covered / count
        print(f"{surface} {metric}: {rate:.2f}% (floor {floor:.1f}%)")
        if rate < floor:
            failures.append(f"{surface} aggregate {metric} {rate:.2f}% < {floor:.1f}%")

    if failures:
        print("COVERAGE GATE FAILURES:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("coverage gate passed (line + region >= floor, aggregate + per-file, non-empty mpp + x402 scopes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
