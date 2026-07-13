#!/usr/bin/env python3
"""Fail-closed validator for the Rust llvm-cov JSON report."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

METRICS = ("lines", "regions")
AGGREGATE_FLOOR = 90.0
PER_FILE_FLOOR = 75.0
KIT_SOURCE_MARKER = "crates/kit/src/"
ROOT = Path(__file__).resolve().parent.parent
KIT_SOURCE_ROOT = ROOT / "rust" / "crates" / "kit" / "src"

# These legacy modules remain outside the deterministic unit-coverage baseline.
# Each entry is deliberately explicit: a new low-coverage file must be added
# here with a reason instead of inheriting an exemption. Exempt files are left
# out of both the per-file gate and the non-exempt aggregate.
FILE_EXEMPTIONS = {
    "mpp/server/subscription.rs": "subscription runtime adapters require optional service integrations",
    "x402/client/batch_settlement/payment.rs": "batch client construction depends on live settlement integration paths",
    "x402/client/upto/payment.rs": "upto client construction is exercised by the cross-SDK on-chain harness",
    "x402/error.rs": "feature-gated error display variants are not all constructed by the deterministic unit run",
    "x402/server/batch_settlement.rs": "batch server orchestration requires service-backed settlement fixtures",
}

# `cargo llvm-cov` deliberately ignores `src/generated/`; keep every generated
# file named rather than applying a prefix exemption so newly generated source
# cannot silently disappear from the policy. The CI ignore regex also names
# `client/multi_delegate`, `x402/server/mock_rpc.rs`, and harness/integration;
# only the latter is under this kit-source inventory today.
GENERATED_SOURCE_FILES = (
    "generated/mod.rs",
    "generated/payment_channels/generated/accounts/channel.rs",
    "generated/payment_channels/generated/accounts/mod.rs",
    "generated/payment_channels/generated/errors/mod.rs",
    "generated/payment_channels/generated/errors/payment_channels.rs",
    "generated/payment_channels/generated/instructions/distribute.rs",
    "generated/payment_channels/generated/instructions/emit_event.rs",
    "generated/payment_channels/generated/instructions/mod.rs",
    "generated/payment_channels/generated/instructions/open.rs",
    "generated/payment_channels/generated/instructions/reclaim.rs",
    "generated/payment_channels/generated/instructions/request_close.rs",
    "generated/payment_channels/generated/instructions/seal.rs",
    "generated/payment_channels/generated/instructions/settle.rs",
    "generated/payment_channels/generated/instructions/settle_and_seal.rs",
    "generated/payment_channels/generated/instructions/top_up.rs",
    "generated/payment_channels/generated/instructions/withdraw_payer.rs",
    "generated/payment_channels/generated/mod.rs",
    "generated/payment_channels/generated/programs.rs",
    "generated/payment_channels/generated/shared.rs",
    "generated/payment_channels/generated/types/account_discriminator.rs",
    "generated/payment_channels/generated/types/channel_status.rs",
    "generated/payment_channels/generated/types/distribute_args.rs",
    "generated/payment_channels/generated/types/distribution_entry.rs",
    "generated/payment_channels/generated/types/mod.rs",
    "generated/payment_channels/generated/types/open_args.rs",
    "generated/payment_channels/generated/types/opened.rs",
    "generated/payment_channels/generated/types/payout_beneficiary.rs",
    "generated/payment_channels/generated/types/payout_redirected.rs",
    "generated/payment_channels/generated/types/redirect_reason.rs",
    "generated/payment_channels/generated/types/settle_and_seal_args.rs",
    "generated/payment_channels/generated/types/settlement_watermarks.rs",
    "generated/payment_channels/generated/types/top_up_args.rs",
    "generated/payment_channels/generated/types/voucher_args.rs",
    "generated/payment_channels/mod.rs",
    "generated/subscriptions/generated/accounts/event_authority.rs",
    "generated/subscriptions/generated/accounts/fixed_delegation.rs",
    "generated/subscriptions/generated/accounts/mod.rs",
    "generated/subscriptions/generated/accounts/plan.rs",
    "generated/subscriptions/generated/accounts/recurring_delegation.rs",
    "generated/subscriptions/generated/accounts/subscription_authority.rs",
    "generated/subscriptions/generated/accounts/subscription_delegation.rs",
    "generated/subscriptions/generated/errors/mod.rs",
    "generated/subscriptions/generated/errors/subscriptions.rs",
    "generated/subscriptions/generated/instructions/cancel_subscription.rs",
    "generated/subscriptions/generated/instructions/close_subscription_authority.rs",
    "generated/subscriptions/generated/instructions/create_fixed_delegation.rs",
    "generated/subscriptions/generated/instructions/create_plan.rs",
    "generated/subscriptions/generated/instructions/create_recurring_delegation.rs",
    "generated/subscriptions/generated/instructions/delete_plan.rs",
    "generated/subscriptions/generated/instructions/init_subscription_authority.rs",
    "generated/subscriptions/generated/instructions/mod.rs",
    "generated/subscriptions/generated/instructions/resume_subscription.rs",
    "generated/subscriptions/generated/instructions/revoke_delegation.rs",
    "generated/subscriptions/generated/instructions/subscribe.rs",
    "generated/subscriptions/generated/instructions/transfer_fixed.rs",
    "generated/subscriptions/generated/instructions/transfer_recurring.rs",
    "generated/subscriptions/generated/instructions/transfer_subscription.rs",
    "generated/subscriptions/generated/instructions/update_plan.rs",
    "generated/subscriptions/generated/mod.rs",
    "generated/subscriptions/generated/programs.rs",
    "generated/subscriptions/generated/shared.rs",
    "generated/subscriptions/generated/types/account_discriminator.rs",
    "generated/subscriptions/generated/types/create_fixed_delegation_data.rs",
    "generated/subscriptions/generated/types/create_recurring_delegation_data.rs",
    "generated/subscriptions/generated/types/header.rs",
    "generated/subscriptions/generated/types/mod.rs",
    "generated/subscriptions/generated/types/plan_data.rs",
    "generated/subscriptions/generated/types/plan_status.rs",
    "generated/subscriptions/generated/types/plan_terms.rs",
    "generated/subscriptions/generated/types/subscribe_data.rs",
    "generated/subscriptions/generated/types/transfer_data.rs",
    "generated/subscriptions/generated/types/update_plan_data.rs",
    "generated/subscriptions/mod.rs",
)

# Every source file with no llvm-cov record is named here. Do not add a broad
# `mod.rs` or directory rule: each source-scope exclusion needs a reason and a
# future logic-bearing file must fail until it is deliberately classified.
SOURCE_SCOPE_EXCLUSIONS = {
    **{
        filename: "Codama-generated client source excluded by CI's src/generated/ regex"
        for filename in GENERATED_SOURCE_FILES
    },
    "core/mints.rs": "constant-only mint-address declarations emit no coverage counters",
    "core/mod.rs": "module wiring and re-exports emit no coverage counters",
    "core/otel.rs": "the optional otel feature is outside the deterministic coverage command",
    "core/settlement/mod.rs": "module wiring and re-exports emit no coverage counters",
    "core/settlement/testkit.rs": "the optional testkit feature is outside the deterministic coverage command",
    "gate.rs": "the optional axum feature is outside the deterministic coverage command",
    "lib.rs": "crate feature gates and module declarations emit no coverage counters",
    "mpp/client/confidential.rs": "the optional confidential feature is outside the deterministic coverage command",
    "mpp/client/mod.rs": "module wiring and re-exports emit no coverage counters",
    "mpp/mod.rs": "module wiring and re-exports emit no coverage counters",
    "mpp/program/mod.rs": "module wiring and re-exports emit no coverage counters",
    "mpp/protocol/confidential.rs": "the optional confidential feature is outside the deterministic coverage command",
    "mpp/protocol/core/mod.rs": "module wiring and re-exports emit no coverage counters",
    "mpp/protocol/mod.rs": "module wiring and re-exports emit no coverage counters",
    "mpp/server/axum.rs": "the optional axum feature is outside the deterministic coverage command",
    "mpp/server/confidential.rs": "the optional confidential feature is outside the deterministic coverage command",
    "mpp/server/confidential_worker.rs": "the optional worker feature is outside the deterministic coverage command",
    "mpp/server/mod.rs": "module wiring and re-exports emit no coverage counters",
    "mpp/store.rs": "re-export-only compatibility module emits no coverage counters",
    "x402/client/batch_settlement/mod.rs": "module wiring and re-exports emit no coverage counters",
    "x402/client/exact/mod.rs": "module wiring and re-exports emit no coverage counters",
    "x402/client/mod.rs": "module declarations emit no coverage counters",
    "x402/client/upto/mod.rs": "module wiring and re-exports emit no coverage counters",
    "x402/constants.rs": "constant-only protocol declarations emit no coverage counters",
    "x402/mod.rs": "module wiring and re-exports emit no coverage counters",
    "x402/protocol/mod.rs": "module declarations emit no coverage counters",
    "x402/protocol/schemes/batch_settlement/mod.rs": "module wiring and re-exports emit no coverage counters",
    "x402/protocol/schemes/exact/mod.rs": "module wiring and re-exports emit no coverage counters",
    "x402/protocol/schemes/mod.rs": "module declarations emit no coverage counters",
    "x402/protocol/schemes/upto/mod.rs": "module wiring and re-exports emit no coverage counters",
    "x402/server/mock_rpc.rs": "test-only mock RPC excluded by CI's x402/server/mock_rpc.rs regex",
    "x402/server/mod.rs": "type declarations and re-exports emit no coverage counters",
}


def number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def source_files() -> set[str]:
    return {
        path.relative_to(KIT_SOURCE_ROOT).as_posix()
        for path in KIT_SOURCE_ROOT.rglob("*.rs")
    }


def source_name(filename: str) -> str | None:
    normalized = filename.replace("\\", "/")
    marker_index = normalized.rfind(KIT_SOURCE_MARKER)
    if marker_index == -1:
        return None
    return normalized[marker_index + len(KIT_SOURCE_MARKER) :]


def surface_for(filename: str) -> str:
    return "x402" if filename.startswith("x402/") else "mpp"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Rust llvm-cov report completeness and coverage floors.",
    )
    parser.add_argument("report", type=Path, help="path to llvm-cov JSON report")
    parser.add_argument(
        "--aggregate-floor",
        type=float,
        default=AGGREGATE_FLOOR,
        metavar="PERCENT",
        help=f"non-exempt aggregate floor (default: {AGGREGATE_FLOOR:.0f})",
    )
    parser.add_argument(
        "--per-file-floor",
        type=float,
        default=PER_FILE_FLOOR,
        metavar="PERCENT",
        help=f"non-exempt per-file floor (default: {PER_FILE_FLOOR:.0f})",
    )
    return parser.parse_args(argv)


def valid_floor(name: str, value: float) -> str | None:
    if not math.isfinite(value) or value < 0 or value > 100:
        return f"invalid {name} floor: {value}"
    return None


def load_records(report_path: Path) -> list[dict[str, Any]] | None:
    try:
        report = json.loads(report_path.read_text())
        data = report["data"]
        files = data[0]["files"]
    except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        print(f"coverage report is malformed: {error}", file=sys.stderr)
        return None
    if not isinstance(files, list) or not files:
        print("coverage report is malformed: data[0].files must be a non-empty array", file=sys.stderr)
        return None
    return files


def metric_values(record: dict[str, Any], relative_name: str, failures: list[str]) -> dict[str, tuple[float, float]]:
    summary = record.get("summary")
    if not isinstance(summary, dict):
        failures.append(f"coverage summary missing for {relative_name}")
        return {}

    values: dict[str, tuple[float, float]] = {}
    for metric in METRICS:
        value = summary.get(metric)
        if not isinstance(value, dict):
            failures.append(f"{metric} coverage missing for {relative_name}")
            continue
        count = number(value.get("count"))
        covered = number(value.get("covered"))
        if count is None or covered is None or count <= 0 or covered < 0 or covered > count:
            failures.append(f"{metric} coverage is invalid or empty for {relative_name}")
            continue
        values[metric] = (covered, count)
    return values


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    for name, floor in (("aggregate", args.aggregate_floor), ("per-file", args.per_file_floor)):
        error = valid_floor(name, floor)
        if error:
            print(error, file=sys.stderr)
            return 2

    records = load_records(args.report)
    if records is None:
        return 1

    actual_sources = source_files()
    failures: list[str] = []
    unknown_scope_exclusions = set(SOURCE_SCOPE_EXCLUSIONS) - actual_sources
    for filename in sorted(unknown_scope_exclusions):
        failures.append(f"source-scope exclusion no longer exists: {filename}")
    unknown_file_exemptions = set(FILE_EXEMPTIONS) - actual_sources
    for filename in sorted(unknown_file_exemptions):
        failures.append(f"file exemption no longer exists: {filename}")
    overlapping_exemptions = set(SOURCE_SCOPE_EXCLUSIONS) & set(FILE_EXEMPTIONS)
    for filename in sorted(overlapping_exemptions):
        failures.append(f"source-scope and file exemptions overlap: {filename}")

    records_by_name: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("filename"), str):
            failures.append("coverage report contains a file without a filename")
            continue
        relative_name = source_name(record["filename"])
        if relative_name is None:
            continue
        if relative_name not in actual_sources:
            failures.append(f"coverage report contains unknown kit source file: {relative_name}")
            continue
        if relative_name in records_by_name:
            failures.append(f"coverage report contains duplicate kit source file: {relative_name}")
            continue
        records_by_name[relative_name] = record

    expected_sources = actual_sources - set(SOURCE_SCOPE_EXCLUSIONS)
    for filename in sorted(expected_sources - set(records_by_name)):
        failures.append(f"missing coverage record: {filename}")
    for filename in sorted(set(SOURCE_SCOPE_EXCLUSIONS) & set(records_by_name)):
        failures.append(f"source-scope exclusion unexpectedly has coverage: {filename}")

    totals: dict[tuple[str, str], list[float]] = {
        (surface, metric): [0.0, 0.0]
        for surface in ("mpp", "x402")
        for metric in METRICS
    }
    non_exempt_sources: dict[str, int] = {"mpp": 0, "x402": 0}
    for relative_name in sorted(expected_sources & set(records_by_name)):
        values = metric_values(records_by_name[relative_name], relative_name, failures)
        if len(values) != len(METRICS):
            continue
        exemption = FILE_EXEMPTIONS.get(relative_name)
        if exemption is not None:
            print(
                f"file exemption (omitted from aggregate and per-file floors): {relative_name} ({exemption})",
            )
            continue

        surface = surface_for(relative_name)
        non_exempt_sources[surface] += 1
        for metric, (covered, count) in values.items():
            totals[(surface, metric)][0] += covered
            totals[(surface, metric)][1] += count
            rate = 100.0 * covered / count
            if rate < args.per_file_floor:
                failures.append(
                    f"per-file {metric} {rate:.1f}% < {args.per_file_floor:.1f}%: {relative_name}",
                )

    for surface, source_count in non_exempt_sources.items():
        if source_count == 0:
            failures.append(f"{surface} non-exempt scope contains no Rust SDK source files")
    for (surface, metric), (covered, count) in totals.items():
        if count <= 0:
            failures.append(f"{surface} non-exempt aggregate {metric} coverage is empty")
            continue
        rate = 100.0 * covered / count
        print(
            f"{surface} non-exempt aggregate {metric}: {rate:.2f}% "
            f"(floor {args.aggregate_floor:.1f}%)",
        )
        if rate < args.aggregate_floor:
            failures.append(
                f"{surface} non-exempt aggregate {metric} {rate:.2f}% < {args.aggregate_floor:.1f}%",
            )

    if failures:
        print("COVERAGE GATE FAILURES:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        "coverage gate passed "
        f"(non-exempt aggregate >= {args.aggregate_floor:.1f}%, "
        f"per-file >= {args.per_file_floor:.1f}%, complete mpp + x402 source scope)",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
