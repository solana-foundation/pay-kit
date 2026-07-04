#!/usr/bin/env bash
set -euo pipefail

# Enforce two statement-coverage floors from a single `go test -coverprofile`
# run, mirroring the Rust/TS gates:
#   1. Aggregate: the whole covered set must clear the aggregate threshold.
#   2. Per-file:  every shipped file must individually clear the per-file
#      floor, so a weak file cannot hide behind inflated easy ones.
#
# Usage: check_coverage.sh [profile] [aggregate_threshold] [per_file_floor]
#
# Both floors are computed directly from the raw coverage profile's per-block
# statement counts (`file:start,end numStmts count`), which - unlike
# `go tool cover -func` - needs no source tree and yields the same
# statement-weighted percentage `go test` reports.

profile_path="${1:-coverage.out}"
threshold="${2:-70}"
# Per-file floor. Defaults below the aggregate threshold: individual files
# legitimately run a few points under the whole-set average, so the per-file
# gate catches real regressions without demanding every file match the mean.
file_threshold="${3:-75}"

if [ ! -f "$profile_path" ]; then
  echo "coverage profile not found: $profile_path" >&2
  exit 1
fi

awk -v threshold="$threshold" -v file_threshold="$file_threshold" '
# Skip the leading "mode:" line; every other line is a coverage block:
#   <path>:<startLine>.<col>,<endLine>.<col> <numStmts> <count>
NR == 1 && $1 == "mode:" { next }
NF < 3 { next }
{
  # The file path is everything up to the first colon (the line/col range
  # separator). Package import paths carry no colon, so this is unambiguous.
  colon = index($1, ":")
  path = substr($1, 1, colon - 1)
  numstmts = $2
  count = $3

  total[path] += numstmts
  agg_total += numstmts
  if (count + 0 > 0) {
    covered[path] += numstmts
    agg_covered += numstmts
  }
  if (!(path in seen)) {
    seen[path] = 1
    order[++nfiles] = path
  }
}
END {
  fail = 0

  agg_pct = (agg_total > 0) ? (100.0 * agg_covered / agg_total) : 100.0
  if (agg_pct + 0 < threshold + 0) {
    printf("coverage threshold failed: %.1f%% < %.1f%%\n", agg_pct, threshold + 0)
    fail = 1
  } else {
    printf("coverage threshold passed: %.1f%% >= %.1f%%\n", agg_pct, threshold + 0)
  }

  for (i = 1; i <= nfiles; i++) {
    path = order[i]
    pct = (total[path] > 0) ? (100.0 * covered[path] / total[path]) : 100.0
    if (pct + 0 < file_threshold + 0) {
      printf("per-file coverage floor failed: %.1f%% < %.1f%%: %s\n", pct, file_threshold + 0, path)
      fail = 1
    }
  }

  if (fail) {
    exit 1
  }
  printf("per-file coverage floor passed: every file >= %.1f%%\n", file_threshold + 0)
}
' "$profile_path"
