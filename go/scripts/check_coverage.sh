#!/usr/bin/env bash
# Coverage gate: enforce an aggregate floor AND a per-file floor, so a
# weakly-tested file cannot hide behind an inflated aggregate (the failure the
# per-file floor exists to catch). Pure awk over the raw Go coverage profile
# ("<file>:<range> <numStmts> <hitCount>"), so it needs no source tree present
# and is fully exercised by check_coverage_test.sh.
#
# Args: <profile> <aggregate-floor> [<per-file-floor>]   (per-file 0 = disabled)
set -euo pipefail

profile_path="${1:-coverage.out}"
threshold="${2:-70}"
per_file_floor="${3:-0}"

awk -v threshold="$threshold" -v floor="$per_file_floor" '
  NR == 1 { next }                          # skip the "mode:" header
  {
    split($1, parts, ":"); file = parts[1]  # a Go import path contains no ":"
    g_total += $2; total[file] += $2
    if ($3 + 0 > 0) { g_cov += $2; covered[file] += $2 }
  }
  END {
    rc = 0
    if (g_total == 0) {
      print "coverage profile contains no instrumented statements"
      exit 1
    }
    agg = 100 * g_cov / g_total
    if (agg + 0 < threshold + 0) {
      printf("aggregate coverage FAILED: %.1f%% < %.1f%%\n", agg, threshold + 0); rc = 1
    } else {
      printf("aggregate coverage passed: %.1f%% >= %.1f%%\n", agg, threshold + 0)
    }
    if (floor + 0 > 0) {
      pf = 0
      for (f in total) {
        # Exclude generated / mock / test-only trees: not shipped logic.
        if (f ~ /\/generated\/|_test\.go$|mock_|\.gen\.go$/) continue
        pct = total[f] > 0 ? 100 * covered[f] / total[f] : 100
        if (pct + 0 < floor + 0) {
          printf("per-file coverage FAILED: %s %.1f%% < %.1f%%\n", f, pct, floor + 0)
          pf = 1; rc = 1
        }
      }
      if (pf == 0) printf("per-file coverage passed: every shipped file >= %.1f%%\n", floor + 0)
    }
    exit rc
  }
' "$profile_path"
