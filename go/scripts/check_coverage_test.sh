#!/usr/bin/env bash
#
# check_coverage_test.sh - regression test for check_coverage.sh.
#
# check_coverage.sh must enforce BOTH an aggregate statement floor and a
# per-file floor (mirroring the Rust/TS gates). Aggregate-only gating lets a
# weak file hide behind inflated easy ones. This test feeds the gate two
# synthetic cover profiles, parsed straight from the raw statement counts so
# no source tree is required:
#
#   fixture-pass: every file clears the per-file floor  -> expect exit 0.
#   fixture-fail: aggregate still clears the aggregate floor, but a single
#                 file sits far below the per-file floor  -> expect exit 1.
#
# The fixture-fail case is the one that distinguishes a real per-file gate
# from an aggregate-only one: an aggregate-only gate passes it (exit 0), so
# this test fails until the per-file floor exists. Removing the per-file logic
# from check_coverage.sh turns this test - and therefore CI - red.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gate="$script_dir/check_coverage.sh"

work="$(mktemp -d 2>/dev/null || mktemp -d -t check_coverage_test)"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "check_coverage_test FAILED: $*" >&2
  exit 1
}

# Aggregate floor and per-file floor used for every case. Both fixtures are
# built to clear the aggregate floor so the per-file dimension is the only
# thing under test.
agg_floor=85
file_floor=75

# fixture-pass: two files, each comfortably above the per-file floor.
#   high.go:  9/10 = 90.0%
#   ok.go:    8/10 = 80.0%
#   aggregate 17/20 = 85.0%  (clears agg_floor)
cat > "$work/pass.out" <<'EOF'
mode: atomic
github.com/example/pkg/high.go:10.1,11.2 5 1
github.com/example/pkg/high.go:12.1,13.2 4 1
github.com/example/pkg/high.go:14.1,15.2 1 0
github.com/example/pkg/ok.go:10.1,11.2 5 1
github.com/example/pkg/ok.go:12.1,13.2 3 1
github.com/example/pkg/ok.go:14.1,15.2 2 0
EOF

# fixture-fail: one strong file inflates the aggregate while a second file
# sits well below the per-file floor.
#   strong.go: 90/90  = 100.0%
#   weak.go:    5/10  =  50.0%   (< file_floor, >= nothing)
#   aggregate  95/100 =  95.0%   (clears agg_floor -> aggregate-only gate PASSES)
cat > "$work/fail.out" <<'EOF'
mode: atomic
github.com/example/pkg/strong.go:10.1,11.2 90 3
github.com/example/pkg/weak.go:10.1,11.2 5 2
github.com/example/pkg/weak.go:12.1,13.2 5 0
EOF

# Case 1: every file clears the per-file floor -> the gate must pass.
if ! "$gate" "$work/pass.out" "$agg_floor" "$file_floor" > "$work/pass.log" 2>&1; then
  echo "---- gate output (fixture-pass) ----" >&2
  cat "$work/pass.log" >&2
  fail "gate rejected fixture-pass where every file clears the per-file floor ${file_floor}%"
fi
echo "check_coverage_test: fixture-pass accepted (exit 0)"

# Case 2: aggregate clears the aggregate floor but one file is below the
# per-file floor -> the gate must reject it. An aggregate-only gate returns 0
# here, so this assertion is what fails before the per-file floor is added.
if "$gate" "$work/fail.out" "$agg_floor" "$file_floor" > "$work/fail.log" 2>&1; then
  echo "---- gate output (fixture-fail) ----" >&2
  cat "$work/fail.log" >&2
  fail "gate accepted fixture-fail: weak.go at 50% is below the per-file floor ${file_floor}% yet the gate returned 0 (aggregate-only gating)"
fi
echo "check_coverage_test: fixture-fail rejected (non-zero exit)"

echo "check_coverage_test: PASS - per-file coverage floor is enforced"
