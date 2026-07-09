#!/usr/bin/env bash
# Self-test for check_coverage.sh. The audit found the coverage gate accepted a
# per-file floor argument but silently ignored it (aggregate-only), so a 20%
# file could hide behind a 91% aggregate. This proves BOTH floors actually
# reject a below-floor profile and pass an above-floor one, so the gate cannot
# regress back into a no-op. Uses synthetic profiles (no go toolchain needed).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check="$here/check_coverage.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# weak.go: 2 of 4 statements covered (50%). strong.go: 4 of 4 (100%).
# Aggregate = 6 / 8 = 75%.
cat > "$tmp/mixed.out" <<'EOF'
mode: atomic
github.com/x/pkg/weak.go:1.1,2.1 2 1
github.com/x/pkg/weak.go:3.1,4.1 2 0
github.com/x/pkg/strong.go:1.1,2.1 4 1
EOF

pass() { echo "  ok: $1"; }
die()  { echo "  FAIL: $1" >&2; exit 1; }

# 1. Per-file floor 75 must REJECT weak.go (50%).
if "$check" "$tmp/mixed.out" 0 75 >/dev/null 2>&1; then
  die "per-file floor 75 did not reject a 50% file"
fi
pass "per-file floor rejects a below-floor file"

# 2. Per-file floor 40: every file clears it, must PASS.
if ! "$check" "$tmp/mixed.out" 0 40 >/dev/null 2>&1; then
  die "per-file floor 40 wrongly rejected an all-above-40% profile"
fi
pass "per-file floor passes when every file clears it"

# 3. Aggregate floor 99 must REJECT the ~75% aggregate.
if "$check" "$tmp/mixed.out" 99 0 >/dev/null 2>&1; then
  die "aggregate floor 99 did not reject a ~75% aggregate"
fi
pass "aggregate floor rejects a below-floor aggregate"

# 4. Both floors satisfied (aggregate 70, per-file 40) must PASS.
if ! "$check" "$tmp/mixed.out" 70 40 >/dev/null 2>&1; then
  die "both-floors-satisfied profile was wrongly rejected"
fi
pass "passes when both aggregate and per-file floors are met"

# 5. Generated/test files are excluded from the per-file floor.
cat > "$tmp/gen.out" <<'EOF'
mode: atomic
github.com/x/pkg/generated/client.go:1.1,2.1 10 0
github.com/x/pkg/real.go:1.1,2.1 4 1
EOF
if ! "$check" "$tmp/gen.out" 0 90 >/dev/null 2>&1; then
  die "per-file floor did not exclude a generated/ file"
fi
pass "per-file floor excludes generated trees"

# 6. A profile with only the mode header has no instrumented statements and
# must fail closed instead of being treated as 100% covered.
printf '%s\n' 'mode: atomic' > "$tmp/empty.out"
if "$check" "$tmp/empty.out" 0 0 >/dev/null 2>&1; then
  die "empty coverage profile passed as fully covered"
fi
pass "empty coverage profile fails closed"

echo "check_coverage.sh self-test passed"
