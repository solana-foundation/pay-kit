#!/usr/bin/env bash
# Regression-test the Swift coverage parser without requiring a macOS runner.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check="$here/check_coverage.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/pass.lcov" <<'EOF'
TN:
SF:/workspace/swift/Sources/SolanaPayKit/Core.swift
LF:10
LH:9
end_of_record
SF:/workspace/swift/Tests/SolanaPayKitTests/CoreTests.swift
LF:10
LH:0
end_of_record
EOF

SWIFT_COVERAGE_LCOV_FILE="$tmp/pass.lcov" "$check" 90

cat > "$tmp/fail.lcov" <<'EOF'
TN:
SF:/workspace/swift/Sources/SolanaPayKit/Core.swift
LF:10
LH:8
end_of_record
EOF

if SWIFT_COVERAGE_LCOV_FILE="$tmp/fail.lcov" "$check" 90 >/dev/null 2>&1; then
  echo "coverage gate accepted a below-floor report" >&2
  exit 1
fi

printf 'TN:\n' > "$tmp/empty.lcov"
if SWIFT_COVERAGE_LCOV_FILE="$tmp/empty.lcov" "$check" 0 >/dev/null 2>&1; then
  echo "coverage gate accepted a report with no shipped source lines" >&2
  exit 1
fi

echo "Swift coverage gate self-test passed"
