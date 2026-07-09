#!/usr/bin/env bash
# Fail closed on Swift SDK line coverage. SwiftPM writes an LLVM profile, not a
# coverage percentage, so convert the package-test binary's profile to LCOV and
# count only shipped SDK sources. SWIFT_COVERAGE_LCOV_FILE makes the parser
# independently regression-testable without a macOS Swift toolchain.
set -euo pipefail

threshold="${1:-90}"
if ! [[ "$threshold" =~ ^([0-9]+([.][0-9]+)?|100([.]0+)?)$ ]]; then
  echo "coverage threshold must be a percentage from 0 to 100" >&2
  exit 2
fi
if ! awk -v threshold="$threshold" 'BEGIN { exit threshold >= 0 && threshold <= 100 ? 0 : 1 }'; then
  echo "coverage threshold must be a percentage from 0 to 100" >&2
  exit 2
fi

if [[ -n "${SWIFT_COVERAGE_LCOV_FILE:-}" ]]; then
  lcov_file="$SWIFT_COVERAGE_LCOV_FILE"
  if [[ ! -f "$lcov_file" ]]; then
    echo "Swift coverage input does not exist: $lcov_file" >&2
    exit 1
  fi
else
  profile="$(find .build -type f -path '*/codecov/default.profdata' -print -quit)"
  test_binary="$(find .build -type f -path '*PackageTests.xctest/Contents/MacOS/*' -perm -111 -print -quit)"
  if [[ -z "$profile" || -z "$test_binary" ]]; then
    echo "Swift coverage profile or test bundle is missing; run swift test --enable-code-coverage first" >&2
    exit 1
  fi

  lcov_file="$(mktemp)"
  trap 'rm -f "$lcov_file"' EXIT
  xcrun llvm-cov export "$test_binary" -instr-profile="$profile" -format=lcov > "$lcov_file"
fi

awk -v threshold="$threshold" '
  /^SF:/ {
    file = substr($0, 4)
    shipped = ($0 ~ /(^|\/)swift\/Sources\//)
    file_lines = 0
    file_covered = 0
    next
  }
  /^LF:/ && shipped {
    split($0, parts, ":")
    lines += parts[2]
    file_lines += parts[2]
    saw_lines = 1
    next
  }
  /^LH:/ && shipped {
    split($0, parts, ":")
    covered += parts[2]
    file_covered += parts[2]
    next
  }
  /^end_of_record/ && shipped {
    if (file_lines > 0) {
      printf("Swift source coverage: %.2f%% %s\n", 100 * file_covered / file_lines, file)
    }
    shipped = 0
  }
  END {
    if (!saw_lines || lines <= 0) {
      print "Swift coverage report contains no shipped SDK source lines" > "/dev/stderr"
      exit 1
    }
    rate = 100 * covered / lines
    printf("Swift SDK line coverage: %.2f%% (floor %.2f%%)\n", rate, threshold)
    if (rate + 0 < threshold + 0) {
      print "Swift coverage floor failed" > "/dev/stderr"
      exit 1
    }
  }
' "$lcov_file"
