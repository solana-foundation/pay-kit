#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
fixtures="$root/swift/Tests/Fixtures"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

swift build --package-path "$root" --product mpp-conformance
runner="$(swift build --package-path "$root" --show-bin-path)/mpp-conformance"

check_fixture() {
  local fixture="$1"
  local expected_outcome="$2"
  local expected_code="${3:-}"
  local result="$tmp/result.json"

  "$runner" < "$fixtures/$fixture" > "$result"
  python3 - "$result" "$expected_outcome" "$expected_code" <<'PY'
import json
import sys

path, expected_outcome, expected_code = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    result = json.load(handle)

if result.get("outcome") != expected_outcome:
    raise SystemExit(f"expected outcome {expected_outcome!r}, got {result!r}")
if expected_code and result.get("x402ExactRejectCode") != expected_code:
    raise SystemExit(f"expected reject code {expected_code!r}, got {result!r}")
PY
}

check_fixture mpp-conformance-token-program-match.json accept
check_fixture \
  mpp-conformance-token-program-mismatch.json \
  reject \
  invalid_exact_svm_payload_no_transfer_instruction

echo "Swift conformance runner self-test passed"
