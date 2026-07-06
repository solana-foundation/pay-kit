#!/usr/bin/env bash
# Enforce a Swift line-coverage floor after `swift test --enable-code-coverage`.
# Parses the llvm-cov JSON export SwiftPM writes (located via
# `swift test --show-codecov-path`), which is robust to the arch-specific build
# layout. The threshold is a ratchet: raise it as coverage improves. Mirrors
# go/scripts/check_coverage.sh in spirit.
set -euo pipefail

threshold="${1:-80}"
json="${2:-$(swift test --show-codecov-path 2>/dev/null | tail -1)}"

if [ -z "$json" ] || [ ! -f "$json" ]; then
  echo "coverage: no codecov JSON found (run: swift test --enable-code-coverage)" >&2
  exit 1
fi

python3 - "$json" "$threshold" <<'PY'
import json, sys
path, threshold = sys.argv[1], float(sys.argv[2])
files = json.load(open(path))["data"][0]["files"]
tot = cov = 0
for f in files:
    # Gate the shipped library only; exclude the test target itself.
    if "/Sources/" in f["filename"]:
        lines = f["summary"]["lines"]
        tot += lines["count"]
        cov += lines["covered"]
pct = 100.0 * cov / tot if tot else 100.0
print(f"Swift Sources line coverage: {pct:.2f}% (floor {threshold})")
if pct < threshold:
    print(f"FAIL: {pct:.2f}% < {threshold}")
    sys.exit(1)
PY
