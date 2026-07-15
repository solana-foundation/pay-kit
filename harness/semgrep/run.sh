#!/usr/bin/env bash
# Radar L7 — static-analysis security lint for the pay-kit escaped bug-classes.
#
# Usage:
#   harness/semgrep/run.sh            # scan real source (typescript/, go/, python/)
#   harness/semgrep/run.sh --test     # self-test: assert every fixture behaves
#   harness/semgrep/run.sh <paths...> # scan explicit paths
#
# Requires semgrep (`pip install semgrep` / `pipx install semgrep`).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RULES="$HERE/rules"

if ! command -v semgrep >/dev/null 2>&1; then
  echo "semgrep not found. Install with: pip install semgrep" >&2
  exit 127
fi

# Directories that are generated, vendored, or built — never real findings.
EXCLUDES=(
  --exclude 'node_modules' --exclude 'dist' --exclude 'build' --exclude 'target'
  --exclude '*.gen.ts' --exclude '*.gen.js' --exclude 'generated' --exclude '__tests__' --exclude 'tests'
  --exclude '*_test.go' --exclude '*.test.ts' --exclude 'test' --exclude 'vendor'
  --exclude '.venv' --exclude 'examples' --exclude 'playground'
)

if [[ "${1:-}" == "--test" ]]; then
  # Self-test: every *.bad.* fixture MUST match, every *.good.* fixture MUST NOT.
  echo "== self-test: harness/semgrep/fixtures =="
  out="$(semgrep --config "$RULES" "$HERE/fixtures" --json --quiet 2>/dev/null)"
  python3 - "$out" "$HERE/fixtures" <<'PY'
import json, sys, glob, os
d = json.loads(sys.argv[1]); root = sys.argv[2]
res = d.get("results", [])
matched = {os.path.abspath(r["path"]) for r in res}
bad = glob.glob(os.path.join(root, "**", "*.bad.*"), recursive=True)
missing = [b for b in bad if os.path.abspath(b) not in matched]
good_hits = [r for r in res if ".good." in r["path"]]
print(f"  bad-fixture matches : {len([r for r in res if '.bad.' in r['path']])}")
print(f"  good-fixture matches: {len(good_hits)} (must be 0)")
for r in good_hits:
    print("  FALSE POSITIVE:", r["check_id"].split(".")[-1], r["path"], r["start"]["line"])
for m in missing:
    print("  BAD fixture did NOT fire:", m)
ok = not missing and not good_hits
print("  RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
PY
  exit $?
fi

TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("$REPO/typescript" "$REPO/go" "$REPO/python")
fi

echo "== radar L7 scan: ${TARGETS[*]} =="
ERROR_ON_FINDINGS=()
if [[ "${SEMGREP_ERROR_ON_FINDINGS:-0}" == "1" ]]; then
  ERROR_ON_FINDINGS+=(--error)
fi
semgrep --config "$RULES" "${ERROR_ON_FINDINGS[@]}" "${EXCLUDES[@]}" "${TARGETS[@]}"
