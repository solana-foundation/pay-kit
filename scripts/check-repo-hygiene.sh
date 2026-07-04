#!/usr/bin/env bash
#
# Repo-hygiene guards for two regressions that no other CI gate catches and
# that a prior audit had to clean up by hand:
#
#   1. Audit finding IDs (e.g. "H-1", "M-3", "C-1", "L-4", "I-2") left in
#      shipped source or comments. They belong in commit messages only; leaving
#      them in code leaks internal review bookkeeping into the released package.
#
#   2. Dependency overrides / build-script allowlists placed in
#      typescript/package.json's `pnpm` field. pnpm v10 no longer reads that
#      field, so security version pins parked there are silently NOT enforced.
#      They must live in typescript/pnpm-workspace.yaml.
#
# Exit non-zero if either guard trips. Safe to run from anywhere.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
fail=0

# --- Guard 1: no audit finding IDs in shipped source ---------------------------
# Runtime source across every SDK, excluding tests, generated clients, conformance
# vectors, and markdown (where an ID may legitimately appear in prose). Matches the
# audit ID shape [C|H|M|L|I]-<1-2 digits> as a standalone token, in comment lines.
id_hits="$(git grep -nE '(^|[^A-Za-z0-9])[CHMLI]-[0-9]{1,2}([^0-9]|$)' -- \
  'typescript/packages/*/src' 'rust/crates/kit/src' 'go' 'python/src' \
  'ruby/lib' 'php/src' 'lua/src' 'swift/Sources' 'kotlin/src' \
  ':!*test*' ':!*Test*' ':!*spec*' ':!*/generated/*' ':!*vector*' ':!*.md' 2>/dev/null \
  | grep -E '(//|#|/\*|\*/|^[[:space:]]*\*|--)' \
  | grep -vE 'https?://' || true)"
if [ -n "$id_hits" ]; then
  echo "FAIL [finding-ids]: audit finding IDs found in shipped source (keep them in commit messages only):"
  echo "$id_hits"
  fail=1
else
  echo "PASS [finding-ids]: no audit finding IDs in shipped source comments"
fi

# --- Guard 2: no dependency config stranded in package.json's pnpm field --------
if [ -f typescript/package.json ]; then
  if node -e 'const p=require("./typescript/package.json"); process.exit(p.pnpm ? 1 : 0)' 2>/dev/null; then
    echo "PASS [pnpm-field]: typescript/package.json has no pnpm field (overrides live in pnpm-workspace.yaml)"
  else
    echo "FAIL [pnpm-field]: typescript/package.json has a 'pnpm' field; pnpm v10 ignores it."
    echo "                   Move overrides / onlyBuiltDependencies to typescript/pnpm-workspace.yaml."
    fail=1
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "repo-hygiene: FAILED"
  exit 1
fi
echo "repo-hygiene: OK"
