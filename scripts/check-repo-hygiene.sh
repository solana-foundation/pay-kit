#!/usr/bin/env bash
#
# Repo-hygiene guards for two regressions that no other CI gate catches and
# that a prior audit had to clean up by hand:
#
#   1. Audit finding IDs (e.g. "H-1", "M-3", "C-1", "L-4", "I-2", and the
#      dashless "H3", "C1", "M8" spellings) left in shipped source or comments.
#      They belong in commit messages only; leaving them in code leaks internal
#      review bookkeeping into the released package.
#
#   2. Dependency overrides / build-script allowlists placed in a package.json
#      `pnpm` field. pnpm v10 no longer reads that field, so security version
#      pins parked there are silently NOT enforced. They must live in the
#      project's pnpm-workspace.yaml.
#
# Exit non-zero if either guard trips. Safe to run from anywhere.
#
# ROOT defaults to the repo this script lives in, but can be overridden (e.g.
# by the self-test) to point the guards at a fixture tree.
set -uo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$ROOT"
fail=0

# Runtime source across every SDK, excluding tests, generated clients (both
# the `generated/` client dirs and the minified `*.gen.*` UI bundles),
# conformance vectors, and markdown (where an ID may legitimately appear in
# prose).
# The typescript entry uses :(glob) so the `*` wildcard is a real glob and the
# trailing /** also matches files sitting directly in a package's src root
# (a plain `typescript/packages/*/src` pathspec silently skips those). The
# other entries are literal directory prefixes, which already match their
# direct children.
SRC_PATHS=(
  ':(glob)typescript/packages/*/src/**' 'rust/crates/kit/src' 'go' 'python/src'
  'ruby/lib' 'php/src' 'lua/src' 'swift/Sources' 'kotlin/src'
)
SRC_EXCLUDES=(
  ':!*test*' ':!*Test*' ':!*spec*' ':!*/generated/*' ':!*.gen.*'
  ':!*vector*' ':!*.md'
)

# --- Guard 1: no audit finding IDs in shipped source ---------------------------
# Matches the audit ID shape as a standalone token, in comment lines:
#   - dashed:   [C|H|M|L|I]-<1-2 digits>   e.g. H-1, M-12, C-1, L-4, I-2
#   - dashless: [C|H|M]<1-2 digits>        e.g. H3, C1, M8
# The dashless form is deliberately limited to the Critical/High/Medium
# severity letters. "L" and "I" are excluded there because the dashless L<n>
# spelling collides with this codebase's legitimate "lock" vocabulary (e.g.
# "the L6 structured error code", "L8 settlement order") and I<n> collides with
# tokens like bus names; the dashed L-<n>/I-<n> spellings are still caught.
# The `grep` comment-line filter keeps matches to comments, and the https
# filter drops URLs.
ID_RE='(^|[^A-Za-z0-9])([CHMLI]-[0-9]{1,2}|[CHM][0-9]{1,2})([^0-9A-Za-z]|$)'
id_hits="$(git grep -nE "$ID_RE" -- \
  "${SRC_PATHS[@]}" "${SRC_EXCLUDES[@]}" 2>/dev/null \
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
# Scan EVERY tracked package.json (not just typescript/package.json): a `pnpm`
# field anywhere is silently ignored by pnpm v10, so a pin parked there is not
# enforced. node_modules copies are excluded.
pnpm_offenders=()
while IFS= read -r pkg; do
  [ -n "$pkg" ] || continue
  # Read the file by its literal path (not require(), which would treat a
  # bare relative path as a module lookup). Exit 1 only when a `pnpm` field is
  # actually present; a read/parse failure exits 2 and is treated as clean so a
  # malformed sibling package.json cannot masquerade as a stranded-pnpm hit.
  node -e 'const fs=require("fs");try{const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.exit(p.pnpm?1:0)}catch(e){process.exit(2)}' "$ROOT/$pkg"
  case "$?" in
    1) pnpm_offenders+=("$pkg") ;;
  esac
done < <(git ls-files '*package.json' ':!*node_modules*' 2>/dev/null)

if [ "${#pnpm_offenders[@]}" -eq 0 ]; then
  echo "PASS [pnpm-field]: no tracked package.json has a pnpm field (overrides live in pnpm-workspace.yaml)"
else
  echo "FAIL [pnpm-field]: these package.json files have a 'pnpm' field; pnpm v10 ignores it."
  echo "                   Move overrides / onlyBuiltDependencies to the project's pnpm-workspace.yaml:"
  for pkg in "${pnpm_offenders[@]}"; do echo "                   - $pkg"; done
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "repo-hygiene: FAILED"
  exit 1
fi
echo "repo-hygiene: OK"
