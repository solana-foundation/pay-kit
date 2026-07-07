#!/usr/bin/env bash
#
# Self-test for check-repo-hygiene.sh. Unlike a pattern-only unit test, this
# drives the REAL script against a throwaway git fixture: if the guard's git
# grep is deleted, its pathspecs break, or its comment filter is narrowed, the
# planted violations stop being caught and this test goes red. That is the
# whole point -- the guard cannot silently rot into a no-op.
#
# Operates on temp fixtures only, never the real tree.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$SCRIPT_DIR/check-repo-hygiene.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0
assert_rc() { # <desc> <expected-rc> <actual-rc>
  if [ "$2" -eq "$3" ]; then echo "ok   - $1"; else echo "FAIL - $1 (want rc=$2, got $3)"; fails=1; fi
}
assert_contains() { # <desc> <needle> <haystack>
  case "$3" in
    *"$2"*) echo "ok   - $1" ;;
    *) echo "FAIL - $1 (missing: $2)"; fails=1 ;;
  esac
}

# Build a minimal git fixture that replicates the guarded layout: shipped
# source paths the guard scans, plus the excluded siblings (tests, generated
# clients, markdown) that must NOT trip it.
make_fixture() { # <dir>
  local root="$1"
  mkdir -p "$root/typescript/packages/mpp/src" \
           "$root/rust/crates/kit/src/mpp" \
           "$root/python/src/pkg" \
           "$root/go" \
           "$root/typescript/packages/mpp/src/__tests__" \
           "$root/typescript/packages/mpp/src/generated" \
           "$root/python/src/pkg/html"
  # Clean shipped source: legitimate lock vocabulary must survive.
  printf '%s\n' '// canonical L6 structured error code; L8 settlement order.' \
    > "$root/typescript/packages/mpp/src/errors.ts"
  printf '%s\n' '{"name":"root","private":true}' > "$root/package.json"
  printf '%s\n' '{"name":"mpp"}' > "$root/typescript/packages/mpp/package.json"
  git -C "$root" init -q
  git -C "$root" add -A
  git -C "$root" -c user.email=t@t -c user.name=t commit -qm init
}

# --- Case A: dirty fixture must FAIL (non-zero) and name every planted leak ---
dirtyA="$tmp/dirty"
make_fixture "$dirtyA"
# Planted violations:
#  1. dashed finding id in a shipped-source comment
printf '%s\n' '// mirrors the sibling port (H-1, M-2).' \
  > "$dirtyA/typescript/packages/mpp/src/leak-dashed.ts"
#  2. dashless finding id in a shipped-source comment (the regex-widening case)
printf '%s\n' '        // H3: process-local channel store, see the audit note.' \
  > "$dirtyA/rust/crates/kit/src/mpp/leak_dashless.rs"
#  3. pnpm field in a NON-typescript package.json (harness-style)
printf '%s' '{"name":"harness","pnpm":{"overrides":{"ws":"^8.20.1"}}}' \
  > "$dirtyA/go/package.json"
# Decoys that must NOT trip either guard:
#  - finding id inside an excluded test file
printf '%s\n' '// H-9 lives here but tests are excluded.' \
  > "$dirtyA/typescript/packages/mpp/src/__tests__/decoy.test.ts"
#  - finding id inside an excluded generated client
printf '%s\n' '// C-7 in generated code is excluded.' \
  > "$dirtyA/typescript/packages/mpp/src/generated/decoy.ts"
#  - dashless token inside an excluded *.gen.* minified bundle
printf '%s\n' 'var x="C1H3M8";// minified junk' \
  > "$dirtyA/python/src/pkg/html/bundle.gen.js"
#  - legitimate L<n> lock prose in clean source (already in errors.ts)
git -C "$dirtyA" add -A
git -C "$dirtyA" -c user.email=t@t -c user.name=t commit -qm dirty

out="$(ROOT="$dirtyA" bash "$GUARD" 2>&1)"; rc=$?
assert_rc "real guard exits non-zero on a dirty fixture" 1 $rc
assert_contains "reports the dashed finding-id leak"   "leak-dashed.ts"   "$out"
assert_contains "reports the dashless finding-id leak" "leak_dashless.rs" "$out"
assert_contains "reports the stranded pnpm field"      "go/package.json"  "$out"
# Decoys must be absent from the report.
if printf '%s' "$out" | grep -q 'decoy'; then
  echo "FAIL - excluded test/generated decoys leaked into the report"; fails=1
else echo "ok   - excluded test/generated decoys stay out of the report"; fi
if printf '%s' "$out" | grep -q 'bundle.gen.js'; then
  echo "FAIL - excluded *.gen.* bundle tripped the finding-id guard"; fails=1
else echo "ok   - excluded *.gen.* bundle does not trip the finding-id guard"; fi

# --- Case B: clean fixture must PASS (exit 0) --------------------------------
cleanB="$tmp/clean"
make_fixture "$cleanB"
# Add only benign content: lock vocabulary, a clean package.json, an excluded
# test with an id, and a *.gen.* bundle with dashless tokens.
printf '%s\n' '// the L4 lock fails closed; number 42 and range 1-2 are fine.' \
  > "$cleanB/python/src/pkg/note.py"
printf '%s\n' '// H-1 in a test file is allowed.' \
  > "$cleanB/typescript/packages/mpp/src/__tests__/ok.test.ts"
printf '%s\n' 'var y="C1M2H8";' \
  > "$cleanB/python/src/pkg/html/ui.gen.js"
git -C "$cleanB" add -A
git -C "$cleanB" -c user.email=t@t -c user.name=t commit -qm clean

out="$(ROOT="$cleanB" bash "$GUARD" 2>&1)"; rc=$?
assert_rc "real guard exits zero on a clean fixture" 0 $rc

# --- Case C: pattern unit checks, deriving ID_RE from the real script --------
# Grep the finding-id regex out of the guard rather than duplicating it, so a
# drift in the guard's pattern is reflected here automatically.
ID_RE="$(grep -E "^ID_RE=" "$GUARD" | sed -E "s/^ID_RE='(.*)'\$/\1/")"
if [ -z "$ID_RE" ]; then echo "FAIL - could not extract ID_RE from the guard"; fails=1; fi
# Dashed and dashless leaked ids must MATCH (grep rc 0)...
printf '%s\n' '// mirrors the sibling port (H-1, M-2).' > "$tmp/leak.ts"
grep -qE "$ID_RE" "$tmp/leak.ts"; assert_rc "ID_RE matches a dashed leaked id" 0 $?
printf '%s\n' '// C1 regression: guard scope.' > "$tmp/leak2.ts"
grep -qE "$ID_RE" "$tmp/leak2.ts"; assert_rc "ID_RE matches a dashless leaked id" 0 $?
# ...and clean source, including the L<n> lock vocabulary, must NOT match.
printf '%s\n' '// nothing here, just the number 42 and a range 1-2.' > "$tmp/clean.ts"
grep -qE "$ID_RE" "$tmp/clean.ts"; assert_rc "ID_RE ignores clean source" 1 $?
printf '%s\n' '// canonical L6 structured error code; L8 settlement order.' > "$tmp/lock.ts"
grep -qE "$ID_RE" "$tmp/lock.ts"; assert_rc "ID_RE ignores L<n> lock vocabulary" 1 $?

if [ "$fails" -eq 0 ]; then echo "check-repo-hygiene_test: PASS"; else echo "check-repo-hygiene_test: FAIL"; exit 1; fi
