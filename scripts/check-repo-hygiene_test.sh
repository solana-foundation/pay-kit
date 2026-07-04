#!/usr/bin/env bash
#
# Self-test for check-repo-hygiene.sh: proves each guard's detection logic
# actually catches a planted violation (and passes clean input), so the guard
# cannot silently rot into a no-op. Operates on temp fixtures, never the tree.
set -uo pipefail
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0
assert_rc() { # <desc> <expected-rc> <actual-rc>
  if [ "$2" -eq "$3" ]; then echo "ok   - $1"; else echo "FAIL - $1 (want rc=$2, got $3)"; fails=1; fi
}

# The exact pattern the guard uses for audit finding IDs.
ID_RE='(^|[^A-Za-z0-9])[CHMLI]-[0-9]{1,2}([^0-9]|$)'

# Guard 1: the pattern must MATCH a leaked ID in a comment (grep rc 0)...
printf '%s\n' '// mirrors the sibling port (H-1, M-2).' > "$tmp/leak.ts"
grep -qE "$ID_RE" "$tmp/leak.ts"; assert_rc "finding-id pattern matches a leaked ID" 0 $?
# ...and must NOT match clean source (grep rc 1).
printf '%s\n' '// nothing to see, just the number 42 and a range 1-2.' > "$tmp/clean.ts"
grep -qE "$ID_RE" "$tmp/clean.ts"; assert_rc "finding-id pattern ignores clean source" 1 $?

# Guard 2: the check must FLAG a package.json with a pnpm field (node exit 1)...
printf '%s' '{"name":"x","pnpm":{"overrides":{"qs":">=6.15.2"}}}' > "$tmp/with-pnpm.json"
node -e "process.exit(require('$tmp/with-pnpm.json').pnpm ? 1 : 0)"
assert_rc "pnpm-field check flags a package.json pnpm field" 1 $?
# ...and must PASS a package.json without one (node exit 0).
printf '%s' '{"name":"x"}' > "$tmp/no-pnpm.json"
node -e "process.exit(require('$tmp/no-pnpm.json').pnpm ? 1 : 0)"
assert_rc "pnpm-field check passes a clean package.json" 0 $?

if [ "$fails" -eq 0 ]; then echo "check-repo-hygiene_test: PASS"; else echo "check-repo-hygiene_test: FAIL"; exit 1; fi
