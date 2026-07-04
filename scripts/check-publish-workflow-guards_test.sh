#!/usr/bin/env bash
#
# check-publish-workflow-guards_test.sh - regression test for
# check-publish-workflow-guards.sh.
#
# The guard must reject a publish workflow that (a) grants any write permission
# at the workflow level, or (b) creates a git tag / GitHub Release without
# gating that step on the publish step's success. This test exercises both
# dimensions:
#
#   1. The two REAL shipped workflows (npm-publish.yml, pypi-publish.yml) must
#      PASS the guard. This is the assertion that is red until the workflows are
#      actually hardened - it is the fail-before proof for the fix.
#
#   2. Two synthetic fixtures, each derived by reverting exactly one guard back
#      to the vulnerable shape, must FAIL. These are the fails-when-guard-removed
#      proofs: they show the guard is load-bearing and not trivially green.
#
# No yq/PyYAML required - the guard parses raw YAML with awk.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
guard="$script_dir/check-publish-workflow-guards.sh"

npm_workflow="$repo_root/.github/workflows/npm-publish.yml"
pypi_workflow="$repo_root/.github/workflows/pypi-publish.yml"

work="$(mktemp -d 2>/dev/null || mktemp -d -t check_publish_guards_test)"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "check-publish-workflow-guards_test FAILED: $*" >&2
  exit 1
}

# ---- Case 1: the real shipped workflows must pass the guard ----
if ! "$guard" "$npm_workflow" "$pypi_workflow" > "$work/real.log" 2>&1; then
  echo "---- guard output (real workflows) ----" >&2
  cat "$work/real.log" >&2
  fail "guard rejected the shipped publish workflows; they must be hardened (top-level permissions read-only; tag/release steps gated on publish success)"
fi
echo "check-publish-workflow-guards_test: real workflows accepted (exit 0)"

# ---- Case 2a: reverting the least-privilege guard must fail ----
# Take the real npm workflow and put a write grant back at the workflow level.
revert_perms="$work/revert-permissions.yml"
awk '
  # Rewrite the top-level (column-0) permissions block back to contents: write.
  /^permissions:[[:space:]]*$/ { print; in_perms = 1; next }
  in_perms == 1 {
    if ($0 ~ /^[^[:space:]]/) { in_perms = 0; print; next }
    if ($0 ~ /^[[:space:]]*contents:/) { print "  contents: write"; next }
    print; next
  }
  { print }
' "$npm_workflow" > "$revert_perms"

if ! grep -Eq '^[[:space:]]*contents:[[:space:]]*write' "$revert_perms"; then
  fail "test setup error: revert-permissions fixture did not reintroduce a top-level write grant"
fi
if "$guard" "$revert_perms" > "$work/revert-perms.log" 2>&1; then
  echo "---- guard output (revert-permissions) ----" >&2
  cat "$work/revert-perms.log" >&2
  fail "guard accepted a workflow whose top-level permissions grant contents: write (least-privilege guard not enforced)"
fi
echo "check-publish-workflow-guards_test: revert-permissions fixture rejected (non-zero exit)"

# ---- Case 2b: reverting the release-gating guard must fail ----
# Take the real npm workflow and strip the publish-success condition off the
# "Create GitHub Release" step, restoring the input-only gate.
revert_gate="$work/revert-gate.yml"
awk '
  # When we are on the if: line immediately following a Create GitHub Release
  # step name, replace it with the old input-only condition.
  {
    if (prev ~ /name:[[:space:]]*Create GitHub Release[[:space:]]*$/ && $0 ~ /^[[:space:]]*if:/) {
      match($0, /^[[:space:]]*/)
      pad = substr($0, 1, RLENGTH)
      print pad "if: ${{ github.event.inputs.create-github-release == '"'"'true'"'"' }}"
      prev = $0
      next
    }
    print
    prev = $0
  }
' "$npm_workflow" > "$revert_gate"

if grep -q "Create GitHub Release" "$revert_gate" && \
   grep -A1 "name: Create GitHub Release" "$revert_gate" | grep -q "outcome"; then
  fail "test setup error: revert-gate fixture still gates the release step on publish outcome"
fi
if "$guard" "$revert_gate" > "$work/revert-gate.log" 2>&1; then
  echo "---- guard output (revert-gate) ----" >&2
  cat "$work/revert-gate.log" >&2
  fail "guard accepted a workflow whose Create GitHub Release step is gated only on the create-release input, not on publish success (release-gating guard not enforced)"
fi
echo "check-publish-workflow-guards_test: revert-gate fixture rejected (non-zero exit)"

echo "check-publish-workflow-guards_test: PASS - least-privilege and publish-success gating are enforced"
