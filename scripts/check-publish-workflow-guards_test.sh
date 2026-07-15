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

# ---- Case 2c: scalar write-all top-level permissions must fail ----
# The permissions block also has a scalar shorthand form (`permissions: write-all`
# on a single line) that grants blanket write. Rewrite the real npm workflow's
# block-form top-level permissions to that scalar and assert the guard rejects it.
writeall_perms="$work/writeall-permissions.yml"
awk '
  # Replace the top-level (column-0) permissions block with the scalar write-all
  # shorthand: emit the scalar line and drop the indented grant/blank lines.
  /^permissions:[[:space:]]*$/ { print "permissions: write-all"; in_perms = 1; next }
  in_perms == 1 {
    if ($0 ~ /^[^[:space:]]/) { in_perms = 0; print; next }
    next
  }
  { print }
' "$npm_workflow" > "$writeall_perms"

if ! grep -Eq '^permissions:[[:space:]]*write-all[[:space:]]*$' "$writeall_perms"; then
  fail "test setup error: writeall-permissions fixture did not reintroduce a scalar write-all top-level grant"
fi
if "$guard" "$writeall_perms" > "$work/writeall-perms.log" 2>&1; then
  echo "---- guard output (writeall-permissions) ----" >&2
  cat "$work/writeall-perms.log" >&2
  fail "guard accepted a workflow whose top-level permissions is the scalar write-all (least-privilege guard not enforced for the scalar form)"
fi
echo "check-publish-workflow-guards_test: writeall-permissions (scalar) fixture rejected (non-zero exit)"

# ---- Case 3: scalar read-all top-level permissions must fail ----
# `read-all` exposes every readable token scope and is broader than the release
# workflows need. The guard requires the explicit `contents: read` block.
readall_perms="$work/readall-permissions.yml"
awk '
  /^permissions:[[:space:]]*$/ { print "permissions: read-all"; in_perms = 1; next }
  in_perms == 1 {
    if ($0 ~ /^[^[:space:]]/) { in_perms = 0; print; next }
    next
  }
  { print }
' "$npm_workflow" > "$readall_perms"

if ! grep -Eq '^permissions:[[:space:]]*read-all[[:space:]]*$' "$readall_perms"; then
  fail "test setup error: readall-permissions fixture did not produce a scalar read-all top-level grant"
fi
if "$guard" "$readall_perms" > "$work/readall-perms.log" 2>&1; then
  echo "---- guard output (readall-permissions) ----" >&2
  cat "$work/readall-perms.log" >&2
  fail "guard accepted scalar read-all even though only contents: read is required"
fi
echo "check-publish-workflow-guards_test: readall-permissions (scalar) fixture rejected (non-zero exit)"

# ---- Case 4: an extra read scope in block form must fail ----
extra_read="$work/extra-read-permissions.yml"
awk '
  { print }
  /^  contents:[[:space:]]*read[[:space:]]*$/ { print "  actions: read" }
' "$npm_workflow" > "$extra_read"

if "$guard" "$extra_read" > "$work/extra-read-perms.log" 2>&1; then
  echo "---- guard output (extra-read-permissions) ----" >&2
  cat "$work/extra-read-perms.log" >&2
  fail "guard accepted an unnecessary top-level actions: read scope"
fi
echo "check-publish-workflow-guards_test: extra read scope fixture rejected (non-zero exit)"

echo "check-publish-workflow-guards_test: PASS - least-privilege and publish-success gating are enforced"
