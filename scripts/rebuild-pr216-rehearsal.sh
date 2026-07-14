#!/usr/bin/env bash
# Rebuild the #216 integration rehearsal branch (PR #240) purely from the
# current redelivery leaf heads, in the canonical merge cascade order.
#
# Green by construction: every semantic fix lives in a leaf PR targeting
# split/pr216-ci-harness-mega (#219). This script performs ONLY mechanical
# merges. Any merge conflict aborts loudly: the resolution belongs in the
# LATER leaf of the conflicting pair (pre-merge the earlier sibling into it),
# never in the rehearsal branch itself.
#
# Usage:
#   scripts/rebuild-pr216-rehearsal.sh          # rebuild locally, report
#   scripts/rebuild-pr216-rehearsal.sh --push   # rebuild + force-push #240
set -euo pipefail

REMOTE=origin
BASE=split/pr216-ci-harness-mega
REHEARSAL=rehearsal/pr216-integration

# Canonical cascade order (mirrors the planned merge order into #219).
# mpp replay-store cluster first, then the union-based session leaf, then
# x402 (carries the mpp reconciliation), rust (carries the subscription
# reconciliation), ruby, and the harness/meta leaf last (its ledger and
# semgrep gates are convergence checks over everything before it).
LEAVES=(
  "237:fix/mpp-replay-store-hardening"
  "238:fix/mpp-subscription-hardening"
  "228:fix/python-security-hardening"
  "239:fix/mpp-session-state-hardening"
  "236:fix/x402-replay-hardening"
  "227:fix/rust-security-hardening"
  "235:fix/ruby-replay-store-capability"
  "233:fix/harness-adversarial-hardening"
)

git fetch "$REMOTE" --quiet
git checkout -q -B "$REHEARSAL" "$REMOTE/$BASE"
echo "rebased $REHEARSAL onto $REMOTE/$BASE ($(git rev-parse --short HEAD))"

for leaf in "${LEAVES[@]}"; do
  pr="${leaf%%:*}"
  branch="${leaf##*:}"
  if git merge --no-edit "$REMOTE/$branch" >/dev/null 2>&1; then
    echo "merged  #$pr $branch -> $(git rev-parse --short HEAD)"
  else
    echo "CONFLICT merging #$pr ($branch):" >&2
    git diff --name-only --diff-filter=U >&2
    echo "Fix belongs in the LATER leaf of the conflicting pair (pre-merge" >&2
    echo "the earlier sibling into #$pr), not in $REHEARSAL." >&2
    git merge --abort
    exit 1
  fi
done

echo "rebuild complete: $REHEARSAL @ $(git rev-parse --short HEAD)"
if [[ "${1:-}" == "--push" ]]; then
  git push --force-with-lease "$REMOTE" "$REHEARSAL"
  echo "pushed $REHEARSAL"
fi
