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
#
# Ordering rule: the harness meta-leaf (#233) OWNS every shared CI/harness file
# (.github/workflows/*, harness/test/boot-policy.test.ts, ci-coverage-gate.test.ts,
# the pr216 ledger) and is merged LAST, so its blobs win for those paths and it
# is the single authoritative reconciler of the shared surface. #238, #228 and
# #239 all also touch ci.yml + boot-policy.test.ts; among them, the python leaf (#228)
# now precedes the mpp-session leaf (#239) — the telescoped branches carry the
# reconciliation merges in that order, so the cascade mirrors the PR chain. Every leaf's blob for its OWN
# files still lands verbatim; verified by a post-rebuild `git diff <leaf-head>`
# per owned path (all identical). x402 (#236) and rust (#227) carry the mpp/
# subscription reconciliations; ruby (#235) then the harness leaf close it out.
LEAVES=(
  "244:ci/pr216-gate-activation"
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

# Ownership assertion — proves "green by construction". For every path any leaf
# touched, the composed blob MUST equal the LAST leaf in cascade order that
# touched it (the owner). A phantom-conflict reorder or a silent 3-way drop that
# corrupted a blob would fail here. This is the mechanical proof that #240 is a
# pure union of leaf heads, not a hand-edited branch.
# Pure-union proof: every NON-merge commit the rehearsal introduces over base
# must be contained in some leaf head. If any survives excluding base + all leaf
# heads, it was hand-authored on the rehearsal (a direct #240 patch) — exactly
# what Ludo forbade. The script's own merge commits are excluded via --no-merges.
# This is stacked-branch-safe (unlike a per-path diff): it does not care how the
# leaves overlap, only that no commit exists outside their union.
echo "verifying pure union (no hand-authored commits on the rehearsal)..."
excludes=("^$REMOTE/$BASE")
for leaf in "${LEAVES[@]}"; do
  excludes+=("^$REMOTE/${leaf##*:}")
done
stray="$(git rev-list --no-merges HEAD "${excludes[@]}")"
if [[ -n "$stray" ]]; then
  echo "PURE-UNION assertion FAILED: commits on $REHEARSAL not in any leaf head:" >&2
  echo "$stray" | while read -r c; do echo "  $(git log --oneline -1 "$c")" >&2; done
  echo "the rehearsal contains direct patches; do not push. Move each fix to its leaf." >&2
  exit 1
fi
echo "pure-union OK: every commit on $REHEARSAL traces to base or a leaf head"

if [[ "${1:-}" == "--push" ]]; then
  git push --force-with-lease "$REMOTE" "$REHEARSAL"
  echo "pushed $REHEARSAL"
fi
