#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$SCRIPT_DIR/check-payment-channels-revision.sh"
EXPECTED_REF="0c07d5751c8972abf6a219570a3f39a72f46f879"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0

write_fixture() {
  local root="$1"
  mkdir -p "$root/.github/actions/build-payment-channels" "$root/.github/workflows"
  cat > "$root/.github/actions/build-payment-channels/action.yml" <<EOF
inputs:
  ref:
    default: $EXPECTED_REF
runs:
  steps:
    - name: Checkout payment channels program
      with:
          repository: solana-foundation/payment-channels
          ref: \${{ inputs.ref }}
    - name: Next step
EOF
  for workflow in go harness python; do
    cat > "$root/.github/workflows/$workflow.yml" <<EOF
steps:
  - name: Checkout payment channels program
    with:
          repository: solana-foundation/payment-channels
          ref: $EXPECTED_REF
  - name: Next step
EOF
  done
}

assert_rc() {
  if [ "$2" -eq "$3" ]; then
    echo "ok   - $1"
  else
    echo "FAIL - $1 (want rc=$2, got $3)"
    fails=1
  fi
}

clean="$tmp/clean"
write_fixture "$clean"
out="$(ROOT="$clean" bash "$GUARD" 2>&1)"; rc=$?
assert_rc "aligned workflow fixture passes" 0 "$rc"

stale="$tmp/stale"
write_fixture "$stale"
sed -i.bak 's/0c07d5751c8972abf6a219570a3f39a72f46f879/d1dee6b34d45d4e4a1ed3174ef421ca2e801aaea/' "$stale/.github/workflows/harness.yml"
out="$(ROOT="$stale" bash "$GUARD" 2>&1)"; rc=$?
assert_rc "stale payment-channels ref fails" 1 "$rc"
case "$out" in
  *"harness.yml must pin"*) echo "ok   - stale ref identifies harness workflow" ;;
  *) echo "FAIL - stale ref report lacks harness workflow"; fails=1 ;;
esac

wrong_repo="$tmp/wrong-repo"
write_fixture "$wrong_repo"
sed -i.bak 's#solana-foundation/payment-channels#Moonsong-Labs/solana-payment-channels#' "$wrong_repo/.github/workflows/go.yml"
out="$(ROOT="$wrong_repo" bash "$GUARD" 2>&1)"; rc=$?
assert_rc "wrong payment-channels repository fails" 1 "$rc"
case "$out" in
  *"go.yml must check out"*) echo "ok   - wrong repository identifies go workflow" ;;
  *) echo "FAIL - wrong repository report lacks go workflow"; fails=1 ;;
esac

if [ "$fails" -ne 0 ]; then
  echo "check-payment-channels-revision_test: FAIL"
  exit 1
fi
echo "check-payment-channels-revision_test: PASS"
