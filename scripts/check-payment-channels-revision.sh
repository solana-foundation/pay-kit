#!/usr/bin/env bash
#
# Verify every workflow that builds payment-channels uses the same epoch-aware
# program revision. A mismatched checkout decodes the new openSlot bytes as a
# recipient count, so the session harness fails on-chain with InvalidRecipientCount.

set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
readonly EXPECTED_REPOSITORY="solana-foundation/payment-channels"
readonly EXPECTED_REF="0c07d5751c8972abf6a219570a3f39a72f46f879"
readonly TARGETS=(
  ".github/actions/build-payment-channels/action.yml"
  ".github/workflows/go.yml"
  ".github/workflows/harness.yml"
  ".github/workflows/python.yml"
)

fail=0
for target in "${TARGETS[@]}"; do
  path="$ROOT/$target"
  if [ ! -f "$path" ]; then
    echo "FAIL [payment-channels-revision]: missing $target"
    fail=1
    continue
  fi

  block="$(awk '
    /^[[:space:]]*-[[:space:]]+name:[[:space:]]+Checkout payment channels program[[:space:]]*$/ { active = 1; next }
    active && /^[[:space:]]*-[[:space:]]+name:/ { exit }
    active { print }
  ' "$path")"
  if [ -z "$block" ]; then
    echo "FAIL [payment-channels-revision]: $target has no payment-channels checkout block"
    fail=1
    continue
  fi
  if ! grep -Eq "^[[:space:]]*repository: $EXPECTED_REPOSITORY[[:space:]]*$" <<<"$block"; then
    echo "FAIL [payment-channels-revision]: $target must check out $EXPECTED_REPOSITORY"
    fail=1
  fi
  if [ "$target" = ".github/actions/build-payment-channels/action.yml" ]; then
    if ! grep -Fqx "    default: $EXPECTED_REF" "$path"; then
      echo "FAIL [payment-channels-revision]: $target must default its ref to $EXPECTED_REF"
      fail=1
    fi
  elif ! grep -Eq "^[[:space:]]*ref: $EXPECTED_REF[[:space:]]*$" <<<"$block"; then
    echo "FAIL [payment-channels-revision]: $target must pin $EXPECTED_REF"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "payment-channels-revision: OK"
