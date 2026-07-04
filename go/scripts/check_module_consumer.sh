#!/usr/bin/env bash
#
# check_module_consumer.sh - guard against the go SDK depending on a personal
# fork of solana-go through a non-propagating replace directive.
#
# A `replace` directive in go/go.mod never propagates to downstream consumers.
# If the SDK requires github.com/gagliardetto/solana-go at a pseudo-version whose
# commit content lives in a personal fork, a consumer that does not copy the
# replace resolves DIFFERENT (untested) upstream content for the same commit
# hash - or a fork the pay-kit team no longer controls. This script reproduces a
# downstream consumer and fails when the SDK is in that state.
#
# Two checks:
#   1. Static: go/go.mod must not redirect gagliardetto/solana-go to a non-org
#      fork through a replace directive.
#   2. Behavioral: build a scratch consumer module that path-replaces ONLY the
#      pay-kit module to ./go (never copying the SDK's own replace directives)
#      and importing the signer + preflight surfaces, then assert the consumer
#      resolves the exact same solana-go content that the SDK itself pins.
#
# Exits non-zero (with a diagnostic) when the guard trips.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
go_dir="$(cd "$script_dir/.." && pwd)"

fail() {
  echo "::error::check_module_consumer: $*" >&2
  echo "check_module_consumer FAILED: $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Check 1: no fork replace for solana-go.
# ---------------------------------------------------------------------------
# Match a replace whose right-hand side is a solana-go module that is NOT the
# canonical gagliardetto upstream (e.g. github.com/lgalabru/solana-go).
if grep -Eq '^[[:space:]]*replace[[:space:]]+github\.com/gagliardetto/solana-go[[:space:]]*=>' "$go_dir/go.mod"; then
  offending="$(grep -E '^[[:space:]]*replace[[:space:]]+github\.com/gagliardetto/solana-go[[:space:]]*=>' "$go_dir/go.mod")"
  fail "go.mod redirects gagliardetto/solana-go via a non-propagating replace; downstream consumers will not inherit it: ${offending}"
fi

# The pinned solana-go version the SDK commits to (require line). The `|| true`
# guards keep an empty match from aborting the script under `set -o pipefail`,
# so the explicit emptiness checks below can emit a useful diagnostic.
pinned_version="$(
  awk '/^require[[:space:]]*\(/{inblock=1} \
       inblock==0 && /^[[:space:]]*require[[:space:]]+github\.com\/gagliardetto\/solana-go[[:space:]]/{print $3} \
       inblock==1 && /github\.com\/gagliardetto\/solana-go[[:space:]]/{print $2} \
       /^\)/{inblock=0}' "$go_dir/go.mod" | head -n1 || true
)"
if [ -z "$pinned_version" ]; then
  fail "could not find the gagliardetto/solana-go require version in go.mod"
fi

# A real released version is a semver tag (vMAJOR.MINOR.PATCH); a
# vX.Y.Z-YYYYMMDDHHMMSS-abcdef pseudo-version pins an untagged commit that a
# downstream consumer resolves against whatever repo now owns that hash.
if ! printf '%s' "$pinned_version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'; then
  fail "gagliardetto/solana-go is pinned to '${pinned_version}', which is not a released semver tag; pin a real released upstream version"
fi
if printf '%s' "$pinned_version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-[0-9]{14}-'; then
  fail "gagliardetto/solana-go is pinned to pseudo-version '${pinned_version}'; pin a real released upstream tag instead"
fi

# The content hash the SDK's own go.sum records for that module+version.
sdk_hash="$(grep -E "^github\.com/gagliardetto/solana-go ${pinned_version} h1:" "$go_dir/go.sum" | awk '{print $3}' | head -n1 || true)"
if [ -z "$sdk_hash" ]; then
  fail "go.sum has no gagliardetto/solana-go ${pinned_version} content hash; run go mod tidy"
fi

echo "check_module_consumer: SDK pins gagliardetto/solana-go ${pinned_version} (${sdk_hash})"

# ---------------------------------------------------------------------------
# Check 2: scratch-consumer content-parity build.
# ---------------------------------------------------------------------------
work="$(mktemp -d 2>/dev/null || mktemp -d -t consumer)"
# Go writes module-cache files read-only, so restore write permission before
# removing the scratch tree; otherwise rm floods the log with "Permission
# denied" without affecting the (already-computed) result.
cleanup() {
  chmod -R u+w "$work" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

cache_dir="$work/gomodcache"
mkdir -p "$cache_dir"

cat > "$work/main.go" <<'GO'
package main

import (
	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
)

// consumerSurface exercises the exact SDK entry points a downstream service
// imports: the signer constructors and the paykit preflight-bearing package.
func consumerSurface() (paykit.Signer, paykit.Config) {
	return signer.Demo(), paykit.Config{}
}

func main() {
	_, _ = consumerSurface()
}
GO

cat > "$work/go.mod" <<GO
module consumer.example/paykit-consumer-guard

go 1.26.1

require github.com/solana-foundation/pay-kit/go v0.0.0

replace github.com/solana-foundation/pay-kit/go => ${go_dir}
GO

# A downstream consumer never inherits the SDK's replace directives: only the
# path-replace to the local checkout is added, exactly as `go get` would leave
# a real consumer that has not manually copied pay-kit's replaces.
(
  cd "$work"
  export GOMODCACHE="$cache_dir"
  export GOFLAGS="-mod=mod"
  if ! go build ./... > "$work/build.log" 2>&1; then
    echo "---- consumer build log ----" >&2
    cat "$work/build.log" >&2
    fail "scratch consumer failed to build against upstream-resolved solana-go"
  fi
)

consumer_hash="$(grep -E "^github\.com/gagliardetto/solana-go [^ ]+ h1:" "$work/go.sum" | awk '{print $3}' | head -n1 || true)"
consumer_version="$(grep -E "^github\.com/gagliardetto/solana-go [^ ]+ h1:" "$work/go.sum" | awk '{print $2}' | head -n1 || true)"
if [ -z "$consumer_hash" ]; then
  fail "consumer go.sum has no gagliardetto/solana-go content hash after build"
fi

echo "check_module_consumer: consumer resolved gagliardetto/solana-go ${consumer_version} (${consumer_hash})"

if [ "$consumer_hash" != "$sdk_hash" ]; then
  fail "downstream consumer resolved DIFFERENT solana-go content than the SDK tested against (SDK ${pinned_version} ${sdk_hash} vs consumer ${consumer_version} ${consumer_hash}); the SDK must pin a real released upstream version that consumers resolve identically"
fi

echo "check_module_consumer: PASS - downstream consumer resolves the identical, tested solana-go content"
