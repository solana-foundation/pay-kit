#!/usr/bin/env bash
# Compile a clean downstream module against this checkout. A replace directive
# in go/go.mod never propagates to consumers, so this guard rejects a redirected
# solana-go dependency and proves the remaining module graph builds unchanged.
set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SDK_DIR="$ROOT/go"
PAY_KIT_MODULE="github.com/solana-foundation/pay-kit/go"
SOLANA_MODULE="github.com/solana-foundation/solana-go/v2"

fail() {
  echo "consumer guard ERROR: $*" >&2
  exit 1
}

if ! command -v go >/dev/null 2>&1; then
  echo "consumer guard ERROR: Go is required" >&2
  exit 2
fi

if [ ! -f "$SDK_DIR/go.mod" ] || [ ! -f "$SDK_DIR/go.sum" ]; then
  echo "consumer guard ERROR: expected Go module with go.sum at $SDK_DIR" >&2
  exit 2
fi

source_module="$(cd "$SDK_DIR" && go list -m -f '{{.Path}}' "$SOLANA_MODULE")" ||
  fail "could not resolve $SOLANA_MODULE from go.mod"
if [ "$source_module" != "$SOLANA_MODULE" ]; then
  fail "resolved $source_module instead of $SOLANA_MODULE"
fi

# Go exposes replacements through the module graph, including replacements
# declared inside a block. Any replacement here would be invisible downstream.
source_replace="$(cd "$SDK_DIR" && go list -m -f '{{with .Replace}}{{.Path}}@{{.Version}}{{end}}' "$SOLANA_MODULE")" ||
  fail "could not inspect the $SOLANA_MODULE replacement"
if [ -n "$source_replace" ]; then
  fail "go.mod redirects $SOLANA_MODULE via a non-propagating replace to $source_replace"
fi

source_version="$(cd "$SDK_DIR" && go list -m -f '{{.Version}}' "$SOLANA_MODULE")" ||
  fail "could not resolve the pinned $SOLANA_MODULE version"
if [ -z "$source_version" ] || [ "$source_version" = "(devel)" ]; then
  fail "could not resolve a released $SOLANA_MODULE version"
fi
if ! printf '%s' "$source_version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'; then
  fail "$SOLANA_MODULE is pinned to $source_version, not a released semver version"
fi
if printf '%s' "$source_version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-[0-9]{14}-'; then
  fail "$SOLANA_MODULE is pinned to pseudo-version $source_version, not a released upstream tag"
fi

source_hash="$(awk -v module="$SOLANA_MODULE" -v version="$source_version" '$1 == module && $2 == version && $3 ~ /^h1:/ { print $3; exit }' "$SDK_DIR/go.sum")"
if [ -z "$source_hash" ]; then
  fail "go.sum has no content hash for $SOLANA_MODULE@$source_version; run go mod tidy"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/pay-kit-go-consumer.XXXXXX")"
trap 'rm -rf "$work"' EXIT

cd "$work"

go mod init example.com/pay-kit-consumer >/dev/null
go mod edit "-require=$PAY_KIT_MODULE@v0.0.0"
go mod edit "-replace=$PAY_KIT_MODULE=$SDK_DIR"

cat > main.go <<'EOF'
package main

import (
	_ "github.com/solana-foundation/pay-kit/go/paycore"
	_ "github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	_ "github.com/solana-foundation/pay-kit/go/paykit"
	_ "github.com/solana-foundation/pay-kit/go/paykit/adapters/mpp"
	_ "github.com/solana-foundation/pay-kit/go/paykit/adapters/x402"
	_ "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	_ "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

func main() {}
EOF

# Tidy creates the graph a real downstream module would have. The subsequent
# readonly build makes a missing or stale graph a hard failure.
if ! go mod tidy >"$work/tidy.log" 2>&1; then
  cat "$work/tidy.log" >&2
  fail "scratch consumer could not resolve the downstream module graph"
fi
consumer_version="$(go list -m -mod=readonly -f '{{.Version}}' "$SOLANA_MODULE")" ||
  fail "scratch consumer did not resolve $SOLANA_MODULE"
consumer_hash="$(awk -v module="$SOLANA_MODULE" -v version="$consumer_version" '$1 == module && $2 == version && $3 ~ /^h1:/ { print $3; exit }' go.sum)"
if [ -z "$consumer_hash" ]; then
  fail "scratch consumer go.sum has no content hash for $SOLANA_MODULE@$consumer_version"
fi
if [ "$consumer_version" != "$source_version" ] || [ "$consumer_hash" != "$source_hash" ]; then
  fail "downstream resolved $SOLANA_MODULE@$consumer_version ($consumer_hash), expected $source_version ($source_hash)"
fi

if ! go build -mod=readonly . >"$work/build.log" 2>&1; then
  cat "$work/build.log" >&2
  fail "scratch consumer failed to build"
fi

echo "consumer guard OK: downstream consumer builds with $SOLANA_MODULE@$consumer_version"
