#!/usr/bin/env bash
# Exercise the real consumer guard with an offline Go module proxy. The fixture
# has the same module and import layout as the SDK, so this covers go mod tidy,
# graph parity, and the readonly downstream build without external network use.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$SCRIPT_DIR/check_module_consumer.sh"
MODULE="github.com/solana-foundation/solana-go/v2"
VERSION="v2.0.0"
GO_VERSION="$(go env GOVERSION | sed 's/^go//')"
tmp="$(mktemp -d)"
trap 'chmod -R u+w "$tmp" 2>/dev/null || true; rm -rf "$tmp"' EXIT
fails=0

assert_rc() {
  if [ "$2" -eq "$3" ]; then
    echo "ok   - $1"
  else
    echo "FAIL - $1 (want rc=$2, got $3)"
    fails=1
  fi
}

assert_contains() {
  case "$3" in
    *"$2"*) echo "ok   - $1" ;;
    *) echo "FAIL - $1 (missing: $2)"; fails=1 ;;
  esac
}

make_proxy() {
  local proxy="$tmp/proxy"
  local stage="$tmp/stage/$MODULE@$VERSION"
  local module_path="$proxy/$MODULE/@v"
  mkdir -p "$stage" "$module_path"
  cat > "$stage/go.mod" <<EOF
module $MODULE

go $GO_VERSION
EOF
  printf '%s\n' 'package solana' > "$stage/solana.go"
  (
    cd "$tmp/stage"
    zip -qr -D "$module_path/$VERSION.zip" "$MODULE@$VERSION"
  )
  printf '%s\n' "$VERSION" > "$module_path/list"
  printf '{"Version":"%s","Time":"2026-01-01T00:00:00Z"}\n' "$VERSION" > "$module_path/$VERSION.info"
  cp "$stage/go.mod" "$module_path/$VERSION.mod"
}

write_fixture() {
  local root="$1"
  local sdk="$root/go"
  mkdir -p "$sdk/paycore/solanatx" \
    "$sdk/paykit/adapters/mpp" \
    "$sdk/paykit/adapters/x402" \
    "$sdk/protocols/mpp/core" \
    "$sdk/protocols/x402"
  cat > "$sdk/go.mod" <<EOF
module github.com/solana-foundation/pay-kit/go

go $GO_VERSION

require $MODULE $VERSION
EOF
  cat > "$sdk/paycore/paycore.go" <<EOF
package paycore

import _ "$MODULE"
EOF
  printf '%s\n' 'package solanatx' > "$sdk/paycore/solanatx/solanatx.go"
  printf '%s\n' 'package paykit' > "$sdk/paykit/paykit.go"
  printf '%s\n' 'package mpp' > "$sdk/paykit/adapters/mpp/mpp.go"
  printf '%s\n' 'package x402' > "$sdk/paykit/adapters/x402/x402.go"
  printf '%s\n' 'package core' > "$sdk/protocols/mpp/core/core.go"
  printf '%s\n' 'package x402' > "$sdk/protocols/x402/x402.go"
  (
    cd "$sdk"
    GOPROXY="file://$tmp/proxy" \
      GOSUMDB=off \
      GOMODCACHE="$tmp/source-gomodcache" \
      GOCACHE="$tmp/source-gocache" \
      go mod tidy
  )
}

run_guard() {
  ROOT="$1" \
    GOPROXY="file://$tmp/proxy" \
    GOSUMDB=off \
    GOMODCACHE="$tmp/gomodcache" \
    GOCACHE="$tmp/gocache" \
    bash "$GUARD"
}

capture_guard() {
  if out="$(run_guard "$1" 2>&1)"; then
    rc=0
  else
    rc=$?
    printf '%s\n' "$out" >&2
  fi
}

make_proxy
good="$tmp/good"
write_fixture "$good"
capture_guard "$good"
assert_rc "clean downstream consumer fixture passes" 0 "$rc"
assert_contains "clean fixture reports a successful consumer build" "consumer guard OK" "$out"

bad="$tmp/bad"
cp -R "$good" "$bad"
cat >> "$bad/go/go.mod" <<EOF

replace $MODULE => example.com/personal-fork/solana-go/v2 $VERSION
EOF
capture_guard "$bad"
assert_rc "non-propagating replacement fails closed" 1 "$rc"
assert_contains "replacement failure names the cause" "non-propagating replace" "$out"

if [ "$fails" -ne 0 ]; then
  echo "check_module_consumer_test: FAIL"
  exit 1
fi
echo "check_module_consumer_test: PASS"
