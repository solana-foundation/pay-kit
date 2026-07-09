#!/usr/bin/env bash
# Compile a clean downstream module against this checkout. This catches module
# graph or import-path regressions that the SDK's own module cannot observe.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SDK_DIR="$ROOT/go"
PAY_KIT_MODULE="github.com/solana-foundation/pay-kit/go"
SOLANA_MODULE="github.com/solana-foundation/solana-go/v2"
LEGACY_SOLANA_MODULE="github.com/gagliardetto/solana-go"

if [ ! -f "$SDK_DIR/go.mod" ]; then
  echo "consumer guard ERROR: expected Go module at $SDK_DIR" >&2
  exit 2
fi

source_solana_version="$(cd "$SDK_DIR" && go list -m -f '{{.Version}}' "$SOLANA_MODULE")"
if [ -z "$source_solana_version" ] || [ "$source_solana_version" = "(devel)" ]; then
  echo "consumer guard ERROR: could not resolve the pinned $SOLANA_MODULE version" >&2
  exit 2
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/pay-kit-go-consumer.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT
cd "$tmpdir"

go mod init example.com/pay-kit-consumer
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

# Tidy and build from the consumer's module root. `-mod=readonly` makes a
# missing or stale consumer graph a hard failure instead of silently repairing
# it during the compile step.
go mod tidy
consumer_solana_version="$(go list -m -f '{{.Version}}' "$SOLANA_MODULE")"
if [ "$consumer_solana_version" != "$source_solana_version" ]; then
  echo "consumer guard ERROR: downstream resolved $SOLANA_MODULE@$consumer_solana_version, expected $source_solana_version" >&2
  exit 1
fi
if go list -m all | awk '{print $1}' | grep -Fxq "$LEGACY_SOLANA_MODULE"; then
  echo "consumer guard ERROR: downstream module graph still contains legacy $LEGACY_SOLANA_MODULE" >&2
  exit 1
fi
go build -mod=readonly .

echo "consumer guard OK: downstream consumer builds with $SOLANA_MODULE@$consumer_solana_version"
