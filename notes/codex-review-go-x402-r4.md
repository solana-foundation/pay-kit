# Codex Round 4 — Go x402 exact port

Carried from `solana-foundation/x402-sdk` PR #18, tip `e3bf746`.

## Summary

- **Real P1 findings**: 0
- **Confidence**: 4/5
- **Coverage**: server 90.9%, client 91.9% (`go test ./... -cover -race`)
- **Lint**: `gofmt -l` clean, `go vet ./...` clean

## Source provenance

The Go binaries under `go/x402/cmd/interop-{client,server}/` are a mechanical
re-org of the upstream x402-sdk PR #18 final state. No upstream behavior
changes; only the module path was rewritten when copying into mpp-sdk's
single-module `go/` tree.

## Regression coverage carried over

- Fee-payer attack regression suite (5 attack shapes + positive control)
- Multi-mint `extra.offered` support
- Lighthouse instruction passthrough (spine-parity per
  `notes/lighthouse-allowlist-tracking.md` in x402-sdk)
- `extra.tokenProgram` mint allowlist enforcement
- Token alias → base58 resolve at env boundary
- Cross-envelope preference fallback
- Idempotent resubmit / replay protection via Solana per-signature native
  + scheme-namespaced cache

## Interop matrix evidence

90/90 pass on the seven-language sweep in x402-sdk PR #18.

MPP §19.6 cross-server scenarios: portability + idempotent-resubmit clean —
the Go server rejects cross-server credentials with the canonical token.
