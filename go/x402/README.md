# Go x402 SDK

Go implementation of the x402 `exact` scheme (client + server) for Solana.

This sub-package mirrors the canonical Rust spine at `rust/crates/x402/`
and ships the interop adapters used by the cross-language harness.

## Layout

```text
go/x402/
├── cmd/
│   ├── interop-client/    interop harness client binary
│   └── interop-server/    interop harness server binary
└── README.md
```

The exact-scheme protocol types, verifier, and settler live inline in
the two `main.go` files. The Rust crate keeps a separate
`protocol/schemes/exact/`, `server/exact.rs`, `client/exact/payment.rs`
split; the Go port keeps them inline because both binaries are
self-contained and there is no third caller. The spine's wire format,
constants, and pipeline ordering are mirrored 1:1.

## Test

```bash
cd go
go test ./x402/... -cover -race
```

Expected coverage: server ≥ 90 %, client ≥ 90 %.

## Format and vet

```bash
gofmt -l go/x402/
go vet ./x402/...
```

## Parity with the Rust spine

The Go port matches `rust/crates/x402/` on:

- CAIP-2 network identifiers (`solana:5eykt...`, `solana:EtWTR...`,
  `solana:4uhc...`) — verbatim.
- Program IDs (Token, Token-2022, Associated Token, Compute Budget,
  System, Memo, Lighthouse) — verbatim.
- Stablecoin mint addresses per network (USDC/USDT/USDG/PYUSD/CASH) —
  verbatim.
- Constants: `EXACT_SCHEME = "exact"`, `maxMemoBytes = 256`.
- Instruction allowlist: ComputeBudget (Set CU Limit + Price), SPL
  Token / Token-2022 `TransferChecked`, plus optional Lighthouse +
  Memo + ATA-create.
- Lighthouse passthrough by program-ID match only (no discriminator
  allowlist, no account-count cap) — spine parity.
- Fee-payer-in-instruction-accounts sweep with the legitimate
  ATA-create payer slot exception.
- Destination ATA re-derived from `(payTo, mint, tokenProgram)` and
  compared against the transaction's destination index.
- L8 settlement ordering: broadcast → confirm → mark.
- Cross-server credential rejection with canonical 4xx + token in body.
- Env-var contract: `X402_INTEROP_TARGET_URL`,
  `X402_INTEROP_RPC_URL`, `X402_INTEROP_NETWORK`,
  `X402_INTEROP_CLIENT_SECRET_KEY`,
  `X402_INTEROP_FACILITATOR_SECRET_KEY`, `X402_INTEROP_PAY_TO`,
  `X402_INTEROP_MINT`, `X402_INTEROP_PRICE`,
  `X402_INTEROP_EXTRA_OFFERED_MINTS` (CSV),
  `X402_INTEROP_PREFER_CURRENCIES` (CSV).
- Client `result` and server `ready` stdout JSON shapes.

Intentional Go-side specifics (not divergences):

- Mint alias resolution happens at the env-read boundary
  (`X402_INTEROP_MINT` may be a symbol or base58); the rest of the
  code sees canonical base58. The spine accepts the same pattern.
- Duplicate-settlement cache keys are SHA-256 of the encoded
  transaction, in addition to Solana's native per-signature
  uniqueness — defense-in-depth, matches the upstream reference.

No upstream behavior changes vs the reference port (tip `e3bf746`).
