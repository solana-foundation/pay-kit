# Codex Review — Lua x402 exact server (Round 4)

Source: solana-foundation/x402-sdk PR #21 (tip `659364f`).

## Result
- **Real P1 findings:** 0
- **Confidence:** 4/5
- **Cross-language matrix:** 90/90
- **MPP §19.6:** cross-server portability + idempotent-resubmit clean

## Hardening carried over
- luasec TLS peer verification (peer + TLSv1.2+; SSLv2/v3/TLSv1.0/1.1 disabled).
- Pure-Lua 256-bit modular field over the Ed25519 prime with independent ATA
  PDA re-derivation.
- Fee-payer instruction-account sweep (only legitimate ATA-create payer
  carve-out).
- HTTP server fee-payer keypair loaded at startup with typed-error exits.
- Lighthouse instruction passthrough (spine-parity with sibling adapters).
- Token program validated against `extra.tokenProgram`.
- Scaffold + runtime test suites (11/11 + 7/7).

## Scope for this port
Server-only for the M2 milestone. Single-file adapter at
`lua/x402/bin/interop-server.lua` plus the `x402-dev-1` rockspec; wired into
the cross-language interop harness as `lua-x402-server` (opt-in via
`MPP_INTEROP_SERVERS`).
