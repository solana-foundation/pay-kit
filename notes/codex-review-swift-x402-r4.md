# Codex Round 4 — Swift x402 exact client port

Carried from `solana-foundation/x402-sdk` PR #26, tip `36c5e9c`.

## Summary

- **Real P1 findings**: 0
- **Confidence**: 4/5
- **Scope**: client-only, cross-platform (SwiftCrypto `Crypto` module, no
  CryptoKit dependency, builds on Linux + Apple platforms with a Swift
  toolchain). Initial r4 landing was darwin-only/CryptoKit; the
  SwiftCrypto migration happened in a later commit on the same PR.
- **Tests**: 23 Swift Testing cases passing (`swift test --filter X402Tests`).

## Source provenance

The Swift X402 targets under `swift/Sources/X402/`,
`swift/Sources/X402InteropClient/`, and `swift/Tests/X402Tests/` are a
mechanical re-org of upstream x402-sdk PR #26 final state, dropped into
the existing pay-kit `swift/Package.swift` (which already declares the
sibling `SolanaMpp` library from PR #104). No upstream behavior changes;
only:

- Library target `X402SwiftExact` → `X402`
- Executable `x402-swift-interop-client` → `x402-interop-client`
- Executable target `X402SwiftInteropClient` → `X402InteropClient`
- Test target `X402SwiftExactTests` → `X402Tests`
- Top-level namespace enum `X402SwiftExact` → `X402`
- Error enum `X402SwiftExactError` → `X402Error`

## Regression coverage carried over

- Challenge `decimals` validation throws on NaN, Inf, negative, fractional,
  or `> 255` values.
- `MemorySolanaSigner` pubkey verify — SwiftCrypto derives the public key
  from the secret seed, mismatch throws `publicKeyMismatch`.
- Ed25519 non-canonical fixture (32-byte `y = p` and `y = p + 1`) plus
  `count == 32` assertion in `Ed25519CompressedPoint`.
- `x402Version` validation throws `unsupportedX402Version` for mismatched
  envelopes.
- `invalidSecretKeyByte` error case for malformed `X402_INTEROP_*_SECRET_KEY`.
- `validatedTokenProgram()` SPL allowlist — SPL Token + Token-2022 only;
  any other `extra.tokenProgram` throws `unsupportedTokenProgram`.
- Network-fallback fail-closed: explicit `selection.network` combined with
  empty `onNetwork` map throws `unsupportedNetwork` (no silent mainnet
  fallback).
- `StablecoinMints` table per-network with cross-network fallback only on
  explicit currency match.
- `X402_INTEROP_PREFER_CURRENCIES` env wired through
  `ChallengeSelection.currencies`.
- `NSNull` representation for absent `X-Payment-Response` settlement header
  in fixture output (parity with TS adapter).
- GET-only scope: interop harness exercises GET only; no POST body capture
  paths claimed.

## CI placement

The harness entry `swift-x402-client` in
`tests/interop/src/implementations.ts` is no longer Darwin-gated after
the SwiftCrypto migration; it runs on any platform that has a Swift
toolchain. The public CI matrix runs interop on `ubuntu-latest` which
does not ship Swift by default, so the adapter stays opt-in via
`MPP_INTEROP_CLIENTS` and `swift run` fails loudly when the toolchain
is missing.

## Interop matrix evidence

90/90 pass on the cross-language matrix in upstream x402-sdk PR #26.
