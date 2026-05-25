# Codex Round 4 — Kotlin x402 exact port

Carried from `solana-foundation/x402-sdk` PR #27, tip `cab2f21`.

## Summary

- **Real P1 findings**: 0
- **Confidence**: 4/5
- **Tests**: 18+ JUnit (`gradle --project-dir kotlin test`)
- **Scope**: client-only (no Kotlin server runtime)

## Source provenance

The Kotlin module under `kotlin/` is a mechanical re-org of the upstream
x402-sdk PR #27 final state. No upstream behavior changes; only the
package namespace was rewritten from `org.x402.sdk.interop` to
`org.solana.x402.exact` when copying into mpp-sdk.

## Regression coverage carried over

- `payTo != payer` self-transfer guard (fail-fast before any RPC / Base58
  work)
- `currencyMatches` `runCatching` wrap (no `IllegalArgumentException`
  leak across the public boundary)
- Stablecoin mainnet-leak fix: sealed-class exhaustive `when` over
  `SolanaNetwork`, fail-closed on unknown network with known stablecoin
  symbol
- `compileV0Message` cross-set account-key dedup with role promotion
- Dead `ULong` guard replaced with real `Long.MAX_VALUE` check
- `ALLOWED_TOKEN_PROGRAMS` triple-validation (challenge envelope +
  transaction builder + RPC mint-owner check)
- Defensive client-side validation before signing
- RFC 8032 §7.1 TEST 1 regression test — locks JCA seed-handling parity
  so signing matches the published test vector byte-for-byte

## Interop matrix evidence

90/90 pass on the cross-language matrix in x402-sdk PR #27.
