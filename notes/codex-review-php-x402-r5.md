# Codex Round 5 — PHP x402 Exact Server

Final independent security/protocol review after rebase onto the harness-intent
base and after wiring `php-x402-server` into the cross-spine matrix paired
with the Rust spine client.

## Summary

No P1 security/protocol findings. The PHP verifier/settlement path is
materially sound on the reviewed diff: accepted-requirement canonicalization,
SVM transfer inspection, fee-payer anti-drain checks, compute-price u64 cap,
duplicate-settlement release, and confirm-before-unlock are all present.

## Findings

### P2 — selector env mismatch on `php-x402-server` (confidence 5/5)

`harness/src/implementations.ts` originally gated the new server with
`MPP_INTEROP_SERVERS`, while the other exact servers use `X402_INTEROP_SERVERS`
and the e2e header documents the `X402_INTEROP_*` selector contract. With the
wrong env, the canonical x402 selection path would silently miss the new
cross-spine pair.

Status: fixed in the same commit that records this review note. Selector
switched to `X402_INTEROP_SERVERS`.

### P3 — adapter readiness was optimistic (confidence 4/5)

`php/bin/x402-interop-server.php` previously deferred `state_from_env()` until
the first `/exact` or `/protected` request. A malformed secret key, missing
env var, or missing extension could pass the readiness handshake and only
fail on the first real request.

Status: fixed. State is now eagerly loaded before the `ready` line is
written; failures emit a structured `{"type":"error","stage":"startup",...}`
record on stderr and exit non-zero.

### P3 — stale typecheck command in r4 notes (confidence 5/5)

The earlier r4 verification note referenced a `pnpm --filter` package name
that does not exist in this checkout. Pure documentation drift, no behavior
impact. Left as a follow-up; the r5 verification run below uses the correct
invocation.

## Verification run

- `composer test` from `php/`: 182 tests / 411 assertions pass.
- `php -l bin/x402-interop-server.php`: clean.
- Cross-spine matrix (`X402_INTEROP_CLIENTS=rust-x402`,
  `X402_INTEROP_SERVERS=php-x402-server`, `X402_INTEROP_MATRIX=1`,
  full `X402_INTEROP_*` env): enumeration and dispatch verified;
  full settlement requires a live Solana RPC + signer (run on CI surfpool).

## Disposition

0 P1, 1 P2 (fixed), 2 P3 (1 fixed, 1 doc follow-up). Ready to push.
