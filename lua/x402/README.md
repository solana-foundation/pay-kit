# Lua x402 SVM server

This package is a server-only Lua adapter for Solana x402 exact interop probes.

## Current boundary

- `/health` returns a readiness check.
- `/capabilities` reports the Lua server role and exact capability.
- `/exact` exposes the exact challenge for harness drift checks.
- `/protected` requires a `PAYMENT-SIGNATURE` header before any settlement attempt.
- `/exact` builds the Solana SVM challenge from the interop environment (`X402_INTEROP_NETWORK`, `X402_INTEROP_MINT`, `X402_INTEROP_EXTRA_OFFERED_MINTS`, `X402_INTEROP_PRICE`, `X402_INTEROP_PAY_TO`, and `X402_INTEROP_FEE_PAYER`).
- When a payment envelope is present, the server decodes the x402 envelope, validates the versioned Solana transaction shape, patches the fee-payer signature, checks duplicate settlements, and submits the signed transaction through JSON-RPC.

The Lua rockspec declares `lua >= 5.4`, `luasocket`, `luasec` (required for HTTPS RPC), `dkjson`, `luasodium`, and `luazen`.

## Runtime decision

Lua exact server runtime is implemented once `pnpm run test:probe:lua-server` passes as a green settlement smoke. The local evidence is TypeScript client to Lua server interop against the Surfpool-backed harness.

Canonical truth for any Lua runtime promotion is:

- `x402-foundation/x402`, especially `specs/schemes/exact/scheme_exact_svm.md`
- local Rust and TypeScript reference tests in this repository
- official x402 documentation
- official Solana SPL Token, Token-2022, and Associated Token Account documentation

`coinbase/x402` can be used only as a development fork/reference for layout or test ideas. Do not implement behavior from inference or non-canonical examples.

Remaining hardening items:

- Keep Lua dependency choices narrow and documented.
- Keep Lua exact server interop optional in default CI until the maintainer environment has LuaRocks dependencies available.
- Add deeper negative-path probes for malformed transaction shape, wrong token program, wrong mint, wrong amount, fee-payer-as-authority, duplicate settlement, and network mismatch.
- Associated Token Account PDA derivation is now performed independently in pure Lua (`derive_associated_token_address` + `ed25519_on_curve`), mirroring the canonical Rust spine in `rust/crates/x402/src/protocol/schemes/exact/verify.rs::get_associated_token_address`. The fee-payer sweep across all instruction accounts mirrors `verify_managed_signers_not_instruction_accounts` from the same file. Lighthouse instructions are passed through without an allowlist to preserve parity with the Rust and TypeScript spines (see `notes/lighthouse-allowlist-tracking.md`).
