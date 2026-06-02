---
name: payment-sdk-implementation
description: Derive a new-language SDK port of the Solana payment SDKs (MPP today, x402 next). Use when the user asks to "port the SDK to <language>", "add <language> client/server for MPP", "scaffold a <language> mpp-sdk", or "add x402 support in <language>". Routes to progressive-disclosure references; do not read every leaf — only the ones for the compatibility-matrix cells the user has in scope.
---

# Payment SDK implementation

This skill scaffolds a language port of the Solana payment SDKs that stays
wire-compatible with the Rust reference at `mpp-sdk/rust` (in the
`solana-foundation/pay-kit` repo). It supports both **MPP** (today) and
**x402** (scaffolded; spec references only until x402-kit lands).

## Specs (authoritative)

- MPP / HTTP Payment Authentication scheme — <https://paymentauth.org>
  - Spec PRs — <https://github.com/tempoxyz/mpp-specs>
- x402 — <https://docs.x402.org/introduction>
- Reference Rust crate — `mpp-sdk/rust` (every wire-format claim in
  this skill is grep-able to a path under that tree)

## Compatibility matrix — pick the cells in scope

Both the client and server README matrices use the same seven rows. Confirm
with the user which cells you are implementing this pass. Each enabled cell
maps to exactly one reference file under `references/intents/`:

| Cell | Reference file | Status |
|---|---|---|
| `x402/exact` | `intents/x402-exact.md` | scaffold (future) |
| `x402/upto` | `intents/x402-upto.md` | scaffold (future) |
| `x402/batch-settlement` | `intents/x402-batch-settlement.md` | scaffold (future) |
| `mpp/charge/pull` | `intents/mpp-charge-pull.md` | implemented in Rust |
| `mpp/charge/push` | `intents/mpp-charge-push.md` | implemented in Rust |
| `mpp/session` | `intents/mpp-session.md` | implemented in Rust |
| `mpp/subscription` | `intents/mpp-subscription.md` | not yet specified |

> **Default scope today:** MPP only. `mpp/charge/{pull,push}` are required
> for any new SDK; `mpp/session` is optional; `mpp/subscription` and all
> x402 cells stay listed in the README as `—` until the spec ships.

## Workflow

Work through these phases in order. Do not skip ahead; later phases assume
the directory skeleton and CI from earlier ones.

1. **Confirm scope.** Ask the user (a) the target language, (b) which
   matrix cells are in scope this pass, (c) the package name. Use
   `AskUserQuestion` if any of these are unclear.
2. **Lay out the repo.** Read `references/repo-layout.md` and create the
   directory tree, package manifest, and `justfile` recipes. Do this
   before writing any protocol code — the layout drives the import paths
   the intents docs assume.
3. **Pick conventions.** Read `references/coding-conventions.md` and lock
   in the formatter, linter, type-checker, error type, and async runtime
   for the language. This file also lists the per-language style guides
   (PSR-12 for PHP, Standard Ruby, etc.) the SDK must follow.
4. **Wire CI before code.** Read `references/ci-quality-coverage.md` and
   add a GitHub Actions job that mirrors `test-rust`/`test-python` in
   `.github/workflows/ci.yml`, with a ≥90 % coverage gate, formatter and
   linter steps, and the `html-assets` download. Push CI green on an
   empty skeleton before adding intent code so regressions are caught
   immediately.
5. **Implement intent code.** For **each** matrix cell the user enabled,
   read the matching file under `references/intents/`. Each leaf is
   self-contained: wire format, server obligations, client obligations,
   subtle bugs to avoid, test cases to mirror, spec links. Reference the
   Rust file paths cited in the leaf to disambiguate anything that's
   under-specified.
6. **Add the interop adapter.** Read `references/interop-harness.md`,
   create `harness/<lang>-client/` (and a `bin/interop_server` if
   you're shipping a server), and register it in
   `harness/src/implementations.ts`. Run the focused matrix
   (`MPP_INTEROP_CLIENTS=<lang> MPP_INTEROP_SERVERS=rust pnpm test` and
   the inverse) before flipping `enabled: true`.
7. **Apply the operability caveats.** Read
   `references/operability-caveats.md`. These are the gaps the Ruby
   gem's PR #142 follow-up closed (default `localnet` RPC, mainnet
   mint fallback on `localnet`, preflight + Surfnet cheatcode
   auto-bootstrap, MPP HMAC secret auto-resolution chain, embedded
   `recentBlockhash` in the x402 challenge, framework-host quirks).
   Every port has to land them; PRs that omit any of the numbered
   items need an explicit "not applicable" note in the body.
8. **Write the README last.** Read `references/readme-template.md` and
   fill in the title, badges, repo layout, basic snippet, install/usage,
   client and server matrices (with the seven rows above), example
   walkthrough, Solana dependency list, and links to spec. The matrix
   must use the exact row order shown above so it's diffable across SDKs.

## Hard rules

- **No fabricated invariants.** Every wire-format claim in the SDK you
  ship must trace back to either a Rust file under
  `mpp-sdk/rust/src/` or the spec at `paymentauth.org`. If a
  reference file says "see X.rs", open it.
- **Canonical JSON → base64url, no padding.** Bodies that flow through
  the `request` field, the `opaque` field, or signing inputs use
  RFC 8785 canonical JSON, then base64url-no-pad. Transactions
  themselves use standard-alphabet base64 (with padding). This split
  has bitten every implementation at least once — see
  `references/intents/mpp-charge-pull.md` for the exact boundary.
- **Cross-route replay protection is non-negotiable.** Every server
  must run the tier-2 pinned-field check before settlement — see the
  pinned-field backstop in `rust/src/server/charge.rs:428`. The new
  SDK must expose a `verify_credential_with_expected` (or the
  language-idiomatic equivalent) that pins `amount`, `currency`, and
  `recipient` per route.
- **Coverage gate, doc comments, no emoji.** Public types and functions
  carry a one-line doc comment so the language's LSP shows hover text.
  Coverage gate is ≥ 90 % unless `references/ci-quality-coverage.md`
  says otherwise for the language. Do not put emoji in code, commits,
  or documentation. Do not put model identifiers, "Generated by Claude"
  signatures, or `claude.ai/code` URLs anywhere in committed artifacts.
- **Interop is the truth.** A unit-test green SDK that fails interop
  against Rust is a bug. Run the harness before declaring a cell done.

## When the user asks for something this skill does not cover

- Spec gaps (e.g. `mpp/subscription` semantics): point at
  `intents/mpp-subscription.md` and ask the user to share the spec
  draft. Do not invent semantics.
- x402-specific code beyond the scaffold: ask the user to share
  `~/Coding/x402-kit` (lives on their local machine; not in this
  container). Treat the scaffold as a placeholder until the reference
  lands.
- Anything cross-cutting (the on-chain payment-channels program, the
  multi-delegate program): treat those as out of scope. The Rust crate
  re-exports the on-chain artifacts; the new SDK only needs to
  serialize/deserialize them.
