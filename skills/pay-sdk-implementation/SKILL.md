---
name: payment-sdk-implementation
description: Port or extend a Pay Kit SDK for x402 and MPP on Solana. Use when the user asks to "port Pay Kit to <language>", "add <language> payment client/server support", "implement an MPP intent", or "add an x402 scheme". Inspect the target language's current matrix before choosing scope, then load only the relevant intent references.
---

# Payment SDK implementation

This skill scaffolds or extends a language port of Pay Kit while keeping it
wire-compatible with the public reference implementations in this repository.
Rust under `rust/crates/kit/src/` is the broadest in-repo reference; TypeScript
under `typescript/packages/` is also authoritative for the surfaces it ships.
Both **MPP** and **x402** are implemented today, but coverage varies by language
and changes quickly.

## Specs (authoritative)

- MPP / HTTP Payment Authentication scheme — <https://paymentauth.org>
  - Spec PRs — <https://github.com/tempoxyz/mpp-specs>
- x402 — <https://docs.x402.org/introduction>
- Pay Kit interface — `docs/paykit-interface.md`
- Rust reference — `rust/crates/kit/src/{mpp,x402}`
- TypeScript reference — `typescript/packages/{mpp,pay-kit}` and
  `typescript/external/x402`

## Compatibility matrix — pick the cells in scope

Both the client and server README matrices use the same seven rows. Confirm
with the user which cells you are implementing this pass. Each enabled cell
maps to exactly one reference file under `references/intents/`:

| Cell | Reference file | Status |
|---|---|---|
| `x402/exact` | `intents/x402-exact.md` | public Rust and TypeScript references |
| `x402/upto` | `intents/x402-upto.md` | public Rust and TypeScript references |
| `x402/batch-settlement` | `intents/x402-batch-settlement.md` | public Rust and TypeScript references |
| `mpp/charge/pull` | `intents/mpp-charge-pull.md` | public Rust and TypeScript references |
| `mpp/charge/push` | `intents/mpp-charge-push.md` | public Rust and TypeScript references |
| `mpp/session` | `intents/mpp-session.md` | public Rust and TypeScript references |
| `mpp/subscription` | `intents/mpp-subscription.md` | public Rust and TypeScript references |

Do not infer a default protocol matrix. Read the target language's README,
source tree, and its entries in `harness/src/implementations.ts`, then implement
only the cells requested. A cell implemented in Rust is not automatically
available or harness-enabled in every other language.

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
   current Rust and TypeScript paths cited in the leaf to disambiguate
   anything that's under-specified.
6. **Consume Solana program clients via Codama.** Read
   `references/codegen.md`. Pay-kit vendors Codama IDLs at
   `idl/<program>.json` and renders per-language clients with
   `@codama/renderers-*` via the tooling under `codegen/` (sibling of
   this `SKILL.md`). Today the Rust path ships for the subscriptions
   program; do **not** hand-write a Solana program client in a new
   language — add a `subscriptions-generate-<lang>` recipe alongside
   the existing `subscriptions-generate-rs` and consume the generated
   tree the same way `rust/crates/kit/src/mpp/program/` does in Rust.
7. **Add the harness adapter.** Read `references/harness.md`,
   create `harness/<lang>-client/` (and a `bin/harness_server` if
   you're shipping a server), and register it in
   `harness/src/implementations.ts`. Run the focused matrix with the
   protocol-specific `MPP_HARNESS_*` or `X402_HARNESS_*` selectors documented
   there before flipping `enabled: true`.
8. **Apply the operability caveats.** Read
   `references/operability-caveats.md`. These are the gaps the Ruby
   gem's PR #142 follow-up closed (default `localnet` RPC, mainnet
   mint fallback on `localnet`, preflight + Surfnet cheatcode
   auto-bootstrap, MPP HMAC secret auto-resolution chain, embedded
   `recentBlockhash` in the x402 challenge, framework-host quirks).
   Every port has to land them; PRs that omit any of the numbered
   items need an explicit "not applicable" note in the body.
9. **Write the README last.** Read `references/readme-template.md` and
   fill in the title, badges, repo layout, basic snippet, install/usage,
   client and server matrices (with the seven rows above), example
   walkthrough, Solana dependency list, and links to spec. The matrix
   must use the exact row order shown above so it's diffable across SDKs.

## Hard rules

- **No fabricated invariants.** Every wire-format claim in the SDK you
  ship must trace back to a public implementation under
  `rust/crates/kit/src/{mpp,x402}`, the corresponding TypeScript package, or
  the governing protocol spec. If a
  reference file says "see X.rs", open it.
- **Canonical JSON → base64url, no padding.** Bodies that flow through
  the `request` field, the `opaque` field, or signing inputs use
  RFC 8785 canonical JSON, then base64url-no-pad. Transactions
  themselves use standard-alphabet base64 (with padding). This split
  has bitten every implementation at least once — see
  `references/intents/mpp-charge-pull.md` for the exact boundary.
- **Cross-route replay protection is non-negotiable.** Every server
  must run the tier-2 pinned-field check before settlement — see the
  pinned-field backstop in `rust/crates/kit/src/mpp/server/charge.rs`. The new
  SDK must expose a `verify_credential_with_expected` (or the
  language-idiomatic equivalent) that pins `amount`, `currency`, and
  `recipient` per route.
- **Coverage gate, doc comments, no emoji.** Public types and functions
  carry a one-line doc comment so the language's LSP shows hover text.
  Coverage gate is ≥ 90 % unless `references/ci-quality-coverage.md`
  says otherwise for the language. Do not put emoji in code, commits,
  or documentation. Do not put model identifiers, "Generated by Claude"
  signatures, or `claude.ai/code` URLs anywhere in committed artifacts.
- **The harness is the truth.** A unit-test green SDK that fails the
  harness against Rust is a bug. Run the harness before declaring a
  cell done.

## When the user asks for something this skill does not cover

- A protocol or language cell without a public reference: report the exact
  missing source or harness vector and ask for scope. Do not invent semantics
  or depend on a private checkout.
- Anything cross-cutting in the on-chain payment-channels program: treat
  that as out of scope. The Rust crate
  re-exports the on-chain artifacts; the new SDK only needs to
  serialize/deserialize them.
