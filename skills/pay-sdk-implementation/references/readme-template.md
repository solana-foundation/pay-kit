# README template

Use this template verbatim; only fill in the placeholders. Skip a section
only if `references/intents/<cell>.md` says "no README section". The two
matrices below are diffable across SDKs — preserve row order exactly.

The reference is `mpp-sdk/README.md` (root) and the per-language
banner blocks inside the `<details>` sections.

---

```md
<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# <package-name>

Solana payment method for the [Machine Payments Protocol](https://mpp.dev),
for <language>.

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow.

[![<lang>](https://img.shields.io/badge/<lang>-<version>-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-<n>%25-green)]()
[![Tests](https://img.shields.io/badge/tests-<n>-blue)]()

## Repo layout

`​``
<dir>/
├── src/protocol/        # Wire format (challenge, headers, intents)
├── src/server/          # 402 challenge issuance + credential verification
├── src/client/          # Build credentials from a challenge
├── examples/            # Minimal protected endpoint
└── tests/               # Unit + Surfpool-backed integration
`​``

## Quick start — server (charge)

`​``<lang>
# Idiomatic snippet — server issues challenge, verifies credential.
# Mirror this from the per-language `<details>` block in the root README.
`​``

## Quick start — client (auto-402)

`​``<lang>
# Idiomatic snippet — client receives 402, signs, retries.
`​``

## Client compatibility matrix

| Cell | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | ✅ |
| `mpp/session` | ✅ |
| `mpp/subscription` | — |

## Server compatibility matrix

| Cell | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | ✅ |
| `mpp/session` | ✅ |
| `mpp/subscription` | — |

## How to use the library

`​``<lang>
# install
<install-cmd>

# import path
import <package-name>
`​``

Public surface is documented inline; every public type/function carries
a one-line summary so your editor's LSP/hover shows it without round-
tripping to source.

## How to use the example

`​``bash
cd <dir>/examples
<run-payment-link-server-cmd>
# In another terminal:
curl -i http://localhost:3001/fortune
`​``

The example serves one protected endpoint that returns a fortune cookie
after a paid 402 challenge succeeds. Run against
[Surfpool](https://surfpool.run) on `:8899` for the localnet flow.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `<solana-rpc-client>` | submitting / polling transactions | <ver> |
| `<solana-keypair-signer>` | server fee-payer + interop signer | <ver> |
| `<base58>` | account / signature encoding | <ver> |
| `<ed25519>` | voucher signature verification | <ver> |
| `<canonical-json>` | RFC 8785 canonical JSON pre-base64url | <ver> |

The Solana toolchain itself is pinned through the language's atomic
crates (Rust) or the canonical SDK (`solders`+`solana` for Python).
Do not depend on the umbrella `solana-sdk` package; pull only the
atomic dependencies you actually use.

## Coding convention

This SDK follows <style guide> (e.g. `clippy + rustfmt` for Rust,
`ruff + pyright` for Python, `gofmt + go vet` for Go, `PSR-12` for
PHP, `Standard Ruby` for Ruby). See `references/coding-conventions.md`
in the skill for the full rule set.

## Code coverage

`​``
just <l>-test-cover     # ≥90% gate
`​``

Reported coverage is uploaded as a CI artifact (see
`.github/workflows/ci.yml`).

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## License

MIT
```

---

## Things to pay attention to

- **Matrix row order is canonical** — every SDK's README puts x402 cells
  first (in spec order: `exact`, `upto`, `batch-settlement`), then MPP
  cells (`charge/pull`, `charge/push`, `session`, `subscription`).
  Reordering breaks the cross-language `README.md` table at the root.
- **Use `—` not "n/a"** for un-shipped cells. The root README's matrix
  comparison and Playwright snapshot tests pattern-match the symbol.
- **Badges:** language + coverage are mandatory; tests count is
  optional (used by Rust which doesn't report a coverage % yet).
- **Snippets must be runnable.** Each `<lang>` block should compile or
  run end-to-end against the example server on `:3001`. If the
  language has a REPL, the snippet should be REPL-pastable. Don't
  invent placeholders like `... rest of imports`.
- **Solana dependency table** is the single source of truth for the
  versions a consumer pins. Keep it in sync with the manifest.
