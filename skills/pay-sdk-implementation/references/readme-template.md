# README template

Use this template verbatim; only fill in the placeholders. Skip a section
only if `references/intents/<cell>.md` says "no README section". The two
matrices below are diffable across SDKs — preserve row order exactly.

The reference is `ruby/README.md` (Ludo's structure update, intro and
limited-crypto-language pass) and the per-language banner blocks inside
the root `README.md` `<details>` sections.

## Voice and crypto language

Lead with the use case, not the cryptography. A developer who has never
touched Solana should be able to read the intro paragraph, pick a
currency, and gate a route without learning about blockhashes or replay
stores up front.

- One-line hook: "Charge stablecoins for any HTTP endpoint, in <language>."
- Intro paragraph names the `402 Payment Required` flow and explicitly
  says the reader does not need Solana knowledge to use the library.
- Code snippets stay copy-pasteable; do not invent placeholder imports.
- The on-chain mechanics (sendTransaction, getSignatureStatuses, ATAs,
  compute budget, replay store) live inside the server-matrix explanation
  paragraph, not in the intro.

---

```md
<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="MPP" width="100%" />
</p>

# <package-name>

Charge stablecoins (USDC, USDT, PYUSD, …) for any HTTP endpoint, in <language>.
Implements the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev).

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
don't need to know anything about Solana to use this library — pick a
currency, give it your wallet address, and gate a route in two lines.

[![<lang>](https://img.shields.io/badge/<lang>-<version>-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-<n>%25-brightgreen)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-<n>%25-brightgreen)]()

## Repo layout

`​``text
<dir>/
├── src/protocol/        # Wire format (challenge, headers, intents)
├── src/server/          # 402 challenge issuance + credential verification
├── src/client/          # Build credentials from a challenge (where applicable)
├── examples/            # Minimal protected endpoints
└── tests/               # Unit + Surfpool-backed integration
`​``

## Quick start — server

`​``<lang>
# Idiomatic snippet: server issues challenge, verifies credential, settles.
# The method object owns every static knob (recipient, default currency,
# network, RPC, optional fee payer). Per-request you only pass `amount`
# and `description`. The blockhash is fetched lazily and cached for ~2s
# inside the method so a busy endpoint doesn't pay an RPC round-trip on
# every protected request.
`​``

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"` — the SDK looks up the mint address, token program, and
decimals from a built-in table. You can also pass a raw mint pubkey for
tokens not in the table.

### Framework integrations

Add one subsection per first-class framework integration the language
ships. Ruby ships Rack middleware and a Sinatra helper. Python ships
ASGI/WSGI middleware. PHP ships PSR-15 middleware. Lua ships an
OpenResty access-phase handler. Keep the snippet short and runnable.

## Running the examples

`​``bash
cd <dir>
<install-cmd>

<run-example-cmd>
`​``

In another terminal:

`​``bash
brew install pay
curl http://localhost:<port>/paid       # 402 payment required
pay curl http://localhost:<port>/paid   # pays and succeeds
`​``

The example defaults to Surfpool localnet (`https://402.surfnet.dev:8899`),
`USDC`, and a local example recipient. Override `MPP_RPC_URL`,
`MPP_CURRENCY`, `MPP_PAY_TO`, `MPP_AMOUNT`, or `MPP_FEE_PAYER_SECRET_KEY`
for a different localnet fixture.

## Client compatibility matrix

State up front whether the language is client-side, server-side, or both
in the current MPP roadmap. Use `—` for unsupported cells.

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | — |
| `mpp/charge/push` | — |
| `mpp/session` | — |
| `mpp/subscription` | — |

## Server compatibility matrix

Split into two phases because an MPP server first verifies the credential
and then settles or confirms the payment on-chain.

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | ✅ |
| `mpp/session` | — |
| `mpp/subscription` | — |

For `mpp/charge/pull`: the server owns the full lifecycle, issue signed
challenges with a fresh `recentBlockhash`, parse and validate the
`Authorization: Payment` credential, pin the echoed charge request,
decode the client-signed transaction and check recipient / amount / mint
/ splits / ATA / memos / compute budget, reject Surfpool-signed
transactions on non-localnet networks, optionally fee-payer co-sign,
broadcast via `sendTransaction`, poll `getSignatureStatuses` to
`confirmed` / `finalized`, and emit `payment-receipt` with the on-chain
signature.

For `mpp/charge/push`: the server fetches the transaction by signature
with `getTransaction`, rejects failed or missing metadata, reuses the
same structural transaction verifier as pull mode, consumes the
signature through replay storage, and emits the same receipt shape.

The direct `<language>` interop server at
[`tests/interop/<lang>-server/server.<ext>`](../tests/interop/<lang>-server/server.<ext>)
exercises this end-to-end through Surfpool in CI.

## Examples

Each example must be runnable and exercise the full 402 / settlement
flow against Surfpool localnet. List the directory, the framework, and
which protected endpoints it exposes.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `<solana-rpc-client>` | submitting / polling transactions | <ver> |
| `<base58>` | account / signature encoding | <ver> |
| `<ed25519>` | fee-payer transaction signing | <ver> |
| `<canonical-json>` | RFC 8785 canonical JSON pre-base64url | <ver> |

State explicitly that the SDK keeps Solana dependencies intentionally
small. Do not depend on an umbrella `solana-sdk` package; pull only the
atomic dependencies you actually use. The Solana toolchain itself is
pinned through the language's atomic crates (Rust) or the canonical SDK
(`solders` + `solana` for Python).

## Coding convention

This SDK follows <style guide> (e.g. `clippy + rustfmt` for Rust,
`ruff + pyright` for Python, `gofmt + go vet` for Go, `PSR-12` for PHP,
`Standard Ruby` for Ruby, `luacheck + LuaJIT 2.1` for Lua). See
`references/coding-conventions.md` in the skill for the full rule set.

The repo-level `pay-sdk-implementation` skill remains the protocol source
of truth: Rust / spec wire format first, language idioms second.

## Code coverage

`​``bash
cd <dir>
just lint
just audit
just test-cover
`​``

`just test-cover` runs the language's coverage tool with line and branch
coverage enabled and enforces the local coverage gates.

Coverage gates:

- line coverage: at least 92 percent
- branch coverage: at least 90 percent

The branch gate is meaningful because the branch tests cover the payment
verifier's critical decisions: valid / invalid credentials, cross-route
replay, split accounting, ATA creation, compute budget limits, fee-payer
abuse, pull settlement, push settlement, transaction failures, missing
metadata, timeouts, and replay consumption.

## Interop

State the harness adapter path and any focused harness commands the
language ships in this pass:

`​``bash
cd tests/interop
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=<lang> pnpm test
MPP_INTEROP_CLIENTS=rust       MPP_INTEROP_SERVERS=<lang> pnpm test
`​``

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
- **Use `—` not `n/a`** for un-shipped cells. The root README's matrix
  comparison and Playwright snapshot tests pattern-match the symbol.
- **Badges:** language + coverage are mandatory; branch coverage is
  strongly recommended for any SDK that ships a `just test-cover` rule.
  Tests count is optional (used by Rust which doesn't report a coverage
  percent yet).
- **Snippets must be runnable.** Each `<lang>` block should compile or
  run end-to-end against the example server on its declared port. If the
  language has a REPL, the snippet should be REPL-pastable. Don't invent
  placeholders like `... rest of imports`.
- **Solana dependency table** is the single source of truth for the
  versions a consumer pins. Keep it in sync with the manifest.
- **Crypto language** stays out of the intro and the quick-start
  snippet. On-chain mechanics (blockhash, sendTransaction, ATAs,
  compute budget, replay consumption) live in the server-matrix
  explanation paragraph and the per-section discussions, never in
  the first paragraph a new reader sees.
