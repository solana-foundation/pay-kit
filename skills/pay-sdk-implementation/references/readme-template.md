# README template

Use this template verbatim; only fill in the placeholders. The reference
implementation is `ruby/README.md` (the structure the maintainer
endorsed in https://github.com/solana-foundation/pay-kit/issues/122).

## Section order

1. Banner + title (`# <package-name>` using language conventions, see below).
2. One-line hero + scope sentence.
3. Badges.
4. Quick start (code snippet drawn from the language's primary example).
5. Protocol compatibility matrix (one table per protocol, with Client /
   Server columns; client-only and server-only packages drop the column
   that does not apply).
6. Examples (how to run them with the simplest possible command; wrap
   anything multi-step behind a `just` task).
7. Solana dependencies.
8. Coding convention.
9. Test / coverage.
10. Interop.
11. Spec.
12. **Repo layout (at the bottom).**
13. License.

## Voice and crypto language

Lead with the use case, not the cryptography. A developer who has never
touched Solana should be able to read the intro paragraph, pick a
currency, and gate a route without learning about blockhashes or replay
stores up front.

- One-line hero: "Charge stablecoins for any HTTP endpoint, in <language>."
  For client-only ports use "Consume stablecoin-gated HTTP endpoints
  (...) from <language>."
- Intro paragraph names the `402 Payment Required` flow and explicitly
  says the reader does not need Solana knowledge to use the library.
- Code snippets stay copy-pasteable; do not invent placeholder imports.
- The on-chain mechanics (sendTransaction, getSignatureStatuses, ATAs,
  compute budget, replay store) live inside the matrix explanation
  paragraph, not in the intro.

## Package name conventions

Use the platform-native packaging convention. If a scope is available,
use it.

| Language | Package name |
|---|---|
| TypeScript | `@solana/pay-kit` (npm scoped) |
| Python | `solana-pay-kit` (PyPI) |
| Ruby | `solana-pay-kit` (RubyGems) |
| PHP | `solana/pay-kit` (Composer vendor/name) |
| Go | `github.com/solana-foundation/pay-kit/go` |
| Kotlin | `com.solanafoundation:pay-kit` (Maven coordinates) |
| Swift | `SolanaPayKit` (SwiftPM target) |
| Lua | `solana-pay-kit` (LuaRocks) |

## Quick start

The first code snippet should be drawn from the language's primary
example. Specifically:

- **PHP**: route from `examples/laravel/routes/api.php`.
- **Ruby**: Sinatra app from `examples/sinatra/app.rb`.
- **Python**: Flask route from `examples/flask/app.py`.
- **TypeScript**: Express route, in the shape used by `demo/server`.
- **Go**: `net/http` `PaymentMiddleware` from `examples/simple-server/`.
- **Lua**: the nginx config from `examples/nginx/nginx.conf` (Lua's
  primary deployment surface).
- **Swift**: the URLSession-backed `MppHTTPClient` flow.
- **Kotlin**: the OkHttp-backed `MppHttpClient` flow.

If the snippet is multi-step, follow it with a "Raw SDK usage"
subsection that shows the underlying primitives.

## Protocol compatibility matrix

State up front whether the language is client-side, server-side, or
both. Use `pass` for shipped cells, `planned` for ones in scope, and
`---` for un-shipped cells. **One table per protocol** in this order:
MPP first, then x402.

For client-only languages, drop the Server column.
For server-only languages, drop the Client column.

```md
### MPP

| Intent | Client | Server |
|---|:---:|:---:|
| `mpp/charge/pull` | pass | pass |
| `mpp/charge/push` | pass | pass |
| `mpp/session` | --- | --- |
| `mpp/subscription` | --- | --- |

### x402

| Intent | Client | Server |
|---|:---:|:---:|
| `x402/exact` | --- | --- |
| `x402/upto` | --- | --- |
| `x402/batch-settlement` | --- | --- |
```

Server-only / client-only callouts replace the missing-side text with a
one-liner like:

> This library is client-only. Server support lives in the TypeScript,
> Rust, Go, PHP, Ruby, Lua, and Python packages.

## Examples section

Each example must be runnable and exercise the full 402 / settlement
flow. Structure it as:

1. **Run server** (if the package ships one).
2. **Drive it from a client** with `curl` and `pay curl`.

Keep commands as clean as possible. If the spin-up is more than three
lines, wrap it behind a `just <task>` so the example block stays short.

## Solana dependencies

Table the dependencies that pull Solana primitives into the package.
State explicitly that the SDK keeps Solana dependencies intentionally
small.

## Coding convention

Name the style guide (e.g. `clippy + rustfmt`, `ruff + pyright`,
`gofmt + go vet`, `PSR-12`, `Standard Ruby`, `luacheck + LuaJIT 2.1`)
and the per-language best-practice skill used during the implementation
pass. Point to `references/coding-conventions.md` for the full rule
set.

## Repo layout (at the bottom)

The repo layout block is the last substantive section before
`## License`. Show the top-level directories with a one-line comment
each.

## Things to pay attention to

- **Matrix row order is canonical**, x402 cells first in spec order
  (`exact`, `upto`, `batch-settlement`), then MPP cells (`charge/pull`,
  `charge/push`, `session`, `subscription`). Cross-SDK table diffs
  depend on this order.
- **Use `pass` / `planned` / `---`** in cells. Avoid mixing `pass` with
  `available` or `implemented`; cross-SDK Playwright snapshots
  pattern-match the canonical token.
- **Badges**: language + coverage are mandatory; branch coverage is
  strongly recommended where the language ships a `just test-cover`
  rule. A tests count badge is optional.
- **Snippets must be runnable.** Each language block should run
  end-to-end against the listed example server on its declared port.
  Do not invent placeholders like `... rest of imports`.
- **Solana dependency table** is the single source of truth for the
  versions a consumer pins. Keep it in sync with the manifest.
- **Crypto language** stays out of the intro and the quick-start
  snippet. On-chain mechanics live in the matrix explanation paragraph
  and the per-section discussions, never in the first paragraph a new
  reader sees.
