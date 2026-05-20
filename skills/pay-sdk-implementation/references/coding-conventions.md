# Coding conventions

The SDK reads as idiomatic in its target language. The Rust crate is the
reference for **wire format and module structure**, not for code style.
Use the language's canonical style guide and tooling.

## Per-language style guides

| Language | Style | Formatter | Linter | Type-checker | Test runner |
|---|---|---|---|---|---|
| Rust | `rustfmt` defaults | `cargo fmt` | `cargo clippy -- -D warnings` | rustc | `cargo test` |
| Python | PEP 8 / `ruff` defaults | `ruff format` | `ruff check` | `pyright` | `pytest` |
| Go | gofmt / Effective Go | `gofmt` | `go vet`, `staticcheck` | (gc) | `go test` |
| TypeScript | `@typescript-eslint` standard, Prettier | `prettier` | `eslint` | `tsc --noEmit` | `vitest` |
| Lua | LDoc + StyLua | `stylua` | `luacheck` | — | custom (`tests/run.lua`) |
| PHP | PSR-12 | `php-cs-fixer` | `phpstan --level=max` | (psalm/phpstan) | `phpunit` |
| Ruby | Standard Ruby | `standardrb --fix` | `standardrb` (or `rubocop`) | optional `sorbet` | `rspec` |
| Java | Google Java Style | `google-java-format` | `errorprone`, `spotbugs` | (javac) | JUnit 5 |
| C# / .NET | `dotnet format` | `dotnet format` | analyzers (`/warnaserror`) | (roslyn) | xUnit |
| Swift | Swift API Design Guidelines | `swift-format` | `swiftlint` | (swiftc) | XCTest |
| Kotlin | Kotlin Coding Conventions | `ktlint` / `ktfmt` | `detekt` | (kotlinc) | JUnit 5 |
| Elixir | `mix format` | `mix format` | `credo` | `dialyxir` | ExUnit |
| Haskell | `ormolu` | `ormolu` | `hlint` | (ghc) | `hspec` |

## Naming

Use the language's canonical identifier case:

- Rust / Lua / Python — `snake_case` for functions, `PascalCase` for
  types, `SCREAMING_SNAKE` for constants.
- Go / TypeScript / Swift / Kotlin / Java / C# — `camelCase` for
  functions, `PascalCase` for types, `SCREAMING_SNAKE` for compile-time
  constants.
- PHP — `camelCase` for methods, `PascalCase` for classes,
  `SCREAMING_SNAKE` for constants.
- Ruby — `snake_case` for methods, `PascalCase` for classes,
  `SCREAMING_SNAKE` for constants.

Wire-format field names are **camelCase JSON** in every language (see
`rust/src/protocol/intents/charge.rs:35` — `externalId`, `methodDetails`
are serde-renamed to camelCase). The struct/class field name follows
language convention; only the serialized form is camelCase.

## Dep version pinning

- **Pin the Solana toolchain to atomic crates / canonical SDKs**, not
  the umbrella SDK. The Rust crate pins `solana-hash`, `solana-pubkey`,
  `solana-message`, `solana-rpc-client`, `solana-signature`,
  `solana-transaction` separately — see `rust/Cargo.toml`. The Python
  package uses `solders` (Rust-backed types) + `solana` (RPC client).
  Lua / Go / TS open-code the small set of constants they need.
- **Pin the signer rev.** Rust pins `solana-keychain` to a git rev
  (`abf75944`). New languages that ship a signer abstraction must
  pin the same way — multi-language signer compatibility breaks
  silently if you don't.
- **Lockfiles in git.** Every SDK commits its lockfile
  (`Cargo.lock`, `pnpm-lock.yaml`, `go.sum`, `poetry.lock`/`uv.lock`).
- **Minimum versions.** Pick the oldest language version that
  supports the SDK's features (Python 3.11, Go 1.22+, Node 22,
  Rust stable 1.78+). Document it in the manifest.

## Errors

The SDK exposes **one** error type per top-level concern:

- `Error` (or `MppError`) — the protocol/SDK-level enum (see
  `rust/src/error.rs`).
- `StoreError` — replay-store internal errors (see
  `rust/src/store.rs:36`).
- `VerificationError` — server-side credential verification result.

In typed languages, use the language's enum/sum-type construct
(Rust `enum`, Go sentinel `errors`, Python class hierarchy, TS
discriminated union, Swift `enum`, etc.). Each variant maps 1:1 to a
Rust `Error::*` variant where possible so error strings remain
diff-able across languages.

## Async / concurrency

- Rust — `tokio` (`#[tokio::main]`).
- Python — `asyncio` + `httpx.AsyncClient`.
- Go — built-in goroutines + `net/http`.
- TS — `async/await` + `fetch`/undici.
- PHP — synchronous (`Guzzle`); the server adapter runs under
  `react/http` only if streaming/SSE is needed for `mpp/session`.
- Ruby — synchronous + `faraday`; `async` gem if `mpp/session`
  needs streaming.
- JVM (Java/Kotlin) — `CompletableFuture` (Java) or `kotlinx.coroutines`
  (Kotlin); `OkHttp` HTTP client.
- Swift — Swift Concurrency (`async/await`).

The server-side **charge** intent is fundamentally synchronous (one
HTTP round-trip; one optional RPC call). Only **session** with metered
streaming forces a true async runtime — see
`rust/src/client/http_stream.rs`.

## Memory & concurrency safety

- Rust — `Arc<dyn Store>` for sharing the replay store across handlers;
  `Mutex` for in-memory state.
- Go — `sync.Map` (or `sync.Mutex` + `map`) for the in-memory store.
- Python / TS / Lua / PHP / Ruby — a thread-safe dict / hash. The
  in-memory store is a fallback for development; production users
  plug a Redis / DynamoDB / Postgres adapter.

## Doc comments

Every public type and function carries a one-line doc comment. The
Rust crate is the reference (`pub fn`/`pub struct` items in
`rust/src/lib.rs` all have a `///` summary). Multi-paragraph doc
comments are fine where they explain a non-obvious invariant — see
`rust/src/protocol/intents/session.rs:71-78` for an example.

## Forbidden in committed artifacts

- Emoji in code, commits, README, or docs (the reference repo has no
  emoji and the user has explicit "no emoji unless asked" policy).
- "Generated by Claude" / `claude.ai/code` URLs / Anthropic model
  identifiers in code, commits, PR bodies, or comments.
- TODO comments without an issue link.
- Skipped tests without a documented reason and a re-enable ticket.
- `unsafe` (Rust) without a SAFETY comment.

## Things to pay attention to

- **Public surface stays minimal.** The Rust crate re-exports a
  flat list from `lib.rs` (60-some items). Mirror that list verbatim;
  do not export internal helpers ad-hoc. New consumers should be able
  to switch between languages by changing the import prefix only.
- **`Default` everywhere it makes sense.** `Config::default()`,
  `ChargeOptions::default()`, `ChargeRequest::default()` — see
  `rust/src/server/charge.rs:94`. Default values keep the language's
  builder ergonomics consistent.
- **Builder methods are short.** `OpenPayload::push()`,
  `OpenPayload::pull()`, `OpenPayload::with_transaction()`,
  `OpenPayload::with_init_tx()` — see
  `rust/src/protocol/intents/session.rs:318-455`. Mirror this
  fluent style in the target language (or its equivalent — Python
  keyword arguments, Go option functions, TS object literal +
  `as const`).
