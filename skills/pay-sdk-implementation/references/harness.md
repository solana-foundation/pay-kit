# Harness adapter

Cross-language compatibility is enforced by the TypeScript/Vitest harness
at `mpp-sdk/harness`. Read its README first
(`harness/README.md`) — that is the contract; this file summarizes
the bits that bite when adding a new language.

## What you must build

A new language ships **two** adapters that conform to the same contract:

1. **Client adapter** — accepts a `MPP_HARNESS_TARGET_URL`, pays it,
   emits one `result` JSON message on stdout, then exits.
2. **Server adapter** — listens on `127.0.0.1:<port>`, exposes the
   scenario's `resourcePath` protected by an MPP `charge` challenge,
   emits one `ready` JSON message on stdout, then serves.

Reference adapters:

- `rust/crates/mpp/src/bin/harness_client.rs` (94 lines — copy it).
- `rust/crates/mpp/src/bin/harness_server.rs` (317 lines — copy it).
- `harness/rust-client/` — Cargo manifest wrapper used by the
  harness command.

## The contract (verbatim from `harness/README.md`)

### Server `ready` message

```json
{"type":"ready","implementation":"<id>","role":"server","port":3001}
```

Fields:

- `type`: `"ready"`
- `implementation`: stable id (matches `harness/src/implementations.ts`)
- `role`: `"server"`
- `port`: local TCP port the protected resource is served on

The server must:

- Expose the shared resource path from `harnessScenario.resourcePath`
- Protect it with the MPP `charge` flow
- Return a successful JSON body after payment
- Include the `harnessScenario.settlementHeader` header on success

Keep server adapters thin. A new server adapter should only spin up the
expected endpoint, translate environment variables into the language SDK's
server configuration, and return HTTP responses. It should not duplicate
scenario expectations. The canonical TypeScript/Vitest harness owns the
assertions: status, response body, recipient/split balance deltas, and the
settled Surfpool transaction shape.

### Client `result` message

```json
{
  "type": "result",
  "implementation": "<id>",
  "role": "client",
  "ok": true,
  "status": 200,
  "responseHeaders": { "x-fixture-settlement": "..." },
  "responseBody": { "ok": true },
  "settlement": "..."
}
```

Required: `type`, `implementation`, `role`, `ok`, `status`,
`responseHeaders`, `responseBody`. `settlement` is recommended.

### Stdout discipline

**Stdout is the message channel — write nothing else there.** All logs,
diagnostics, panics, framework chatter go to stderr. If the adapter
emits a stray line on stdout, the harness fails JSON parsing and
mis-attributes the failure.

In Rust this means `tracing` defaults are fine because they go to
stderr; in Python, configure logging to stderr explicitly; in Go,
default `log.Print` goes to stderr which is correct.

## Environment variables

The harness exports these to every adapter run:

| Var | Used by | Meaning |
|---|---|---|
| `MPP_HARNESS_RPC_URL` | both | Surfpool RPC URL (localhost:8899) |
| `MPP_HARNESS_NETWORK` | both | `localnet` |
| `MPP_HARNESS_MINT` | both | SPL mint used by the scenario |
| `MPP_HARNESS_PRICE` | both | display price (decimal string, e.g. `"0.001"`) |
| `MPP_HARNESS_SECRET_KEY` | server | deterministic HMAC secret |
| `MPP_HARNESS_CLIENT_SECRET_KEY` | client | JSON array of bytes (Solana keypair) |
| `MPP_HARNESS_FEE_PAYER_SECRET_KEY` | server | JSON array of bytes |
| `MPP_HARNESS_PAY_TO` | server | expected recipient pubkey |
| `MPP_HARNESS_TARGET_URL` | client | URL to pay |
| `MPP_HARNESS_REPLAY_SOURCE_PATH` | server | optional cheaper source route (cross-route replay test) |
| `MPP_HARNESS_REPLAY_SOURCE_PRICE` | server | optional source route price |
| `MPP_HARNESS_REPLAY_SOURCE_AMOUNT` | server | optional source route amount |

Hard rule: secret keys are JSON arrays of bytes (the Solana canonical
keypair-file format). Parse them with the language's JSON lib, not
base58 — the harness does not encode them in base58.

## Registering the adapter

Add an entry to `harness/src/implementations.ts` — one each for
client and server:

```ts
export const clientImplementations: ImplementationDefinition[] = [
  // ...
  {
    id: "<lang>",
    label: "<Language> HTTP client",
    role: "client",
    command: ["sh", "-c", "cd <lang>-client && <run-cmd>"],
    enabled: isEnabled("<lang>", "MPP_HARNESS_CLIENTS", false),
  },
];

export const serverImplementations: ImplementationDefinition[] = [
  // ...
  {
    id: "<lang>",
    label: "<Language> HTTP server",
    role: "server",
    command: [
      // build-then-run, or single command per language idioms
    ],
    enabled: isEnabled("<lang>", "MPP_HARNESS_SERVERS", false),
  },
];
```

Default `enabled: false`. Only flip to `true` once the focused matrix
below passes locally.

Then drop an adapter wrapper in `harness/<lang>-client/` with
whatever scaffold the language needs (e.g. a `Cargo.toml` that
path-depends on `../../<lang>`, or a `package.json` with a single
`start` script). The harness command is relative to `harness`.

## Focused matrix command

Before enabling the implementation by default, run:

```bash
# new client against the Rust server
MPP_HARNESS_CLIENTS=<lang> MPP_HARNESS_SERVERS=rust pnpm test

# Rust client against the new server
MPP_HARNESS_CLIENTS=rust MPP_HARNESS_SERVERS=<lang> pnpm test

# self-pair
MPP_HARNESS_CLIENTS=<lang> MPP_HARNESS_SERVERS=<lang> pnpm test
```

Add corresponding `Run <lang> client harness smoke` /
`Run <lang> server harness smoke` / `Run <lang> end-to-end harness smoke`
steps to the `harness` job in `.github/workflows/ci.yml`. The Rust steps
in that file are the pattern.

## Things to pay attention to

- **`responseHeaders` is a flat string-keyed object**, not an array of
  `[k, v]` tuples. Headers with multiple values are joined per the
  language's HTTP client behavior; if the client receives multiple
  `WWW-Authenticate` headers, use `parse_www_authenticate_all` (see
  `rust/crates/mpp/src/bin/harness_client.rs:22-32`) to handle them — do not
  rely on a single header.
- **`settlement` is optional** but the harness expects it whenever
  the server returns the `harnessScenario.settlementHeader` header.
  Surface it; don't omit.
- **The replay-source env vars are optional**. The harness uses them to
  test cross-route replay: it asks your server to set up a cheaper
  route alongside the protected one, then attacks the protected
  route with a credential issued for the cheap one. Your server must
  reject it — see `verify_credential_with_expected` in
  `rust/crates/mpp/src/bin/harness_server.rs` for the wiring.
- **Build first, then run** in the harness command if your language
  compiles. Rust uses `cargo run` (which compiles on demand); Go uses
  `go run`. Avoid double-build paths in CI by reusing the language's
  cache directory across jobs.
- **Surfpool cheatcodes** (e.g. `surfnet_setAccount`,
  `surfnet_setTokenAccount`) are JSON-RPC methods on the Surfpool
  endpoint. The server adapter uses them to fund the recipient's
  token account before serving — see
  `rust/crates/mpp/src/bin/harness_server.rs` and
  `rust/examples/payment_link_server.rs:160-186` for the pattern.
- **Expectations are centralized.** For successful charge scenarios,
  the harness fetches the settlement signature from Surfpool and
  verifies the resulting transaction includes expected SPL
  `transferChecked` instructions, split amounts, required idempotent
  ATA creation instructions, and memos. It also fails on unexpected
  extra `transferChecked` instructions for the scenario mint. Do not
  re-implement those checks in every language adapter.
- **Don't pin a parallel Solana SDK** in the harness adapter. Path-
  depend on your main package and reuse its primitives.
