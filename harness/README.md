# MPP interop tests

This directory contains the cross-language MPP interoperability tests.

The active interop layer is the TypeScript/Vitest process harness in `src/`
and `test/e2e.test.ts`. This is the adapter contract new language
implementations should target.

## Process adapter contract

Each adapter is a standalone process launched by `src/process.ts`. It receives configuration through environment variables and reports machine-readable status on stdout as newline-delimited JSON.

Adapter stdout must contain only JSON protocol messages. Diagnostic logs should go to stderr so the harness can parse stdout deterministically.

### Server adapters

A server adapter starts an HTTP server on `127.0.0.1` and prints a `ready` message once it can accept requests:

```json
{"type":"ready","implementation":"typescript","role":"server","port":3000}
```

Required fields:

- `type`: `"ready"`
- `implementation`: stable implementation id from `src/implementations.ts`
- `role`: `"server"`
- `port`: local TCP port where the protected resource is served

The server must expose the shared scenario resource path from
`interopScenario.resourcePath` and protect it with the MPP `charge` flow. It
should return a successful JSON response after payment and include the
settlement header named by `interopScenario.settlementHeader`.

Server adapters should stay thin: read the harness environment, spin up the
expected endpoint, route requests through the language SDK server, and return
HTTP responses. Do not duplicate scenario expectations in each server adapter.
The Vitest harness is responsible for asserting status, response body,
recipient/split balance deltas, and the settled transaction shape in Surfpool.

### Client adapters

A client adapter receives the target URL in `MPP_INTEROP_TARGET_URL`, pays it, and prints one `result` message:

```json
{
  "type": "result",
  "implementation": "typescript",
  "role": "client",
  "ok": true,
  "status": 200,
  "responseHeaders": {"x-fixture-settlement": "..."},
  "responseBody": {"ok": true},
  "settlement": "..."
}
```

Required fields:

- `type`: `"result"`
- `implementation`: stable implementation id from `src/implementations.ts`
- `role`: `"client"`
- `ok`: whether the paid request succeeded
- `status`: final HTTP status
- `responseHeaders`: final response headers as a plain object
- `responseBody`: parsed final response body

The `settlement` field is optional, but clients should populate it when the implementation exposes settlement details.

## Shared environment

The Vitest harness prepares Surfpool state and passes these variables to each adapter:

- `MPP_INTEROP_RPC_URL`: local Surfpool RPC URL
- `MPP_INTEROP_NETWORK`: network name, currently `localnet`
- `MPP_INTEROP_MINT`: SPL mint used by the scenario
- `MPP_INTEROP_PRICE`: display price
- `MPP_INTEROP_SECRET_KEY`: deterministic server secret
- `MPP_INTEROP_CLIENT_SECRET_KEY`: JSON array for the client keypair
- `MPP_INTEROP_FEE_PAYER_SECRET_KEY`: JSON array for the server fee payer keypair
- `MPP_INTEROP_PAY_TO`: expected recipient public key
- `MPP_INTEROP_TARGET_URL`: client-only target URL
- `MPP_INTEROP_REPLAY_SOURCE_PATH`: optional cheaper source route for cross-route replay tests
- `MPP_INTEROP_REPLAY_SOURCE_PRICE`: optional source route display price
- `MPP_INTEROP_REPLAY_SOURCE_AMOUNT`: optional source route integer amount

The canonical scenario values, including integer amounts, split recipients, and
expected success/failure status, live in `src/contracts.ts`.

## Adding an implementation

1. Add a process adapter for the language.
2. Register it in `src/implementations.ts` as a client, server, or both.
3. Keep the adapter command relative to `harness`.
4. Make stdout emit only the `ready` or `result` JSON message.
5. Run a focused matrix before enabling it by default:

```bash
MPP_INTEROP_CLIENTS=<id> MPP_INTEROP_SERVERS=rust pnpm test
MPP_INTEROP_CLIENTS=rust MPP_INTEROP_SERVERS=<id> pnpm test
```

Enable the implementation by default only after the focused matrix is stable.

## Matrix strategy

The harness can run a full client/server cross-product, but CI should keep the
default smoke matrix small and intentional. Rust is the reference implementation
for the current CI gate:

- every enabled client should pass against the Rust server
- the Rust client should pass against every enabled server

This hub-and-spoke shape catches regressions in both directions without running
every implementation against every other implementation on every pull request.
Run the full cross-product locally when a protocol-level change needs broader
coverage.

Use these environment variables to filter the active matrix:

- `MPP_INTEROP_CLIENTS=typescript,rust`
- `MPP_INTEROP_SERVERS=typescript,rust`
- `MPP_INTEROP_INTENTS=charge`
- `MPP_INTEROP_SCENARIOS=charge-basic,charge-split-ata,charge-network-mismatch,charge-cross-route-replay`

The current scenario set covers only the `charge` intent. It includes a basic
payment, a split payment that requires the server fee payer to create the split
recipient ATA, a negative network-mismatch payment, and a cross-route replay
attempt where a credential issued for a cheaper route is replayed against a
more expensive route. For successful charge scenarios, the harness fetches the
settlement signature from Surfpool and centrally asserts the resulting
transaction includes the expected SPL `transferChecked` instructions, split
amounts, required idempotent ATA creation instructions, and memos. It also
fails when the transaction contains unexpected extra `transferChecked`
instructions for the scenario mint. Scenarios can restrict the clients or
servers they run against when an adapter does not yet report a structured
failure for that negative case. Selecting `session` or `subscription` currently
fails fast with a clear unsupported-intent error. Future coverage for those
intents should add explicit scenarios behind the same selector instead of
widening the default CI matrix implicitly.

## Running

From this directory:

```bash
pnpm install --frozen-lockfile
pnpm test
```

If the TypeScript adapter cannot resolve `@solana/mpp/client` or
`@solana/mpp/server`, rebuild the local package and refresh the interop package
install:

```bash
cd ../typescript
pnpm --filter @solana/mpp build

cd ../harness
pnpm install --force --frozen-lockfile
pnpm test
```

`@solana/mpp` is installed from a local `file:` dependency, so
`harness` needs to install after the TypeScript package has produced its
`dist` files.

The harness starts Surfpool through `start-surfnet-proxy.mjs`, funds the test
accounts, starts each enabled server adapter, runs each enabled client adapter
against it, verifies recipient/split balance deltas, and verifies the settled
transaction shape for successful charge scenarios.
