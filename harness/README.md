# PayKit cross-language harness

This directory is PayKit's **conformance and interop test harness**. PayKit
ships the same two payment protocols — **MPP** and **x402** — in many languages
(TypeScript, Rust, Go, Python, Ruby, Lua, Swift, Kotlin, PHP) over a shared
on-chain Solana payment-channels program. The harness exists to prove those
independent implementations actually agree with each other and with the
deployed program, so a change in one SDK (or the program) can't silently break
another.

It catches three classes of regression:

1. **Protocol divergence** — one SDK encodes a challenge / credential / wire
   message differently than another.
2. **Interop breakage** — language A's client can no longer pay language B's
   server.
3. **Settlement regressions** — a payment is accepted off-chain but the
   settlement transaction is rejected *on-chain* (e.g. a wrong treasury account,
   an expired voucher, a malformed address-lookup-table). This class is the
   reason the on-chain tier (below) exists: it only surfaces when the real
   program executes.

---

## Architecture

The harness has **two verification tiers** plus a **conformance-vector** layer.

### 1. Structural cross-language interop (default)

`test/e2e.test.ts`, `test/x402-exact.e2e.test.ts`,
`test/cross-server-scenarios.test.ts`.

Each language ships a thin **process adapter** (a client and/or server). The
Vitest harness boots an in-process Surfpool validator, funds test wallets,
starts a server adapter, runs a client adapter against it, then **fetches the
settled transaction from Surfpool and asserts its structure** — the expected SPL
`transferChecked` instructions, split amounts, idempotent ATA-creation
instructions, memos, and recipient/split balance deltas — and fails on
unexpected extra transfers.

This tier is fast and broad, but it verifies the **shape of the transaction
bytes**, not the result of executing the on-chain program.

### 2. On-chain settlement E2E

`test/onchain.e2e.test.ts`, `src/onchain/surfnet.ts`.

Boots a Surfpool that **forks mainnet-beta** (via `@solana/surfpool`) and streams
the live programs — payment-channels (`CHNLx…`) and subscriptions (`De1eg…`) —
so settlement transactions **actually execute the deployed program**. It drives
the real pay-kit client/server and asserts the settlement **confirms on-chain**
(a settlement failure surfaces as a re-challenged `402`). This is what catches
treasury / voucher / ALT failures the structural tier cannot see.

Run with `pnpm test:onchain`. Network-gated (see Limitations).

### 3. Conformance vectors

`test/conformance.test.ts`, `src/protocol/`, `vectors/`, `src/canonical-codes.ts`.

Per-SDK runners (`runners/<lang>.json`) replay shared vectors (canonical JSON,
wire bytes, frozen voucher preimages, error-code classification) and assert
every SDK produces byte-identical output. No validator required.

### Process adapter contract

Each adapter is a standalone process launched by `src/process.ts`. It is
configured entirely through environment variables and reports machine-readable
status on stdout as newline-delimited JSON. **stdout must contain only JSON
protocol messages; all diagnostics go to stderr** so the harness can parse
stdout deterministically.

**Server adapter** — starts an HTTP server on `127.0.0.1`, prints `ready` once
it can accept requests, serves the scenario resource path, and protects it with
the payment flow:

```json
{"type":"ready","implementation":"typescript","role":"server","port":3000}
```

**Client adapter** — receives the target URL, pays it, prints one `result`:

```json
{"type":"result","implementation":"typescript","role":"client","ok":true,"status":200,
 "responseHeaders":{"x-fixture-settlement":"…"},"responseBody":{"ok":true},"settlement":"…"}
```

Adapters stay thin: read the harness env, route requests through the language
SDK, return HTTP responses. **The harness owns the assertions** (status,
headers, body, balances, settled-transaction shape / on-chain confirmation) — a
server adapter must not re-encode scenario expectations.

### Layout

```
src/
  artifacts.ts       native/JVM build targets and prebuilt command resolution
  ci-matrix.ts       generated MPP charge shards and exact-case coverage checks
  contracts.ts        canonical scenario values (amounts, splits, expected status)
  implementations.ts  registry of language adapters (client / server / both)
  process.ts          process spawning + JSON protocol parsing
  intents/            scenario definitions (charge, x402-exact, session, …)
  onchain/surfnet.ts  mainnet-fork bootstrap for the on-chain tier
  protocol/           cross-SDK vector drivers + divergence matrix
test/                 vitest entrypoints (structural, on-chain, conformance)
runners/<lang>.json   per-SDK conformance runner configs
<lang>-{client,server}/  per-language process adapters
```

---

## Methodology

- **Scenarios are data.** Canonical values live in `src/contracts.ts` /
  `src/intents/`; adapters never hard-code them. The harness generates the
  client×server matrix from the active scenario set and asserts centrally.
- **Generated MPP charge matrix.** CI runs every eligible charge client/server
  pair, including same-language pairs. The adapter registry and scenario
  allowlists determine coverage; job-name filters do not. The matrix planner
  rejects unknown adapters and missing toolchain mappings. Other intents retain
  their existing focused jobs.
- **Replay belongs to the shared runner.** For `charge-idempotent-resubmit`,
  the runner captures the credential through a loopback proxy while the real
  client pays the real server, then resubmits it without the client's automatic
  payment retry. Every charge client can drive this check. The first response
  must be 200; the replay must be 402 with `signature_consumed`.
- **Assigned cases must run.** Generated shards set `HARNESS_STRICT_SHARD=1`.
  A selected scenario with no eligible pair is an error, even if another
  shard could run it. Local broad selections may still skip ineligible pairs.
- **Structural first, on-chain for settlement.** The structural tier gives fast,
  broad interop coverage; the on-chain tier is reserved for the schemes whose
  correctness depends on program execution.
- **Environment in, JSON out.** Adapters are language-agnostic processes, so a
  new language joins by implementing the contract, registering its adapter,
  and declaring its CI toolchain requirements.

### Shared environment (selected)

`MPP_HARNESS_RPC_URL`, `MPP_HARNESS_NETWORK`, `MPP_HARNESS_MINT`,
`MPP_HARNESS_PRICE`, `MPP_HARNESS_SECRET_KEY`, `MPP_HARNESS_CLIENT_SECRET_KEY`,
`MPP_HARNESS_FEE_PAYER_SECRET_KEY`, `MPP_HARNESS_PAY_TO`,
`MPP_HARNESS_TARGET_URL` (client). x402 uses the parallel `X402_HARNESS_*` set.
Full list and the canonical integer amounts live in `src/contracts.ts`.

---

## Coverage matrix

Protocols × schemes that exist:

- **MPP**: `charge` (incl. multi-recipient split → `distribute`), `session`,
  `subscription`
- **x402**: `exact`, `upto`, `batch-settlement`

What the harness exercises today:

| Scheme | Structural interop | On-chain settlement |
| --- | --- | --- |
| MPP `charge` (+ split) | TS, Rust, Go, Python, PHP, Ruby, Lua (per matrix) | ✅ (charge) |
| x402 `exact` | TS, Rust (+ adapters as they land) | ✅ |
| x402 `upto` | — | ✅ (TS/pay-kit) |
| MPP `session` | Python (limited) | — |
| MPP `subscription` | — | — |
| x402 `batch-settlement` | — | — |

**Known gaps** (tracked, not yet covered):

- x402 `upto` / `batch-settlement` clients in Go and Python (Rust + TS only).
- MPP `subscription` outside Rust (needs plan bootstrap).
- MPP `session` servers outside Python/Rust.

Per-language on-chain coverage lands by registering process adapters for these
schemes against the same mainnet-fork bootstrap in `src/onchain/surfnet.ts`.

---

## Limitations

- **The structural tier does not execute the program.** It asserts transaction
  byte-shape and balance deltas, not the result of running the payment-channels
  program. Settlement-class bugs (treasury ATA, voucher expiry, ALT guard) are
  invisible to it — they only fail when the program runs. That is precisely the
  gap the on-chain tier fills, and historically why such bugs reached the
  playground undetected.
- **The on-chain tier needs a program-capable validator.** It requires
  `@solana/surfpool` **≥ 1.4**; the embedded VM in `surfpool-sdk` 1.2 rejects the
  deployed program build with `unsupported BPF instruction`. It is also
  **network-gated** — surfpool forks from a mainnet datasource RPC
  (`SURFPOOL_DATASOURCE_RPC_URL`, default public mainnet) — so it runs behind
  `HARNESS_ONCHAIN=1` (its own `onchain` CI job supplies the datasource secret).
  It is isolated from the base typecheck/vitest
  config (`tsconfig.onchain.json` / `vitest.onchain.config.ts`) because it
  imports `@solana/pay-kit`, a `file:` dep built separately from `@solana/mpp`.
- **Treasury owner is pinned to the deployed (mainnet-build) program.** The
  on-chain tier asserts against `ATA(Cs2zdf…, mint)`; a localnet-build program
  with a different `TREASURY_OWNER` would not match.
- **Coverage follows declared capabilities.** The generated MPP charge matrix
  covers registered adapters and scenario allowlists, not every public framework
  integration. Its replay assertion checks HTTP rejection, not application
  side-effect counts. Other intents still use focused CI matrices.
- **Surfpool ≠ a real cluster.** Forking approximates mainnet feature flags and
  account state; it is not a substitute for devnet/mainnet integration on the
  real network.

---

## Goals

- Prove cross-SDK protocol agreement (encoders, challenges, credentials, error
  codes) with byte-level vectors.
- Prove interop: any enabled client can pay any enabled server for a scheme both
  support.
- Prove **on-chain settlement** for program-backed schemes, so a payment that is
  accepted off-chain is one that actually settles.
- Make adding a language cheap: implement the process-adapter contract, register
  it, done.
- Keep CI coverage explicit and deterministic (generated shards; pure-JSON adapter I/O).

## Non-goals

- Not a load/performance/soak benchmark.
- Not a replacement for each SDK's own unit/integration tests — it tests
  *agreement and settlement*, not internal correctness.
- Not a deploy/release pipeline, and not a devnet/mainnet integration suite
  (the on-chain tier forks; it does not transact on a public cluster).
- Not a fuzzer — scenarios are curated, not randomly generated.
- The on-chain tier does not aim to run in every PR; it is a targeted
  settlement gate, not part of the default smoke matrix.

---

## Running

From this directory:

```bash
pnpm install --frozen-lockfile
pnpm test                      # structural + conformance (default matrix)
pnpm test:onchain              # on-chain settlement tier (HARNESS_ONCHAIN=1)
pnpm typecheck                 # base typecheck (excludes the on-chain suite)
pnpm typecheck:onchain         # on-chain suite typecheck (needs pay-kit built)
```

`@solana/mpp` (and, for the on-chain tier, `@solana/pay-kit`) are local `file:`
dependencies, so build them before installing the harness:

```bash
cd ../typescript && pnpm --filter @solana/mpp build   # + pay-kit for on-chain
cd ../harness && pnpm install --force --frozen-lockfile
```

Filter the matrix with env vars:

```bash
MPP_HARNESS_CLIENTS=typescript,rust MPP_HARNESS_SERVERS=rust pnpm test
MPP_HARNESS_INTENTS=charge MPP_HARNESS_SCENARIOS=charge-basic,charge-split-ata pnpm test
X402_HARNESS_MATRIX=1 pnpm test x402-exact.e2e.test.ts
X402_HARNESS_CROSS_SERVER=1 pnpm test cross-server-scenarios.test.ts
SURFPOOL_DATASOURCE_RPC_URL=<mainnet-rpc> pnpm test:onchain
```

### MPP charge CI coverage

`.github/workflows/mpp-matrix.yml` generates its jobs from the adapter registry
and charge scenarios. Inspect the plan or run the fast planning tests:

```bash
pnpm exec tsx emit-ci-matrix.ts
pnpm exec vitest run test/ci-matrix.test.ts test/replay.test.ts test/guards.test.ts
```

Each shard carries its exact case keys in `MPP_HARNESS_EXPECTED_CASES`. The e2e
runner checks both registration and execution against that set. CI does not use
`--testNamePattern`; scenario selection comes from the generated shard.

The workflow uses `fail-fast: false` so one failing SDK does not cancel coverage
of the others. The final **MPP charge coverage** job requires planning and every
shard to succeed; use that stable check name for branch protection.

### Build once, execute the artifacts

Each matrix workflow builds `@solana/mpp` once and publishes its portable `dist`.
Native producers build the union of required adapters once per OS/architecture,
then publish tar archives that preserve executable permissions. Go protocol aliases
reuse the same binary; Kotlin artifacts include the installed distribution's JARs.
The legacy harness also packages its compiled conformance runners.

Test jobs download these outputs and set `HARNESS_PREBUILT_DIR`. They execute the
binaries directly: no `cargo run`, `go run`, `swift run`, or Gradle payment-adapter
builds inside a test leg. Missing or unclassified artifacts fail explicitly rather
than falling back to a compiler. Cargo caches accelerate producers but are never
treated as evidence that an executable is ready.

Without `HARNESS_PREBUILT_DIR`, local developer commands retain their build-on-demand
behavior. To exercise packaged Go adapters locally:

```bash
node --import tsx build-adapters.ts --clients go --servers go --out ../.harness-artifacts
HARNESS_PREBUILT_DIR="$PWD/../.harness-artifacts" \
  MPP_HARNESS_CLIENTS=go MPP_HARNESS_SERVERS=go \
  MPP_HARNESS_SCENARIOS=charge-idempotent-resubmit pnpm test test/e2e.test.ts
```

Use `--conformance swift,kotlin` to package those runners when their toolchains are
available. Compilation is shared within each workflow run; independent language
unit-test workflows retain their own build environments.

---

## Adding an implementation

1. Write a process adapter (client and/or server) for the language.
2. Register it in `src/implementations.ts` (`client`, `server`, or both) under
   the intents it supports.
3. Keep the adapter command relative to `harness`; emit only `ready` / `result`
   JSON on stdout.
4. Validate a focused slice before enabling by default:
   ```bash
   MPP_HARNESS_CLIENTS=<id> MPP_HARNESS_SERVERS=rust pnpm test
   MPP_HARNESS_CLIENTS=rust MPP_HARNESS_SERVERS=<id> pnpm test
   ```
5. Add its toolchain mapping in `src/ci-matrix.ts` and, for a new language, its
   setup in `.github/workflows/mpp-matrix.yml`. Run the planning tests and inspect
   the emitted matrix. Registered charge adapters join CI regardless of their
   local `enabled` default; do not remove failing cases to make a shard green.
