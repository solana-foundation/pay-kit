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

### 1. Interop against the Rust reference (`pkc run --tier interop`)

`rust/crates/conformance/src/interop/` (scenarios, adapters, fault proxy,
settlement assertions), `expectations/*.toml` (`capabilities.interop`).

Each language ships a thin **process adapter** (a client and/or server).
`pkc` starts one local Surfpool per run (surfpool-sdk, offline, clock-driven
blocks), deploys the scenario mints and the payment-channels program, and for
every case gives fresh keypairs, starts the server adapter, routes the client
adapter through a **fault proxy**, then **fetches the settled transaction and
asserts its structure** in Rust: the expected SPL `transferChecked` set (or
System transfer), split amounts, idempotent ATA creation, memos, no extra
transfers, the upto `settle_and_seal` + `distribute` shape, balance deltas,
canonical codes on every 402, and exactly-once settlement on resubmit.

Every case pairs an SDK with the Rust reference: its client against the Rust
server, the Rust client against its server, Rust against Rust as the control.
Keys are `interop/<scenario>/<client>/<server>`; claims are
`<protocol>:<scheme>:<role>`, reconciled exactly against both SDKs' files
(an entry lives on the side the gap belongs to). The proxy also injects the
faults: idempotent resubmit and cross-server portability (capture and
replay), cross-route replay (the credential presented to another route),
wrong amount and wrong recipient (the credential's transaction rewritten and
re-signed, against every server), and an expired, wrong-network, over-asking
or mis-signed challenge (against every client).

```bash
cd rust
cargo run -q -p paykit-conformance --features interop --bin pkc -- run --tier interop --sdk go,rust --require
cargo run -q -p paykit-conformance --features interop --bin pkc -- run --tier interop --shard python --require
cargo run -q -p paykit-conformance --features interop --bin pkc -- run --tier interop --case charge-basic/rust/php
cargo run -q -p paykit-conformance --bin pkc -- plan --tier interop          # shards; --write regenerates the table
```

x402 `upto` needs the localnet payment-channels build: `--program-so` or
`PAYMENT_CHANNELS_PROGRAM_SO` (`.github/actions/build-payment-channels`).
Native adapters (Rust, Go, Swift, Kotlin) are compiled once per run into
`rust/target/pkc-adapters` (or `pkc adapters build --shard <sdk> --out DIR`
plus `--prebuilt DIR`).

This tier verifies transaction structure, not the result of executing the
payment-channels program on mainnet state; that is the on-chain tier.

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

`pkc run` (`rust/crates/conformance`), `vectors/`, `expectations/`,
`runners/<lang>.json`; the mpp-tools protocol and flow suites stay in
`test/protocol-conformance.test.ts` and `test/flow-conformance.test.ts`.

Every SDK ships one **testee** (`runners/<lang>.json`) that `pkc` drives over
the vectors `pkc fill` generates from the Rust kit: canonical JSON, wire bytes,
voucher preimages, charge and x402 builds and verifies, reject codes. No
validator and no network: each vector's chain state is served by a fixture
JSON-RPC whose URL the testee receives as `input.rpcUrl`.

```bash
cd rust
cargo run -q -p paykit-conformance --bin pkc -- run --sdk python --tier offline   # one SDK, seconds
cargo run -q -p paykit-conformance --bin pkc -- run --sdk all --tier offline --require
cargo run -q -p paykit-conformance --bin pkc -- next --sdk python                  # smallest failing class
cargo run -q -p paykit-conformance --bin pkc -- case run --sdk python <vector-id>
cargo run -q -p paykit-conformance --bin pkc -- case show <vector-id>
cargo run -q -p paykit-conformance --bin pkc -- run --sdk python --diff-expectations
cargo run -q -p paykit-conformance --bin pkc -- run --cross                         # client x server matrix
cargo run -q -p paykit-conformance --bin pkc -- help
```

`pkc` judges every result itself (outcome, `rejectCode`, exact bytes, x402
envelope shape, transaction shape) and, for every accepted build, decodes the
built transaction, runs the Rust kit's verifier on it against the vector's
request and compares its instruction multiset (program, set of accounts, data;
signatures excluded, ordering free) with the kit's own build of the same case.
It reconciles against `expectations/<lang>.toml` exactly in both directions and
writes `results/<lang>.json`, `results/<lang>.failures.json` (every failure
with the requirement, mutation, decoded diff, Rust reference, stderr and replay
command), `results/junit-<lang>.xml` and `results/<lang>/builds/`. `--require`
(or `HARNESS_REQUIRE=1`, set in CI) makes a run that skipped any claimed case
fail; `--discover` (or `HARNESS_EXPECTATIONS_DISCOVER=1`) runs every vector for
every SDK without judging, to seed an expectations file. `--seed N` fills a
variant corpus first (the nightly `conformance-nightly.yml` job, reported, not
gating). See [`AGENTS.md`](AGENTS.md) for the working loop.

### Testee ABI

ABI v2, the default: one long-lived process started with the manifest's
`serve` command, newline-delimited JSON on stdin and stdout, diagnostics on
stderr only.

```text
-> {"id":"1","op":"capabilities","input":{}}
<- {"id":"1","ok":true,"result":{"abi":2,"language":"go","intents":["charge","x402-exact","session"],"honoursClock":true}}
-> {"id":"2","op":"verify","input":{"id":"<vector id>","intent":"charge","mode":"verify-transaction","description":"...","input":{...,"rpcUrl":"http://127.0.0.1:..."}}}
<- {"id":"2","ok":true,"result":{"id":"<vector id>","outcome":"reject","rejectCode":"amount-mismatch","error":"..."}}
<- {"id":"3","ok":false,"error":"bad-request","detail":"..."}
```

- `op` is `capabilities`, `build`, `verify` or `canonical-bytes` (the vector's
  mode); `protocol.*` ops join when the mpp-tools suite moves to `pkc`.
- `input` is the v1 vector without its `expect` block and traceability
  metadata; `result` is exactly the v1 `RunnerResult` (`src/conformance/schema.ts`),
  validated strictly (`additionalProperties: false`). An accepted build also
  carries the built artifact: `transaction` (charge, base64 wire transaction)
  or `x402PaymentHeader` (x402, base64 header).
- `ok: false` is for testee-level errors only; an SDK reject is `ok: true` with
  `outcome: "reject"`. `outcome: "unsupported-mode"` (or a reject whose `error`
  starts with it) declares the SDK cannot express the case.
- `capabilities` must match `expectations/<lang>.toml` (`capabilities.vector`
  and `capabilities.honours_clock`), or the run fails.
- Every case has a timeout (`--timeout`, default 10 s; the first case also gets
  `--startup-timeout`). A testee that times out or exits is killed, the case
  fails with its stderr attached, and the testee restarts for the next case.
- A testee keeps no state across cases (reset per-process SDK singletons
  before each case); `--legacy` runs the manifest's one-shot `command` (one
  process per case, v1 vector on stdin, one result line on stdout) and must
  produce identical results.

`pkc scaffold --lang <python|typescript|go|ruby|php|lua> --sdk <name>` writes a
testee skeleton for this ABI, its manifest and an expectations file claiming
nothing.

### Process adapter contract

Each adapter is a standalone process launched by `pkc` (`interop/process.rs`). It is
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
  artifacts.ts        native build targets of the offline conformance runners
  contracts.ts        the adapter contract types and the TypeScript adapters' fallbacks
  expectations.ts     the TS twin of the expectations parser (protocol and flow suites)
  fixtures/typescript the TypeScript process adapters
  onchain/surfnet.ts  mainnet-fork bootstrap for the on-chain tier
  protocol/           mpp-tools protocol and flow drivers
test/                 vitest: protocol/flow conformance, on-chain, harness unit tests
runners/<lang>.json   per-SDK conformance testee (`command` one-shot, `serve` ABI v2)
expectations/         per-SDK claims, unsupported and known_failing (exact-set)
interop-plan.json     generated by `pkc plan --tier interop --write`
vectors/              filled by `pkc fill`; never edited by hand
<lang>-{client,server}/  per-language process adapters
```

---

## Methodology

- **Scenarios are data.** The interop scenarios live in
  `rust/crates/conformance/src/interop/scenarios.rs`, each with a verbatim
  spec quote checked against the pinned specs; adapters never hard-code them.
- **Rust is the reference counterparty.** No pair between two other SDKs is
  run; one honest Rust client and server, with the misbehaviour in the proxy,
  cover every SDK in the opposite role.
- **Restrictions are stated, not hidden.** A scenario limited to some adapters
  (`Participants::Only`) carries a reason: a driver knob only one adapter
  implements, the pivot side of a fault, or a policy that is not a spec rule.
  A failing SDK is a `known_failing` entry with a FINDINGS.md section, never a
  restriction.
- **Assigned cases must run.** `--require` fails a run that skipped a claimed
  case of its selection; `test/ci-coverage.test.ts` fails when a planned shard
  has no CI step.
- **Environment in, JSON out.** Adapters are language-agnostic processes, so a
  new language joins by implementing the contract, adding it to
  `interop/adapters.rs` and claiming its roles in its toml.

### Shared environment (selected)

`MPP_HARNESS_RPC_URL`, `MPP_HARNESS_NETWORK`, `MPP_HARNESS_MINT`,
`MPP_HARNESS_PRICE`, `MPP_HARNESS_SECRET_KEY`, `MPP_HARNESS_CLIENT_SECRET_KEY`,
`MPP_HARNESS_FEE_PAYER_SECRET_KEY`, `MPP_HARNESS_PAY_TO`,
`MPP_HARNESS_TARGET_URL` (client). x402 uses the parallel `X402_HARNESS_*` set.
Full list in `environment()` of `rust/crates/conformance/src/interop/runner.rs`.

---

## Coverage matrix

Protocols × schemes that exist:

- **MPP**: `charge` (incl. multi-recipient split → `distribute`), `session`,
  `subscription`
- **x402**: `exact`, `upto`, `batch-settlement`

### Offline conformance (generated)

Vectors, canonical mpp-tools protocol cases and HTTP 402 flows, per SDK.
Reconciled exactly against `expectations/<language>.toml` in CI; the table is
regenerated with `pnpm coverage` and CI fails when it is stale.

<!-- coverage:begin (generated by coverage-table.ts; do not edit) -->
| Suite | Cases | go | kotlin | lua | php | python | ruby | rust | swift | typescript |
| --- | ---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| flow | 34 | — | — | — | — | — | — | — | — | 30 · 4u |
| protocol | 91 | 91 | — | 91 | 91 | 91 | 91 | 91 | — | 91 |
| vector charge | 65 | 56 · 9k | — | 47 · 17u · 1k | 48 · 17u | 59 · 6k | 48 · 17u | 63 · 2k | 25 · 38u · 2k | 60 · 5k |
| vector session | 17 | 8 · 9u | 3 · 14u | — | — | 17 | — | 17 | 3 · 14u | 17 |
| vector x402-exact | 36 | 35 · 1k | — | 25 · 9u · 2k | 25 · 9u · 2k | 34 · 2k | 26 · 9u · 1k | 36 | 9 · 27u | 27 · 7u · 2k |

Each cell counts the cases that must pass, then `u` unsupported (declared, executed, must report unsupported) and `k` known failing (declared with tracking, executed, must fail). `—` means the SDK does not claim the suite. Source: `harness/expectations/<language>.toml`.
<!-- coverage:end -->

### Offline cross-verification (generated)

Every SDK's offline builds (`results/<sdk>/builds/`) fed to every
server-capable SDK's verifier, with no validator or network (`pkc run
--cross`). A cell counts the builds on which the server agrees with the Rust
judge. Regenerate after a full offline run; `pkc run --cross --check` fails
when the table is stale.

<!-- cross:begin (generated by `pkc run --cross`; do not edit) -->
**charge**: builds by the client SDK (rows) verified by the server SDK (columns), agreeing with the Rust judge / total.

| client \ server | go | lua | php | python | ruby | rust | typescript |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| go | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| python | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| rust | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| swift | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| typescript | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |

**x402-exact**: builds by the client SDK (rows) verified by the server SDK (columns), agreeing with the Rust judge / total.

| client \ server | go | lua | php | python | ruby | rust | typescript |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| go | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 | 7/7 · 2u |
| python | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 | 7/7 · 2u |
| rust | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 | 7/7 · 2u |
| swift | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 | 7/7 · 2u |
| typescript | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |

A server agrees with a build when it accepts what the Rust judge accepted (verifier plus instruction multiset against the kit's own build) and refuses what it refused; `u` counts builds the server reports it cannot express. Disagreements are listed in `harness/results/cross.json`.
<!-- cross:end -->

Each cell is also a case, `cross/<case>/<client>/<server>`, reconciled
against the server's `expectations/<server>.toml` (`capabilities.cross`,
`[[unsupported]]`, `[[known_failing]]`). The `cross` CI job collects every
client leg's builds and runs `pkc run --cross --require --check`: an
unlisted disagreement, a stale entry, a verifier that does not claim
`cross` or a missing client build fails it.

### Requirement traceability (generated)

Which normative spec sentences have cases, and how each SDK stands on
them, from `harness/requirements/*.toml`, the vectors and the expectations
files (`pkc report`; `pkc report --check` fails when stale). The counts
come from the same extraction as `pkc req-lint`.

<!-- traceability:begin (generated by `pkc report`; do not edit) -->
544 normative sentences in the pinned specs: 72 mapped to a requirement, 452 unmapped.

| Spec file | Normative | Mapped | Ignored | Unmapped |
| --- | ---: | ---: | ---: | ---: |
| `mpp-specs/draft-httpauth-payment-01.md` | 74 | 1 | 0 | 73 |
| `mpp-specs/draft-payment-intent-charge-00.md` | 19 | 0 | 0 | 19 |
| `mpp-specs/draft-solana-charge-00.md` | 145 | 47 | 0 | 98 |
| `mpp-specs/draft-solana-session-00.md` | 219 | 6 | 0 | 213 |
| `x402/x402-specification-v2.md` | 10 | 0 | 0 | 10 |
| `x402/scheme_exact.md` | 42 | 2 | 20 | 20 |
| `x402/scheme_exact_svm.md` | 35 | 16 | 0 | 19 |
| `x402/payment_identifier.md` | 0 | 0 | 0 | 0 |

**Requirements × SDK**: cases per requirement, and per SDK the cases it must pass, then `u` unsupported and `k` known failing; `—` means the SDK claims none of them. `*` marks `required = true` (req-lint fails if its last case goes).

| Requirement | Spec § | Cases | go | kotlin | lua | php | python | ruby | rust | swift | typescript |
| --- | --- | ---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `MPP-8a3cdc949b`* | draft-httpauth-payment-01.md § Challenge Binding | 5 | 5 | — | 5 | 5 | 5 | 5 | 5 | 5 | 5 |
| `MPP-de0815e07c`* | draft-solana-charge-00.md § Client Requirements | 1 | 1 | — | 0 · 1u | 0 · 1u | 1 | 0 · 1u | 1 | 1 | 1 |
| `MPP-51806e831a`* | draft-solana-charge-00.md § Encoding Conventions | 3 | 3 | — | 3 | 3 | 3 | 3 | 3 | 3 | 3 |
| `MPP-71198689c1`* | draft-solana-charge-00.md § Encoding Conventions | 5 | 5 | — | 5 | 5 | 5 | 5 | 5 | 5 | 5 |
| `MPP-f4eca94243`* | draft-solana-charge-00.md § Encoding Conventions | 2 | 2 | — | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| `MPP-837333ec9f`* | draft-solana-charge-00.md § Fee Payer Configuration | 1 | 1 | — | 0 · 1u | 0 · 1u | 1 | 0 · 1u | 1 | 1 | 1 |
| `MPP-b4a76cab12`* | draft-solana-charge-00.md § Fee Payer Configuration | 1 | 1 | — | 0 · 1u | 0 · 1u | 1 | 0 · 1u | 1 | 1 | 1 |
| `MPP-1180595e82`* | draft-solana-charge-00.md § Method Details | 4 | 4 | — | 4 | 4 | 4 | 4 | 4 | 0 · 4u | 4 |
| `MPP-4b02ff0c39`* | draft-solana-charge-00.md § Method Details | 2 | 2 | — | 0 · 2u | 0 · 2u | 2 | 0 · 2u | 2 | 2 | 1 · 1k |
| `MPP-5348f3f797`* | draft-solana-charge-00.md § Method Details | 1 | 1 | — | 0 · 1u | 0 · 1u | 1 | 0 · 1u | 1 | 1 | 1 |
| `MPP-58f2b1922a`* | draft-solana-charge-00.md § Method Details | 1 | 0 · 1k | — | 0 · 1u | 0 · 1u | 0 · 1k | 0 · 1u | 0 · 1k | 1 | 1 |
| `MPP-6ce505e77b`* | draft-solana-charge-00.md § Method Details | 4 | 4 | — | 4 | 4 | 4 | 4 | 4 | 0 · 4u | 4 |
| `MPP-6d81f2478f`* | draft-solana-charge-00.md § Method Details | 2 | 2 | — | 2 | 2 | 2 | 2 | 2 | 0 · 2u | 2 |
| `MPP-73af393543`* | draft-solana-charge-00.md § Method Details | 2 | 2 | — | 1 · 1u | 1 · 1u | 2 | 1 · 1u | 2 | 1 · 1u | 2 |
| `MPP-7743ae4e51`* | draft-solana-charge-00.md § Method Details | 2 | 2 | — | 0 · 2u | 0 · 2u | 2 | 0 · 2u | 2 | 2 | 2 |
| `MPP-95730a55e2`* | draft-solana-charge-00.md § Method Details | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-b134044e08`* | draft-solana-charge-00.md § Method Details | 1 | 1 | — | 0 · 1u | 0 · 1u | 1 | 0 · 1u | 1 | 1 | 1 |
| `MPP-b769615b39`* | draft-solana-charge-00.md § Method Details | 2 | 0 · 2k | — | 1 · 1u | 1 · 1u | 1 · 1k | 1 · 1u | 2 | 1 · 1u | 2 |
| `MPP-c189ef935e`* | draft-solana-charge-00.md § Method Details | 2 | 2 | — | 0 · 2u | 0 · 2u | 2 | 0 · 2u | 2 | 2 | 2 |
| `MPP-ec29292f9d`* | draft-solana-charge-00.md § Method Details | 1 | 0 · 1k | — | 0 · 1u | 0 · 1u | 0 · 1k | 0 · 1u | 1 | 0 · 1k | 0 · 1k |
| `MPP-fde6ebf8c7`* | draft-solana-charge-00.md § Method Details | 1 | 0 · 1k | — | 0 · 1u | 0 · 1u | 0 · 1k | 0 · 1u | 0 · 1k | 0 · 1k | 0 · 1k |
| `MPP-e02293d02d`* | draft-solana-charge-00.md § Native SOL | 1 | 1 | — | 0 · 1u | 0 · 1u | 1 | 0 · 1u | 1 | 1 | 1 |
| `MPP-1659a03107`* | draft-solana-charge-00.md § Native SOL Verification | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-4a77950278`* | draft-solana-charge-00.md § Native SOL Verification | 2 | 2 | — | 2 | 2 | 2 | 2 | 2 | 0 · 2u | 2 |
| `MPP-6e9ac6c31d`* | draft-solana-charge-00.md § Native SOL Verification | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-c1ed754e32`* | draft-solana-charge-00.md § Pull Mode Verification | 2 | 1 · 1k | — | 2 | 2 | 1 · 1k | 2 | 2 | 0 · 2u | 2 |
| `MPP-4f9c5997c8`* | draft-solana-charge-00.md § SPL Token Verification | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-96ba338b1e`* | draft-solana-charge-00.md § SPL Token Verification | 7 | 7 | — | 7 | 7 | 7 | 7 | 7 | 0 · 7u | 7 |
| `MPP-d90a2b66e5`* | draft-solana-charge-00.md § SPL Token Verification | 2 | 2 | — | 2 | 2 | 2 | 2 | 2 | 0 · 2u | 2 |
| `MPP-1fe20b9485`* | draft-solana-charge-00.md § SPL Tokens | 3 | 1 · 2k | — | 3 | 3 | 3 | 3 | 3 | 0 · 3u | 3 |
| `MPP-5b4687796d`* | draft-solana-charge-00.md § SPL Tokens | 1 | 0 · 1k | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-64da85f4f3`* | draft-solana-charge-00.md § SPL Tokens | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-2d30d806c0`* | draft-solana-charge-00.md § Server Requirements | 2 | 2 | — | 2 | 2 | 2 | 2 | 2 | 0 · 2u | 2 |
| `MPP-3d2ad6ef40`* | draft-solana-charge-00.md § Shared Fields | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-a6f3950ec9`* | draft-solana-charge-00.md § Shared Fields | 2 | 2 | — | 0 · 2u | 0 · 2u | 1 · 1k | 0 · 2u | 2 | 2 | 1 · 1k |
| `MPP-0399450c79`* | draft-solana-charge-00.md § Split Recipient ATA Creation | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-197d674f50`* | draft-solana-charge-00.md § Split Recipient ATA Creation | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-304370cfc4`* | draft-solana-charge-00.md § Split Recipient ATA Creation | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-438c3bfb12`* | draft-solana-charge-00.md § Split Recipient ATA Creation | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-681f5e090f`* | draft-solana-charge-00.md § Split Recipient ATA Creation | 2 | 1 · 1k | — | 2 | 2 | 2 | 2 | 2 | 0 · 2u | 2 |
| `MPP-74cf327879`* | draft-solana-charge-00.md § Split Recipient ATA Creation | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-ab401714b4`* | draft-solana-charge-00.md § Split Recipient ATA Creation | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 0 · 1k |
| `MPP-b333c50e7e`* | draft-solana-charge-00.md § Split Recipient ATA Creation | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `MPP-baa94f08cb`* | draft-solana-charge-00.md § Split Recipient ATA Creation | 2 | 0 · 2k | — | 2 | 2 | 2 | 2 | 2 | 0 · 2u | 2 |
| `MPP-d63913e921`* | draft-solana-charge-00.md § Split Recipient ATA Creation | 2 | 1 · 1k | — | 2 | 2 | 2 | 2 | 2 | 0 · 2u | 2 |
| `MPP-048617f9d7`* | draft-solana-charge-00.md § Transaction Payload Security | 5 | 5 | — | 4 · 1k | 5 | 5 | 5 | 5 | 0 · 5u | 5 |
| `MPP-1a2e7c737e`* | draft-solana-charge-00.md § Transaction Payload Security | 5 | 4 · 1k | — | 4 · 1k | 5 | 5 | 5 | 5 | 0 · 5u | 5 |
| `MPP-d5e5d796c6`* | draft-solana-charge-00.md § Transaction Payload — Pull Mode | 1 | 0 · 1k | — | 1 | 1 | 0 · 1k | 1 | 1 | 0 · 1u | 1 |
| `MPP-dc4603ccd4`* | draft-solana-session-00.md § Action: "open" | 2 | 0 · 2u | 0 · 2u | — | — | 2 | — | 2 | 0 · 2u | 2 |
| `MPP-ebee0156c7`* | draft-solana-session-00.md § Action: "voucher" | 4 | 0 · 4u | 0 · 4u | — | — | 4 | — | 4 | 0 · 4u | 4 |
| `MPP-69c0a4f95f`* | draft-solana-session-00.md § Method Details | 3 | 0 · 3u | 0 · 3u | — | — | 3 | — | 3 | 0 · 3u | 3 |
| `MPP-4acddd43ce`* | draft-solana-session-00.md § Voucher Verification | 3 | 3 | 3 | — | — | 3 | — | 3 | 3 | 3 |
| `MPP-ec9e85084d`* | draft-solana-session-00.md § Voucher Verification | 5 | 5 | 0 · 5u | — | — | 5 | — | 5 | 0 · 5u | 5 |
| `X402-f870a56d25`* | scheme_exact.md § Client-submitted (payment proof) | 17 | 17 | — | 9 · 8u | 9 · 8u | 17 | 9 · 8u | 17 | 8 · 9u | 10 · 7u |
| `X402-f45fed3f51`* | scheme_exact.md § SVM | 2 | 2 | — | 2 | 2 | 2 | 2 | 2 | 0 · 2u | 2 |
| `X402-2f0d5ef017`* | scheme_exact_svm.md § 1.4 Exactly One Matching Transfer (MUST) | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `X402-516a2d7b57`* | scheme_exact_svm.md § 1.4 Exactly One Matching Transfer (MUST) | 3 | 3 | — | 3 | 3 | 3 | 3 | 3 | 0 · 3u | 2 · 1k |
| `X402-bac6bc288a`* | scheme_exact_svm.md § 1.4 Exactly One Matching Transfer (MUST) | 3 | 3 | — | 3 | 3 | 3 | 3 | 3 | 0 · 3u | 3 |
| `X402-ee90546220`* | scheme_exact_svm.md § 1.4 Exactly One Matching Transfer (MUST) | 4 | 4 | — | 4 | 4 | 4 | 4 | 4 | 0 · 4u | 3 · 1k |
| `X402-93650bf2e3`* | scheme_exact_svm.md § 2.1 Minimal Safety Baseline (Normative MUSTs) | 3 | 3 | — | 2 · 1k | 2 · 1k | 2 · 1k | 3 | 3 | 0 · 3u | 3 |
| `X402-0ad718daab`* | scheme_exact_svm.md § 2.1.1 Fee Payer Isolation (MUST) | 1 | 1 | — | 0 · 1k | 0 · 1k | 0 · 1k | 1 | 1 | 0 · 1u | 1 |
| `X402-6708749c55`* | scheme_exact_svm.md § 2.1.1 Fee Payer Isolation (MUST) | 2 | 2 | — | 1 · 1k | 1 · 1k | 1 · 1k | 2 | 2 | 0 · 2u | 2 |
| `X402-ed41478ffe`* | scheme_exact_svm.md § 2.1.1 Fee Payer Isolation (MUST) | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `X402-985ecc1ea3`* | scheme_exact_svm.md § 2.1.3 Fee Payer Fund Safety (MUST) | 1 | 1 | — | 0 · 1k | 0 · 1k | 0 · 1k | 1 | 1 | 0 · 1u | 1 |
| `X402-27bff260c3`* | scheme_exact_svm.md § 2.1.4 Signer Set Integrity (MUST) | 1 | 0 · 1k | — | 0 · 1k | 0 · 1k | 0 · 1k | 0 · 1k | 1 | 0 · 1u | 0 · 1k |
| `X402-9b240d95a0`* | scheme_exact_svm.md § 2.1.4 Signer Set Integrity (MUST) | 1 | 0 · 1k | — | 0 · 1k | 0 · 1k | 0 · 1k | 0 · 1k | 1 | 0 · 1u | 0 · 1k |
| `X402-6b3e9350c8`* | scheme_exact_svm.md § 3.1 Path 1 — Static Layout Verification (standard wallets) | 5 | 5 | — | 0 · 5u | 0 · 5u | 5 | 0 · 5u | 5 | 5 | 3 · 2u |
| `X402-a1cf65b0f0`* | scheme_exact_svm.md § 3.1 Path 1 — Static Layout Verification (standard wallets) | 1 | 1 | — | 1 | 1 | 1 | 1 | 1 | 0 · 1u | 1 |
| `X402-a8bd75d71b`* | scheme_exact_svm.md § 3.1 Path 1 — Static Layout Verification (standard wallets) | 4 | 4 | — | 4 | 4 | 4 | 4 | 4 | 0 · 4u | 4 |
| `X402-c9a227ad88`* | scheme_exact_svm.md § 3.1 Path 1 — Static Layout Verification (standard wallets) | 3 | 3 | — | 3 | 3 | 3 | 3 | 3 | 0 · 3u | 3 |
| `X402-d5f1ded529`* | scheme_exact_svm.md § PaymentRequirements for exact | 1 | 1 | — | 0 · 1u | 0 · 1u | 1 | 0 · 1u | 1 | 1 | 1 |

<details><summary>Unmapped normative sentences by spec file and section (452)</summary>

| Spec file | Section | Normative | Mapped | Unmapped |
| --- | --- | ---: | ---: | ---: |
| `draft-httpauth-payment-01.md` | Status Codes | 2 | 0 | 2 |
| `draft-httpauth-payment-01.md` | When NOT to Return 402 | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Required Parameters | 9 | 0 | 9 |
| `draft-httpauth-payment-01.md` | Optional Parameters | 15 | 0 | 15 |
| `draft-httpauth-payment-01.md` | Challenge Binding | 2 | 1 | 1 |
| `draft-httpauth-payment-01.md` | Example Challenge Selecting an Alternate Header | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Request Body Digest Binding | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Credentials | 8 | 0 | 8 |
| `draft-httpauth-payment-01.md` | Example Credential with Alternate Header | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Receipt Status Semantics | 3 | 0 | 3 |
| `draft-httpauth-payment-01.md` | Method Identifier Format | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Client Payment Preferences | 2 | 0 | 2 |
| `draft-httpauth-payment-01.md` | Payment Method Specifications | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Core Protocol | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Custom Parameters | 2 | 0 | 2 |
| `draft-httpauth-payment-01.md` | Size Considerations | 2 | 0 | 2 |
| `draft-httpauth-payment-01.md` | Transport Security | 3 | 0 | 3 |
| `draft-httpauth-payment-01.md` | Credential Handling | 2 | 0 | 2 |
| `draft-httpauth-payment-01.md` | Challenge-Binding Secret Management | 2 | 0 | 2 |
| `draft-httpauth-payment-01.md` | Replay Protection | 2 | 0 | 2 |
| `draft-httpauth-payment-01.md` | Idempotency and Side Effects | 2 | 0 | 2 |
| `draft-httpauth-payment-01.md` | Concurrent Request Handling | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Amount Verification | 2 | 0 | 2 |
| `draft-httpauth-payment-01.md` | Privacy | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Credential Storage | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Intermediary Handling of 402 | 1 | 0 | 1 |
| `draft-httpauth-payment-01.md` | Caching | 4 | 0 | 4 |
| `draft-httpauth-payment-01.md` | Multiple Payment Options | 1 | 0 | 1 |
| `draft-payment-intent-charge-00.md` | Atomicity | 2 | 0 | 2 |
| `draft-payment-intent-charge-00.md` | Request Schema | 1 | 0 | 1 |
| `draft-payment-intent-charge-00.md` | Shared Fields | 2 | 0 | 2 |
| `draft-payment-intent-charge-00.md` | Optional Fields | 1 | 0 | 1 |
| `draft-payment-intent-charge-00.md` | Currency Formats | 1 | 0 | 1 |
| `draft-payment-intent-charge-00.md` | Method Extensions | 2 | 0 | 2 |
| `draft-payment-intent-charge-00.md` | Payload | 1 | 0 | 1 |
| `draft-payment-intent-charge-00.md` | Single-Use | 2 | 0 | 2 |
| `draft-payment-intent-charge-00.md` | Server Responsibilities | 1 | 0 | 1 |
| `draft-payment-intent-charge-00.md` | Amount Verification | 1 | 0 | 1 |
| `draft-payment-intent-charge-00.md` | Replay Protection | 3 | 0 | 3 |
| `draft-payment-intent-charge-00.md` | Transport Security | 1 | 0 | 1 |
| `draft-payment-intent-charge-00.md` | Currency Verification | 1 | 0 | 1 |
| `draft-solana-charge-00.md` | Terminology | 1 | 0 | 1 |
| `draft-solana-charge-00.md` | Intent Identifier | 1 | 0 | 1 |
| `draft-solana-charge-00.md` | Shared Fields | 7 | 2 | 5 |
| `draft-solana-charge-00.md` | Method Details | 30 | 14 | 16 |
| `draft-solana-charge-00.md` | Transaction Payload — Pull Mode | 6 | 1 | 5 |
| `draft-solana-charge-00.md` | Signature Payload — Push Mode | 2 | 0 | 2 |
| `draft-solana-charge-00.md` | Bundle Payload — Confidential Transfers | 8 | 0 | 8 |
| `draft-solana-charge-00.md` | Limitations of Push Mode | 2 | 0 | 2 |
| `draft-solana-charge-00.md` | Client-Paid Fees | 1 | 0 | 1 |
| `draft-solana-charge-00.md` | Server Requirements | 2 | 1 | 1 |
| `draft-solana-charge-00.md` | Client Requirements | 3 | 1 | 2 |
| `draft-solana-charge-00.md` | Split Recipient ATA Creation | 14 | 10 | 4 |
| `draft-solana-charge-00.md` | Confidential Transfers | 2 | 0 | 2 |
| `draft-solana-charge-00.md` | Prerequisites | 3 | 0 | 3 |
| `draft-solana-charge-00.md` | Amount Verification | 1 | 0 | 1 |
| `draft-solana-charge-00.md` | Proof Context State Accounts | 3 | 0 | 3 |
| `draft-solana-charge-00.md` | Restrictions | 4 | 0 | 4 |
| `draft-solana-charge-00.md` | Verification Procedure | 2 | 0 | 2 |
| `draft-solana-charge-00.md` | Pull Mode Verification | 2 | 1 | 1 |
| `draft-solana-charge-00.md` | Native SOL Verification | 4 | 3 | 1 |
| `draft-solana-charge-00.md` | SPL Token Verification | 4 | 3 | 1 |
| `draft-solana-charge-00.md` | Confidential Transfer Verification | 5 | 0 | 5 |
| `draft-solana-charge-00.md` | Replay Protection | 4 | 0 | 4 |
| `draft-solana-charge-00.md` | SPL Tokens | 4 | 3 | 1 |
| `draft-solana-charge-00.md` | Fee Payer Configuration | 5 | 2 | 3 |
| `draft-solana-charge-00.md` | Confirmation Requirements | 3 | 0 | 3 |
| `draft-solana-charge-00.md` | Receipt Generation | 1 | 0 | 1 |
| `draft-solana-charge-00.md` | Confidential Charge Receipt | 1 | 0 | 1 |
| `draft-solana-charge-00.md` | Error Responses | 3 | 0 | 3 |
| `draft-solana-charge-00.md` | Transport Security | 2 | 0 | 2 |
| `draft-solana-charge-00.md` | Replay Protection Considerations | 2 | 0 | 2 |
| `draft-solana-charge-00.md` | Client-Side Verification | 1 | 0 | 1 |
| `draft-solana-charge-00.md` | Fee Payer Risks | 2 | 0 | 2 |
| `draft-solana-charge-00.md` | Proof Context Rent Drain (Confidential) | 2 | 0 | 2 |
| `draft-solana-charge-00.md` | Partial Bundle Settlement (Confidential) | 1 | 0 | 1 |
| `draft-solana-charge-00.md` | Amount Privacy Scope (Confidential) | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Relationship to the Charge Intent | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Intent Identifier | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Channel Program Interface | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Channel State | 8 | 0 | 8 |
| `draft-solana-session-00.md` | open | 15 | 0 | 15 |
| `draft-solana-session-00.md` | settle | 1 | 0 | 1 |
| `draft-solana-session-00.md` | topUp | 2 | 0 | 2 |
| `draft-solana-session-00.md` | settleAndSeal | 1 | 0 | 1 |
| `draft-solana-session-00.md` | distribute | 6 | 0 | 6 |
| `draft-solana-session-00.md` | reclaim | 3 | 0 | 3 |
| `draft-solana-session-00.md` | Channel Closure | 5 | 0 | 5 |
| `draft-solana-session-00.md` | Shared Fields | 3 | 0 | 3 |
| `draft-solana-session-00.md` | Method Details | 21 | 2 | 19 |
| `draft-solana-session-00.md` | Session Bearer Proof | 10 | 0 | 10 |
| `draft-solana-session-00.md` | Action: "open" | 23 | 1 | 22 |
| `draft-solana-session-00.md` | Action: "voucher" | 4 | 1 | 3 |
| `draft-solana-session-00.md` | Action: "use" | 3 | 0 | 3 |
| `draft-solana-session-00.md` | Action: "topUp" | 3 | 0 | 3 |
| `draft-solana-session-00.md` | Action: "close" | 6 | 0 | 6 |
| `draft-solana-session-00.md` | Voucher Data | 3 | 0 | 3 |
| `draft-solana-session-00.md` | Signed Voucher | 4 | 0 | 4 |
| `draft-solana-session-00.md` | Voucher Signing | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Voucher Verification | 5 | 2 | 3 |
| `draft-solana-session-00.md` | On-Chain Voucher Verification | 5 | 0 | 5 |
| `draft-solana-session-00.md` | Canonical Preimage | 2 | 0 | 2 |
| `draft-solana-session-00.md` | Hash Algorithm | 2 | 0 | 2 |
| `draft-solana-session-00.md` | Authorized Signer | 3 | 0 | 3 |
| `draft-solana-session-00.md` | Per-Channel State | 3 | 0 | 3 |
| `draft-solana-session-00.md` | Mint Allow-List | 2 | 0 | 2 |
| `draft-solana-session-00.md` | Debit Processing | 3 | 0 | 3 |
| `draft-solana-session-00.md` | Partial Settlement | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Crash Safety | 2 | 0 | 2 |
| `draft-solana-session-00.md` | Concurrency and Idempotency | 6 | 0 | 6 |
| `draft-solana-session-00.md` | Open | 5 | 0 | 5 |
| `draft-solana-session-00.md` | Resume | 5 | 0 | 5 |
| `draft-solana-session-00.md` | TopUp | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Close (Cooperative) | 2 | 0 | 2 |
| `draft-solana-session-00.md` | Server-Initiated Idle Close | 9 | 0 | 9 |
| `draft-solana-session-00.md` | Forced Close (Client-Initiated) | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Receipt Format | 8 | 0 | 8 |
| `draft-solana-session-00.md` | Error Responses | 3 | 0 | 3 |
| `draft-solana-session-00.md` | Transport Security | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Session Bearer Proofs | 4 | 0 | 4 |
| `draft-solana-session-00.md` | Voucher Replay Protection | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Reincarnation Replay | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Open Transaction Binding | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Grace Period Security | 4 | 0 | 4 |
| `draft-solana-session-00.md` | Delegated Signer Risks | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Channel Program Trust | 1 | 0 | 1 |
| `draft-solana-session-00.md` | CPI and Program-ID Validation | 4 | 0 | 4 |
| `draft-solana-session-00.md` | Token-2022 Extension Policy | 4 | 0 | 4 |
| `draft-solana-session-00.md` | Account Ownership Validation | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Channel Exhaustion | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Clock Skew | 1 | 0 | 1 |
| `draft-solana-session-00.md` | Solana Verification Programs | 1 | 0 | 1 |
| `x402-specification-v2.md` | X402 Protocol Specification | 10 | 0 | 10 |
| `scheme_exact.md` | Asset Transfer Method Families | 1 | 0 | 1 |
| `scheme_exact.md` | Facilitator-submitted | 5 | 0 | 5 |
| `scheme_exact.md` | Client-submitted (payment proof) | 12 | 1 | 11 |
| `scheme_exact.md` | Critical Validation Requirements | 1 | 0 | 1 |
| `scheme_exact.md` | SVM | 3 | 1 | 2 |
| `scheme_exact_svm.md` | Exact Payment Scheme for Solana Virtual Machine (SVM) (exact) | 1 | 0 | 1 |
| `scheme_exact_svm.md` | PaymentRequirements for exact | 2 | 1 | 1 |
| `scheme_exact_svm.md` | 1.1 Required Payment Outcome (MUST) | 2 | 0 | 2 |
| `scheme_exact_svm.md` | 1.2 Payment Identification (MUST) | 1 | 0 | 1 |
| `scheme_exact_svm.md` | 2.1.2 Address Lookup Table Visibility (MUST) | 3 | 0 | 3 |
| `scheme_exact_svm.md` | 2.1.5 Exact Payment Verification (MUST) | 1 | 0 | 1 |
| `scheme_exact_svm.md` | 2.3 Policy Flexibility (Explicit) | 1 | 0 | 1 |
| `scheme_exact_svm.md` | 3. Reference Verification Implementation (Two-Path) | 1 | 0 | 1 |
| `scheme_exact_svm.md` | 3.2 Path 2 — Simulation-Based Smart Wallet Verification | 5 | 0 | 5 |
| `scheme_exact_svm.md` | 3.3 Path Selection (Path 1 → Path 2) | 1 | 0 | 1 |
| `scheme_exact_svm.md` | 3.4 Post-Settlement Verification (TOCTOU defense) | 2 | 0 | 2 |

</details>

Source: `harness/requirements/*.toml`, the vectors' `requirements`, `harness/expectations/<sdk>.toml`. Sentence texts and the observed outcome of the last local run per case are in `harness/results/report.json`; `pkc report --unmapped` prints the gap list.
<!-- traceability:end -->

### Interop (generated)

Every claimed client × server × scenario case, from the interop claims in
`expectations/<language>.toml` and the scenario registry
(`rust/crates/conformance/src/interop/scenarios.rs`), with the CI shard
that runs it (`pkc plan --tier interop`, also written to
`interop-plan.json`). Regenerate with `pkc plan --tier interop --write`;
CI runs `--check`, and `test/ci-coverage.test.ts` fails when a claimed
case is in no scheduled shard.

<!-- interop:begin (generated by `pkc plan --tier interop --write`; do not edit) -->
| Intent | Claimed cases | Must pass | Known failing |
| --- | ---: | ---: | ---: |
| charge | 159 | 128 | 31 |
| x402-exact | 75 | 51 | 24 |
| x402-upto | 12 | 12 | 0 |

**charge**: claimed cases per SDK as client (against the Rust server) and as server (against the Rust client); `k` known failing.

| SDK | as client | as server |
| --- | :---: | :---: |
| go | 15 · 4k | 13 · 2k |
| kotlin | 15 · 4k |  |
| lua |  | 13 · 5k |
| php |  | 13 · 4k |
| python |  | 13 |
| ruby |  | 13 |
| rust | 17 · 4k | (control) |
| swift | 15 · 4k |  |
| typescript | 19 · 4k | 13 |

**x402-exact**: claimed cases per SDK as client (against the Rust server) and as server (against the Rust client); `k` known failing.

| SDK | as client | as server |
| --- | :---: | :---: |
| go | 5 · 2k | 6 · 2k |
| kotlin | 5 · 2k |  |
| lua |  | 7 · 2k |
| php |  | 6 · 2k |
| python | 5 · 2k | 6 · 2k |
| ruby |  | 12 · 4k |
| rust | 7 · 2k | (control) |
| swift | 5 · 2k |  |
| typescript | 5 · 1k | 6 · 1k |

**x402-upto**: claimed cases per SDK as client (against the Rust server) and as server (against the Rust client); `k` known failing.

| SDK | as client | as server |
| --- | :---: | :---: |
| go | 2 | 1 |
| kotlin | 2 |  |
| python | 2 | 1 |
| rust | 2 | (control) |
| swift | 2 |  |

9 SDK shards, each one `Conformance / <sdk>` job in `.github/workflows/conformance.yml` on every pull request. Source: `harness/expectations/<language>.toml` and the scenario registry in `rust/crates/conformance/src/interop/scenarios.rs`.
<!-- interop:end -->

### On-chain settlement

| Scheme | On-chain settlement |
| --- | --- |
| MPP `charge` (+ split) | ✅ |
| x402 `exact` | ✅ |
| x402 `upto` | ✅ (TS/pay-kit) |
| MPP `session` | — |
| MPP `subscription` | — |
| x402 `batch-settlement` | — |

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
- **Coverage follows declared capabilities.** The interop tier covers the
  registered process adapters and the claims in the expectations files, not
  every public framework integration, and pairs every SDK with Rust only: a
  divergence two non-Rust SDKs share, against each other, is not exercised.
  The resubmit cases assert HTTP rejection and exactly-once settlement, not
  application side-effect counts.
- **Surfpool ≠ a real cluster.** Forking approximates mainnet feature flags and
  account state; it is not a substitute for devnet/mainnet integration on the
  real network.

---

## Goals

- Prove cross-SDK protocol agreement (encoders, challenges, credentials, error
  codes) with byte-level vectors.
- Prove interop: every SDK's client pays the Rust reference server, and the Rust
  client pays every SDK's server, for every scheme the SDK claims.
- Prove **on-chain settlement** for program-backed schemes, so a payment that is
  accepted off-chain is one that actually settles.
- Make adding a language cheap: implement the process-adapter contract, register
  it, done.
- Keep CI coverage explicit and deterministic (planned shards; pure-JSON adapter I/O).

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
pnpm exec vitest run test/protocol-conformance.test.ts   # protocol suite (MPP_CONFORMANCE_LANGUAGES=<sdk>)
pnpm test:onchain              # on-chain settlement tier (HARNESS_ONCHAIN=1)
pnpm typecheck                 # base typecheck (excludes the on-chain suite)
pnpm typecheck:onchain         # on-chain suite typecheck (needs pay-kit built)
```

`@solana/mpp` (and `@solana/pay-kit`, which the TypeScript adapters import) are
local `file:` dependencies, so build them before installing the harness:

```bash
cd ../typescript && pnpm install --frozen-lockfile && pnpm build
cd ../harness && pnpm install --frozen-lockfile
```

The offline tier and the interop tier run from `rust/` with `pkc` (above).

### CI

`.github/workflows/conformance.yml` (`Conformance / <sdk>`): one job per SDK
from `pkc plan --tier interop` (offline vectors, protocol and flow suites,
interop against the Rust reference), plus `Conformance / registry` (case
registry, `pkc fill --check`, `req-lint`, `report --check`, harness unit
tests) and `Conformance / onchain`. A `changes` job runs only the SDKs a PR
touches; changes under `harness/`, `rust/crates/{conformance,kit,harness-bins}`
or `.github/` run every SDK. The offline cross matrix and the seeded corpus run
nightly (`conformance-nightly.yml`).

## Adding an implementation

1. Write a process adapter (client and/or server) for the language.
2. Add it to `ADAPTERS` in `rust/crates/conformance/src/interop/adapters.rs`
   (id, language, role, intent, reported implementation, launch command).
3. Claim its roles in `expectations/<language>.toml` (`capabilities.interop`).
4. Run it against the reference:
   ```bash
   pkc run --tier interop --sdk <language>,rust --require
   ```
   and record every failing case as `known_failing` with a FINDINGS.md section.
5. `pkc plan --tier interop --write`; the new shard appears in CI.
