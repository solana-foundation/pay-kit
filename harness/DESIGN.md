# Conformance harness redesign

Status: proposal, 2026-10-20. Not implemented.

## 1. Why the current harness misses bugs

The symptoms ("matrix incomplete", "vectors wrong") share one root cause:
**coverage is declared by the implementation under test, not demanded by the
spec, and the oracle is a third implementation rather than Rust.**

Evidence from the tree:

1. **Skips are green.** `runners/<lang>.json` `intents` allowlists, the
   `unsupported-mode` sentinel (`test/conformance.test.ts:296`), 20 of 30
   adapters `enabled: false` by default (`src/implementations.ts`), matrices
   behind `X402_HARNESS_MATRIX=1` / `X402_UPTO_HARNESS_MATRIX=1` /
   `X402_HARNESS_CROSS_SERVER=1`, and Rust integration tests that
   `return` when `SURFPOOL_DATASOURCE_RPC_URL` is unset
   (`rust/crates/integration-tests/tests/charge_integration.rs:20-23`). An
   SDK that declares less is tested less, and the report looks the same.
   Kotlin runs `session` vectors only. Rust has no `runners/rust.json` at all.
2. **The oracle is TypeScript, hand-derived.** 54 hand-written vectors whose
   expected values are checked by `src/conformance/{jcs,decode,x402,ts-runner}.ts`,
   which "mirrors Rust" in comments. There is no generator. When a vector is
   wrong, either every SDK fails identically or the vector is edited to
   match, and neither outcome is distinguishable from a real result.
3. **Five frameworks, zero shared scenario model.** Rust integration tests
   (surfpool, serial, one fork per test), structural e2e (vitest+surfpool,
   `src/intents/*.ts`), vector conformance (vitest, one process per vector),
   mpp-protocol (port of mpp-tools), on-chain tier. A failure case written in
   Rust (`sol_charge_expired_challenge_rejected`) never becomes a cross-SDK
   case. Negative interop cases need a misbehaving client in every language,
   so they do not get written.
4. **No denominator.** mpp-specs has ~1,430 MUST/MUST NOT statements, x402
   specs ~960. None is mapped to a test. "Matrix incomplete" cannot be
   detected because nothing defines complete.
5. **The fix history matches.** Verification/replay fixes shipped with
   harness coverage (#169, #361, #380). Session, settlement-worker and client
   fixes did not (#204, #250, #251, #253, #265, #305, #337, #370). Session has
   1 interop scenario; subscription and batch-settlement have 0 adapters.

## 2. What mature conformance suites do

| Project | Pattern worth copying |
| --- | --- |
| ethereum/execution-spec-tests | **fill / consume**: a reference implementation *fills* fixtures from programmatic test cases; every client *consumes* the committed, hashed fixtures. "Filling is not the test, consuming is." |
| protobuf conformance | One runner binary owns every test. Each language ships a ~150-line **testee** speaking a pipe protocol. Per-implementation **failure lists**: an expected failure that starts passing fails CI. |
| Wycheproof | Every vector has `tcId`, `result: valid/invalid/acceptable`, and `flags` → notes with a `bugType`. Negative vectors carry the expected error class. Only the test input may be malformed, never the envelope. |
| ethereum/hive | Simulator (test logic) separate from clients; one client abstraction so simulators are written once; results as structured JSON per suite/case with log pointers. |
| OpenTelemetry compliance matrix | Spec requirement × language table, each cell linked to evidence. The table is the denominator. |

pay-kit already has fragments of each (JSON-over-stdio adapters, `KNOWN_*_DIVERGENCES`
sets, `rejectCode` on vectors, a generated charge matrix). The redesign makes
them the whole system instead of fragments.

## 3. Design

### 3.1 Principles

1. **Rust in three roles.** It fills the vectors, it is the pivot in every
   interop pair, and it is itself a runner that must pass what it filled. A
   Rust runner failing a Rust-filled vector means the filler is wrong.
2. **Vectors are generated.** A case registry in `rust/crates/conformance`
   (`paykit-conformance`, one binary, compiled once, linking
   `solana-pay-kit`). A `#[test]` per case is the positive control.
3. **Every skip is declared**, with exact-set semantics in both directions.
4. **The driver asserts with pay-kit**, not with a shape DSL.
5. **The capability matrix is an output**, never hand-maintained.
6. **Three independent oracles**: Rust, the vendored mpp-tools vectors, and
   real program execution on surfpool. A single reference cannot see bugs it
   shares with everyone.
7. **The spec is the denominator.** Cases are mapped to pinned normative
   statements and the unmapped remainder is a visible number.

### 3.2 Three subcommands of one binary

```
paykit-conformance fill   [--check]                      # generate vectors from Rust cases
paykit-conformance run    --sdk <lang> --tier <tiers>     # drive one SDK's testee
paykit-conformance report <results...>                    # merge → matrix markdown/JSON
```

**`fill`.** Cases are Rust values (one module per suite: `charge`, `session`,
`subscription`, `x402_exact`, `x402_upto`, `batch_settlement`, `protocol`,
`canonical_bytes`). Each case constructs deterministic inputs (fixed keys,
blockhash, slot, epoch, clock) and runs the real pay-kit code to produce the
expected output: wire bytes, or `reject` with a canonical error class.

Most reject cases are **one valid credential plus a mutation operator**
(`drop_signature`, `bump_amount`, `swap_recipient`, `expire_challenge`,
`replay`, `wrong_network`, `wrong_treasury`, ...) paired with the canonical
code the verifier must return. The same operator table drives the interop
fault-injection proxy in §3.2, so a mutation written once runs offline against
every server SDK and live against every server SDK.

Output goes to `harness/vectors/generated/<suite>.json` with
`_info: { paykit_sha, filler_version, hash }` and is committed. CI runs
`fill --check` and fails on drift, like the existing "committed gen files are
up to date" step.

**Determinism without SDK changes.** `run` starts a **fixture RPC server**
(fixed blockhash, slot, epoch, mint owners, account data) and passes its URL
plus a clock override through two env vars. Runners point their SDK at the
fixture RPC and honour the clock; no SDK needs an offline builder family to
participate. Rust uses the same fixture RPC when filling.

Authored vectors stay, in `harness/vectors/authored/`. They are how the spec
tests Rust: a vector derived from the spec text, not from Rust output. The
vendored mpp-tools vectors are authored vectors with an external owner.
When a generated and an authored vector disagree, `fill --check` fails and a
human decides. That is the only place where "Rust is the oracle" is allowed
to be wrong, and it is loud.

**`run`.** Loads the corpus, the SDK's capability manifest, and its failure
list. Spawns the SDK's **single long-lived testee process** (not one process
per vector) and speaks newline JSON. Embeds the Rust server and Rust client
from `solana-pay-kit` (`MemoryStore`, `MemoryChannelStore`,
`with_blockhash_cache`, `testkit` helpers) so that:

- a **client** SDK is tested against the Rust server, including a
  misbehaving Rust server (malformed or expired challenge, wrong network,
  wrong treasury, replayed receipt, over-asking price) through a
  fault-injection layer, so client-side MUST NOTs (never overpay, never sign
  for the wrong network, refuse a mis-signed challenge) are covered;
- a **server** SDK is tested against the Rust client, including a
  misbehaving Rust client (mutated credential, replayed signature, wrong
  amount) through a proxy that mutates requests in flight (the existing
  loopback-proxy replay in `src/replay.ts` generalised).

One misbehaving Rust implementation therefore covers every SDK in the
opposite role. This is the single biggest coverage unlock: today every
negative interop case needs a misbehaving client per language, so they are
not written.

**Judging a build.** A client-build vector is judged by feeding the SDK's
output to the **Rust verifier** against the fixture RPC. This removes the
`transactionShape` DSL and every per-SDK mock. Because a lenient verifier
would pass everyone, the driver additionally compares the decoded instruction
multiset to Rust's own build of the same case (ed25519 is deterministic, so
with the fixture RPC only account ordering may legitimately differ).
`canonical-bytes` and `protocol.*` cases stay byte-exact.

`run` owns every assertion. Testees return raw results; they never encode
expectations (the current README already states this rule; the Rust driver
enforces it because the testee ABI has no place to put expectations).

**`report`.** Merges per-SDK JSON into the requirement × SDK matrix
(`pass / fail / expected-fail / unclaimed`), writes markdown for the PR
comment and regenerates the coverage table in `harness/README.md`.

### 3.3 Testee ABI (per language, one binary, all roles)

```
stdin : {"id":"...","op":"<op>","input":{...}}
stdout: {"id":"...","ok":true,"result":{...}} | {"id":"...","ok":false,"error":"<canonical-code>","detail":"..."}
```

Ops:

| op | role | notes |
| --- | --- | --- |
| `capabilities` | both | returns the manifest the testee was built with; `run` cross-checks against `harness/sdks/<lang>.toml` and fails on mismatch |
| `build` / `verify` | client / server | existing vector modes, all intents |
| `protocol.*` | both | the 9 mpp-tools ops, unchanged |
| `server.start {scheme, config} → {port}` / `server.stop` | server | replaces per-scheme `*-server/` adapter dirs |
| `client.pay {url, config} → {status, headers, body, settlement}` | client | replaces per-scheme `*-client/` adapter dirs |
| `store.dump` | server | lets the driver assert replay-store / channel-store state, not just HTTP status |

Diagnostics go to stderr; the driver attaches stderr to the case result
(hive-style log pointers).

### 3.4 The denominator

Three files per concern, all data, all reviewed in PRs:

- **`harness/requirements/<spec>.toml`** — one entry per testable normative
  statement: `id` (`MPP-CHARGE-SVM-017`), `spec` (repo, path, section, pinned
  SHA), `text` (quoted), `cases` (vector / scenario ids). A lint extracts
  MUST / MUST NOT sentences from `~/Coding/mpp-specs` and `~/Coding/x402`
  (both pinned as submodules or SHAs) restricted to the SVM-relevant
  documents, and reports: unmapped statements, mapped statements whose text
  changed since pinning, and mapped ids with zero cases. Start with the SVM
  charge / session / exact / upto documents; grow by lint output.
- **`harness/expectations/<lang>.toml`** — capability manifest: claimed
  `(protocol, scheme, role)` tuples, toolchain, how to build and launch the
  testee, `unsupported` case-id patterns with a reason, and `known_failing`
  ids each with an issue link. **Exact-set semantics in both directions**: a
  failure not listed fails CI, and a listed failure that passes fails CI with
  "remove from known_failing". An unclaimed capability appears as
  `unclaimed` in the report, never as a skip. This replaces `enabled:` flags,
  `intents` allowlists, `KNOWN_*` sets, env gates and the `unsupported-mode`
  sentinel.
- **Case metadata** (Wycheproof): every case carries `requirements: [...]`,
  `tier`, `result: accept | reject`, `reject_code`, and `flags` with a
  `bug_type` (`REPLAY`, `AUTH_BYPASS`, `SETTLEMENT`, `WIRE`, `DEFAULTS`,
  `MALLEABILITY`, ...). The report groups by `bug_type` so a regression is
  described by class, not by vector id.

Rust is a testee like any other. `run --sdk rust` executes authored vectors
and Rust↔Rust interop. There is no exemption for the reference.

### 3.5 Tiers

Each case declares the minimum tier it needs. Lower-tier cases also run at
higher tiers for free.

| Tier | Executes | Validator | Default CI |
| --- | --- | --- | --- |
| `offline` | `build` / `verify` / `protocol.*` with fixed blockhash and RPC fixtures | none | every PR, every SDK |
| `interop` | real client ↔ real server over HTTP, structural assertions on the broadcast transaction, store assertions | one surfpool per `run` invocation, shared | every PR: each SDK against the Rust pivot in both roles; nightly: full pairwise matrix |
| `onchain` | settlement must execute the deployed program (mainnet fork) | surfpool ≥ 1.4 fork | every PR for Rust + TS; nightly for all; **fails, not skips, when the datasource secret is missing on `main`** |

Network gating rule: `CI=1` makes every gate required. Skipping is a local
convenience only and is printed as a warning, not recorded as a result.

### 3.6 Migration of the Rust integration tests

`charge_integration.rs` (8), `settlement_onchain.rs` (5),
`confidential_integration.rs` (3) become conformance cases:

- happy paths → `interop` / `onchain` cases where the Rust side is just the
  `rust` testee, so the same case now runs for every SDK in both roles;
- `wrong_amount`, `wrong_recipient`, `identical_retry`, `expired_challenge`
  → fault-injection cases (driver mutates the Rust client's credential), so
  they run against every server SDK;
- `expired_voucher_is_rejected_on_chain`, `distribution_hash_matches` →
  `onchain` cases with the treasury-mismatch check moved from
  `test/onchain.e2e.test.ts:158` into Rust.

`tx_v1_litesvm.rs` stays a unit test. `harness/rust-client/` is orphaned
(not in the workspace, not referenced) and is deleted.

### 3.7 What is kept, what goes

Keep: vendored mpp-tools vectors and flows (authored, external owner); the
structural transaction assertions (ported to Rust, which already fetches and
decodes settled transactions in `settlement_onchain.rs`); path-based CI
selection with the shared-path tripwire; `with_blockhash_cache`,
`MemoryStore`, `testkit`.

Delete once each language testee exists: the 25 per-scheme adapter
directories, `src/implementations.ts`, `src/intents/*.ts` (ported to Rust
cases), `src/conformance/*.ts` (the TS oracle), vitest conformance drivers,
`divergence-matrix.mts` (subsumed by `report`), every `*_HARNESS_MATRIX` env
gate.

New Rust work required first: the fixture RPC server (small; serves the
handful of RPC methods the builders call) and exporting `MockSigner` /
`MockBroadcaster` under the `testkit` feature. The `_offline` builders on
`feat/rust-wasm-support` are useful for filling but no longer a prerequisite.

### 3.8 CI shape

```
build        cargo build -p paykit-conformance ; fill --check ; requirements lint
offline      run --sdk <lang> --tier offline          (every PR, all SDKs, seconds each)
interop      run --sdk <lang> --tier interop --pivot  (every PR, SDK ↔ Rust both roles, one surfpool per job)
onchain      run --sdk rust,typescript --tier onchain (every PR)
nightly      full pairwise interop + on-chain for all SDKs
report       merge → PR comment + README table ; fail if stale or if any known_failing passed
```

One compile of the Rust kernel, one compile of each testee, no Rust rebuild
inside language jobs (the current `cargo run` in `implementations.ts`
recompiles pay-kit inside every language leg).

### 3.9 Borrowed from FlatBuffers

- **Every SDK's output is every other SDK's input.** The offline tier saves
  each SDK's built credentials to `harness/results/<sdk>/builds/`, then feeds
  them to every other SDK's verifier. This is a pairwise client × server
  matrix with no validator, HTTP or network, and it catches a leniency Rust
  shares with one other SDK, which judging by the Rust verifier alone cannot.
- **Annotated vectors.** Next to each generated vector, `fill` writes an
  annotated view: transactions split into instructions, named accounts and
  parsed data fields; voucher preimages and canonical bytes split by offset
  and field. Generated from the Codama IDLs in `idl/`. A PR that changes a
  vector shows which field changed. The same annotator renders failure
  diffs (§6.2).
- **Clean tree before regenerating.** `fill --check` refuses to run on a
  dirty `harness/vectors/`, so a local edit cannot mask drift.
- **Version-skew cases.** x402 v1↔v2, session draft revisions, the
  epoch-addressed voucher, permit profile v2: old-format client against new
  server and the reverse. The previous published release of each SDK can
  run as an extra testee.
- **Corpus-seeded fuzzing.** The vector corpus seeds `cargo fuzz` targets
  over Rust parse and verify. Every crash or accept/reject flip becomes a
  committed case.

## 4. Phasing

| Phase | What lands | Payoff |
| --- | --- | --- |
| 0 | `expectations/<lang>.toml` with exact-set reconciliation inside the current TS driver; `runners/rust.json`; every skip fails under `CI=1`; drop hand-picked CI pairs; generated coverage table; delete `harness/rust-client`. | Shows the real matrix today. One cheap PR. |
| 1 | `paykit-conformance fill` with drift check; fixture RPC + clock env; port the 54 vectors and the Rust reject tests into cases with mutation operators; requirements lint over the SVM subset of the pinned spec repos. | Hardening in Rust becomes cross-SDK vectors automatically; unmapped MUSTs become a number. |
| 2 | `run --tier offline` replaces the vitest vector drivers; Rust verifier judges builds; delete the TS oracle in `src/conformance/`. | One oracle. |
| 3 | `run --tier interop` on surfpool with the embedded Rust pivot and fault-injection proxy; port `src/intents/*` and the Rust integration tests; pivot matrix on PR, pairwise nightly; one testee per language; retire vitest and the adapter directories. | Every SDK against Rust, both roles, every PR. |
| 4 | Session, upto, batch-settlement, subscription scenarios; on-chain tier in Rust; full traceability report. | Closes the documented gaps. |

## 5. Risks

- **Rust bug becomes everyone's bug.** Mitigated by authored vectors (spec →
  Rust direction), the external mpp-tools corpus, Rust running as a testee,
  and `fill --check` surfacing generated/authored disagreement instead of
  resolving it.
- **Testee drift.** The `capabilities` op is cross-checked against the
  committed manifest on every run, so a testee silently losing a role fails.
- **Scope.** Phase 0 is independent of the rewrite and worth doing even if
  Phases 1–3 slip.

## 6. Agent-driven iteration

The harness is also the specification an agent implements against. Every
design choice above helps; these are the additional requirements for an
agent to converge on an accurate SDK without a human in the loop.

### 6.1 The loop

```
pkc next     --sdk python                 # smallest failing class, with the fix brief
pkc case run --sdk python <id>            # one case, seconds, no network
pkc run      --sdk python --tier offline  # full offline tier, under a minute
pkc run      --sdk python --tier interop  # starts surfpool itself
```

The offline tier needs no secrets, no network, no validator. An agent must
be able to go from clone to first red result with one command per SDK.

### 6.2 Failures explain themselves

A failing case prints, in this order, as JSON and as markdown:

1. **The requirement.** Quoted normative sentence(s) with repo, file,
   section and pinned SHA. The agent reads the MUST next to the diff.
2. **The mutation**, if any, in words: "valid credential, then `BumpAmount`
   (+1 base unit); expected `charge_request_mismatch`".
3. **Expected vs actual, decoded.** Transactions as instructions with
   program id, named accounts and parsed data fields; headers parsed into
   their parameters; canonical codes as names. Never two base64 blobs. The
   first divergent field is named.
4. **The reference.** `file:line` of the Rust function that produced the
   expected value, from case metadata. The agent can read how Rust decides.
5. **The testee's own stderr** for that case, so the SDK's exception is
   visible.
6. **Replay command**: the exact `pkc case run` line and the raw input, so
   the agent can reproduce it in the SDK's own test framework.

### 6.3 Fix the class, not the instance

`pkc next` groups failures by `(requirement, bug_type, canonical code)` and
returns the smallest group first with every case id in it. The agent fixes
the class and re-runs the group. This is the harness enforcing
CONTRIBUTING's "fix the class, not the instance".

### 6.4 The TODO list is the expectations file

`expectations/<lang>.toml` `known_failing` is the agent's work queue.
`pkc run --diff-expectations` prints what flipped since the last run. The
agent removes ids as they pass; exact-set semantics mean it cannot remove
one early. A new SDK starts with a scaffolded testee that reports
`unsupported` for everything and a report that lists the whole surface in
dependency order: protocol ops, then build, then verify, then interop.

### 6.5 No way to game it

- Exact-set expectations: skipping is impossible; the only lever is the
  toml, and the toml diff is the review surface.
- Mutation operators take a `--seed`. Nightly fills with a random seed, so
  a testee that memorises the committed bytes fails the next night.
- The testee ABI has no field for expectations and the driver ignores any
  extra fields, so a testee cannot assert its own success.
- Timeouts per case, killed and reported as `timeout`, so a hung testee
  cannot stall the loop or look like a pass.
- CI treats a `known_failing` addition without an issue link as an error.

### 6.6 Discoverability

A `harness/AGENTS.md` (and a `skills/sdk-conformance` skill) with the loop,
the ABI, the scaffold command and the rule "never edit a vector to make it
pass; file against the filler". `pkc --help` carries examples. `pkc scaffold
--lang <x>` emits the testee skeleton and the expectations file so the ABI
is never hand-rolled.
