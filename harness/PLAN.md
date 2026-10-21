# Conformance harness: implementation plan

Companion to [DESIGN.md](DESIGN.md). This is the handoff document for the
implementing agent. Read DESIGN.md first; this file says what to build, in
what order, how to know it is done, and where the work tends to go wrong.

Repository rules that apply throughout: [CONTRIBUTING.md](../CONTRIBUTING.md)
(parse don't validate, enforce don't document, behavioural fixes ship with a
regression test that fails before the change plus a positive control,
conventional commits, run formatter/linter/tests for every language touched).

## Ground truth you can rely on

Verified on 2026-10-20 against `main` at `cee5b8ff`.

| Fact | Where |
| --- | --- |
| 54 hand-written vectors in 14 files, schema in TS | `harness/vectors/*.json`, `harness/src/conformance/schema.ts` |
| Vector driver spawns one process per SDK per vector | `harness/test/conformance.test.ts:276-300` |
| Runners declared by manifest, `intents` allowlist, default `["charge","x402-exact"]` | `harness/runners/<lang>.json`, `harness/src/conformance/runners.ts:36` |
| No Rust vector runner exists | no `harness/runners/rust.json` |
| Rust protocol runner (mpp-tools ABI, 9 ops) | `rust/crates/kit/examples/protocol_runner.rs`, `harness/protocol-runners/rust.json` |
| 30 interop adapters, 20 disabled by default via `isEnabled(..., false)` | `harness/src/implementations.ts` |
| Four env gates hide whole matrices | `X402_HARNESS_MATRIX`, `X402_UPTO_HARNESS_MATRIX`, `X402_HARNESS_CROSS_SERVER`, `HARNESS_ONCHAIN` |
| Known-divergence sets, ad hoc, asserted to still fail | `harness/test/protocol-conformance.test.ts:33,85,170`, `flow-conformance.test.ts:44` |
| Canonical error codes (7) | `harness/src/canonical-codes.ts` |
| Rust integration tests skip when `SURFPOOL_DATASOURCE_RPC_URL` unset | `rust/crates/integration-tests/tests/charge_integration.rs:19-38` |
| Rust integration tests: 8 charge, 5 settlement, 3 confidential, 2 litesvm | `rust/crates/integration-tests/tests/` |
| Harness bins: 6 (mpp/x402-exact/x402-upto × client/server) | `rust/crates/harness-bins/src/bin/` |
| Orphaned crate, not in workspace, unreferenced | `harness/rust-client/` |
| RPC methods the Rust builders call | `get_account` (29), `get_multiple_accounts` (15), `send_transaction` (9), `get_latest_blockhash` (8), `get_signature_statuses` (4), `get_slot` (2), `get_minimum_balance_for_rent_exemption` (2), `get_token_account_balance`, `get_epoch_info`, `get_balance` |
| Rust verifier entry points | `rust/crates/kit/src/x402/protocol/schemes/exact/verify.rs:28,237,246`; `mpp/protocol/channel_charge.rs:247`; `core/voucher.rs:34`; `mpp/protocol/core/challenge.rs:159` |
| Reusable test helpers | `core/store.rs` (`MemoryStore`:68, `ChargeReplayStore`:299, `MemoryChannelStore`:1968); `core/settlement/testkit.rs` (feature `testkit`); `with_blockhash_cache` on all four servers |
| Private mocks that must be exported | `MockBroadcaster` (`core/settlement/worker.rs:561`), `MockSigner` (`x402/client/exact/payment.rs:604`) |
| x402 spec repo pinned as submodule | `typescript/external/x402` at `03b3919b` (2026-10-02) |
| mpp-specs not pinned anywhere; local checkout on `feat/idle` at `ae11bb5` | `~/Coding/mpp-specs` |
| surfpool-sdk pinned by git rev | `rust/crates/integration-tests/Cargo.toml:31` |
| CI: harness jobs in `harness.yml`, charge matrix in `mpp-matrix.yml`, Rust in `ci.yml:199-310` | `.github/workflows/` |

Re-verify any line above before depending on it. The tree moves fast.

## Status (updated 2026-10-20)

Phase 0 is in progress on `feat/harness-phase0-expectations`.

Phase 1 landed on `feat/pkc-phase1`: `rust/crates/conformance` (`pkc fill
[--check]`, `pkc req-lint`), every vector filled from the Rust registry with
a required `spec` reference, annotated views, mpp-specs pinned at
`external/mpp-specs`. Deviations from the task list below: vectors keep their
file names under `harness/vectors/` (no `generated/` / `authored/` split;
`provenance` is a per-vector field), the lint is a `pkc` subcommand rather
than a Python script, and `run` / `report` are not started.

Phase 2 and 2b landed on `feat/pkc-phase2`:

- `pkc run --sdk <lang>[,..]|all --tier offline [--require]` replaces
  `harness/test/conformance.test.ts` (deleted) in every CI leg. Rust port of
  the TS reconciler (`run/expectations.rs`, tests ported), of `judgeVector`
  (`run/judge.rs`) and of the result schema (`run/result.rs`); per-vector
  fixture RPC; `harness/results/<sdk>.json`, `<sdk>.failures.json`,
  `junit-<sdk>.xml`, GitHub `::error` annotations.
- Testee ABI v2 (`--serve`, newline JSON, `capabilities` / `build` /
  `verify` / `canonical-bytes`) in all nine runners; manifests gained
  `serve`; one-shot kept as `--legacy` and checked to give identical results
  for all eight local languages. `capabilities` is cross-checked against the
  toml, which gained a required `capabilities.honours_clock`. Per-case
  timeout, stderr drained per case, process-group kill and restart.
- Builds are judged by the Rust kit: every accepted charge / x402 build
  carries `transaction` / `x402PaymentHeader`, is run through the kit's
  verifier and compared, as an instruction multiset, with the kit's own build.
  This found the Python x402 runner signing with an ephemeral key instead of
  the vector's signer (fixed in the runner).
- `pkc run --cross`: every saved build verified by every server-capable SDK;
  the x402 build offers now use a sponsor whose seed the harness holds
  (`[11; 32]`) so server SDKs that need a key can be configured. Matrix in
  `harness/README.md` (markers, `--check` for staleness); not gating yet.
- 2b: `pkc case show`, `pkc case run`, `pkc next` (grouping, blocking first),
  `--diff-expectations`, six-element failure reports (`run/explain.rs`,
  references resolved from search strings and checked by a test),
  `pkc scaffold`, `pkc run --seed` with the nightly `conformance-seeded.yml`
  (reported, not gating), `harness/AGENTS.md`, `skills/sdk-conformance`.

Wall clock for the offline vector suite, local, warm caches (old vitest
driver, one process per vector, vs `pkc run`): typescript 107 s vs 3 s, rust
60 s vs 1.3 s, go 15 s vs 0.5 s, python 29 s vs 0.8 s, ruby 16 s vs 0.6 s,
php 7 s vs 0.3 s, lua 3 s vs 0.4 s, swift 70 s vs 1.5 s.

Not done in phase 2: the protocol and flow suites still run on vitest (their
`protocol.*` ops are not in the ABI yet), so `src/expectations.ts` stays as
the TS twin of the Rust parser; `src/conformance/{decode,jcs,reject,x402}.ts`
stay because the TypeScript runner uses them; the cross matrix is reported,
not reconciled against expectations; decoders in `annotate.rs` are
hand-written, not generated from `idl/`; `reference` metadata is derived per
(intent, mode), not stored per case. The Kotlin testee's `--serve` mode was
written without a local JVM and is first compiled in CI.

Phase 4, first part, on `feat/pkc-report`:

- `pkc report`: requirement × SDK traceability (README markers, `--check` in
  CI; observed outcomes in `harness/results/report.json`), with the unmapped
  sentences per spec file and section.
- `pkc req-lint` fails when a `required = true` requirement has no case;
  every mapped requirement with cases is marked.
- The cross-verification matrix is gating: `cross/<case>/<client>/<server>`
  cells reconciled against the server's expectations, a `cross` CI job fed
  by the client legs' build artifacts (`pkc run --cross --require --check`).
- 42 cases for 37 previously unmapped charge / x402-exact MUSTs
  (`charge_policy.rs`, `x402_policy.rs`); 13 new FINDINGS.md sections.

Phase 3 on `feat/pkc-phase3`:

- `pkc run --tier interop` (`rust/crates/conformance/src/interop/`)
  replaces `test/e2e.test.ts`, `cross-server-scenarios`, `x402-exact.e2e`,
  `x402-upto.e2e` and their support code (`src/{ci-matrix,replay,guards,
  process,implementations}.ts`, `src/intents/`, `emit-ci-matrix.ts`,
  `interop-coverage.ts`, `mpp-matrix.yml`). The existing process adapters are
  the testees, driven exactly as `process.ts` did; one offline surfpool per
  run, fresh keypairs per case, scenario mints fixed (x402 servers price in
  the network's stablecoin, so fresh mints were not possible).
- 30 scenarios (the 23 of `src/intents/*.ts`, ids kept, plus 7 faults), each
  with a verbatim spec quote; structural settlement assertions in Rust.
- Direction change: **Rust is the only counterparty.** Every case pairs an SDK
  with the Rust adapter in the opposite role (Rust against Rust as the
  control); there are no non-Rust pairs and no nightly pairwise matrix.
  Consequence: the scenarios only the TypeScript client can drive
  (`charge-compute-budget-over-cap`, `charge-splits-*`, `charge-push`) now run
  against the Rust server only.
- Fault proxy: capture/replay (resubmit, cross-server portability),
  cross-route replay, wrong amount / wrong recipient re-signed with the
  client key (the negative cases of the deleted `charge_integration.rs`,
  against every server), expired / wrong-network / over-asking / mis-signed
  challenge (against every client).
- `capabilities.interop` claims, exact-set reconciliation across both sides
  of a pair, `known_failing.ids`. 224 local cases (Kotlin excluded: no JVM):
  175 pass, 49 known failing (FINDINGS.md "Interop findings").
- CI: `pkc plan --tier interop` emits one `Conformance / <sdk>` job per SDK
  (offline + protocol/flow + interop) in `conformance.yml`, path-filtered per
  SDK; the cross matrix and the seeded corpus moved to
  `conformance-nightly.yml`. `ci.yml` split into `TypeScript`, `Rust`,
  `Playground` and `Payment links` workflows; language workflows keep only
  `test` / `lint`.

Not done in phase 3: harness adapter directories are kept (no single
per-language testee yet), `settlement_onchain.rs` is not ported (on-chain
tier, phase 4), `store.dump` and the sequence suite are not implemented.

Done:

- Expectations files with exact-set reconciliation for the vector,
  protocol and flow suites (`src/expectations.ts`, `expectations/*.toml`).
- Every claimed offline suite runs in CI under `HARNESS_REQUIRE=1`,
  enforced by `test/ci-coverage.test.ts`.
- Generated tables in `harness/README.md`: offline conformance per SDK
  (`coverage-table.ts`) and interop cases actually run in CI
  (`interop-coverage.ts`), both staleness-checked.
- Rust integration tests fail instead of skipping under `HARNESS_REQUIRE=1`.
- `harness/rust-client/` removed.
- Rust vector runner (`rust/crates/kit/examples/vector_runner.rs`): 45 of 54
  vectors pass; its 7 known failures mostly expose vectors that contradict
  the spec (see `expectations/FINDINGS.md`).

Facts established while doing it:

| Gap found | Effect before the fix |
| --- | --- |
| Vector runners for TypeScript, Go, Ruby, Lua, PHP never ran in CI | 5 of 8 SDKs had no vector conformance in CI |
| Protocol and flow suites never ran in CI | 91 protocol and 34 flow cases unchecked |
| Spawned protocol runners ran one smoke case per op | 7 of 91 cases per language; hid a PHP divergence |
| Flow suite crashed in `beforeAll` (mppx 32-byte secret) | all flows skipped locally too |
| Kotlin vector runner implements 3 of 54 vectors | reported as a green job |
| `ts-x402` client and server run no interop case in CI | 46 of 56 x402-exact cases never run |
| 9 harness test files run by no CI step | one had been failing since a path move |
| Rust settlement and confidential integration tests are not in any CI invocation | 8 on-chain tests never run |
| Skipped Rust integration tests print `ok` | indistinguishable from a pass except by duration |

Remaining for phase 0: replacing hand-picked x402 / upto / session interop
pairs with a generated matrix and interop claims in the expectations files.
The never-run x402 pairs were run locally first; their failures are recorded
under "Interop findings" in `expectations/FINDINGS.md`.

## Backlog: Rust tests to migrate into shared cases

Surveyed 2026-10-20: about 136 Rust tests cover replay, tampering, expiry and
concurrency, and almost none have a shared counterpart.

**Expressible as vectors today** (single input, one verdict):

| Rust test(s) | Rule | Vector to add |
| --- | --- | --- |
| `verify_{sol,spl}_transfers_rejects_reusing_single_instruction_for_duplicate_splits` (`mpp/server/charge.rs`) | charge: "A single transfer instruction MUST NOT satisfy more than one required payment leg" | verify reject + accept pair with a duplicate split recipient |
| `verify_parsed_memo_instructions_requires_distinct_memos_for_duplicate_split_memos` | split memos per leg | verify reject |
| `tier2_rejects_tampered_{realm,currency,recipient,method}`, `verify_rejects_tampered_{id,challenge_id}` | core: challenge binding | credential-verify vectors: one valid credential, one field mutated |
| `verify_rejects_expired_challenge`, `challenge_expired_*` | core: "Clients MUST NOT submit credentials for expired challenges" | verify with pinned clock |
| `cross_route_v2_attacker_lying_about_{amount,recipient,currency}` (`x402/server/exact.rs`) | x402: `accepted` must match the route | verify reject per field |
| `wrong_amount` / `wrong_recipient` (`charge_integration.rs`) | charge SPL/SOL verification | verify reject per field (no validator needed) |
| x402 §1.4 and §2.1.1, no Rust test yet | exactly one matching transfer; fee payer in no instruction | verify rejects: zero transfers, two transfers, fee payer as account; accept: overpayment |
| `rejects_expired_and_not_yet_active` (`x402/.../upto/verify.rs`) | upto voucher validity window | upto verify vectors (needs an `x402-upto` intent) |

**Need a sequence suite** (ordered steps against one server, store state
asserted between steps):

- **Replay.** `replay_protection_marks_and_detects_consumed`,
  `charge_identical_retry_is_rejected`, `process_payment_rejects_cross_route_replay`
  and `a_replay_is_bound_to_the_route_that_committed_it` each send the same
  credential twice, the second time to the same or another route.
- **Concurrency.** `consume_signature_concurrent_replay_reserves_exactly_once`,
  `concurrent_pending_retries_grant_one_receipt`,
  `concurrent_cumulative_vouchers_are_served_one_at_a_time` and
  `concurrent_recoveries_produce_exactly_one_binding` send N parallel copies
  and expect exactly one success.
- **Replicas.** `{push,x402}_signature_consumed_on_one_replica_is_rejected_on_another`
  needs two server instances sharing one store.
- **Session lifecycle** (`mpp/server/session.rs`): voucher replay,
  below-price voucher, expired pre-broadcast open, guarded failure rollback,
  delayed activation after close.

A sequence case is a list of `{ send, expect: { status, code }, assertStore? }`
steps run by the driver against the server testee (PLAN phase 3
`server.start` + `store.dump`), with the Rust client and fault proxy
producing the credentials. Until then, the replay and cross-route cases stay
as interop scenarios (`charge-idempotent-resubmit`, `*-cross-route-replay`).

**Vector documentation.** All 55 vectors have a description; 26 cite the
spec. Add a required `spec` field (`{ doc, section, quote }`) to the vector
schema and fail at load when it is missing, so each case is traceable to the
sentence it encodes.

## Backlog: the playground E2E as a gate-level tier

`playground/tests/playground.spec.ts` drives the unified gate through a real
browser and a real server: quote and fortune over MPP and x402, split charge,
x402 usage settlement, subscription activation and a metered MPP session. It
covers flows the harness interop does not (subscription has no interop case,
session has one), and it exercises discovery, OpenAPI and both protocols on
one route, which adapter-level tests never see.

Today it runs only against the TypeScript playground API
(`typescript/examples/playground-api`). Go has an equivalent
(`go/examples/playground-api`, with its own `playground_e2e_test.go`).

Proposal: treat a playground API as the gate-level server testee.

- **One contract.** Specify its routes, prices and environment
  (`RPC_URL`, `NETWORK`, fee payer) once, and implement it per server SDK
  that ships a gate.
- **One scenario list.** Run the same Playwright and headless-client
  scenarios against each implementation, always on a local Surfnet.
- **The same reconciliation.** Claim the `gate` suite in
  `expectations/<language>.toml` and reconcile it exactly like the offline
  suites.

Its CI job already found one hermeticity bug: the payment-link variant ran
against the shared remote sandbox instead of the local Surfnet it started.

## Phase 0: make the current harness honest (one PR, 1–3 days)

Goal: no code moves, no new crate. After this PR the existing driver cannot
show green for a case it did not run, and the real coverage is visible.

### Tasks

1. **Expectations files.** Create `harness/expectations/<lang>.toml` for
   every language that has a runner or adapter (typescript, rust, go, python,
   ruby, lua, php, swift, kotlin):

   ```toml
   language = "go"
   # Vector intents and interop (protocol, scheme, role) tuples this SDK claims.
   capabilities = ["vector:charge", "vector:x402-exact", "vector:session",
                   "interop:mpp:charge:client", "interop:mpp:charge:server",
                   "interop:x402:exact:client", "interop:x402:upto:client", ...]
   [[unsupported]]
   pattern = "x402-v1-*"
   reason  = "Go SDK has no v1 surface"
   [[known_failing]]
   id     = "session-voucher-verify-003"
   issue  = "https://github.com/.../issues/NNN"
   ```

   Seed them from what is actually enabled today: `runners/*.json` `intents`,
   `implementations.ts` `enabled` defaults and `intents`, and the
   `KNOWN_*` sets. Every disabled adapter becomes either a claimed
   capability (and starts running) or an explicit `unsupported` with a
   reason. Nothing is silently dropped.

2. **Exact-set reconciliation in the TS driver.** In
   `harness/test/conformance.test.ts`, `protocol-conformance.test.ts`,
   `flow-conformance.test.ts` and the e2e matrix tests, replace
   `ctx.skip()`, the `unsupported-mode` sentinel and the `KNOWN_*` sets with
   one shared module `harness/src/expectations.ts` that:
   - loads the toml, validates it (unknown case ids, unknown capabilities,
     and duplicate entries are hard errors),
   - decides per `(sdk, case)`: `run` / `unsupported` / `known_failing`,
   - after the run, fails if any `known_failing` passed, if any claimed case
     was not executed, or if any failure was not listed.
   `unsupported` is recorded in the results JSON, never as a vitest skip.

3. **Rust vector runner.** Add `rust/crates/kit/examples/vector_runner.rs`
   (or a bin in `harness-bins`) speaking the existing vector ABI
   (`schema.ts` `ConformanceVector` in, `RunnerResult` out), covering
   `charge`, `x402-exact`, `session`, `canonical-bytes`. Add
   `harness/runners/rust.json`. Expect Rust to fail some vectors: that is the
   point. Record each in `expectations/rust.toml` with an issue, do not fix
   silently in this PR.

4. **CI gates fail, not skip.** Introduce `HARNESS_REQUIRE=1`, set in every
   CI job. Under it: a missing toolchain, a missing secret, surfpool not
   coming up, or an adapter not producing `ready` is a test failure. In
   `rust/crates/integration-tests`, `start_surfnet_or_skip` panics instead of
   returning `None` when `CI` is set.

5. **Drop hand-picked CI pairs.** `mpp-matrix.yml` already generates shards
   from the registry. Make `harness.yml`'s per-language jobs and the x402
   jobs derive their pairs from `expectations/*.toml` capabilities the same
   way, and delete the `MPP_HARNESS_CLIENTS=` / `X402_HARNESS_*` env
   selections.

6. **Generated coverage table.** `harness/scripts/coverage-table.ts`
   renders the capability × case-group matrix from the results JSON into
   `harness/README.md` between markers. CI fails if the committed table is
   stale (same pattern as the html gen-file check in `ci.yml`).

7. **Delete `harness/rust-client/`.**

### Success criteria

- `grep -rn "ctx.skip\|it.skip\|KNOWN_.*DIVERGENCES\|unsupported-mode" harness/test harness/src` returns nothing.
- Every `(sdk, case)` pair appears in the results JSON with exactly one of
  `pass | fail | known_failing | unsupported`. Count of pairs equals
  `|sdks| × |cases|`.
- Removing an id from `known_failing` while the SDK still fails turns CI red.
  Adding a passing id to `known_failing` turns CI red. (Write both as tests
  of `expectations.ts` with a fake runner.)
- Unsetting `SURFPOOL_DATASOURCE_RPC_URL` in a CI job turns it red.
- `harness/runners/rust.json` exists and the Rust runner runs every vector.
- The README coverage table is generated and the stale check is wired.
- No vector, scenario or SDK behaviour changed. Diff to `rust/crates/kit/src`
  is zero (the example file is outside `src`).

### Traps

- **Seeding expectations from today's green is tempting and wrong** when a
  case is green only because it was skipped. Run the full matrix once with
  all gates forced on, locally, before writing the toml. Expect new red.
- The `unsupported-mode` sentinel also fires for genuinely role-mismatched
  cases (verify vector on a client-only SDK). Those become `unsupported`
  entries with the reason "client-only"; do not invent a new sentinel.
- `isEnabled(...)` defaults differ between local and CI. Delete the
  function, do not add another env var.
- The Kotlin and Swift runners are built by `gradle installDist` /
  `swift build` in separate workflows. Exact-set reconciliation will expose
  that they are not run on most PRs. Claim them in the toml and let the
  workflow cost be visible; do not mark them unsupported to stay green.

## Phase 1: `paykit-conformance fill` (1–2 weeks)

Goal: vectors are a build artifact of Rust. Hand-written vectors stay only
where they are derived from the spec rather than from Rust.

### Tasks

1. **Crate.** `rust/crates/conformance/` (`paykit-conformance`), in the
   workspace, not published, depends on `solana-pay-kit` with features
   `mpp,x402,client,server,testkit`. Binary `pkc` with subcommands
   `fill`, `run`, `report`. Only `fill` lands in this phase.

2. **Case model.** `src/case.rs`:

   ```rust
   pub struct Case {
       pub id: CaseId,                 // "charge/build/spl-default-decimals"
       pub suite: Suite,               // Charge | Session | Subscription | X402Exact | X402Upto | BatchSettlement | Protocol | CanonicalBytes
       pub tier: Tier,                 // Offline | Interop | OnChain
       pub role: Role,                 // Client | Server | Both
       pub requirements: Vec<ReqId>,   // "MPP-CHARGE-SVM-017"
       pub bug_type: BugType,          // Replay | AuthBypass | Settlement | Wire | Defaults | Malleability | Precedence
       pub input: Input,
       pub expect: Expect,             // Accept(ExpectedArtifact) | Reject(CanonicalCode)
   }
   ```

   `CaseId` and `ReqId` are newtypes with private constructors that validate
   format. `Expect::Reject` carries one of the seven canonical codes as an
   enum, not a string.

3. **Registry.** `src/cases/<suite>.rs`, each exposing
   `pub fn cases() -> Vec<Case>`. One `#[test]` per case asserts the case
   produces its `expect` when run through pay-kit now (positive control).
   Generate those tests with a macro over the registry so a case cannot
   exist without its test.

4. **Mutation operators.** `src/mutate.rs`: an enum of operators over a
   valid credential/transaction/challenge (`DropSignature`, `BumpAmount`,
   `SwapRecipient`, `ExpireChallenge`, `WrongNetwork`, `WrongTreasury`,
   `ReplaySame`, `ExtraTransfer`, `TruncateMemo`, `FlipDecimals`, ...), each
   with the canonical code it must produce. `cases()` for reject suites is
   mostly `valid_cases × operators`, filtered by applicability. Write an
   operator once; it must serialise into the vector so other SDKs see the
   mutated bytes, not the operator name.

5. **Fixture RPC.** `src/fixture_rpc.rs`: a small JSON-RPC server (axum,
   already a dependency) serving exactly the methods in the ground-truth
   table, from a `Fixture` struct (blockhash, slot, epoch, accounts map,
   rent). Unknown method → error that names the method, so the gap is
   obvious. Also a `PKC_CLOCK` env convention: ISO-8601 instant that
   runners must treat as "now". Document both in `harness/README.md` under
   the runner contract.

6. **Fill.** `pkc fill --out harness/vectors/generated/` writes one JSON
   file per suite with `_info { paykit_sha, filler_version, hash }` and the
   case list in the existing `ConformanceVector` shape where possible (so
   phase 2's runners keep working), extended with `requirements`,
   `bug_type`, `tier`. `pkc fill --check` exits non-zero on any byte
   difference. Wire into `ci.yml` next to the Rust tests.

7. **Port.** Move the 54 vectors in `harness/vectors/*.json` into cases.
   For each, decide: generated (Rust produces the same expected value) or
   authored (move to `harness/vectors/authored/`, add a comment citing the
   spec section). Port the Rust reject unit tests in
   `x402/.../exact/verify.rs`, `mpp/server/charge.rs`, `session*.rs` to
   operators. Keep the unit tests; the cases are additive.

8. **Annotated vectors.** `src/annotate.rs` renders each generated vector
   as an annotated text file next to the JSON (instructions, accounts,
   parsed data from the Codama IDLs; offsets and fields for byte vectors).
   `fill --check` covers them and refuses to run on a dirty
   `harness/vectors/`.

9. **Requirements lint.** `harness/requirements/{mpp,x402}.toml` and
   `harness/scripts/req-lint.py` (`python3 -I`): extracts MUST / MUST NOT /
   SHALL / REQUIRED sentences from the pinned spec texts restricted to the
   SVM-relevant files (mpp: `specs/core/`, `specs/intents/`,
   `specs/methods/solana/`; x402: `specs/x402-specification-v2.md`,
   `specs/schemes/{exact,upto,batch-settlement}/scheme_*{,_svm}.md`), stable
   ids by hashing the normalised sentence, and reports: unmapped sentences,
   mapped ids whose text changed, mapped ids with zero cases. Pin mpp-specs
   as a submodule (`external/mpp-specs`) the same way x402 already is.
   Phase 1 success is the report existing and the number being visible,
   not the number being zero.

### Success criteria

- `cargo test -p paykit-conformance` runs one test per case; count matches
  `pkc fill --list | wc -l`.
- `pkc fill --check` passes on a clean tree and fails after editing any
  generated JSON by one byte or any case by one field.
- Every one of the original 54 vectors is either regenerated byte-identically
  in `expect` (ignoring additive fields) or moved to `authored/` with a spec
  citation. Zero deleted.
- Reject cases outnumber accept cases at least 3:1 in `charge` and
  `x402-exact`.
- At least one case per canonical error code.
- `req-lint` runs in CI and prints the three counts. `requirements/*.toml`
  maps every existing case to at least one requirement id.
- Fixture RPC serves every method in the ground-truth table and the Rust
  client builders complete a build against it with no network.

### Traps

- **Determinism leaks.** `SystemTime::now()` in challenge expiry, random
  nonces in challenge ids, `rand` keypairs, HashMap iteration order in JSON
  serialisation, surfpool-dependent slot. Grep the kit for `now()`,
  `thread_rng`, `Keypair::new` on the fill path and thread a `Clock` and
  seeded keys through. If a case cannot be made deterministic, it is an
  interop case, not an offline one.
- **Rust bug fossilised as truth.** A case whose expected value comes from
  Rust and disagrees with an authored vector or with the spec must fail
  `fill --check`, not quietly win. Implement the generated/authored
  disagreement check explicitly and test it with a planted conflict.
- **Floating `_info.paykit_sha`.** It changes every commit. Hash the case
  content, not the sha; record the sha for humans only and exclude it from
  the drift comparison.
- **Operators that produce the wrong canonical code.** `BumpAmount` on a
  charge is `charge_request_mismatch`; on a session voucher it may be
  `payment_invalid`. Pair the code per (operator, suite), not per operator.
- **Fixture RPC too clever.** Do not implement `simulateTransaction` or
  `sendTransaction` semantics. Offline cases never broadcast. If a builder
  calls them on the build path, that is a kit bug to file, not a fixture
  feature to add.
- **Spec sentence extraction** is noisy (examples, tables, non-normative
  notes contain MUST). Accept noise and let the toml carry `ignore = [...]`
  with reasons. Do not try to parse RFC structure.

## Phase 2: `pkc run --tier offline` replaces the vitest vector drivers (1–2 weeks)

### Tasks

1. **Testee ABI v2.** Long-lived process, newline JSON, request `id` echoed.
   Ops: `capabilities`, `build`, `verify`, `protocol.*`. Document in
   `harness/README.md`; keep the field names of the v1 vector ABI so SDK
   runners change minimally. Add a `--legacy` shim in `pkc` that drives the
   current one-process-per-vector runners so languages can migrate one at a
   time.

2. **Driver.** `src/run/offline.rs`: starts the fixture RPC, spawns the
   testee with `PKC_RPC_URL` and `PKC_CLOCK`, streams cases, collects
   results, reconciles against `harness/expectations/<lang>.toml` (reuse the
   phase 0 semantics; port the toml loader to Rust and delete the TS one).

3. **Judging.** For `build` results: parse, feed to the matching Rust
   verifier against the fixture, require accept; then decode and compare
   the instruction multiset with Rust's own build for the case (program id,
   accounts as a set, data bytes). For `verify` results: compare outcome
   and canonical code. For `canonical-bytes` and `protocol.*`: byte-exact.

4. **Offline cross-verification.** Every `build` result is saved to
   `harness/results/<sdk>/builds/<case>.json`. After all SDKs run, `pkc run
   --cross` feeds each SDK's builds to every other server-capable SDK's
   `verify`, giving a pairwise matrix without a validator.

5. **Results.** `harness/results/<sdk>.json`: per case `{ id, status,
   duration_ms, stderr_ref, detail }`. junit output for GitHub annotations.

5. **Migrate runners.** Rust and TypeScript first (TS runner lives in
   `harness/src/conformance/ts-runner.ts`; keep the build/verify calls,
   replace stdin handling). Then go, python. Then ruby, lua, php, swift,
   kotlin. Delete `harness/test/conformance.test.ts`,
   `protocol-conformance.test.ts`, `flow-conformance.test.ts` and the TS
   oracle in `harness/src/conformance/{jcs,decode,x402,reject}.ts` only when
   every language has migrated.

### Success criteria

- `pkc run --sdk rust --tier offline` and `--sdk typescript` pass with
  `expectations` files that list every current known failure.
- Wall clock for the full offline suite per SDK under 60 s on CI
  (one process, not one per vector).
- A planted lenient-verifier test: make the Rust verifier accept an extra
  transfer in a test build, confirm the multiset comparison fails the case.
- Deleted TS oracle files; `harness/src/conformance/` contains only the TS
  runner.

### Traps

- **Account ordering.** Solana message compilation orders accounts by
  signer/writable class; SDKs differ in intra-class order. Compare per
  instruction as `(program_id, set(accounts), data)`, not positional.
- **Signatures in the multiset.** Exclude signatures from the comparison;
  include signer pubkeys.
- **Testee deadlocks** on stderr buffer fill. Drain stderr on a thread.
- **Clock env ignored** by an SDK silently makes its expiry cases pass or
  fail by wall time. The `capabilities` response must include
  `honours_clock: true`; cases tagged `needs_clock` are `unsupported` for
  testees that report false, visibly.
- **Partial migration state.** The `--legacy` shim and the new ABI must
  produce identical results JSON so the report does not care which one an
  SDK uses.

## Phase 2b: agent ergonomics (lands with or right after phase 2)

These are driver features in `pkc`, cheap once the offline tier exists, and
they decide whether an agent can be pointed at an SDK and left alone.

### Tasks

1. **Case metadata.** Add `reference: Vec<SourceRef>` (`file:line`, kept
   current by a test that resolves each ref with `grep -n` of the function
   name) and `requirements` text lookup to `Case`. `pkc case show <id>`
   prints input, expected (decoded), mutation, requirement text, reference.
2. **Decoded diff.** `src/explain.rs`: decode transactions (instructions,
   named accounts via known program ids, parsed data for System, Token,
   Token-2022, ATA, Memo, ComputeBudget, payment-channels, subscriptions)
   and headers into a canonical tree; diff trees; name the first divergent
   path. Used for every failure, offline and interop.
3. **`pkc next --sdk <x>`**: group failures by `(requirement, bug_type,
   code)`, print smallest group with all ids, the requirement text, the
   reference, and the replay command for one representative.
4. **`pkc case run --sdk <x> <id>`**: one case, one process, no fixture RPC
   restart cost beyond startup.
5. **`pkc run --diff-expectations`**: compare results to the toml and print
   `newly_passing` (remove these), `newly_failing` (regressions), and
   `still_failing`.
6. **`pkc scaffold --lang <x>`**: emit the testee skeleton for the ABI in
   that language's conventional layout (go `cmd/conformance`, python
   `conformance_runner.py`, ...) plus `expectations/<x>.toml` claiming
   nothing, and the Justfile recipe.
7. **Per-case timeout** (default 10 s offline, 120 s interop), kill and
   report `timeout`. Stderr drained per case and attached.
8. **Seeded mutations.** `fill --seed`, nightly job with a random seed
   against every SDK, results reported but not gating.
9. **`harness/AGENTS.md`** and `skills/sdk-conformance/SKILL.md`: the loop,
   the ABI, the rules. Reference it from `CLAUDE.md`.
10. **CI policy**: a diff to `expectations/*.toml` that adds `known_failing`
    without an `issue` field fails the lint.

### Success criteria

- From a clean clone with only the SDK's toolchain installed, `pkc run
  --sdk <x> --tier offline` produces results in under 60 s.
- Every failure output contains the six elements in DESIGN.md §6.2;
  a test asserts the markdown has all six sections for a planted failure.
- `pkc next` on an SDK with a planted class of 10 failures (one operator
  broken) returns one group of 10 with one fix brief.
- A testee that returns the committed expected bytes verbatim (a planted
  "cheater") passes the committed fill and fails the seeded nightly.
- `pkc scaffold --lang python` output runs and reports every case as
  `unsupported`, not as an error.

### Traps

- **Decoders drift from programs.** Pin the decoders to the vendored IDLs
  (`idl/`) and generate the data-field parsers from them, do not hand-write.
- **Reference line numbers rot.** Store function names and resolve to lines
  at report time; a test fails if a name no longer resolves.
- **Too much output.** An agent's context is finite. Default to the first
  divergent path and the representative case; `--verbose` for the full tree.
- **`pkc next` ordering.** Smallest group first can starve a big class that
  blocks everything (for example the testee not honouring `PKC_CLOCK`).
  Mark such cases `blocking` in metadata and surface them first.
- **Agents editing vectors.** Generated vectors are read-only by `fill
  --check`; authored vectors are not. Add a CODEOWNERS entry for
  `harness/vectors/authored/` and say so in AGENTS.md.

## Phase 3: `pkc run --tier interop` with the Rust pivot (2–3 weeks)

### Tasks

1. **Embedded pivot.** `src/run/pivot.rs`: start the Rust MPP and x402
   servers (axum, `MemoryStore`, `MemoryChannelStore`,
   `with_blockhash_cache`) and expose a Rust client that pays any URL.
   Both sit behind a `Fault` layer (same operator enum as `mutate.rs`,
   applied to the HTTP layer: challenge, credential, receipt).

2. **Validator.** One surfpool per `pkc run` via `surfpool-sdk` (reuse the
   `start_surfnet` logic from `charge_integration.rs`), funding via
   cheatcodes, mint deployment per scenario as the TS harness does today in
   `src/intents/`.

3. **Testee ops.** `server.start {protocol, scheme, config} → {port}`,
   `server.stop`, `client.pay {url, config} → result`, `store.dump`. Keep
   the env variable names from `src/contracts.ts` inside `config` so the
   existing adapter bodies can be wrapped rather than rewritten.

4. **Scenarios.** Port `harness/src/intents/{charge,x402-exact,x402-upto,session}.ts`
   (32 scenarios) and the structural assertions from `test/e2e.test.ts`
   into interop cases. Port the Rust integration tests in
   `charge_integration.rs` and `settlement_onchain.rs` as described in
   DESIGN.md §3.6. The replay proxy in `src/replay.ts` becomes the
   `ReplaySame` fault.

5. **Matrix.** On PR: every SDK in each claimed role against the Rust pivot,
   including Rust against Rust. Nightly (`schedule:` in `harness.yml`): full
   pairwise over claimed capabilities. Path-based selection remains, with
   any change under `rust/` or `harness/` running everything.

6. **Retire.** vitest e2e tests, `src/implementations.ts`, `src/intents/`,
   `src/process.ts`, `src/replay.ts`, `src/ci-matrix.ts`, `emit-ci-matrix.ts`,
   and each `harness/<lang>-{client,server}/` directory once that language's
   testee covers it. `mpp-matrix.yml` folds into `harness.yml`.

### Success criteria

- Every scenario id from `src/intents/*.ts` exists as an interop case id and
  the structural assertions (transfer set, split amounts, ATA creation,
  memo, balance deltas, no extra transfers) are asserted in Rust.
- Every negative Rust integration test runs against every server SDK via a
  fault, and a client-side fault set (expired challenge, wrong network,
  over-asking price, mis-signed challenge) runs against every client SDK.
- `charge_integration.rs` and `settlement_onchain.rs` deleted or reduced to
  a thin wrapper that calls `pkc run --sdk rust`.
- PR CI time for the interop tier is not worse than today's `harness.yml` +
  `mpp-matrix.yml` combined (measure before and after; record in the PR).
- `harness/` contains no `*-client/` or `*-server/` directories.

### Traps

- **Surfpool per test** is why the Rust integration tests are slow. One per
  `run`, reset state between cases by fresh keypairs and fresh mints, not by
  restarting.
- **Port collisions** when many testees start servers. The testee picks the
  port and reports it; the driver never assigns one.
- **Fault layer on the wrong side.** A server-side fault must mutate the
  challenge/receipt the Rust server emits; a client-side fault must mutate
  the credential the Rust client sends. Do not implement faults as "ask the
  testee to misbehave". Testees are always honest.
- **Settlement is async.** Several servers settle on a worker after
  returning 200. Assert settlement by polling the validator for the
  signature with a bounded deadline, as the TS harness does, and record the
  settlement latency in results.
- **Treasury pinned to the mainnet build** (README Limitations). Carry that
  constant into the Rust driver as a named constant with the same caveat.
- **Deleting adapters too early.** Delete a language's adapter directory in
  the same PR that proves its testee passes the same case ids.

## Phase 4: close the documented gaps (ongoing)

- Session, x402 upto, batch-settlement, subscription cases in all three
  tiers. Subscription needs plan bootstrap; batch-settlement is
  spec-drafted, not implemented in every SDK, so most cells start as
  `unsupported` with reasons.
- On-chain tier moved into `pkc run --tier onchain`, replacing
  `test/onchain.e2e.test.ts`; the treasury-mismatch check lives in Rust.
- Traceability report: `pkc report` emits the requirement × SDK matrix,
  the unmapped-MUST count trends down, and spec text drift under a mapped
  id fails CI.
- Success: README coverage table has no hand-maintained cells, and the
  three documented known gaps in `harness/README.md` are either covered or
  listed as `unsupported` with an issue.

## Cross-cutting rules for the implementer

- One PR per phase at most; smaller is better. Phase 0 must merge before
  phase 1 starts so expectations files exist to seed from.
- Never fix an SDK bug inside a harness PR. File it, add to `known_failing`
  with the issue, keep going. The harness PR's job is to make the bug
  visible, not to hide it by fixing it quietly.
- Any time a case is removed or relaxed, the PR description names the case
  and the reason. Reviewers should grep the diff for deleted case ids.
- Do not add env vars. Capabilities live in toml, selection in `pkc` flags.
- Run `cargo fmt`, `cargo clippy`, `pnpm lint`, and the full harness
  locally with all gates forced before pushing a phase PR. Record the
  before/after counts of `pass / fail / known_failing / unsupported` in the
  PR description.
- Commits: `feat(harness): ...`, `fix(harness): ...`, `chore(harness): ...`.
  No AI trailers on commits to the x402 fork submodule.

## Definition of done for the whole effort

1. A new normative statement added to mpp-specs or x402 for SVM shows up as
   an unmapped requirement in CI within one PR.
2. A new reject check added in Rust becomes a vector for every SDK by
   running `pkc fill`, with no TS or per-SDK edit.
3. An SDK that stops implementing a capability cannot go green by declaring
   less; the change to its expectations file is the review surface.
4. Every SDK is tested against Rust in every claimed role on every PR, and
   against every other SDK nightly.
5. The README coverage table is a build artifact.
