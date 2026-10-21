# Conformance: working on an SDK against the harness

For agents (and people) making an SDK pass the shared conformance vectors.
Design: [DESIGN.md](DESIGN.md) §3 and §6. Repository rules:
[CONTRIBUTING.md](../CONTRIBUTING.md).

All commands run from `rust/` (`pkc` is `cargo run -q -p paykit-conformance
--bin pkc --`; after one `cargo build -p paykit-conformance` you can call
`rust/target/debug/pkc` directly). No network, validator or secrets: every
vector's chain state comes from a fixture RPC the driver starts.

## The loop

```sh
pkc next --sdk python                     # the smallest failing class, blocking ones first, with a fix brief
pkc case run --sdk python <vector-id>     # one case, seconds; prints the six-part failure report
pkc case show <vector-id>                 # input, decoded expectation, mutation, spec quote, Rust reference
pkc run --sdk python --tier offline       # the whole offline tier, seconds
pkc run --sdk python --diff-expectations  # newly_passing / newly_failing / still_failing vs the toml
```

1. `pkc next` groups failures (unexpected ones and the `known_failing` work
   queue) by requirement, bug type and expected code. Fix the class, not the
   instance: every id in the group shares the cause.
2. Read the failure report. In order it gives the normative sentence (with the
   pinned spec SHA), the mutation in words, the decoded expected and actual
   values with the first divergent field, `file:line` of the Rust code that
   produced the expected value, the testee's stderr, and the replay command
   with the raw request.
3. Fix the **SDK**. Add a unit test in the SDK that fails before the fix.
4. Re-run the group, then the tier. Remove the entries your fix made stale
   from `harness/expectations/<sdk>.toml`: a `known_failing` case that passes
   fails the run until you remove it, and so does an `[[unsupported]]` case the
   testee starts handling.
5. Before pushing: `pkc run --sdk <sdk> --tier offline --require` (what CI
   runs) and the SDK's own formatter, linter and tests.

## Interop against the Rust reference

```sh
pkc run --tier interop --sdk python,rust          # every claimed case pairing python with Rust (build with --features interop)
pkc run --tier interop --case charge-basic/rust/python
pkc run --tier interop --shard python --require   # what `Conformance / python` runs
```

A case is `interop/<scenario>/<client>/<server>`; one side is always Rust.
A failure prints the assertion, the client's result, every exchange the fault
proxy saw, and both adapters' stderr. Gaps go in `known_failing` of the toml
of the side at fault (the client's for client faults, the server's
otherwise), with a FINDINGS.md section. Scenarios live in
`rust/crates/conformance/src/interop/scenarios.rs`; never narrow one with
`Participants::Only` to hide a failing SDK.

## Rules

- **Never edit a vector to make it pass.** `harness/vectors/` is filled by
  `pkc fill` from the case registry in `rust/crates/conformance/src/cases/`
  and checked byte for byte in CI (`pkc fill --check`). If a vector looks
  wrong, the filler (or the Rust kit) is wrong: file it against the filler,
  quote the spec sentence, and add an authored case with the divergence
  recorded (`authored(Some(reason))`) rather than changing the expected value
  to match an SDK.
- **Never put logic in the testee.** The testee passes the vector's input to
  the SDK unchanged, including `input.rpcUrl`. It never fills defaults,
  resolves token programs, applies field precedence or builds envelopes. If a
  case needs that logic, the SDK needs it.
- **The toml is the review surface.** Every `[[unsupported]]` entry needs a
  precise reason; every `[[known_failing]]` entry needs a reason and a
  `tracking` link (a GitHub issue or `FINDINGS.md#anchor`). The parser rejects
  entries without them. Never fix an SDK bug quietly inside a harness change.
- **No new env vars.** Selection is `pkc` flags; capabilities are the toml.
- **Testees keep no state across cases.** A served process handles many
  cases; reset per-process singletons before each one. `--legacy` (one
  process per case) must give identical results.

## Testee ABI

Documented in [README.md](README.md#testee-abi). In short: one long-lived
process (`serve` in `runners/<sdk>.json`), newline JSON
`{id, op, input}` -> `{id, ok, result | error}`, ops `capabilities`, `build`,
`verify`, `canonical-bytes`. `input` is the v1 vector (no `expect`), `result`
the v1 `RunnerResult` plus the built `transaction` / `x402PaymentHeader` on an
accepted build. Diagnostics go to stderr. Every case has a 10 s timeout.

`capabilities` returns `{abi: 2, intents, honoursClock}` and must match the
toml's `capabilities.vector` and `capabilities.honours_clock`.

## A new SDK

```sh
pkc scaffold --lang python --sdk mysdk --dir mysdk   # testee, runner manifest, toml claiming nothing
pkc run --sdk mysdk --tier offline --discover        # every vector, reported unsupported, nothing judged
```

Then implement one mode at a time in the order canonical bytes, verify, build;
claim the intent in the toml and in the testee's `INTENTS` as it passes; list
what the SDK cannot express under `[[unsupported]]`. Add a CI step running
`pkc run --sdk mysdk --tier offline --require` (`harness/test/ci-coverage.test.ts`
fails until one exists).

## Where things are

| What | Where |
| --- | --- |
| Case registry (inputs, verdicts, spec refs) | `rust/crates/conformance/src/cases/` |
| Mutation operators and their reject codes | `rust/crates/conformance/src/mutate.rs` |
| Driver, judge, failure reports | `rust/crates/conformance/src/run/` |
| Vectors (generated) and annotated views | `harness/vectors/`, `harness/vectors/annotated/` |
| Expectations per SDK | `harness/expectations/<sdk>.toml` |
| Spec rulings where SDKs disagreed | `harness/expectations/RULINGS.md` |
| Results of the last run | `harness/results/<sdk>.json`, `<sdk>.failures.json`, `junit-<sdk>.xml` |
| Requirements (the denominator) | `harness/requirements/{mpp,x402}.toml`, `pkc req-lint` |
