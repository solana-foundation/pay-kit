---
name: sdk-conformance
description: Make a Pay Kit SDK pass the shared conformance vectors with `pkc` (rust/crates/conformance). Use when asked to "fix conformance for <language>", "make <sdk> pass the vectors", "work the known_failing list", "add a conformance testee", "scaffold a new SDK testee", or when a `pkc run` / harness CI step fails. Covers the pkc loop, the testee ABI and the rules (never edit a vector; fix the SDK, not the runner).
---

# SDK conformance with pkc

The shared vectors under `harness/vectors/` are filled from the Rust kit by
`pkc fill`. Every SDK ships a testee (`harness/runners/<sdk>.json`) that `pkc
run` drives offline: no network, no validator, chain state from a fixture RPC
passed as `input.rpcUrl`. What each SDK must pass is
`harness/expectations/<sdk>.toml`, reconciled exactly in both directions.

Full guide: `harness/AGENTS.md`. ABI: `harness/README.md#testee-abi`.

## Loop

Run from `rust/` (`pkc` = `cargo run -q -p paykit-conformance --bin pkc --`):

1. `pkc next --sdk <sdk>`: the smallest failing class (blocking classes such
   as timeouts or ABI violations first), every case id in it, the spec
   sentence, the Rust reference and a replay command.
2. `pkc case run --sdk <sdk> <id>`: the failure report (requirement,
   mutation, decoded expected vs actual with the first divergent field,
   `file:line` reference, testee stderr, replay request).
3. `pkc case show <id>` when you need the input and decoded expectation.
4. Fix the SDK; add an SDK unit test that fails before the fix.
5. `pkc run --sdk <sdk> --tier offline --diff-expectations`, then remove the
   now-passing ids from `known_failing` (the run fails until you do).
6. `pkc run --sdk <sdk> --tier offline --require` before pushing, plus the
   SDK's formatter, linter and tests.

## Rules

- Never edit a vector to make it pass; file against the filler
  (`rust/crates/conformance/src/cases/`) with the spec quote.
- Testees pass input to the SDK unchanged: no defaults, no token-program
  resolution, no precedence, no envelope building in the testee.
- Every `[[unsupported]]` needs a reason; every `[[known_failing]]` a reason
  and `tracking` (GitHub issue or `FINDINGS.md#anchor`).
- Fix the class, not the instance: re-run the whole group from `pkc next`.
- Do not add env vars; use `pkc` flags.
- A served testee keeps no state across cases; `--legacy` must agree.

## New SDK

`pkc scaffold --lang <python|typescript|go|ruby|php|lua> --sdk <name> --dir <path>`
writes the testee, manifest and a toml claiming nothing; `pkc run --sdk <name>
--tier offline --discover` then reports every vector unsupported. Implement
canonical bytes, then verify, then build; claim intents as they pass; add the
CI step `pkc run --sdk <name> --tier offline --require`.
