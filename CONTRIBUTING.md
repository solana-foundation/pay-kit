# Contributing

## Correctness by construction

Payment code fails open in subtle ways: a check at one call site gets skipped by a sibling path, a second replica, a later refactor, or another SDK. Fix the class, not the instance:

- **Make invalid states unrepresentable.** Validate once at the boundary into a newtype with a private constructor (parse, don't validate). Prefer enums to bool/`Option` flags. No `Default` for security-relevant config.
- **Make required steps unskippable.** If B must follow check A, have A return a value (guard, token, proof) that B takes as an argument: a lock guard to write a journal, a reservation token to commit, a "not landed" proof to replace a transaction.
- **Put atomicity in the contract.** Check-and-reserve belongs inside one storage operation, not in callers. Every implementation of a storage trait runs the same shared test suite.
- **Cover every exit path.** Metering, settlement and cleanup that must happen run from a guard/`Drop` or a spawned task that a cancelled request cannot drop.
- **Enforce, don't document.** Prefer a compile error, then a test that fails in default CI, then a comment.
- **Keep SDKs in lockstep.** A wire or security invariant fixed in one language is a bug in every other until ported. Add it as a shared vector in [`harness/`](harness/README.md) that runs for every SDK in default CI, not behind an opt-in matrix.

## Fixing a bug in one SDK

A bug found in one language is a conformance gap until every SDK is checked. Work spec first, test second, fix last.

1. **Find the normative text.** Quote the sentence in [mpp-specs](https://github.com/tempoxyz/mpp-specs) or [x402](https://github.com/x402-foundation/x402/tree/main/specs) the code violates. If the spec is silent or ambiguous, add or extend an entry in [`harness/expectations/RULINGS.md`](harness/expectations/RULINGS.md) with the quote and the reading, and propose a spec change upstream. Another SDK's behaviour, including Rust's, is not a ruling.
2. **Reproduce it as a shared case before touching the SDK.**
   - Single-shot input and output (wire bytes, build, verify): add a vector under `harness/vectors/`. Its `description` names the spec section and the rule, for example `draft-solana-charge-00 methodDetails: decimals "MUST be present when currency is a mint address"`.
   - Pair every reject vector with an accept vector that differs only in the field under test, so a vector that rejects for the wrong reason is caught. Reject vectors set `rejectCode`.
   - Chain state goes in `rpcFixtures` and is served by the fixture RPC. Never put a precomputed answer in the input, and never pin a placeholder transaction.
   - Transactions in verify vectors are real. Add them to a generator such as `harness/gen-x402-verify-vectors.ts`, not by hand.
   - Multi-step behaviour (replay, retries, concurrency, lifecycles): add an interop scenario under `harness/src/intents/` until the sequence suite exists, and say in the PR that a vector could not express it.
   - If a vector already covers the bug and passes, the vector or the runner is wrong. Fix that first.
3. **Run the new case against every SDK.**
   ```sh
   cd harness
   HARNESS_EXPECTATIONS_DISCOVER=1 HARNESS_PREBUILT_DIR= pnpm exec vitest run test/conformance.test.ts
   ```
   Read `harness/results/vector.<language>.json`. Every SDK that fails has the same bug. Fix it in this PR, or list it in that SDK's `harness/expectations/<language>.toml` under `[[known_failing]]` with a reason and `tracking` pointing at an issue.
4. **Fix the SDK, never the runner.** Runners pass the vector's input to the SDK unchanged, including `input.rpcUrl`. They never fill defaults, resolve token programs, apply field precedence or build envelopes themselves. If a runner needs logic to pass a vector, that logic belongs in the SDK. Validate at the SDK boundary, and add a unit test in the SDK that fails before the fix.
5. **Reconcile and regenerate.** Remove the entries your fix makes stale. The run fails if a listed known failure passes or an unsupported entry is handled. Then regenerate:
   ```sh
   cd harness
   pnpm coverage && pnpm interop && pnpm vectors:x402
   HARNESS_REQUIRE=1 HARNESS_PREBUILT_DIR= MPP_CONFORMANCE_LANGUAGES=<languages you touched> \
     pnpm exec vitest run test/conformance.test.ts test/protocol-conformance.test.ts test/expectations.test.ts
   ```

### Adding an SDK capability

- **Claim it** in `harness/expectations/<language>.toml`. An unclaimed suite shows as `—` in the README table, never as a pass.
- **Make sure CI runs it.** Add the language to a CI step with `HARNESS_REQUIRE=1`; `test/ci-coverage.test.ts` fails otherwise.
- **Declare what the runner cannot express.** List it under `[[unsupported]]` with a precise reason, for example "server-only SDK, no client builder". The driver still executes those cases and fails if the runner starts handling them.

### Reviewing a conformance change

- **Removed or relaxed cases** need a reason in the PR description; grep the diff for deleted vector ids and expectations entries.
- **New `known_failing` and `unsupported` entries** are the review surface: each needs a reason, and known failures need a tracking reference.
- **Generated files** (`harness/README.md` tables, generated vectors) are never edited by hand; CI checks them for staleness.

## Before submitting

- Run the formatter, linter and tests for every language you touched.
- Use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:`, ...).
- Behavioural fixes ship with a regression test that fails before the change, plus a positive control.
- Wire or verification fixes also ship with a shared conformance case (see [Fixing a bug in one SDK](#fixing-a-bug-in-one-sdk)).
