# Contributing

## Correctness by construction

Payment code fails open in subtle ways: a check at one call site gets skipped by a sibling path, a second replica, a later refactor, or another SDK. Fix the class, not the instance:

- **Make invalid states unrepresentable.** Validate once at the boundary into a newtype with a private constructor (parse, don't validate). Prefer enums to bool/`Option` flags. No `Default` for security-relevant config.
- **Make required steps unskippable.** If B must follow check A, have A return a value (guard, token, proof) that B takes as an argument: a lock guard to write a journal, a reservation token to commit, a "not landed" proof to replace a transaction.
- **Put atomicity in the contract.** Check-and-reserve belongs inside one storage operation, not in callers. Every implementation of a storage trait runs the same shared test suite.
- **Cover every exit path.** Metering, settlement and cleanup that must happen run from a guard/`Drop` or a spawned task that a cancelled request cannot drop.
- **Enforce, don't document.** Prefer a compile error, then a test that fails in default CI, then a comment.
- **Keep SDKs in lockstep.** A wire or security invariant fixed in one language is a bug in every other until ported. Add it as a shared vector in [`harness/`](harness/README.md) that runs for every SDK in default CI, not behind an opt-in matrix.

## Before submitting

- Run the formatter, linter and tests for every language you touched.
- Use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:`, ...).
- Behavioural fixes ship with a regression test that fails before the change, plus a positive control.
