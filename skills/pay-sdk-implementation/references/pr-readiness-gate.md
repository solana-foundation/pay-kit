# PR readiness gate

Use this gate before marking any language PR ready for review. Keep the
transcript local while working, then summarize the evidence in the PR
body.

## Source of truth read

Record the exact sources used for the pass:

- This skill's `SKILL.md` and every referenced file for the enabled
  matrix cells.
- Rust reference files cited by those intent leaves.
- The current language implementation and README.
- One language best-practice skill or credible source, read before code.
- Relevant examples and interop adapters in Rust / TypeScript.

Do not claim parity from memory. If a source says "see X.rs", open it.

## Unit tests

Record:

- Test command.
- Number of tests run.
- Coverage percent and the gate used.
- New tests added for every new behavior.

The default coverage gate for new SDKs is 90 percent. If a legacy SDK has
a lower gate, keep the lower gate only if the PR explicitly explains why
raising it is out of scope.

## Static checks

Record the language-local commands for:

- Format check.
- Lint.
- Type/static analysis when the language has a standard tool.
- Dependency audit.

These commands should be available through the language-local `justfile`
and, where useful, mirrored by root justfile recipes.

## Interop

Record all focused cells that apply:

- TypeScript client -> language server.
- Rust client -> language server.
- Language client -> Rust server.
- Language client -> language server, when the language has both roles.

Server adapters must run the target language's SDK directly. They must
not depend on a TypeScript wrapper for challenge issuance, settlement,
or replay behavior.

## Manual DX

Before review, manually run the documented examples:

- Start the simple-server example.
- Confirm unpaid `curl` returns 402.
- Confirm `pay curl` returns 200.
- Start the framework middleware example (Laravel for PHP, Rack for
  Ruby, or the idiomatic equivalent).

If manual verification needs Surfpool or another service, document the
exact command and whether it was run locally or left as a CI-only check.

## Known limitations

State limitations plainly:

- Client-only or server-only.
- Pull-only or push-only.
- Verification-only vs full settlement.
- Unsupported intents.
- Missing coverage tooling or manual DX gaps.

Do not hide limitations behind green unit tests.
