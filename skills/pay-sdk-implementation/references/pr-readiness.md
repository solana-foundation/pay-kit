# PR readiness

Use this before tagging a new language PR ready for review.

## Required evidence

- CI job exists for the language.
- Formatter and linter run in CI.
- Unit tests pass.
- Coverage is reported in CI and is at least 90 percent, or the PR documents a
  concrete tooling exception and compensating evidence.
- End-to-end interop runs through the TypeScript harness.
- The README includes language badge, coverage badge, repo layout, runnable
  snippet, example instructions, Solana dependency table, and client/server
  compatibility matrices.
- Public methods/classes/structs have doc comments useful for LSP/IDE hover.
- Greptile feedback is fixed, stale because of later commits, or explicitly
  documented as non-actionable.

## Ready-for-review comment

When ready, comment with this shape:

```text
@<maintainer> Greptile feedback is addressed here and I think this is ready for review.

Skill pass:
- payment SDK implementation skill: current
- language skill/guide: <name>

Addressed points:
- <what changed>

Verification:
- <unit/coverage command>
- <interop command or CI job>

Known limits:
- <unimplemented matrix cells, if any>
```

## Capability matrix discipline

Do not mark `mpp/session`, `mpp/subscription`, or any x402 cell as shipped just
because the repo layout contains future reference files. A cell is shipped only
when that target language has code, tests, coverage, and interop evidence for
that cell.
