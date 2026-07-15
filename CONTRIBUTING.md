# Contributing

## Pull request scope

Keep changes reviewable and independently green. Use one pull request per language when a coherent SDK feature or refactor is language-owned. Use one pull request per protocol flaw when the same invariant must change in multiple SDKs, for example `fix(upto): bind settlement amounts in Ruby and TypeScript`.

Stacked pull requests must name their base and merge order. Do not mix unrelated language cleanup, protocol security changes, generated artifacts, and CI infrastructure solely to reduce the number of pull requests.

## Verification

Run the focused SDK tests, lint, typecheck, format, coverage, and owned harness legs before requesting review. Changes to shared vectors, schemas, routing, or harness infrastructure must run the full matrix; unknown paths deliberately fall back to full verification.

Security guards need an adversarial reject case that executes the real verifier, plus a valid accept case proving the guard is not over-broad. A declared verifier mode without both outcomes is treated as untested.

## Large pull requests and Greptile

Greptile may skip diffs above its 100-file review ceiling. Prefer splitting those changes by language or protocol. When a large mechanical migration cannot be split safely:

1. Separate and document the mechanical and semantic portions of the diff.
2. Keep the exact head green and resolve human review findings first.
3. Post `@greptile-apps please review` once on the meaningful final head.
4. Record the reviewed head commit in the pull request description; request another review only after a semantic change.

This bypass is review friction, not a substitute for focused tests, the full integration matrix, or maintainer approval.
