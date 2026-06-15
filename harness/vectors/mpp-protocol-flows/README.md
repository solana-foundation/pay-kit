# MPP flow conformance suite (canonical)

These files are imported from
[`tempoxyz/mpp-tools`](https://github.com/tempoxyz/mpp-tools)
(`conformance/flows/`), the canonical HTTP 402 **flow** suite for the MPP
`Payment` HTTP authentication scheme. Where the vectors in
`../mpp-protocol/` exercise individual protocol ops, this suite exercises
the full client flow against a live server: initial request -> 402 +
`WWW-Authenticate` -> `challenge.parse` -> build credential ->
`credential.format` -> retry with `Authorization` -> `Payment-Receipt` ->
`receipt.parse`. All flow cases use the `tempo` method.

| File | Role |
|------|------|
| `flows.json` | Flow case definitions (path, request, payload, and behavior knobs like `invalid_challenge_id`, `digest_binding`, `concurrent_replay`, ...). Verbatim from upstream. |
| `golden-results.json` | Expected per-case results recorded from the canonical TypeScript adapter. Verbatim from upstream. |
| `compliance-server.ts` | The runner-owned HTTP server serving the flow endpoints (issues tempo-method challenges, verifies credentials, emits receipts / problem+json). Vendored with ONE documented deviation (see below). |

The orchestration that drives a protocol adapter through these cases is the
pay-kit port of the normative `conformance/scripts/flow_runner.py`:
`harness/src/protocol/flow-driver.ts`, exercised by
`harness/test/flow-conformance.test.ts`.

## Deviations from verbatim vendoring

`compliance-server.ts` differs from upstream in exactly one place
(documented in its header comment as well):

1. The dynamic JSON import of `MPP_FLOW_CASES` uses
   `with: { type: 'json' }` instead of upstream's
   `assert: { type: 'json' }`. Node >= 23 removed the legacy `assert`
   import-assertion keyword; semantics are identical.

`flows.json` and `golden-results.json` are byte-for-byte upstream.

Note the upstream server pins `mppx@0.6.29` while the harness resolves
`mppx@^0.5.5`; the flow conformance test proves the served challenges,
receipts, and golden results line up regardless.

## Source / attribution

- Upstream: `tempoxyz/mpp-tools`, `conformance/flows/`
- Upstream commit: `b15fea4ee3f12da7ece735dc778ad84102af679c` (2026-06-08)
- License: MIT, Copyright (c) 2026 Tempo — see `LICENSE.mpp-tools` in this
  directory (copied alongside, identical to
  `../mpp-protocol/LICENSE.mpp-tools`).

Do not hand-edit these files. To refresh, re-copy from the upstream repo,
re-apply the documented deviation, and bump the commit reference above.
