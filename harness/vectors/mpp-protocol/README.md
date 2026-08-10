# MPP protocol conformance vectors (canonical)

> **Two provenances live in this directory.** Every file except
> `expires-rfc3339-corpus.json` is imported verbatim from `tempoxyz/mpp-tools`
> and is described immediately below. `expires-rfc3339-corpus.json` is a
> separate import with its own upstreams and its own licence files — see
> [RFC 3339 `expires` corpus](#rfc-3339-expires-corpus).

These JSON vector files are **imported verbatim** from
[`tempoxyz/mpp-tools`](https://github.com/tempoxyz/mpp-tools)
(`conformance/vectors/`), the canonical IETF-spec conformance suite for the
MPP `Payment` HTTP authentication scheme. They are the protocol **oracle**:
the golden inputs and expected outputs that every pay-kit SDK's protocol
layer (challenge / credential / receipt header codec, base64url, and the
challenge-id HMAC) is validated against.

| File | Operation(s) | Spec reference |
|------|--------------|----------------|
| `www-authenticate.json` | `challenge.parse`, `challenge.format` | draft-ietf-httpauth-payment §5.1 |
| `authorization.json`    | `credential.parse`, `credential.format` | draft-ietf-httpauth-payment §5.2 |
| `receipt.json`          | `receipt.parse`, `receipt.format` | draft-ietf-httpauth-payment §5.3 |
| `base64url.json`        | `base64url.encode`, `base64url.decode` | RFC 4648 §5 |
| `challenge-id.json`     | `challenge.id` (HMAC-SHA256) | draft-ietf-httpauth-payment §5.1.1 |

## Challenge-id derivation (the protocol math)

The challenge id is:

```
base64url( HMAC-SHA256( secretKey,
  realm | method | intent | base64url(JCS(request)) | expires | digest | opaque
) )   // no padding; "|" is a literal pipe; absent optional fields are ""
```

`request` is canonicalized with RFC 8785 JCS (sorted keys, no insignificant
whitespace) and base64url-encoded before it enters the pipe-joined HMAC input.
`opaque` enters the pipe as its already-serialized string form.

## Scenario shape extensions (upstream b15fea4e)

Beyond the original `{ name, object, wire, tests }` shape, header scenarios
may carry:

- **Constructed `wire`** — instead of a literal string, `wire` may be an
  object `{ "prefix": "...", "repeat": "...", "count": N, "suffix": "..." }`.
  The materialized wire is `prefix + repeat.repeat(count) + suffix` (absent
  fields default to `""` / `0`), mirroring the canonical runner's
  `scenario_wire`. Used for adversarial inputs too large to vendor literally
  (e.g. `adversarial_unclosed_quoted_extension`, a 12k-backslash unclosed
  quoted extension param probing ReDoS-style parser backtracking).
- **`adapters`** — an allow-list of adapter/language names. When present, the
  scenario only runs against runners whose language is listed (the canonical
  runner skips it for everyone else).
- **`maxDurationMs` / `maxDurationMsByAdapter`** — wall-clock budget (ms) for
  the operation. The per-adapter map wins over the scalar; a passing result
  that exceeds the budget is recorded as a failure
  (`duration exceeded: expected <= L ms, got E ms`).

## Source / attribution

Applies to every file in this directory **except** `expires-rfc3339-corpus.json`.

- Upstream: `tempoxyz/mpp-tools`, `conformance/vectors/`
- Upstream commit: `b15fea4ee3f12da7ece735dc778ad84102af679c` (2026-06-08)
- License: MIT, Copyright (c) 2026 Tempo — see `LICENSE.mpp-tools` in this directory.

Do not hand-edit these files. To refresh, re-copy from the upstream repo and
bump the commit reference above.

## RFC 3339 `expires` corpus

| File | Operation(s) | Spec reference |
|------|--------------|----------------|
| `expires-rfc3339-corpus.json` | `expires.parse` | RFC 3339 §5.6 (grammar), §5.7, §5.8, §4.2–§4.3, App. C, App. D |

RFC 3339 date / time / date-time **parse** conformance vectors for the MPP
`expires` field (issue #111). Read by `loadExpiresRfc3339()` /
`collectExpiresCases()` in `harness/src/protocol/vectors.ts`. It uses the same
`{ version, spec_ref, description, commands, scenarios }` file shape and the
same `tests.parse` verdict encoding as the canonical files above:

```
"tests": { "parse": true }                                              // ACCEPT
"tests": { "parse": { "success": false, "error_type": "parse_error" } } // REJECT
```

**Read `applies_to` before you read `tests.parse`.** The corpus holds vectors
for three different RFC 3339 productions — `date-time` (116), `full-date` (74),
`full-time` (38) — and a verdict only means what it says inside its own
production. MPP `expires` holds a `date-time`. **Filter to
`applies_to == "date-time"` before running anything against an `expires`
parser**; 29 of the other 112 carry ACCEPT for inputs (`1963-06-19`,
`08:30:06Z`, …) that an `expires` parser is *correct* to reject.
`collectExpiresCases()` applies that filter. The corpus's own `scope` block
states this at length.

No `object` golden is supplied for ACCEPT scenarios — deliberately. #111 is a
verdict-alignment problem, not an instant-normalisation problem.

### Source / attribution (this file only)

Three upstreams, none of them mpp-tools. The corpus's own top-level
`attribution` object carries the full notices; the summary:

- **RFC 3339** — Klyne & Newman, July 2002, retrieved 2026-08-07 from
  `https://www.rfc-editor.org/rfc/rfc3339.txt`. Copyright (C) The Internet
  Society (2002); reproduction permitted per the RFC's own notice, carried
  verbatim in `attribution.rfc_3339.notice`.
- **JSON Schema Test Suite** —
  [`json-schema-org/JSON-Schema-Test-Suite`](https://github.com/json-schema-org/JSON-Schema-Test-Suite),
  `tests/draft2020-12/optional/format/date-time.json`. Upstream commit
  `15fe552d6cf76e29cc8165306fb6a72503fd360b` (2026-08-06). MIT, Copyright (c)
  2012 Julian Berman — see `LICENSE.json-schema-test-suite` in this directory.
- **Go standard library** — [`golang/go`](https://github.com/golang/go),
  `src/time/format_test.go`. Upstream commit
  `c19862e5f8415b4f24b189d065ed739517c548ba` (tag `go1.26.5`). BSD-3-Clause,
  Copyright 2009 The Go Authors — see `LICENSE.go-stdlib` in this directory;
  additional patent grant in `PATENTS.go-stdlib`.

Every scenario additionally carries its own `provenance` object naming the
source repo, commit sha, commit date, file, and (for extracted rows) the exact
source line.

Do not hand-edit this file. To refresh, re-run the import from the upstream
repos and bump the commit references in the corpus's `attribution` block and
above.
