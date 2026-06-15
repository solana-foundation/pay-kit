# MPP protocol conformance vectors (canonical)

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

- Upstream: `tempoxyz/mpp-tools`, `conformance/vectors/`
- Upstream commit: `b15fea4ee3f12da7ece735dc778ad84102af679c` (2026-06-08)
- License: MIT, Copyright (c) 2026 Tempo — see `LICENSE.mpp-tools` in this directory.

Do not hand-edit these files. To refresh, re-copy from the upstream repo and
bump the commit reference above.
