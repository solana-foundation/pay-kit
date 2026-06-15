# MPP protocol conformance: pay-kit SDKs vs canonical mpp-tools

Divergence matrix and findings from driving every pay-kit SDK protocol runner
against the canonical `tempoxyz/mpp-tools` conformance vectors (vendored at
`harness/vectors/mpp-protocol/`, upstream commit `09b968af`).

- Oracle: canonical mpp-tools vectors (the golden inputs/outputs).
- SDKs under test: go, lua, php, python, ruby, rust, typescript (reference).
- Driver: `harness/src/protocol/divergence-matrix.mts` (captures raw bytes;
  raw output at `harness/divergence-raw.json`).
- Operations: `challenge.parse/format`, `credential.parse/format`,
  `receipt.parse/format`, `base64url.encode/decode`, `challenge.id`.
- Total cells: 90 cases x 7 SDKs = 630.

## Headline

**The matrix is fully green: 630/630 cells PASS, zero DIV, zero UNSUP.**
Every pay-kit SDK now conforms byte-for-byte (or semantically, after re-parse)
to the canonical mpp-tools protocol vectors across all nine operations.

Group totals (each cell = one scenario x one SDK):

| group | cases | cells | PASS | DIV | UNSUP |
|---|---|---|---|---|---|
| www-authenticate | 26 | 182 | 182 | 0 | 0 |
| authorization | 10 | 70 | 70 | 0 | 0 |
| receipt | 9 | 63 | 63 | 0 | 0 |
| base64url | 20 | 140 | 140 | 0 | 0 |
| challenge-id | 25 | 175 | 175 | 0 | 0 |
| **total** | **90** | **630** | **630** | **0** | **0** |

The two harness-critical primitives are 100% exact-byte PASS: **base64url
(140/140)** and **challenge.id, the cross-impl HMAC (175/175)** — including the
`html_sensitive_request_canonicalization` case that previously exposed the Go
RFC 8785 JCS HTML-escaping bug. The header codec layer
(WWW-Authenticate / Authorization / Receipt parse+format) is now also fully
green; the remaining benign `PASS~` cells are byte-different-but-semantically-
equal serialization orderings on `*.format` ops, which the driver treats as
PASS after a round-trip re-parse.

Legend: `PASS` = byte/semantic match to canonical. `PASS~` = byte-different but
semantically equal after re-parse (benign serialization order; counted as PASS).
`DIV` = divergence (real mismatch). `UNSUP` = runner returned no usable answer.

## Divergence matrix

### www-authenticate

| op :: scenario | go | lua | php | python | ruby | rust | typescript |
|---|---|---|---|---|---|---|---|
| `challenge.parse` :: basic_challenge | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.format` :: basic_challenge | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: full_challenge | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.format` :: full_challenge | PASS | PASS~ | PASS~ | PASS | PASS~ | PASS | PASS |
| `challenge.parse` :: empty_request | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.format` :: empty_request | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: nested_request | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.format` :: nested_request | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: unescaped_quotes_in_description | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: escaped_quotes_in_description | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_payment_prefix | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_id | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_realm | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_method | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_intent | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_request | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_invalid_base64url | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_invalid_json | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: whitespace_tolerance | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: parameter_order_independence | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: unknown_extension_parameter | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: case_insensitive_scheme | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_empty_id | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_duplicate_parameters | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_empty_header | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_scheme_only | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

### authorization

| op :: scenario | go | lua | php | python | ruby | rust | typescript |
|---|---|---|---|---|---|---|---|
| `credential.parse` :: basic_credential | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `credential.format` :: basic_credential | PASS | PASS~ | PASS~ | PASS~ | PASS~ | PASS~ | PASS~ |
| `credential.parse` :: credential_with_source | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `credential.format` :: credential_with_source | PASS~ | PASS~ | PASS~ | PASS~ | PASS~ | PASS~ | PASS~ |
| `credential.parse` :: credential_with_expires | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `credential.parse` :: error_missing_payment_prefix | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `credential.parse` :: error_invalid_base64url | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `credential.parse` :: error_missing_challenge | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `credential.parse` :: error_missing_challenge_id | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `credential.parse` :: error_invalid_json_structure | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

### receipt

| op :: scenario | go | lua | php | python | ruby | rust | typescript |
|---|---|---|---|---|---|---|---|
| `receipt.parse` :: success_receipt | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `receipt.format` :: success_receipt | PASS~ | PASS | PASS | PASS~ | PASS | PASS | PASS |
| `receipt.parse` :: error_invalid_base64url | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `receipt.parse` :: error_invalid_json | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `receipt.parse` :: error_missing_status | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `receipt.parse` :: error_missing_method | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `receipt.parse` :: error_missing_reference | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `receipt.parse` :: error_missing_timestamp | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `receipt.parse` :: error_non_iso8601_timestamp | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

### base64url

| op :: scenario | go | lua | php | python | ruby | rust | typescript |
|---|---|---|---|---|---|---|---|
| `base64url.encode` :: empty_string | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.decode` :: empty_string | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.encode` :: hello_world | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.decode` :: hello_world | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.encode` :: json_object | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.decode` :: json_object | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.encode` :: url_chars | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.decode` :: url_chars | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.encode` :: padding_1_byte | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.decode` :: padding_1_byte | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.encode` :: padding_2_bytes | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.decode` :: padding_2_bytes | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.encode` :: no_padding | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.decode` :: no_padding | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.encode` :: url_safe_chars | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.decode` :: url_safe_chars | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.encode` :: special_ascii | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.decode` :: special_ascii | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.encode` :: whitespace | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `base64url.decode` :: whitespace | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

### challenge-id

| op :: scenario | go | lua | php | python | ruby | rust | typescript |
|---|---|---|---|---|---|---|---|
| `challenge.id` :: required_fields_only | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: with_expires | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: with_digest | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: with_expires_and_digest | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: with_opaque | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: opaque_route_scope_binding | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: description_not_in_hmac | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: multi_field_request | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: nested_method_details | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: html_sensitive_request_canonicalization | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: resource_path_query_binding | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: external_id_request_binding | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: fee_payer_policy_binding | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: empty_request | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: different_realm | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: different_method | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: different_intent | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: basic_charge | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: with_expires_alt_secret | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: with_digest_alt_secret | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: full_challenge_alt_secret | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: different_secret_different_id | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: empty_request_alt_secret | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: unicode_in_description | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.id` :: nested_method_details_alt_secret | PASS | PASS | PASS | PASS | PASS | PASS | PASS |


## What was fixed (previously-DIV / UNSUP cells, now PASS)

Every fix below is codec-layer only — no Solana settlement, charge, or x402
path was touched. The canonical vectors were NOT weakened to force green.

### challenge `description` round-trip (was Cluster A)
go, lua, python, rust no longer drop the `description="..."` WWW-Authenticate
parameter on `challenge.format`; php and ruby no longer drop it on
`challenge.parse`. `challenge.format::full_challenge` is PASS everywhere
(`PASS~` for lua/php/ruby = benign parameter-ordering difference, semantically
equal after re-parse). The canonical decision: `description` is a first-class,
round-trippable parameter and stays out of the HMAC (confirmed still PASS by
`challenge.id::description_not_in_hmac`).

### receipt required-field + timestamp validation (was Cluster B1/B2)
go, lua, python now reject receipts missing `status` / `method` / `reference` /
`timestamp` with `parse_error`. The non-ISO-8601 timestamp case
(`receipt.parse::error_non_iso8601_timestamp`) is now rejected by all 7 SDKs
(previously go/lua/php/python/rust accepted it).

### credential missing-challenge / missing-challenge-id (was Cluster B3/B4)
go now rejects a credential with no `challenge`; go, lua, php, python now
reject a credential whose nested challenge has no `id`
(`credential.parse::error_missing_challenge_id` PASS across all SDKs).

### PHP empty-object + strict-parse cluster (was Cluster C)
PHP serializes an empty request as `{}` (not `[]`), so
`challenge.parse::empty_request`, `whitespace_tolerance`,
`parameter_order_independence`, `unknown_extension_parameter`,
`case_insensitive_scheme` are PASS. PHP's header tokenizer now tolerates the
non-param / unescaped-quote `description` cases and round-trips `description`.

### Go challenge.id JCS HTML-escaping (was critical one-off D1)
`challenge.id::html_sensitive_request_canonicalization` is PASS. Go's JCS
request canonicalizer no longer HTML-escapes `< > &`, so the HMAC input bytes
match RFC 8785 across every SDK. This closes the silent cross-impl
challenge-verification break for any request containing `< > &`.

### TypeScript empty challenge id (was one-off D2)
`challenge.parse::error_empty_id` is PASS. The reference SDK now rejects a
challenge with `id=""` (HMAC-bound id must be non-empty), matching canonical.

### Go/Ruby receipt shape on success_receipt (was one-off D3)
`receipt.parse/format::success_receipt` is PASS. Go no longer injects
`challengeId:""`; ruby no longer hard-requires a `challengeId` key the
canonical receipt shape does not define. The `challengeId` field is omitted
when empty.

### Ruby runner non-UTF-8 error serialization (was UNSUP, harness-side)
`challenge.parse / credential.parse / receipt.parse :: error_invalid_base64url`
are PASS for ruby (previously UNSUP). The Ruby runner now sanitizes the error
string before `JSON.generate`, so the SDK's correct `parse_error` surfaces
instead of a runner crash. This was a runner-harness fix, not an SDK behavior
change.

## Residual divergences

None. All 90 scenarios x 7 SDKs = 630 cells PASS. No DIV, no UNSUP, no
`unsupported_operation`. All 7 SDKs implement all 9 canonical operations.

## Per-SDK test status (no regression)

| SDK | suite | result |
|---|---|---|
| go | `go test ./protocols/mpp/wire/...` | ok |
| lua | `luajit tests/run.lua` | 549 passed, 1 skipped, 0 failed |
| php | `phpunit` | 360 tests, 924 assertions, 0 failures |
| python | `pytest` (headers/challenge/base64url/canonical_json) | 99 passed |
| ruby | `bundle exec rake` | 387 runs, 1085 assertions, 0 failures |
| rust | `cargo test -p solana-mpp --lib protocol` | 206 passed, 0 failed |
| typescript | reference runner (drives matrix in-process) | green |

## Reproduce

```
# from repo root, branch feat/mpp-protocol-conformance
cd harness
pnpm install --frozen-lockfile
pnpm exec node --import tsx src/protocol/divergence-matrix.mts
# writes harness/divergence-raw.json
```

Per-runner prereqs: `go` (toolchain), `php` (`composer install` in php/),
`ruby` (`bundle install` in ruby/), `python` (`uv sync`), `lua` (luajit +
`luarocks --tree lua_modules install luasodium`), `rust`
(`cargo build -q -p solana-mpp --example protocol_runner`), `typescript`
(build `typescript/packages/mpp` then `pnpm install` in harness/).
