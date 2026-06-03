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

The interop-critical primitives hold. **base64url is 100% PASS across all 7
SDKs (140/140 cells).** **challenge.id (the cross-impl HMAC) is PASS for all
SDKs except one Go case** (`html_sensitive_request_canonicalization`), and that
one is a real, high-severity Go bug (RFC 8785 JCS escaping of `< > &`).

Every other divergence is in the WWW-Authenticate / Authorization / Receipt
header codec layer, and almost all of it is one of three coherent clusters
(not random one-off bugs):

1. `description` parameter is lost on challenge round-trip in most SDKs.
2. Error-detection is too lax: several SDKs accept malformed credentials and
   receipts that the canonical spec rejects.
3. PHP has an empty-object encoding bug (`{}` serialized as `[]`) plus a stricter
   header parser that drops a trailing `description` parameter.

Verdict: our SDKs **substantially conform** on the wire-critical math
(base64url + HMAC), but the header codec layer has real, clustered gaps that
need decisions — some are plain SDK bugs, two clusters are genuine
pay-kit-vs-spec questions for Ludo.

Legend: `PASS` = byte/semantic match to canonical. `PASS~` = byte-different but
semantically equal after re-parse (benign serialization order). `DIV` =
divergence (real mismatch). `UNSUP` = runner returned no usable answer.

## Divergence matrix

### www-authenticate

| op :: scenario | go | lua | php | python | ruby | rust | typescript |
|---|---|---|---|---|---|---|---|
| `challenge.parse` :: basic_challenge | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.format` :: basic_challenge | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: full_challenge | PASS | PASS | **DIV** | PASS | **DIV** | PASS | PASS |
| `challenge.format` :: full_challenge | **DIV** | **DIV** | PASS~ | **DIV** | PASS~ | **DIV** | PASS |
| `challenge.parse` :: empty_request | PASS | PASS | **DIV** | PASS | PASS | PASS | PASS |
| `challenge.format` :: empty_request | PASS | PASS | PASS~ | PASS | PASS | PASS | PASS |
| `challenge.parse` :: nested_request | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.format` :: nested_request | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: unescaped_quotes_in_description | **DIV** | **DIV** | **DIV** | PASS | **DIV** | PASS | PASS |
| `challenge.parse` :: escaped_quotes_in_description | PASS | PASS | **DIV** | PASS | **DIV** | PASS | PASS |
| `challenge.parse` :: error_missing_payment_prefix | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_id | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_realm | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_method | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_intent | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_missing_request | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_invalid_base64url | PASS | PASS | PASS | PASS | UNSUP | PASS | PASS |
| `challenge.parse` :: error_invalid_json | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `challenge.parse` :: whitespace_tolerance | PASS | PASS | **DIV** | PASS | PASS | PASS | PASS |
| `challenge.parse` :: parameter_order_independence | PASS | PASS | **DIV** | PASS | PASS | PASS | PASS |
| `challenge.parse` :: unknown_extension_parameter | PASS | PASS | **DIV** | PASS | PASS | PASS | PASS |
| `challenge.parse` :: case_insensitive_scheme | PASS | PASS | **DIV** | PASS | PASS | PASS | PASS |
| `challenge.parse` :: error_empty_id | PASS | PASS | PASS | PASS | PASS | PASS | **DIV** |
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
| `credential.parse` :: error_invalid_base64url | PASS | PASS | PASS | PASS | UNSUP | PASS | PASS |
| `credential.parse` :: error_missing_challenge | **DIV** | PASS | PASS | PASS | PASS | PASS | PASS |
| `credential.parse` :: error_missing_challenge_id | **DIV** | **DIV** | **DIV** | **DIV** | PASS | PASS | PASS |
| `credential.parse` :: error_invalid_json_structure | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

### receipt

| op :: scenario | go | lua | php | python | ruby | rust | typescript |
|---|---|---|---|---|---|---|---|
| `receipt.parse` :: success_receipt | **DIV** | PASS | PASS | PASS | **DIV** | PASS | PASS |
| `receipt.format` :: success_receipt | PASS~ | PASS | PASS | PASS~ | **DIV** | PASS | PASS |
| `receipt.parse` :: error_invalid_base64url | PASS | PASS | PASS | PASS | UNSUP | PASS | PASS |
| `receipt.parse` :: error_invalid_json | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `receipt.parse` :: error_missing_status | **DIV** | **DIV** | PASS | **DIV** | PASS | PASS | PASS |
| `receipt.parse` :: error_missing_method | **DIV** | **DIV** | PASS | **DIV** | PASS | PASS | PASS |
| `receipt.parse` :: error_missing_reference | **DIV** | **DIV** | PASS | **DIV** | PASS | PASS | PASS |
| `receipt.parse` :: error_missing_timestamp | **DIV** | **DIV** | PASS | **DIV** | PASS | PASS | PASS |
| `receipt.parse` :: error_non_iso8601_timestamp | **DIV** | **DIV** | **DIV** | **DIV** | PASS | **DIV** | PASS |

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
| `challenge.id` :: html_sensitive_request_canonicalization | **DIV** | PASS | PASS | PASS | PASS | PASS | PASS |
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

## Cluster analysis (DIV cells)

### Cluster A — `description` challenge parameter lost on round-trip [LIKELY LUDO QUESTION]

Affected: go, lua, python, rust (on `challenge.format`); php, ruby (on
`challenge.parse`). Only TypeScript round-trips `description` cleanly.

- `challenge.format::full_challenge`: go/lua/python/rust **omit** the
  `description="..."` parameter from the produced WWW-Authenticate header. The
  canonical wire includes it. php/ruby keep it (their DIV here is only param
  ordering, shown as `PASS~`).
- `challenge.parse::full_challenge` and `escaped_quotes_in_description`:
  php/ruby **drop** `description` when parsing, so the parsed object is missing
  the field the canonical object has.

Net: every SDK except TS loses `description` at some stage of the challenge
header round-trip, just at different stages. This is consistent enough to be a
deliberate pay-kit design choice (treat `description` as advisory / out of the
typed Challenge shape) rather than 5 independent bugs. **Spec question for
Ludo: is `description` a first-class, round-trippable WWW-Authenticate
parameter, or advisory metadata pay-kit is free to drop?** The canonical
vectors say it must round-trip.

### Cluster B — lax error detection on malformed input [MIXED: real bugs + one spec question]

#### B1. `receipt.parse` missing-required-field acceptance [SDK BUGS]
Affected: go, lua, python (rust/php pass).
- `error_missing_status`, `error_missing_method`, `error_missing_reference`,
  `error_missing_timestamp`: go/lua/python **accept** a receipt that omits a
  required field; canonical rejects with `parse_error`. These are SDK
  validation gaps — the receipt parser does not enforce required fields.

#### B2. `receipt.parse::error_non_iso8601_timestamp` [LIKELY LUDO QUESTION]
Affected: go, lua, php, python, rust (5 of 7; only ruby + TS reject).
- The canonical vector requires rejecting a receipt whose `timestamp` is not
  ISO-8601. Five of seven SDKs accept it. A 5/7 cluster on a single semantic
  rule (timestamp format validation) points at a shared assumption that the
  receipt codec does not validate timestamp shape. **Spec question for Ludo:
  must the receipt parser reject non-ISO-8601 timestamps, or is timestamp
  validation a layer above the protocol codec?**

#### B3. `credential.parse::error_missing_challenge_id` [SDK BUGS]
Affected: go, lua, php, python (rust + ruby pass).
- A credential whose embedded challenge has no `id` is accepted by 4 SDKs;
  canonical rejects with `parse_error`. The credential parser does not enforce
  that the nested challenge carries an `id`.

#### B4. `credential.parse::error_missing_challenge` [SDK BUG, one-off]
Affected: go only.
- Go accepts a credential with no `challenge` at all. One-off Go validation gap.

### Cluster C — PHP empty-object / strict-parse cluster [SDK BUGS, php-only]

Affected: php only, but a coherent group.
- `challenge.parse::empty_request`, `whitespace_tolerance`,
  `parameter_order_independence`, `unknown_extension_parameter`,
  `case_insensitive_scheme`: php emits `"request":[]` instead of `"request":{}`.
  Root cause: PHP serializes an empty associative array as a JSON array `[]`.
  An empty decoded request object must be forced to `{}` (e.g.
  `json_encode((object)$req)` or `JSON_FORCE_OBJECT`).
- `challenge.parse::full_challenge`, `escaped_quotes_in_description`,
  `unescaped_quotes_in_description`: php drops `description` (overlaps Cluster A)
  and its header tokenizer rejects an unescaped-quote description that the
  canonical parser tolerates.

### Critical one-offs

#### D1. Go challenge.id JCS HTML-escaping [CRITICAL SDK BUG]
`challenge.id::html_sensitive_request_canonicalization` — go only.
- Go produces id `1MZrSBSf...` vs canonical `9wuIbToT...`.
- Root cause: Go's `encoding/json` escapes `<`, `>`, `&` to the `<`,
  `>`, `&` unicode forms by default. The canonicalized request bytes
  that feed the HMAC are therefore `...<premium> & analytics...`
  instead of the RFC 8785 JCS literal `...<premium> & analytics...`. Verified by
  decoding Go's emitted `request=` param: it contains the `<` escapes.
- Impact: **any** charge whose request contains `<`, `>`, or `&` (common in
  free-text descriptions, URLs, query strings) yields a Go challenge-id that no
  other SDK and no canonical server will accept. This breaks cross-impl
  challenge verification silently. Fix: disable HTML escaping in the JCS
  serializer (`json.Encoder.SetEscapeHTML(false)` or a JCS-correct encoder).
  This is the single highest-priority fix.

#### D2. TypeScript accepts empty challenge id [SDK BUG, reference runner]
`challenge.parse::error_empty_id` — typescript only.
- The reference SDK accepts a challenge with `id=""`; canonical rejects with
  `parse_error`. Notable because TS is the reference everything else is
  validated against — the per-language runners were checked against TS, so this
  gap could have been propagated. (It was not: other SDKs correctly reject.)

#### D3. Go/Ruby receipt extra/required-field shape on `success_receipt` [SDK BUGS]
- `receipt.parse::success_receipt`: go adds `challengeId:""` to the parsed
  object (canonical has no such key); ruby requires a `challengeId` key and
  errors when absent (`key not found: "challengeId"`), and the same on
  `receipt.format::success_receipt`. The canonical receipt shape has no
  `challengeId`. Ruby's receipt codec hard-requires a field the spec does not
  define; go injects an empty one.

## UNSUP cells (runner harness bug, NOT an SDK divergence)

`challenge.parse / credential.parse / receipt.parse :: error_invalid_base64url`
— ruby (3 cells).
- The Ruby SDK correctly raises a parse error on a request param that
  base64url-decodes to invalid UTF-8. The Ruby **runner** then crashes trying
  to `JSON.generate` an error message that embeds the raw non-UTF-8 bytes
  (`JSON::GeneratorError: source sequence is illegal/malformed utf-8`). This is
  a runner-harness bug (sanitize the error string before serializing), not a
  protocol divergence. Once fixed these 3 cells should be PASS.

## Operations no SDK supports

None. All 7 SDKs implement all 9 canonical operations; there are zero
`unsupported_operation` results. (The 3 UNSUP cells above are a ruby runner
crash, not missing operations.)

## Prioritized action list

### Fix in SDK (clear bugs)

1. **[CRITICAL] Go challenge.id JCS HTML-escaping (D1).** Disable HTML escaping
   in Go's JCS request canonicalization. Breaks challenge-id interop for any
   `< > &` in the request. Highest priority — silent cross-impl auth failure.
2. **Go/lua/python receipt required-field validation (B1).** Reject receipts
   missing `status` / `method` / `reference` / `timestamp`.
3. **Go/lua/php/python credential missing-challenge-id validation (B3).** Reject
   credentials whose nested challenge has no `id`.
4. **Go credential missing-challenge validation (B4).**
5. **PHP empty-object encoding (C).** Force empty request to `{}` not `[]`.
6. **Ruby receipt `challengeId` over-requirement (D3).** Drop the hard
   `challengeId` requirement from the receipt codec; it is not in the canonical
   receipt shape. Also fix go injecting `challengeId:""`.
7. **TypeScript empty-id acceptance (D2).** Reject `id=""` on challenge parse.
8. **PHP unescaped-quote description tolerance (part of C / A).**

### Fix in harness (not SDK)

9. **Ruby runner non-UTF-8 error serialization (UNSUP).** Sanitize error
   strings before `JSON.generate`. Unblocks 3 false-UNSUP cells.

### Spec questions for Ludo (do not mass-fix)

A. **`description` round-trip (Cluster A).** Is `description` a first-class
   round-trippable WWW-Authenticate parameter (canonical says yes), or advisory
   metadata pay-kit may drop from the typed Challenge? 6 of 7 SDKs drop it at
   some stage — looks like a shared design decision, not 6 bugs.

B. **Receipt non-ISO-8601 timestamp rejection (B2).** Must the protocol-layer
   receipt parser validate timestamp format (canonical says reject), or is that
   a higher layer's job? 5 of 7 SDKs accept it.

## Reproduce

```
# from repo root, branch feat/mpp-protocol-conformance
cd harness
pnpm install --frozen-lockfile
pnpm exec node --import tsx src/protocol/divergence-matrix.mts
# writes harness/divergence-raw.json
```

Per-runner prereqs: `go` (toolchain), `php` (`composer install` in php/),
`ruby` (`bundle install` in ruby/), `python` (`uv`), `lua` (luajit), `rust`
(`cargo build -q -p solana-mpp --example protocol_runner`).
