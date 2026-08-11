# MPP protocol conformance vectors (canonical)

> **Two provenances live in this directory.** Every file except `expires.json` is imported
> verbatim from `tempoxyz/mpp-tools` and is described immediately below. `expires.json` is a
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

Applies to every file in this directory **except** `expires.json`.

- Upstream: `tempoxyz/mpp-tools`, `conformance/vectors/`
- Upstream commit: `b15fea4ee3f12da7ece735dc778ad84102af679c` (2026-06-08)
- License: MIT, Copyright (c) 2026 Tempo — see `LICENSE.mpp-tools` in this directory.

Do not hand-edit these files. To refresh, re-copy from the upstream repo and
bump the commit reference above.

## RFC 3339 `expires` corpus

| File | Operation(s) | Spec reference |
|------|--------------|----------------|
| `expires.json` | `expires.parse` | RFC 3339 §5.6 |

RFC 3339 **parse** conformance vectors for the MPP `expires` field (issue #111): 124 scenarios, 54 ACCEPT and 70 REJECT. Same
`{ version, spec_ref, description, commands, scenarios }` file shape, same `{ name, description, tags, … , tests }`
row shape and the same verdict encoding as the canonical files above:

```
"tests": { "parse": true }                                              // ACCEPT
"tests": { "parse": { "success": false, "error_type": "parse_error" } } // REJECT
```

Every scenario in the file is an `expires` verdict and every scenario is exercised. There is no
filter to apply and no scenario a consumer should skip. No `object` golden is supplied for an
ACCEPT — deliberately: #111 is a verdict-alignment problem, not an instant-normalisation one, and
leap seconds have no representable instant in most date libraries.

### Source / attribution (this file only)

Three upstreams, none of them mpp-tools.

- **RFC 3339** — "Date and Time on the Internet: Timestamps", Klyne & Newman, July 2002.
  Retrieved 2026-08-07 from `https://www.rfc-editor.org/rfc/rfc3339.txt`. Copyright (C) The
  Internet Society (2002); reproduction and derivative works permitted per the RFC's own notice.
- **JSON Schema Test Suite** —
  [`json-schema-org/JSON-Schema-Test-Suite`](https://github.com/json-schema-org/JSON-Schema-Test-Suite),
  `tests/draft2020-12/optional/format/date-time.json` and `.../date.json` and `.../time.json`.
  Commit `15fe552d6cf76e29cc8165306fb6a72503fd360b` (2026-08-06). MIT, Copyright (c) 2012 Julian
  Berman — see `LICENSE.json-schema-test-suite` in this directory.
- **Go standard library** — [`golang/go`](https://github.com/golang/go),
  `src/time/format_test.go`, tables `parseTests`, `parseErrorTests` and
  `longFractionalDigitsTests`. Commit `c19862e5f8415b4f24b189d065ed739517c548ba` (tag `go1.26.5`).
  BSD-3-Clause, Copyright 2009 The Go Authors — see `LICENSE.go-stdlib` in this directory;
  additional patent grant in `PATENTS.go-stdlib`.

### Per-row provenance

Provenance is recorded here rather than on every row, so that the vector file reads like its
neighbours. Each shipped scenario belongs to exactly one class:

| class | shipped rows | what it means | verdict authority |
|---|---|---|---|
| `imported_verbatim` | 27 | input and verdict copied byte-for-byte from the JSON Schema Test Suite at the pinned commit; descriptions are the upstream's own and are not rewritten | JSON Schema Test Suite |
| `extracted_from_source` | 27 | input lifted from a test table in Go stdlib source at the pinned commit. `parseTests` and `longFractionalDigitsTests` rows fail the Go test on a parse error, so the table asserts Go ACCEPTS them; `parseErrorTests` rows fail the Go test when parsing succeeds, so the table asserts Go REJECTS them | Go stdlib |
| `derived_from_rfc_text` | 58 | derived from the §5.6 grammar, the §5.7 restrictions and the §5.8 worked examples, with the deciding section recorded per row | RFC 3339 |
| `hand_authored` | 4 | written against the ABNF to close a boundary the imports left open | RFC 3339 |
| authored for this file | 8 | the wrong-production rejections and the empty string, below | RFC 3339 §5.6 |

### Dedupe rule

Byte-exact on the `input` string. No normalisation and no case folding: two vectors differing only by `T` vs `t`, or by surrounding whitespace, are two vectors.

Precedence when two sources carry the same input: `imported_verbatim` → `extracted_from_source` → `hand_authored` → `derived_from_rfc_text`. Tie-break: same provenance type: the earlier position in the source file wins.

**6 duplicates dropped, 0 verdict disagreements** between sources.

| input | kept | dropped | verdicts agree |
|---|---|---|---|
| `22:59:60Z` | `jsts_time_006` (imported_verbatim, REJECT) | `jsts_time_029` (imported_verbatim) | yes |
| `23:58:60Z` | `jsts_time_007` (imported_verbatim, REJECT) | `jsts_time_030` (imported_verbatim) | yes |
| `2020-11-28T23:55:45Z` | `jsts_date_039` (imported_verbatim, REJECT) | `jsts_time_041` (imported_verbatim) | yes |
| `1937-01-01T12:00:27.87+00:20` | `jsts_date_time_003` (imported_verbatim, ACCEPT) | `rfc_5_8_example_twenty_minute_offset` (derived_from_rfc_text) | yes |
| `1998-12-31T23:59:60Z` | `jsts_date_time_005` (imported_verbatim, ACCEPT) | `leap_second_december_month_end` (derived_from_rfc_text) | yes |
| (the empty string) | `jsts_date_047` (imported_verbatim, REJECT) | `empty_string` (derived_from_rfc_text) | yes |

### Independent audit

All 170 imported vectors were re-derived by hand from the text of RFC 3339 by a second author who did not
build the import. **Result: 169 AGREE, 0 DIVERGE, 1 UNRESOLVED-PROVENANCE.** Verdicts changed by the merge: 0.
The RFC text used was pinned at sha256
`9ab2b8864a85dca73a88f49b0927bc7bc85f596926e4fd1890905777924e700a`.

### Not shipped — and why. Nothing was deleted.

The import considered 235 inputs and settled 228 scenarios across three RFC 3339
productions. This file ships the 124 that are `expires` verdicts. The other 104 are listed individually
below, with the rule that excluded each one.

#### Unresolved provenance (1)

A vector whose verdict could not be tied to an RFC 3339 section by the S4 audit does not ship here. It travels in EVIDENCE.md as a finding about the specification, which is its entire purpose.

- **`jsts_date_070`**, input `1582-10-10` (upstream ACCEPT) — UNRESOLVED-PROVENANCE. RFC 3339 does not decide whether a date inside the 1582 Julian-to-Gregorian reform gap is valid: §5.6 is purely syntactic, §5.7 constrains only the maximum mday, and neither §2 nor Appendix C qualifies "the Gregorian calendar" as proleptic or historical. The upstream suite asserts valid: true.

#### Disputed — RFC 3339 does not settle these (5)

Recorded rather than quietly decided. Each is a literal whose verdict the text does not pin down; a
maintainer wanting one of them decided should say which way.

| input | candidate verdicts | why it is not settled |
|---|---|---|
| `2026-01-29 12:00:00Z` | reject / accept | RFC 3339 §5.6 ABNF is date-time = full-date "T" full-time, which mandates a literal "T". But the second NOTE in the same section reads: "ISO 8601 defines date and time separated by 'T'. |
| `2026-03-15T23:59:60Z` | reject / accept | Second = 60 on a date that is not a June or December month end. §5.7 permits time-second = 60 "at the end of months in which a leap second occurs -- to date: June (XXXX-06-30T23:59:60Z) or December (XXXX-12-31T23:59:60Z)" and adds "At all other times the maximum value of time-second is 59". |
| `2026-06-30T23:59:60Z` | accept / reject | Second = 60 at a June month end in a year for which no leap second was announced. Positionally this is exactly the shape §5.7 names as permitted (XXXX-06-30T23:59:60Z), so a grammar-only reading ACCEPTS. |
| `  2026-01-29T12:00:00Z  ` | reject / accept | Surrounding whitespace. RFC 3339 §5.6 defines the date-time production and nothing else; it does not say whether a protocol field carrying a date-time may be padded. |
| `9999-12-31T23:59:59+00:01` and `0000-01-01T00:00:00-00:01` | accept / reject | Lexically valid date-times whose offset-adjusted UTC instant falls outside the four-digit year range (year 10000 and year -0001 respectively). §5.6 date-fullyear = 4DIGIT constrains the LEXICAL year only. |

#### Wrong production, or a duplicate failure shape (104)

The import covered three RFC 3339 productions because the upstream suites do: `date-time` (the one
`expires` holds), `full-date` (a bare `YYYY-MM-DD`) and `full-time` (a bare time with an offset). A
`full-date` or `full-time` verdict is a correct statement about a different production and is **not**
an `expires` verdict. Those rows are admitted here only when their `expires` verdict follows
mechanically from §5.6 `date-time = full-date "T" full-time` — that is, when the input is well
formed in its own production and therefore cannot also be a `date-time`. Seven such rows ship, one
per distinct failure shape, plus one restoration:

| shipped as | input | the failure shape it covers |
|---|---|---|
| `bare_date_no_time` | `1963-06-19` | a well-formed bare full-date |
| `bare_date_leap_day` | `2020-02-29` | a bare full-date on a calendar edge — catches a parser that checks the calendar before the shape |
| `bare_time_zulu` | `08:30:06Z` | a well-formed bare full-time |
| `bare_time_lowercase_z` | `08:30:06z` | catches a parser keying on an upper-case `Z` |
| `bare_time_numeric_offset` | `08:30:06-08:00` | catches a parser keying on `Z` at all |
| `bare_time_secfrac` | `23:20:50.52Z` | catches a parser keying on the `.` |
| `bare_time_leap_second` | `23:59:60Z` | catches a leap-second special-case path |
| `empty_string` | `(the empty string)` | restores the `date-time` empty-string row that the dedupe rule above absorbed into `jsts_date_047` |

The remaining rows are listed below. Every one of them still carries a correct verdict for its own
production; none is retracted and none is deleted.

##### `verdict-would-flip` (1)

**Excluded because re-expressing it would flip a verdict.**

`jsts_date_039`, input `2020-11-28T23:55:45Z`, production `full-date`, verdict REJECT. That input is a fully conforming RFC 3339
date-time. Upstream ships it in `.../format/date.json` as a negative case for the `full-date`
production — a date-time is not a bare `YYYY-MM-DD`, so REJECT is the right `full-date` answer. As an
`expires` verdict it would invert to ACCEPT. It is excluded rather than re-adjudicated.

##### `wrong-production-shape-already-represented` (22)

**Well formed in its own production, but its `expires` failure shape is already covered by one of the eight rows above.** The eleven month-length variants are one failure shape to an `expires` parser, not eleven.

| name | input | production | its own verdict |
|---|---|---|---|
| `jsts_date_002` | `2020-01-31` | `full-date` | ACCEPT |
| `jsts_date_004` | `2021-02-28` | `full-date` | ACCEPT |
| `jsts_date_006` | `2020-03-31` | `full-date` | ACCEPT |
| `jsts_date_008` | `2020-04-30` | `full-date` | ACCEPT |
| `jsts_date_010` | `2020-05-31` | `full-date` | ACCEPT |
| `jsts_date_012` | `2020-06-30` | `full-date` | ACCEPT |
| `jsts_date_014` | `2020-07-31` | `full-date` | ACCEPT |
| `jsts_date_016` | `2020-08-31` | `full-date` | ACCEPT |
| `jsts_date_018` | `2020-09-30` | `full-date` | ACCEPT |
| `jsts_date_020` | `2020-10-31` | `full-date` | ACCEPT |
| `jsts_date_022` | `2020-11-30` | `full-date` | ACCEPT |
| `jsts_date_024` | `2020-12-31` | `full-date` | ACCEPT |
| `jsts_date_041` | `0400-02-29` | `full-date` | ACCEPT |
| `jsts_date_052` | `0001-01-01` | `full-date` | ACCEPT |
| `jsts_time_008` | `23:59:60+00:00` | `full-time` | ACCEPT |
| `jsts_time_011` | `01:29:60+01:30` | `full-time` | ACCEPT |
| `jsts_time_012` | `23:29:60+23:30` | `full-time` | ACCEPT |
| `jsts_time_015` | `15:59:60-08:00` | `full-time` | ACCEPT |
| `jsts_time_016` | `00:29:60-23:30` | `full-time` | ACCEPT |
| `jsts_time_020` | `08:30:06.283185Z` | `full-time` | ACCEPT |
| `jsts_time_021` | `08:30:06+00:20` | `full-time` | ACCEPT |
| `jsts_time_023` | `12:34:56-00:00` | `full-time` | ACCEPT |

##### `wrong-production-malformed` (81)

**Malformed within its own production.** Every parser rejects these for a reason that has nothing to do with production confusion, so they add no `expires` coverage.

| name | input | production | its own verdict |
|---|---|---|---|
| `jsts_date_003` | `2020-01-32` | `full-date` | REJECT |
| `jsts_date_005` | `2020-02-30` | `full-date` | REJECT |
| `jsts_date_007` | `2020-03-32` | `full-date` | REJECT |
| `jsts_date_009` | `2020-04-31` | `full-date` | REJECT |
| `jsts_date_011` | `2020-05-32` | `full-date` | REJECT |
| `jsts_date_013` | `2020-06-31` | `full-date` | REJECT |
| `jsts_date_015` | `2020-07-32` | `full-date` | REJECT |
| `jsts_date_017` | `2020-08-32` | `full-date` | REJECT |
| `jsts_date_019` | `2020-09-31` | `full-date` | REJECT |
| `jsts_date_021` | `2020-10-32` | `full-date` | REJECT |
| `jsts_date_023` | `2020-11-31` | `full-date` | REJECT |
| `jsts_date_025` | `2020-12-32` | `full-date` | REJECT |
| `jsts_date_026` | `06/19/1963` | `full-date` | REJECT |
| `jsts_date_027` | `2013-350` | `full-date` | REJECT |
| `jsts_date_028` | `1998-1-20` | `full-date` | REJECT |
| `jsts_date_029` | `1998-01-1` | `full-date` | REJECT |
| `jsts_date_030` | `1998-13-01` | `full-date` | REJECT |
| `jsts_date_031` | `2021-02-29` | `full-date` | REJECT |
| `jsts_date_033` | `1963-06-1৪` | `full-date` | REJECT |
| `jsts_date_034` | `2020-0৪-01` | `full-date` | REJECT |
| `jsts_date_035` | `20230328` | `full-date` | REJECT |
| `jsts_date_036` | `2023-W01` | `full-date` | REJECT |
| `jsts_date_037` | `2023-W13-2` | `full-date` | REJECT |
| `jsts_date_038` | `2022W527` | `full-date` | REJECT |
| `jsts_date_040` | `0100-02-29` | `full-date` | REJECT |
| `jsts_date_042` | `2100-02-29` | `full-date` | REJECT |
| `jsts_date_043` | ` 2024-01-15` | `full-date` | REJECT |
| `jsts_date_044` | `2024-01-15 ` | `full-date` | REJECT |
| `jsts_date_045` | `2024-00-15` | `full-date` | REJECT |
| `jsts_date_046` | `2024-01-00` | `full-date` | REJECT |
| `jsts_date_048` | `2020 -01-01` | `full-date` | REJECT |
| `jsts_date_049` | `2020-01-01X` | `full-date` | REJECT |
| `jsts_date_050` | `2020-01-01Z` | `full-date` | REJECT |
| `jsts_date_051` | `2020-01-01 00:00:00Z` | `full-date` | REJECT |
| `jsts_date_053` | `20-01-01` | `full-date` | REJECT |
| `jsts_date_054` | `998-01-01` | `full-date` | REJECT |
| `jsts_date_055` | `12020-01-01` | `full-date` | REJECT |
| `jsts_date_056` | `+2020-01-01` | `full-date` | REJECT |
| `jsts_date_057` | `-2020-01-01` | `full-date` | REJECT |
| `jsts_date_058` | `২020-01-01` | `full-date` | REJECT |
| `jsts_date_059` | `YYYY-01-01` | `full-date` | REJECT |
| `jsts_date_060` | `2020-001-01` | `full-date` | REJECT |
| `jsts_date_061` | `2020-MM-01` | `full-date` | REJECT |
| `jsts_date_062` | `2020-01-001` | `full-date` | REJECT |
| `jsts_date_063` | `2020-01-DD` | `full-date` | REJECT |
| `jsts_date_064` | `2020:01:01` | `full-date` | REJECT |
| `jsts_date_065` | `2020.01.01` | `full-date` | REJECT |
| `jsts_date_066` | `2020 01 01` | `full-date` | REJECT |
| `jsts_date_067` | `2020-01/01` | `full-date` | REJECT |
| `jsts_date_068` | `2020--01-01` | `full-date` | REJECT |
| `jsts_date_069` | `2020-01--01` | `full-date` | REJECT |
| `jsts_date_071` | `2147483648-01-01` | `full-date` | REJECT |
| `jsts_date_072` | `2020-01-0:` | `full-date` | REJECT |
| `jsts_date_073` | `২0-01-01` | `full-date` | REJECT |
| `jsts_date_074` | `2020–01–01` | `full-date` | REJECT |
| `jsts_date_075` | `2020-01-01\x00` | `full-date` | REJECT |
| `jsts_time_002` | `008:030:006Z` | `full-time` | REJECT |
| `jsts_time_003` | `8:3:6Z` | `full-time` | REJECT |
| `jsts_time_004` | `8:0030:6Z` | `full-time` | REJECT |
| `jsts_time_006` | `22:59:60Z` | `full-time` | REJECT |
| `jsts_time_007` | `23:58:60Z` | `full-time` | REJECT |
| `jsts_time_009` | `22:59:60+00:00` | `full-time` | REJECT |
| `jsts_time_010` | `23:58:60+00:00` | `full-time` | REJECT |
| `jsts_time_013` | `23:59:60+01:00` | `full-time` | REJECT |
| `jsts_time_014` | `23:59:60+00:30` | `full-time` | REJECT |
| `jsts_time_017` | `23:59:60-01:00` | `full-time` | REJECT |
| `jsts_time_018` | `23:59:60-00:30` | `full-time` | REJECT |
| `jsts_time_024` | `08:30:06-8:000` | `full-time` | REJECT |
| `jsts_time_026` | `24:00:00Z` | `full-time` | REJECT |
| `jsts_time_027` | `00:60:00Z` | `full-time` | REJECT |
| `jsts_time_028` | `00:00:61Z` | `full-time` | REJECT |
| `jsts_time_031` | `01:02:03+24:00` | `full-time` | REJECT |
| `jsts_time_032` | `01:02:03+00:60` | `full-time` | REJECT |
| `jsts_time_033` | `01:02:03Z+00:30` | `full-time` | REJECT |
| `jsts_time_034` | `08:30:06 PST` | `full-time` | REJECT |
| `jsts_time_035` | `01:01:01,1111` | `full-time` | REJECT |
| `jsts_time_036` | `12:00:00` | `full-time` | REJECT |
| `jsts_time_037` | `12:00:00.52` | `full-time` | REJECT |
| `jsts_time_038` | `1২:00:00Z` | `full-time` | REJECT |
| `jsts_time_039` | `08:30:06#00:20` | `full-time` | REJECT |
| `jsts_time_040` | `ab:cd:ef` | `full-time` | REJECT |

---

Do not hand-edit `expires.json`. To refresh, re-run the import against newer pinned commits and
bump the shas above.
