# RFC 3339 `expires` conformance: pay-kit SDK parse paths

Divergence results from driving every pay-kit `expires` parse path against the RFC 3339 `date-time`
vectors vendored at `harness/vectors/mpp-protocol/expires.json` (issue #111).

- Oracle: RFC 3339, pinned text sha256 `9ab2b8864a85dca73a88f49b0927bc7bc85f596926e4fd1890905777924e700a` (35,064 B).
- Vectors: `harness/vectors/mpp-protocol/expires.json`, version `2.0.0`, **124 scenarios** (54 ACCEPT,
  70 REJECT), 36,470 B, sha256 `72f90dc9c9e6d7c373fcae7893e1d9f0c537ecc69fc7397773d5b006a78e0e3d`.
- Parse paths: go, lua, php, python, ruby, rust, typescript; typescript has two call sites, so eight.
- Operation `expires.parse`. Verdict axis ACCEPT or REJECT. Cells: 124 x 8 = 992.
- Source lines resolve at `16777d465f4446c7ac519378663d6d4bbf394877`, the merge base.
- Sources, upstream shas, licences, the dedupe rule and every settled scenario not shipped are in
  `harness/vectors/mpp-protocol/README.md`.

## Headline

**The corpus is not green: 120 of 992 cells diverge, 12.1%. One parse path of eight passes all 124.**
Every divergence is a verdict disagreement, not a crash; no cell produced anything but ACCEPT or REJECT.

| parse path | scenarios | pass | **fail** |
|---|---|---|---|
| rust | 124 | 124 | **0** |
| python | 124 | 115 | **9** |
| go | 124 | 108 | **16** |
| lua | 124 | 108 | **16** |
| php | 124 | 107 | **17** |
| ruby | 124 | 106 | **18** |
| typescript, charge call site | 124 | 102 | **22** |
| typescript, session call site | 124 | 102 | **22** |
| **total** | **992** | **872** | **120** |

**Scope.** Every scenario in the file is an `expires` verdict, so there is no filter and no skip; each
tree asserts that the count it exercised equals the count in the file. The 104 settled `full-date` and
`full-time` scenarios are not `expires` verdicts and are not in the file, and
`harness/vectors/mpp-protocol/README.md` lists each with the rule that excluded it.

**The rust row** means rust never disagreed with the corpus about validity, not that rust is correct:
finding 8 records rust clamping the RFC's own §5.8 leap second to `23:59:59.999999999`. It was checked as
a suspected instrument defect first, and emits mechanism-specific rejection text on four mechanisms
(`the 'year' component could not be parsed`, `the 'separator' component could not be parsed`, `offset
minute was not in range`, `second was not in range`) with minority verdicts in both directions.

## Per-tree results

`repo-parser`: the verdict came from an SDK function whose return value distinguishes parse failure from
a valid past date. `delegated-parser`: the SDK wrapper cannot, so the runner evaluated the parse
expression the SDK delegates to. The harness contains no RFC 3339 parser written for this work.

| tree | parse path (file:line) | verdict source | runtime | **fail of 124** |
|---|---|---|---|---|
| rust | `rust/crates/kit/src/mpp/protocol/core/challenge.rs:173-184` `PaymentChallenge::is_expired` to `time::OffsetDateTime::parse(s, &Rfc3339)` | `delegated-parser` | `cargo 1.96.0`, `time` crate `0.3.55` | **0** |
| python | `python/src/solana_pay_kit/protocols/mpp/core/types.py:28` `_parse_rfc3339` (regex `_RFC3339_RE` at `:17`, then `datetime.fromisoformat`) | `repo-parser` | `Python 3.12.13` | **9** |
| go | `go/protocols/mpp/wire/challenge.go:110-119` `PaymentChallenge.IsExpired(now)` | `repo-parser` | `go1.26.5 darwin/arm64` | **16** |
| lua | `lua/pay_kit/protocols/mpp/expires.lua:27` `M.parse_rfc3339` | `repo-parser` | `Lua 5.5.1` | **16** |
| php | `php/src/PayCore/Rfc3339Parser.php:37` `Rfc3339Parser::parse` | `repo-parser` | `PHP 8.5.9 (cli)` | **17** |
| ruby | `ruby/lib/pay_core/rfc3339_parser.rb:28` `Rfc3339Parser.parse` | `repo-parser` | `ruby 4.0.6` | **18** |
| typescript, charge | `typescript/packages/mpp/src/client/Charge.ts:402` `assertChallengeNotExpired` to `new Date(expires).getTime()` at `:404` | `delegated-parser` | `node v26.0.0` | **22** |
| typescript, session | `typescript/packages/mpp/src/server/Session.ts:346` `assertChallengeOpenNotExpired` to `Date.parse(expires)` at `:348` | `delegated-parser` | `node v26.0.0` | **22** |

**Every row is a property of (SDK source x that runtime), not of the SDK alone.**
`rust/crates/kit/Cargo.toml:153` pins `time = "0.3"` with no lockfile, so a fresh resolve takes whatever
`0.3.x` is current; this run resolved `0.3.55`. pay-kit's Lua rockspecs target Lua 5.1 and 5.4; this run
used Lua 5.5.1.

Two SDKs carry a second RFC 3339 grammar. Both are reachable; neither is counted in the 992.

| tree | second path | why it exists |
|---|---|---|
| go | raw `time.Parse(time.RFC3339, v)` | isolates stdlib behaviour from the wrapper's early-return guard (finding 3) |
| python | `_ISO8601_RE` at `headers.py:32`, used at `headers.py:229` to gate receipt timestamps | the SDK's second RFC 3339 grammar (finding 5) |

**Python 3.9 has no measurement.** `types.py:7` executes `from datetime import UTC` and raises
`ImportError: cannot import name 'UTC' from 'datetime'`; `datetime.UTC` is Python 3.11 and later.
Reported as unwired rather than as 124 disagreements.

## Findings

Nine findings, each a measurement over the shipped file unless stated otherwise. Divergence is measured,
exploitability is not. Consequence is inference, at most once per finding, in a `> **Inference:**` block.

### 1. An offsetless date-time is host-dependent in the typescript path

`offset_absent` (`2026-01-29T12:00:00`, corpus REJECT) is the only offsetless date-time in the file,
found by regex `^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?$` over all 124 inputs, not by name. Six
trees reject it: rust, go, python, ruby, php, lua. TypeScript accepts it and reads it in host local time:

```
TZ=UTC               2026-01-29T12:00:00  ->  2026-01-29T12:00:00.000Z
TZ=America/New_York  2026-01-29T12:00:00  ->  2026-01-29T17:00:00.000Z
TZ=Asia/Tokyo        2026-01-29T12:00:00  ->  2026-01-29T03:00:00.000Z
```

§5.6 makes the offset mandatory in `date-time` and §4.4 states why; ECMA-262 reads an offsetless form as
local. **Limit:** one vector, written from the RFC text, since neither import has an offsetless
date-time.

> **Inference:** for any input omitting an offset, the verdict and instant this path produces are
> properties of the host as well as the input. How such an input reaches this path is not measured.

### 2. The typescript path evaluates ECMA-262 date-time strings, not RFC 3339

`Charge.ts:402` `assertChallengeNotExpired` evaluates `new Date(expires).getTime()` at `:404`;
`Session.ts:346` `assertChallengeOpenNotExpired` evaluates `Date.parse(expires)` at `:348`. Both resolve
at `16777d46`, are the same V8 algorithm, and return byte-identical verdicts on all 124 scenarios.
**16 of the 22 divergences at each call site are over-acceptances, an input the corpus rejects that this
path accepts; the remaining 6 run the other way.** Those 6 are the leap-second `date-time`s —
`jsts_date_time_005`, `jsts_date_time_006`, `leap_second_june_month_end`,
`leap_second_offset_rolls_local_date_forward`, `rfc_5_8_example_leap_second_offset`,
`rfc_5_8_example_leap_second_z` — all corpus ACCEPT under §5.7 and all rejected here, V8 having no
representable 61st second; finding 6 reads one of them against its control. The over-acceptances follow.
Rows 1-2 are direct probes, rows 3-5 the shipped vectors `jsts_date_time_010`, `jsts_date_time_013`,
`jsts_date_time_016`.

| input | `Date.parse` result | RFC 3339 |
|---|---|---|
| `2026-01-01` | `2026-01-01T00:00:00.000Z`, accepted | REJECT, a date-only form is not a `date-time` |
| `2026-01-01T12:00` | `2026-01-01T18:00:00.000Z`, accepted | REJECT, `time-second` is mandatory |
| `1990-02-31T15:59:59.123-08:00` | `1990-03-03T23:59:59.123Z`, rolled over | REJECT, §5.7 February maximum |
| `1990-12-31T24:00:00Z` | `1991-01-01T00:00:00.000Z`, rolled over | REJECT, §5.7 hour 00-23 |
| `06/19/1963 08:30:06 PST` | `1963-06-19T16:30:06.000Z`, accepted | REJECT, not §5.6 syntax at all |

Five shipped vectors take the calendar-rollover path: all corpus REJECT, all accepted, `Session.ts`
matching `Charge.ts` on each. `epochMs` is read from the results file; the instant beside it is decoded.

| vector | input | `Charge.ts` result | rolls to |
|---|---|---|---|
| `feb_30` | `2026-02-30T00:00:00Z` | ACCEPT, `epochMs=1772409600000` | `2026-03-02T00:00:00.000Z` |
| `sep_31` | `2026-09-31T00:00:00Z` | ACCEPT, `epochMs=1790812800000` | `2026-10-01T00:00:00.000Z` |
| `apr_31` | `2026-04-31T00:00:00Z` | ACCEPT, `epochMs=1777593600000` | `2026-05-01T00:00:00.000Z` |
| `non_leap_year_1900_feb_29` | `1900-02-29T00:00:00Z` | ACCEPT, `epochMs=-2203891200000` | `1900-03-01T00:00:00.000Z` |
| `hour_24` | `2026-01-29T24:00:00Z` | ACCEPT, `epochMs=1769731200000` | `2026-01-30T00:00:00.000Z` |

**Three further divergences are bare-production forms. The third is the sharpest in the finding.**

| vector | input | corpus | `new Date(x)` / `Date.parse(x)` resolves to |
|---|---|---|---|
| `bare_date_no_time` | `1963-06-19` | REJECT | `1963-06-19T00:00:00.000Z`, silently becomes midnight UTC |
| `bare_date_leap_day` | `2020-02-29` | REJECT | `2020-02-29T00:00:00.000Z`, same |
| `bare_time_leap_second` | `23:59:60Z` | REJECT | **`1960-01-01T23:59:00.000Z`**, read as year 1960 with the leap second truncated to `:00` |

An `expires` of `23:59:60Z` does not fail here; it becomes an instant in 1960, which every comparison
reads as long expired. `bare_time_zulu` (`08:30:06Z`) and the other three bare-time shapes are correctly
rejected, so the defect is specific to the leap-second form.

### 3. An empty `expires` short-circuits the go guard and returns not-expired without parsing

`go/protocols/mpp/wire/challenge.go`, read off disk at `16777d46`:

```go
110: func (c PaymentChallenge) IsExpired(now time.Time) bool {
111: 	if strings.TrimSpace(c.Expires) == "" {
112: 		return false
113: 	}
114: 	expiresAt, err := time.Parse(time.RFC3339, c.Expires)
```

**The guard at `:111-113` returns `false`, not expired; `time.Parse` at `:114` is not reached.** Line 111
tests `TrimSpace`, so the early-return class is empty or whitespace-only, and the value handed to
`time.Parse` is untrimmed, which is why a trailing-newline input passes in go. `empty_string` is corpus
REJECT: six trees reject it, go reports ACCEPT, and that one vector is the whole difference between the
go wrapper and raw `time.Parse`, which errors on `""` and agrees on every other input.

**A semantic question, not a plain defect.** `IsExpired` is a field-level surface where `expires: ""`
means *no expiry set*, not *malformed*; the other six drive the parser, which rejects `""` as a
`date-time`. Python's suite asserts `test_empty_expires_never_expired` at the field level, so both
readings are deliberate in this repository, and **a boolean corpus carries only one.**

**Reachability**, client path only, from untrusted input. Paths are relative to `go/protocols/mpp/`.

| hop | file:line | what happens |
|---|---|---|
| 1 | `client/transport.go:38` | `PaymentTransport.RoundTrip`, an `http.RoundTripper` installed by `NewClient` (`:110`), on every request |
| 2 | `client/transport.go:56-60` | a remote `402` is parsed; `resp.Header` is whatever the remote sent |
| 3 | `wire/headers.go:81` | `ParseWWWAuthenticate(value)`, per header value |
| 4 | `wire/headers.go:60` | `Expires: params["expires"]`, a `map[string]string`: absent yields `""`, so absent and empty collapse |
| 5 | `wire/headers.go:68-70` | the required-field gate covers `ID`, `Realm`, `Intent`; `Expires` is required by nothing |
| 6 | `client/transport.go:65` to `:105-107` | `isSupportedChargeChallenge` filters on method and intent only; `grep -n "Expires" client/transport.go` returns nothing |
| 7 | `client/charge.go:295` | `challenge.IsExpired(time.Now())` is called |
| 8 | `wire/challenge.go:111-112` | the early return fires, returns `false`, the client proceeds to sign |

A second entry point reaches the same guard: `ParseSessionChallenge` (`client/session.go:335`) and
`challenge_selection.go:112` feed the same unfiltered type.

**The server path is blocked three ways, each sufficient alone.** (1) HMAC ordering: `Verify` precedes
the guard, `server/server.go:457` before `:461` and `server/session_method.go:380` before `:383`.
(2) `expires` is in the HMAC preimage, `challenge.go:105` passing `c.Expires` to `ComputeChallengeID` as
the sixth field (`:147`), so blanking it changes the ID and `Verify` fails first. (3) Both issuers
default it to five minutes, `server/server.go:375-378` and `server/session_method.go:349-352`; the Rust
issuers likewise at `charge.rs:537-538` and `:651-652`.

**Defensive depth, not a vulnerability.** The early return is documented as deliberate two lines above
the call site (`client/charge.go:293-294`):

```go
293	// #10: always refuse to sign an expired challenge. Challenges with no
294	// expiry are still accepted (the protocol allows omitting it).
```

Three confirmations that "no expiry means not expired" is convention rather than a Go defect: that
comment; Rust's `None => false` at `challenge.rs:175`; named tests in both trees (`challenge_test.go:46`
`TestIsExpiredEmptyString`, `challenge.rs:534` `challenge_not_expired_when_no_expires`).

**The residual is the actionable part.** `NewChallengeWithSecret` (`wire/challenge.go:63-64`) is exported
public API hardcoding `expires: ""` into `NewChallengeWithSecretFull`, re-exported as
`mpp.NewChallengeWithSecret` (`core/mpp.go:68`). Its only non-test callers are the two issuers above,
which default the field, **so the safe default lives in the callers, not the constructor.** A downstream
server built on the exported constructor issues challenges HMAC-valid over an empty `expires` that reach
`server.go:461` / `session_method.go:383` and return "not expired" indefinitely.

**A related Go / Rust divergence, recorded without taking a side.**

| wire input | Rust, `server/charge.rs:855-857` | Go, `challenge.go:111` |
|---|---|---|
| `expires` absent | `None`, `if let` skipped, accepted | `""`, early return, accepted |
| `expires: ""` present | `Some("")`, `OffsetDateTime::parse` fails, rejected | `""`, early return, accepted |

Rust's `Option<String>` (`challenge.rs:17`) represents absent, present-empty and present-valid; Go's bare
`string` (`challenge.go:27`) cannot. The distinction does not survive the wire: `challenge.rs:212` folds
`None` and `Some("")` into one preimage with `expires.unwrap_or("")`, giving an identical challenge ID,
and `#[serde(skip_serializing_if = "Option::is_none")]` at `challenge.rs:16` means Rust never emits
`expires: ""`. **Which side is right is the maintainer's call.** Adding `expires` to the required-field
gate at `headers.go:68-70` makes the guard unreachable from the wire; conversely any server-side issuance
path emitting an empty `expires` raises the severity above defensive depth. The convention reading rests
on two implementations, two test suites and one source comment, not a written spec.

### 4. php preserves six fractional digits exactly, truncates 7 to 9, and rejects 10 or more

Issue #111 names the limit by hand: *"PHP's `%u` format only accepts 6"*. The import supplied a six-digit
vector, `jsts_date_time_001` = `1963-06-19T08:30:06.283185Z`, corpus ACCEPT. **All seven trees accept it,
and php preserves all six digits exactly.**

| tree | verdict | parsed value |
|---|---|---|
| rust | ACCEPT | `1963-06-19 8:30:06.283185 +00:00:00` |
| go | ACCEPT | `1963-06-19T08:30:06.283185Z` |
| python | ACCEPT | `datetime(1963, 6, 19, 8, 30, 6, 283185, tzinfo=utc)` |
| ruby | ACCEPT | `1963-06-19T08:30:06.283185000Z` (nsec=283185000) |
| **php** | **ACCEPT** | **`1963-06-19T08:30:06.283185+00:00`** |
| lua | ACCEPT | `epoch=-206292594` = `1963-06-19T08:30:06Z` (lua's return type is a whole-second epoch) |
| typescript | ACCEPT | `epochMs=-206292593717` = `1963-06-19T08:30:06.283Z` |

The limit is real and sits one digit further along. Executed against PHP 8.5.9:

| input | result |
|---|---|
| `…06.283185Z` (6 digits) | **ACCEPT, `.283185` preserved exactly** |
| `…33.1234567Z` (7 digits) | ACCEPT, truncated to `.123456` |
| `…33.123456789Z` (9 digits) | ACCEPT, truncated to `.123456` |
| `…33.0000000000Z` (10 digits) | **REJECT (`parse()` returns null)** |
| `…33.9999999999999999Z` (16 digits) | **REJECT** |

All five rows are shipped vectors: `jsts_date_time_001`, `secfrac_7_digits`, `secfrac_9_digits`,
`go_longfrac_10digits_0000000000`, `go_longfrac_16digits_9999999999999999`. All five are corpus ACCEPT,
so php's rejection of the last two is two of its 17 divergences. Two mechanisms, two lines: the regex at
`php/src/PayCore/Rfc3339Parser.php:26` bounds `time-secfrac` to `(?:\.(\d{1,9}))?`, producing the
rejection past 9; the truncation is `substr($frac, 0, 6)` at `:86`. On the same 9-digit input rust, go,
python and ruby preserve all nine digits (ruby `nsec=123456789`); lua and typescript truncate by return
type. **php is the only tree that loses fractional digits it claims to support.**

### 5. The python SDK carries two RFC 3339 grammars and they disagree

`_RFC3339_RE` at `types.py:17`, gating `_parse_rfc3339` at `types.py:28`, is the wired path.
`_ISO8601_RE` at `headers.py:32`, used at `headers.py:229` to gate receipt timestamps, is a second
grammar in the same package. Same interpreter, same run, same 124 inputs: **`_ISO8601_RE` disagrees with
the corpus on 33 of 124 where the wired `_parse_rfc3339` disagrees on 9.**

Both directions fire. `_ISO8601_RE` is purely lexical and accepts calendar-impossible dates that
`_parse_rfc3339` rejects: `feb_30`, `month_13`, `non_leap_year_1900_feb_29`, `minute_60`,
`offset_hour_out_of_range` (`+24:00`); `_parse_rfc3339` accepts lower-case forms `_ISO8601_RE` rejects.
Two trailing-newline inputs, `jsts_date_time_027` and `trailing_newline_after_offset`, are corpus REJECT
and both match `_ISO8601_RE`, because python's `$` matches before a final newline. The 33 also include
**non-ASCII digits**: `jsts_date_time_021` = `1963-06-1৪T00:00:00Z` matches, Python's `\d` being
Unicode-aware. They gate different fields, so `_ISO8601_RE` is a second path, not part of the 992.

> **Inference:** whether a timestamp is valid in that SDK depends on which function reaches it. Which
> function reaches a given field in production is not measured here.

### 6. The leap second whose offset rolls the local date across midnight, and its control

These two vectors are the sharpest discriminator in the file.

| vector | input | corpus | rust | go | python | ruby | php | lua | typescript |
|---|---|---|---|---|---|---|---|---|---|
| `leap_second_offset_rolls_local_date_forward` | `1999-01-01T00:59:60+01:00` | **ACCEPT** | **ACCEPT** | REJECT | REJECT | ACCEPT | ACCEPT | ACCEPT | REJECT |
| `…_wrong_offset` (control) | `1999-01-01T00:59:60+02:00` | **REJECT** | **REJECT** | REJECT | REJECT | **ACCEPT** | **ACCEPT** | **ACCEPT** | REJECT |

`00:59:60+01:00` resolves to `1998-12-31T23:59:60Z`, the final row of the RFC's Appendix D table;
`00:59:60+02:00` resolves to `1998-12-31T22:59:60Z`, not the leap-second point, and §5.7 says *"At all
other times the maximum value of time-second is '59'."*

**Read as a pair: rust is the only tree that gets both right.** go, python and typescript reject every
`:60` and pass the control for the wrong reason, having no representable 61st second; ruby, php and lua
accept every `:60` and pass the first for the wrong reason, normalising `:60` away silently. rust rejects
the control with `time::Parse error: second was not in range`, the only implementation here that
evaluates the leap second after applying the offset. **Without the control, ruby, php and lua would have
scored a pass identical in shape to rust's and opposite in meaning.**

### 7. A clean negative: no tree range-checks offsets against timezone data

`time-numoffset = ("+" / "-") time-hour ":" time-minute` with `time-hour = 2DIGIT ; 00-23` and
`time-minute = 2DIGIT ; 00-59`, so `±23:59` is the widest offset §5.6 generates, well outside the ±14:00
range any real timezone uses. `offset_max_syntactic_plus_23_59` and `offset_min_syntactic_minus_23_59`
are both corpus ACCEPT. **All seven trees accept both, with correct arithmetic.** Every tree resolved
`+23:59` to the same instant: lua `epoch=1769601660`, typescript `epochMs=1769601660000`, rust
`+23:59:00`, go `+23:59`, python `timedelta(seconds=86340)`, ruby `+23:59`, php `+23:59`; `1769601660`
decodes to `2026-01-28T12:01:00Z`, which is `2026-01-29T12:00:00` minus 23h59m.

An adjacent case does fire. `offset_minute_out_of_range` (`+00:60`) is REJECT under §5.6, and go, python
and ruby accept it; python's returned value is the proof text,
`tzinfo=timezone(timedelta(seconds=3600))`, so `+00:60` became exactly `+01:00`. The import corroborated
this in a form this corpus had not written: `jsts_date_time_015` = `1990-12-31T10:00:00+10:60`, corpus
REJECT, accepted by the same three trees by the same mechanism.

### 8. Trees that ACCEPT the same input and denote different instants

The corpus verdict is ACCEPT or REJECT and nothing else, so this divergence class scores PASS everywhere.
On `rfc_5_8_example_leap_second_z` = `1990-12-31T23:59:60Z`, the RFC §5.8 worked example, corpus ACCEPT:

| tree | verdict | instant returned |
|---|---|---|
| rust | ACCEPT | `1990-12-31 23:59:59.999999999 +00:00:00`, clamped down |
| php | ACCEPT | `1990-12-31T23:59:59.000000+00:00`, clamped down, fraction dropped |
| ruby | ACCEPT | `1991-01-01T00:00:00.000000000Z`, rolled forward into the next year |
| lua | ACCEPT | `epoch=662688000` = `1991-01-01T00:00:00Z`, rolled forward |
| go / python / typescript | REJECT | (none) |

**Four trees accept and return two different instants, one second apart, across a year boundary, and a
boolean corpus scores all four as PASS.** On the finding 6 control vector, which the corpus rejects, the
three accepting trees split again: ruby `01:00:00+02:00`, php `00:59:59+02:00`, lua `epoch=915145200`
(`1999-01-01T01:00:00+02:00`).

> **Inference:** for a field whose purpose is to say when a challenge stops being valid, a difference in
> the denoted instant is a difference in when it stops being valid. This corpus does not measure it.

### 9. A space where §5.6 mandates a `T`, and a five-two split

`2020-01-01 00:00:00Z`, imported from the upstream `date.json` suite with verdict REJECT. **rust and
typescript accept it; go, python, ruby, php and lua reject it.**

```
$ rust_runner probe.tsv
space_sep	1	2020-01-01 0:00:00.0 +00:00:00
```

The `time` crate's `Rfc3339` well-known format accepts a space separator. §5.6's ABNF mandates `T` while
the same section's second NOTE contemplates separating full-date and full-time "by (say) a space
character", and one verdict cannot satisfy both; the upstream `date.json` case answers it sideways,
through a REJECT that judges `date` rather than `date-time`. **This vector does not ship, and the finding
is recorded on that basis:** it sits in the disputed list in `harness/vectors/mpp-protocol/README.md`,
and **how it should be verdicted is an open question, not settled here.**

## The one vector RFC 3339 does not decide

**`1582-10-10`**, from the upstream `date.json` suite, which asserts `valid: true` and describes it as
*"valid: date inside the Julian to Gregorian reform gap"*, a deliberate position. **It is marked
`UNRESOLVED-PROVENANCE` and does not ship in the vector file**, its absence independently verified. The
date fell inside the ten days, 5 to 14 October 1582, skipped when the Gregorian calendar replaced the
Julian one: under a proleptic Gregorian calendar it exists, under the historical calendar it never
occurred. RFC 3339 says which calendar it profiles and never says which reading applies.

| section | what it says | why it does not decide |
|---|---|---|
| §5.6 | `full-date = date-fullyear "-" date-month "-" date-mday`, `4DIGIT`/`2DIGIT` fields | Purely syntactic. `1582-10-10` matches. The grammar cannot express "this day did not occur". |
| §5.7 | the `date-mday` maximum table: October to 31 | Constrains the maximum day number only; 10 is at most 31. Reading its silence as permission is inference, not citation. |
| §2 | "leap year" defined on the Gregorian calendar, with the /4, /100, /400 rule | Arithmetic about leap years, not calendar adoption. "The Gregorian calendar" is unqualified. |
| Appendix C | the same rule in sample C code | Says nothing about 1582. |
| §1 / Abstract | "…using the Gregorian calendar" | One unqualified noun phrase; it does not distinguish the two readings. |
| §3, Appendix D | two-digit years; leap seconds | Neither is about calendar adoption. |

**The strongest argument for deciding it, and why it was not taken.** §2's leap-year arithmetic is
applied in this same corpus to years more than a millennium before the Gregorian calendar existed:
`0100-02-29` is REJECT and `0400-02-29` is ACCEPT, decided purely by the /100 and /400 rule. Year 0100
*was* a Julian leap year, so `0100-02-29` was a real date and RFC 3339's rule rejects it. **RFC 3339
therefore applies Gregorian arithmetic proleptically, and the word "proleptic" appears nowhere in it**
(`grep -niE "gregorian|julian|proleptic|calendar"` over the pinned text returns four hits, none
addressing the reform). That is an inference from the document's structure, not a statement in it.
**The suite is right that an implementation has to do something. It is not right that RFC 3339 told it
what.**

## Limitations

- **The boolean axis is blind to the instant divergence in finding 8.** No golden instant is asserted for
  ACCEPT scenarios, so finding 8's four instants all score PASS. Same limit on php's truncation in
  finding 4: it accepts 7- and 9-digit fractions the corpus accepts, truncates both to six, passes both.
- **Two trees cannot be conformance-tested through their own public surfaces.** rust's `is_expired()`
  collapses parse failure and past date into one fail-closed bool and reads `OffsetDateTime::now_utc()`
  internally; `server/session.rs:64` collapses both into `Error::ChallengeExpired`; `server/charge.rs:857`
  distinguishes but is reachable only after a constant-time HMAC challenge-ID check. typescript's two
  expiry checks are module-private and the package ships no RFC 3339 parser module. Hence
  `delegated-parser` on both.
- **Kotlin and Swift are not measured.** Neither is on `langs` in `harness/divergence-raw.json` nor in
  `harness/protocol-runners/`. pay-kit carries nine SDK trees; seven are measured here.
- **Python 3.9 has no measurement.** The SDK does not load on it.
- **No `expires` verdict is compared against a normalised instant, a timezone database, or a clock.** The
  corpus asserts grammar and calendar validity per RFC 3339 and nothing else.
- **Neither import contains a leap second in a positive offset that rolls the local date across
  midnight.** The only vectors covering it are the two in finding 6, written for this corpus; the
  upstream `time` file covers the offset arithmetic on `full-time`, which has no date to roll.

## Reproduce

**Six of the seven trees exit non-zero, and that is the correct result**, so the commands are not chained
with `&&`. **Every line states the number of tests it must run**, because a wrong `-run` pattern or a
stale path exits 0 on several of these toolchains.

```
# 1. Hash gate. If it does not match, nothing below applies. From the repository root:
shasum -a 256 harness/vectors/mpp-protocol/expires.json
# 72f90dc9c9e6d7c373fcae7893e1d9f0c537ecc69fc7397773d5b006a78e0e3d      exit 0

# 2. The seven trees. Run each; none depends on another.

# go  from the repository root; -C go because the go module root is go/. -v or no count is printed
go -C go test -v ./protocols/mpp/wire/ -run TestRFC3339ConformanceCorpus   # exit 1, 16 FAIL of 124

# python  from python/
pytest tests/test_expires.py                                              # exit 1, 9 FAIL of 124

# rust  from rust/
cargo test -p solana-pay-kit rfc3339_conformance_corpus                   # exit 0, 0 FAIL of 124

# typescript  from typescript/
npx vitest run packages/mpp/src/__tests__/client-charge-validation.test.ts # exit 1, 44 FAIL of 248

# ruby  from ruby/;  needs ruby >= 3.1, see the prerequisites table
bundle exec ruby test/pay_core/expires_rfc3339_test.rb                    # exit 1, 18 FAIL of 124

# php  from php/;  composer install first
./vendor/bin/phpunit tests/PayCore/Rfc3339Test.php                        # exit 1, 17 FAIL of 124

# lua  from lua/;  the suite's runner is tests/test_helper.lua in-repo, not busted
lua -e "package.path=table.concat({'./?.lua','./?/init.lua',package.path},';'); \
        require('tests.expires_rfc3339_spec'); require('tests.test_helper').run()"
#   exit 1, 1 of 8 tests fails, printing "16 of 124 vectors diverge"
```

The numbers those commands printed, not a prediction. The `fail` column counts corpus vectors and equals
the headline table row for row.

| tree | working directory | exit | tests run | corpus vectors driven | pass | **fail** |
|---|---|---|---|---|---|---|
| go | repo root | 1 | 125 (`-v` to see them) | 124 | 108 | **16** |
| python | `python/` | 1 | 144 | 124 | 135 | **9** |
| rust | `rust/` | **0** | 3 | 124 | 3 | **0** |
| typescript | `typescript/` | 1 | 272 | 248 (124 x 2) | 228 | **44** (22 per call site) |
| ruby | `ruby/` | 1 | 130 | 124 | 112 | **18** |
| php | `php/` | 1 | 145 | 124 | 128 | **17** |
| lua | `lua/` | 1 | 8 | 124 | 7 | **1**, reporting 16 of 124 diverging |

**Every tree drives all 124 scenarios. There is no filter and no skip.** Six enforce it by assertion, as
in rust's `rfc3339_conformance_corpus_exercises_every_scenario` or lua's
`t.assert_true(admitted == #corpus.scenarios, ...)`. **go is the exception:** it ranges directly over the
decoded array, so its count is visible in the run rather than asserted.

**Two invocation notes, each of which cost a wrong answer once.** `-run Expires` matches none of the 14
test functions in `challenge_test.go` and go reports `PASS … [no tests to run]` with exit 0; the symbol
is `TestRFC3339ConformanceCorpus`. The rust filter must be `rfc3339_conformance_corpus`, not `expires`,
which selects 16 unrelated helper tests and runs none of the three conformance tests.

### The same eight commands, as one command

Same commands, same directories, from the repository root. **No `&&`**, and each entry runs in its own
subshell so no `cd` leaks. The go line carries `-v` because without it go prints no count.

```
for t in gate go python rust typescript ruby php lua; do \
  printf '\n===== %s =====\n' "$t"; \
  ( case $t in \
      gate)       shasum -a 256 harness/vectors/mpp-protocol/expires.json ;; \
      go)         go -C go test -v ./protocols/mpp/wire/ -run TestRFC3339ConformanceCorpus ;; \
      python)     cd python; pytest tests/test_expires.py ;; \
      rust)       cd rust; cargo test -p solana-pay-kit rfc3339_conformance_corpus ;; \
      typescript) cd typescript; npx vitest run packages/mpp/src/__tests__/client-charge-validation.test.ts ;; \
      ruby)       cd ruby; bundle exec ruby test/pay_core/expires_rfc3339_test.rb ;; \
      php)        cd php; ./vendor/bin/phpunit tests/PayCore/Rfc3339Test.php ;; \
      lua)        cd lua; lua -e "package.path=table.concat({'./?.lua','./?/init.lua',package.path},';'); require('tests.expires_rfc3339_spec'); require('tests.test_helper').run()" ;; \
    esac ); \
  printf '===== %s exit %d =====\n' "$t" "$?"; \
done
```

Each entry's output prints in full between the delimiters, greppable with `| grep '^====='`. Executed
from the repository root, the eight delimiters printed:

```
===== gate exit 0 =====        # 72f90dc9…e0e3d
===== go exit 1 =====          # 125 "=== RUN" (1 parent + 124 subtests), 108 PASS, 16 FAIL
===== python exit 1 =====      # 9 failed, 135 passed  (144)
===== rust exit 0 =====        # running 3 tests; 3 passed, 0 failed
===== typescript exit 1 =====  # 44 failed | 228 passed  (272)
===== ruby exit 1 =====        # 130 runs, 155 assertions, 18 failures, 0 errors
===== php exit 1 =====         # Tests: 145, Assertions: 153, Failures: 17
===== lua exit 1 =====         # 7 tests passed, 0 skipped, 1 failed, "16 of 124 vectors diverge"
```

### Prerequisites per tree

Every row was established by running the command above, not by reading a manifest.

| tree | prerequisite | probe |
|---|---|---|
| go | none beyond the toolchain | `go version` gives `go1.26.5 darwin/arm64` |
| python | the SDK with dev extras (`uv sync --extra dev`, or `pip install -e ".[dev]"` in a 3.12 venv) | `python3.12 --version` gives `Python 3.12.13` |
| rust | a resolvable workspace. **It does not resolve offline**: `cargo test --offline` fails on a `solana-bpf-loader-program` version conflict via `litesvm`, pre-existing and unrelated to these vectors | `cargo --version` gives `1.96.0` |
| typescript | `pnpm install` in `typescript/` | `node --version` gives `v26.0.0` |
| ruby | `bundle install`, **and ruby >= 3.1**, see below | `ruby --version` |
| php | `composer install` in `php/` | `php --version` gives `8.5.9` |
| lua | none. The runner is `lua/tests/test_helper.lua`, in-repo; busted is not a dependency. **`lua tests/run.lua` (the whole suite) additionally needs `luasodium` from luarocks; the single-spec invocation above does not** | `lua -v` gives `Lua 5.5.1` |

**The ruby row.** `bundle exec` cannot run under ruby 2.6.10: the gemspec requires `ed25519 ~> 1.4`
(ruby >= 3.0) and `minitest ~> 5.25` (ruby >= 3.1), so the suite will not load, and a reader on system
ruby sees `Gem::GemNotFoundException` rather than a result. The row was measured under ruby 4.0.6, and
ruby's parser returns the same 18 failures on the same 124 vectors under 2.6.10p210, so the count is not
runtime-sensitive.
