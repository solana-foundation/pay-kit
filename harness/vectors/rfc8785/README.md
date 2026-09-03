# RFC 8785 (JCS) conformance corpus

Vendored input/output pairs from the
[cyberphone/json-canonicalization](https://github.com/cyberphone/json-canonicalization)
reference suite, pinned to commit `19d51d7fe467d4706a3ff08adf8a748f29fc21e0`
(2024-12-13). See `Justfile` → `cyberphone_ref` for the pin; the
`jcs-pull-corpus` recipe re-fetches from the same commit.

## Files

| Name | What it covers |
|---|---|
| `arrays` | array ordering / nested arrays; input is `[56, {"d": true, "10": null, "1": []}]`, expected canonical form sorts the inner object by UTF-16 code unit (`{"1":[], "10":null, "d":true}`) while preserving the array's element order |
| `french` | BMP non-ASCII keys (`peach` / `péché` / `pêche`); pins UTF-16 code-unit sort order across accented characters |
| `structures` | nested object key ordering, mixed numeric / string / empty / `A`-vs-`a` keys |
| `unicode` | unnormalized Unicode (`Å` → `Å`) — the canonical-form contract is *not* NFC, by RFC 8785 §3.2.2.2 |
| `values` | the five ES6 number edge cases (RFC 8785 §3.2.2.3): `333333333.33333329`, `1E30`, `4.50`, `2e-3`, `0.000000000000000000000000001`; plus a string covering ``, newline, and embedded escape sequences |
| `weird` | control characters, lone surrogates (via `😂`), browser-fragment keys, and Hebrew combining marks |

The corpus exercises RFC 8785 §3.2.2.2 (I-JSON), §3.2.2.3 (ECMA-262 number
serialization), and §3.2.3 (UTF-16 code-unit key sorting). The 100M-value
ES6 random-number file referenced by the cyberphone Go test lives outside
this repo and is not vendored — its size and seed would make the
conformance matrix non-deterministic.

### Known test-channel limitation: `values` precision

The `values` vector's `numbers` array has one case, `333333333.33333329`,
where the source string carries a digit beyond what IEEE 754 doubles can
represent. After any JSON parse — including the harness driver's stdin
deserialization — the value collapses to the nearest double,
`333333333.3333333`, which is the same form the canonical output requires.
The other four number cases (`1E30` → `1e+30`, `4.50` → `4.5`, `2e-3` →
`0.002`, `0.000000000000000000000000001` → `1e-27`) survive the parse
lossless and continue to exercise the §3.2.2.3 shortest-form rule end to
end. The collapsed case still pins the property at the value level: an
encoder that emits anything other than the shortest round-trip form for
the parsed double fails the vector. The original cyberphone Go/Java/JS
test frameworks avoid this by piping the raw input bytes straight into
`Transform(bytes)` without a parse round-trip; the harness's typed-`value`
conformance channel can't. A future change that adds a raw-bytes input
shape to the conformance schema would restore the end-to-end precision
test.

## Why verbatim?

The whole point is to import from a battle-tested reference suite. Do not
hand-author vectors here; if a new case is needed, find it in the upstream
corpus (or in a different established reference like Test262) and re-pin
`cyberphone_ref` in the `Justfile` to bring it in.

## Usage

The vendored pairs are inputs to `harness/src/conformance/jcs-corpus.ts`,
which renders them into `harness/vectors/rfc8785-vectors.json` (a
`ConformanceVector[]` in `canonical-bytes` mode). The cross-SDK driver at
`harness/test/conformance.test.ts` then runs every registered runner
against the rendered file — no per-SDK plumbing changes were needed for
SDKs whose conformance runner already wires their JCS encoder to a
stdin/stdout `RunnerResult` envelope.

```bash
# From the repo root: full refresh (pull + generate).
just jcs-sync

# From the harness dir: regenerate vectors only.
pnpm run jcs:generate-vectors
```

## License

The cyberphone corpus is licensed Apache-2.0
([LICENSE](https://github.com/cyberphone/json-canonicalization/blob/master/LICENSE)).
Test data attribution per Apache-2.0 §4(d).
