// Drives the vendored canonical mpp-protocol vectors (tempoxyz/mpp-tools,
// MIT) through pay-kit's TypeScript protocol layer (mppx). Every challenge
// / credential / receipt header codec case, every base64url case, and every
// challenge-id HMAC case must match the canonical golden output.
//
// This is the reference wiring: per-language runners plug a spawned-process
// `ProtocolAdapter` into the same `runCase` driver.

import { describe, expect, it } from "vitest";
import { caseRunsOnAdapter, collectProtocolCases } from "../src/protocol/vectors";
import { runCase } from "../src/protocol/driver";
import { typescriptProtocolAdapter } from "../src/protocol/runners/typescript";
import {
  discoverProtocolRunners,
  spawnedProtocolAdapter,
} from "../src/protocol/runners/spawn";
import { parseLanguageAllowlist } from "../src/conformance/select";

const cases = collectProtocolCases();

// Known divergences between pay-kit's TypeScript protocol surface (`@solana/mpp`,
// which wraps mppx) and the canonical mpp-tools oracle. Each entry is
// `${op} :: ${scenario}`. These are asserted to STILL diverge so the gap is
// tracked, not silently green; when an SDK fix lands, the divergence test fails
// loudly and the entry is removed.
//
// (none) — `challenge.parse :: error_empty_id` previously diverged because
//   mppx@0.5.x accepts a `WWW-Authenticate` challenge with an empty `id`
//   parameter (its Zod `id` schema allows ""), while the canonical spec and
//   pay-kit's rust spine (protocol/core/headers.rs) reject it as parse_error.
//   pay-kit's `@solana/mpp` now guards this at its boundary
//   (src/shared/challenge-guard.ts), rejecting an empty `id` on parse, so the
//   TypeScript SDK conforms to the canonical golden.
const KNOWN_TS_DIVERGENCES = new Set<string>([]);

describe("mpp-protocol conformance (canonical vectors / TypeScript runner)", () => {
  it("expands a non-trivial set of canonical cases", () => {
    expect(cases.length).toBeGreaterThan(40);
  });

  for (const testCase of cases) {
    const key = `${testCase.op} :: ${testCase.scenario}`;
    // Canonical adapter allow-list: cases carrying `adapters` only run
    // against the listed languages (the adversarial ReDoS probe is
    // python-only canonically). The TS reference still exercises them in
    // the pay-kit extra block below.
    if (!caseRunsOnAdapter(testCase, typescriptProtocolAdapter.name)) continue;
    if (KNOWN_TS_DIVERGENCES.has(key)) {
      it(`KNOWN DIVERGENCE: ${key}`, async () => {
        const result = await runCase(typescriptProtocolAdapter, testCase);
        // Assert the divergence persists. Remove the entry from
        // KNOWN_TS_DIVERGENCES once the TS core conforms.
        expect(result.ok, `${key} now conforms — remove from KNOWN_TS_DIVERGENCES`).toBe(false);
      });
      continue;
    }
    it(key, async () => {
      const result = await runCase(typescriptProtocolAdapter, testCase);
      expect(result.ok, result.detail).toBe(true);
    });
  }
});

// PAY-KIT EXTRA (not part of the canonical suite): adapter-allow-listed
// adversarial cases — canonically python-only — are also driven through the
// in-process TS reference adapter with a generous explicit budget, because
// ReDoS-resistance matters to every parser. If the TS parser produces the
// wrong result or blows the budget, that is a finding to report, not to
// hide: the case either fails outright or lands in the asserted
// known-divergence list below.
const TS_ADVERSARIAL_BUDGET_MS = 5000;

// Known adversarial divergences of the TS reference from the canonical
// golden, mirroring KNOWN_TS_DIVERGENCES (asserted to STILL diverge, and
// asserted NOT to be a duration blowout — the divergence must stay a fast
// rejection, never a hang).
//
// - `challenge.parse :: adversarial_unclosed_quoted_extension`: the
//   canonical golden (python adapter) IGNORES the malformed unclosed quoted
//   extension auth-param (`fuzz="\\\\...`) and parses the challenge
//   successfully. mppx's parser instead rejects the whole header with
//   parse_error "Unterminated quoted-string.". The rejection is immediate
//   (~2ms for the 12k-escape wire), so the TS parser is NOT
//   ReDoS-vulnerable — it is stricter than canonical about malformed
//   extension params it would otherwise discard.
const KNOWN_TS_ADVERSARIAL_DIVERGENCES = new Set<string>([
  "challenge.parse :: adversarial_unclosed_quoted_extension",
]);

describe("mpp-protocol conformance (pay-kit extra: adversarial cases vs TS reference)", () => {
  const adversarialCases = cases.filter(
    (testCase) => !caseRunsOnAdapter(testCase, typescriptProtocolAdapter.name),
  );

  it("covers the canonical python-only adversarial parse case", () => {
    expect(adversarialCases.map((c) => `${c.op} :: ${c.scenario}`)).toContain(
      "challenge.parse :: adversarial_unclosed_quoted_extension",
    );
  });

  for (const testCase of adversarialCases) {
    const key = `${testCase.op} :: ${testCase.scenario}`;
    if (KNOWN_TS_ADVERSARIAL_DIVERGENCES.has(key)) {
      it(`KNOWN DIVERGENCE: ${key} (budget ${TS_ADVERSARIAL_BUDGET_MS}ms)`, async () => {
        const result = await runCase(typescriptProtocolAdapter, testCase, {
          durationLimitMsOverride: TS_ADVERSARIAL_BUDGET_MS,
        });
        // Assert the divergence persists; remove the entry once mppx
        // tolerates malformed extension params the way canonical does.
        expect(
          result.ok,
          `${key} now conforms — remove from KNOWN_TS_ADVERSARIAL_DIVERGENCES`,
        ).toBe(false);
        // The divergence must never degrade into a performance failure: a
        // duration blowout here means the TS parser started backtracking
        // pathologically, which is a real ReDoS finding, not a tolerated gap.
        expect(result.detail, `${key} blew the duration budget`).not.toMatch(
          /duration exceeded/,
        );
      });
      continue;
    }
    it(`${key} (budget ${TS_ADVERSARIAL_BUDGET_MS}ms)`, async () => {
      const result = await runCase(typescriptProtocolAdapter, testCase, {
        durationLimitMsOverride: TS_ADVERSARIAL_BUDGET_MS,
      });
      expect(result.ok, result.detail).toBe(true);
    });
  }
});

// Cross-SDK protocol conformance: drive the FULL canonical case set (success
// AND adversarial reject cases) through each manifest-discovered SDK runner over
// the spawned stdin/stdout ABI, exactly the way the cross-SDK runners are wired
// in src/conformance. Every SDK with a protocol runner ships a manifest under
// harness/protocol-runners/ (go, lua, php, python, ruby, rust, typescript today;
// kotlin/swift pending). Earlier this loop ran only a success-only "smoke" slice
// (one case per op), so the adversarial reject cases — the escaping / CRLF /
// empty-field / method-case bug classes — were exercised against the TS
// reference IN-PROCESS ONLY, and the same bugs sat untested in every other SDK.
// Running the full set here surfaces them cross-SDK; the confirmed current
// divergences are tracked in KNOWN_RUNNER_DIVERGENCES until each SDK is fixed.

// Per-language known divergences from the canonical oracle, keyed by language.
// Each entry is `${op} :: ${scenario}` and is asserted to STILL diverge so the
// gap fails loudly the moment the SDK conforms (mirrors KNOWN_TS_DIVERGENCES).
//
// CONFIRMED cross-SDK divergences surfaced by running the full canonical case
// set (not just the success-only smoke slice) against each spawned SDK runner
// (2026-07-08). These are the same bug FAMILIES the TS reference carried before
// it was fixed this round — empty realm/intent not rejected, CRLF-in-description
// not rejected, unescaped quote/backslash in the challenge quoted-string — plus
// method-case validation and a Ruby challenge-id unicode divergence. Each is a
// real per-SDK protocol-codec bug to fix in that SDK's per-language PR; tracking
// it here makes the harness RED the moment a NEW divergence appears, and RED
// (loudly) the moment an SDK is fixed so its entry must be removed. php +
// typescript conform fully.
const KNOWN_RUNNER_DIVERGENCES: Record<string, Set<string>> = {
  go: new Set([
    "challenge.format :: error_format_crlf_in_description",
    "challenge.parse :: error_uppercase_method",
  ]),
  rust: new Set([
    "challenge.parse :: error_empty_realm",
    "challenge.parse :: error_empty_intent",
  ]),
  python: new Set([
    "challenge.parse :: error_empty_realm",
    "challenge.parse :: error_empty_intent",
  ]),
  // ruby: intentionally NOT listed and NOT CI-gated (see the note in ruby.yml).
  // The observed ruby divergences were environment-contaminated: the local probe
  // ran ruby 4.0.5 (CI pins 3.3), and the challenge.id `unicode_in_description`
  // case CRASHED the runner on a US-ASCII/UTF-8 encoding mismatch
  // (protocol_runner.rb stdin encoding) rather than being a real protocol
  // divergence. An independent second-model run had ruby conforming. Verify on
  // ruby 3.3 and fix the runner's stdin UTF-8 encoding before wiring ruby as a
  // strict cross-SDK gate; a local `MPP_CONFORMANCE_LANGUAGES=ruby` run on ruby
  // 4.x will RED here until then, which is expected.
  lua: new Set(["challenge.parse :: error_uppercase_method"]),
};

// Honor MPP_CONFORMANCE_LANGUAGES (mirrors conformance.test.ts): the Node-only
// CI leg sets it to the toolchains actually present (e.g. `typescript`) so the
// spawn loop does not try to exec absent uv/cargo/php runners and env-fail.
// Unset = every discovered runner (the local/multi-toolchain default). The
// in-process TypeScript-reference describe blocks above run regardless, so
// wiring this file with `=typescript` already un-blinds the WWW-Authenticate /
// receipt / canonical vectors against the reference verifier in CI.
const runnerAllowlist = parseLanguageAllowlist(process.env.MPP_CONFORMANCE_LANGUAGES);
const runners = discoverProtocolRunners().filter(
  (runner) => !runnerAllowlist || runnerAllowlist.has(runner.language),
);

// Anti-vacuous-pass guard (mirrors conformance.test.ts): when
// MPP_CONFORMANCE_LANGUAGES pins an allowlist, at least one spawned protocol
// runner MUST match it. The in-process TypeScript blocks above always run, so a
// typo like "rustt" would otherwise exercise zero spawned SDKs and still pass.
describe("protocol conformance runner selection", () => {
  it("resolves at least one runner for the configured allowlist", () => {
    if (runnerAllowlist) {
      const available = discoverProtocolRunners().map((r) => r.language).join(", ");
      expect(
        runners.length,
        `MPP_CONFORMANCE_LANGUAGES=${process.env.MPP_CONFORMANCE_LANGUAGES} matched no ` +
          `discovered protocol runner (available: ${available}). A typo or a missing ` +
          `manifest would otherwise run zero spawned SDKs and pass green.`,
      ).toBeGreaterThan(0);
    }
  });
});

for (const runner of runners) {
  const known = KNOWN_RUNNER_DIVERGENCES[runner.language] ?? new Set<string>();
  describe(`mpp-protocol conformance (spawned ${runner.language} runner)`, () => {
    const adapter = spawnedProtocolAdapter(runner);
    for (const testCase of cases) {
      if (!caseRunsOnAdapter(testCase, runner.language)) continue;
      const key = `${testCase.op} :: ${testCase.scenario}`;
      if (known.has(key)) {
        it(`KNOWN DIVERGENCE: ${key}`, async () => {
          const result = await runCase(adapter, testCase);
          expect(
            result.ok,
            `${key} now conforms — remove from KNOWN_RUNNER_DIVERGENCES[${runner.language}]`,
          ).toBe(false);
        });
        continue;
      }
      it(key, async () => {
        const result = await runCase(adapter, testCase);
        expect(result.ok, result.detail).toBe(true);
      });
    }
  });
}
