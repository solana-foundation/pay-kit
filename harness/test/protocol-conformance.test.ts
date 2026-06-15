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

// Per-language wiring proof: drive a representative slice of cases through
// each manifest-discovered runner over the spawned stdin/stdout ABI, exactly
// the way the cross-SDK runners are wired in src/conformance. Only the
// TypeScript reference runner ships a manifest today; other languages are a
// file-drop follow-up (implement the stdin/stdout runner + drop a manifest).
const smokeOps = new Set([
  "base64url.encode",
  "base64url.decode",
  "challenge.id",
  "challenge.parse",
  "challenge.format",
  "credential.parse",
  "receipt.parse",
]);
const smokeCases = (() => {
  const seen = new Set<string>();
  const picked = [] as typeof cases;
  for (const c of cases) {
    if (!c.expectSuccess) continue;
    if (!smokeOps.has(c.op)) continue;
    // Adapter-allow-listed cases are language-specific by definition, so
    // they are never representative smoke cases.
    if (c.adapters) continue;
    if (seen.has(c.op)) continue;
    seen.add(c.op);
    picked.push(c);
  }
  return picked;
})();

// Per-language known divergences from the canonical oracle, keyed by language.
// Each entry is `${op} :: ${scenario}` and is asserted to STILL diverge so the
// gap fails loudly the moment the SDK conforms (mirrors KNOWN_TS_DIVERGENCES).
//
// Empty: every SDK now conforms to the canonical receipt shape. The Go
// (`challengeId:""` injected) and Ruby (`challengeId` hard-required) schema
// mismatches on `receipt.parse :: success_receipt` were both fixed in the
// per-SDK protocol-conformance round, so there are no remaining known runner
// divergences.
const KNOWN_RUNNER_DIVERGENCES: Record<string, Set<string>> = {};

const runners = discoverProtocolRunners();
for (const runner of runners) {
  const known = KNOWN_RUNNER_DIVERGENCES[runner.language] ?? new Set<string>();
  describe(`mpp-protocol conformance (spawned ${runner.language} runner)`, () => {
    const adapter = spawnedProtocolAdapter(runner);
    for (const testCase of smokeCases) {
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
