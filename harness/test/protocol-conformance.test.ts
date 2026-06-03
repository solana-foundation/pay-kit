// Drives the vendored canonical mpp-protocol vectors (tempoxyz/mpp-tools,
// MIT) through pay-kit's TypeScript protocol layer (mppx). Every challenge
// / credential / receipt header codec case, every base64url case, and every
// challenge-id HMAC case must match the canonical golden output.
//
// This is the reference wiring: per-language runners plug a spawned-process
// `ProtocolAdapter` into the same `runCase` driver.

import { describe, expect, it } from "vitest";
import { collectProtocolCases } from "../src/protocol/vectors";
import { runCase } from "../src/protocol/driver";
import { typescriptProtocolAdapter } from "../src/protocol/runners/typescript";
import {
  discoverProtocolRunners,
  spawnedProtocolAdapter,
} from "../src/protocol/runners/spawn";

const cases = collectProtocolCases();

// Known divergences between pay-kit's TypeScript protocol core (mppx) and the
// canonical mpp-tools oracle. Each entry is `${op} :: ${scenario}`. These are
// asserted to STILL diverge so the gap is tracked, not silently green; when an
// SDK fix lands, the divergence test fails loudly and the entry is removed.
//
// - challenge.parse :: error_empty_id
//     The canonical spec (and pay-kit's own rust spine, protocol/core/
//     headers.rs) reject a WWW-Authenticate challenge with an empty `id`
//     parameter as parse_error. mppx@0.5.5 accepts it (its Zod `id` schema
//     allows ""). base64url + challenge-id HMAC are byte-identical; this is a
//     missing validation guard on the TS parse path, not a wire-math gap.
const KNOWN_TS_DIVERGENCES = new Set<string>([
  "challenge.parse :: error_empty_id",
]);

describe("mpp-protocol conformance (canonical vectors / TypeScript runner)", () => {
  it("expands a non-trivial set of canonical cases", () => {
    expect(cases.length).toBeGreaterThan(40);
  });

  for (const testCase of cases) {
    const key = `${testCase.op} :: ${testCase.scenario}`;
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
    if (seen.has(c.op)) continue;
    seen.add(c.op);
    picked.push(c);
  }
  return picked;
})();

const runners = discoverProtocolRunners();
for (const runner of runners) {
  describe(`mpp-protocol conformance (spawned ${runner.language} runner)`, () => {
    const adapter = spawnedProtocolAdapter(runner);
    for (const testCase of smokeCases) {
      it(`${testCase.op} :: ${testCase.scenario}`, async () => {
        const result = await runCase(adapter, testCase);
        expect(result.ok, result.detail).toBe(true);
      });
    }
  });
}
