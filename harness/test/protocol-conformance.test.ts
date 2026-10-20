// Drives the vendored canonical mpp-protocol vectors (tempoxyz/mpp-tools,
// MIT) through every SDK that ships a protocol runner. Every challenge /
// credential / receipt header codec case, every base64url case, and every
// challenge-id HMAC case must match the canonical golden output.
//
// TypeScript runs in-process (src/protocol/runners/typescript.ts); every
// other language runs its manifest-declared runner under
// harness/protocol-runners/ over the spawned stdin/stdout ABI. Every
// language runs EVERY case: there is no smoke subset.
//
// Per-case expectations live in harness/expectations/<lang>.toml and are
// reconciled exactly (src/expectations.ts).
//
// Adapter allow-listed cases (canonically python-only, e.g. the adversarial
// ReDoS probe) run for every language with an explicit budget, because
// ReDoS resistance matters to every parser. For those languages the case
// asserts the time bound and accepts either the golden result or a
// parse_error, since the spec does not mandate the golden's leniency.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CaseRef, danglingEntries, decide, loadAllExpectations } from "../src/expectations";
import { CaseRecorder, discoveryMode, observe, requireMode } from "../src/expectations-run";
import { caseRunsOnAdapter, collectProtocolCases } from "../src/protocol/vectors";
import { type ProtocolAdapter, runCase } from "../src/protocol/driver";
import { typescriptProtocolAdapter } from "../src/protocol/runners/typescript";
import { discoverProtocolRunners, spawnedProtocolAdapter } from "../src/protocol/runners/spawn";
import { parseLanguageAllowlist } from "../src/conformance/select";

const cases = collectProtocolCases();
const EXPECTATIONS = loadAllExpectations();
const protocolRefs: CaseRef[] = cases.map((c) => ({
  suite: "protocol",
  id: `${c.op} :: ${c.scenario}`,
  capability: "protocol",
}));

// Budget for adapter-allow-listed adversarial cases on runners they are not
// canonically assigned to. Spawned runners add their measured start-up cost.
const ADVERSARIAL_BUDGET_MS = 5000;

const runners = discoverProtocolRunners();
// CI runs each language in the job that has its toolchain, narrowing with
// MPP_CONFORMANCE_LANGUAGES (same variable as the vector driver).
// test/ci-coverage.test.ts proves every claiming language runs somewhere.
const allowlist = parseLanguageAllowlist(process.env.MPP_CONFORMANCE_LANGUAGES);
const selectedRunners = runners.filter((r) => !allowlist || allowlist.has(r.language));

describe("mpp-protocol conformance (suite)", () => {
  it("expands a non-trivial set of canonical cases with unique ids", () => {
    expect(cases.length).toBeGreaterThan(40);
    const ids = protocolRefs.map((r) => r.id);
    expect(ids.length).toBe(new Set(ids).size);
  });

  it("every protocol runner manifest has expectations claiming protocol, and vice versa", () => {
    const manifests = runners.map((r) => r.language).sort();
    const claiming = [...EXPECTATIONS.values()]
      .filter((e) => e.capabilities.protocol.size > 0)
      .map((e) => e.language)
      .sort();
    expect(manifests).toEqual(claiming);
  });
});

for (const runner of selectedRunners) {
  const language = runner.language;
  // TypeScript uses the in-process adapter: identical ABI, no spawn cost.
  const adapter: ProtocolAdapter =
    language === "typescript" ? typescriptProtocolAdapter : spawnedProtocolAdapter(runner);

  describe(`mpp-protocol conformance (${language} runner)`, () => {
    const exp = EXPECTATIONS.get(language);
    if (!exp) throw new Error(`no harness/expectations/${language}.toml`);
    const recorder = new CaseRecorder("protocol", language);
    let startupMs = 0;

    beforeAll(async () => {
      if (adapter === typescriptProtocolAdapter) return;
      const samples: number[] = [];
      for (let i = 0; i < 2; i++) {
        const t = performance.now();
        await adapter.runProtocolRequest({ op: "base64url.encode", input: { text: "a" } });
        samples.push(performance.now() - t);
      }
      startupMs = Math.ceil(Math.min(...samples));
    }, 300_000);

    afterAll(() => {
      recorder.flush();
      if (requireMode() && !discoveryMode()) recorder.assertComplete(protocolRefs, exp);
    });

    it("expectations have no dangling entries", () => {
      expect(danglingEntries(exp, "protocol", protocolRefs)).toEqual([]);
    });

    for (const [index, testCase] of cases.entries()) {
      const ref = protocolRefs[index];
      const decision = discoveryMode() ? { kind: "pass" as const } : decide(exp, ref);
      if (decision.kind === "unclaimed") {
        recorder.record(ref, decision, undefined);
        continue;
      }
      const assigned = caseRunsOnAdapter(testCase, language);
      it(`${ref.id} [${decision.kind}]${assigned ? "" : " (adversarial budget)"}`, async () => {
        const observed = await observe(async () => {
          const result = await runCase(
            adapter,
            testCase,
            assigned ? undefined : { durationLimitMsOverride: ADVERSARIAL_BUDGET_MS + startupMs },
          );
          if (!result.ok && /unsupported_operation/.test(result.detail ?? "")) {
            return { unsupported: result.detail ?? "unsupported_operation" };
          }
          // A case the canonical suite assigns to other adapters (the
          // python-only ReDoS probe) is run here for its time bound. Its
          // golden encodes one parser's leniency toward a header that
          // violates the auth-param grammar (an unterminated quoted-string),
          // which draft-httpauth-payment-00 does not require: rejecting the
          // malformed header with parse_error is equally conformant. The
          // duration budget below stays non-waivable either way.
          if (!assigned && !result.ok && /got error_type=parse_error/.test(result.detail ?? "")) {
            return "pass";
          }
          expect(result.ok, result.detail).toBe(true);
          return "pass";
        });
        // A blown duration budget is a ReDoS finding, never a tolerated
        // divergence: it fails even when the case is listed known_failing.
        if (!discoveryMode() && observed.kind === "fail" && /duration exceeded/.test(observed.detail)) {
          recorder.record(ref, decision, observed);
          throw new Error(`${ref.id}: ${observed.detail} (possible ReDoS; cannot be listed known_failing)`);
        }
        recorder.verdict(exp, ref, decision, observed);
      }, 120_000);
    }
  });
}
