// Maturity gate (bedrock gauge): no harness test may silently go dead in CI.
//
// The multi-agent audit's #1 systemic finding was that ~21 of 25 harness test
// files never ran in any workflow — the safety net existed but was unplugged,
// so real bugs (compute-budget cap gaps, canonical divergences, fund-safety
// defect vectors) shipped green. This gate makes that regression IMPOSSIBLE:
// every harness/test/*.test.ts must be either (a) referenced by name in a CI
// workflow, or (b) listed in CI_EXEMPT with a concrete reason. A new test that
// is neither wired nor exempted turns this RED — you cannot add a radar test and
// forget to run it.
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url)); // harness/test
const testDir = here;
const workflowsDir = join(here, "..", "..", ".github", "workflows");

// Tests that legitimately do NOT run in the standard push/PR legs, each with a
// reason. These are the E2E tier (Testing Trophy: kept minimal) — they need a
// live surfnet + the payment-channels program or multiple running SDK servers,
// so they run in dedicated on-chain / matrix legs (harness.yml, go.yml
// playground) or are opt-in, NOT the fast unit job. Keep this list SMALL and
// justified; prefer wiring a test over exempting it.
const CI_EXEMPT: Record<string, string> = {
  "onchain.e2e.test.ts":
    "on-chain E2E: needs a live surfnet + payment-channels program; core on-chain settlement is covered by the e2e.test.ts matrix legs (charge/x402-exact/x402-upto/session).",
  "x402-exact.e2e.test.ts":
    "on-chain/cross-server E2E: opt-in via the X402_HARNESS_* surfnet + real-SDK-server setup (matrix legs), not the fast unit job.",
  "x402-upto.e2e.test.ts":
    "on-chain E2E: needs surfnet + the payment-channels program; the x402-upto flow runs via the e2e.test.ts matrix leg.",
  "cross-server-scenarios.test.ts":
    "cross-server matrix E2E: needs multiple live SDK servers; runs via the harness matrix legs (opt-in X402_HARNESS_CROSS_SERVER).",
  // protocol-conformance.test.ts is no longer exempt: it now honors
  // MPP_CONFORMANCE_LANGUAGES (spawn loop filtered) and is wired into ci.yml
  // pinned to `typescript`, running the canonical challenge/receipt vectors
  // against the real TS reference codecs. The 6 divergences it caught are fixed.
};

// Strip YAML comments before matching: a test path that appears only in a
// comment / doc block is NOT execution, so it must not count as "wired". The
// real wirings live in `run:` command lines (and env/matrix entries). Strips
// BOTH full-line comments AND trailing inline comments (` # ...` — a YAML inline
// comment must be whitespace-preceded), so `run: vitest test/a.test.ts # test/b.test.ts`
// no longer falsely counts test/b as wired. Over-stripping (a `#` inside a
// value) only risks a FALSE NEGATIVE (RED), never a false green, so it errs safe.
function stripYamlComments(text: string): string {
  return text
    .split("\n")
    .map((line) => (/^\s*#/.test(line) ? "" : line.replace(/\s+#.*$/, "")))
    .join("\n");
}

const workflowText = readdirSync(workflowsDir)
  .filter((name) => /\.ya?ml$/.test(name))
  .map((name) => stripYamlComments(readFileSync(join(workflowsDir, name), "utf8")))
  .join("\n");

const allTests = readdirSync(testDir)
  .filter((name) => name.endsWith(".test.ts"))
  .sort();

describe("CI coverage gate: every harness test runs in CI (or is documented-exempt)", () => {
  it("finds a non-trivial set of harness tests and workflow files", () => {
    expect(allTests.length).toBeGreaterThan(10);
    expect(workflowText.length).toBeGreaterThan(100);
  });

  it("does not carry stale CI_EXEMPT entries", () => {
    for (const f of Object.keys(CI_EXEMPT)) {
      expect(
        allTests,
        `CI_EXEMPT names '${f}' but no such harness test exists — remove the stale exemption`,
      ).toContain(f);
    }
  });

  for (const test of allTests) {
    it(`${test} is wired into a workflow or in CI_EXEMPT`, () => {
      const wired = workflowText.includes(`test/${test}`);
      const exempt = Object.prototype.hasOwnProperty.call(CI_EXEMPT, test);
      if (!wired && !exempt) {
        throw new Error(
          `harness/test/${test} is not referenced by any .github/workflows/*.yml ` +
            `and is not in CI_EXEMPT. Wire it into a CI step, or add it to ` +
            `CI_EXEMPT with a reason. (This gate exists because the audit found ` +
            `~21 harness tests silently dead in CI.)`,
        );
      }
      if (wired && exempt) {
        throw new Error(
          `harness/test/${test} is BOTH wired in a workflow and listed in ` +
            `CI_EXEMPT — the exemption is stale, remove it from CI_EXEMPT.`,
        );
      }
    });
  }
});
