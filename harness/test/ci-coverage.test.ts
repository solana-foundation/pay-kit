// Every SDK that claims a conformance suite in harness/expectations/ must be
// executed by some CI step, with HARNESS_REQUIRE=1 so a narrowed or aborted
// run cannot pass. Before this check existed, vector runners for TypeScript,
// Go, Ruby, Lua and PHP, and every protocol and flow case, were never run in
// CI at all.

import { describe, expect, it } from "vitest";
import { workflowRunSteps } from "../src/ci-workflows";
import { loadAllExpectations, type Suite } from "../src/expectations";

const SUITE_FILES: Record<Suite, string> = {
  vector: "test/conformance.test.ts",
  protocol: "test/protocol-conformance.test.ts",
  flow: "test/flow-conformance.test.ts",
};

// (suite, language | "*") pairs run under HARNESS_REQUIRE=1, with their origin.
function requiredRuns(): Map<string, string[]> {
  const runs = new Map<string, string[]>();
  for (const step of workflowRunSteps()) {
    if (step.env.HARNESS_REQUIRE !== "1") continue;
    const languages = (step.env.MPP_CONFORMANCE_LANGUAGES ?? "*")
      .split(",")
      .map((l) => l.trim())
      .filter(Boolean);
    for (const [suite, testFile] of Object.entries(SUITE_FILES)) {
      if (!step.run.includes(testFile)) continue;
      for (const language of languages) {
        const key = `${suite}:${language}`;
        runs.set(key, [...(runs.get(key) ?? []), step.origin]);
      }
    }
  }
  return runs;
}

describe("CI runs every claimed conformance suite", () => {
  const runs = requiredRuns();
  const expectations = loadAllExpectations();

  for (const exp of expectations.values()) {
    for (const suite of Object.keys(SUITE_FILES) as Suite[]) {
      if (exp.capabilities[suite].size === 0) continue;
      it(`${exp.language} ${suite}`, () => {
        const where = [...(runs.get(`${suite}:${exp.language}`) ?? []), ...(runs.get(`${suite}:*`) ?? [])];
        expect(
          where,
          `${exp.language} claims the ${suite} suite but no CI step runs ${SUITE_FILES[suite]} for it with HARNESS_REQUIRE=1`,
        ).not.toEqual([]);
      });
    }
  }

  it("every language named in a required conformance step has an expectations file", () => {
    const unknown = [...runs.keys()]
      .map((k) => k.split(":")[1])
      .filter((l) => l !== "*" && !expectations.has(l));
    expect(unknown).toEqual([]);
  });
});
