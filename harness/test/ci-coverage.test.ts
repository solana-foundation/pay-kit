// Every SDK that claims a conformance suite in harness/expectations/ must be
// executed by some CI step, with HARNESS_REQUIRE=1 so a narrowed or aborted
// run cannot pass. Before this check existed, vector runners for TypeScript,
// Go, Ruby, Lua and PHP, and every protocol and flow case, were never run in
// CI at all.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import { loadAllExpectations, type Suite } from "../src/expectations";

const here = dirname(fileURLToPath(import.meta.url));
const workflowsDir = join(here, "..", "..", ".github", "workflows");

const SUITE_FILES: Record<Suite, string> = {
  vector: "test/conformance.test.ts",
  protocol: "test/protocol-conformance.test.ts",
  flow: "test/flow-conformance.test.ts",
};

type Step = { name?: string; run?: string; env?: Record<string, unknown> };
type Job = { env?: Record<string, unknown>; steps?: Step[] };

// (suite, language | "*") pairs run under HARNESS_REQUIRE=1, with their origin.
export function requiredRuns(): Map<string, string[]> {
  const runs = new Map<string, string[]>();
  for (const file of readdirSync(workflowsDir).filter((f) => /\.ya?ml$/.test(f)).sort()) {
    const doc = parseYaml(readFileSync(join(workflowsDir, file), "utf8")) as {
      env?: Record<string, unknown>;
      jobs?: Record<string, Job>;
    };
    for (const [jobId, job] of Object.entries(doc.jobs ?? {})) {
      for (const step of job.steps ?? []) {
        if (typeof step.run !== "string") continue;
        const env = { ...(doc.env ?? {}), ...(job.env ?? {}), ...(step.env ?? {}) };
        if (String(env.HARNESS_REQUIRE ?? "") !== "1") continue;
        const languages = String(env.MPP_CONFORMANCE_LANGUAGES ?? "*")
          .split(",")
          .map((l) => l.trim())
          .filter(Boolean);
        for (const [suite, testFile] of Object.entries(SUITE_FILES)) {
          if (!step.run.includes(testFile)) continue;
          for (const language of languages) {
            const key = `${suite}:${language}`;
            runs.set(key, [...(runs.get(key) ?? []), `${file}#${jobId}`]);
          }
        }
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
