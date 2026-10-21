// Every SDK that claims a conformance suite in harness/expectations/ must be
// executed by some CI step that cannot pass on a narrowed run. Before this
// check existed, vector runners for TypeScript, Go, Ruby, Lua and PHP, and
// every protocol and flow case, were never run in CI at all.
//
// The vector suite is run by `pkc run --sdk <lang> --tier offline --require`
// (rust/crates/conformance); the protocol and flow suites are still vitest
// files gated by HARNESS_REQUIRE=1.

import { describe, expect, it } from "vitest";
import { testNamePattern, type WorkflowStep, workflowRunSteps } from "../src/ci-workflows";
import { loadAllExpectations, type Suite } from "../src/expectations";

const VITEST_SUITE_FILES: Partial<Record<Suite, string>> = {
  protocol: "test/protocol-conformance.test.ts",
  flow: "test/flow-conformance.test.ts",
};

// How each suite is run, for failure messages.
const SUITE_RUNNER: Record<Suite, string> = {
  vector: "pkc run --sdk <lang> --tier offline --require",
  protocol: "pnpm exec vitest run test/protocol-conformance.test.ts (HARNESS_REQUIRE=1)",
  flow: "pnpm exec vitest run test/flow-conformance.test.ts (HARNESS_REQUIRE=1)",
  cross: "pkc run --cross --require (after every client's offline run)",
};

// The servers a `pkc run --cross` step reconciles ("*" when not narrowed),
// or undefined when it does not require completeness: without --require a
// missing client build or an unclaimed verifier is not an error.
export function pkcCrossLanguages(step: WorkflowStep): string[] | undefined {
  if (!PKC_RUN.test(step.run) || !/--cross\b/.test(step.run)) return undefined;
  if (!/--require\b/.test(step.run) && step.env.HARNESS_REQUIRE !== "1") return undefined;
  const sdk = step.run.match(/--sdk[ =](\S+)/)?.[1];
  if (!sdk) return ["*"];
  return sdk
    .split(",")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => (l === "all" ? "*" : l));
}

// `pkc run ...` or `cargo run ... --bin pkc -- run ...`.
const PKC_RUN = /\bpkc\b(?:\s+--)?\s+run\b/;

// The SDKs a `pkc run` step drives, or undefined when the step cannot prove
// completeness: it is not a pkc run, it is narrowed with --case, it judges
// nothing (--discover), or it does not require completeness.
export function pkcVectorLanguages(step: WorkflowStep): string[] | undefined {
  if (!PKC_RUN.test(step.run)) return undefined;
  if (/--case\b|--discover\b|--cross\b/.test(step.run)) return undefined;
  if (!/--require\b/.test(step.run) && step.env.HARNESS_REQUIRE !== "1") return undefined;
  const sdk = step.run.match(/--sdk[ =](\S+)/)?.[1];
  if (!sdk) return undefined;
  return sdk
    .split(",")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => (l === "all" ? "*" : l));
}

// (suite, language | "*") pairs run so that a narrowed run fails, with their
// origin. A vitest step with a test-name filter does not count: it may
// select only part of a suite, so it cannot prove a language's claims ran.
function requiredRuns(steps: readonly WorkflowStep[] = workflowRunSteps()): Map<string, string[]> {
  const runs = new Map<string, string[]>();
  const add = (suite: Suite, language: string, origin: string) => {
    const key = `${suite}:${language}`;
    runs.set(key, [...(runs.get(key) ?? []), origin]);
  };
  for (const step of steps) {
    for (const language of pkcVectorLanguages(step) ?? []) add("vector", language, step.origin);
    for (const language of pkcCrossLanguages(step) ?? []) add("cross", language, step.origin);
    if (step.env.HARNESS_REQUIRE !== "1") continue;
    if (testNamePattern(step.run) !== undefined) continue;
    const languages = (step.env.MPP_CONFORMANCE_LANGUAGES ?? "*")
      .split(",")
      .map((l) => l.trim())
      .filter(Boolean);
    for (const [suite, testFile] of Object.entries(VITEST_SUITE_FILES)) {
      if (!step.run.includes(testFile)) continue;
      for (const language of languages) add(suite as Suite, language, step.origin);
    }
  }
  return runs;
}

describe("requiredRuns", () => {
  const step = (run: string, env: Record<string, string> = { HARNESS_REQUIRE: "1" }): WorkflowStep => ({
    origin: "x.yml#job/step",
    run,
    env: { ...env, MPP_CONFORMANCE_LANGUAGES: "go" },
  });

  it("counts a required pkc run (control)", () => {
    expect(requiredRuns([step("pkc run --sdk go --tier offline --require")]).get("vector:go")).toHaveLength(1);
    expect(
      requiredRuns([step("cargo run -q -p paykit-conformance --bin pkc -- run --sdk go,rust --tier offline --require")]).get(
        "vector:rust",
      ),
    ).toHaveLength(1);
    expect(requiredRuns([step("pkc run --sdk all --tier offline --require")]).get("vector:*")).toHaveLength(1);
  });

  it("ignores a pkc run that is narrowed, judges nothing or does not require completeness", () => {
    for (const run of [
      "pkc run --sdk go --tier offline --require --case charge-sol-native-build",
      "pkc run --sdk go --tier offline --discover",
      "pkc run --sdk go --tier offline",
    ]) {
      expect(requiredRuns([step(run, {})]).get("vector:go"), run).toBeUndefined();
    }
  });

  it("counts a required cross run for every server (control)", () => {
    expect(requiredRuns([step("pkc run --cross --require --check", {})]).get("cross:*")).toHaveLength(1);
    expect(requiredRuns([step("pkc run --cross", { HARNESS_REQUIRE: "1" })]).get("cross:*")).toHaveLength(1);
    expect(requiredRuns([step("pkc run --cross --require --sdk go", {})]).get("cross:go")).toHaveLength(1);
  });

  it("ignores a cross run that does not require completeness", () => {
    expect(requiredRuns([step("pkc run --cross --check", {})]).get("cross:*")).toBeUndefined();
    // A cross run is never a vector run.
    expect(requiredRuns([step("pkc run --cross --require --sdk go", {})]).get("vector:go")).toBeUndefined();
  });

  it("counts an unfiltered required vitest step (control)", () => {
    expect(
      requiredRuns([step("pnpm exec vitest run test/protocol-conformance.test.ts")]).get("protocol:go"),
    ).toHaveLength(1);
  });

  it("ignores a vitest step with a test-name filter", () => {
    expect(
      requiredRuns([step('pnpm exec vitest run test/protocol-conformance.test.ts -t "go"')]).get("protocol:go"),
    ).toBeUndefined();
  });
});

describe("CI runs every claimed conformance suite", () => {
  const runs = requiredRuns();
  const expectations = loadAllExpectations();

  for (const exp of expectations.values()) {
    for (const suite of Object.keys(SUITE_RUNNER) as Suite[]) {
      if (exp.capabilities[suite].size === 0) continue;
      it(`${exp.language} ${suite}`, () => {
        const where = [...(runs.get(`${suite}:${exp.language}`) ?? []), ...(runs.get(`${suite}:*`) ?? [])];
        expect(
          where,
          `${exp.language} claims the ${suite} suite but no CI step runs \`${SUITE_RUNNER[suite]}\` for it`,
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
