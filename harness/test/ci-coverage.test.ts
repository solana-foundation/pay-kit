// Every SDK that claims a conformance suite in harness/expectations/ must be
// executed by some CI step that cannot pass on a narrowed run. Before this
// check existed, vector runners for TypeScript, Go, Ruby, Lua and PHP, and
// every protocol and flow case, were never run in CI at all.
//
// The vector suite is run by `pkc run --sdk <lang> --tier offline --require`
// (rust/crates/conformance); the protocol and flow suites are still vitest
// files gated by HARNESS_REQUIRE=1; the interop suite by `pkc run --tier
// interop --shard <lang> --require` in the planned `Conformance / <sdk>`
// matrix job (expanded from harness/interop-plan.json); the cross suite by
// `pkc run --cross --require` in the nightly workflow, not on PRs.

import { describe, expect, it } from "vitest";
import { plannedMatrix, testNamePattern, type WorkflowStep, workflowRunSteps } from "../src/ci-workflows";
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
  interop: "pkc run --tier interop --shard <lang> --require",
};

// The shard an interop `pkc run` step drives, or undefined when it cannot
// prove completeness (narrowed with --case, --discover, or no --require).
export function pkcInteropShard(step: WorkflowStep): string | undefined {
  if (!PKC_RUN.test(step.run) || !/--tier[ =]interop\b/.test(step.run)) return undefined;
  if (/--case\b|--discover\b/.test(step.run)) return undefined;
  if (!/--require\b/.test(step.run) && step.env.HARNESS_REQUIRE !== "1") return undefined;
  return step.run.match(/--shard[ =](\S+)/)?.[1];
}

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
  if (/--case\b|--discover\b|--cross\b|--tier[ =]interop\b/.test(step.run)) return undefined;
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
    const shard = pkcInteropShard(step);
    if (shard) add("interop", shard, step.origin);
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

  it("counts a required interop shard (control) and ignores a narrowed one", () => {
    expect(requiredRuns([step("pkc run --tier interop --shard go --require", {})]).get("interop:go")).toHaveLength(1);
    expect(requiredRuns([step("pkc run --tier interop --shard go", {})]).get("interop:go")).toBeUndefined();
    expect(
      requiredRuns([step("pkc run --tier interop --shard go --require --case charge-basic", {})]).get("interop:go"),
    ).toBeUndefined();
    // An interop run is never a vector run.
    expect(requiredRuns([step("pkc run --sdk go --tier interop --require", {})]).get("vector:go")).toBeUndefined();
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

  const shards = new Map(plannedMatrix().map((s) => [s.sdk, s]));

  for (const exp of expectations.values()) {
    for (const suite of Object.keys(SUITE_RUNNER) as Suite[]) {
      if (exp.capabilities[suite].size === 0) continue;
      // An SDK whose interop claims own no case (it is only ever the
      // counterparty of another SDK's shard) has nothing to schedule.
      if (suite === "interop" && !shards.get(exp.language)?.interop) continue;
      it(`${exp.language} ${suite}`, () => {
        const where = [...(runs.get(`${suite}:${exp.language}`) ?? []), ...(runs.get(`${suite}:*`) ?? [])];
        expect(
          where,
          `${exp.language} claims the ${suite} suite but no CI step runs \`${SUITE_RUNNER[suite]}\` for it`,
        ).not.toEqual([]);
      });
    }
  }

  it("every planned interop shard runs on every pull request", () => {
    const pr = requiredRuns(workflowRunSteps().filter((s) => s.origin.startsWith("conformance.yml#")));
    for (const shard of shards.values()) {
      if (!shard.interop) continue;
      expect(pr.get(`interop:${shard.sdk}`), `no PR step runs the ${shard.sdk} interop shard`).toBeDefined();
    }
  });

  it("the cross matrix runs nightly, not on pull requests", () => {
    const where = runs.get("cross:*") ?? [];
    expect(where.some((o) => o.startsWith("conformance-nightly.yml#"))).toBe(true);
    expect(where.filter((o) => o.startsWith("conformance.yml#"))).toEqual([]);
  });

  it("every language named in a required conformance step has an expectations file", () => {
    const unknown = [...runs.keys()]
      .map((k) => k.split(":")[1])
      .filter((l) => l !== "*" && !expectations.has(l));
    expect(unknown).toEqual([]);
  });
});
