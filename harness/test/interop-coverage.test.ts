import { describe, expect, it } from "vitest";
import { testNamePattern } from "../src/ci-workflows";
import { chargeReplayMatchesPlanner, executedInterop } from "../interop-coverage";

describe("interop coverage analyzer", () => {
  it("agrees with the charge planner, which enumerates every eligible case", () => {
    expect(chargeReplayMatchesPlanner()).toBe(true);
  });

  it("every executed case is an eligible case", () => {
    const { executed, eligible } = executedInterop();
    const eligibleKeys = new Set(eligible.map((c) => `${c.scenario.id}|${c.client}|${c.server}`));
    expect([...executed.keys()].filter((k) => !eligibleKeys.has(k))).toEqual([]);
  });

  it("parses test-name filters the way CI writes them", () => {
    expect(testNamePattern(`pnpm exec vitest run test/e2e.test.ts --testNamePattern "rust client pays lua server"`))
      .toBe("rust client pays lua server");
    expect(testNamePattern(`vitest run test/e2e.test.ts -t 'ruby' --testTimeout 1`)).toBe("ruby");
    expect(testNamePattern(`vitest run test/e2e.test.ts --testTimeout 180000`)).toBeUndefined();
  });
});
