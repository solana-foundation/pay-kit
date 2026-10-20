import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { WORKFLOWS_DIR } from "../src/ci-workflows";
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

  it("stops counting charge shards when the matrix step is removed", () => {
    // Copy the real workflows, then drop mpp-matrix.yml's shard step.
    const dir = mkdtempSync(join(tmpdir(), "workflows-"));
    for (const file of readdirSync(WORKFLOWS_DIR)) {
      let text = readFileSync(join(WORKFLOWS_DIR, file), "utf8");
      if (file === "mpp-matrix.yml") {
        expect(text).toContain("env: ${{ matrix.env }}");
        text = text.replace(/\n\s*- name: Run exact charge shard[\s\S]*?test\/e2e\.test\.ts[^\n]*\n/, "\n");
        expect(text).not.toContain("env: ${{ matrix.env }}");
      }
      writeFileSync(join(dir, file), text);
    }
    expect(chargeReplayMatchesPlanner(WORKFLOWS_DIR)).toBe(true);
    expect(chargeReplayMatchesPlanner(dir)).toBe(false);
  });
});
