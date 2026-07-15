// CI meta-checks for the harness release-gate false-green killers.
//
// These are config/guard tests, not payment tests: they assert that the
// machinery which is supposed to turn a zero-assertion run RED actually does.
//
//   - M-8: `scripts/assert-run-count.mjs` must fail when zero settlement
//     pair-tests executed, and `passWithNoTests` must be false in both harness
//     vitest configs so a filtered-to-empty run cannot exit green on its own.
//   - M-9: the on-chain gate must hard-fail when the on-chain config runs under
//     CI without HARNESS_ONCHAIN=1.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";

import {
  ONCHAIN_FLAG_MISSING_CI_MESSAGE,
  assertOnchainGate,
} from "./onchain-gate.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const harnessRoot = path.resolve(here, "..");
const assertRunCountScript = path.join(harnessRoot, "scripts", "assert-run-count.mjs");

function writeReport(contents: unknown): string {
  const dir = mkdtempSync(path.join(tmpdir(), "harness-gate-"));
  const file = path.join(dir, "report.json");
  writeFileSync(file, JSON.stringify(contents));
  return file;
}

// A vitest JSON report with `count` executed (passed) settlement pair-tests and
// `skipped` filtered-out ones, plus the per-scenario eligibility guard test.
function reportWith(count: number, skipped = 0): unknown {
  const assertionResults: { title: string; status: string }[] = [
    { title: "charge-basic: has at least one eligible client/server pair", status: "passed" },
  ];
  for (let i = 0; i < count; i += 1) {
    assertionResults.push({
      title: `charge-basic: client-${i} client pays typescript server`,
      status: "passed",
    });
  }
  for (let i = 0; i < skipped; i += 1) {
    assertionResults.push({
      title: `charge-basic: skipped-${i} client pays typescript server`,
      status: "skipped",
    });
  }
  return { success: true, testResults: [{ assertionResults }] };
}

function runAssertRunCount(args: string[]): { code: number; stderr: string } {
  const result = spawnSync(process.execPath, [assertRunCountScript, ...args], {
    encoding: "utf8",
  });
  return { code: result.status ?? -1, stderr: `${result.stdout}${result.stderr}` };
}

describe("M-8: assert-run-count run-count guard", () => {
  it("fails when zero settlement pair-tests executed", () => {
    const report = writeReport(reportWith(0, 3));
    const { code, stderr } = runAssertRunCount(["--report", report, "--min", "1"]);
    expect(code, stderr).not.toBe(0);
    expect(stderr).toContain("Zero settlement pair-tests EXECUTED");
  });

  it("passes when the executed pair count meets the floor", () => {
    const report = writeReport(reportWith(2));
    const { code, stderr } = runAssertRunCount(["--report", report, "--min", "1"]);
    expect(code, stderr).toBe(0);
  });

  it("fails when the executed pair count is below the pinned floor", () => {
    const report = writeReport(reportWith(1));
    const { code, stderr } = runAssertRunCount(["--report", report, "--min", "3"]);
    expect(code, stderr).not.toBe(0);
    expect(stderr).toContain("at least 3");
  });

  it("fails when the exact pinned pair count drifts", () => {
    const report = writeReport(reportWith(2));
    const { code, stderr } = runAssertRunCount(["--report", report, "--exact", "3"]);
    expect(code, stderr).not.toBe(0);
    expect(stderr).toContain("exactly 3");
  });

  it("passes when the exact pinned pair count matches", () => {
    const report = writeReport(reportWith(3));
    const { code, stderr } = runAssertRunCount(["--report", report, "--exact", "3"]);
    expect(code, stderr).toBe(0);
  });

  it("fails when the underlying vitest run did not succeed", () => {
    const report = writeReport({
      success: false,
      testResults: [
        {
          assertionResults: [
            { title: "charge-basic: a client pays typescript server", status: "passed" },
          ],
        },
      ],
    });
    const { code, stderr } = runAssertRunCount(["--report", report, "--min", "1"]);
    expect(code, stderr).not.toBe(0);
    expect(stderr).toContain("success=false");
  });

  it("counts cross-server and idempotent pair titles as executed", () => {
    const report = writeReport({
      success: true,
      testResults: [
        {
          assertionResults: [
            { title: "x-port: typescript client, A=typescript B=rust", status: "passed" },
            { title: "charge-idem: typescript client pays rust server twice", status: "passed" },
            { title: "charge-idem: has at least one eligible idempotent pair", status: "passed" },
          ],
        },
      ],
    });
    const { code, stderr } = runAssertRunCount(["--report", report, "--exact", "2"]);
    expect(code, stderr).toBe(0);
  });

  it("fails all-assertion mode when every selected test was skipped", () => {
    const report = writeReport({
      success: true,
      testResults: [{ assertionResults: [{ title: "security suite", status: "skipped" }] }],
    });
    const { code, stderr } = runAssertRunCount(["--report", report, "--all", "--min", "1"]);
    expect(code, stderr).not.toBe(0);
    expect(stderr).toContain("Zero test assertion(s) EXECUTED");
  });

  it("counts every passed assertion in all-assertion mode", () => {
    const report = writeReport({
      success: true,
      testResults: [
        {
          assertionResults: [
            { title: "security suite one", status: "passed" },
            { title: "security suite two", status: "passed" },
          ],
        },
      ],
    });
    const { code, stderr } = runAssertRunCount(["--report", report, "--all", "--exact", "2"]);
    expect(code, stderr).toBe(0);
  });
});

describe("M-9: on-chain settlement gate", () => {
  it("throws under CI when HARNESS_ONCHAIN is unset", () => {
    expect(() => assertOnchainGate({ CI: "true" })).toThrowError(
      ONCHAIN_FLAG_MISSING_CI_MESSAGE,
    );
  });

  it("throws under CI when HARNESS_ONCHAIN is not exactly 1", () => {
    expect(() => assertOnchainGate({ CI: "1", HARNESS_ONCHAIN: "0" })).toThrowError(
      ONCHAIN_FLAG_MISSING_CI_MESSAGE,
    );
  });

  it("does not throw under CI when HARNESS_ONCHAIN=1", () => {
    expect(() => assertOnchainGate({ CI: "true", HARNESS_ONCHAIN: "1" })).not.toThrow();
  });

  it("does not throw outside CI even without the flag", () => {
    expect(() => assertOnchainGate({})).not.toThrow();
    expect(() => assertOnchainGate({ CI: "0" })).not.toThrow();
    expect(() => assertOnchainGate({ CI: "false" })).not.toThrow();
  });
});

describe("M-8/M-9: vitest configs disable passWithNoTests", () => {
  it("vitest.config.ts sets passWithNoTests: false", () => {
    const source = readFileSync(path.join(harnessRoot, "vitest.config.ts"), "utf8");
    expect(source).toMatch(/passWithNoTests:\s*false/);
  });

  it("vitest.onchain.config.ts sets passWithNoTests: false and wires the gate setup", () => {
    const source = readFileSync(
      path.join(harnessRoot, "vitest.onchain.config.ts"),
      "utf8",
    );
    expect(source).toMatch(/passWithNoTests:\s*false/);
    expect(source).toMatch(/onchain\.setup/);
  });
});
