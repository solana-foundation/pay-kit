import { describe, expect, it } from "vitest";
import {
  assertDeclaredModeWasExecuted,
  assertStrictModeCoverage,
  declaresModeSupport,
  recordModeExecution,
} from "../src/conformance/mode-support";
import {
  discoverRunners,
  type ModeCapabilities,
} from "../src/conformance/runners";
import { assertRequestedLanguagesResolved } from "../src/conformance/select";

const capabilities: ModeCapabilities = {
  "x402-exact": ["verify-x402-transaction"],
};
const vector = {
  id: "partial-runner-reject-vector",
  intent: "x402-exact" as const,
  mode: "verify-x402-transaction" as const,
};
const strictCapabilities: ModeCapabilities = {
  "x402-exact": ["verify-transaction", "verify-x402-transaction"],
};

function completeMode(
  counts: Map<string, number>,
  mode: "verify-transaction" | "verify-x402-transaction",
): void {
  for (const outcome of ["accept", "reject"] as const) {
    recordModeExecution(
      counts,
      "strict-runner",
      { intent: "x402-exact", mode },
      outcome,
    );
  }
}

describe("declared conformance mode support", () => {
  it("rejects a runner that only executes part of a declared mode", () => {
    expect(declaresModeSupport(capabilities, vector)).toBe(true);
    expect(() => {
      for (const result of [
        { id: "partial-runner-accept-vector", outcome: "accept" as const },
        { id: vector.id, outcome: "unsupported-mode" as const },
      ]) {
        assertDeclaredModeWasExecuted(
          "partial-runner",
          capabilities,
          vector,
          result,
        );
      }
    }).toThrow(
      /partial-runner.*declares.*verify-x402-transaction.*unsupported-mode/,
    );
  });

  it("pins Rust x402-exact to both strict verifier modes", () => {
    const rust = discoverRunners().find((runner) => runner.language === "rust");
    expect(rust?.strictModesByIntent?.["x402-exact"]).toEqual([
      "verify-transaction",
      "verify-x402-transaction",
    ]);
  });

  it("rejects a missing strict mode", () => {
    const counts = new Map<string, number>();
    completeMode(counts, "verify-transaction");

    expect(() =>
      assertStrictModeCoverage("strict-runner", strictCapabilities, counts),
    ).toThrow(/verify-x402-transaction.*no accept/);
  });

  it("rejects a strict mode with only one outcome", () => {
    const counts = new Map<string, number>();
    completeMode(counts, "verify-transaction");
    recordModeExecution(
      counts,
      "strict-runner",
      { intent: "x402-exact", mode: "verify-x402-transaction" },
      "accept",
    );

    expect(() =>
      assertStrictModeCoverage("strict-runner", strictCapabilities, counts),
    ).toThrow(/verify-x402-transaction.*no reject/);
  });

  it("rejects a partially unmatched language allowlist", () => {
    expect(() =>
      assertRequestedLanguagesResolved(
        new Set(["rust", "ruts"]),
        ["rust"],
        ["rust", "typescript"],
        "fixture allowlist",
      ),
    ).toThrow(/did not resolve requested language\(s\): ruts/);
  });
});
