import { describe, expect, it } from "vitest";
import {
  assertDeclaredModeWasExecuted,
  declaresModeSupport,
} from "../src/conformance/mode-support";
import type { ModeCapabilities } from "../src/conformance/runners";

const capabilities: ModeCapabilities = {
  "x402-exact": ["verify-x402-transaction"],
};
const vector = {
  id: "partial-runner-reject-vector",
  intent: "x402-exact" as const,
  mode: "verify-x402-transaction" as const,
};

describe("declared conformance mode support", () => {
  it("rejects a runner that only executes part of a declared mode", () => {
    expect(declaresModeSupport(capabilities, vector)).toBe(true);
    expect(() => {
      for (const result of [
        { id: "partial-runner-accept-vector", outcome: "accept" as const },
        { id: vector.id, outcome: "unsupported-mode" as const },
      ]) {
        assertDeclaredModeWasExecuted("partial-runner", capabilities, vector, result);
      }
    }).toThrow(/partial-runner.*declares.*verify-x402-transaction.*unsupported-mode/);
  });
});
