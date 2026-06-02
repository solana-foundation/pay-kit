import { afterEach, describe, expect, it } from "vitest";
import {
  assertNonEmptyEligibility,
  socketGateMode,
} from "../src/guards";

const originalCi = process.env.CI;

afterEach(() => {
  if (originalCi === undefined) {
    delete process.env.CI;
  } else {
    process.env.CI = originalCi;
  }
});

describe("socketGateMode", () => {
  it("runs when a socket can bind", () => {
    process.env.CI = "true";
    expect(socketGateMode(true)).toBe("run");
  });

  it("hard-fails when no socket binds under CI", () => {
    process.env.CI = "true";
    expect(socketGateMode(false)).toBe("fail");
  });

  it("skips when no socket binds outside CI", () => {
    delete process.env.CI;
    expect(socketGateMode(false)).toBe("skip");
  });

  it("treats CI=0 / CI=false as not CI", () => {
    process.env.CI = "0";
    expect(socketGateMode(false)).toBe("skip");
    process.env.CI = "false";
    expect(socketGateMode(false)).toBe("skip");
  });
});

describe("assertNonEmptyEligibility", () => {
  it("passes when all counts are positive", () => {
    expect(() =>
      assertNonEmptyEligibility({
        scenarioId: "s",
        clientCount: 1,
        serverCount: 1,
        pairCount: 1,
      }),
    ).not.toThrow();
  });

  it("fails on zero clients", () => {
    expect(() =>
      assertNonEmptyEligibility({ scenarioId: "s", clientCount: 0, serverCount: 1 }),
    ).toThrow(/zero eligible clients/);
  });

  it("fails on zero servers", () => {
    expect(() =>
      assertNonEmptyEligibility({ scenarioId: "s", clientCount: 1, serverCount: 0 }),
    ).toThrow(/zero eligible servers/);
  });

  it("fails on zero pairs", () => {
    expect(() =>
      assertNonEmptyEligibility({
        scenarioId: "s",
        clientCount: 1,
        serverCount: 1,
        pairCount: 0,
      }),
    ).toThrow(/zero client\/server pairs/);
  });
});
