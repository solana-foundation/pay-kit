import { afterEach, describe, expect, it } from "vitest";
import {
  assertNonEmptyEligibility,
  evaluateShardEligibility,
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

describe("evaluateShardEligibility", () => {
  it("runs when the shard has eligible clients, servers, and pairs", () => {
    expect(
      evaluateShardEligibility({
        scenarioId: "s",
        shard: { clientCount: 1, serverCount: 1, pairCount: 1 },
        full: { clientCount: 1, serverCount: 1, pairCount: 1 },
      }),
    ).toEqual({ verdict: "run" });
  });

  it("skips (does not throw) when the shard excludes a server the full registry has", () => {
    const result = evaluateShardEligibility({
      scenarioId: "charge-decimals-9",
      // Shard has the client but no server (the server lives in another shard).
      shard: { clientCount: 1, serverCount: 0, pairCount: 0 },
      full: { clientCount: 1, serverCount: 1, pairCount: 1 },
    });
    expect(result.verdict).toBe("skip");
    if (result.verdict === "skip") {
      expect(result.reason).toMatch(/no eligible server in the enabled adapter subset/);
    }
  });

  it("skips when the shard excludes a client the full registry has", () => {
    const result = evaluateShardEligibility({
      scenarioId: "charge-sol-native",
      shard: { clientCount: 0, serverCount: 1, pairCount: 0 },
      full: { clientCount: 1, serverCount: 1, pairCount: 1 },
    });
    expect(result.verdict).toBe("skip");
  });

  it("skips when the shard has client+server but no pair, while the full registry pairs", () => {
    const result = evaluateShardEligibility({
      scenarioId: "charge-cross-server-portability",
      shard: { clientCount: 1, serverCount: 1, pairCount: 0 },
      full: { clientCount: 1, serverCount: 1, pairCount: 1 },
    });
    expect(result.verdict).toBe("skip");
  });

  it("HARD FAILS (throws) when the scenario has zero servers across the FULL registry", () => {
    expect(() =>
      evaluateShardEligibility({
        scenarioId: "genuinely-misconfigured",
        shard: { clientCount: 1, serverCount: 0, pairCount: 0 },
        full: { clientCount: 1, serverCount: 0, pairCount: 0 },
      }),
    ).toThrow(/zero eligible servers/);
  });

  it("HARD FAILS when the scenario has zero clients across the FULL registry", () => {
    expect(() =>
      evaluateShardEligibility({
        scenarioId: "genuinely-misconfigured",
        shard: { clientCount: 0, serverCount: 1, pairCount: 0 },
        full: { clientCount: 0, serverCount: 1, pairCount: 0 },
      }),
    ).toThrow(/zero eligible clients/);
  });

  it("HARD FAILS when the scenario has zero pairs across the FULL registry", () => {
    expect(() =>
      evaluateShardEligibility({
        scenarioId: "genuinely-misconfigured",
        shard: { clientCount: 1, serverCount: 1, pairCount: 0 },
        full: { clientCount: 1, serverCount: 1, pairCount: 0 },
      }),
    ).toThrow(/zero client\/server pairs/);
  });
});
