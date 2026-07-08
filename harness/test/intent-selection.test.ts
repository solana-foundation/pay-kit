import { describe, expect, it } from "vitest";
import { selectHarnessIntents, selectHarnessScenarios } from "../src/contracts";

describe("harness intent selection", () => {
  it("defaults to the legacy charge intent for CI stability", () => {
    // x402-exact is opt-in via MPP_HARNESS_INTENTS=x402-exact (or
    // comma-list) so the canonical MPP charge matrix in the existing
    // runner is not perturbed by the new intent's enabled-by-default
    // adapters.
    expect(selectHarnessIntents(undefined)).toEqual(["charge"]);
  });

  it("accepts the implemented charge scenario", () => {
    expect(selectHarnessIntents(" charge ")).toEqual(["charge"]);
  });

  it("accepts the implemented x402-exact intent", () => {
    expect(selectHarnessIntents("x402-exact")).toEqual(["x402-exact"]);
  });

  it("accepts session intent", () => {
    expect(selectHarnessIntents("session")).toEqual(["session"]);
  });

  it("accepts the implemented x402-upto intent", () => {
    expect(selectHarnessIntents("x402-upto")).toEqual(["x402-upto"]);
  });

  it("accepts all intents at once", () => {
    expect(selectHarnessIntents("charge,x402-exact,session,x402-upto")).toEqual([
      "charge",
      "x402-exact",
      "session",
      "x402-upto",
    ]);
  });

  it("rejects scenarios that are not implemented yet", () => {
    expect(() => selectHarnessIntents("batch-settlement")).toThrow(
      /Unsupported MPP_HARNESS_INTENTS/,
    );
  });
});

describe("harness scenario selection", () => {
  it("defaults to all charge scenarios", () => {
    expect(
      selectHarnessScenarios(undefined, undefined).map(
        (scenario) => scenario.id,
      ),
    ).toEqual([
      "charge-basic",
      "charge-split-ata",
      "charge-push",
      "charge-network-mismatch",
      "charge-cross-route-replay",
      "charge-symbol-usdc-localnet",
      "charge-token2022-split-ata",
      "charge-decimals-9",
      "charge-split-ata-idempotent",
      "charge-compute-budget-over-cap",
      "charge-sol-native",
      "charge-splits-too-many",
      "charge-splits-sum-equals-amount",
      "charge-cross-server-portability",
      "charge-idempotent-resubmit",
    ]);
  });

  it("returns x402-exact scenarios when explicitly requested", () => {
    expect(
      selectHarnessScenarios("x402-exact", undefined).map(
        (scenario) => scenario.id,
      ),
    ).toEqual([
      "x402-exact-basic",
      "x402-exact-network-mismatch",
      "x402-exact-cross-route-replay",
      "x402-exact-cross-server-portability",
      "x402-exact-idempotent-resubmit",
    ]);
  });

  it("returns session scenarios when explicitly requested", () => {
    expect(
      selectHarnessScenarios("session", undefined).map((scenario) => scenario.id),
    ).toEqual(["session-basic"]);
  });

  it("returns x402-upto scenarios when explicitly requested", () => {
    expect(
      selectHarnessScenarios("x402-upto", undefined).map(
        (scenario) => scenario.id,
      ),
    ).toEqual(["x402-upto-basic", "x402-upto-zero-actual"]);
  });

  it("runs one requested scenario", () => {
    expect(
      selectHarnessScenarios("charge", "charge-split-ata").map(
        (scenario) => scenario.id,
      ),
    ).toEqual(["charge-split-ata"]);
  });

  it("rejects unknown scenario ids", () => {
    expect(() => selectHarnessScenarios("charge", "unknown")).toThrow(
      /Unsupported MPP_HARNESS_SCENARIOS/,
    );
  });
});
