import { describe, expect, it } from "vitest";
import { selectInteropIntents, selectInteropScenarios } from "../src/contracts";

describe("interop intent selection", () => {
  it("defaults to the legacy charge intent for CI stability", () => {
    // x402-exact is opt-in via MPP_INTEROP_INTENTS=x402-exact (or
    // comma-list) so the canonical MPP charge matrix in the existing
    // runner is not perturbed by the new intent's enabled-by-default
    // adapters.
    expect(selectInteropIntents(undefined)).toEqual(["charge"]);
  });

  it("accepts the implemented charge scenario", () => {
    expect(selectInteropIntents(" charge ")).toEqual(["charge"]);
  });

  it("accepts the implemented x402-exact intent", () => {
    expect(selectInteropIntents("x402-exact")).toEqual(["x402-exact"]);
  });

  it("accepts both intents at once", () => {
    expect(selectInteropIntents("charge,x402-exact")).toEqual([
      "charge",
      "x402-exact",
    ]);
  });

  it("rejects scenarios that are not implemented yet", () => {
    expect(() => selectInteropIntents("session")).toThrow(
      /Unsupported MPP_INTEROP_INTENTS/,
    );
  });
});

describe("interop scenario selection", () => {
  it("defaults to all charge scenarios", () => {
    expect(
      selectInteropScenarios(undefined, undefined).map(
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
      selectInteropScenarios("x402-exact", undefined).map(
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

  it("runs one requested scenario", () => {
    expect(
      selectInteropScenarios("charge", "charge-split-ata").map(
        (scenario) => scenario.id,
      ),
    ).toEqual(["charge-split-ata"]);
  });

  it("rejects unknown scenario ids", () => {
    expect(() => selectInteropScenarios("charge", "unknown")).toThrow(
      /Unsupported MPP_INTEROP_SCENARIOS/,
    );
  });
});
