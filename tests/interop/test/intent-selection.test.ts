import { describe, expect, it } from "vitest";
import { selectInteropIntents, selectInteropScenarios } from "../src/contracts";

describe("interop intent selection", () => {
  it("defaults to the implemented charge scenario", () => {
    expect(selectInteropIntents(undefined)).toEqual(["charge"]);
  });

  it("accepts the implemented charge scenario", () => {
    expect(selectInteropIntents(" charge ")).toEqual(["charge"]);
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
