import { describe, expect, it } from "vitest";
import {
  isPaymentRejected,
  PhpBridgeError,
} from "../src/fixtures/php/charge-server";

describe("php bridge errors", () => {
  it("classifies transaction verifier failures as payment rejections", () => {
    expect(
      isPaymentRejected(
        new PhpBridgeError("payment_rejected", "missing transaction payload"),
      ),
    ).toBe(true);
  });

  it("does not classify unexpected bridge failures as payment rejections", () => {
    expect(isPaymentRejected(new PhpBridgeError("bridge_error", "boom"))).toBe(
      false,
    );
  });
});
