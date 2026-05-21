import { describe, expect, it } from "vitest";
import {
  formatPaymentReceipt,
  isSettledSignatureStatus,
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

  it("rejects confirmed transactions with on-chain errors", () => {
    expect(() =>
      isSettledSignatureStatus("sig", {
        confirmationStatus: "confirmed",
        err: { InstructionError: [0, "Custom"] },
      }),
    ).toThrow("Transaction sig failed");
  });

  it("accepts confirmed and finalized transactions without on-chain errors", () => {
    expect(isSettledSignatureStatus("sig", {
      confirmationStatus: "confirmed",
    })).toBe(true);
    expect(isSettledSignatureStatus("sig", {
      confirmationStatus: "finalized",
    })).toBe(true);
    expect(isSettledSignatureStatus("sig", null)).toBe(false);
  });

  it("formats receipts with the settled signature as reference", () => {
    const receiptHeader = formatPaymentReceipt("settled-signature", {
      id: "credential-challenge-id",
      request: { externalId: "order-1" },
    });
    const receipt = JSON.parse(Buffer.from(receiptHeader, "base64url").toString("utf8")) as {
      challengeId?: string;
      externalId?: string;
      reference?: string;
    };

    expect(receipt.challengeId).toBe("credential-challenge-id");
    expect(receipt.externalId).toBe("order-1");
    expect(receipt.reference).toBe("settled-signature");
  });
});
