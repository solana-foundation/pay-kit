// Unit coverage for the legacy x402 EXACT v1 wire shape in the conformance
// reference (src/conformance/x402.ts). These assert the v1 build/verify/
// parse contract that the cross-SDK vectors (harness/vectors/x402-v1-*.json)
// drive across every SDK runner, plus the body-challenge parse path that
// the vector driver has no dedicated mode for.
//
// The contract is mirrored from the rust spine; see
// docs/x402/exact-v1-spec.md for the per-rule file:line citations.

import { describe, expect, it } from "vitest";
import {
  buildPaymentHeaderV1,
  buildPaymentHeaderV2,
  decodeEnvelopeShape,
  parseV1ChallengeBody,
  parseX402Challenge,
  v1NetworkForOffer,
  verifyPaymentHeader,
  SOLANA_DEVNET,
  SOLANA_MAINNET,
} from "../src/conformance/x402";
import type { X402Offer } from "../src/conformance/schema";

const devnetOffer: X402Offer = {
  scheme: "exact",
  network: SOLANA_DEVNET,
  amount: "1000",
  asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
  payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
  maxTimeoutSeconds: 60,
  extra: { feePayer: "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ" },
};

const mainnetOffer: X402Offer = {
  scheme: "exact",
  network: SOLANA_MAINNET,
  amount: "10000",
  asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
  maxTimeoutSeconds: 300,
};

describe("x402 v1 network-name mapping", () => {
  it("maps devnet-family offers to the plain slug solana-devnet", () => {
    expect(v1NetworkForOffer(devnetOffer)).toBe("solana-devnet");
  });

  it("maps everything else to the plain slug solana", () => {
    expect(v1NetworkForOffer(mainnetOffer)).toBe("solana");
  });
});

describe("x402 v1 client build (X-PAYMENT)", () => {
  it("emits top-level scheme + plain network, no accepted", () => {
    const header = buildPaymentHeaderV1(devnetOffer, "AA==");
    const shape = decodeEnvelopeShape(header);
    expect(shape.x402Version).toBe(1);
    expect(shape.scheme).toBe("exact");
    expect(shape.network).toBe("solana-devnet");
    expect(shape.hasAccepted).toBe(false);
    expect(shape.payloadHasTransaction).toBe(true);
    // v1 must NOT carry CAIP-2 in the top-level network field.
    expect(shape.network).not.toContain("solana:");
  });

  it("is standard (padded) base64, not base64url", () => {
    const header = buildPaymentHeaderV1(devnetOffer, "AA==");
    // standard base64 uses + and / and = padding; base64url uses - and _.
    expect(header).not.toMatch(/[-_]/);
    const roundTrip = Buffer.from(header, "base64").toString("utf8");
    expect(JSON.parse(roundTrip).x402Version).toBe(1);
  });
});

describe("x402 v1 server verify (dual-accept)", () => {
  const devnetRoute = {
    network: "devnet",
    recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
    currency: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    amount: "1000",
  };

  it("accepts a v1 X-PAYMENT against a matching-network route", () => {
    const header = buildPaymentHeaderV1(devnetOffer, "AA==");
    expect(verifyPaymentHeader(header, devnetRoute)).toEqual({ ok: true });
  });

  it("rejects a v1 credential signed for the wrong network", () => {
    const header = buildPaymentHeaderV1(mainnetOffer, "AA==");
    expect(() => verifyPaymentHeader(header, devnetRoute)).toThrow(
      /Network mismatch/i,
    );
  });

  it("rejects a genuinely-unknown version on the v1-shaped path", () => {
    const env = {
      x402Version: 9,
      scheme: "exact",
      network: "solana-devnet",
      payload: { transaction: "AA==" },
    };
    const header = Buffer.from(JSON.stringify(env)).toString("base64");
    expect(() => verifyPaymentHeader(header, devnetRoute)).toThrow(
      /Unsupported x402 version/i,
    );
  });

  it("still accepts a v2 PAYMENT-SIGNATURE on the same server (emit-v2-default peer)", () => {
    const header = buildPaymentHeaderV2(devnetOffer, "AA==");
    expect(verifyPaymentHeader(header, devnetRoute)).toEqual({ ok: true });
  });
});

describe("x402 v1 client parses a 402 JSON-body challenge", () => {
  // The legacy v1 challenge arrives as the HTTP 402 body with accepts[]
  // and maxAmountRequired. Mirrors rust parse_accepts_body.
  const v1Body = JSON.stringify({
    x402Version: 1,
    error: "PAYMENT-SIGNATURE header is required",
    accepts: [
      {
        scheme: "exact",
        network: "solana-devnet",
        maxAmountRequired: "1000",
        asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
        resource: "http://localhost:3402/x402/joke",
        maxTimeoutSeconds: 60,
        extra: { feePayer: "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ" },
      },
    ],
  });

  it("reads maxAmountRequired/payTo/asset from accepts[]", () => {
    const offer = parseV1ChallengeBody(v1Body);
    expect(offer).toEqual({
      network: "solana-devnet",
      amount: "1000",
      asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
      payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
    });
  });

  it("round-trips through the v1 builder: parsed body -> X-PAYMENT", () => {
    const offer = parseV1ChallengeBody(v1Body);
    expect(offer).toBeDefined();
    if (!offer) return;
    // Rebuild a v1 header from the parsed offer (network slug is already a
    // plain v1 name here, which v1NetworkForOffer maps to itself).
    const header = buildPaymentHeaderV1(
      { ...offer, scheme: "exact" } as X402Offer,
      "AA==",
    );
    const shape = decodeEnvelopeShape(header);
    expect(shape.x402Version).toBe(1);
    expect(shape.network).toBe("solana-devnet");
  });

  it("falls back to the v1 body only after the v2 header path", () => {
    // No v2 header present -> body is consulted.
    const fromBody = parseX402Challenge([], v1Body);
    expect(fromBody?.amount).toBe("1000");

    // A valid v2 PAYMENT-REQUIRED header wins over a v1 body.
    const v2Body = JSON.stringify({
      x402Version: 2,
      accepts: [
        {
          scheme: "exact",
          network: SOLANA_DEVNET,
          amount: "777",
          asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
          payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
        },
      ],
    });
    const v2Header = Buffer.from(v2Body).toString("base64");
    const fromHeader = parseX402Challenge(
      [["PAYMENT-REQUIRED", v2Header]],
      v1Body,
    );
    expect(fromHeader?.amount).toBe("777");
  });

  it("returns undefined for a body with no Solana offer", () => {
    expect(parseV1ChallengeBody('{"accepts":[]}')).toBeUndefined();
    expect(parseV1ChallengeBody("not json")).toBeUndefined();
  });
});
