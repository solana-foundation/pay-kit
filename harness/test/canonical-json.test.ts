import { describe, expect, it } from "vitest";
import { chargeCanonicalJsonVectors } from "../src/contracts";
import { canonicalizeJson, encodeBase64Url } from "./support/canonical-json";

describe("RFC 8785 canonical JSON vectors", () => {
  for (const vector of chargeCanonicalJsonVectors) {
    it(`${vector.id}: canonical JSON before base64url`, () => {
      const canonicalJson = canonicalizeJson(vector.value);

      expect(canonicalJson).toBe(vector.canonicalJson);
      expect(encodeBase64Url(canonicalJson)).toBe(vector.base64Url);
    });
  }

  it("rejects lone surrogates per RFC 8785 sec 3.2.2", () => {
    const lone = String.fromCharCode(0xd834);
    expect(() => canonicalizeJson({ k: lone })).toThrow(/lone surrogate/);
  });

  it("rejects NaN and Infinity per RFC 8785 sec 3.2.2.3", () => {
    expect(() => canonicalizeJson(Number.NaN)).toThrow();
    expect(() => canonicalizeJson(Number.POSITIVE_INFINITY)).toThrow();
  });
});
