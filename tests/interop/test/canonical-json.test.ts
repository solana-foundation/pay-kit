import { describe, expect, it } from "vitest";
import { chargeCanonicalJsonVectors } from "../src/contracts";

function canonicalizeJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalizeJson);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalizeJson(nested)]),
    );
  }
  return value;
}

function encodeBase64Url(value: string): string {
  return Buffer.from(value).toString("base64url");
}

describe("RFC 8785 canonical JSON vectors", () => {
  for (const vector of chargeCanonicalJsonVectors) {
    it(`${vector.id}: canonical JSON before base64url`, () => {
      const canonicalJson = JSON.stringify(canonicalizeJson(vector.value));

      expect(canonicalJson).toBe(vector.canonicalJson);
      expect(encodeBase64Url(canonicalJson)).toBe(vector.base64Url);
    });
  }
});
