import { describe, expect, it } from "vitest";
import vectors from "../vectors/jcs-rfc8785-reference.json";
import { canonicalizeJson, encodeBase64Url } from "./support/canonical-json";

type JcsReferenceVector = {
  id: string;
  source: {
    input: string;
    canonicalJson: string;
    base64Url: string;
  };
  input: { value: unknown };
  expect: { canonicalJson: string; base64Url: string };
};

function assertJcsReferenceVectors(
  value: unknown,
): asserts value is JcsReferenceVector[] {
  expect(Array.isArray(value)).toBe(true);

  for (const vector of value as Array<Partial<JcsReferenceVector>>) {
    expect(typeof vector.id).toBe("string");
    expect(typeof vector.source?.input).toBe("string");
    expect(typeof vector.source?.canonicalJson).toBe("string");
    expect(typeof vector.source?.base64Url).toBe("string");
    expect(vector.input).toHaveProperty("value");
    expect(typeof vector.expect?.canonicalJson).toBe("string");
    expect(typeof vector.expect?.base64Url).toBe("string");
  }
}

describe("RFC 8785 reference corpus vectors", () => {
  it("has the expected fixture schema", () => {
    assertJcsReferenceVectors(vectors);
  });

  for (const vector of vectors) {
    it(`${vector.id}: matches the attributed canonical JSON output`, () => {
      const canonicalJson = canonicalizeJson(vector.input.value);

      expect(canonicalJson).toBe(vector.expect.canonicalJson);
      expect(encodeBase64Url(canonicalJson)).toBe(vector.expect.base64Url);
    });
  }
});
