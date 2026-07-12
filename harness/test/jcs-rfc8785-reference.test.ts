import { describe, expect, it } from "vitest";
import vectors from "../vectors/jcs-rfc8785-reference.json";
import { canonicalizeJson, encodeBase64Url } from "./support/canonical-json";

type JcsReferenceVector = {
  id: string;
  input: { value: unknown };
  expect: { canonicalJson: string; base64Url: string };
};

describe("RFC 8785 reference corpus vectors", () => {
  for (const vector of vectors as JcsReferenceVector[]) {
    it(`${vector.id}: matches the attributed canonical JSON output`, () => {
      const canonicalJson = canonicalizeJson(vector.input.value);

      expect(canonicalJson).toBe(vector.expect.canonicalJson);
      expect(encodeBase64Url(canonicalJson)).toBe(vector.expect.base64Url);
    });
  }
});
