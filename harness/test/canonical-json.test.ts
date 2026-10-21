import { describe, expect, it } from "vitest";

// RFC 8785 vectors the reference encoder below must reproduce (formerly
// exported from src/intents/charge.ts, retired with the vitest e2e driver).
const chargeCanonicalJsonVectors: readonly {
  id: string;
  value: Record<string, unknown>;
  canonicalJson: string;
  base64Url: string;
}[] = [
  {
    id: "nested-object-key-order",
    value: { b: 2, a: [{ b: true, a: false }] },
    canonicalJson: '{"a":[{"a":false,"b":true}],"b":2}',
    base64Url: "eyJhIjpbeyJhIjpmYWxzZSwiYiI6dHJ1ZX1dLCJiIjoyfQ",
  },
  {
    // RFC 8785 sec 3.2.3: UTF-16 code-unit ordering. 'f' (0x66) < 'é' (0xE9) < 'ƒ' (0x192).
    id: "utf16-key-ordering",
    value: { "é": 1, f: 2, "ƒ": 3 },
    canonicalJson: '{"f":2,"é":1,"ƒ":3}',
    base64Url: "eyJmIjoyLCLDqSI6MSwixpIiOjN9",
  },
  {
    // RFC 8785 sec 3.2.2.3: ES6 ToString. 1e21 must canonicalize as "1e+21".
    id: "number-1e21",
    value: { n: 1e21 },
    canonicalJson: '{"n":1e+21}',
    base64Url: "eyJuIjoxZSsyMX0",
  },
  {
    // 0.1 round-trips as "0.1" under ES6 ToString.
    id: "number-0_1",
    value: { n: 0.1 },
    canonicalJson: '{"n":0.1}',
    base64Url: "eyJuIjowLjF9",
  },
  {
    // Negative zero collapses to "0".
    id: "number-negative-zero",
    value: { n: -0 },
    canonicalJson: '{"n":0}',
    base64Url: "eyJuIjowfQ",
  },
  {
    // ES6 ToString shortest-roundtrip needs exactly 16 significant digits here;
    // encoders that stop at 15 digits and fall back to 17 emit
    // "333333333.33333331", which diverges from JS, Ruby and Rust.
    id: "number-16-digit-shortest",
    value: { n: 333333333.33333329 },
    canonicalJson: '{"n":333333333.3333333}',
    base64Url: "eyJuIjozMzMzMzMzMzMuMzMzMzMzM30",
  },
];

/**
 * Reference RFC 8785 (JCS) implementation for harness conformance vectors.
 *
 * Sorts object keys by UTF-16 code-unit order, serializes numbers per ES6 ToString,
 * rejects NaN, Infinity, and lone surrogates. Used to pin the expected canonical
 * bytes each language SDK must produce.
 */
function canonicalizeJson(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") return encodeNumber(value);
  if (typeof value === "string") return encodeString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalizeJson).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort(compareUtf16CodeUnits);
    return "{" + keys.map((k) => encodeString(k) + ":" + canonicalizeJson(obj[k])).join(",") + "}";
  }
  throw new Error(`unsupported JSON value: ${typeof value}`);
}

function compareUtf16CodeUnits(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const ax = a.charCodeAt(i);
    const bx = b.charCodeAt(i);
    if (ax !== bx) return ax - bx;
  }
  return a.length - b.length;
}

function encodeNumber(value: number): string {
  if (Number.isNaN(value)) throw new Error("cannot encode NaN");
  if (!Number.isFinite(value)) throw new Error("cannot encode Infinity");
  if (value === 0) return "0"; // ES6 ToString collapses -0 to "0"
  // JS String(value) already implements ECMA-262 7.1.12.1 ToString.
  return String(value);
}

function encodeString(value: string): string {
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      // High surrogate; require a following low surrogate.
      const low = value.charCodeAt(i + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) {
        throw new Error("lone surrogate in string");
      }
      out += value[i] + value[i + 1];
      i++;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error("lone surrogate in string");
    }
    const ch = value[i];
    if (ch === "\\") out += "\\\\";
    else if (ch === '"') out += '\\"';
    else if (code === 0x08) out += "\\b";
    else if (code === 0x09) out += "\\t";
    else if (code === 0x0a) out += "\\n";
    else if (code === 0x0c) out += "\\f";
    else if (code === 0x0d) out += "\\r";
    else if (code < 0x20) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

function encodeBase64Url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

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
