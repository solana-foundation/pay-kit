import { describe, expect, it } from "vitest";

import { toBaseUnits } from "../src/fixtures/typescript/exact-shared";

/**
 * The x402 `exact` wire `amount` / `maxAmountRequired` field carries an
 * atomic base-unit integer, never the human-readable decimal price.
 * Conformant clients (the Rust spine plus the Swift and Kotlin SDKs)
 * parse it as a u64, so a server that advertised the decimal price
 * (e.g. "0.001") would have its offer rejected by every client except a
 * matching decimal-echoing fixture.
 *
 * `toBaseUnits` is the TS reference server's price -> base-unit scaling.
 * It mirrors the Rust spine's price normalization: strip a leading `$`,
 * take the first whitespace token, then scale by `decimals`. These
 * cases lock byte-identical output against the Rust harness server,
 * which advertises "1000" for price "0.001" at 6 decimals.
 */
describe("toBaseUnits (x402 exact amount scaling)", () => {
  it("scales the canonical harness price to base units", () => {
    expect(toBaseUnits("0.001", 6)).toBe("1000");
  });

  it("scales sub-cent fractions without precision loss", () => {
    expect(toBaseUnits("0.0005", 6)).toBe("500");
  });

  it("strips a leading currency symbol", () => {
    expect(toBaseUnits("$0.001", 6)).toBe("1000");
  });

  it("ignores a trailing currency suffix", () => {
    expect(toBaseUnits("0.001 USDC", 6)).toBe("1000");
  });

  it("scales whole-number prices", () => {
    expect(toBaseUnits("1", 6)).toBe("1000000");
    expect(toBaseUnits("1.5", 6)).toBe("1500000");
  });

  it("rejects more fractional digits than the decimals precision", () => {
    // Truncating would silently under-advertise the price; the Rust spine
    // rejects the same input, so the fixture must too.
    expect(() => toBaseUnits("0.0000001", 6)).toThrow(/decimal places/);
    expect(() => toBaseUnits("1.2345678", 6)).toThrow(/decimal places/);
  });

  it("accepts fractional digits exactly at the decimals precision", () => {
    expect(toBaseUnits("1.234567", 6)).toBe("1234567");
    expect(toBaseUnits("0.000001", 6)).toBe("1");
  });

  it("keeps zero as a single base unit of zero", () => {
    expect(toBaseUnits("0", 6)).toBe("0");
    expect(toBaseUnits("0.000000", 6)).toBe("0");
  });

  it("rejects non-numeric and malformed prices", () => {
    expect(() => toBaseUnits("USDC", 6)).toThrow(/invalid price/);
    expect(() => toBaseUnits("1.2.3", 6)).toThrow(/invalid price/);
    expect(() => toBaseUnits("", 6)).toThrow(/invalid price/);
  });
});
