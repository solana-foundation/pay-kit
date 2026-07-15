import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Anti-false-green guard for the vector corpus itself.
//
// conformance.test.ts documents that it "loads every vector under
// harness/vectors/", but its `readdirSync(vectorsDir)` is NOT recursive: it
// only executes the top-level *.json files. Vectors that live in a
// subdirectory are therefore run only if some OTHER driver explicitly loads
// that subdirectory. Nothing enforced that, so a reject corpus
// (session-voucher/session-voucher-reject.json) shipped that no test ever
// executes or even reads — an authored "known-bad" artifact that guards
// nothing, which is exactly the false-green class this PR exists to kill.
//
// This test makes the vector tree self-accounting: every *.json under
// harness/vectors/ must map to a declared consumer below. The mapping is
// deliberately per FILE, not per directory: a new ignored-security-case.json
// beside a consumed protocol vector must fail closed instead of inheriting a
// directory's coverage claim.

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, "..", "vectors");

// "conformance-driver" and the protocol/flow drivers EXECUTE their vectors;
// the *-catalog entries are non-executable reason banks that a dedicated schema
// test validates. Every entry is explicit so a new file cannot silently inherit
// its sibling's consumer.
type Consumer =
  | "conformance-driver" // test/conformance.test.ts (top-level *.json, executed)
  | "protocol-layer" // src/protocol/* (mpp-protocol/*, executed)
  | "flow-driver" // src/protocol/flow-driver.ts (mpp-protocol-flows/*, executed)
  | "regression-bank-catalog" // test/regression-bank.test.ts (schema-validated)
  | "voucher-reject-catalog" // this file (schema-validated)
  | "value-binding-catalog"; // spec mirror; cases executed inline by test/value-binding-verify.test.ts, shape-validated here

const FILE_CONSUMERS: Record<string, Consumer> = {
  "canonical-bytes.json": "conformance-driver",
  "charge-defaults.json": "conformance-driver",
  "charge-envelope.json": "conformance-driver",
  "charge-precedence.json": "conformance-driver",
  "charge-rejects.json": "conformance-driver",
  "session-voucher.json": "conformance-driver",
  "wire-bytes.json": "conformance-driver",
  "x402-build.json": "conformance-driver",
  "x402-exact-reject.json": "conformance-driver",
  "x402-extensions.json": "conformance-driver",
  "x402-v1-build.json": "conformance-driver",
  "x402-v1-verify.json": "conformance-driver",
  "x402-verify.json": "conformance-driver",
  "known-bad/regression-bank.json": "regression-bank-catalog",
  "mpp-protocol-flows/flows.json": "flow-driver",
  "mpp-protocol-flows/golden-results.json": "flow-driver",
  "mpp-protocol/authorization.json": "protocol-layer",
  "mpp-protocol/base64url.json": "protocol-layer",
  "mpp-protocol/challenge-id.json": "protocol-layer",
  "mpp-protocol/receipt.json": "protocol-layer",
  "mpp-protocol/www-authenticate.json": "protocol-layer",
  "session-voucher/session-voucher-reject.json": "voucher-reject-catalog",
  "value-binding/open.json": "value-binding-catalog",
  "value-binding/topup.json": "value-binding-catalog",
};

function listJsonFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (entry.endsWith(".json")) {
        out.push(full);
      }
    }
  };
  walk(root);
  return out;
}

function relativeVectorPath(fileFromVectors: string): string {
  return relative(vectorsDir, fileFromVectors).replaceAll("\\", "/");
}

function corpusGaps(files: readonly string[]): { unaccounted: string[]; stale: string[] } {
  const actual = new Set(files.map(relativeVectorPath));
  return {
    unaccounted: [...actual].filter((file) => !(file in FILE_CONSUMERS)).sort(),
    stale: Object.keys(FILE_CONSUMERS).filter((file) => !actual.has(file)).sort(),
  };
}

describe("vector corpus accounting", () => {
  const files = listJsonFiles(vectorsDir);

  it("finds at least the known vector files", () => {
    // Sanity floor so a globbing regression (e.g. reverting to non-recursive)
    // does not make the accounting assertions vacuously pass.
    expect(files.length).toBeGreaterThanOrEqual(10);
  });

  it("accounts for every *.json under vectors/ by exact file path", () => {
    const { unaccounted, stale } = corpusGaps(files);
    expect(
      unaccounted,
      `Unaccounted vector file(s): ${unaccounted.join(", ")}. ` +
        "Every *.json under harness/vectors/ must be executed by a driver or " +
        "validated as a catalog. Declare its exact path in FILE_CONSUMERS " +
        "(vector-accounting.test.ts) and wire the consuming driver, or the file " +
        "is a false green: it looks like coverage but guards nothing.",
    ).toEqual([]);
    expect(
      stale,
      `Stale vector consumer entries: ${stale.join(", ")}. Remove the entry or restore the vector.`,
    ).toEqual([]);
  });

  it("rejects an unconsumed file even when it sits beside consumed protocol vectors", () => {
    const ignored = join(vectorsDir, "mpp-protocol", "ignored-security-case.json");
    expect(corpusGaps([...files, ignored]).unaccounted).toContain(
      "mpp-protocol/ignored-security-case.json",
    );
  });

  it("validates the session-voucher reject catalog shape", () => {
    // The catalog is a non-executable reason bank today (tag/reason/description),
    // so validate it as one and pin the security-critical voucher reject reasons
    // so the bank cannot silently drop them. Executing these against the runners
    // (as x402-exact-reject.json is executed) is the tracked follow-up.
    const catalogPath = join(vectorsDir, "session-voucher", "session-voucher-reject.json");
    const catalog = JSON.parse(readFileSync(catalogPath, "utf8")) as Array<{
      tag: string;
      reason: string;
      description: string;
    }>;

    expect(Array.isArray(catalog)).toBe(true);
    expect(catalog.length).toBeGreaterThan(0);

    const tags = new Set<string>();
    for (const entry of catalog) {
      expect(typeof entry.tag, "tag").toBe("string");
      expect(entry.tag.trim(), "tag non-empty").not.toBe("");
      expect(tags.has(entry.tag), `duplicate reject tag ${entry.tag}`).toBe(false);
      tags.add(entry.tag);
      expect(entry.reason, `${entry.tag}.reason`).toBe(entry.tag);
      expect(typeof entry.description, `${entry.tag}.description`).toBe("string");
      expect(entry.description.trim(), `${entry.tag}.description non-empty`).not.toBe("");
    }

    // The voucher trust model turns on these classes; a reject bank that drops
    // one of them is how a replay/expiry regression escapes review.
    const REQUIRED_REJECT_REASONS = [
      "cumulative-not-monotonic",
      "invalid-cumulative",
      "exceeds-deposit",
      "expired",
      "expires-within-settlement-window",
      "invalid-signature",
      "channel-sealed",
      "channel-close-pending",
    ];
    for (const reason of REQUIRED_REJECT_REASONS) {
      expect(tags.has(reason), `missing voucher reject reason ${reason}`).toBe(true);
    }
  });
});
