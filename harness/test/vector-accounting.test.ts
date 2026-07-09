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
// harness/vectors/ must map to a declared consumer below. Adding a new vector
// directory now fails here until its consuming driver is declared, so a future
// vector file cannot silently sit unexecuted.

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, "..", "vectors");

// Each vector file's consumer, keyed by its immediate location under
// harness/vectors/. "conformance-driver" and the protocol/flow drivers EXECUTE
// their vectors; the *-catalog entries are non-executable reason banks that a
// dedicated schema test validates (regression-bank.test.ts for the known-bad
// bank; this file for the voucher reject catalog). Keep this map in sync with
// the drivers when a vector directory is added.
type Consumer =
  | "conformance-driver" // test/conformance.test.ts (top-level *.json, executed)
  | "protocol-layer" // src/protocol/* (mpp-protocol/*, executed)
  | "flow-driver" // src/protocol/flow-driver.ts (mpp-protocol-flows/*, executed)
  | "regression-bank-catalog" // test/regression-bank.test.ts (schema-validated)
  | "voucher-reject-catalog" // this file (schema-validated)
  | "value-binding-catalog"; // spec mirror; cases executed inline by test/value-binding-verify.test.ts, shape-validated here

const DIRECTORY_CONSUMERS: Record<string, Consumer> = {
  "": "conformance-driver",
  "mpp-protocol": "protocol-layer",
  "mpp-protocol-flows": "flow-driver",
  "known-bad": "regression-bank-catalog",
  "session-voucher": "voucher-reject-catalog",
  "value-binding": "value-binding-catalog",
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

function immediateDir(fileFromVectors: string): string {
  const rel = relative(vectorsDir, fileFromVectors);
  const dir = dirname(rel);
  return dir === "." ? "" : dir;
}

describe("vector corpus accounting", () => {
  const files = listJsonFiles(vectorsDir);

  it("finds at least the known vector files", () => {
    // Sanity floor so a globbing regression (e.g. reverting to non-recursive)
    // does not make the accounting assertions vacuously pass.
    expect(files.length).toBeGreaterThanOrEqual(10);
  });

  it("accounts for every *.json under vectors/ (no orphaned corpus)", () => {
    const orphans: string[] = [];
    for (const file of files) {
      const dir = immediateDir(file);
      if (!(dir in DIRECTORY_CONSUMERS)) {
        orphans.push(relative(vectorsDir, file));
      }
    }
    expect(
      orphans,
      `Unaccounted vector file(s): ${orphans.join(", ")}. ` +
        "Every *.json under harness/vectors/ must be executed by a driver or " +
        "validated as a catalog. Declare its directory in DIRECTORY_CONSUMERS " +
        "(vector-accounting.test.ts) and wire the consuming driver, or the file " +
        "is a false green: it looks like coverage but guards nothing.",
    ).toEqual([]);
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
