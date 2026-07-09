import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Radar guard: a verify-capable protocol must ship BOTH accept and reject
// executed vectors. One-sided coverage — accept-only, or reject-only — is how a
// verifier regression escapes: an accept-only corpus never proves a bad payment
// is refused, and a reject-only corpus never proves a good one still settles.
// This fails if any intent that has verify vectors is missing either outcome,
// so the reject bank for a protocol cannot be quietly deleted or never added.
//
// Session-voucher semantic verification is exercised directly against the pure
// verifier in session-voucher-verify.test.ts (its corpus vectors are byte-level
// canonical-bytes only); that intent is asserted present here as a backstop so
// the direct suite cannot silently disappear.

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, "..", "vectors");

const VERIFY_MODES = new Set(["verify-transaction", "verify-x402-transaction"]);

type Vector = {
  intent?: string;
  mode?: string;
  expect?: { outcome?: string };
};

function loadTopLevelVectors(): Vector[] {
  const out: Vector[] = [];
  for (const name of readdirSync(vectorsDir)) {
    if (!name.endsWith(".json")) continue;
    const parsed = JSON.parse(readFileSync(join(vectorsDir, name), "utf8"));
    if (Array.isArray(parsed)) out.push(...parsed);
  }
  return out;
}

describe("coverage shape — no one-sided verify corpus", () => {
  const vectors = loadTopLevelVectors();

  it("every verify-capable intent has BOTH accept and reject vectors", () => {
    const byIntent = new Map<string, Set<string>>();
    for (const v of vectors) {
      if (!v.mode || !VERIFY_MODES.has(v.mode)) continue;
      const intent = v.intent ?? "(none)";
      const outcome = v.expect?.outcome ?? "(none)";
      if (!byIntent.has(intent)) byIntent.set(intent, new Set());
      byIntent.get(intent)?.add(outcome);
    }

    // Floor: the two protocols with a real verifier must be present, so a
    // globbing regression cannot make this assertion vacuous.
    expect([...byIntent.keys()].sort()).toEqual(
      expect.arrayContaining(["charge", "x402-exact"]),
    );

    const oneSided: string[] = [];
    for (const [intent, outcomes] of byIntent) {
      if (!(outcomes.has("accept") && outcomes.has("reject"))) {
        oneSided.push(`${intent} (has: ${[...outcomes].sort().join(", ")})`);
      }
    }
    expect(
      oneSided,
      `Verify-capable intent(s) with one-sided coverage: ${oneSided.join("; ")}. ` +
        "Add the missing accept or reject vectors so the verifier is proven in both directions.",
    ).toEqual([]);
  });

  it("session-voucher semantic verification is covered by the direct verifier suite", () => {
    // The corpus carries only byte-level session vectors; the adversarial
    // reject coverage lives in the direct suite. Assert it exists and drives
    // the real verifier so the semantic coverage cannot vanish unnoticed.
    const suite = readFileSync(join(here, "session-voucher-verify.test.ts"), "utf8");
    expect(suite).toContain("verifyVoucherForChannel");
    expect(suite).toContain("expires-within-settlement-window");
  });
});
