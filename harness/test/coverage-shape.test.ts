import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Radar guard: every verify mode of a protocol must ship BOTH accept and reject
// executed vectors. One-sided coverage — accept-only, or reject-only — is how a
// verifier regression escapes: an accept-only corpus never proves a bad payment
// is refused, and a reject-only corpus never proves a good one still settles.
// This fails if any intent:mode pair is missing either outcome, so coverage in
// one verifier cannot hide a one-sided corpus in another verifier.
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

describe("coverage shape — no one-sided intent:verify-mode corpus", () => {
  const vectors = loadTopLevelVectors();

  it("every intent:verify-mode has BOTH accept and reject vectors", () => {
    const byIntentAndMode = new Map<string, Set<string>>();
    for (const v of vectors) {
      if (!v.mode || !VERIFY_MODES.has(v.mode)) continue;
      const intent = v.intent ?? "(none)";
      const outcome = v.expect?.outcome ?? "(none)";
      const group = `${intent}:${v.mode}`;
      if (!byIntentAndMode.has(group)) byIntentAndMode.set(group, new Set());
      byIntentAndMode.get(group)?.add(outcome);
    }

    // Floor: every real verifier mode must be present, so deleting one entire
    // mode cannot make the per-group assertion vacuous.
    expect([...byIntentAndMode.keys()].sort()).toEqual(
      expect.arrayContaining([
        "charge:verify-transaction",
        "x402-exact:verify-transaction",
        "x402-exact:verify-x402-transaction",
      ]),
    );

    const oneSided: string[] = [];
    for (const [group, outcomes] of byIntentAndMode) {
      if (!(outcomes.has("accept") && outcomes.has("reject"))) {
        oneSided.push(`${group} (has: ${[...outcomes].sort().join(", ")})`);
      }
    }
    expect(
      oneSided,
      `Intent:verify-mode group(s) with one-sided coverage: ${oneSided.join("; ")}. ` +
        "Add the missing accept or reject vectors so the verifier is proven in both directions.",
    ).toEqual([]);
  });

  it("session-voucher semantic verification is covered by the direct verifier suite", () => {
    // The corpus carries only byte-level session vectors; the adversarial
    // reject coverage lives in the direct suite. Assert it exists and drives
    // the real verifier so the semantic coverage cannot vanish unnoticed.
    const suite = readFileSync(
      join(here, "session-voucher-verify.test.ts"),
      "utf8",
    );
    expect(suite).toContain("verifyVoucherForChannel");
    expect(suite).toContain("expires-within-settlement-window");
  });
});
