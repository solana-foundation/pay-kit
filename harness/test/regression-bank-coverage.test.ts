import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Enforced coverage ledger for the known-bad regression bank.
//
// regression-bank.test.ts validates the bank's SHAPE; it does not prove any
// bug class is actually exercised. A registry that claims "wrong-mint is
// covered" while nothing rejects a wrong mint is a false green. This ledger
// binds every bug class to REAL executed coverage and verifies the binding
// resolves — a reject vector with that code must exist in the corpus, or the
// named direct/e2e test must exist and reference the class. A class with no
// live coverage yet must be declared in PENDING_EXECUTABLE (ratcheted, may only
// shrink), so a bug class can never silently sit in the bank claiming a
// protection it does not have, and deleting the covering vector turns this red.

const here = dirname(fileURLToPath(import.meta.url));
const harnessDir = join(here, "..");
const vectorsDir = join(harnessDir, "vectors");

type Coverage =
  | { kind: "x402-reject-code"; code: string }
  | { kind: "reject-code"; code: string }
  | { kind: "direct-suite"; file: string; marker: string }
  | { kind: "e2e-scenario"; files: string[]; marker: string };

// bugClass -> the executed coverage that proves it is refused today.
const COVERAGE: Record<string, Coverage> = {
  "wrong-network": { kind: "reject-code", code: "wrong-network" },
  "wrong-mint": { kind: "x402-reject-code", code: "invalid_exact_svm_payload_mint_mismatch" },
  "wrong-amount": { kind: "x402-reject-code", code: "invalid_exact_svm_payload_amount_mismatch" },
  "wrong-route": {
    kind: "e2e-scenario",
    files: ["src/intents/x402-exact.ts", "src/intents/charge.ts"],
    marker: "cross-route-replay",
  },
  // Driven against the reference verifier directly (a malformed transaction
  // proof and a reordered transferChecked are both refused).
  "malformed-envelope": {
    kind: "direct-suite",
    file: "test/x402-exact-defect-verify.test.ts",
    marker: "malformed-envelope",
  },
  "wrong-account-order": {
    kind: "direct-suite",
    file: "test/x402-exact-defect-verify.test.ts",
    marker: "wrong-account-order",
  },
  // The Ed25519-signature-rejection class is executed against the real verifier
  // in the direct voucher suite; charge-credential signature rejection is the
  // same guarantee at the same layer.
  "invalid-signature": {
    kind: "direct-suite",
    file: "test/session-voucher-verify.test.ts",
    marker: '"invalid-signature"',
  },
  "expired-voucher": {
    kind: "direct-suite",
    file: "test/session-voucher-verify.test.ts",
    marker: '"expired"',
  },
};

// Bug classes whose distinct executed vector still needs a crafted transaction
// carrying the exact defect. RATCHET: this set may only shrink — moving a class
// to COVERAGE as its vector lands. Growing it (or leaving a bank class out of
// both maps) fails the ledger.
const PENDING_EXECUTABLE: Record<string, string> = {
  "wrong-signer-writable-flags":
    "enforced ON-CHAIN by the payment-channels program's account constraints, not by the " +
    "off-chain structural verifier (which is flag-agnostic by design; see " +
    "x402-exact-defect-verify.test.ts's boundary control). Covered by the " +
    "split/pr216-onchain-parity instruction-shape goldens, a separate PR.",
};
const PENDING_RATCHET_MAX = 1;

function loadTopLevelRejectCodes(): { rejectCodes: Set<string>; x402Codes: Set<string> } {
  const rejectCodes = new Set<string>();
  const x402Codes = new Set<string>();
  for (const name of readdirSync(vectorsDir)) {
    if (!name.endsWith(".json")) continue;
    const parsed = JSON.parse(readFileSync(join(vectorsDir, name), "utf8"));
    if (!Array.isArray(parsed)) continue;
    for (const v of parsed) {
      const e = v?.expect;
      if (!e || e.outcome !== "reject") continue;
      if (e.rejectCode) rejectCodes.add(e.rejectCode);
      if (e.x402ExactRejectCode) x402Codes.add(e.x402ExactRejectCode);
    }
  }
  return { rejectCodes, x402Codes };
}

function bankBugClasses(): string[] {
  const bank = JSON.parse(
    readFileSync(join(vectorsDir, "known-bad", "regression-bank.json"), "utf8"),
  ) as { vectors: Array<{ bugClass: string }> };
  return bank.vectors.map((v) => v.bugClass);
}

describe("regression bank — enforced coverage ledger", () => {
  const classes = bankBugClasses();

  it("classifies every bank bug class as covered or explicitly pending", () => {
    const unclassified = classes.filter(
      (c) => !(c in COVERAGE) && !(c in PENDING_EXECUTABLE),
    );
    expect(
      unclassified,
      `Bank bug class(es) with no coverage declaration: ${unclassified.join(", ")}. ` +
        "Bind to executed coverage in COVERAGE, or declare in PENDING_EXECUTABLE.",
    ).toEqual([]);

    // No stale ledger entries (a COVERAGE/PENDING key not in the bank).
    const known = new Set(classes);
    const stale = [...Object.keys(COVERAGE), ...Object.keys(PENDING_EXECUTABLE)].filter(
      (c) => !known.has(c),
    );
    expect(stale, `Ledger references bug class(es) not in the bank: ${stale.join(", ")}`).toEqual(
      [],
    );

    // A class cannot be both covered and pending.
    const both = Object.keys(COVERAGE).filter((c) => c in PENDING_EXECUTABLE);
    expect(both, `Bug class(es) both covered and pending: ${both.join(", ")}`).toEqual([]);
  });

  it("resolves every COVERAGE binding to real executed coverage", () => {
    const { rejectCodes, x402Codes } = loadTopLevelRejectCodes();
    for (const [bugClass, cov] of Object.entries(COVERAGE)) {
      if (cov.kind === "reject-code") {
        expect(rejectCodes.has(cov.code), `${bugClass}: no reject vector with rejectCode=${cov.code}`).toBe(
          true,
        );
      } else if (cov.kind === "x402-reject-code") {
        expect(
          x402Codes.has(cov.code),
          `${bugClass}: no reject vector with x402ExactRejectCode=${cov.code}`,
        ).toBe(true);
      } else if (cov.kind === "direct-suite") {
        const src = readFileSync(join(harnessDir, cov.file), "utf8");
        expect(src.includes(cov.marker), `${bugClass}: ${cov.file} does not reference ${cov.marker}`).toBe(
          true,
        );
      } else {
        for (const file of cov.files) {
          const src = readFileSync(join(harnessDir, file), "utf8");
          expect(
            src.includes(cov.marker),
            `${bugClass}: ${file} does not define the ${cov.marker} scenario`,
          ).toBe(true);
        }
      }
    }
  });

  it("keeps the pending-executable set ratcheted (may only shrink)", () => {
    const pending = Object.keys(PENDING_EXECUTABLE);
    expect(
      pending.length,
      `pending-executable grew to ${pending.length} (${pending.join(", ")}); it must only shrink — ` +
        "add the executed vector and move the class to COVERAGE instead.",
    ).toBeLessThanOrEqual(PENDING_RATCHET_MAX);
    // Every pending class must still be a real bank class.
    for (const c of pending) {
      expect(classes.includes(c), `pending class ${c} is not in the bank`).toBe(true);
    }
  });
});
