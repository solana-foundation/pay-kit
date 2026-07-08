// x402-upto SETTLEMENT-CEILING radar (matrix cell
// x402-upto-over-ceiling-reject :: invalid_upto_svm_payload_settlement_exceeds_amount).
//
// `AssertSettlementWithinCeiling` (Go upto.go:40,182; mirrored in Rust
// assert_settlement_within_ceiling, Python, and the TS adapter) is the ONLY
// canonical `upto` reject every SDK emits VERBATIM: a metered actual amount that
// exceeds the authorized ceiling (MaxAmount) must be REFUSED with the exact code
// string, never silently clamped down to the max. Nothing in the harness drove
// it — the whole upto matrix leg is RPC/on-chain-gated, so this fund-safety
// threshold shipped untested in CI (it was KNOWN_GAP in matrix-coverage-gate).
//
// This suite closes that cell WITHOUT a slow on-chain E2E. It drives the REAL
// production verifier in-process: pay-kit's `X402Upto.settle`, whose ceiling
// guard runs BEFORE any RPC/network work (adapters/x402-upto.ts:180 —
// `if (actualBaseUnits > verified.maxBaseUnits) throw ...ERR_SETTLEMENT_EXCEEDS_AMOUNT`).
// So the over-ceiling reject is fully deterministic and RPC-free. X402Upto is not
// on pay-kit's public export surface (only the framework wrappers drive it), so
// it is imported from source — the same module the SDK's own unit test exercises
// — resolving @x402/svm through the pay-kit package's node_modules.
//
// The at/under-ceiling controls are the differential: they must NOT reject with
// the ceiling code (they pass the guard and fail LATER for an unrelated reason on
// the stub payload), proving the guard is a real threshold — not a blanket
// reject — and that an at/under-ceiling amount is not clamped-rejected.

import { describe, expect, it } from "vitest";
import { X402Upto } from "../../typescript/packages/pay-kit/src/adapters/x402-upto.js";
import { configure } from "../../typescript/packages/pay-kit/src/config.js";

// The shared canonical reject string, byte-identical across Go
// (UptoErrorSettlementExceedsAmount), Rust (ERR_SETTLEMENT_EXCEEDS_AMOUNT),
// Python (UPTO_ERROR_SETTLEMENT_EXCEEDS_AMOUNT), and the TS adapter. Pinned as a
// literal so a rename in any SDK that diverges the wire code turns this red.
const SETTLEMENT_EXCEEDS_AMOUNT =
  "invalid_upto_svm_payload_settlement_exceeds_amount";

const CEILING = 1_000_000n;

async function makeUpto(): Promise<X402Upto> {
  // A minimal, offline config (no live RPC needed: the ceiling guard precedes
  // all network work). Mirrors the SDK unit test's testConfig().
  const config = await configure({
    mpp: { challengeBindingSecret: "x402-upto-ceiling-secret" },
    network: "solana_localnet",
  });
  return new X402Upto(config);
}

// A verified authorization whose authorized ceiling is CEILING. The payload is a
// stub because the over-ceiling guard rejects before parseUptoPayload/RPC ever
// run; the at/under-ceiling controls intentionally proceed past the guard and
// fail on this stub with a DIFFERENT code, which is the point of the control.
function verifiedAtCeiling(): never {
  return {
    maxBaseUnits: CEILING,
    payer: "payer",
    payload: {},
    requirements: {},
  } as never;
}

// Resolve the reject code the verifier surfaces (InvalidProofError.code), or a
// sentinel if it did not throw.
async function settleCode(actual: bigint): Promise<string> {
  const upto = await makeUpto();
  try {
    await upto.settle(verifiedAtCeiling(), actual);
    return "<accepted-no-throw>";
  } catch (error) {
    const e = error as { code?: string; message?: string };
    return e.code ?? e.message ?? String(error);
  }
}

describe("x402-upto over-ceiling settlement is refused (real X402Upto.settle verifier)", () => {
  // THE CELL: actual (CEILING + 1) > authorized ceiling -> refused verbatim with
  // the shared canonical code, never clamped down to the ceiling.
  it("rejects a metered actual above the authorized ceiling with the exact canonical code", async () => {
    expect(await settleCode(CEILING + 1n)).toBe(SETTLEMENT_EXCEEDS_AMOUNT);
    // A wildly-over amount is refused with the same code (not a different bucket).
    expect(await settleCode(CEILING * 2n)).toBe(SETTLEMENT_EXCEEDS_AMOUNT);
  }, 30_000);

  // NO SILENT CLAMP / real-threshold differential: at-ceiling and under-ceiling
  // do NOT trip the ceiling guard. They pass it and fail LATER on the stub
  // payload for an unrelated reason, so the surfaced code is NOT the ceiling
  // code. This proves the guard is a genuine `actual > max` threshold rather
  // than a verifier that rejects everything with this string, and that an
  // in-bounds amount is not clamp-rejected as over-ceiling.
  it("does not raise the over-ceiling code at or under the ceiling (real threshold, no clamp)", async () => {
    expect(await settleCode(CEILING)).not.toBe(SETTLEMENT_EXCEEDS_AMOUNT);
    expect(await settleCode(CEILING - 1n)).not.toBe(SETTLEMENT_EXCEEDS_AMOUNT);
    expect(await settleCode(0n)).not.toBe(SETTLEMENT_EXCEEDS_AMOUNT);
  }, 30_000);
});
