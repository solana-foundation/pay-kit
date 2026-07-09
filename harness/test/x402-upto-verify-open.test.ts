// x402-upto VERIFY-OPEN structural radar (matrix path x402-upto-verify-open-server).
//
// The audit's matrix flagged nearly the whole `upto` verify-open surface as
// unvectored: the cross-SDK conformance driver (conformance.test.ts) only knows
// the "charge" / "x402-exact" / "session" intents, so no JSON vector reaches an
// `upto` verifier at all. This suite closes two of those cells —
// `invalid_upto_svm_payload_authorized_signer` and
// `invalid_upto_svm_payload_deposit_not_ceiling` — by driving the REAL `@x402/svm`
// upto facilitator verifier (the exact code the pay-kit adapter calls at
// adapters/x402-upto.ts:161 `this.#facilitator.verify(...)`) and asserting it
// refuses a payload whose `authorizedSigner` is NOT the operator, and one whose
// escrowed `deposit` is NOT the signed ceiling (`maxAmount`).
//
// Why this is the faithful verifier: `X402Upto.verifyOpen` decodes the payment
// header and immediately delegates to `UptoSvmScheme.verify(payload, requirements)`
// (@x402/svm/upto/facilitator). The authorized-signer guard lives there
// (facilitator/index.js: `if (p.authorizedSigner !== operatorAddr) return {
// invalidReason: "invalid_upto_svm_payload_authorized_signer" }`) and mirrors the
// Go spine `VerifyUptoPayload` (go/protocols/x402/upto.go:173) and Python
// `verify_upto_payload`. The voucher that authorizes settlement is signed by the
// OPERATOR, not the client — so a payload naming any other authorized signer must
// be rejected, else a client could pin a signer it controls.
//
// RPC-free (hence a T1 structural unit, not a slow on-chain e2e): the signer
// guard returns BEFORE the verifier ever constructs an RPC client or broadcasts
// the open (that happens only after every payload/open-transaction check passes).
// So this runs deterministically in the default `pnpm test` with no surfpool /
// validator.
//
// Resolution note: `@x402/svm` is a transitive dependency of `@solana/pay-kit`
// (a direct harness dependency), not a direct harness dependency, so we resolve
// it through the pay-kit source package the same way the harness already relies
// on the sibling `typescript/` workspace being installed + built for the
// `@solana/mpp` value-binding radar.

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createKeyPairSignerFromPrivateKeyBytes,
  type KeyPairSigner,
} from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

// ── resolve the real @x402/svm upto facilitator (transitive via pay-kit) ──
const here = dirname(fileURLToPath(import.meta.url)); // harness/test
const payKitPackageJson = join(
  here,
  "..",
  "..",
  "typescript",
  "packages",
  "pay-kit",
  "package.json",
);
const requireFromPayKit = createRequire(payKitPackageJson);
// The class is exported as `UptoSvmScheme`; the pay-kit adapter imports it
// aliased as `UptoSvmFacilitator` and drives its `.verify(...)`.
const { UptoSvmScheme } = requireFromPayKit(
  "@x402/svm/upto/facilitator",
) as {
  UptoSvmScheme: new (
    operator: unknown,
    config?: { rpcUrl?: string },
  ) => {
    verify(
      payload: unknown,
      requirements: unknown,
    ): Promise<{
      isValid: boolean;
      invalidReason?: string;
      invalidMessage?: string;
      payer?: string;
    }>;
  };
};

// ── fixtures ──────────────────────────────────────────────────────────────
const UPTO_ASSET_TRANSFER_METHOD = "payment-channel";
const NETWORK = "solana-devnet";
const USDC_DEVNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const PAYMENT_CHANNELS_PROGRAM = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX";
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
// A real base58 32-byte channel id (never decoded here — the signer guard
// short-circuits before the open transaction is parsed).
const CHANNEL_ID = "HpQ2u1nBoQ2zt6f2n9tqf7cXrJ8pM9cVYh6ZkQmA1B2C";
const CEILING = "1000000";

function seed(byte: number): Uint8Array {
  const s = new Uint8Array(32);
  s.fill(byte);
  return s;
}

let operator: KeyPairSigner; // the facilitator/operator: the ONLY valid authorized signer
let client: KeyPairSigner; // the channel payer (payload.from)
let attacker: KeyPairSigner; // a signer the client does NOT own the operator role for

beforeAll(async () => {
  [operator, client, attacker] = await Promise.all([
    createKeyPairSignerFromPrivateKeyBytes(seed(0x31)),
    createKeyPairSignerFromPrivateKeyBytes(seed(0x32)),
    createKeyPairSignerFromPrivateKeyBytes(seed(0x33)),
  ]);
});

/** Route-pinned upto requirement (facilitator == operator, deposit ceiling ==
 *  amount), mirroring the harness upto-challenge fixture. */
function requirements() {
  return {
    scheme: "upto",
    network: NETWORK,
    amount: CEILING,
    asset: USDC_DEVNET,
    payTo: operator.address,
    maxTimeoutSeconds: 300,
    extra: {
      assetTransferMethod: UPTO_ASSET_TRANSFER_METHOD,
      channelProgram: PAYMENT_CHANNELS_PROGRAM,
      facilitatorAddress: operator.address,
      facilitatorFee: 0,
      feePayer: operator.address,
      tokenProgram: TOKEN_PROGRAM,
    },
  };
}

/** A well-formed upto PAYMENT-SIGNATURE envelope whose only variable is the
 *  claimed `authorizedSigner`. Every OTHER field is valid so the verifier
 *  reaches the signer guard rather than tripping an earlier check. */
function payload(authorizedSigner: string) {
  const now = Math.floor(Date.now() / 1000);
  return {
    accepted: { scheme: "upto", network: NETWORK },
    payload: {
      from: client.address,
      maxAmount: CEILING,
      deposit: CEILING,
      channelId: CHANNEL_ID,
      authorizedSigner,
      // Never decoded: the signer guard returns first. A dummy keeps the
      // payload shape valid (`isUptoSvmPayload` only requires a string).
      openTransaction: "AA==",
      expiresAt: now + 3600,
      validAfter: now - 60,
      nonce: "01",
    },
  };
}

describe("x402-upto verify-open: authorized-signer binding (real @x402/svm facilitator)", () => {
  const AUTHORIZED_SIGNER_REJECT = "invalid_upto_svm_payload_authorized_signer";

  it("rejects a payload whose authorizedSigner is not the operator", async () => {
    const scheme = new UptoSvmScheme(operator, {});

    const result = await scheme.verify(payload(attacker.address), requirements());

    expect(result.isValid).toBe(false);
    expect(result.invalidReason).toBe(AUTHORIZED_SIGNER_REJECT);
    // The verifier still attributes the payer (payload.from), not the bogus signer.
    expect(result.payer).toBe(client.address);
  });

  // Positive control: with the CORRECT authorized signer (== operator) the
  // verifier must move PAST the signer guard. It then fails downstream on the
  // dummy open transaction (invalid_upto_svm_payload_open_transaction), proving
  // the rejection above is caused specifically by the wrong signer and is not an
  // incidental failure that would fire for any input.
  it("accepts the operator as authorized signer (reject above is signer-specific)", async () => {
    const scheme = new UptoSvmScheme(operator, {});

    const result = await scheme.verify(payload(operator.address), requirements());

    expect(result.isValid).toBe(false);
    expect(result.invalidReason).not.toBe(AUTHORIZED_SIGNER_REJECT);
    expect(result.invalidReason).toBe("invalid_upto_svm_payload_open_transaction");
  });
});

// ── deposit == ceiling binding (matrix cell
//    x402-upto-verify-open-server::invalid_upto_svm_payload_deposit_not_ceiling) ──
//
// The upto channel escrows the AUTHORIZED CEILING up front: the signed
// `deposit` must equal the signed `maxAmount` (== the advertised ceiling), so
// the operator can meter-then-settle any actual <= ceiling against funds that
// are provably already locked. A payload whose `deposit` is BELOW `maxAmount`
// is a silent under-deposit — the client authorizes (e.g.) a 1_000_000 ceiling
// while escrowing less, so a later settlement up to that ceiling has no on-chain
// backing. The guard lives at UptoSvmScheme.verify (`if (deposit !== maxAmount)
// return invalid_upto_svm_payload_deposit_not_ceiling`), mirroring the Go spine
// VerifyUptoPayload (go/protocols/x402/upto.go:164) and Python
// verify_upto_payload. It is checked AFTER the authorized-signer + amount guards
// and BEFORE the open-transaction/RPC work, so this stays RPC-free like the
// signer radar above.
describe("x402-upto verify-open: deposit must equal the authorized ceiling (real @x402/svm facilitator)", () => {
  const DEPOSIT_NOT_CEILING_REJECT = "invalid_upto_svm_payload_deposit_not_ceiling";

  /** The valid signer-and-amount payload, varying ONLY `deposit` so the verifier
   *  reaches the deposit==ceiling guard: `authorizedSigner` == operator (passes
   *  the signer guard) and `maxAmount` == the advertised ceiling (passes the
   *  amount guard). */
  function depositPayload(deposit: string) {
    const env = payload(operator.address);
    return { ...env, payload: { ...env.payload, deposit } };
  }

  it("rejects an under-deposit whose deposit is below the signed maxAmount ceiling", async () => {
    const scheme = new UptoSvmScheme(operator, {});

    // deposit 999_999 < ceiling 1_000_000: the escrow does not back the ceiling.
    const result = await scheme.verify(depositPayload("999999"), requirements());

    expect(result.isValid).toBe(false);
    expect(result.invalidReason).toBe(DEPOSIT_NOT_CEILING_REJECT);
    // Attribution is still the channel payer (payload.from), not the operator.
    expect(result.payer).toBe(client.address);
  });

  it("rejects an over-deposit whose deposit exceeds the signed maxAmount ceiling", async () => {
    const scheme = new UptoSvmScheme(operator, {});

    // The guard is a strict equality (deposit !== maxAmount), so an over-deposit
    // is refused too — the escrow must be EXACTLY the signed ceiling.
    const result = await scheme.verify(depositPayload("1000001"), requirements());

    expect(result.isValid).toBe(false);
    expect(result.invalidReason).toBe(DEPOSIT_NOT_CEILING_REJECT);
  });

  // Positive control: deposit == ceiling passes the deposit guard and the
  // verifier moves PAST it, failing downstream on the dummy open transaction
  // (invalid_upto_svm_payload_open_transaction). This proves the rejections
  // above are caused specifically by deposit != ceiling and are not an incidental
  // failure that would fire for any input.
  it("accepts deposit == ceiling (reject above is deposit-specific)", async () => {
    const scheme = new UptoSvmScheme(operator, {});

    const result = await scheme.verify(depositPayload(CEILING), requirements());

    expect(result.isValid).toBe(false);
    expect(result.invalidReason).not.toBe(DEPOSIT_NOT_CEILING_REJECT);
    expect(result.invalidReason).toBe("invalid_upto_svm_payload_open_transaction");
  });
});
