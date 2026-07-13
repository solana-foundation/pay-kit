import {
  getBase64Codec,
  getCompiledTransactionMessageDecoder,
  getCompiledTransactionMessageEncoder,
  getTransactionDecoder,
  getTransactionEncoder,
} from "@solana/kit";
import { describe, expect, it } from "vitest";
import {
  type X402ExactRequirement,
  verifyExactTransaction,
} from "../src/conformance/x402";

// Executed coverage for the x402-exact structural defect classes that the
// regression bank tracked but nothing ran: malformed envelope, wrong account
// order, and wrong signer/writable flags. Rather than pin new cross-SDK reject
// vectors (which would have to reject identically across all 8 runners), this
// drives the TS reference verifier directly — the same 11-rule pass the runners
// mirror — so the defect is proven refused without risking the cross-SDK matrix
// on a locally-unrunnable runner. A positive control asserts the base
// transaction is accepted, so each reject is a real differential, not a
// verifier that rejects everything.

const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// A valid x402-exact transaction + its route requirement (the accept vector
// `x402-exact-accept-lighthouse-guard-referencing-fee-payer`).
const BASE_TX =
  "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAIBBAgBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsamXrWtVYgdvBS7bPEFS+O48vbfaJ03V3YyMVxJX9JrsvlNqVWh8N62Op6w3hGqvzrPlEKqbIqN+iY+xXcuvPwMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE3615Yv+x3ZJdCp+15tAM5hlbqLs6kf0H75hgxel7uAbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkEBAAFAiBOAAAEAAkDAQAAAAAAAAAHBAMFAgEKDOgDAAAAAAAABgYBAAEAAA==";

const REQUIREMENT: X402ExactRequirement = {
  asset: "GgBaCs3NCBuZN12kCJgAW63ydqohFkHEdfdEXBPzLHq",
  payTo: "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",
  amount: "1000",
  extra: { tokenProgram: TOKEN_PROGRAM },
};
const MANAGED_SIGNERS = ["4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"];

// The @solana/kit decoder returns a broad union; the reference verifier itself
// casts to its own compiled-message view to read staticAccounts/instructions.
// Mirror that with the fields this test mutates.
interface CompiledMsg {
  header: {
    numSignerAccounts: number;
    numReadonlySignerAccounts: number;
    numReadonlyNonSignerAccounts: number;
  };
  staticAccounts: readonly unknown[];
  instructions: ReadonlyArray<{
    programAddressIndex: number;
    accountIndices?: readonly number[];
    data?: Uint8Array;
  }>;
  [key: string]: unknown;
}

// Decode BASE_TX, let the caller mutate the compiled message, and re-encode
// into a fresh base64 transaction. The verifier's structural pass reads the
// message bytes only (no signature check), so a mutated message with stale
// signatures still exercises the exact rules.
function remint(mutate: (message: CompiledMsg) => CompiledMsg): string {
  const txBytes = getBase64Codec().encode(BASE_TX);
  const tx = getTransactionDecoder().decode(txBytes);
  const message = getCompiledTransactionMessageDecoder().decode(
    tx.messageBytes,
  ) as unknown as CompiledMsg;
  const mutated = mutate(message);
  const messageBytes = new Uint8Array(
    getCompiledTransactionMessageEncoder().encode(mutated as never),
  );
  const newTxBytes = getTransactionEncoder().encode({
    ...tx,
    messageBytes: messageBytes as unknown as typeof tx.messageBytes,
  });
  return getBase64Codec().decode(new Uint8Array(newTxBytes));
}

describe("x402-exact structural defects are refused (direct reference verifier)", () => {
  it("positive control: the base transaction verifies", async () => {
    await expect(
      verifyExactTransaction(BASE_TX, REQUIREMENT, MANAGED_SIGNERS),
    ).resolves.toBeUndefined();
  });

  it("malformed-envelope: an undecodable transaction proof is refused", async () => {
    await expect(
      verifyExactTransaction("!!!not-base64-or-a-transaction!!!", REQUIREMENT, MANAGED_SIGNERS),
    ).rejects.toThrow();
    // A truncated but base64-valid blob is refused too.
    await expect(
      verifyExactTransaction("AAAA", REQUIREMENT, MANAGED_SIGNERS),
    ).rejects.toThrow();
  });

  it("wrong-account-order: reordering the transferChecked accounts is refused", async () => {
    const reordered = remint((message) => {
      const keys = message.staticAccounts.map(String);
      const instructions = message.instructions.map((ix) =>
        keys[ix.programAddressIndex] === TOKEN_PROGRAM && ix.accountIndices
          ? { ...ix, accountIndices: [...ix.accountIndices].reverse() }
          : ix,
      );
      return { ...message, instructions };
    });
    expect(reordered).not.toBe(BASE_TX);
    await expect(
      verifyExactTransaction(reordered, REQUIREMENT, MANAGED_SIGNERS),
    ).rejects.toThrow();
  });

  // wrong-signer-writable-flags is intentionally NOT asserted here. The
  // off-chain structural verifier reads accounts by index and checks their
  // identities (mint/recipient/authority slots) and the instruction shape; it
  // is flag-agnostic by design. Flipping the message header's
  // numReadonlyNonSignerAccounts leaves the off-chain verdict unchanged
  // (empirically confirmed). Signer/writable-flag enforcement is an ON-CHAIN
  // guarantee (the payment-channels program's account constraints), covered by
  // the split/pr216-onchain-parity instruction-shape goldens, not by this
  // off-chain pass. The regression ledger records it as on-chain-covered so it
  // is neither silently claimed here nor lost.
  it("control: the off-chain verifier is flag-agnostic (documents the on-chain boundary)", async () => {
    const flipped = remint((message) => ({
      ...message,
      header: {
        ...message.header,
        numReadonlyNonSignerAccounts: message.header.numReadonlyNonSignerAccounts + 1,
      },
    }));
    expect(flipped).not.toBe(BASE_TX);
    // No off-chain rule depends on the flag, so this still verifies — proving
    // the boundary rather than a bug.
    await expect(
      verifyExactTransaction(flipped, REQUIREMENT, MANAGED_SIGNERS),
    ).resolves.toBeUndefined();
  });
});
