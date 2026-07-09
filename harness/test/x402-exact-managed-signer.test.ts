import { address } from "@solana/kit";
import { findAssociatedTokenPda } from "@solana-program/token";
import { describe, expect, it } from "vitest";
import { assertNoManagedTransferFunding } from "../src/conformance/x402";

const CANONICAL_ERROR =
  "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds";
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const MANAGED_SIGNER = "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ";
const CUSTOMER = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";

describe("x402 exact managed signer transfer guard", () => {
  it("rejects a managed multisig signer in the transfer account tail", async () => {
    await expect(
      assertNoManagedTransferFunding(
        [0, 1, 2, 3, 4],
        [CUSTOMER, MINT, CUSTOMER, CUSTOMER, MANAGED_SIGNER],
        MINT,
        TOKEN_PROGRAM,
        [MANAGED_SIGNER],
      ),
    ).rejects.toThrow(CANONICAL_ERROR);
  });

  it("rejects a managed signer named directly as the transfer source", async () => {
    await expect(
      assertNoManagedTransferFunding(
        [0, 1, 2, 3],
        [MANAGED_SIGNER, MINT, CUSTOMER, CUSTOMER],
        MINT,
        TOKEN_PROGRAM,
        [MANAGED_SIGNER],
      ),
    ).rejects.toThrow(CANONICAL_ERROR);
  });

  it("derives the managed source ATA with the transfer's Token-2022 program", async () => {
    const [managedAta] = await findAssociatedTokenPda({
      mint: address(MINT),
      owner: address(MANAGED_SIGNER),
      tokenProgram: address(TOKEN_2022_PROGRAM),
    });
    await expect(
      assertNoManagedTransferFunding(
        [0, 1, 2, 3],
        [String(managedAta), MINT, CUSTOMER, CUSTOMER],
        MINT,
        TOKEN_2022_PROGRAM,
        [MANAGED_SIGNER],
      ),
    ).rejects.toThrow(CANONICAL_ERROR);
  });
});
