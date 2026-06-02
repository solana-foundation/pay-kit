// Decode a base64 wire transaction into the semantic shape the
// conformance driver asserts against. Shared by the TS reference runner
// and (eventually) any TS-side shape assertions. RPC-free.

import {
  getBase64Codec,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
} from "@solana/kit";

const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111";
const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

type CompiledInstruction = {
  accountIndices: readonly number[];
  data: Uint8Array;
  programAddressIndex: number;
};

type CompiledMessage = {
  addressTableLookups?: readonly unknown[];
  instructions: readonly CompiledInstruction[];
  staticAccounts: readonly string[];
};

export type DecodedShape = {
  feePayer: string;
  programs: string[];
  transfers: Array<{
    kind: "spl" | "sol";
    destination: string;
    mint?: string;
    amount: string;
    decimals?: number;
    tokenProgram?: string;
  }>;
  computeUnitLimit?: number;
  computeUnitPrice?: string;
  memos: string[];
};

function readU32Le(data: Uint8Array, offset: number): number {
  return (
    (data[offset] |
      (data[offset + 1] << 8) |
      (data[offset + 2] << 16) |
      (data[offset + 3] << 24)) >>>
    0
  );
}

function readU64Le(data: Uint8Array, offset: number): bigint {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return view.getBigUint64(offset, true);
}

export function decodeTransactionShape(transactionBase64: string): DecodedShape {
  const txBytes = getBase64Codec().encode(transactionBase64);
  const decoded = getTransactionDecoder().decode(txBytes);
  const message = getCompiledTransactionMessageDecoder().decode(
    decoded.messageBytes,
  ) as unknown as CompiledMessage;

  const accountAt = (index: number): string => String(message.staticAccounts[index]);
  const programs = new Set<string>();
  const transfers: DecodedShape["transfers"] = [];
  const memos: string[] = [];
  let computeUnitLimit: number | undefined;
  let computeUnitPrice: string | undefined;

  for (const ix of message.instructions) {
    const program = accountAt(ix.programAddressIndex);
    programs.add(program);

    if (program === COMPUTE_BUDGET_PROGRAM) {
      if (ix.data[0] === 2 && ix.data.length === 5) {
        computeUnitLimit = readU32Le(ix.data, 1);
      } else if (ix.data[0] === 3 && ix.data.length === 9) {
        computeUnitPrice = readU64Le(ix.data, 1).toString();
      }
      continue;
    }

    if (program === MEMO_PROGRAM) {
      memos.push(new TextDecoder().decode(ix.data));
      continue;
    }

    if (program === SYSTEM_PROGRAM) {
      // System transfer: u32 LE discriminator 2 + u64 LE lamports.
      if (ix.data.length >= 12 && readU32Le(ix.data, 0) === 2) {
        transfers.push({
          amount: readU64Le(ix.data, 4).toString(),
          destination: accountAt(ix.accountIndices[1]),
          kind: "sol",
        });
      }
      continue;
    }

    if (program === TOKEN_PROGRAM || program === TOKEN_2022_PROGRAM) {
      // transferChecked: discriminator 12, u64 amount at [1], decimals [9].
      if (ix.data[0] === 12 && ix.accountIndices.length >= 4) {
        transfers.push({
          amount: readU64Le(ix.data, 1).toString(),
          decimals: ix.data[9],
          destination: accountAt(ix.accountIndices[2]),
          kind: "spl",
          mint: accountAt(ix.accountIndices[1]),
          tokenProgram: program,
        });
      }
      continue;
    }
  }

  return {
    computeUnitLimit,
    computeUnitPrice,
    feePayer: accountAt(0),
    memos,
    programs: Array.from(programs),
    transfers,
  };
}
