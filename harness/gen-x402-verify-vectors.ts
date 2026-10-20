// Generate the transactions inside the x402-exact verify vectors.
//
// The verify vectors used to carry a one-byte placeholder (`AA==`) as
// `payload.transaction`, so an SDK could "accept" them without verifying the
// payment. scheme_exact_svm.md requires a verifier to identify exactly one
// TransferChecked of `amount` of `asset` to the ATA of `payTo`, to keep the
// fee payer out of every instruction, and to check the memo. This script
// replaces each placeholder with a real, partially signed versioned
// transaction in the reference static layout (§3.1):
//
//   1. ComputeBudget SetComputeUnitLimit
//   2. ComputeBudget SetComputeUnitPrice
//   3. TransferChecked (client ATA -> payTo ATA, authority = client)
//   4. Memo (extra.memo, or a deterministic 32-hex-char nonce)
//
// with the server's fee payer as message fee payer and its signature slot
// left empty. Everything else in each header (version, network, extensions)
// is preserved, so reject vectors still isolate a single cause. Inputs are
// fixed and ed25519 is deterministic, so the output is byte-stable.
//
//   pnpm exec tsx gen-x402-verify-vectors.ts           # rewrite vectors
//   pnpm exec tsx gen-x402-verify-vectors.ts --check   # exit 1 if stale

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  address,
  appendTransactionMessageInstructions,
  type Blockhash,
  createKeyPairFromBytes,
  createSignerFromKeyPair,
  partiallySignTransactionMessageWithSigners,
  createTransactionMessage,
  getAddressFromPublicKey,
  getBase64EncodedWireTransaction,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
} from "@solana/kit";
import { findAssociatedTokenPda, getTransferCheckedInstruction } from "@solana-program/token";

const here = dirname(fileURLToPath(import.meta.url));
const FILES = ["vectors/x402-v1-verify.json", "vectors/x402-verify.json", "vectors/x402-extensions.json"];
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111";
const MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const BLOCKHASH = "11111111111111111111111111111111" as Blockhash;
const DECIMALS = 6;
// Deterministic keys. The client key matches the charge vectors.
const CLIENT_SECRET = [...Array(32).fill(7), 234, 74, 108, 99, 226, 156, 82, 10, 190, 245, 80, 123, 19, 46, 197, 249, 149, 71, 118, 174, 190, 190, 123, 146, 66, 30, 234, 105, 20, 70, 210, 44];

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}
function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}

async function feePayerKeys() {
  // ed25519 secret = seed || pubkey; derive the pubkey from a fixed seed.
  const seed = new Uint8Array(32).fill(9);
  const { getPublicKeyFromPrivateKey, createPrivateKeyFromBytes } = await import("@solana/kit");
  const priv = await createPrivateKeyFromBytes(seed, true);
  const pub = await getPublicKeyFromPrivateKey(priv, true);
  const pubBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pub));
  return { secret: [...seed, ...pubBytes], address: await getAddressFromPublicKey(pub) };
}

async function buildTransaction(opts: {
  feePayer: string;
  mint: string;
  payTo: string;
  amount: bigint;
  memo: string;
}): Promise<string> {
  const client = await createSignerFromKeyPair(await createKeyPairFromBytes(new Uint8Array(CLIENT_SECRET)));
  const clientAddress = client.address;
  const mint = address(opts.mint);
  const [source] = await findAssociatedTokenPda({ mint, owner: clientAddress, tokenProgram: address(TOKEN_PROGRAM) });
  const [destination] = await findAssociatedTokenPda({ mint, owner: address(opts.payTo), tokenProgram: address(TOKEN_PROGRAM) });
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayer(address(opts.feePayer), m),
    (m) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1000n }, m),
    (m) =>
      appendTransactionMessageInstructions(
        [
          { programAddress: address(COMPUTE_BUDGET), data: new Uint8Array([2, ...u32le(200_000)]) },
          { programAddress: address(COMPUTE_BUDGET), data: new Uint8Array([3, ...u64le(1n)]) },
          getTransferCheckedInstruction({
            source,
            mint,
            destination,
            authority: client,
            amount: opts.amount,
            decimals: DECIMALS,
          }),
          { programAddress: address(MEMO), data: new TextEncoder().encode(opts.memo) },
        ],
        m,
      ),
  );
  // The fee payer is an address, so its signature slot stays empty.
  const signed = await partiallySignTransactionMessageWithSigners(message);
  return getBase64EncodedWireTransaction(signed);
}

type Vector = { id: string; mode: string; input: Record<string, unknown>; description?: string };

async function regenerate(vector: Vector, feePayer: { secret: number[]; address: string }): Promise<Vector> {
  if (vector.mode !== "verify-transaction") return vector;
  const input = vector.input;
  const header = JSON.parse(Buffer.from(String(input.x402PaymentHeader), "base64").toString("utf8")) as {
    accepted?: { extra?: Record<string, unknown> };
    payload: { transaction?: string };
  };
  if (header.accepted) {
    header.accepted.extra = { ...(header.accepted.extra ?? {}), feePayer: feePayer.address };
    delete header.accepted.extra.decimals;
  }
  const memo = String(header.accepted?.extra?.memo ?? `${vector.id.replace(/[^a-z0-9]/g, "").slice(0, 16).padEnd(16, "0")}00000000000000000`.slice(0, 32));
  header.payload.transaction = await buildTransaction({
    feePayer: feePayer.address,
    mint: String(input.x402ServerCurrency),
    payTo: String(input.x402ServerRecipient),
    amount: BigInt(String(input.x402ServerAmount)),
    memo,
  });
  return {
    ...vector,
    input: {
      ...input,
      x402PaymentHeader: Buffer.from(JSON.stringify(header), "utf8").toString("base64"),
      x402ServerFeePayer: feePayer.address,
      x402ServerFeePayerSecretKey: feePayer.secret,
      rpcFixtures: {
        recentBlockhash: BLOCKHASH,
        mints: { [String(input.x402ServerCurrency)]: { owner: TOKEN_PROGRAM, decimals: DECIMALS } },
      },
    },
  };
}

async function main() {
  const check = process.argv.includes("--check");
  const feePayer = await feePayerKeys();
  let stale = false;
  for (const file of FILES) {
    const path = join(here, file);
    const current = readFileSync(path, "utf8");
    const vectors = JSON.parse(current) as Vector[];
    const next = `${JSON.stringify(await Promise.all(vectors.map((v) => regenerate(v, feePayer))), null, 2)}\n`;
    if (next !== current) {
      stale = true;
      if (!check) writeFileSync(path, next);
    }
  }
  if (check && stale) {
    console.error("x402 verify vectors are stale; run `pnpm exec tsx gen-x402-verify-vectors.ts` in harness/");
    process.exit(1);
  }
}

await main();
