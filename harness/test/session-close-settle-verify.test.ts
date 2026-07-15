// SESSION CLOSE + SETTLE + DISTRIBUTE structural coverage (matrix cell
// mpp-session-close-settle::accept).
//
// The audit flagged this cell as a CONFIRMED systemic gap: on a cooperative
// close the session is supposed to settle the highest accepted voucher on-chain
// (settle_and_finalize + Ed25519 precompile + distribute) and split the settled
// amount across the configured recipients. But in CI the session never actually
// settles — the harness runs rpc=None with the program absent, so `handleClose`
// (Session.ts:894-920) takes the `!merchantSigner || !rpc` branch and returns a
// receipt whose `reference` is the *channelId itself*, a fake "settlement" that
// never broadcasts and never distributes. Nothing asserted that a real close
// composes and submits the settle+distribute transaction, nor that the
// distribute instruction carries one balance-delta destination per split.
//
// This suite drives the REAL settle+distribute composer on the public server
// surface — `@solana/mpp/server`'s `submitSettleAndDistribute`, the exact
// function `closeAndSettleChannel` (Session.ts:1140) calls on the accept path —
// with a hand-built highest voucher and a two-recipient basis-point split, and
// asserts the accept outcome end to end, RPC-free and deterministic:
//
//   1. the settlement is BROADCAST (rpc.sendTransaction is invoked exactly once
//      and its signature is what the caller gets back) — a close that returned a
//      receipt ref without submitting, the regression this cell tracks, would
//      never reach sendTransaction;
//   2. the transaction settles THE HIGHEST VOUCHER — the Ed25519 precompile at
//      instruction 0 embeds the canonical 50-byte voucher message binding the
//      channel + cumulative + expiry we signed;
//   3. the distribute instruction encodes the DISTRIBUTE BALANCE DELTAS PER
//      RECIPIENT SPLIT — its `distributeArgs.recipients` are exactly the
//      configured (recipient, bps) entries, in order, and its dynamic account
//      tail is one WRITABLE recipient ATA per split (the on-chain delta target),
//      with the payee (merchant) ATA present to receive the residual.
//
// The composer is RPC-free by construction (the caller injects the wire builder
// and a minimal `sendTransaction`), so this is a fast structural (T1) net rather
// than a slow surfpool E2E — and unlike an on-chain run it is wireable today
// (there is no TS session client to drive a full forked-surfnet close).
import { findAssociatedTokenPda } from "@solana-program/token";
import {
  AccountRole,
  appendTransactionMessageInstructions,
  createTransactionMessage,
  generateKeyPairSigner,
  getAddressDecoder,
  getArrayDecoder,
  getBase58Decoder,
  getBase64EncodedWireTransaction,
  getSignatureFromTransaction,
  getStructDecoder,
  getU16Decoder,
  getU8Decoder,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type Address,
  type Blockhash,
  type Instruction,
  type KeyPairSigner,
  type Signature,
} from "@solana/kit";
import { encodeVoucherMessageBytes, submitSettleAndDistribute } from "@solana/mpp/server";
import { beforeAll, describe, expect, it } from "vitest";

// SPL Token program (the tokenProgram the ATAs are derived under).
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
// Fixed 11-account header of the distribute instruction (channel, payer,
// rentPayer, channelTokenAccount, payerTokenAccount, payeeTokenAccount,
// treasuryTokenAccount, mint, tokenProgram, eventAuthority, selfProgram);
// the recipient-ATA tail follows. Mirrors getDistributeInstruction (generated).
const DISTRIBUTE_HEADER_ACCOUNTS = 11;
const PAYEE_TOKEN_ACCOUNT_INDEX = 5;
// Ed25519 precompile message offset (16-byte header + 32 pubkey + 64 sig = 112).
const ED25519_MESSAGE_OFFSET = 112;
const VOUCHER_MESSAGE_BYTES = 50;

const CUMULATIVE = 900_000n; // highest accepted voucher (base units)
const EXPIRES_AT = 4_000_000_000n; // far-future expiry (outlasts the window)

// A base58 signature-shaped value the mock RPC returns as the broadcast result.
const BROADCAST_SIGNATURE = getBase58Decoder().decode(
  new Uint8Array(64).fill(9),
) as Signature;

type VoucherSigner = { pubkeyBase58: string; keyPair: CryptoKeyPair };

async function makeVoucherSigner(): Promise<VoucherSigner> {
  const keyPair = (await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  return { pubkeyBase58: getBase58Decoder().decode(raw), keyPair };
}

/** Sign the canonical 50-byte voucher message so the precompile the composer
 *  emits carries exactly this channel + cumulative + expiry. */
async function signHighestVoucher(
  voucherSigner: VoucherSigner,
  channelId: string,
  cumulative: bigint,
  expiresAt: bigint,
) {
  const encoded = encodeVoucherMessageBytes({ channelId, cumulativeAmount: cumulative, expiresAt });
  // Re-back the message with a plain ArrayBuffer so it satisfies BufferSource.
  const message = new Uint8Array(new ArrayBuffer(encoded.byteLength));
  message.set(encoded);
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", voucherSigner.keyPair.privateKey, message),
  );
  return {
    data: {
      channelId,
      cumulativeAmount: cumulative.toString(),
      expiresAt: Number(expiresAt),
    },
    signature: getBase58Decoder().decode(sig),
  };
}

// distribute instruction data = discriminator u8(7) || u32-prefixed array of
// { recipient: address(32), bps: u16 }. Decoded with kit codecs (the generated
// decoder is not on the package's public surface).
const distributeDataDecoder = getStructDecoder([
  ["discriminator", getU8Decoder()],
  [
    "recipients",
    getArrayDecoder(
      getStructDecoder([
        ["recipient", getAddressDecoder()],
        ["bps", getU16Decoder()],
      ]),
    ),
  ],
]);

async function ata(mint: string, owner: string): Promise<Address> {
  const [addr] = await findAssociatedTokenPda({
    mint: mint as Address,
    owner: owner as Address,
    tokenProgram: TOKEN_PROGRAM as Address,
  });
  return addr;
}

describe("session close settle+distribute composer — accept", () => {
  let merchant: KeyPairSigner; // authorized settle signer
  let channel: KeyPairSigner; // channel PDA address (32-byte base58)
  let payer: KeyPairSigner; // channel payer (refund destination)
  let operator: KeyPairSigner; // rentPayer recorded at open
  let recipientA: KeyPairSigner; // split recipient A
  let recipientB: KeyPairSigner; // split recipient B
  let mint: KeyPairSigner;
  let voucherSigner: VoucherSigner;

  // Merchant (payee) is the settle signer; residual settles to its ATA.
  let payee: string;
  let splits: readonly { readonly bps: number; readonly recipient: string }[];

  let sendCount = 0;
  let broadcastWire: string | undefined;
  let builtWire: string | undefined;
  let builtSignature: Signature | undefined;
  let result: Awaited<ReturnType<typeof submitSettleAndDistribute>>;

  beforeAll(async () => {
    [merchant, channel, payer, operator, recipientA, recipientB, mint] = await Promise.all([
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
    ]);
    voucherSigner = await makeVoucherSigner();
    payee = merchant.address;
    // 25% / 15% to the two recipients; the 60% residual lands on the payee.
    splits = [
      { bps: 2500, recipient: recipientA.address },
      { bps: 1500, recipient: recipientB.address },
    ];

    const signed = await signHighestVoucher(voucherSigner, channel.address, CUMULATIVE, EXPIRES_AT);

    result = await submitSettleAndDistribute({
      buildAndSignWireTransaction: async (composed) => {
        // Compile the composed instruction list into a REAL signed wire tx:
        // the settle path decodes it to bind the broadcast signature before
        // submitting, so a placeholder string no longer satisfies the contract.
        const message = pipe(
          createTransactionMessage({ version: 0 }),
          (m) => setTransactionMessageFeePayerSigner(merchant, m),
          (m) =>
            setTransactionMessageLifetimeUsingBlockhash(
              {
                blockhash: "11111111111111111111111111111111" as Blockhash,
                lastValidBlockHeight: 0n,
              },
              m,
            ),
          (m) => appendTransactionMessageInstructions(composed as unknown as Instruction[], m),
        );
        const signedTx = await signTransactionMessageWithSigners(message);
        builtWire = getBase64EncodedWireTransaction(signedTx);
        builtSignature = getSignatureFromTransaction(signedTx);
        return builtWire;
      },
      channelId: channel.address,
      mint: mint.address,
      network: "localnet",
      payee,
      payer: payer.address,
      rentPayer: operator.address,
      rpc: {
        sendTransaction: (wire: string) => {
          sendCount += 1;
          broadcastWire = wire;
          return { send: async () => BROADCAST_SIGNATURE };
        },
      },
      signer: merchant,
      splits,
      tokenProgram: TOKEN_PROGRAM,
      voucher: { authorizedSigner: voucherSigner.pubkeyBase58, signed },
    });
  });

  it("BROADCASTS the settlement (not a fake receipt ref that never submits)", () => {
    expect(sendCount, "settle+distribute must be submitted exactly once").toBe(1);
    expect(broadcastWire).toBe(builtWire);
    // The reported signature is DERIVED from the signed wire (bound before
    // broadcast), never trusted from the RPC's response value.
    expect(result.signature).toBe(builtSignature);
    expect(result.signature).not.toBe(BROADCAST_SIGNATURE);
  });

  it("composes ed25519-precompile + settle_and_finalize + distribute", () => {
    // voucher present => Ed25519 precompile is prepended (index 0), then
    // settle_and_finalize (1), then distribute (2).
    expect(result.instructions).toHaveLength(3);
  });

  it("settles THE HIGHEST VOUCHER (precompile binds channel + cumulative + expiry)", () => {
    const expected = encodeVoucherMessageBytes({
      channelId: channel.address,
      cumulativeAmount: CUMULATIVE,
      expiresAt: EXPIRES_AT,
    });
    const precompile = new Uint8Array(result.instructions[0].data as Uint8Array);
    const embedded = precompile.subarray(
      ED25519_MESSAGE_OFFSET,
      ED25519_MESSAGE_OFFSET + VOUCHER_MESSAGE_BYTES,
    );
    expect(Array.from(embedded)).toEqual(Array.from(expected));
  });

  it("distributes the balance deltas PER RECIPIENT SPLIT (recipients + bps, in order)", () => {
    const distribute = result.instructions[2];
    const decoded = distributeDataDecoder.decode(distribute.data as Uint8Array);
    expect(decoded.discriminator).toBe(7); // distribute
    expect(decoded.recipients).toEqual([
      { recipient: recipientA.address, bps: 2500 },
      { recipient: recipientB.address, bps: 1500 },
    ]);
  });

  it("appends one WRITABLE recipient-ATA delta target per split (the payout accounts)", async () => {
    const distribute = result.instructions[2];
    const tail = distribute.accounts.slice(DISTRIBUTE_HEADER_ACCOUNTS);
    expect(tail).toHaveLength(splits.length);

    const expectedAtas = [
      await ata(mint.address, recipientA.address),
      await ata(mint.address, recipientB.address),
    ];
    tail.forEach((meta, i) => {
      expect(meta.address).toBe(expectedAtas[i]);
      expect(meta.role, "recipient ATA must be writable to receive its split").toBe(
        AccountRole.WRITABLE,
      );
    });
  });

  it("carries the payee (merchant) ATA writable for the settled residual", async () => {
    const distribute = result.instructions[2];
    const payeeMeta = distribute.accounts[PAYEE_TOKEN_ACCOUNT_INDEX];
    expect(payeeMeta.address).toBe(await ata(mint.address, payee));
    expect(payeeMeta.role).toBe(AccountRole.WRITABLE);
  });
});
