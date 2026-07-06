// Server-side on-chain operations for MPP sessions.
//
// Mirrors the on-chain helpers in
// `rust/crates/mpp/src/program/payment_channels.rs` and the orchestration
// in `rust/crates/mpp/src/server/session.rs`. Two responsibilities:
//
//   1. Build the exact instruction bytes the on-chain payment-channels
//      program expects (settle_and_finalize, distribute, top_up, plus the
//      multi-delegator init/update for OperatedVoucher pull parity).
//   2. Verify client-submitted open transactions against the session
//      challenge before persisting channel state.
//
// All builders are pure functions — the only thing that touches the
// network is the optional submit* helpers, which the caller threads an
// RPC + signer through.

import {
    type AccountMeta,
    AccountRole,
    type Address,
    address,
    getAddressEncoder,
    getBase58Decoder,
    getBase58Encoder,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getI64Encoder,
    getProgramDerivedAddress,
    getTransactionDecoder,
    getU64Encoder,
    getUtf8Encoder,
    type Instruction,
    type InstructionWithAccounts,
    type InstructionWithData,
    type ReadonlyUint8Array,
    type Signature,
    type TransactionPartialSigner,
    type TransactionSigner,
} from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';

import { ASSOCIATED_TOKEN_PROGRAM, defaultTokenProgramForCurrency, resolveStablecoinMint } from '../../constants.js';
import { getChannelDecoder } from '../../generated/payment-channels/accounts/channel.js';
import { getDistributeInstruction } from '../../generated/payment-channels/instructions/distribute.js';
import { getSettleAndFinalizeInstruction } from '../../generated/payment-channels/instructions/settleAndFinalize.js';
import { getTopUpInstruction } from '../../generated/payment-channels/instructions/topUp.js';
import { findEventAuthorityPda } from '../../generated/payment-channels/pdas/eventAuthority.js';
import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../../generated/payment-channels/programs/paymentChannels.js';
import { ChannelStatus } from '../../generated/payment-channels/types/channelStatus.js';
import type { OpenPayload, SignedVoucher } from '../../shared/session-types.js';
import { assertLegacyOrV0Message, coSignBase64Transaction } from '../../utils/transactions.js';

/**
 * Concrete instruction shape returned by every builder in this module:
 * the program address, a concrete account list, and a `Uint8Array` data
 * buffer. Avoids the `data?: Uint8Array | undefined` widening of the
 * base `Instruction` interface.
 */
export type ServerInstruction = Instruction &
    InstructionWithAccounts<readonly AccountMeta[]> &
    InstructionWithData<ReadonlyUint8Array>;

/** Sysvar address holding the current transaction's instructions list. */
export const INSTRUCTIONS_SYSVAR_ADDRESS =
    'Sysvar1nstructions1111111111111111111111111' as Address<'Sysvar1nstructions1111111111111111111111111'>;

/** Ed25519 signature-verification precompile program id. */
export const ED25519_PROGRAM_ADDRESS =
    'Ed25519SigVerify111111111111111111111111111' as Address<'Ed25519SigVerify111111111111111111111111111'>;

/**
 * Canonical payment-channels program ID, re-exported from the generated client
 * so there's a single source of truth that updates on IDL regeneration.
 * Callers can override per-call.
 */
export const PAYMENT_CHANNELS_PROGRAM_ID = PAYMENT_CHANNELS_PROGRAM_ADDRESS;

/** Canonical multi-delegator program ID. */
export const MULTI_DELEGATOR_PROGRAM_ID =
    'EPEUTog1kptYkthDJF6MuB1aM4aDAwHYwoF32Rzv5rqg' as Address<'EPEUTog1kptYkthDJF6MuB1aM4aDAwHYwoF32Rzv5rqg'>;

/**
 * Treasury owner baked into the deployed (mainnet-build) payment-channels
 * program — Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP. The treasury ATA is
 * ATA(TREASURY_OWNER, mint, tokenProgram). Mirrors `TREASURY_OWNER` in
 * `rust/crates/core/src/payment_channels.rs`.
 */
const TREASURY_OWNER_BYTES = new Uint8Array([
    0xb0, 0x41, 0xd9, 0xd3, 0x37, 0xb7, 0x21, 0xbe, 0x57, 0x89, 0x4e, 0xb6, 0x9c, 0x3b, 0x68, 0x09, 0xa5, 0x3a, 0x0e,
    0x2b, 0x6a, 0x23, 0x99, 0xfc, 0x7d, 0x5b, 0x7e, 0xda, 0x8c, 0xac, 0x89, 0xaa,
]);

/** Payment-channel open instruction discriminator. */
const OPEN_DISCRIMINATOR = 1;

/** Payment-channel top_up instruction discriminator. */
const TOP_UP_DISCRIMINATOR = 3;

const U16_LE = (n: number) => new Uint8Array([n & 0xff, (n >> 8) & 0xff]);

// ─────────────────────────────────────────────────────────────────────
// Ed25519 precompile
// ─────────────────────────────────────────────────────────────────────

/**
 * Build an Ed25519 verify precompile instruction over the 48-byte voucher
 * message. Layout matches `build_ed25519_verify_instruction` in
 * `rust/crates/mpp/src/program/payment_channels.rs`.
 *
 * `signature` is the 64-byte ed25519 signature, `signer` is the 32-byte
 * verifying key, and `message` is the canonical voucher payload.
 */
export function buildEd25519VerifyInstruction(args: {
    readonly message: Uint8Array;
    readonly signature: Uint8Array;
    readonly signer: Uint8Array;
}): ServerInstruction {
    if (args.signer.byteLength !== 32) throw new Error(`signer must be 32 bytes, got ${args.signer.byteLength}`);
    if (args.signature.byteLength !== 64) {
        throw new Error(`signature must be 64 bytes, got ${args.signature.byteLength}`);
    }

    const publicKeyOffset = 16;
    const signatureOffset = publicKeyOffset + 32; // 48
    const messageDataOffset = signatureOffset + 64; // 112
    const messageDataSize = args.message.byteLength;
    if (messageDataSize > 0xffff) {
        throw new Error(`voucher message too long: ${messageDataSize}`);
    }
    const currentInstruction = 0xffff;

    // Header (16 bytes): num_signatures (1) + padding (1) + 12 bytes of offsets
    // + 2 bytes message_data_size = 16. Layout below mirrors the Rust builder.
    const data = new Uint8Array(messageDataOffset + messageDataSize);
    data[0] = 1; // num_signatures
    data[1] = 0; // padding
    data.set(U16_LE(signatureOffset), 2);
    data.set(U16_LE(currentInstruction), 4);
    data.set(U16_LE(publicKeyOffset), 6);
    data.set(U16_LE(currentInstruction), 8);
    data.set(U16_LE(messageDataOffset), 10);
    data.set(U16_LE(messageDataSize), 12);
    data.set(U16_LE(currentInstruction), 14);
    data.set(args.signer, publicKeyOffset);
    data.set(args.signature, signatureOffset);
    data.set(args.message, messageDataOffset);

    return {
        accounts: [],
        data,
        programAddress: ED25519_PROGRAM_ADDRESS,
    } as ServerInstruction;
}

/**
 * Encode the canonical 48-byte voucher payload. Identical to
 * `encodeVoucherMessage` in `shared/voucher.ts` but kept here so the
 * on-chain helpers don't pull in client-side types.
 */
export function encodeVoucherMessageBytes(args: {
    readonly channelId: string;
    readonly cumulativeAmount: bigint;
    readonly expiresAt: bigint;
}): Uint8Array {
    const channelBytes = getBase58Encoder().encode(args.channelId);
    if (channelBytes.byteLength !== 32) {
        throw new Error(`channelId must decode to 32 bytes; got ${channelBytes.byteLength}`);
    }
    const out = new Uint8Array(48);
    out.set(channelBytes as Uint8Array, 0);
    out.set(getU64Encoder().encode(args.cumulativeAmount) as Uint8Array, 32);
    out.set(getI64Encoder().encode(args.expiresAt) as Uint8Array, 40);
    return out;
}

// ─────────────────────────────────────────────────────────────────────
// settle_and_finalize + distribute + top_up
// ─────────────────────────────────────────────────────────────────────

/** Arguments to {@link buildSettleAndFinalizeInstructions}. */
export interface SettleAndFinalizeBuildArgs {
    /** Payment-channel address being settled (base58). */
    readonly channelId: string;
    /** Merchant signer authorized to settle the channel. */
    readonly merchantSigner: TransactionSigner;
    /** Payment-channels program id override. */
    readonly programId?: Address | undefined;
    /**
     * Optional final voucher. When present, an Ed25519 precompile IX is
     * prepended and `hasVoucher` is set to 1 on the settle_and_finalize args.
     * Both `signature` (base58, 64 bytes) and `authorizedSigner` (base58, 32 bytes)
     * are required when `voucher` is provided.
     */
    readonly voucher?:
        | {
              readonly authorizedSigner: string;
              readonly signed: SignedVoucher;
          }
        | undefined;
}

/** Instructions produced for a settle_and_finalize call. */
export interface SettleAndFinalizeBuildResult {
    /** Instructions in submit order (Ed25519 precompile first when a voucher is settled). */
    readonly instructions: readonly ServerInstruction[];
    /** True when the transaction must carry the Ed25519 precompile instruction. */
    readonly requiresEd25519Precompile: boolean;
}

/**
 * Build the instruction(s) for an on-chain settle_and_finalize. If a
 * voucher is provided, an Ed25519 precompile IX is prepended at index 0
 * — the settle_and_finalize IX references the instructions sysvar at
 * index `-1` (i.e. the precompile immediately before it).
 */
export function buildSettleAndFinalizeInstructions(args: SettleAndFinalizeBuildArgs): SettleAndFinalizeBuildResult {
    const programId = args.programId ?? PAYMENT_CHANNELS_PROGRAM_ID;
    const channel = address(args.channelId);
    const instructions: ServerInstruction[] = [];

    let cumulativeAmount = 0n;
    let expiresAt = 0n;
    let hasVoucher = 0;

    if (args.voucher) {
        const { signed, authorizedSigner } = args.voucher;
        cumulativeAmount = parseU64String(signed.data.cumulativeAmount, 'voucher.cumulativeAmount');
        expiresAt = toBigInt(signed.data.expiresAt);
        hasVoucher = 1;

        const signerBytes = getBase58Encoder().encode(authorizedSigner) as Uint8Array;
        if (signerBytes.byteLength !== 32) {
            throw new Error(`authorizedSigner must decode to 32 bytes; got ${signerBytes.byteLength}`);
        }
        const signatureBytes = getBase58Encoder().encode(signed.signature) as Uint8Array;
        if (signatureBytes.byteLength !== 64) {
            throw new Error(`voucher signature must decode to 64 bytes; got ${signatureBytes.byteLength}`);
        }
        const message = encodeVoucherMessageBytes({
            channelId: signed.data.channelId,
            cumulativeAmount,
            expiresAt,
        });

        instructions.push(
            buildEd25519VerifyInstruction({
                message,
                signature: signatureBytes,
                signer: signerBytes,
            }),
        );
    }

    const ix = getSettleAndFinalizeInstruction(
        {
            channel,
            instructionsSysvar: INSTRUCTIONS_SYSVAR_ADDRESS,
            merchant: args.merchantSigner,
            // The program reads the voucher from the ed25519 precompile; the
            // settle_and_finalize args carry only the hasVoucher flag.
            settleAndFinalizeArgs: { hasVoucher },
        },
        { programAddress: programId },
    );
    instructions.push(ix as unknown as ServerInstruction);

    return {
        instructions,
        requiresEd25519Precompile: hasVoucher === 1,
    };
}

/** Arguments to {@link buildDistributeInstruction}. */
export interface DistributeBuildArgs {
    readonly channelState: { readonly channelId: string; readonly payee: string; readonly payer: string };
    readonly mint: string;
    readonly payerAddr?: string | undefined;
    readonly programId?: Address | undefined;
    /**
     * Operator recorded as `rentPayer` at open; it reclaims the channel PDA +
     * escrow ATA rent at finalize (writable, not a signer). Required — it must
     * match the rentPayer the channel stored, so there is no payer fallback.
     */
    readonly rentPayer: string;
    readonly splits: readonly { readonly bps: number; readonly recipient: string }[];
    readonly tokenProgram: string;
}

/**
 * Build a distribute instruction with the dynamic recipient ATA tail.
 *
 * The tail (one writable account per split) is appended after the fixed
 * 10-account header, matching the Rust `build_distribute_instruction` in
 * `rust/crates/mpp/src/program/payment_channels.rs`.
 */
export async function buildDistributeInstruction(args: DistributeBuildArgs): Promise<ServerInstruction> {
    const programId = args.programId ?? PAYMENT_CHANNELS_PROGRAM_ID;
    const mint = address(args.mint);
    const tokenProgram = address(args.tokenProgram);
    const channel = address(args.channelState.channelId);
    const payer = address(args.payerAddr ?? args.channelState.payer);
    const payee = address(args.channelState.payee);
    // rentPayer reclaims the channel/escrow rent at finalize; it is the
    // operator recorded as the channel rentPayer at open. It must match the
    // rentPayer the channel stored, so it is required: a payer fallback would
    // build an instruction the on-chain rentPayer check rejects.
    if (!args.rentPayer) {
        throw new Error(
            'buildDistributeInstruction: rentPayer is required (the operator recorded as the channel rentPayer at open)',
        );
    }
    const rentPayer = address(args.rentPayer);

    const [channelTokenAccount] = await findAssociatedTokenPda({ mint, owner: channel, tokenProgram });
    const [payerTokenAccount] = await findAssociatedTokenPda({ mint, owner: payer, tokenProgram });
    const [payeeTokenAccount] = await findAssociatedTokenPda({ mint, owner: payee, tokenProgram });
    const [eventAuthority] = await findEventAuthorityPda({ programAddress: programId });
    const treasury = deriveTreasuryAddress();
    const [treasuryTokenAccount] = await findAssociatedTokenPda({ mint, owner: treasury, tokenProgram });

    const recipientTokenAccounts: Address[] = [];
    const distributions: { bps: number; recipient: Address }[] = [];
    for (const split of args.splits) {
        const recipient = address(split.recipient);
        const [recipientAta] = await findAssociatedTokenPda({ mint, owner: recipient, tokenProgram });
        recipientTokenAccounts.push(recipientAta);
        distributions.push({ bps: split.bps, recipient });
    }

    const ix = getDistributeInstruction(
        {
            channel,
            channelTokenAccount,
            distributeArgs: { recipients: distributions },
            eventAuthority,
            mint,
            payee: payee,
            payeeTokenAccount,
            payer,
            payerTokenAccount,
            recipientTokenAccounts,
            rentPayer,
            selfProgram: programId,
            tokenProgram,
            treasuryTokenAccount,
        } as unknown as Parameters<typeof getDistributeInstruction>[0],
        { programAddress: programId },
    );
    return ix as unknown as ServerInstruction;
}

/** Arguments to the top_up instruction builder. */
export interface TopUpBuildArgs {
    readonly amount: bigint;
    readonly channelId: string;
    readonly mint: string;
    readonly payer: TransactionSigner;
    readonly programId?: Address | undefined;
    readonly tokenProgram: string;
}

/**
 * Build a top_up instruction. Derives the payer + channel ATAs for the
 * given mint/token program — same layout the on-chain program expects.
 */
export async function buildTopUpInstruction(args: TopUpBuildArgs): Promise<ServerInstruction> {
    const programId = args.programId ?? PAYMENT_CHANNELS_PROGRAM_ID;
    const channel = address(args.channelId);
    const mint = address(args.mint);
    const tokenProgram = address(args.tokenProgram);
    const [payerTokenAccount] = await findAssociatedTokenPda({ mint, owner: args.payer.address, tokenProgram });
    const [channelTokenAccount] = await findAssociatedTokenPda({ mint, owner: channel, tokenProgram });

    const ix = getTopUpInstruction(
        {
            channel,
            channelTokenAccount,
            mint,
            payer: args.payer,
            payerTokenAccount,
            tokenProgram,
            topUpArgs: { amount: args.amount },
        },
        { programAddress: programId },
    );
    return ix as unknown as ServerInstruction;
}

// ─────────────────────────────────────────────────────────────────────
// verifyOpenTx: parse a client-submitted open tx and validate the IX
// ─────────────────────────────────────────────────────────────────────

/**
 * Expected fields against which the server validates a client-submitted
 * open transaction. The PDAs (channel, channel-token-account,
 * payer-token-account, event-authority) are recomputed if not provided.
 */
export interface VerifyOpenTxExpected {
    readonly authorizedSigner: string;
    readonly currency: string;
    readonly maxCap: bigint;
    /** Optional override for the SPL mint (otherwise resolved from currency/network). */
    readonly mint?: string | undefined;
    readonly network?: string | undefined;
    /**
     * Operator / fee-payer pubkey (base58) = the expected `rentPayer`. The open
     * instruction's `rentPayer` account (slot 1) must equal it (it is pinned to
     * the operator that co-signs open as fee payer while gasless). Required: the
     * rentPayer slot is a security boundary and is always checked.
     */
    readonly operator: string;
    /** Optional override for the payment-channels program id. */
    readonly programId?: string | undefined;
    /** Primary recipient (challenge `recipient`). */
    readonly recipient: string;
    /** Optional explicit token program (otherwise derived from currency/network). */
    readonly tokenProgram?: string | undefined;
}

/** One entry of a `getSignatureStatuses` response. */
export interface SignatureStatus {
    readonly confirmationStatus?: string | null | undefined;
    readonly err: unknown;
}

/** Minimal RPC shape needed to check transaction signature statuses. */
export interface SignatureStatusRpc {
    getSignatureStatuses(signatures: readonly Signature[]): {
        send(): Promise<{ value: ReadonlyArray<SignatureStatus | null> }>;
    };
}

/** Arguments to {@link verifyOpenTx}. */
export interface VerifyOpenTxArgs {
    /** Expected values from the challenge. */
    readonly expected: VerifyOpenTxExpected;
    /** Open payload received from the client. */
    readonly openPayload: OpenPayload;
    /** Minimal RPC shape; only `getSignatureStatuses` is used. Optional. */
    readonly rpc?: SignatureStatusRpc | undefined;
}

/** Channel facts extracted from a verified open transaction. */
export interface VerifyOpenTxResult {
    /** Payment-channel address derived from the open instruction (base58). */
    readonly channelId: string;
    /** Deposit locked by the open, in base units. */
    readonly deposit: bigint;
    /** Close grace period in seconds. */
    readonly gracePeriod: number;
    /**
     * Channel payer (open account 0, base58): the deposit funder and the
     * distribute refund destination (the program enforces it equals
     * `channel.payer`).
     */
    readonly payer: string;
    /** Channel-derivation salt. */
    readonly salt: bigint;
}

/**
 * Decode and validate the client-submitted open transaction.
 *
 * Accepts both legacy and v0 transaction encodings (the Rust client emits
 * legacy; the TS client emits v0).
 *
 * Asserts the embedded Open IX targets the configured payment-channels
 * program, that `payee == expected.recipient`, that the mint matches the
 * challenge currency/network, that `deposit <= maxCap`, and that the
 * channel PDA matches the recomputed value.
 *
 * When the payload carries a non-placeholder `signature`, it must equal
 * the transaction's own first signature — a client must not be able to
 * pair unrelated (but confirmed) signatures with different transaction
 * bytes. If `rpc` is provided, that signature is also sanity-checked via
 * `getSignatureStatuses`. When the transaction is still partially-signed
 * (signature placeholder), neither check is made.
 */
export async function verifyOpenTx(args: VerifyOpenTxArgs): Promise<VerifyOpenTxResult> {
    const { openPayload, expected } = args;
    if (!openPayload.transaction) {
        throw new Error('openPayload.transaction is required for push-mode open verification');
    }

    const txBytes = getBase64Codec().encode(openPayload.transaction);
    const decoded = getTransactionDecoder().decode(txBytes);
    // The kit compiled-message decoder dispatches on the version prefix
    // byte, so legacy and v0 messages both decode to this shape.
    const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as {
        addressTableLookups?: readonly unknown[] | undefined;
        instructions: readonly {
            accountIndices?: readonly number[];
            data?: Uint8Array | undefined;
            programAddressIndex: number;
        }[];
        staticAccounts: readonly string[];
        version: number | 'legacy';
    };

    // Reject any versioned message beyond legacy/v0 before touching
    // `.instructions` / `.addressTableLookups`. A v1 message decodes to a shape
    // carrying neither, so the ALT guard below would be silently skipped and
    // the instruction loop would crash with a TypeError on hostile input.
    assertLegacyOrV0Message(message.version, 'verifyOpenTx');

    // Reject address-lookup tables. The operator co-signs the open as fee
    // payer, and every account this verifier inspects (payer, rentPayer,
    // payee, mint, authorizedSigner, channel) must be a *static* account it
    // can read directly — an ALT-resolved account is opaque here and would
    // let a client smuggle a different account past the slot checks. Mirrors
    // the x402 svm `verifyOpenTransaction` ALT guard.
    if (message.addressTableLookups && message.addressTableLookups.length > 0) {
        throw new Error(
            'verifyOpenTx: address-lookup tables are not permitted in an open transaction — all accounts must be static',
        );
    }

    // Bind the claimed signature to this transaction (see doc comment).
    if (openPayload.signature && !isPlaceholderSignature(openPayload.signature)) {
        const feePayer = message.staticAccounts[0];
        const signatures = decoded.signatures as Readonly<Record<string, Uint8Array | null>>;
        const firstSignature = feePayer === undefined ? undefined : signatures[feePayer];
        if (!firstSignature || firstSignature.every(byte => byte === 0)) {
            throw new Error(
                'verifyOpenTx: openPayload.signature is set but the transaction carries no fee-payer signature',
            );
        }
        const txSignature = getBase58Decoder().decode(firstSignature);
        if (txSignature !== openPayload.signature) {
            throw new Error(
                `verifyOpenTx: openPayload.signature ${openPayload.signature} != transaction signature ${txSignature}`,
            );
        }
    }

    const programIdStr = expected.programId ?? PAYMENT_CHANNELS_PROGRAM_ID;
    const expectedMint =
        expected.mint ?? resolveStablecoinMint(expected.currency, expected.network ?? 'mainnet') ?? expected.currency;
    if (!expectedMint) {
        throw new Error('verifyOpenTx: could not resolve mint from currency/network');
    }

    let openIx: { accountIndices: readonly number[]; data: Uint8Array } | undefined;
    for (const ix of message.instructions) {
        const programIxAddr = message.staticAccounts[ix.programAddressIndex];
        if (programIxAddr !== programIdStr) continue;
        // Some decoders omit `data` entirely for empty instruction data.
        if (!ix.data || ix.data.length < 1) continue;
        if (ix.data[0] !== OPEN_DISCRIMINATOR) continue;
        openIx = { accountIndices: ix.accountIndices ?? [], data: ix.data };
        break;
    }
    if (!openIx) {
        throw new Error('verifyOpenTx: no payment-channels open instruction found');
    }

    // open instruction account layout (matches vendored open.ts) after the
    // rentPayer (+1) shift:
    //   0 payer, 1 rentPayer, 2 payee, 3 mint, 4 authorizedSigner, 5 channel,
    //   6 payerTokenAccount, 7 channelTokenAccount, 8 tokenProgram, …
    // rentPayer (slot 1) is pinned to the operator / fee payer.
    const indices = openIx.accountIndices;
    if (indices.length < 8) {
        throw new Error(`verifyOpenTx: open instruction has too few accounts (${indices.length})`);
    }
    const accountAt = (slot: number, label: string): string => {
        const idx = indices[slot];
        const addr = idx === undefined ? undefined : message.staticAccounts[idx];
        if (!addr) throw new Error(`verifyOpenTx: missing account at slot ${slot} (${label})`);
        return addr;
    };
    const payerAddr = accountAt(0, 'payer');
    const rentPayerAddr = accountAt(1, 'rentPayer');
    const payeeAddr = accountAt(2, 'payee');
    const mintAddr = accountAt(3, 'mint');
    const authorizedSignerAddr = accountAt(4, 'authorizedSigner');
    const channelAddr = accountAt(5, 'channel');

    if (payeeAddr !== expected.recipient) {
        throw new Error(`verifyOpenTx: payee ${payeeAddr} != expected recipient ${expected.recipient}`);
    }
    if (mintAddr !== expectedMint) {
        throw new Error(`verifyOpenTx: mint ${mintAddr} != expected mint ${expectedMint}`);
    }
    if (authorizedSignerAddr !== expected.authorizedSigner) {
        throw new Error(
            `verifyOpenTx: authorizedSigner ${authorizedSignerAddr} != expected ${expected.authorizedSigner}`,
        );
    }
    if (!expected.operator) {
        throw new Error('verifyOpenTx: expected.operator (the channel rentPayer) is required');
    }
    if (rentPayerAddr !== expected.operator) {
        throw new Error(`verifyOpenTx: rentPayer ${rentPayerAddr} != expected operator ${expected.operator}`);
    }

    // ix data: [discriminator u8][salt u64][deposit u64][grace u32][recipients array]
    if (openIx.data.length < 1 + 8 + 8 + 4) {
        throw new Error('verifyOpenTx: open instruction data too short');
    }
    const view = new DataView(openIx.data.buffer, openIx.data.byteOffset, openIx.data.byteLength);
    const salt = view.getBigUint64(1, true);
    const deposit = view.getBigUint64(9, true);
    const gracePeriod = view.getUint32(17, true);

    if (deposit === 0n) {
        throw new Error('verifyOpenTx: deposit must be greater than zero');
    }
    if (deposit > expected.maxCap) {
        throw new Error(`verifyOpenTx: deposit ${deposit} exceeds maxCap ${expected.maxCap}`);
    }

    // Re-derive the channel PDA and assert it matches.
    const programAddress = programIdStr as Address;
    const [derivedChannel] = await getProgramDerivedAddress({
        programAddress,
        seeds: [
            getUtf8Encoder().encode('channel'),
            getAddressEncoder().encode(address(payerAddr)),
            getAddressEncoder().encode(address(payeeAddr)),
            getAddressEncoder().encode(address(mintAddr)),
            getAddressEncoder().encode(address(authorizedSignerAddr)),
            getU64Encoder().encode(salt),
        ],
    });
    if (derivedChannel !== channelAddr) {
        throw new Error(`verifyOpenTx: channel PDA ${channelAddr} != derived ${derivedChannel}`);
    }
    if (openPayload.channelId && openPayload.channelId !== channelAddr) {
        throw new Error(`verifyOpenTx: openPayload.channelId ${openPayload.channelId} != tx channel ${channelAddr}`);
    }

    // Optional liveness check — only when caller provides an RPC and the
    // client has already populated the tx signature (push mode).
    if (args.rpc && openPayload.signature && !isPlaceholderSignature(openPayload.signature)) {
        const [status] = (await args.rpc.getSignatureStatuses([openPayload.signature as Signature]).send()).value;
        if (!status) {
            throw new Error(`verifyOpenTx: tx ${openPayload.signature} not found on-chain`);
        }
        if (status.err) {
            throw new Error(`verifyOpenTx: tx ${openPayload.signature} failed on-chain: ${JSON.stringify(status.err)}`);
        }
    }

    return { channelId: channelAddr, deposit, gracePeriod, payer: payerAddr, salt };
}

// ─────────────────────────────────────────────────────────────────────
// verifyTopUpTx: fetch a top-up tx by signature and validate the IX
// ─────────────────────────────────────────────────────────────────────

/** Minimal RPC shape needed to fetch a confirmed transaction by signature. */
export interface GetTransactionRpc {
    getTransaction(
        signature: Signature,
        config?: unknown,
    ): {
        send(): Promise<{
            meta?: { readonly err: unknown } | null | undefined;
            transaction: unknown;
        } | null>;
    };
}

/** Narrow an arbitrary RPC-ish object to {@link GetTransactionRpc}. */
export function isGetTransactionRpc(rpc: unknown): rpc is GetTransactionRpc {
    return typeof rpc === 'object' && rpc !== null && typeof (rpc as GetTransactionRpc).getTransaction === 'function';
}

/**
 * Fetch a landed transaction's base64 wire bytes by signature. Throws if
 * the transaction is unknown, failed on-chain, or the RPC answers with a
 * non-base64 encoding.
 */
export async function fetchTransactionBase64(
    rpc: GetTransactionRpc,
    signature: string,
    context: string,
): Promise<string> {
    const response = await rpc
        .getTransaction(signature as Signature, {
            commitment: 'confirmed',
            encoding: 'base64',
            maxSupportedTransactionVersion: 0,
        })
        .send();
    if (!response) {
        throw new Error(`${context}: tx ${signature} not found on-chain`);
    }
    if (response.meta?.err) {
        throw new Error(`${context}: tx ${signature} failed on-chain: ${JSON.stringify(response.meta.err)}`);
    }

    // `encoding: 'base64'` responses carry a `[data, 'base64']` tuple; be
    // lenient about a bare string but reject anything else (e.g. a
    // jsonParsed shape) rather than guess at its account ordering.
    const raw = response.transaction;
    const transactionBase64 = Array.isArray(raw) ? (raw[0] as unknown) : raw;
    if (typeof transactionBase64 !== 'string') {
        throw new Error(`${context}: unsupported getTransaction encoding (expected base64)`);
    }
    return transactionBase64;
}

/** Expected channel facts a top-up transaction must be bound to. */
export interface VerifyTopUpTxExpected {
    /** Exact deposit increase (`newDeposit - currentDeposit`), base units. */
    readonly amountDelta: bigint;
    /** Payment-channel address (base58) the top_up must target. */
    readonly channelId: string;
    readonly mint: string;
    /** Channel payer (base58) recorded at open. Checked when set. */
    readonly payer?: string | undefined;
    /** Optional override for the payment-channels program id. */
    readonly programId?: string | undefined;
    readonly tokenProgram: string;
}

/** Arguments to {@link verifyTopUpTx}. */
export interface VerifyTopUpTxArgs {
    /** Expected values from the stored channel + session config. */
    readonly expected: VerifyTopUpTxExpected;
    readonly rpc: GetTransactionRpc;
    /** Signature of the already-broadcast top-up transaction (base58). */
    readonly signature: string;
}

/**
 * Fetch the transaction behind a client-asserted top-up signature and
 * verify it actually contains a payment-channels `top_up` instruction
 * bound to the expected channel / mint / token program / amount delta.
 *
 * A bare `{channelId, newDeposit, signature}` top-up payload carries no
 * transaction bytes, so a liveness check alone would accept ANY
 * successful signature — including one for an unrelated transaction —
 * and let a client inflate its deposit for free. Mirrors the
 * decode-and-bind pattern of {@link verifyOpenTx}, with the transaction
 * bytes fetched via `getTransaction` instead of read from the payload.
 */
export async function verifyTopUpTx(args: VerifyTopUpTxArgs): Promise<void> {
    const { expected } = args;
    const transactionBase64 = await fetchTransactionBase64(args.rpc, args.signature, 'verifyTopUpTx');

    const decoded = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as {
        addressTableLookups?: readonly unknown[] | undefined;
        instructions: readonly {
            accountIndices?: readonly number[];
            data?: Uint8Array | undefined;
            programAddressIndex: number;
        }[];
        staticAccounts: readonly string[];
        version: number | 'legacy';
    };

    // Same version guard as verifyOpenTx: reject a v1+ message before the ALT
    // guard and instruction loop, which both assume the legacy/v0 field shape.
    assertLegacyOrV0Message(message.version, 'verifyTopUpTx');

    // Same ALT guard as verifyOpenTx: every account this verifier inspects
    // must be static, or a client could smuggle a different account past
    // the slot checks via a lookup table.
    if (message.addressTableLookups && message.addressTableLookups.length > 0) {
        throw new Error(
            'verifyTopUpTx: address-lookup tables are not permitted in a top-up transaction — all accounts must be static',
        );
    }

    const programIdStr = expected.programId ?? PAYMENT_CHANNELS_PROGRAM_ID;
    let topUpIx: { accountIndices: readonly number[]; data: Uint8Array } | undefined;
    for (const ix of message.instructions) {
        const programIxAddr = message.staticAccounts[ix.programAddressIndex];
        if (programIxAddr !== programIdStr) continue;
        if (!ix.data || ix.data.length < 1) continue;
        if (ix.data[0] !== TOP_UP_DISCRIMINATOR) continue;
        topUpIx = { accountIndices: ix.accountIndices ?? [], data: ix.data };
        break;
    }
    if (!topUpIx) {
        throw new Error('verifyTopUpTx: no payment-channels top_up instruction found');
    }

    // top_up instruction account layout (matches vendored topUp.ts):
    //   0 payer, 1 channel, 2 payerTokenAccount, 3 channelTokenAccount,
    //   4 mint, 5 tokenProgram
    const indices = topUpIx.accountIndices;
    if (indices.length < 6) {
        throw new Error(`verifyTopUpTx: top_up instruction has too few accounts (${indices.length})`);
    }
    const accountAt = (slot: number, label: string): string => {
        const idx = indices[slot];
        const addr = idx === undefined ? undefined : message.staticAccounts[idx];
        if (!addr) throw new Error(`verifyTopUpTx: missing account at slot ${slot} (${label})`);
        return addr;
    };
    const payerAddr = accountAt(0, 'payer');
    const channelAddr = accountAt(1, 'channel');
    const mintAddr = accountAt(4, 'mint');
    const tokenProgramAddr = accountAt(5, 'tokenProgram');

    if (channelAddr !== expected.channelId) {
        throw new Error(`verifyTopUpTx: channel ${channelAddr} != expected ${expected.channelId}`);
    }
    if (mintAddr !== expected.mint) {
        throw new Error(`verifyTopUpTx: mint ${mintAddr} != expected ${expected.mint}`);
    }
    if (tokenProgramAddr !== expected.tokenProgram) {
        throw new Error(`verifyTopUpTx: tokenProgram ${tokenProgramAddr} != expected ${expected.tokenProgram}`);
    }
    if (expected.payer !== undefined && payerAddr !== expected.payer) {
        throw new Error(`verifyTopUpTx: payer ${payerAddr} != channel payer ${expected.payer}`);
    }

    // ix data: [discriminator u8][amount u64 LE]
    if (topUpIx.data.length < 1 + 8) {
        throw new Error('verifyTopUpTx: top_up instruction data too short');
    }
    const view = new DataView(topUpIx.data.buffer, topUpIx.data.byteOffset, topUpIx.data.byteLength);
    const amount = view.getBigUint64(1, true);
    if (expected.amountDelta <= 0n || amount !== expected.amountDelta) {
        throw new Error(`verifyTopUpTx: top_up amount ${amount} != expected deposit delta ${expected.amountDelta}`);
    }
}

// ─────────────────────────────────────────────────────────────────────
// verifyChannelAccountState: decode the on-chain Channel and bind its
// fields — defense-in-depth on top of the instruction-level binding.
// ─────────────────────────────────────────────────────────────────────

/** Minimal RPC shape needed to fetch an account by address. */
export interface GetAccountInfoRpc {
    getAccountInfo(
        address: Address,
        config?: unknown,
    ): {
        send(): Promise<{
            value: { readonly data?: unknown; readonly owner?: string } | null;
        }>;
    };
}

/** Narrow an arbitrary RPC-ish object to {@link GetAccountInfoRpc}. */
export function isGetAccountInfoRpc(rpc: unknown): rpc is GetAccountInfoRpc {
    return typeof rpc === 'object' && rpc !== null && typeof (rpc as GetAccountInfoRpc).getAccountInfo === 'function';
}

/** Expected on-chain Channel fields, checked against the decoded account. */
export interface VerifyChannelStateExpected {
    readonly authorizedSigner: string;
    /**
     * Expected `deposit` on the decoded channel. For a fresh open this is the
     * open deposit; for a top-up it is the RAISED deposit (`newDeposit`) — the
     * on-chain account must actually reflect it, not just contain a top_up
     * instruction with the right delta.
     */
    readonly deposit: bigint;
    readonly mint: string;
    readonly payee: string;
    /** Channel payer (base58). Checked when set. */
    readonly payer?: string | undefined;
    /** Payment-channels program id the account must be owned by. */
    readonly programId?: string | undefined;
}

/**
 * Fetch the on-chain Channel account and assert its decoded fields match
 * what the session expects. The instruction-level binding
 * ({@link verifyOpenTx} / {@link verifyTopUpTx}) proves the transaction
 * *contained* a valid open/top_up; this proves the resulting *account
 * state* on-chain is what the server is about to trust — catching a
 * channel that was closed, re-opened with different authority, or whose
 * deposit diverges from the asserted amount (e.g. a racing top-up).
 *
 * The account MUST be owned by the payment-channels program, so a
 * look-alike account crafted under a different program cannot satisfy
 * the field checks via forged bytes.
 */
export async function verifyChannelAccountState(args: {
    readonly channelId: string;
    readonly expected: VerifyChannelStateExpected;
    readonly rpc: GetAccountInfoRpc;
}): Promise<void> {
    const { expected } = args;
    const info = await args.rpc
        .getAccountInfo(address(args.channelId), { commitment: 'confirmed', encoding: 'base64' })
        .send();
    const value = info.value;
    if (!value) {
        throw new Error(`verifyChannelAccountState: channel ${args.channelId} not found on-chain`);
    }

    const programIdStr = expected.programId ?? PAYMENT_CHANNELS_PROGRAM_ID;
    if (value.owner !== undefined && value.owner !== programIdStr) {
        throw new Error(
            `verifyChannelAccountState: channel ${args.channelId} is owned by ${value.owner} != payment-channels program ${programIdStr}`,
        );
    }

    // `encoding: 'base64'` account data is a `[data, 'base64']` tuple.
    const raw = value.data;
    const dataBase64 = Array.isArray(raw) ? (raw[0] as unknown) : raw;
    if (typeof dataBase64 !== 'string' || dataBase64 === '') {
        throw new Error('verifyChannelAccountState: unsupported getAccountInfo encoding (expected base64)');
    }
    const channel = getChannelDecoder().decode(getBase64Codec().encode(dataBase64));

    // The channel must still be open. A finalized/closing channel that happens
    // to match the other pinned fields must not be trusted as live session
    // state. Mirrors Go (session_onchain.go), Python (upto.py), and Rust
    // (upto.rs), which all enforce status == open after decoding the account.
    // The generated decoder types `status` as a raw u8, so compare against the
    // enum's numeric value rather than the enum member itself.
    const openStatus: number = ChannelStatus.Open;
    if (channel.status !== openStatus) {
        throw new Error(
            `verifyChannelAccountState: on-chain channel ${args.channelId} status ${channel.status} != open (${openStatus})`,
        );
    }

    if (channel.payee !== expected.payee) {
        throw new Error(`verifyChannelAccountState: on-chain payee ${channel.payee} != expected ${expected.payee}`);
    }
    if (channel.mint !== expected.mint) {
        throw new Error(`verifyChannelAccountState: on-chain mint ${channel.mint} != expected ${expected.mint}`);
    }
    if (channel.authorizedSigner !== expected.authorizedSigner) {
        throw new Error(
            `verifyChannelAccountState: on-chain authorizedSigner ${channel.authorizedSigner} != expected ${expected.authorizedSigner}`,
        );
    }
    if (channel.deposit !== expected.deposit) {
        throw new Error(
            `verifyChannelAccountState: on-chain deposit ${channel.deposit} != expected ${expected.deposit}`,
        );
    }
    if (expected.payer !== undefined && channel.payer !== expected.payer) {
        throw new Error(`verifyChannelAccountState: on-chain payer ${channel.payer} != expected ${expected.payer}`);
    }
}

/** Tuning knobs for {@link waitForSignatureConfirmation}. */
export interface ConfirmSignatureOptions {
    /** Delay between status polls in ms. Defaults to 1_000. */
    readonly pollIntervalMs?: number | undefined;
    /** Optional abort signal to cancel the wait early. */
    readonly signal?: AbortSignal | undefined;
    /** Total time budget in ms. Defaults to 30_000. */
    readonly timeoutMs?: number | undefined;
}

/**
 * Poll `getSignatureStatuses` until `signature` reaches at least
 * 'confirmed' commitment. Throws if the transaction failed on-chain, the
 * abort signal fires, or the timeout elapses before confirmation.
 */
export async function waitForSignatureConfirmation(args: {
    readonly context?: string | undefined;
    readonly options?: ConfirmSignatureOptions | undefined;
    readonly rpc: SignatureStatusRpc;
    readonly signature: Signature;
}): Promise<void> {
    const context = args.context ?? 'waitForSignatureConfirmation';
    const timeoutMs = args.options?.timeoutMs ?? 30_000;
    const pollIntervalMs = args.options?.pollIntervalMs ?? 1_000;
    const deadline = Date.now() + timeoutMs;

    for (;;) {
        if (args.options?.signal?.aborted) {
            throw new Error(`${context}: aborted while waiting for tx ${args.signature} confirmation`);
        }
        const [status] = (await args.rpc.getSignatureStatuses([args.signature]).send()).value;
        if (status) {
            if (status.err) {
                throw new Error(`${context}: tx ${args.signature} failed on-chain: ${JSON.stringify(status.err)}`);
            }
            const level = status.confirmationStatus;
            // RPC endpoints that omit confirmationStatus only report a
            // status once the tx landed — treat that as confirmed.
            if (level === undefined || level === null || level === 'confirmed' || level === 'finalized') {
                return;
            }
        }
        if (Date.now() >= deadline) {
            throw new Error(`${context}: timed out waiting for tx ${args.signature} confirmation`);
        }
        await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
    }
}

/**
 * Server-submits-open flow: validates the client-submitted tx, broadcasts
 * it via the supplied RPC, then waits for the signature to reach at least
 * 'confirmed' before returning — callers must not persist channel state
 * for a transaction that never landed.
 */
export interface SubmitOpenTxArgs extends VerifyOpenTxArgs {
    /** Confirmation polling overrides (timeout, poll interval, abort). */
    readonly confirm?: ConfirmSignatureOptions | undefined;
    /**
     * Server-side fee-payer signer. When the client built the open
     * transaction with the operator as fee payer (and a placeholder where
     * the operator's signature belongs), this signer completes the
     * signature before broadcast.
     */
    readonly payerSigner?: TransactionPartialSigner | undefined;
    readonly rpc: SignatureStatusRpc & {
        sendTransaction: (wire: string, config?: unknown) => { send: () => Promise<Signature> };
    };
}

/** Result of a server-submitted open: the verified channel facts plus the broadcast signature. */
export interface SubmitOpenTxResult extends VerifyOpenTxResult {
    /** Signature of the broadcast open transaction. */
    readonly signature: Signature;
}

/**
 * Verifies a client-built open transaction, broadcasts it, and waits for
 * confirmation. Used when the session is configured with
 * `openTxSubmitter: 'server'`.
 */
export async function submitOpenTx(args: SubmitOpenTxArgs): Promise<SubmitOpenTxResult> {
    const verified = await verifyOpenTx(args);
    if (!args.openPayload.transaction) {
        throw new Error('submitOpenTx: openPayload.transaction is required');
    }
    let wire = args.openPayload.transaction;
    if (args.payerSigner) {
        const decoded = getTransactionDecoder().decode(getBase64Codec().encode(wire));
        if (decoded.signatures[args.payerSigner.address] !== undefined) {
            wire = await coSignBase64Transaction(args.payerSigner, wire);
        }
    }
    const signature = await args.rpc.sendTransaction(wire, { encoding: 'base64', skipPreflight: false }).send();
    await waitForSignatureConfirmation({
        context: 'submitOpenTx',
        options: args.confirm,
        rpc: args.rpc,
        signature,
    });
    return { ...verified, signature };
}

// ─────────────────────────────────────────────────────────────────────
// submitSettleAndDistribute: convenience wrapper
// ─────────────────────────────────────────────────────────────────────

/** Arguments to {@link submitSettleAndDistribute}. */
export interface SubmitSettleAndDistributeArgs {
    /**
     * Caller-provided transaction builder — keeping this module RPC-free
     * for now keeps tests deterministic. The caller composes the
     * instructions into a transaction, signs it, encodes as base64, and
     * returns the wire bytes. Phase F surfpool integration will replace
     * this with a real pipe/sign call.
     */
    readonly buildAndSignWireTransaction: (instructions: readonly ServerInstruction[]) => Promise<string>;
    readonly channelId: string;
    readonly currency?: string | undefined;
    readonly mint: string;
    readonly network?: string | undefined;
    readonly payee: string;
    readonly payer: string;
    readonly programId?: Address | undefined;
    /**
     * Operator recorded as `rentPayer` at open; it reclaims the channel/escrow
     * rent at finalize. Required (no payer fallback).
     */
    readonly rentPayer: string;
    readonly rpc: {
        sendTransaction: (wire: string, config?: unknown) => { send: () => Promise<Signature> };
    };
    readonly signer: TransactionSigner;
    readonly splits: readonly { readonly bps: number; readonly recipient: string }[];
    readonly tokenProgram?: string | undefined;
    readonly voucher?:
        | {
              readonly authorizedSigner: string;
              readonly signed: SignedVoucher;
          }
        | undefined;
}

/** Result of a settle-and-distribute submission. */
export interface SubmitSettleAndDistributeResult {
    /** Instructions that were composed into the transaction. */
    readonly instructions: readonly ServerInstruction[];
    /** Signature of the broadcast transaction. */
    readonly signature: Signature;
}

/**
 * Build settle_and_finalize (+ optional Ed25519 precompile) + distribute
 * instructions and submit them as a single transaction. Designed for
 * push-mode close — the caller supplies a signing closure so the actual
 * compile/sign step stays out of this module's surface.
 */
export async function submitSettleAndDistribute(
    args: SubmitSettleAndDistributeArgs,
): Promise<SubmitSettleAndDistributeResult> {
    const tokenProgram =
        args.tokenProgram ?? (args.currency ? defaultTokenProgramForCurrency(args.currency, args.network) : undefined);
    if (!tokenProgram) {
        throw new Error('submitSettleAndDistribute: tokenProgram or currency is required');
    }

    const settle = buildSettleAndFinalizeInstructions({
        channelId: args.channelId,
        merchantSigner: args.signer,
        programId: args.programId,
        voucher: args.voucher,
    });

    const distribute = await buildDistributeInstruction({
        channelState: { channelId: args.channelId, payee: args.payee, payer: args.payer },
        mint: args.mint,
        payerAddr: args.payer,
        programId: args.programId,
        rentPayer: args.rentPayer,
        splits: args.splits,
        tokenProgram,
    });

    const instructions: ServerInstruction[] = [...settle.instructions, distribute];
    const wire = await args.buildAndSignWireTransaction(instructions);
    const signature = await args.rpc.sendTransaction(wire, { encoding: 'base64' }).send();
    return { instructions, signature };
}

// ─────────────────────────────────────────────────────────────────────
// multi-delegator (OperatedVoucher pull parity)
// ─────────────────────────────────────────────────────────────────────
//
// The upstream multi-delegator TS client uses an older generator with a
// different `program-client-core` import path; hand-encoding the two
// instructions we need keeps the dep list small and matches the byte
// layout in `rust/crates/mpp/src/program/multi_delegator.rs`.

/** PDA seed for the multi-delegate account (mirrors the Rust program). */
export const MULTI_DELEGATE_SEED = 'MultiDelegate';
/** PDA seed for per-operator delegation accounts (mirrors the Rust program). */
export const DELEGATION_SEED = 'delegation';

export async function findMultiDelegatePda(args: {
    readonly mint: string;
    readonly programId?: Address | undefined;
    readonly user: string;
}): Promise<Address> {
    const programAddress = args.programId ?? MULTI_DELEGATOR_PROGRAM_ID;
    const [pda] = await getProgramDerivedAddress({
        programAddress,
        seeds: [
            getUtf8Encoder().encode(MULTI_DELEGATE_SEED),
            getAddressEncoder().encode(address(args.user)),
            getAddressEncoder().encode(address(args.mint)),
        ],
    });
    return pda;
}

export async function findFixedDelegationPda(args: {
    readonly delegatee: string;
    readonly delegator: string;
    readonly multiDelegate: string;
    readonly nonce: bigint;
    readonly programId?: Address | undefined;
}): Promise<Address> {
    const programAddress = args.programId ?? MULTI_DELEGATOR_PROGRAM_ID;
    const [pda] = await getProgramDerivedAddress({
        programAddress,
        seeds: [
            getUtf8Encoder().encode(DELEGATION_SEED),
            getAddressEncoder().encode(address(args.multiDelegate)),
            getAddressEncoder().encode(address(args.delegator)),
            getAddressEncoder().encode(address(args.delegatee)),
            getU64Encoder().encode(args.nonce),
        ],
    });
    return pda;
}

/** RPC shape needed by {@link submitInitMultiDelegateTxIfMissing}. */
export interface MultiDelegateSubmitRpc extends SignatureStatusRpc {
    getAccountInfo(address: Address, config?: unknown): { send(): Promise<{ value: unknown }> };
    sendTransaction(wire: string, config?: unknown): { send(): Promise<Signature> };
}

/**
 * Idempotently submit a client-pre-signed `InitMultiDelegate` (+ initial
 * `CreateFixedDelegation`) transaction: the MultiDelegate PDA for
 * (owner, mint) is checked first via RPC and the transaction is only
 * broadcast when the PDA does not exist yet. Returns the submission
 * signature, or `undefined` when the PDA already exists.
 */
export async function submitInitMultiDelegateTxIfMissing(args: {
    readonly confirm?: ConfirmSignatureOptions | undefined;
    readonly initMultiDelegateTx: string;
    readonly mint: string;
    readonly owner: string;
    readonly programId?: Address | undefined;
    readonly rpc: MultiDelegateSubmitRpc;
}): Promise<Signature | undefined> {
    const pda = await findMultiDelegatePda({
        mint: args.mint,
        programId: args.programId,
        user: args.owner,
    });
    const info = await args.rpc.getAccountInfo(pda, { encoding: 'base64' }).send();
    if (info.value) return undefined;

    const signature = await args.rpc
        .sendTransaction(args.initMultiDelegateTx, { encoding: 'base64', skipPreflight: false })
        .send();
    await waitForSignatureConfirmation({
        context: 'initMultiDelegateTx',
        options: args.confirm,
        rpc: args.rpc,
        signature,
    });
    return signature;
}

export interface MultiDelegatorInitArgs {
    readonly mint: string;
    readonly programId?: Address | undefined;
    readonly tokenProgram: string;
    readonly user: TransactionSigner;
    readonly userAta: string;
}

/**
 * Hand-encoded `InitMultiDelegate` instruction (disc = 0x00).
 *
 * Accounts: `[user (signer/write), multiDelegate (write, derived),
 * tokenMint (read), userAta (write), systemProgram (read), tokenProgram
 * (read)]`. Matches Rust `build_init_multi_delegate_ix` in
 * `program/multi_delegator.rs`.
 */
export async function buildMultiDelegatorInitInstruction(args: MultiDelegatorInitArgs): Promise<ServerInstruction> {
    const programAddress = args.programId ?? MULTI_DELEGATOR_PROGRAM_ID;
    const multiDelegate = await findMultiDelegatePda({
        mint: args.mint,
        programId: programAddress,
        user: args.user.address,
    });
    const data = new Uint8Array([0x00]);
    return {
        accounts: [
            { address: args.user.address, role: AccountRole.WRITABLE_SIGNER, signer: args.user },
            { address: multiDelegate, role: AccountRole.WRITABLE },
            { address: address(args.mint), role: AccountRole.READONLY },
            { address: address(args.userAta), role: AccountRole.WRITABLE },
            { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
            { address: address(args.tokenProgram), role: AccountRole.READONLY },
        ],
        data,
        programAddress,
    } as unknown as ServerInstruction;
}

export interface MultiDelegatorUpdateArgs {
    readonly amount: bigint;
    readonly delegatee: string;
    readonly delegator: TransactionSigner;
    /** Unix seconds, 0 = no expiry. */
    readonly expiryTs: bigint;
    readonly mint: string;
    readonly nonce: bigint;
    readonly programId?: Address | undefined;
}

/**
 * Hand-encoded `CreateFixedDelegation` instruction (disc = 0x01).
 *
 * Data: `[0x01] ++ nonce_le ++ amount_le ++ expiry_le` (25 bytes).
 * Accounts: `[delegator (signer/write), multiDelegate (read), delegationPda
 * (write), delegatee (read), systemProgram (read)]`. Matches Rust
 * `build_create_fixed_delegation_ix` in `program/multi_delegator.rs`.
 */
export async function buildMultiDelegatorUpdateInstruction(args: MultiDelegatorUpdateArgs): Promise<ServerInstruction> {
    const programAddress = args.programId ?? MULTI_DELEGATOR_PROGRAM_ID;
    const multiDelegate = await findMultiDelegatePda({
        mint: args.mint,
        programId: programAddress,
        user: args.delegator.address,
    });
    const delegationPda = await findFixedDelegationPda({
        delegatee: args.delegatee,
        delegator: args.delegator.address,
        multiDelegate,
        nonce: args.nonce,
        programId: programAddress,
    });

    const data = new Uint8Array(25);
    data[0] = 0x01;
    data.set(getU64Encoder().encode(args.nonce) as Uint8Array, 1);
    data.set(getU64Encoder().encode(args.amount) as Uint8Array, 9);
    data.set(getI64Encoder().encode(args.expiryTs) as Uint8Array, 17);

    return {
        accounts: [
            { address: args.delegator.address, role: AccountRole.WRITABLE_SIGNER, signer: args.delegator },
            { address: multiDelegate, role: AccountRole.READONLY },
            { address: delegationPda, role: AccountRole.WRITABLE },
            { address: address(args.delegatee), role: AccountRole.READONLY },
            { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
        ],
        data,
        programAddress,
    } as unknown as ServerInstruction;
}

// ─────────────────────────────────────────────────────────────────────
// internals
// ─────────────────────────────────────────────────────────────────────

const SYSTEM_PROGRAM_ADDRESS = '11111111111111111111111111111111' as Address<'11111111111111111111111111111111'>;

function isPlaceholderSignature(sig: string): boolean {
    // The pending placeholder produced by `createServerOpenedPaymentChannelSessionOpener`.
    return sig.length === 0 || /^1{40,}$/.test(sig);
}

function deriveTreasuryAddress(): Address {
    return getBase58FromBytes(TREASURY_OWNER_BYTES);
}

function getBase58FromBytes(bytes: Uint8Array): Address {
    // base58 of a fixed-pattern 32-byte address; encode via a small library-free path.
    return bytesToBase58(bytes) as Address;
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function bytesToBase58(bytes: Uint8Array): string {
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    // Convert big-endian byte array to base58 digits.
    const digits = [0];
    for (let i = zeros; i < bytes.length; i++) {
        let carry = bytes[i] ?? 0;
        for (let j = 0; j < digits.length; j++) {
            carry += (digits[j] ?? 0) << 8;
            digits[j] = carry % 58;
            carry = (carry / 58) | 0;
        }
        while (carry > 0) {
            digits.push(carry % 58);
            carry = (carry / 58) | 0;
        }
    }
    let out = '';
    for (let i = 0; i < zeros; i++) out += '1';
    for (let i = digits.length - 1; i >= 0; i--) {
        const ch = BASE58_ALPHABET[digits[i] ?? 0];
        out += ch ?? '1';
    }
    return out;
}

function parseU64String(value: string, name: string): bigint {
    if (!/^\d+$/.test(value)) throw new Error(`${name} is not an unsigned integer string: ${value}`);
    const parsed = BigInt(value);
    if (parsed < 0n || parsed > (1n << 64n) - 1n) throw new Error(`${name} outside u64 range`);
    return parsed;
}

function toBigInt(value: bigint | number | string): bigint {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) throw new Error(`value ${value} is not a safe integer`);
        return BigInt(value);
    }
    return BigInt(value);
}

export { ASSOCIATED_TOKEN_PROGRAM, SYSTEM_PROGRAM_ADDRESS };
