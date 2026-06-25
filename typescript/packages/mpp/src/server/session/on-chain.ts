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
import { getDistributeInstruction } from '../../generated/payment-channels/instructions/distribute.js';
import { getSettleAndFinalizeInstruction } from '../../generated/payment-channels/instructions/settleAndFinalize.js';
import { getTopUpInstruction } from '../../generated/payment-channels/instructions/topUp.js';
import { findEventAuthorityPda } from '../../generated/payment-channels/pdas/eventAuthority.js';
import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../../generated/payment-channels/programs/paymentChannels.js';
import type { OpenPayload, SignedVoucher } from '../../shared/session-types.js';
import { coSignBase64Transaction } from '../../utils/transactions.js';

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
        instructions: readonly {
            accountIndices?: readonly number[];
            data?: Uint8Array | undefined;
            programAddressIndex: number;
        }[];
        staticAccounts: readonly string[];
    };

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

    // open instruction account layout (matches vendored open.ts):
    //   0 payer, 1 payee, 2 mint, 3 authorizedSigner, 4 channel,
    //   5 payerTokenAccount, 6 channelTokenAccount, 7 tokenProgram, …
    const indices = openIx.accountIndices;
    if (indices.length < 7) {
        throw new Error(`verifyOpenTx: open instruction has too few accounts (${indices.length})`);
    }
    const accountAt = (slot: number, label: string): string => {
        const idx = indices[slot];
        const addr = idx === undefined ? undefined : message.staticAccounts[idx];
        if (!addr) throw new Error(`verifyOpenTx: missing account at slot ${slot} (${label})`);
        return addr;
    };
    const payerAddr = accountAt(0, 'payer');
    const payeeAddr = accountAt(1, 'payee');
    const mintAddr = accountAt(2, 'mint');
    const authorizedSignerAddr = accountAt(3, 'authorizedSigner');
    const channelAddr = accountAt(4, 'channel');

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

    return { channelId: channelAddr, deposit, gracePeriod, salt };
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
