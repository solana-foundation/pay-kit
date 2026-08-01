// Server-side on-chain operations for MPP sessions.
//
// Mirrors the on-chain helpers in
// `rust/crates/mpp/src/program/payment_channels.rs` and the orchestration
// in `rust/crates/mpp/src/server/session.rs`. Two responsibilities:
//
//   1. Build the exact instruction bytes the on-chain payment-channels
//      program expects (settle_and_seal, distribute, top_up, reclaim).
//   2. Verify client-submitted open transactions against the session
//      challenge before persisting channel state.
//
// All builders are pure functions — the only thing that touches the
// network is the optional submit* helpers, which the caller threads an
// RPC + signer through.

import {
    type AccountMeta,
    type Address,
    address,
    getAddressEncoder,
    getBase58Encoder,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getI64Encoder,
    getProgramDerivedAddress,
    getSignatureFromTransaction,
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
import { fetchChannel } from '../../generated/payment-channels/accounts/channel.js';
import { getDistributeInstruction } from '../../generated/payment-channels/instructions/distribute.js';
import { getOpenInstructionDataDecoder } from '../../generated/payment-channels/instructions/open.js';
import { getReclaimInstruction } from '../../generated/payment-channels/instructions/reclaim.js';
import { getSettleAndSealInstruction } from '../../generated/payment-channels/instructions/settleAndSeal.js';
import { getTopUpInstruction } from '../../generated/payment-channels/instructions/topUp.js';
import { getTopUpInstructionDataDecoder } from '../../generated/payment-channels/instructions/topUp.js';
import { findEventAuthorityPda } from '../../generated/payment-channels/pdas/eventAuthority.js';
import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../../generated/payment-channels/programs/paymentChannels.js';
import { ChannelStatus } from '../../generated/payment-channels/types/channelStatus.js';
import type { OpenPayload, SignedVoucher } from '../../shared/session-types.js';
import { VOUCHER_MAGIC } from '../../shared/voucher.js';
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

/**
 * On-chain freshness window (in slots, ~10 minutes) around a channel's
 * `openSlot`: the program rejects opens whose `openSlot` is in the future or
 * older than this many slots, and gates reclaim until the window has passed.
 * The server enforces the same window between the challenged `recentSlot`
 * and the payload's `openSlot` before broadcasting an open. Mirrors
 * `OPEN_SLOT_WINDOW` in `rust/crates/kit/src/core/payment_channels.rs`.
 */
export const OPEN_SLOT_WINDOW = 1_500n;

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
 * Build an Ed25519 verify precompile instruction over the 50-byte voucher
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
 * Encode the canonical 50-byte voucher payload (magic-prefixed). Identical
 * to `encodeVoucherMessage` in `shared/voucher.ts` but kept here so the
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
    const out = new Uint8Array(50);
    out.set(VOUCHER_MAGIC, 0);
    out.set(channelBytes as Uint8Array, 2);
    out.set(getU64Encoder().encode(args.cumulativeAmount) as Uint8Array, 34);
    out.set(getI64Encoder().encode(args.expiresAt) as Uint8Array, 42);
    return out;
}

// ─────────────────────────────────────────────────────────────────────
// settle_and_seal + distribute + top_up + reclaim
// ─────────────────────────────────────────────────────────────────────

/** Arguments to {@link buildSettleAndSealInstructions}. */
export interface SettleAndSealBuildArgs {
    /** Payment-channel address being settled (base58). */
    readonly channelId: string;
    /** Merchant signer authorized to settle the channel. */
    readonly merchantSigner: TransactionSigner;
    /** Payment-channels program id override. */
    readonly programId?: Address | undefined;
    /**
     * Optional final voucher. When present, an Ed25519 precompile IX is
     * prepended and `hasVoucher` is set to 1 on the settle_and_seal args.
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

/** Instructions produced for a settle_and_seal call. */
export interface SettleAndSealBuildResult {
    /** Instructions in submit order (Ed25519 precompile first when a voucher is settled). */
    readonly instructions: readonly ServerInstruction[];
    /** True when the transaction must carry the Ed25519 precompile instruction. */
    readonly requiresEd25519Precompile: boolean;
}

/**
 * Build the instruction(s) for an on-chain settle_and_seal. If a
 * voucher is provided, an Ed25519 precompile IX is prepended at index 0
 * — the settle_and_seal IX references the instructions sysvar at
 * index `-1` (i.e. the precompile immediately before it).
 */
export function buildSettleAndSealInstructions(args: SettleAndSealBuildArgs): SettleAndSealBuildResult {
    const programId = args.programId ?? PAYMENT_CHANNELS_PROGRAM_ID;
    const channel = address(args.channelId);
    const instructions: ServerInstruction[] = [];

    let cumulativeAmount = 0n;
    let expiresAt = 0n;
    let hasVoucher = 0;

    if (args.voucher) {
        const { signed, authorizedSigner } = args.voucher;
        cumulativeAmount = parseU64String(signed.voucher.cumulativeAmount, 'voucher.cumulativeAmount');
        expiresAt = toBigInt(signed.voucher.expiresAt ?? 0);
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
            channelId: signed.voucher.channelId,
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

    const ix = getSettleAndSealInstruction(
        {
            channel,
            instructionsSysvar: INSTRUCTIONS_SYSVAR_ADDRESS,
            // The channel payee (merchant) signs the seal.
            payee: args.merchantSigner,
            // The program reads the voucher from the ed25519 precompile; the
            // settle_and_seal args carry only the hasVoucher flag.
            settleAndSealArgs: { hasVoucher },
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
     * escrow ATA rent at distribute (writable, not a signer). Required — it
     * must match the rentPayer the channel stored, so there is no payer
     * fallback.
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
    // rentPayer reclaims the channel/escrow rent at distribute; it is the
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

/** Arguments to the reclaim instruction builder. */
export interface ReclaimBuildArgs {
    readonly channelId: string;
    readonly programId?: Address | undefined;
    /** Operator recorded as `rentPayer` at open; receives the channel PDA lamports. */
    readonly rentPayer: string;
}

/**
 * Build a reclaim instruction. Permissionless rent recovery for a channel
 * left in the `distributed` status: the program closes the channel PDA and
 * returns its lamports to `rentPayer` once `clock.slot > open_slot + 1500`.
 */
export function buildReclaimInstruction(args: ReclaimBuildArgs): ServerInstruction {
    const programId = args.programId ?? PAYMENT_CHANNELS_PROGRAM_ID;
    const ix = getReclaimInstruction(
        {
            channel: address(args.channelId),
            rentPayer: address(args.rentPayer),
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
    /** Optional override for the payment-channels program id. */
    readonly channelProgram?: string | undefined;
    readonly currency: string;
    /** Transaction fee payer required by the challenge policy. */
    readonly feePayer: string;
    readonly minimumDeposit?: bigint | undefined;
    /** Optional override for the SPL mint (otherwise resolved from currency/network). */
    readonly mint?: string | undefined;
    readonly network?: string | undefined;
    /**
     * Challenge-issued open slot. When set, the open instruction's `openSlot`
     * arg must equal it — the client is required to echo the slot the server
     * handed out in the 402 challenge.
     */
    readonly openSlot: bigint;
    /**
     * The challenged `methodDetails.recentBlockhash` (base58). The compiled
     * open message MUST use exactly this blockhash: it proves the transaction
     * was built for this challenge, not replayed from an older one the server
     * never authorized. Mirrors `SessionOpenContext::recent_blockhash` in
     * `rust/crates/kit/src/mpp/server/session.rs`.
     */
    readonly recentBlockhash: string;
    /** Primary recipient (challenge `recipient`). */
    readonly recipient: string;
    /**
     * Operator / fee-payer pubkey (base58) = the expected `rentPayer`. The open
     * instruction's `rentPayer` account (slot 1) must equal it (it is pinned to
     * the operator that co-signs open as fee payer while gasless). Required: the
     * rentPayer slot is a security boundary and is always checked.
     */
    readonly rentPayer: string;
    /**
     * Challenged distribution splits (the server's configured splits, echoed
     * in the 402 challenge). The open instruction's recipients must equal
     * exactly this list, in order: the open commits the on-chain
     * `distributionHash`, and `distribute` at settle is built from the
     * server's config — a client-substituted list would make the bundled
     * settleAndSeal+distribute revert and strand every voucher. Mirrors the
     * `payload_splits != self.config.splits` rejection in
     * `rust/crates/kit/src/mpp/server/session.rs`.
     */
    readonly splits: readonly { readonly recipient: string; readonly shareBps: number }[];
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
    /** Slot the open was built against (a channel PDA seed; gates reclaim). */
    readonly openSlot: bigint;
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
 * challenge currency/network, that the deposit and other declared open fields
 * match the instruction, and that the
 * channel PDA matches the recomputed value.
 *
 * Confirmation is performed by {@link submitOpenTx}; this function only
 * validates the transaction bytes before the server broadcasts them.
 */
export async function verifyOpenTx(args: VerifyOpenTxArgs): Promise<VerifyOpenTxResult> {
    const { openPayload, expected } = args;
    if (!openPayload.transaction) throw new Error('openPayload.transaction is required');

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
        lifetimeToken?: string | undefined;
        staticAccounts: readonly string[];
    };

    // The compiled message must use the challenged `recentBlockhash`: it
    // proves the transaction was built for this challenge, not replayed from
    // an older one the server never authorized. Mirrors
    // `verify_submit_and_fetch_open` in the Rust SessionServer.
    if (!expected.recentBlockhash) {
        throw new Error('verifyOpenTx: expected.recentBlockhash is required');
    }
    if (message.lifetimeToken !== expected.recentBlockhash) {
        throw new Error('verifyOpenTx: open transaction does not use the challenged recentBlockhash');
    }

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

    const programIdStr = expected.channelProgram ?? PAYMENT_CHANNELS_PROGRAM_ID;
    const expectedMint =
        expected.mint ?? resolveStablecoinMint(expected.currency, expected.network ?? 'mainnet') ?? expected.currency;
    if (!expectedMint) {
        throw new Error('verifyOpenTx: could not resolve mint from currency/network');
    }

    let openIx: { accountIndices: readonly number[]; data: Uint8Array } | undefined;
    for (const ix of message.instructions) {
        const programIxAddr = message.staticAccounts[ix.programAddressIndex];
        if (programIxAddr !== programIdStr) {
            if (programIxAddr !== 'ComputeBudget111111111111111111111111111111') {
                throw new Error(`verifyOpenTx: unexpected instruction program ${String(programIxAddr)}`);
            }
            continue;
        }
        // Some decoders omit `data` entirely for empty instruction data.
        if (!ix.data || ix.data.length < 1) continue;
        if (ix.data[0] !== OPEN_DISCRIMINATOR) continue;
        if (openIx) throw new Error('verifyOpenTx: transaction contains more than one open instruction');
        openIx = { accountIndices: ix.accountIndices ?? [], data: ix.data };
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
    if (indices.length < 9) {
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
    const channelTokenAccountAddr = accountAt(7, 'channelTokenAccount');
    const tokenProgramAddr = accountAt(8, 'tokenProgram');

    if (message.staticAccounts[0] !== expected.feePayer) {
        throw new Error(
            `verifyOpenTx: transaction fee payer ${String(message.staticAccounts[0])} != expected ${expected.feePayer}`,
        );
    }
    const signatures = decoded.signatures as Readonly<Record<string, Uint8Array | null>>;
    const payerSignature = signatures[payerAddr];
    if (!payerSignature || payerSignature.every(byte => byte === 0)) {
        throw new Error('verifyOpenTx: channel payer must sign the open transaction');
    }

    if (payeeAddr !== expected.recipient) {
        throw new Error(`verifyOpenTx: payee ${payeeAddr} != expected recipient ${expected.recipient}`);
    }
    if (mintAddr !== expectedMint) {
        throw new Error(`verifyOpenTx: mint ${mintAddr} != expected mint ${expectedMint}`);
    }
    if (expected.tokenProgram && tokenProgramAddr !== expected.tokenProgram) {
        throw new Error(`verifyOpenTx: tokenProgram ${tokenProgramAddr} != expected ${expected.tokenProgram}`);
    }
    if (authorizedSignerAddr !== expected.authorizedSigner) {
        throw new Error(
            `verifyOpenTx: authorizedSigner ${authorizedSignerAddr} != expected ${expected.authorizedSigner}`,
        );
    }
    if (!expected.rentPayer) {
        throw new Error('verifyOpenTx: expected.rentPayer is required');
    }
    if (rentPayerAddr !== expected.rentPayer) {
        throw new Error(`verifyOpenTx: rentPayer ${rentPayerAddr} != expected ${expected.rentPayer}`);
    }

    const decodedOpen = getOpenInstructionDataDecoder().decode(openIx.data);
    const { deposit, gracePeriod, openSlot, recipients, salt } = decodedOpen.openArgs;

    if (deposit === 0n) {
        throw new Error('verifyOpenTx: deposit must be greater than zero');
    }
    const declaredDeposit = BigInt(openPayload.depositAmount);
    if (deposit !== declaredDeposit) {
        throw new Error(`verifyOpenTx: deposit ${deposit} != payload depositAmount ${declaredDeposit}`);
    }
    if (expected.minimumDeposit !== undefined && deposit < expected.minimumDeposit) {
        throw new Error(`verifyOpenTx: deposit ${deposit} is below minimumDeposit ${expected.minimumDeposit}`);
    }
    if (openSlot !== expected.openSlot || openSlot !== BigInt(openPayload.openSlot)) {
        throw new Error(`verifyOpenTx: openSlot ${openSlot} does not match the payload`);
    }
    if (gracePeriod !== openPayload.gracePeriodSeconds) {
        throw new Error(
            `verifyOpenTx: gracePeriod ${gracePeriod} != payload gracePeriodSeconds ${openPayload.gracePeriodSeconds}`,
        );
    }
    if (salt !== BigInt(openPayload.salt)) {
        throw new Error(`verifyOpenTx: salt ${salt} != payload salt ${openPayload.salt}`);
    }
    if (payerAddr !== openPayload.payer || payeeAddr !== openPayload.payee || mintAddr !== openPayload.mint) {
        throw new Error('verifyOpenTx: payer, payee, or mint does not match the open payload');
    }
    const declaredSplits = openPayload.distributionSplits ?? [];
    if (
        recipients.length !== declaredSplits.length ||
        recipients.some(
            (entry, index) =>
                entry.recipient !== declaredSplits[index]?.recipient || entry.bps !== declaredSplits[index]?.shareBps,
        )
    ) {
        throw new Error('verifyOpenTx: distributionSplits do not match the open instruction');
    }
    // Bind the instruction's recipients to the *challenged* splits, not just
    // the client's own payload: payload↔instruction self-consistency above
    // proves nothing about whose splits they are.
    const challengedSplits = expected.splits;
    if (
        recipients.length !== challengedSplits.length ||
        recipients.some(
            (entry, index) =>
                entry.recipient !== challengedSplits[index]?.recipient ||
                entry.bps !== challengedSplits[index]?.shareBps,
        )
    ) {
        throw new Error('verifyOpenTx: distributionSplits do not match the challenge');
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
            getU64Encoder().encode(openSlot),
        ],
    });
    if (derivedChannel !== channelAddr) {
        throw new Error(`verifyOpenTx: channel PDA ${channelAddr} != derived ${derivedChannel}`);
    }
    if (openPayload.channelId !== channelAddr) {
        throw new Error(`verifyOpenTx: openPayload.channelId ${openPayload.channelId} != tx channel ${channelAddr}`);
    }
    const [expectedEscrow] = await findAssociatedTokenPda({
        mint: address(mintAddr),
        owner: address(channelAddr),
        tokenProgram: address(tokenProgramAddr),
    });
    if (expectedEscrow !== channelTokenAccountAddr) {
        throw new Error(`verifyOpenTx: channel token account ${channelTokenAccountAddr} is not the canonical ATA`);
    }

    return { channelId: channelAddr, deposit, gracePeriod, openSlot, payer: payerAddr, salt };
}

/** Validate, broadcast, and confirm a top-up transaction bound to one channel. */
export async function submitTopUpTx(args: {
    readonly additionalAmount: bigint;
    readonly channelId: string;
    readonly channelProgram: string;
    /** Deposit recorded before this top-up, for the post-confirm re-check. */
    readonly currentDeposit: bigint;
    readonly payer: string;
    readonly rpc: SignatureStatusRpc & {
        sendTransaction: (wire: string, config?: unknown) => { send(): Promise<Signature> };
    };
    readonly transaction: string;
}): Promise<Signature> {
    const decoded = getTransactionDecoder().decode(getBase64Codec().encode(args.transaction));
    const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as {
        addressTableLookups?: readonly unknown[] | undefined;
        instructions: readonly { accountIndices?: readonly number[]; data?: Uint8Array; programAddressIndex: number }[];
        staticAccounts: readonly string[];
    };
    if (message.addressTableLookups?.length) throw new Error('submitTopUpTx: address lookup tables are not permitted');
    let found = false;
    for (const ix of message.instructions) {
        const program = message.staticAccounts[ix.programAddressIndex];
        if (program === 'ComputeBudget111111111111111111111111111111') continue;
        if (program !== args.channelProgram || !ix.data || found) {
            throw new Error(`submitTopUpTx: unexpected instruction program ${String(program)}`);
        }
        const decodedData = getTopUpInstructionDataDecoder().decode(ix.data);
        const indices = ix.accountIndices ?? [];
        const payer = message.staticAccounts[indices[0] ?? -1];
        const channel = message.staticAccounts[indices[1] ?? -1];
        if (payer !== args.payer || channel !== args.channelId) {
            throw new Error('submitTopUpTx: payer or channel does not match persisted channel state');
        }
        if (decodedData.topUpArgs.amount !== args.additionalAmount) {
            throw new Error('submitTopUpTx: amount does not match additionalAmount');
        }
        found = true;
    }
    if (!found) throw new Error('submitTopUpTx: top-up instruction not found');
    let signature: Signature;
    try {
        signature = await args.rpc
            .sendTransaction(args.transaction, { encoding: 'base64', skipPreflight: false })
            .send();
    } catch (error) {
        // A duplicate of an already-landed top-up dies at preflight with
        // "already processed". The signature identifies this exact verified
        // transaction — an unrelated top-up cannot satisfy it — so a landed
        // non-error status means the escrow was funded by the first
        // submission, and the caller's signature dedupe decides whether it
        // was already credited.
        const landed = getSignatureFromTransaction(decoded);
        const [status] = (await args.rpc.getSignatureStatuses([landed]).send()).value;
        if (!status || status.err) throw error;
        signature = landed;
    }
    await waitForSignatureConfirmation({ context: 'submitTopUpTx', rpc: args.rpc, signature });
    // Post-confirm re-check, mirroring Rust: the confirmed channel account
    // must be open and reflect at least the recorded deposit plus this
    // top-up before the deposit cap is raised.
    const account = await fetchChannel(args.rpc as never, address(args.channelId), { commitment: 'confirmed' });
    if (
        account.data.status !== Number(ChannelStatus.Open) ||
        account.data.deposit < args.currentDeposit + args.additionalAmount
    ) {
        throw new Error('submitTopUpTx: confirmed channel state does not reflect the submitted top-up');
    }
    return signature;
}

/** Signature (transaction id) of a base64-encoded wire transaction. */
export function transactionSignatureFromWire(transaction: string): Signature {
    return getSignatureFromTransaction(getTransactionDecoder().decode(getBase64Codec().encode(transaction)));
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
        getAccountInfo: (address: Address, config?: unknown) => { send: () => Promise<unknown> };
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
 * a server-sponsored open.
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
    const assertConfirmedChannelMatchesOpen = async (): Promise<void> => {
        const account = await fetchChannel(args.rpc as never, address(verified.channelId), {
            commitment: 'confirmed',
        });
        const channel = account.data;
        const expectedMint =
            args.expected.mint ??
            resolveStablecoinMint(args.expected.currency, args.expected.network ?? 'mainnet') ??
            args.expected.currency;
        if (
            channel.status !== Number(ChannelStatus.Open) ||
            channel.deposit !== verified.deposit ||
            channel.salt !== verified.salt ||
            channel.openSlot !== verified.openSlot ||
            channel.gracePeriod !== verified.gracePeriod ||
            channel.payer !== verified.payer ||
            channel.payee !== args.expected.recipient ||
            channel.mint !== expectedMint ||
            channel.authorizedSigner !== args.expected.authorizedSigner ||
            channel.rentPayer !== args.expected.rentPayer
        ) {
            throw new Error('submitOpenTx: confirmed channel state does not match the verified open transaction');
        }
    };
    let signature: Signature;
    try {
        signature = await args.rpc.sendTransaction(wire, { encoding: 'base64', skipPreflight: false }).send();
        await waitForSignatureConfirmation({
            context: 'submitOpenTx',
            options: args.confirm,
            rpc: args.rpc,
            signature,
        });
    } catch (error) {
        // A broadcast rejection is not authoritative: a retry of an open
        // whose first submission landed (response lost, or the persist after
        // it failed) dies at preflight with "already processed". The
        // confirmed channel account matches the verified open params only if
        // this exact open succeeded, so a full field match below is success;
        // anything short of it keeps the broadcast failure authoritative.
        // Mirrors the Rust open retry-idempotency fix.
        signature = getSignatureFromTransaction(getTransactionDecoder().decode(getBase64Codec().encode(wire)));
        try {
            await assertConfirmedChannelMatchesOpen();
        } catch {
            throw error;
        }
        return { ...verified, signature };
    }
    await assertConfirmedChannelMatchesOpen();
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
     * rent at distribute. Required (no payer fallback).
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
 * Build settle_and_seal (+ optional Ed25519 precompile) + distribute
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

    const settle = buildSettleAndSealInstructions({
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
// internals
// ─────────────────────────────────────────────────────────────────────

const SYSTEM_PROGRAM_ADDRESS = '11111111111111111111111111111111' as Address<'11111111111111111111111111111111'>;

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
