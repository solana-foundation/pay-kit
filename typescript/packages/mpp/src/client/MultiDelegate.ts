// Client-side multi-delegator transaction builders.
//
// Mirrors `rust/crates/mpp/src/client/multi_delegate.rs` and the pure
// instruction builders in `rust/crates/mpp/src/program/multi_delegator.rs`:
// the client pre-signs the `initMultiDelegateTx` / `updateDelegationTx`
// payloads attached to a pull-mode session `open` action, and the server
// submits whichever transaction the on-chain state requires.

import {
    type AccountMeta,
    AccountRole,
    type Address,
    address,
    appendTransactionMessageInstructions,
    type Base64EncodedWireTransaction,
    type Blockhash,
    createTransactionMessage,
    getAddressEncoder,
    getBase64EncodedWireTransaction,
    getI64Encoder,
    getProgramDerivedAddress,
    getU64Encoder,
    getUtf8Encoder,
    type Instruction,
    type InstructionWithAccounts,
    type InstructionWithData,
    pipe,
    type ReadonlyUint8Array,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
    type TransactionSigner,
} from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';

import { SYSTEM_PROGRAM } from '../constants.js';
import type { AmountLike } from './Session.js';

const U64_MAX = (1n << 64n) - 1n;
const I64_MAX = (1n << 63n) - 1n;

/** Canonical mainnet multi-delegator program address. */
export const MULTI_DELEGATOR_PROGRAM = 'EPEUTog1kptYkthDJF6MuB1aM4aDAwHYwoF32Rzv5rqg';

/** PDA seed prefix for `MultiDelegate` accounts. */
export const MULTI_DELEGATE_SEED = 'MultiDelegate';

/** PDA seed prefix for delegation accounts. */
export const DELEGATION_SEED = 'delegation';

/**
 * Concrete instruction shape produced by the multi-delegator builders.
 */
export type MultiDelegateInstruction = Instruction &
    InstructionWithAccounts<readonly AccountMeta[]> &
    InstructionWithData<ReadonlyUint8Array>;

/**
 * Derives the `MultiDelegate` PDA for `(user, mint)`.
 */
export async function findMultiDelegatePda(parameters: findMultiDelegatePda.Parameters): Promise<Address> {
    const programAddress = address(parameters.programAddress ?? MULTI_DELEGATOR_PROGRAM);
    const [pda] = await getProgramDerivedAddress({
        programAddress,
        seeds: [
            getUtf8Encoder().encode(MULTI_DELEGATE_SEED),
            getAddressEncoder().encode(address(parameters.user)),
            getAddressEncoder().encode(address(parameters.mint)),
        ],
    });
    return pda;
}

export declare namespace findMultiDelegatePda {
    interface Parameters {
        readonly mint: string;
        readonly programAddress?: string | undefined;
        readonly user: string;
    }
}

/**
 * Derives the `FixedDelegation` PDA for `(multiDelegate, delegator, delegatee, nonce)`.
 */
export async function findFixedDelegationPda(parameters: findFixedDelegationPda.Parameters): Promise<Address> {
    const programAddress = address(parameters.programAddress ?? MULTI_DELEGATOR_PROGRAM);
    const [pda] = await getProgramDerivedAddress({
        programAddress,
        seeds: [
            getUtf8Encoder().encode(DELEGATION_SEED),
            getAddressEncoder().encode(address(parameters.multiDelegate)),
            getAddressEncoder().encode(address(parameters.delegator)),
            getAddressEncoder().encode(address(parameters.delegatee)),
            getU64Encoder().encode(parseU64(parameters.nonce, 'nonce')),
        ],
    });
    return pda;
}

export declare namespace findFixedDelegationPda {
    interface Parameters {
        readonly delegatee: string;
        readonly delegator: string;
        readonly multiDelegate: string;
        readonly nonce: AmountLike;
        readonly programAddress?: string | undefined;
    }
}

/**
 * Builds an `InitMultiDelegate` instruction (discriminator `0x00`).
 *
 * Creates the `MultiDelegate` PDA for `(user, mint)` and approves it as the
 * SPL Token delegate on `userAta` with a `u64::MAX` allowance. Account order
 * matches `build_init_multi_delegate_ix` in `program/multi_delegator.rs`.
 */
export async function buildInitMultiDelegateInstruction(
    parameters: buildInitMultiDelegateInstruction.Parameters,
): Promise<MultiDelegateInstruction> {
    const programAddress = address(parameters.programAddress ?? MULTI_DELEGATOR_PROGRAM);
    const multiDelegate = await findMultiDelegatePda({
        mint: parameters.mint,
        programAddress,
        user: parameters.user,
    });

    return {
        accounts: [
            { address: address(parameters.user), role: AccountRole.WRITABLE_SIGNER },
            { address: multiDelegate, role: AccountRole.WRITABLE },
            { address: address(parameters.mint), role: AccountRole.READONLY },
            { address: address(parameters.userAta), role: AccountRole.WRITABLE },
            { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
            { address: address(parameters.tokenProgram), role: AccountRole.READONLY },
        ],
        data: new Uint8Array([0x00]),
        programAddress,
    };
}

export declare namespace buildInitMultiDelegateInstruction {
    interface Parameters {
        readonly mint: string;
        readonly programAddress?: string | undefined;
        readonly tokenProgram: string;
        readonly user: string;
        readonly userAta: string;
    }
}

/**
 * Builds a `CreateFixedDelegation` instruction (discriminator `0x01`).
 *
 * Data layout: `[0x01] ++ nonce_le_u64 ++ amount_le_u64 ++ expiry_ts_le_i64`.
 * Account order matches `build_create_fixed_delegation_ix` in
 * `program/multi_delegator.rs`.
 */
export async function buildCreateFixedDelegationInstruction(
    parameters: buildCreateFixedDelegationInstruction.Parameters,
): Promise<MultiDelegateInstruction> {
    const programAddress = address(parameters.programAddress ?? MULTI_DELEGATOR_PROGRAM);
    const nonce = parseU64(parameters.nonce, 'nonce');
    const multiDelegate = await findMultiDelegatePda({
        mint: parameters.mint,
        programAddress,
        user: parameters.delegator,
    });
    const delegation = await findFixedDelegationPda({
        delegatee: parameters.delegatee,
        delegator: parameters.delegator,
        multiDelegate,
        nonce,
        programAddress,
    });

    const data = new Uint8Array(25);
    data[0] = 0x01;
    data.set(getU64Encoder().encode(nonce) as Uint8Array, 1);
    data.set(getU64Encoder().encode(parseU64(parameters.amount, 'amount')) as Uint8Array, 9);
    data.set(getI64Encoder().encode(parseI64(parameters.expiryTs, 'expiryTs')) as Uint8Array, 17);

    return {
        accounts: [
            { address: address(parameters.delegator), role: AccountRole.WRITABLE_SIGNER },
            { address: multiDelegate, role: AccountRole.READONLY },
            { address: delegation, role: AccountRole.WRITABLE },
            { address: address(parameters.delegatee), role: AccountRole.READONLY },
            { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
        ],
        data,
        programAddress,
    };
}

export declare namespace buildCreateFixedDelegationInstruction {
    interface Parameters {
        readonly amount: AmountLike;
        readonly delegatee: string;
        readonly delegator: string;
        /** Unix seconds; `0` means the delegation never expires. */
        readonly expiryTs: AmountLike;
        readonly mint: string;
        readonly nonce: AmountLike;
        readonly programAddress?: string | undefined;
    }
}

/**
 * Shared parameters for the pre-signed multi-delegator transactions.
 */
export interface MultiDelegateTxParameters {
    /** Delegation cap in base units. */
    readonly amount: AmountLike;
    /** Unix seconds; `0` means the delegation never expires. */
    readonly expiryTs: AmountLike;
    readonly mint: string;
    readonly nonce?: AmountLike | undefined;
    /** Operator (delegatee) authorized to pull up to `amount`. */
    readonly operator: string;
    readonly programAddress?: string | undefined;
    /** Server-provided recent blockhash (base58). */
    readonly recentBlockhash: string;
    /** User wallet; signs the transaction and pays fees. */
    readonly signer: TransactionSigner;
    readonly tokenProgram: string;
    /** User token account; derived as the ATA of `(signer, mint)` when omitted. */
    readonly userAta?: string | undefined;
}

/**
 * Builds and signs the `initMultiDelegateTx` for a pull-mode session open.
 *
 * Two instructions in one transaction, mirroring `build_init_multi_delegate_tx`
 * in `client/multi_delegate.rs`: `InitMultiDelegate` followed by
 * `CreateFixedDelegation`. The user signs and pays fees; the result is the
 * base64-encoded wire transaction the server submits.
 */
export async function buildInitMultiDelegateTx(
    parameters: MultiDelegateTxParameters,
): Promise<Base64EncodedWireTransaction> {
    const userAta = await resolveUserAta(parameters);
    const initInstruction = await buildInitMultiDelegateInstruction({
        mint: parameters.mint,
        programAddress: parameters.programAddress,
        tokenProgram: parameters.tokenProgram,
        user: parameters.signer.address,
        userAta,
    });
    const createInstruction = await buildCreateFixedDelegationInstruction({
        amount: parameters.amount,
        delegatee: parameters.operator,
        delegator: parameters.signer.address,
        expiryTs: parameters.expiryTs,
        mint: parameters.mint,
        nonce: parameters.nonce ?? 0n,
        programAddress: parameters.programAddress,
    });
    return await signAndEncode(parameters.signer, [initInstruction, createInstruction], parameters.recentBlockhash);
}

/**
 * Builds and signs the `updateDelegationTx` for a pull-mode session open.
 *
 * One `CreateFixedDelegation` instruction, mirroring
 * `build_update_delegation_tx` in `client/multi_delegate.rs`; used to raise an
 * existing cap or create a delegation at a fresh nonce.
 */
export async function buildUpdateDelegationTx(
    parameters: Omit<MultiDelegateTxParameters, 'userAta'>,
): Promise<Base64EncodedWireTransaction> {
    const instruction = await buildCreateFixedDelegationInstruction({
        amount: parameters.amount,
        delegatee: parameters.operator,
        delegator: parameters.signer.address,
        expiryTs: parameters.expiryTs,
        mint: parameters.mint,
        nonce: parameters.nonce ?? 0n,
        programAddress: parameters.programAddress,
    });
    return await signAndEncode(parameters.signer, [instruction], parameters.recentBlockhash);
}

/**
 * Derives the user's associated token account for the delegated mint.
 */
export async function deriveDelegatedTokenAccount(parameters: {
    readonly mint: string;
    readonly owner: string;
    readonly tokenProgram: string;
}): Promise<Address> {
    const [ata] = await findAssociatedTokenPda({
        mint: address(parameters.mint),
        owner: address(parameters.owner),
        tokenProgram: address(parameters.tokenProgram),
    });
    return ata;
}

async function resolveUserAta(parameters: MultiDelegateTxParameters): Promise<string> {
    if (parameters.userAta) return parameters.userAta;
    return await deriveDelegatedTokenAccount({
        mint: parameters.mint,
        owner: parameters.signer.address,
        tokenProgram: parameters.tokenProgram,
    });
}

async function signAndEncode(
    signer: TransactionSigner,
    instructions: readonly MultiDelegateInstruction[],
    recentBlockhash: string,
): Promise<Base64EncodedWireTransaction> {
    // The Rust builder serializes a legacy transaction; keep the same wire
    // format so either server implementation can decode it.
    const message = pipe(
        createTransactionMessage({ version: 'legacy' }),
        msg => setTransactionMessageFeePayerSigner(signer, msg),
        msg =>
            setTransactionMessageLifetimeUsingBlockhash(
                { blockhash: recentBlockhash as Blockhash, lastValidBlockHeight: 0n },
                msg,
            ),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );
    const signed = await signTransactionMessageWithSigners(message);
    return getBase64EncodedWireTransaction(signed);
}

function parseU64(value: AmountLike, name: string): bigint {
    const parsed = parseInteger(value, name);
    if (parsed < 0n) throw new Error(`${name} must be non-negative`);
    if (parsed > U64_MAX) throw new Error(`${name} exceeds u64 max`);
    return parsed;
}

function parseI64(value: AmountLike, name: string): bigint {
    const parsed = parseInteger(value, name);
    if (parsed < 0n) throw new Error(`${name} must be non-negative`);
    if (parsed > I64_MAX) throw new Error(`${name} exceeds i64 max`);
    return parsed;
}

function parseInteger(value: AmountLike, name: string): bigint {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) throw new Error(`${name} must be a safe integer`);
        return BigInt(value);
    }
    if (!/^\d+$/.test(value)) throw new Error(`${name} must be an integer string`);
    return BigInt(value);
}
