/**
 * Test helper: re-encode a version-0 wire transaction as a version-1
 * (SIMD-0385) message with the given header config, re-signed by `signer`.
 */
import {
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
    getTransactionDecoder,
    getTransactionEncoder,
    type KeyPairSigner,
} from '@solana/kit';

import type { TransactionV1Config } from '../utils/transaction-versions.js';

const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';

/** The full 64 MiB loaded-account-data limit an MPP version-1 header must carry. */
export const V1_LOADED_ACCOUNTS_DATA_SIZE = 64 * 1024 * 1024;

/** A valid MPP version-1 header budget. */
export const VALID_SESSION_V1_CONFIG: TransactionV1Config = {
    computeUnitLimit: 200_000,
    loadedAccountsDataSizeLimit: V1_LOADED_ACCOUNTS_DATA_SIZE,
    priorityFeeLamports: 0n,
};

type V0Compiled = {
    header: { numReadonlyNonSignerAccounts: number; numReadonlySignerAccounts: number; numSignerAccounts: number };
    instructions: { accountIndices?: number[]; data?: Uint8Array; programAddressIndex: number }[];
    staticAccounts: string[];
};

/**
 * Re-encode `transactionBase64` (version 0) as version 1. ComputeBudget
 * instructions are dropped; `computeBudgetInstruction` appends one with that
 * data (and the ComputeBudget program as a read-only account). `config`
 * becomes the header's masked config.
 */
export async function reencodeAsV1(
    transactionBase64: string,
    signer: KeyPairSigner,
    config: TransactionV1Config,
    options: { computeBudgetInstruction?: Uint8Array } = {},
): Promise<string> {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const compiled = getCompiledTransactionMessageDecoder().decode(tx.messageBytes) as unknown as V0Compiled &
        Record<string, unknown>;
    const instructions = compiled.instructions.filter(
        ix => compiled.staticAccounts[ix.programAddressIndex] !== COMPUTE_BUDGET_PROGRAM,
    );
    let header = compiled.header;
    let staticAccounts = compiled.staticAccounts;
    if (options.computeBudgetInstruction) {
        let index = staticAccounts.indexOf(COMPUTE_BUDGET_PROGRAM);
        if (index < 0) {
            index = staticAccounts.length;
            staticAccounts = [...staticAccounts, COMPUTE_BUDGET_PROGRAM];
            header = { ...header, numReadonlyNonSignerAccounts: header.numReadonlyNonSignerAccounts + 1 };
        }
        instructions.push({ accountIndices: [], data: options.computeBudgetInstruction, programAddressIndex: index });
    }
    let configMask = 0;
    const configValues: { kind: 'u32' | 'u64'; value: bigint | number }[] = [];
    if (config.priorityFeeLamports !== undefined) {
        configMask |= 0b11;
        configValues.push({ kind: 'u64', value: config.priorityFeeLamports });
    }
    if (config.computeUnitLimit !== undefined) {
        configMask |= 0b100;
        configValues.push({ kind: 'u32', value: config.computeUnitLimit });
    }
    if (config.loadedAccountsDataSizeLimit !== undefined) {
        configMask |= 0b1000;
        configValues.push({ kind: 'u32', value: config.loadedAccountsDataSizeLimit });
    }
    if (config.heapSize !== undefined) {
        configMask |= 0b10000;
        configValues.push({ kind: 'u32', value: config.heapSize });
    }
    const messageBytes = getCompiledTransactionMessageEncoder().encode({
        configMask,
        configValues,
        header,
        instructionHeaders: instructions.map(ix => ({
            numInstructionAccounts: (ix.accountIndices ?? []).length,
            numInstructionDataBytes: (ix.data ?? new Uint8Array()).length,
            programAccountIndex: ix.programAddressIndex,
        })),
        instructionPayloads: instructions.map(ix => ({
            instructionAccountIndices: ix.accountIndices ?? [],
            instructionData: ix.data ?? new Uint8Array(),
        })),
        lifetimeToken: compiled.lifetimeToken,
        numInstructions: instructions.length,
        numStaticAccounts: staticAccounts.length,
        staticAccounts,
        version: 1,
    } as never);
    const [signature] = await signer.signMessages([{ content: messageBytes as Uint8Array } as never]);
    const encoded = getTransactionEncoder().encode({
        messageBytes: messageBytes as never,
        signatures: { ...tx.signatures, ...signature } as never,
    });
    return getBase64Codec().decode(encoded);
}
