/**
 * Tests for the server charge verification logic.
 *
 * Covers both settlement modes:
 * - Push mode (type="signature"): server fetches + verifies on-chain
 * - Pull mode (type="transaction"): server broadcasts, confirms, then verifies on-chain
 */
import { test, expect, beforeEach, afterEach } from 'vitest';
import { Store } from 'mppx/server';
import { getSetComputeUnitLimitInstruction, getSetComputeUnitPriceInstruction } from '@solana-program/compute-budget';
import { getTransferSolInstruction } from '@solana-program/system';
import { findAssociatedTokenPda, getTransferCheckedInstruction } from '@solana-program/token';
import {
    AccountRole,
    type Address,
    address,
    appendTransactionMessageInstructions,
    createTransactionMessage,
    generateKeyPairSigner,
    getBase64EncodedWireTransaction,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
    type Instruction,
    partiallySignTransactionMessageWithSigners,
    pipe,
    setTransactionMessageFeePayer,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    type Blockhash,
} from '@solana/kit';
import { buildChargeTransaction } from '../client/Charge.js';
import { charge, interpretPostTimeoutStatus, verifyChargeTransaction } from '../server/Charge.js';
import {
    claimConsumedSignature,
    consumedSignatureKey,
    legacyConsumedSignatureKey,
    reserveReplayKey,
} from '../server/replay.js';
import { assertTransactionSignaturesVerify, transactionSignatureFromBase64 } from '../utils/transactions.js';
import {
    ASSOCIATED_TOKEN_PROGRAM,
    CASH,
    MEMO_PROGRAM,
    PYUSD,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    USDG,
} from '../constants.js';

// ── Fixtures ──

const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const USDC_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const SIGNATURE = '5UfDuX6nSqMzMR8W7n6K3b1GKLmaqEisBFCcYPRLjNHrCbVQJF3BVjkE7aQJMQ2Kx';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;

type TestCompiledInstruction = {
    accountIndices?: readonly unknown[];
    accounts?: readonly unknown[];
    data: Uint8Array;
    programAddressIndex: number;
};

type TestCompiledMessage = {
    instructions: readonly TestCompiledInstruction[];
    staticAccounts: readonly { toString(): string }[];
};

/** Build a push mode credential (type="signature"). */
function signatureCredential(
    sig: string,
    overrides: {
        amount?: string;
        currency?: string;
        recipient?: string;
        decimals?: number;
        externalId?: string;
        tokenProgram?: string;
        feePayer?: boolean;
        feePayerKey?: string;
        splits?: Array<{ recipient: string; amount: string; ataCreationRequired?: boolean; memo?: string }>;
    } = {},
) {
    const curr = overrides.currency ?? 'sol';
    const isSpl = curr !== 'sol';
    return {
        payload: { type: 'signature', signature: sig },
        challenge: {
            request: {
                amount: overrides.amount ?? '1000000',
                currency: curr,
                ...(overrides.externalId ? { externalId: overrides.externalId } : {}),
                recipient: overrides.recipient ?? RECIPIENT,
                methodDetails: {
                    network: 'devnet',
                    ...(isSpl
                        ? {
                              decimals: overrides.decimals ?? 6,
                              tokenProgram: overrides.tokenProgram ?? TOKEN_PROGRAM,
                          }
                        : {}),
                    ...(overrides.feePayer !== undefined ? { feePayer: overrides.feePayer } : {}),
                    ...(overrides.feePayerKey ? { feePayerKey: overrides.feePayerKey } : {}),
                    ...(overrides.splits ? { splits: overrides.splits } : {}),
                },
            },
        },
    } as any;
}

/** Build a pull mode credential (type="transaction"). */
function transactionCredential(
    txBase64: string,
    overrides: {
        amount?: string;
        currency?: string;
        recipient?: string;
        decimals?: number;
        externalId?: string;
        tokenProgram?: string;
        feePayer?: boolean;
        feePayerKey?: string;
        splits?: Array<{ recipient: string; amount: string; ataCreationRequired?: boolean; memo?: string }>;
    } = {},
) {
    const curr = overrides.currency ?? 'sol';
    const isSpl = curr !== 'sol';
    return {
        payload: { type: 'transaction', transaction: txBase64 },
        challenge: {
            request: {
                amount: overrides.amount ?? '1000000',
                currency: curr,
                ...(overrides.externalId ? { externalId: overrides.externalId } : {}),
                recipient: overrides.recipient ?? RECIPIENT,
                methodDetails: {
                    network: 'devnet',
                    ...(isSpl
                        ? {
                              decimals: overrides.decimals ?? 6,
                              tokenProgram: overrides.tokenProgram ?? TOKEN_PROGRAM,
                          }
                        : {}),
                    ...(overrides.feePayer !== undefined ? { feePayer: overrides.feePayer } : {}),
                    ...(overrides.feePayerKey ? { feePayerKey: overrides.feePayerKey } : {}),
                    ...(overrides.splits ? { splits: overrides.splits } : {}),
                },
            },
        },
    } as any;
}

async function buildSolPaymentTxBase64(
    destination: string,
    lamports: string | number,
    options: { externalId?: string; splits?: Array<{ recipient: string; amount: string; memo?: string }> } = {},
) {
    const payer = await generateKeyPairSigner();
    const instructions: Instruction[] = [
        getTransferSolInstruction({
            source: payer,
            destination: address(destination),
            amount: BigInt(lamports),
        }),
    ];
    if (options.externalId) {
        instructions.push(memoInstruction(options.externalId));
    }

    for (const split of options.splits ?? []) {
        instructions.push(
            getTransferSolInstruction({
                source: payer,
                destination: address(split.recipient),
                amount: BigInt(split.amount),
            }),
        );
        if (split.memo) {
            instructions.push(memoInstruction(split.memo));
        }
    }

    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(payer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );

    return getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(txMessage));
}

async function buildSplPaymentTxBase64(
    destinationOwner: string,
    mint: string,
    amount: string | number,
    decimals = 6,
    tokenProgram = TOKEN_PROGRAM,
    options: {
        extraAtaOwners?: string[];
        externalId?: string;
        feePayerKey?: string;
        skipAtaCreationFor?: string[];
        splits?: Array<{ recipient: string; amount: string; ataCreationRequired?: boolean; memo?: string }>;
    } = {},
) {
    const payer = await generateKeyPairSigner();
    const mintAddress = address(mint);
    const tokenProgramAddress = address(tokenProgram);
    const [sourceAta] = await findAssociatedTokenPda({
        owner: payer.address,
        mint: mintAddress,
        tokenProgram: tokenProgramAddress,
    });
    const [destinationAta] = await findAssociatedTokenPda({
        owner: address(destinationOwner),
        mint: mintAddress,
        tokenProgram: tokenProgramAddress,
    });

    const instructionPayer = options.feePayerKey ? address(options.feePayerKey) : payer.address;
    const instructions: Instruction[] = [];
    const shouldSkipAtaCreation = (owner: string) => options.skipAtaCreationFor?.includes(owner) === true;
    instructions.push(
        getTransferCheckedInstruction(
            {
                source: sourceAta,
                mint: mintAddress,
                destination: destinationAta,
                authority: payer,
                amount: BigInt(amount),
                decimals,
            },
            { programAddress: tokenProgramAddress },
        ),
    );
    if (options.externalId) {
        instructions.push(memoInstruction(options.externalId));
    }

    for (const split of options.splits ?? []) {
        const splitOwner = address(split.recipient);
        const [splitAta] = await findAssociatedTokenPda({
            owner: splitOwner,
            mint: mintAddress,
            tokenProgram: tokenProgramAddress,
        });
        if ((!options.feePayerKey || split.ataCreationRequired === true) && !shouldSkipAtaCreation(split.recipient)) {
            instructions.push(
                await createAssociatedTokenAccountIdempotent(
                    instructionPayer,
                    splitOwner,
                    mintAddress,
                    tokenProgramAddress,
                ),
            );
        }
        instructions.push(
            getTransferCheckedInstruction(
                {
                    source: sourceAta,
                    mint: mintAddress,
                    destination: splitAta,
                    authority: payer,
                    amount: BigInt(split.amount),
                    decimals,
                },
                { programAddress: tokenProgramAddress },
            ),
        );
        if (split.memo) {
            instructions.push(memoInstruction(split.memo));
        }
    }

    for (const owner of options.extraAtaOwners ?? []) {
        instructions.push(
            await createAssociatedTokenAccountIdempotent(
                instructionPayer,
                address(owner),
                mintAddress,
                tokenProgramAddress,
            ),
        );
    }

    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg =>
            options.feePayerKey
                ? setTransactionMessageFeePayer(address(options.feePayerKey), msg)
                : setTransactionMessageFeePayerSigner(payer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );

    return getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(txMessage));
}

async function createAssociatedTokenAccountIdempotent(
    payer: Address,
    owner: Address,
    mint: Address,
    tokenProgram: Address,
): Promise<Instruction> {
    const [ata] = await findAssociatedTokenPda({
        owner,
        mint,
        tokenProgram,
    });

    return {
        accounts: [
            { address: payer, role: AccountRole.WRITABLE_SIGNER },
            { address: ata, role: AccountRole.WRITABLE },
            { address: owner, role: AccountRole.READONLY },
            { address: mint, role: AccountRole.READONLY },
            { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
            { address: tokenProgram, role: AccountRole.READONLY },
        ],
        data: new Uint8Array([1]),
        programAddress: address(ASSOCIATED_TOKEN_PROGRAM),
    };
}

function memoInstruction(memo: string): Instruction {
    return {
        accounts: [],
        data: new TextEncoder().encode(memo),
        programAddress: address(MEMO_PROGRAM),
    };
}

function decodeMemoInstructions(transaction: string): readonly TestCompiledInstruction[] {
    const txBytes = getBase64Codec().encode(transaction);
    const decoded = getTransactionDecoder().decode(txBytes);
    const message = getCompiledTransactionMessageDecoder().decode(
        decoded.messageBytes,
    ) as unknown as TestCompiledMessage;
    return message.instructions.filter(
        ix => message.staticAccounts[ix.programAddressIndex].toString() === MEMO_PROGRAM,
    );
}

// ── RPC response builders ──

function rpcSuccess(result: unknown) {
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        headers: { 'Content-Type': 'application/json' },
    });
}

function rpcError(message: string) {
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { message } }), {
        headers: { 'Content-Type': 'application/json' },
    });
}

function solTransferTx(destination: string, lamports: number | string) {
    return txWithInstructions([
        {
            program: 'system',
            parsed: {
                type: 'transfer',
                info: { destination, lamports: Number(lamports) },
            },
        },
    ]);
}

function memoIx(memo: string) {
    return {
        parsed: memo,
        program: 'spl-memo',
        programId: MEMO_PROGRAM,
    };
}

function memoInfoIx(key: 'data' | 'memo', memo: string) {
    return {
        parsed: { info: { [key]: memo } },
        program: 'spl-memo',
        programId: MEMO_PROGRAM,
    };
}

function txWithInstructions(instructions: unknown[]) {
    return {
        meta: { err: null },
        version: 0,
        transaction: {
            message: {
                instructions,
            },
        },
    };
}

function splTransferIx(destination: string, mint: string, amount: string, programId: string = TOKEN_PROGRAM) {
    return {
        programId,
        parsed: {
            type: 'transferChecked',
            info: {
                destination,
                mint,
                tokenAmount: { amount },
            },
        },
    };
}

function splTransferTx(destination: string, mint: string, amount: string, programId: string = TOKEN_PROGRAM) {
    return txWithInstructions([splTransferIx(destination, mint, amount, programId)]);
}

function ataCreateIx({
    account,
    mint,
    owner,
    payer,
    tokenProgram = TOKEN_PROGRAM,
}: {
    account: string;
    mint: string;
    owner: string;
    payer: string;
    tokenProgram?: string;
}) {
    return {
        program: 'spl-associated-token-account',
        programId: ASSOCIATED_TOKEN_PROGRAM,
        parsed: {
            type: 'createIdempotent',
            info: {
                account,
                mint,
                source: payer,
                systemProgram: SYSTEM_PROGRAM,
                tokenProgram,
                wallet: owner,
            },
        },
    };
}

// ── Test setup ──

let originalFetch: typeof globalThis.fetch;
let store: Store.Store;

beforeEach(() => {
    originalFetch = globalThis.fetch;
    store = Store.memory();
});

afterEach(() => {
    globalThis.fetch = originalFetch;
});

// ── Parameter validation ──

test('charge() throws when currency is a mint but decimals is missing', () => {
    expect(() =>
        charge({
            recipient: RECIPIENT,
            currency: USDC_MINT,
            // decimals intentionally omitted
            network: 'devnet',
            store,
        }),
    ).toThrow(/decimals is required/);
});

test('charge() does not throw for native SOL', () => {
    expect(() =>
        charge({
            recipient: RECIPIENT,
            network: 'devnet',
            store,
        }),
    ).not.toThrow();
});

test('charge() rejects split ATA creation when currency is native SOL', () => {
    expect(() =>
        charge({
            recipient: RECIPIENT,
            network: 'devnet',
            splits: [{ recipient: PLATFORM, amount: '50000', ataCreationRequired: true }],
            store,
        }),
    ).toThrow(/SPL token currency/);
});

test('charge() rejects split ATA creation when currency is a stablecoin symbol', () => {
    expect(() =>
        charge({
            recipient: RECIPIENT,
            currency: 'USDC',
            decimals: 6,
            network: 'devnet',
            splits: [{ recipient: PLATFORM, amount: '50000', ataCreationRequired: true }],
            store,
        }),
    ).toThrow(/mint address/);
});

// ── Request generation ──

test('request() populates fields without a request-side reference', async () => {
    // Mock fetch for the blockhash pre-fetch in request().
    globalThis.fetch = async () =>
        rpcSuccess({ value: { blockhash: 'MockBlockhash1111111111111111111111111111111', lastValidBlockHeight: 100 } });

    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        store,
    });

    const stub = {};

    const request1 = await method.request!({
        credential: null,
        request: { amount: '1000000', currency: USDC_MINT, recipient: '', methodDetails: stub },
    });

    expect(request1.recipient).toBe(RECIPIENT);
    expect(request1.methodDetails.network).toBe('devnet');
    expect(request1.methodDetails.decimals).toBe(6);
    expect(request1.methodDetails.recentBlockhash).toBeTruthy();
    expect(request1.methodDetails).not.toHaveProperty('reference');
});

test('request() returns the challenge request when credential is present', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        store,
    });

    const challengeRequest = {
        amount: '1000000',
        currency: 'sol',
        recipient: RECIPIENT,
        methodDetails: {
            network: 'devnet',
        },
    };

    const result = await method.request!({
        credential: { challenge: { request: challengeRequest } } as any,
        request: { amount: '1000000', currency: 'sol', recipient: '', methodDetails: {} },
    });

    expect(result).toEqual(challengeRequest);
});

// ══════════════════════════════════════════════════════════════════════
// Push mode (type="signature")
// ══════════════════════════════════════════════════════════════════════

// ── Native SOL verification ──

test('signature: accepts valid native SOL transfer', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () => rpcSuccess(solTransferTx(RECIPIENT, 1000000));

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.reference).toBe(SIGNATURE);
});

// One on-chain payment authorizes one request across protocols: a signature
// another protocol (PayKit's x402 adapter) already claimed in the shared
// ledger is refused, and MPP claims its own payments in that same ledger.
test('signature: shares one consumed-signature ledger with other protocols', async () => {
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store });
    globalThis.fetch = async () => rpcSuccess(solTransferTx(RECIPIENT, 1000000));
    const credential = signatureCredential(SIGNATURE, { amount: '1000000' });

    expect(await claimConsumedSignature(store, SIGNATURE)).toBe(true);
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('already consumed');

    await store.delete(consumedSignatureKey(SIGNATURE));
    await store.delete(legacyConsumedSignatureKey(SIGNATURE));
    await expect(method.verify({ credential, request: {} as any })).resolves.toMatchObject({ status: 'success' });
    expect(await claimConsumedSignature(store, SIGNATURE)).toBe(false);
});

// Rolling upgrade: a replica on the previous release claims and checks only
// the legacy key. Every claim takes it too, so such a replica refuses a
// payment this release accepted, through either settlement mode.
test('a settled payment is visible to replicas on the previous release', async () => {
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store });
    globalThis.fetch = async () => rpcSuccess(solTransferTx(RECIPIENT, 1000000));
    await expect(
        method.verify({ credential: signatureCredential(SIGNATURE, { amount: '1000000' }), request: {} as any }),
    ).resolves.toMatchObject({ status: 'success' });
    expect(await reserveReplayKey(store, legacyConsumedSignatureKey(SIGNATURE))).toBe(false);

    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);
    const signature = transactionSignatureFromBase64(transaction);
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000));
    await expect(
        method.verify({ credential: transactionCredential(transaction, { amount: '1000000' }), request: {} as any }),
    ).resolves.toMatchObject({ status: 'success' });
    expect(await store.get(legacyConsumedSignatureKey(signature))).toMatchObject({ state: 'confirmed' });
    expect(await reserveReplayKey(store, legacyConsumedSignatureKey(signature))).toBe(false);
});

// A previous-release replica that claimed the legacy key in the window after
// the ledger check owns the payment: nothing is sent, and the ledger key is
// given back.
test('pull: a legacy claim taken by a previous release stops the broadcast', async () => {
    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);
    const signature = transactionSignatureFromBase64(transaction);
    const legacy = legacyConsumedSignatureKey(signature);
    let raced = false;
    const racingStore: Store.Store = {
        ...store,
        async get(key) {
            const value = await store.get(key);
            // An old replica claims its key right after this release checked it.
            if (key === legacy && !raced) {
                raced = true;
                await store.put(legacy, true);
            }
            return value;
        },
    };
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store: racingStore });
    const rpcMethods: string[] = [];
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000), rpcMethods);
    await expect(
        method.verify({ credential: transactionCredential(transaction, { amount: '1000000' }), request: {} as any }),
    ).rejects.toThrow('already consumed');
    expect(rpcMethods).not.toContain('sendTransaction');
    expect(await store.get(consumedSignatureKey(signature))).toBeNull();
});

// A signature claimed under the pre-ledger MPP key (by an older replica, or
// just before an upgrade) stays consumed for every claim path; the legacy
// record is only read, never rewritten.
test('signature: a pre-ledger consumed record stays consumed', async () => {
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store });
    globalThis.fetch = async () => rpcSuccess(solTransferTx(RECIPIENT, 1000000));
    const legacyKey = `solana-charge:consumed:${SIGNATURE}`;
    await store.put(legacyKey, true);

    await expect(
        method.verify({ credential: signatureCredential(SIGNATURE, { amount: '1000000' }), request: {} as any }),
    ).rejects.toThrow('already consumed');
    expect(await claimConsumedSignature(store, SIGNATURE)).toBe(false);
    expect(await store.get(consumedSignatureKey(SIGNATURE))).toBeNull();
    expect(await store.get(legacyKey)).toBe(true);

    // Signatures without a legacy record claim normally.
    await store.delete(legacyKey);
    await expect(
        method.verify({ credential: signatureCredential(SIGNATURE, { amount: '1000000' }), request: {} as any }),
    ).resolves.toMatchObject({ status: 'success' });
});

test('signature: rejects SOL transfer with wrong recipient', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () => rpcSuccess(solTransferTx('WrongRecipient111111111111111111111', 1000000));

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No.*transfer.*instruction.*found|Recipient mismatch/);
});

test('signature: rejects SOL transfer with wrong amount', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () => rpcSuccess(solTransferTx(RECIPIENT, 500000));

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No system transfer instruction found/);
});

test('client: includes memo instructions for memo-bearing SOL splits', async () => {
    const signer = await generateKeyPairSigner();
    const transaction = await buildChargeTransaction({
        signer,
        request: {
            amount: '1000000',
            currency: 'sol',
            recipient: RECIPIENT,
            methodDetails: {
                network: 'devnet',
                recentBlockhash: BLOCKHASH,
                splits: [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }],
            },
        },
    });

    const txBytes = getBase64Codec().encode(transaction);
    const decoded = getTransactionDecoder().decode(txBytes);
    const message = getCompiledTransactionMessageDecoder().decode(
        decoded.messageBytes,
    ) as unknown as TestCompiledMessage;
    const memoInstruction = message.instructions.find(
        ix => message.staticAccounts[ix.programAddressIndex].toString() === MEMO_PROGRAM,
    );

    expect(memoInstruction).toBeDefined();
    expect(new TextDecoder().decode(memoInstruction!.data)).toBe('platform fee');
});

test('client: includes memo instructions for memo-bearing SPL splits', async () => {
    const signer = await generateKeyPairSigner();
    const transaction = await buildChargeTransaction({
        signer,
        request: {
            amount: '1000000',
            currency: USDC_MINT,
            recipient: RECIPIENT,
            methodDetails: {
                decimals: 6,
                network: 'devnet',
                recentBlockhash: BLOCKHASH,
                splits: [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }],
                tokenProgram: TOKEN_PROGRAM,
            },
        },
    });

    const txBytes = getBase64Codec().encode(transaction);
    const decoded = getTransactionDecoder().decode(txBytes);
    const message = getCompiledTransactionMessageDecoder().decode(
        decoded.messageBytes,
    ) as unknown as TestCompiledMessage;
    const memoInstruction = message.instructions.find(
        ix => message.staticAccounts[ix.programAddressIndex].toString() === MEMO_PROGRAM,
    );

    expect(memoInstruction).toBeDefined();
    const memoAccounts = memoInstruction?.accountIndices ?? memoInstruction?.accounts ?? [];
    expect(memoAccounts).toHaveLength(0);
    expect(new TextDecoder().decode(memoInstruction!.data)).toBe('platform fee');
});

test('client: includes externalId memo instruction for root SOL payment', async () => {
    const signer = await generateKeyPairSigner();
    const transaction = await buildChargeTransaction({
        signer,
        request: {
            amount: '1000000',
            currency: 'sol',
            externalId: 'order-123',
            recipient: RECIPIENT,
            methodDetails: {
                network: 'devnet',
                recentBlockhash: BLOCKHASH,
            },
        },
    });

    const memoTexts = decodeMemoInstructions(transaction).map(ix => new TextDecoder().decode(ix.data));
    expect(memoTexts).toContain('order-123');
});

test('client: includes externalId memo instruction for root SPL payment', async () => {
    const signer = await generateKeyPairSigner();
    const transaction = await buildChargeTransaction({
        signer,
        request: {
            amount: '1000000',
            currency: USDC_MINT,
            externalId: 'order-123',
            recipient: RECIPIENT,
            methodDetails: {
                decimals: 6,
                network: 'devnet',
                recentBlockhash: BLOCKHASH,
                tokenProgram: TOKEN_PROGRAM,
            },
        },
    });

    const memoTexts = decodeMemoInstructions(transaction).map(ix => new TextDecoder().decode(ix.data));
    expect(memoTexts).toContain('order-123');
});

test('client: rejects externalId memos above the SPL Memo byte limit', async () => {
    const signer = await generateKeyPairSigner();

    await expect(
        buildChargeTransaction({
            signer,
            request: {
                amount: '1000000',
                currency: 'sol',
                externalId: 'x'.repeat(567),
                recipient: RECIPIENT,
                methodDetails: {
                    network: 'devnet',
                    recentBlockhash: BLOCKHASH,
                },
            },
        }),
    ).rejects.toThrow(/memo cannot exceed 566 bytes/);
});

test('client: rejects split memos above the SPL Memo byte limit', async () => {
    const signer = await generateKeyPairSigner();

    await expect(
        buildChargeTransaction({
            signer,
            request: {
                amount: '1000000',
                currency: 'sol',
                recipient: RECIPIENT,
                methodDetails: {
                    network: 'devnet',
                    recentBlockhash: BLOCKHASH,
                    splits: [{ recipient: PLATFORM, amount: '50000', memo: 'x'.repeat(567) }],
                },
            },
        }),
    ).rejects.toThrow(/memo cannot exceed 566 bytes/);
});

test('signature: accepts SOL externalId memo when requested', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                {
                    program: 'system',
                    parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 1000000 } },
                },
                memoIx('order-123'),
            ]),
        );

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000', externalId: 'order-123' }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.externalId).toBe('order-123');
});

test.each([
    ['memo', memoInfoIx('memo', 'order-123')],
    ['data', memoInfoIx('data', 'order-123')],
])('signature: accepts SOL externalId memo parsed as info.%s', async (_field, memoInstruction) => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                {
                    program: 'system',
                    parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 1000000 } },
                },
                memoInstruction,
            ]),
        );

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000', externalId: 'order-123' }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('signature: rejects SOL externalId memo when missing', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () => rpcSuccess(solTransferTx(RECIPIENT, 1000000));

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', externalId: 'order-123' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found for externalId memo/);
});

test('signature: rejects SOL externalId memo when wrong', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                {
                    program: 'system',
                    parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 1000000 } },
                },
                memoIx('wrong order'),
            ]),
        );

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', externalId: 'order-123' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found for externalId memo/);
});

test('signature: accepts SOL split memo when requested', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                { program: 'system', parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } } },
                { program: 'system', parsed: { type: 'transfer', info: { destination: PLATFORM, lamports: 50000 } } },
                memoIx('platform fee'),
            ]),
        );

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test.each([
    ['memo', memoInfoIx('memo', 'platform fee')],
    ['data', memoInfoIx('data', 'platform fee')],
])('signature: accepts SOL split memo parsed as info.%s', async (_field, memoInstruction) => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                { program: 'system', parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } } },
                { program: 'system', parsed: { type: 'transfer', info: { destination: PLATFORM, lamports: 50000 } } },
                memoInstruction,
            ]),
        );

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('signature: rejects SOL split when requested memo is missing', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                { program: 'system', parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } } },
                { program: 'system', parsed: { type: 'transfer', info: { destination: PLATFORM, lamports: 50000 } } },
            ]),
        );

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found/);
});

test('signature: rejects SOL split when requested memo is wrong', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                { program: 'system', parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } } },
                { program: 'system', parsed: { type: 'transfer', info: { destination: PLATFORM, lamports: 50000 } } },
                memoIx('wrong memo'),
            ]),
        );

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found/);
});

test('signature: rejects unrequested SOL memo instructions', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                {
                    program: 'system',
                    parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 1000000 } },
                },
                memoIx('not requested'),
            ]),
        );

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/Unexpected Memo Program instruction/);
});

test('signature: duplicate requested SOL memos require distinct memo instructions', async () => {
    const referrer = '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';
    const splits = [
        { recipient: PLATFORM, amount: '30000', memo: 'platform fee' },
        { recipient: referrer, amount: '20000', memo: 'platform fee' },
    ];
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                { program: 'system', parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } } },
                { program: 'system', parsed: { type: 'transfer', info: { destination: PLATFORM, lamports: 30000 } } },
                { program: 'system', parsed: { type: 'transfer', info: { destination: referrer, lamports: 20000 } } },
                memoIx('platform fee'),
            ]),
        );

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found/);
});

// ── SPL token verification ──

test('signature: accepts valid SPL token transfer', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const [expectedAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () => rpcSuccess(splTransferTx(expectedAta, USDC_MINT, '1000000'));

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, {
            amount: '1000000',
            currency: USDC_MINT,
            decimals: 6,
        }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.reference).toBe(SIGNATURE);
});

test('signature: accepts SPL externalId memo when requested', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const [expectedAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess(txWithInstructions([splTransferIx(expectedAta, USDC_MINT, '1000000'), memoIx('order-123')]));

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, {
            amount: '1000000',
            currency: USDC_MINT,
            decimals: 6,
            externalId: 'order-123',
        }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.externalId).toBe('order-123');
});

test('signature: rejects SPL externalId memo when missing', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const [expectedAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () => rpcSuccess(splTransferTx(expectedAta, USDC_MINT, '1000000'));

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
                externalId: 'order-123',
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found for externalId memo/);
});

test('signature: accepts SPL split memo when requested', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(PLATFORM),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                splTransferIx(recipientAta, USDC_MINT, '950000'),
                splTransferIx(platformAta, USDC_MINT, '50000'),
                memoIx('platform fee'),
            ]),
        );

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000', currency: USDC_MINT, decimals: 6, splits }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('signature: rejects SPL split when requested memo is missing', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(PLATFORM),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                splTransferIx(recipientAta, USDC_MINT, '950000'),
                splTransferIx(platformAta, USDC_MINT, '50000'),
            ]),
        );

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
                splits,
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found/);
});

test('signature: rejects SPL split when requested memo is wrong', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(PLATFORM),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                splTransferIx(recipientAta, USDC_MINT, '950000'),
                splTransferIx(platformAta, USDC_MINT, '50000'),
                memoIx('wrong memo'),
            ]),
        );

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
                splits,
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found/);
});

test('signature: rejects unrequested SPL memo instructions', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess(txWithInstructions([splTransferIx(recipientAta, USDC_MINT, '1000000'), memoIx('not requested')]));

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', currency: USDC_MINT, decimals: 6 }),
            request: {} as any,
        }),
    ).rejects.toThrow(/Unexpected Memo Program instruction/);
});

test('signature: rejects SPL transfer with wrong mint', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const [expectedAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    const WRONG_MINT = 'So11111111111111111111111111111111111111112';
    globalThis.fetch = async () => rpcSuccess(splTransferTx(expectedAta, WRONG_MINT, '1000000'));

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No TransferChecked instruction found|Token mint mismatch/);
});

test('signature: rejects SPL transfer with wrong amount', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const [expectedAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () => rpcSuccess(splTransferTx(expectedAta, USDC_MINT, '500000'));

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No TransferChecked instruction found/);
});

test('signature: rejects SPL transfer with wrong destination ATA', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const WRONG_ATA = 'WrongATA11111111111111111111111111111111111';
    globalThis.fetch = async () => rpcSuccess(splTransferTx(WRONG_ATA, USDC_MINT, '1000000'));

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No TransferChecked instruction found|Destination token account does not belong/);
});

test('signature: rejects extra SPL payment legs after required transfer is matched', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const [expectedAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const attacker = await generateKeyPairSigner();
    const [attackerAta] = await findAssociatedTokenPda({
        owner: attacker.address,
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                splTransferIx(expectedAta, USDC_MINT, '1000000'),
                splTransferIx(attackerAta, USDC_MINT, '1'),
            ]),
        );

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/Unexpected Token Program instruction/);
});

test('signature: rejects ATA creation for owner not authorized by the challenge', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const payer = await generateKeyPairSigner();
    const extraOwner = await generateKeyPairSigner();
    const [recipientAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [extraAta] = await findAssociatedTokenPda({
        owner: extraOwner.address,
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                ataCreateIx({
                    account: extraAta,
                    mint: USDC_MINT,
                    owner: extraOwner.address,
                    payer: payer.address,
                }),
                splTransferIx(recipientAta, USDC_MINT, '1000000'),
            ]),
        );

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/ATA creation owner is not authorized/);
});

test('signature: rejects ATA creation for top-level recipient', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const payer = await generateKeyPairSigner();
    const [recipientAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess(
            txWithInstructions([
                ataCreateIx({
                    account: recipientAta,
                    mint: USDC_MINT,
                    owner: RECIPIENT,
                    payer: payer.address,
                }),
                splTransferIx(recipientAta, USDC_MINT, '1000000'),
            ]),
        );

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/ATA creation owner is not authorized/);
});

// ── Replay prevention (type="signature") ──

test('signature: rejects already-consumed transaction signature', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () => rpcSuccess(solTransferTx(RECIPIENT, 1000000));

    // First call succeeds
    await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
        request: {} as any,
    });

    // Second call with same signature is rejected
    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/already consumed/);
});

test('signature: concurrent requests with the same signature settle at most once', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    // Delay every fetch so all N verifies clear the pre-lock consumed check
    // and reach the on-chain verify at the same time: the exact TOCTOU window.
    // Without per-signature serialization all of them would settle (one payment,
    // N accesses); with it, exactly one wins.
    globalThis.fetch = (async () => {
        await new Promise(resolve => setTimeout(resolve, 20));
        return rpcSuccess(solTransferTx(RECIPIENT, 1000000));
    }) as typeof fetch;

    const verifyOnce = () =>
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        });

    const results = await Promise.allSettled(Array.from({ length: 8 }, verifyOnce));
    const settled = results.filter(r => r.status === 'fulfilled');
    const rejectedConsumed = results.filter(
        r => r.status === 'rejected' && /already consumed/.test(String((r as PromiseRejectedResult).reason)),
    );

    expect(settled).toHaveLength(1);
    expect(rejectedConsumed).toHaveLength(7);
});

// ── RPC error handling (type="signature") ──

test('signature: throws when transaction is not found', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () => rpcSuccess(null);

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/Transaction not found/);
});

test('signature: throws when transaction failed on-chain', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: { InstructionError: [0, 'Custom'] } },
            transaction: { message: { instructions: [] } },
            version: 0,
        });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/Transaction failed on-chain/);
});

test('signature: throws on RPC error response', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () => rpcError('Transaction version not supported');

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/RPC error/);
});

// ── Reported transaction version (type="signature") ──

test('signature: settles a legacy transaction reported by the RPC like a version-0 one', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    // A pre-cutover client's landed legacy transaction is policed as
    // version 0 and settles.
    globalThis.fetch = async () => rpcSuccess({ ...solTransferTx(RECIPIENT, 1000000), version: 'legacy' });
    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
        request: {} as any,
    });
    expect(receipt.status).toBe('success');
});

test('signature: rejects when the RPC does not report the transaction version', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const { version: _omitted, ...withoutVersion } = solTransferTx(RECIPIENT, 1000000);
    globalThis.fetch = async () => rpcSuccess(withoutVersion);

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow('RPC did not report the transaction version');
});

test('signature: rejects a transaction version outside the accepted set', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () => rpcSuccess({ ...solTransferTx(RECIPIENT, 1000000), version: 7 });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow('transaction version 7 is not accepted; accepted versions: 0, 1');
});

test.each([0, 1])('signature: accepts a version %i transaction reported by the RPC', async version => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () => rpcSuccess({ ...solTransferTx(RECIPIENT, 1000000), version });

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.reference).toBe(SIGNATURE);
});

test('signature: throws when no transfer instruction found (SOL)', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: { message: { instructions: [] } },
        });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No system transfer instruction found/);
});

test('signature: throws when no TransferChecked instruction found (SPL)', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: { message: { instructions: [] } },
        });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No TransferChecked instruction found/);
});

// ══════════════════════════════════════════════════════════════════════
// Pull mode (type="transaction")
// ══════════════════════════════════════════════════════════════════════

/**
 * Helper to mock fetch for pull mode flow.
 * The server makes 3 sequential RPC calls:
 *   1. sendTransaction → returns signature
 *   2. getSignatureStatuses → returns confirmed
 *   3. getTransaction → returns parsed tx for verification
 */
function mockServerBroadcastFetch(txResult: unknown, rpcMethods?: string[]) {
    globalThis.fetch = async (_url: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(init?.body as string);
        const method = body.method;
        rpcMethods?.push(method);

        if (method === 'simulateTransaction') {
            return rpcSuccess({ value: { err: null, logs: [] } });
        }

        if (method === 'sendTransaction') {
            return rpcSuccess(SIGNATURE);
        }

        if (method === 'getSignatureStatuses') {
            return rpcSuccess({
                value: [{ confirmationStatus: 'confirmed', err: null }],
            });
        }

        if (method === 'getTransaction') {
            return rpcSuccess(txResult);
        }

        throw new Error(`Unexpected RPC method: ${method}`);
    };
}

test('pull: accepts valid native SOL transfer', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000));
    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);

    const receipt = await method.verify({
        credential: transactionCredential(transaction, { amount: '1000000' }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.reference).toBe(transactionSignatureFromBase64(transaction));
});

test('pull: settles when the RPC reports the broadcast transaction as legacy', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    mockServerBroadcastFetch({ ...solTransferTx(RECIPIENT, 1000000), version: 'legacy' });
    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);

    const receipt = await method.verify({
        credential: transactionCredential(transaction, { amount: '1000000' }),
        request: {} as any,
    });
    expect(receipt.status).toBe('success');
});

test('pull: identical challenge-bound retry rejects a completed payment', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });
    const rpcMethods: string[] = [];
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000), rpcMethods);
    const credential = transactionCredential(await buildSolPaymentTxBase64(RECIPIENT, 1000000), {
        amount: '1000000',
    });

    const first = await method.verify({ credential, request: {} as any });
    expect(first.status).toBe('success');
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('already consumed');
    expect(rpcMethods.filter(method => method === 'simulateTransaction')).toHaveLength(1);
    expect(rpcMethods.filter(method => method === 'sendTransaction')).toHaveLength(1);
});

test('pull: concurrent credentials grant exactly one receipt and broadcast once', async () => {
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store });
    const rpcMethods: string[] = [];
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000), rpcMethods);
    const credential = transactionCredential(await buildSolPaymentTxBase64(RECIPIENT, 1000000), {
        amount: '1000000',
    });
    const outcomes = await Promise.allSettled(
        Array.from({ length: 16 }, () => method.verify({ credential, request: {} as any })),
    );
    expect(outcomes.filter(outcome => outcome.status === 'fulfilled')).toHaveLength(1);
    expect(rpcMethods.filter(method => method === 'sendTransaction')).toHaveLength(1);
});

test('pull: an uncertain settlement can recover once after its lease expires without rebroadcast', async () => {
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store });
    const rpcMethods: string[] = [];
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000), rpcMethods);
    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);
    const credential = transactionCredential(transaction, { amount: '1000000' });
    const key = consumedSignatureKey(transactionSignatureFromBase64(transaction));
    await store.put(key, {
        binding: JSON.stringify({
            challengeId: credential.challenge.id ?? null,
            request: credential.challenge.request,
        }),
        leaseUntil: 0,
        state: 'pending',
    });

    await expect(method.verify({ credential, request: {} as any })).resolves.toMatchObject({ status: 'success' });
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('already consumed');
    expect(rpcMethods).not.toContain('simulateTransaction');
    expect(rpcMethods).not.toContain('sendTransaction');
});

// A signature copied from any landed transaction must not name the charge:
// the node refuses a forged one without a preflight result, it would stay
// pending, and recovery would confirm the status of the transaction that owns
// it. It is refused before anything is claimed or sent.
test('pull: a forged client signature is refused before it is claimed', async () => {
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store });
    const signed = await buildSolPaymentTxBase64(RECIPIENT, 1000000);
    const wire = Buffer.from(signed, 'base64');
    wire.fill(7, 1, 65);
    const forged = wire.toString('base64');
    const rpcMethods: string[] = [];
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000), rpcMethods);
    for (let attempt = 0; attempt < 2; attempt++) {
        await expect(
            method.verify({ credential: transactionCredential(forged, { amount: '1000000' }), request: {} as any }),
        ).rejects.toThrow('signature verification failed');
    }
    expect(rpcMethods).not.toContain('sendTransaction');
    expect(await store.get(consumedSignatureKey(transactionSignatureFromBase64(forged)))).toBeNull();

    // Positive control: the transaction as really signed settles.
    await expect(
        method.verify({ credential: transactionCredential(signed, { amount: '1000000' }), request: {} as any }),
    ).resolves.toMatchObject({ status: 'success' });
});

test('pull: recovers an accepted send with a lost response exactly once without rebroadcast', async () => {
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store });
    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);
    const credential = transactionCredential(transaction, { amount: '1000000' });
    const key = consumedSignatureKey(transactionSignatureFromBase64(transaction));
    const rpcMethods: string[] = [];
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000), rpcMethods);
    const successfulFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
        const response = await successfulFetch(url, init);
        if (JSON.parse(init?.body as string).method === 'sendTransaction') {
            // The node accepted the wire transaction, but the HTTP response was lost.
            throw new Error('send response lost');
        }
        return response;
    };
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('send response lost');
    const pending = await store.get(key);
    expect(pending).toMatchObject({ state: 'pending' });
    // The lease lapses on the ledger key and its legacy mirror alike.
    await store.put(key, { ...(pending as object), leaseUntil: 0 });
    const legacy = legacyConsumedSignatureKey(transactionSignatureFromBase64(transaction));
    await store.put(legacy, { ...((await store.get(legacy)) as object), leaseUntil: 0 });
    globalThis.fetch = successfulFetch;

    await expect(method.verify({ credential, request: {} as any })).resolves.toMatchObject({ status: 'success' });
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('already consumed');
    expect(rpcMethods.filter(method => method === 'sendTransaction')).toHaveLength(1);
    expect(rpcMethods.filter(method => method === 'simulateTransaction')).toHaveLength(1);
});

test('push cannot overwrite a pull reservation after passing its initial replay check', async () => {
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store });
    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);
    const signature = transactionSignatureFromBase64(transaction);
    const key = consumedSignatureKey(signature);
    const rpcMethods: string[] = [];
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000), rpcMethods);
    const successfulFetch = globalThis.fetch;
    function deferred() {
        let resolve!: () => void;
        const promise = new Promise<void>(done => {
            resolve = done;
        });
        return { promise, resolve };
    }
    const pushEntered = deferred();
    const releasePush = deferred();
    const pullReserved = deferred();
    const releasePull = deferred();
    let firstRead = true;
    globalThis.fetch = async (url, init) => {
        const rpcMethod = JSON.parse(init?.body as string).method;
        if (rpcMethod === 'getTransaction' && firstRead) {
            firstRead = false;
            pushEntered.resolve();
            await releasePush.promise;
        }
        if (rpcMethod === 'sendTransaction') {
            pullReserved.resolve();
            await releasePull.promise;
        }
        return successfulFetch(url, init);
    };
    const push = method.verify({
        credential: signatureCredential(signature, { amount: '1000000' }),
        request: {} as any,
    });
    const pushRejected = expect(push).rejects.toThrow('already consumed');
    await pushEntered.promise;
    const pull = method.verify({
        credential: transactionCredential(transaction, { amount: '1000000' }),
        request: {} as any,
    });
    await pullReserved.promise;
    const pending = await store.get(key);
    expect(pending).toMatchObject({ state: 'pending' });
    releasePush.resolve();
    await pushRejected;
    expect(await store.get(key)).toEqual(pending);
    releasePull.resolve();
    await expect(pull).resolves.toMatchObject({ status: 'success' });
    await expect(
        method.verify({
            credential: signatureCredential(signature, { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow('already consumed');
    expect(rpcMethods.filter(method => method === 'sendTransaction')).toHaveLength(1);
});

test.each([false, true])('pull: atomic consumption failure grants no receipt (committed=%s)', async committed => {
    type AtomicStore = Store.Store & {
        update<T>(
            key: string,
            fn: (current: unknown) => { op: 'noop'; result: T } | { op: 'set'; result: T; value: unknown },
        ): Promise<T>;
    };
    const atomicStore = store as AtomicStore;
    const update = atomicStore.update.bind(atomicStore);
    let updates = 0;
    let fail = true;
    const failingStore: AtomicStore = {
        ...store,
        async update(key, fn) {
            updates++;
            // Updates: claim, legacy claim, grant begin, legacy consume, ledger consume.
            if (!fail || updates !== 5) return update(key, fn);
            if (committed) await update(key, fn);
            await Promise.resolve();
            throw new Error('atomic storage unavailable');
        },
    };
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store: failingStore });
    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);
    const credential = transactionCredential(transaction, { amount: '1000000' });
    const key = consumedSignatureKey(transactionSignatureFromBase64(transaction));
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000));
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('atomic storage unavailable');
    expect(await store.get(key)).toMatchObject({ state: committed ? 'confirmed' : 'granting' });
    fail = false;
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow(
        committed ? 'already consumed' : 'already in progress',
    );
});

// The two keys of a grant cannot change atomically. A store failure after
// the previous release's key was consumed but before the ledger key leaves a
// confirmed payment without a receipt; the ledger record says a grant began,
// so once its lease lapses the identical retry finishes it, exactly once.
test('pull: a grant interrupted between its two keys is finished by the retry', async () => {
    type AtomicStore = Store.Store & {
        update<T>(
            key: string,
            fn: (current: unknown) => { op: 'noop'; result: T } | { op: 'set'; result: T; value: unknown },
        ): Promise<T>;
    };
    const atomicStore = store as AtomicStore;
    const update = atomicStore.update.bind(atomicStore);
    let updates = 0;
    let fail = true;
    const failingStore: AtomicStore = {
        ...store,
        async update(key, fn) {
            updates++;
            // Updates: claim, legacy claim, grant begin, legacy consume, ledger consume.
            if (fail && updates === 5) throw new Error('atomic storage unavailable');
            return update(key, fn);
        },
    };
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store: failingStore });
    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);
    const credential = transactionCredential(transaction, { amount: '1000000' });
    const signature = transactionSignatureFromBase64(transaction);
    const key = consumedSignatureKey(signature);
    const legacy = legacyConsumedSignatureKey(signature);
    const rpcMethods: string[] = [];
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000), rpcMethods);
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('atomic storage unavailable');
    expect(await store.get(legacy)).toMatchObject({ state: 'confirmed' });
    expect(await store.get(key)).toMatchObject({ state: 'granting' });

    fail = false;
    for (const lapsed of [key, legacy]) {
        await store.put(lapsed, { ...((await store.get(lapsed)) as object), leaseUntil: 0 });
    }
    await expect(method.verify({ credential, request: {} as any })).resolves.toMatchObject({ status: 'success' });
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('already consumed');
    expect(rpcMethods.filter(m => m === 'sendTransaction')).toHaveLength(1);
});

// A grant can stop after marking the ledger record granting and before it
// confirms the legacy key. If a previous-release replica then recovers the
// legacy record and confirms (and serves) it, the retry must not take that
// confirmation for its own: only the grant id written with the confirmation
// proves ownership.
test('pull: a legacy key confirmed by an old replica during a grant stays consumed', async () => {
    type AtomicStore = Store.Store & {
        update<T>(
            key: string,
            fn: (current: unknown) => { op: 'noop'; result: T } | { op: 'set'; result: T; value: unknown },
        ): Promise<T>;
    };
    const atomicStore = store as AtomicStore;
    const update = atomicStore.update.bind(atomicStore);
    let updates = 0;
    let fail = true;
    const failingStore: AtomicStore = {
        ...store,
        async update(key, fn) {
            updates++;
            // Updates: claim, legacy claim, grant begin, legacy confirm, ledger consume.
            if (fail && updates === 4) throw new Error('atomic storage unavailable');
            return update(key, fn);
        },
    };
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store: failingStore });
    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);
    const credential = transactionCredential(transaction, { amount: '1000000' });
    const signature = transactionSignatureFromBase64(transaction);
    const key = consumedSignatureKey(signature);
    const legacy = legacyConsumedSignatureKey(signature);
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000));
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('atomic storage unavailable');
    expect(await store.get(key)).toMatchObject({ state: 'granting' });
    expect(await store.get(legacy)).toMatchObject({ state: 'pending' });

    // The previous release recovers the legacy record and serves it: it
    // confirms the key the way it always did, with no grant id.
    const pending = (await store.get(legacy)) as object;
    await store.put(legacy, { ...pending, leaseUntil: 0, state: 'confirmed' });
    await store.put(key, { ...((await store.get(key)) as object), leaseUntil: 0 });
    fail = false;
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('already consumed');
});

// Without that ownership record a confirmed legacy key is someone else's
// grant (a replica on the previous release): it is never granted again.
test('pull: a legacy key confirmed by another grant stays consumed', async () => {
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store });
    const transaction = await buildSolPaymentTxBase64(RECIPIENT, 1000000);
    const credential = transactionCredential(transaction, { amount: '1000000' });
    const signature = transactionSignatureFromBase64(transaction);
    const key = consumedSignatureKey(signature);
    const legacy = legacyConsumedSignatureKey(signature);
    mockServerBroadcastFetch(solTransferTx(RECIPIENT, 1000000));
    const successfulFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
        const response = await successfulFetch(url, init);
        if (JSON.parse(init?.body as string).method === 'sendTransaction') throw new Error('send response lost');
        return response;
    };
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('send response lost');
    globalThis.fetch = successfulFetch;
    // A previous-release replica recovered the legacy record and served it.
    const pending = (await store.get(legacy)) as object;
    await store.put(legacy, { ...pending, leaseUntil: 0, state: 'confirmed' });
    await store.put(key, { ...((await store.get(key)) as object), leaseUntil: 0 });
    await expect(method.verify({ credential, request: {} as any })).rejects.toThrow('already consumed');
});

test('pull: accepts native SOL externalId memo pre-broadcast and on-chain', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    mockServerBroadcastFetch(
        txWithInstructions([
            { program: 'system', parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 1000000 } } },
            memoIx('order-123'),
        ]),
    );

    const receipt = await method.verify({
        credential: transactionCredential(
            await buildSolPaymentTxBase64(RECIPIENT, 1000000, { externalId: 'order-123' }),
            {
                amount: '1000000',
                externalId: 'order-123',
            },
        ),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.externalId).toBe('order-123');
});

test('pull: rejects native SOL externalId memo when missing pre-broadcast', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    mockServerBroadcastFetch(txWithInstructions([]));

    await expect(
        method.verify({
            credential: transactionCredential(await buildSolPaymentTxBase64(RECIPIENT, 1000000), {
                amount: '1000000',
                externalId: 'order-123',
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found for externalId memo/);
});

test('pull: accepts native SOL split memo pre-broadcast and on-chain', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    mockServerBroadcastFetch(
        txWithInstructions([
            { program: 'system', parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } } },
            { program: 'system', parsed: { type: 'transfer', info: { destination: PLATFORM, lamports: 50000 } } },
            memoIx('platform fee'),
        ]),
    );

    const receipt = await method.verify({
        credential: transactionCredential(await buildSolPaymentTxBase64(RECIPIENT, 950000, { splits }), {
            amount: '1000000',
            splits,
        }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('pull: rejects native SOL split when requested memo is missing pre-broadcast', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    mockServerBroadcastFetch(txWithInstructions([]));

    await expect(
        method.verify({
            credential: transactionCredential(
                await buildSolPaymentTxBase64(RECIPIENT, 950000, {
                    splits: [{ recipient: PLATFORM, amount: '50000' }],
                }),
                { amount: '1000000', splits },
            ),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found/);
});

test('pull: accepts valid SPL token transfer', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const [expectedAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    mockServerBroadcastFetch(splTransferTx(expectedAta, USDC_MINT, '1000000'));

    const transaction = await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '1000000');
    const receipt = await method.verify({
        credential: transactionCredential(transaction, {
            amount: '1000000',
            currency: USDC_MINT,
            decimals: 6,
        }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.reference).toBe(transactionSignatureFromBase64(transaction));
});

test('pull: accepts SPL externalId memo pre-broadcast and on-chain', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const [expectedAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    mockServerBroadcastFetch(
        txWithInstructions([splTransferIx(expectedAta, USDC_MINT, '1000000'), memoIx('order-123')]),
    );

    const receipt = await method.verify({
        credential: transactionCredential(
            await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '1000000', 6, TOKEN_PROGRAM, {
                externalId: 'order-123',
            }),
            {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
                externalId: 'order-123',
            },
        ),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.externalId).toBe('order-123');
});

test('pull: rejects SPL externalId memo when missing pre-broadcast', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    mockServerBroadcastFetch(txWithInstructions([]));

    await expect(
        method.verify({
            credential: transactionCredential(await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '1000000'), {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
                externalId: 'order-123',
            }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found for externalId memo/);
});

test('pull: accepts SPL split memo pre-broadcast and on-chain', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        owner: address(PLATFORM),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    mockServerBroadcastFetch(
        txWithInstructions([
            splTransferIx(recipientAta, USDC_MINT, '950000'),
            splTransferIx(platformAta, USDC_MINT, '50000'),
            memoIx('platform fee'),
        ]),
    );

    const receipt = await method.verify({
        credential: transactionCredential(
            await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '950000', 6, TOKEN_PROGRAM, { splits }),
            {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
                splits,
            },
        ),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('pull: rejects SPL split when requested memo is missing pre-broadcast', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    mockServerBroadcastFetch(txWithInstructions([]));

    await expect(
        method.verify({
            credential: transactionCredential(
                await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '950000', 6, TOKEN_PROGRAM, {
                    splits: [{ recipient: PLATFORM, amount: '50000' }],
                }),
                {
                    amount: '1000000',
                    currency: USDC_MINT,
                    decimals: 6,
                    splits,
                },
            ),
            request: {} as any,
        }),
    ).rejects.toThrow(/No memo instruction found/);
});

test('client buildChargeTransaction creates verifier-compatible SPL transaction', async () => {
    const signer = await generateKeyPairSigner();
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    const [expectedAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    mockServerBroadcastFetch(splTransferTx(expectedAta, USDC_MINT, '1000000'));

    const tx = await buildChargeTransaction({
        request: {
            amount: '1000000',
            currency: USDC_MINT,
            recipient: RECIPIENT,
            methodDetails: {
                decimals: 6,
                network: 'devnet',
                recentBlockhash: BLOCKHASH,
                tokenProgram: TOKEN_PROGRAM,
            },
        },
        rpcUrl: 'https://mock-rpc',
        signer,
    });

    const receipt = await method.verify({
        credential: transactionCredential(tx, {
            amount: '1000000',
            currency: USDC_MINT,
            decimals: 6,
            tokenProgram: TOKEN_PROGRAM,
        }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.reference).toBe(transactionSignatureFromBase64(tx));
});

test('pull: accepts fee payer split recipient ATA creation', async () => {
    const signer = await generateKeyPairSigner();
    const splits = [{ recipient: PLATFORM, amount: '50000', ataCreationRequired: true }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        signer,
        splits,
        store,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        owner: address(PLATFORM),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    mockServerBroadcastFetch(
        txWithInstructions([
            splTransferIx(recipientAta, USDC_MINT, '950000'),
            ataCreateIx({ account: platformAta, mint: USDC_MINT, owner: PLATFORM, payer: signer.address }),
            splTransferIx(platformAta, USDC_MINT, '50000'),
        ]),
    );

    const receipt = await method.verify({
        credential: transactionCredential(
            await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '950000', 6, TOKEN_PROGRAM, {
                feePayerKey: signer.address,
                splits,
            }),
            {
                amount: '1000000',
                currency: USDC_MINT,
                decimals: 6,
                feePayer: true,
                feePayerKey: signer.address,
                splits,
            },
        ),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('pull: rejects fee payer split ATA creation for top-level recipient', async () => {
    const signer = await generateKeyPairSigner();
    const splits = [{ recipient: PLATFORM, amount: '50000', ataCreationRequired: true }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        signer,
        splits,
        store,
    });

    mockServerBroadcastFetch(txWithInstructions([]));

    await expect(
        method.verify({
            credential: transactionCredential(
                await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '950000', 6, TOKEN_PROGRAM, {
                    extraAtaOwners: [RECIPIENT],
                    feePayerKey: signer.address,
                    splits,
                }),
                {
                    amount: '1000000',
                    currency: USDC_MINT,
                    decimals: 6,
                    feePayer: true,
                    feePayerKey: signer.address,
                    splits,
                },
            ),
            request: {} as any,
        }),
    ).rejects.toThrow(/not authorized/);
});

test('pull: rejects client-paid ATA creation for top-level recipient', async () => {
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    mockServerBroadcastFetch(txWithInstructions([]));

    await expect(
        method.verify({
            credential: transactionCredential(
                await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '1000000', 6, TOKEN_PROGRAM, {
                    extraAtaOwners: [RECIPIENT],
                }),
                {
                    amount: '1000000',
                    currency: USDC_MINT,
                    decimals: 6,
                },
            ),
            request: {} as any,
        }),
    ).rejects.toThrow(/not authorized/);
});

test('pull: rejects fee payer split challenge when pre-broadcast tx omits required split ATA', async () => {
    const signer = await generateKeyPairSigner();
    const splits = [{ recipient: PLATFORM, amount: '50000', ataCreationRequired: true }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        signer,
        splits,
        store,
    });

    mockServerBroadcastFetch(txWithInstructions([]));

    await expect(
        method.verify({
            credential: transactionCredential(
                await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '950000', 6, TOKEN_PROGRAM, {
                    feePayerKey: signer.address,
                    skipAtaCreationFor: [PLATFORM],
                    splits,
                }),
                {
                    amount: '1000000',
                    currency: USDC_MINT,
                    decimals: 6,
                    feePayer: true,
                    feePayerKey: signer.address,
                    splits,
                },
            ),
            request: {} as any,
        }),
    ).rejects.toThrow(/Missing required ATA creation/);
});

test('pull: rejects split ATA creation when challenge currency is a stablecoin symbol', async () => {
    const signer = await generateKeyPairSigner();
    const splits = [{ recipient: PLATFORM, amount: '50000', ataCreationRequired: true }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        signer,
        splits,
        store,
    });

    mockServerBroadcastFetch(txWithInstructions([]));

    await expect(
        method.verify({
            credential: transactionCredential(
                await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '950000', 6, TOKEN_PROGRAM, {
                    feePayerKey: signer.address,
                    splits,
                }),
                {
                    amount: '1000000',
                    currency: 'USDC',
                    decimals: 6,
                    feePayer: true,
                    feePayerKey: signer.address,
                    splits,
                },
            ),
            request: {} as any,
        }),
    ).rejects.toThrow(/mint address/);
});

test('pull: rejects fee payer split challenge when post-broadcast tx omits required split ATA', async () => {
    const signer = await generateKeyPairSigner();
    const splits = [{ recipient: PLATFORM, amount: '50000', ataCreationRequired: true }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        signer,
        splits,
        store,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        owner: address(RECIPIENT),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        owner: address(PLATFORM),
        mint: address(USDC_MINT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    mockServerBroadcastFetch(
        txWithInstructions([
            splTransferIx(recipientAta, USDC_MINT, '950000'),
            splTransferIx(platformAta, USDC_MINT, '50000'),
        ]),
    );

    await expect(
        method.verify({
            credential: transactionCredential(
                await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '950000', 6, TOKEN_PROGRAM, {
                    feePayerKey: signer.address,
                    splits,
                }),
                {
                    amount: '1000000',
                    currency: USDC_MINT,
                    decimals: 6,
                    feePayer: true,
                    feePayerKey: signer.address,
                    splits,
                },
            ),
            request: {} as any,
        }),
    ).rejects.toThrow(/Missing required ATA creation/);
});

test('transaction: rejects when sendTransaction fails', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    globalThis.fetch = async () => rpcError('Transaction simulation failed');

    await expect(
        method.verify({
            credential: transactionCredential(await buildSolPaymentTxBase64(RECIPIENT, 1000000), { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/RPC error/);
});

test('transaction: rejects when on-chain verification fails (wrong recipient)', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    mockServerBroadcastFetch(solTransferTx('WrongRecipient111111111111111111111', 1000000));

    await expect(
        method.verify({
            credential: transactionCredential(await buildSolPaymentTxBase64(RECIPIENT, 1000000), { amount: '1000000' }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No.*transfer.*instruction.*found|Recipient mismatch/);
});

test('transaction: throws when transaction data is missing', async () => {
    const method = charge({
        recipient: RECIPIENT,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
    });

    await expect(
        method.verify({
            credential: {
                payload: { type: 'transaction' },
                challenge: {
                    request: {
                        amount: '1000000',
                        currency: 'sol',
                        recipient: RECIPIENT,
                        methodDetails: {
                            network: 'devnet',
                        },
                    },
                },
            } as any,
            request: {} as any,
        }),
    ).rejects.toThrow(/Missing transaction data/);
});

// ══════════════════════════════════════════════════════════════════════
// Splits
// ══════════════════════════════════════════════════════════════════════

const PLATFORM = '3pF8Kg2aHbNvJkLMwEqR7YtDxZ5sGhJn4UV6mWcXrT9A';

test('splits: charge() rejects more than 8 splits', () => {
    const splits = Array.from({ length: 9 }, () => ({
        recipient: PLATFORM,
        amount: '1000',
    }));
    expect(() => charge({ recipient: RECIPIENT, network: 'devnet', store, splits })).toThrow(/exceed 8/);
});

test('splits: request() includes splits in challenge', async () => {
    globalThis.fetch = async () =>
        rpcSuccess({
            value: { blockhash: 'MockBlockhash1111111111111111111111111111111', lastValidBlockHeight: 100 },
        });

    const splits = [{ recipient: PLATFORM, amount: '50000', memo: 'platform fee' }];
    const method = charge({ recipient: RECIPIENT, network: 'devnet', store, splits });

    const request = await method.request!({
        credential: null,
        request: { amount: '1050000', currency: 'sol', recipient: '', methodDetails: {} },
    });

    expect(request.methodDetails.splits).toBeTruthy();
    expect(request.methodDetails.splits!.length).toBe(1);
    expect(request.methodDetails.splits![0].recipient).toBe(PLATFORM);
    expect(request.methodDetails.splits![0].amount).toBe('50000');
    expect(request.methodDetails.splits![0].memo).toBe('platform fee');
});

test('request() includes split ATA creation requirements', async () => {
    globalThis.fetch = async () =>
        rpcSuccess({
            value: { blockhash: 'MockBlockhash1111111111111111111111111111111', lastValidBlockHeight: 100 },
        });

    const signer = await generateKeyPairSigner();
    const splits = [{ recipient: PLATFORM, amount: '50000', ataCreationRequired: true }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        signer,
        store,
        splits,
    });

    const request = await method.request!({
        credential: null,
        request: { amount: '1000000', currency: USDC_MINT, recipient: '', methodDetails: {} },
    });

    expect(request.methodDetails.feePayer).toBe(true);
    expect(request.methodDetails.feePayerKey).toBe(signer.address);
    expect(request.methodDetails.splits).toEqual(splits);
});

test('request() preserves unmarked splits in fee payer mode', async () => {
    globalThis.fetch = async () =>
        rpcSuccess({
            value: { blockhash: 'MockBlockhash1111111111111111111111111111111', lastValidBlockHeight: 100 },
        });

    const signer = await generateKeyPairSigner();
    const splits = [{ recipient: PLATFORM, amount: '50000' }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        signer,
        store,
        splits,
    });

    const request = await method.request!({
        credential: null,
        request: {
            amount: '1000000',
            currency: USDC_MINT,
            recipient: '',
            methodDetails: {},
        },
    });

    expect(request.methodDetails.feePayer).toBe(true);
    expect(request.methodDetails.splits).toEqual(splits);
});

test('request() defaults Token-2022 stablecoins to Token-2022', async () => {
    globalThis.fetch = async () =>
        rpcSuccess({
            value: { blockhash: 'MockBlockhash1111111111111111111111111111111', lastValidBlockHeight: 100 },
        });

    for (const currency of ['CASH', 'PYUSD', 'USDG']) {
        const method = charge({
            recipient: RECIPIENT,
            currency,
            decimals: 6,
            network: 'mainnet-beta',
            store,
        });

        const request = await method.request!({
            credential: null,
            request: { amount: '1000000', currency, recipient: '', methodDetails: {} },
        });

        expect(request.currency).toBe(currency);
        expect(request.methodDetails.tokenProgram).toBe(TOKEN_2022_PROGRAM);
    }

    expect(CASH.mainnet).toBe('CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH');
    expect(PYUSD.mainnet).toBe('2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo');
    expect(USDG.mainnet).toBe('2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH');
});

test('splits: SOL verification passes with valid primary + split transfers', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000' }];
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store, splits });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } },
                        },
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: PLATFORM, lamports: 50000 } },
                        },
                    ],
                },
            },
        });

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('splits: SOL verification fails when split transfer missing', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000' }];
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store, splits });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } },
                        },
                    ],
                },
            },
        });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No.*transfer.*instruction.*found.*3pF8/);
});

test('splits: SOL verification fails when split amount is wrong', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000' }];
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store, splits });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } },
                        },
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: PLATFORM, lamports: 25000 } },
                        },
                    ],
                },
            },
        });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No system transfer instruction found.*3pF8/);
});

test('splits: SOL verification matches distinct same-recipient transfers by amount', async () => {
    const duplicateRecipient = PLATFORM;
    const splits = [{ recipient: duplicateRecipient, amount: '50000' }];
    const method = charge({
        recipient: duplicateRecipient,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: duplicateRecipient, lamports: 950000 } },
                        },
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: duplicateRecipient, lamports: 50000 } },
                        },
                    ],
                },
            },
        });

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000', recipient: duplicateRecipient, splits }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('splits: rejects splits that consume entire amount', async () => {
    const splits = [{ recipient: PLATFORM, amount: '1000000' }];
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store, splits });

    globalThis.fetch = async () =>
        rpcSuccess({ meta: { err: null }, version: 0, transaction: { message: { instructions: [] } } });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/primary recipient must receive a positive amount/);
});

test('splits: rejects splits that exceed total amount', async () => {
    const splits = [{ recipient: PLATFORM, amount: '2000000' }];
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store, splits });

    globalThis.fetch = async () =>
        rpcSuccess({ meta: { err: null }, version: 0, transaction: { message: { instructions: [] } } });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/primary recipient must receive a positive amount/);
});

test('splits: SPL verification passes with valid primary + split transfers', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000' }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(PLATFORM),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: recipientAta, mint: USDC_MINT, tokenAmount: { amount: '950000' } },
                            },
                        },
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: platformAta, mint: USDC_MINT, tokenAmount: { amount: '50000' } },
                            },
                        },
                    ],
                },
            },
        });

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000', currency: USDC_MINT, decimals: 6, splits }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('splits: SPL verification fails when split transfer is missing', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000' }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: recipientAta, mint: USDC_MINT, tokenAmount: { amount: '950000' } },
                            },
                        },
                    ],
                },
            },
        });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', currency: USDC_MINT, decimals: 6, splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No TransferChecked instruction found.*3pF8/);
});

test('splits: SPL verification fails when primary amount is wrong', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000' }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(PLATFORM),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: {
                                    destination: recipientAta,
                                    mint: USDC_MINT,
                                    tokenAmount: { amount: '1000000' },
                                },
                            },
                        },
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: platformAta, mint: USDC_MINT, tokenAmount: { amount: '50000' } },
                            },
                        },
                    ],
                },
            },
        });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', currency: USDC_MINT, decimals: 6, splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No TransferChecked instruction found.*9xAX/);
});

test('splits: SPL verification fails when split amount is wrong', async () => {
    const splits = [{ recipient: PLATFORM, amount: '50000' }];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(PLATFORM),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: recipientAta, mint: USDC_MINT, tokenAmount: { amount: '950000' } },
                            },
                        },
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: platformAta, mint: USDC_MINT, tokenAmount: { amount: '25000' } },
                            },
                        },
                    ],
                },
            },
        });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', currency: USDC_MINT, decimals: 6, splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No TransferChecked instruction found.*3pF8/);
});

test('splits: SPL verification matches distinct same-recipient transfers by amount', async () => {
    const duplicateRecipient = PLATFORM;
    const splits = [{ recipient: duplicateRecipient, amount: '50000' }];
    const method = charge({
        recipient: duplicateRecipient,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [duplicateAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(duplicateRecipient),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: duplicateAta, mint: USDC_MINT, tokenAmount: { amount: '950000' } },
                            },
                        },
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: duplicateAta, mint: USDC_MINT, tokenAmount: { amount: '50000' } },
                            },
                        },
                    ],
                },
            },
        });

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, {
            amount: '1000000',
            currency: USDC_MINT,
            recipient: duplicateRecipient,
            decimals: 6,
            splits,
        }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('splits: multiple splits with SPL', async () => {
    const REFERRER = '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';
    const splits = [
        { recipient: PLATFORM, amount: '30000' },
        { recipient: REFERRER, amount: '20000' },
    ];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(PLATFORM),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [referrerAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(REFERRER),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: recipientAta, mint: USDC_MINT, tokenAmount: { amount: '950000' } },
                            },
                        },
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: platformAta, mint: USDC_MINT, tokenAmount: { amount: '30000' } },
                            },
                        },
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: referrerAta, mint: USDC_MINT, tokenAmount: { amount: '20000' } },
                            },
                        },
                    ],
                },
            },
        });

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000', currency: USDC_MINT, decimals: 6, splits }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

test('splits: duplicate SOL recipients require distinct transfer instructions', async () => {
    const splits = [
        { recipient: PLATFORM, amount: '30000' },
        { recipient: PLATFORM, amount: '20000' },
    ];
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store, splits });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } },
                        },
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: PLATFORM, lamports: 30000 } },
                        },
                    ],
                },
            },
        });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No system transfer instruction found.*3pF8/);
});

test('splits: duplicate SPL recipients require distinct transfer instructions', async () => {
    const splits = [
        { recipient: PLATFORM, amount: '30000' },
        { recipient: PLATFORM, amount: '20000' },
    ];
    const method = charge({
        recipient: RECIPIENT,
        currency: USDC_MINT,
        decimals: 6,
        network: 'devnet',
        rpcUrl: 'https://mock-rpc',
        store,
        splits,
    });

    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const [platformAta] = await findAssociatedTokenPda({
        mint: address(USDC_MINT),
        owner: address(PLATFORM),
        tokenProgram: address(TOKEN_PROGRAM),
    });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: recipientAta, mint: USDC_MINT, tokenAmount: { amount: '950000' } },
                            },
                        },
                        {
                            programId: TOKEN_PROGRAM,
                            parsed: {
                                type: 'transferChecked',
                                info: { destination: platformAta, mint: USDC_MINT, tokenAmount: { amount: '30000' } },
                            },
                        },
                    ],
                },
            },
        });

    await expect(
        method.verify({
            credential: signatureCredential(SIGNATURE, { amount: '1000000', currency: USDC_MINT, decimals: 6, splits }),
            request: {} as any,
        }),
    ).rejects.toThrow(/No TransferChecked instruction found.*3pF8/);
});

test('splits: multiple splits with SOL', async () => {
    const REFERRER = '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';
    const splits = [
        { recipient: PLATFORM, amount: '30000' },
        { recipient: REFERRER, amount: '20000' },
    ];
    const method = charge({ recipient: RECIPIENT, network: 'devnet', rpcUrl: 'https://mock-rpc', store, splits });

    globalThis.fetch = async () =>
        rpcSuccess({
            meta: { err: null },
            version: 0,
            transaction: {
                message: {
                    instructions: [
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: RECIPIENT, lamports: 950000 } },
                        },
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: PLATFORM, lamports: 30000 } },
                        },
                        {
                            program: 'system',
                            parsed: { type: 'transfer', info: { destination: REFERRER, lamports: 20000 } },
                        },
                    ],
                },
            },
        });

    const receipt = await method.verify({
        credential: signatureCredential(SIGNATURE, { amount: '1000000', splits }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
});

// ── Audit fix coverage ──────────────────────────────────────────────────────

// #37 — network allowlist at boot
test('#37 charge() rejects an unknown network slug at construction', () => {
    expect(() => charge({ recipient: RECIPIENT, network: 'testnet' })).toThrow(/Unsupported network/);
});

test('#37 charge() rejects an empty network slug', () => {
    expect(() => charge({ recipient: RECIPIENT, network: '' })).toThrow(/must not be empty/);
});

test('#37 charge() accepts the canonical networks and the mainnet-beta alias', () => {
    for (const network of ['mainnet', 'devnet', 'localnet', 'mainnet-beta']) {
        expect(() => charge({ recipient: RECIPIENT, network })).not.toThrow();
    }
});

// #21 — split validation at issuance
test('#21 charge() rejects more than 8 splits at issuance', () => {
    const splits = Array.from({ length: 9 }, () => ({ recipient: PLATFORM, amount: '1' }));
    expect(() => charge({ recipient: RECIPIENT, network: 'devnet', splits })).toThrow(/cannot exceed 8/);
});

test('#21 charge() rejects an unparseable split recipient at issuance', () => {
    const splits = [{ recipient: 'not-a-pubkey!!!', amount: '100' }];
    expect(() => charge({ recipient: RECIPIENT, network: 'devnet', splits })).toThrow(/Invalid split recipient/);
});

test('#21 charge() rejects a zero/negative split amount at issuance', () => {
    expect(() =>
        charge({ recipient: RECIPIENT, network: 'devnet', splits: [{ recipient: PLATFORM, amount: '0' }] }),
    ).toThrow(/must be positive/);
});

test('#21 charge() accepts a valid split set at issuance', () => {
    expect(() =>
        charge({ recipient: RECIPIENT, network: 'devnet', splits: [{ recipient: PLATFORM, amount: '100' }] }),
    ).not.toThrow();
});

// #38 — primary recipient in splits + ataCreationRequired in fee-sponsored mode
test('#38 charge() rejects a primary-recipient split with ataCreationRequired in fee-sponsored mode', async () => {
    const signer = await generateKeyPairSigner();
    const splits = [{ recipient: RECIPIENT, amount: '50000', ataCreationRequired: true }];
    expect(() =>
        charge({ recipient: RECIPIENT, currency: USDC_MINT, decimals: 6, network: 'devnet', signer, splits }),
    ).toThrow(/primary recipient must not set ataCreationRequired/);
});

test('#38 charge() allows a primary-recipient split WITHOUT ataCreationRequired in fee-sponsored mode', async () => {
    const signer = await generateKeyPairSigner();
    const splits = [{ recipient: RECIPIENT, amount: '50000' }];
    expect(() =>
        charge({ recipient: RECIPIENT, currency: USDC_MINT, decimals: 6, network: 'devnet', signer, splits }),
    ).not.toThrow();
});

test('#38 charge() allows a primary-recipient split with ataCreationRequired in client-paid mode (no signer)', () => {
    const splits = [{ recipient: RECIPIENT, amount: '50000', ataCreationRequired: true }];
    expect(() =>
        charge({ recipient: RECIPIENT, currency: USDC_MINT, decimals: 6, network: 'devnet', splits }),
    ).not.toThrow();
});

// #25 — fee-sponsored compute-unit price cap
async function buildSolTxWithComputePrice(feePayerKey: string, microLamports: bigint) {
    const authority = await generateKeyPairSigner();
    const instructions: Instruction[] = [
        getSetComputeUnitPriceInstruction({ microLamports }),
        getTransferSolInstruction({ source: authority, destination: address(RECIPIENT), amount: 1_000_000n }),
    ];
    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayer(address(feePayerKey), msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );
    return getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(txMessage));
}

test('#25 fee-sponsored compute-unit price above the tight cap is rejected', async () => {
    const signer = await generateKeyPairSigner();
    const tx = await buildSolTxWithComputePrice(signer.address, 20_000n);
    await expect(
        verifyChargeTransaction(tx, {
            amount: '1000000',
            currency: 'sol',
            methodDetails: { network: 'devnet', feePayer: true, feePayerKey: signer.address },
            recipient: RECIPIENT,
        }),
    ).rejects.toThrow(/Compute unit price.*exceeds maximum 10000/);
});

test('#25 fee-sponsored compute-unit price under the tight cap passes', async () => {
    const signer = await generateKeyPairSigner();
    const tx = await buildSolTxWithComputePrice(signer.address, 5_000n);
    await expect(
        verifyChargeTransaction(tx, {
            amount: '1000000',
            currency: 'sol',
            methodDetails: { network: 'devnet', feePayer: true, feePayerKey: signer.address },
            recipient: RECIPIENT,
        }),
    ).resolves.toBeUndefined();
});

// A sponsor pays a signature fee per required signer, so every leg of a split
// must be funded by one authority, and no signer may ride along that funds
// nothing.
async function buildSponsoredSolSplitTx(
    feePayerKey: string,
    splitRecipient: string,
    options: { extraSigner?: boolean; splitPayer?: 'other' | 'same' } = {},
) {
    const payer = await generateKeyPairSigner();
    const splitPayer = options.splitPayer === 'other' ? await generateKeyPairSigner() : payer;
    const primary = getTransferSolInstruction({ source: payer, destination: address(RECIPIENT), amount: 800_000n });
    const extra = await generateKeyPairSigner();
    const instructions: Instruction[] = [
        options.extraSigner
            ? ({
                  ...primary,
                  accounts: [
                      ...primary.accounts,
                      { address: extra.address, role: AccountRole.READONLY_SIGNER, signer: extra },
                  ],
              } as Instruction)
            : primary,
        getTransferSolInstruction({ source: splitPayer, destination: address(splitRecipient), amount: 200_000n }),
    ];
    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayer(address(feePayerKey), msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );
    return getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(txMessage));
}

test('sponsored split legs must share one funding authority and carry no extra signer', async () => {
    const feePayer = await generateKeyPairSigner();
    const splitRecipient = (await generateKeyPairSigner()).address;
    const request = {
        amount: '1000000',
        currency: 'sol',
        methodDetails: {
            network: 'devnet',
            feePayer: true,
            feePayerKey: feePayer.address,
            splits: [{ amount: '200000', recipient: splitRecipient }],
        },
        recipient: RECIPIENT,
    };

    await expect(
        verifyChargeTransaction(
            await buildSponsoredSolSplitTx(feePayer.address, splitRecipient, { splitPayer: 'other' }),
            request,
        ),
    ).rejects.toThrow('Payment transfers must share one funding authority');
    await expect(
        verifyChargeTransaction(
            await buildSponsoredSolSplitTx(feePayer.address, splitRecipient, { extraSigner: true }),
            request,
        ),
    ).rejects.toThrow('Unexpected signer in payment transaction');
    await expect(
        verifyChargeTransaction(await buildSponsoredSolSplitTx(feePayer.address, splitRecipient), request),
    ).resolves.toBeUndefined();
});

async function buildSponsoredSplitTx(feePayerKey: string, budget: Instruction[]) {
    const authority = await generateKeyPairSigner();
    const instructions: Instruction[] = [
        ...budget,
        getTransferSolInstruction({ source: authority, destination: address(RECIPIENT), amount: 950_000n }),
        getTransferSolInstruction({ source: authority, destination: address(PLATFORM), amount: 50_000n }),
    ];
    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayer(address(feePayerKey), msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );
    return getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(txMessage));
}

test('fee-sponsored priority fee is bounded across limit and price, including the implicit limit', async () => {
    const signer = await generateKeyPairSigner();
    const request = {
        amount: '1000000',
        currency: 'sol',
        methodDetails: {
            feePayer: true,
            feePayerKey: signer.address,
            network: 'devnet',
            splits: [{ amount: '50000', recipient: PLATFORM }],
        },
        recipient: RECIPIENT,
    };
    // No limit: two transfers are budgeted 400_000 CU, so 10_000 µL/CU is 4_000 lamports.
    const implicit = await buildSponsoredSplitTx(signer.address, [
        getSetComputeUnitPriceInstruction({ microLamports: 10_000n }),
    ]);
    await expect(verifyChargeTransaction(implicit, request)).rejects.toThrow(
        /Priority fee 4000 lamports exceeds the sponsored maximum 2000/,
    );

    const duplicate = await buildSponsoredSplitTx(signer.address, [
        getSetComputeUnitLimitInstruction({ units: 1_000 }),
        getSetComputeUnitPriceInstruction({ microLamports: 1n }),
        getSetComputeUnitPriceInstruction({ microLamports: 10_000n }),
    ]);
    await expect(verifyChargeTransaction(duplicate, request)).rejects.toThrow(/Duplicate SetComputeUnitPrice/);

    const declared = await buildSponsoredSplitTx(signer.address, [
        getSetComputeUnitLimitInstruction({ units: 200_000 }),
        getSetComputeUnitPriceInstruction({ microLamports: 10_000n }),
    ]);
    await expect(verifyChargeTransaction(declared, request)).resolves.toBeUndefined();
});

test('#25 client-paid compute-unit price above the tight cap still passes (general cap applies)', async () => {
    const authority = await generateKeyPairSigner();
    const instructions: Instruction[] = [
        getSetComputeUnitPriceInstruction({ microLamports: 20_000n }),
        getTransferSolInstruction({ source: authority, destination: address(RECIPIENT), amount: 1_000_000n }),
    ];
    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(authority, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );
    const tx = getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(txMessage));
    await expect(
        verifyChargeTransaction(tx, {
            amount: '1000000',
            currency: 'sol',
            methodDetails: { network: 'devnet' },
            recipient: RECIPIENT,
        }),
    ).resolves.toBeUndefined();
});

test('verifyChargeTransaction accepts a legacy (unversioned) transaction under the version-0 rules', async () => {
    const authority = await generateKeyPairSigner();
    const txMessage = pipe(
        createTransactionMessage({ version: 'legacy' }),
        msg => setTransactionMessageFeePayerSigner(authority, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg =>
            appendTransactionMessageInstructions(
                [getTransferSolInstruction({ source: authority, destination: address(RECIPIENT), amount: 1_000_000n })],
                msg,
            ),
    );
    const tx = getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(txMessage));
    await expect(
        verifyChargeTransaction(tx, {
            amount: '1000000',
            currency: 'sol',
            methodDetails: { network: 'devnet' },
            recipient: RECIPIENT,
        }),
    ).resolves.toBeUndefined();
});

// RULINGS SIG1: the verification step itself refuses a client signature
// that does not verify over the message, so a caller of
// verifyChargeTransaction never sees "valid" for a forged transaction. Only a
// sponsoring server's own fee-payer slot may be empty before it co-signs.
async function buildClientPaidSolTx() {
    const authority = await generateKeyPairSigner();
    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(authority, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg =>
            appendTransactionMessageInstructions(
                [getTransferSolInstruction({ source: authority, destination: address(RECIPIENT), amount: 1_000_000n })],
                msg,
            ),
    );
    return getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(txMessage));
}

/** Overwrite signature slot `index` (one-byte shortvec count) with a non-verifying value. */
function forgeSignatureSlot(transaction: string, index: number, fill = 7): string {
    const wire = Buffer.from(transaction, 'base64');
    wire.fill(fill, 1 + index * 64, 1 + (index + 1) * 64);
    return wire.toString('base64');
}

const CLIENT_PAID_SOL_REQUEST = {
    amount: '1000000',
    currency: 'sol',
    methodDetails: { network: 'devnet' },
    recipient: RECIPIENT,
};

test('verifyChargeTransaction refuses a forged client signature', async () => {
    const signed = await buildClientPaidSolTx();
    await expect(verifyChargeTransaction(forgeSignatureSlot(signed, 0), CLIENT_PAID_SOL_REQUEST)).rejects.toThrow(
        'transaction signature verification failed',
    );
    // An empty client slot verifies nothing either.
    await expect(verifyChargeTransaction(forgeSignatureSlot(signed, 0, 0), CLIENT_PAID_SOL_REQUEST)).rejects.toThrow(
        'transaction signature verification failed',
    );
    // Positive control: the transaction as really signed is accepted.
    await expect(verifyChargeTransaction(signed, CLIENT_PAID_SOL_REQUEST)).resolves.toBeUndefined();
});

test('verifyChargeTransaction refuses a forged client signature on a sponsored charge, leaving only the fee-payer slot empty', async () => {
    const feePayer = await generateKeyPairSigner();
    const request = {
        amount: '1000000',
        currency: 'sol',
        methodDetails: { network: 'devnet', feePayer: true, feePayerKey: feePayer.address },
        recipient: RECIPIENT,
    };
    // Slot 0 is the server's (still empty), slot 1 the client's.
    const signed = await buildSolTxWithComputePrice(feePayer.address, 5_000n);
    await expect(verifyChargeTransaction(forgeSignatureSlot(signed, 1), request)).rejects.toThrow(
        'transaction signature verification failed',
    );
    await expect(verifyChargeTransaction(forgeSignatureSlot(signed, 1, 0), request)).rejects.toThrow(
        'transaction signature verification failed',
    );
    // A non-verifying signature in the fee-payer slot is refused too.
    await expect(verifyChargeTransaction(forgeSignatureSlot(signed, 0), request)).rejects.toThrow(
        'transaction signature verification failed',
    );
    // Positive control: the empty fee-payer slot is left for the server.
    await expect(verifyChargeTransaction(signed, request)).resolves.toBeUndefined();
});

test('assertTransactionSignaturesVerify exempts only the named unsigned signer', async () => {
    const feePayer = await generateKeyPairSigner();
    const signed = await buildSolTxWithComputePrice(feePayer.address, 5_000n);
    await expect(assertTransactionSignaturesVerify(signed)).rejects.toThrow(
        'transaction signature verification failed',
    );
    await expect(
        assertTransactionSignaturesVerify(signed, { unsignedSigner: (await generateKeyPairSigner()).address }),
    ).rejects.toThrow('transaction signature verification failed');
    await expect(
        assertTransactionSignaturesVerify(signed, { unsignedSigner: feePayer.address }),
    ).resolves.toBeUndefined();
});

// #3 — post-timeout definitive status interpretation
test('#3 interpretPostTimeoutStatus: landed cleanly returns confirmed', () => {
    expect(interpretPostTimeoutStatus({ err: null })).toEqual({ kind: 'confirmed' });
});

test('#3 interpretPostTimeoutStatus: landed but failed on-chain returns failed', () => {
    const outcome = interpretPostTimeoutStatus({ err: { InstructionError: [0, 'Custom'] } });
    expect(outcome.kind).toBe('failed');
});

test('#3 interpretPostTimeoutStatus: not found returns timeout', () => {
    expect(interpretPostTimeoutStatus(null)).toEqual({ kind: 'timeout' });
});

test('#3 interpretPostTimeoutStatus: rpc error returns timeout with detail', () => {
    const outcome = interpretPostTimeoutStatus(null, 'connection refused');
    expect(outcome).toEqual({ detail: 'connection refused', kind: 'timeout' });
});
