/**
 * Tests for the server charge verification logic.
 *
 * Covers both settlement modes:
 * - Push mode (type="signature"): server fetches + verifies on-chain
 * - Pull mode (type="transaction"): server broadcasts, confirms, then verifies on-chain
 */
import { test, expect, beforeEach, afterEach } from 'vitest';
import { Store } from 'mppx/server';
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
import { charge } from '../server/Charge.js';
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
function mockServerBroadcastFetch(txResult: unknown, signature: string = SIGNATURE) {
    globalThis.fetch = async (_url: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(init?.body as string);
        const method = body.method;

        if (method === 'simulateTransaction') {
            return rpcSuccess({ value: { err: null, logs: [] } });
        }

        if (method === 'sendTransaction') {
            return rpcSuccess(signature);
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

    const receipt = await method.verify({
        credential: transactionCredential(await buildSolPaymentTxBase64(RECIPIENT, 1000000), { amount: '1000000' }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.reference).toBe(SIGNATURE);
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

    const receipt = await method.verify({
        credential: transactionCredential(await buildSplPaymentTxBase64(RECIPIENT, USDC_MINT, '1000000'), {
            amount: '1000000',
            currency: USDC_MINT,
            decimals: 6,
        }),
        request: {} as any,
    });

    expect(receipt.status).toBe('success');
    expect(receipt.reference).toBe(SIGNATURE);
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
    expect(receipt.reference).toBe(SIGNATURE);
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

    globalThis.fetch = async () => rpcSuccess({ meta: { err: null }, transaction: { message: { instructions: [] } } });

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

    globalThis.fetch = async () => rpcSuccess({ meta: { err: null }, transaction: { message: { instructions: [] } } });

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
