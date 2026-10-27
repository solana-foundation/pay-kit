/**
 * Transaction message versions (SIMD-0385, mpp-specs-txv1): the
 * `methodDetails.transactionVersions` wire field, client negotiation and
 * version-1 builds, and server admission with the version-1 header budget.
 */
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { Store } from 'mppx/server';
import { getSetComputeUnitLimitInstruction } from '@solana-program/compute-budget';
import { getTransferSolInstruction } from '@solana-program/system';
import {
    address,
    appendTransactionMessageInstructions,
    type Blockhash,
    createTransactionMessage,
    generateKeyPairSigner,
    getBase64Codec,
    getBase64EncodedWireTransaction,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
    type Instruction,
    type KeyPairSigner,
    partiallySignTransactionMessageWithSigners,
    pipe,
    setTransactionMessageComputeUnitLimit,
    setTransactionMessageFeePayer,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    setTransactionMessageLoadedAccountsDataSizeLimit,
    setTransactionMessagePriorityFeeLamports,
} from '@solana/kit';

import { buildChargeTransaction } from '../client/Charge.js';
import { COMPUTE_BUDGET_PROGRAM, SYSTEM_PROGRAM } from '../constants.js';
import { charge as chargeMethod, session as sessionMethod } from '../Methods.js';
import { charge, type ChallengeRequest, verifyChargeTransaction } from '../server/Charge.js';
import {
    acceptedTransactionVersions,
    checkTransactionEnvelope,
    MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    negotiateTransactionVersion,
    normalizeCompiledMessage,
    priorityFeeLamports,
    type TransactionV1Config,
} from '../utils/transaction-versions.js';
import { assertTransactionSignaturesVerify, coSignBase64Transaction } from '../utils/transactions.js';

const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const USDC_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;

function solRequest(methodDetails: Partial<ChallengeRequest['methodDetails']> = {}): ChallengeRequest {
    return {
        amount: '1000000',
        currency: 'sol',
        methodDetails: { network: 'devnet', recentBlockhash: BLOCKHASH, ...methodDetails },
        recipient: RECIPIENT,
    };
}

function decode(transaction: string) {
    const wire = getTransactionDecoder().decode(getBase64Codec().encode(transaction));
    return normalizeCompiledMessage(getCompiledTransactionMessageDecoder().decode(wire.messageBytes));
}

/** A signed SOL payment as a version-1 message with the given header config and extra instructions. */
async function buildV1Payment(
    authority: KeyPairSigner,
    config: TransactionV1Config,
    options: { extra?: Instruction[]; feePayer?: string } = {},
): Promise<string> {
    // The @solana/kit 6.x types do not list version 1; the runtime does.
    const base = pipe(
        createTransactionMessage({ version: 1 as 0 }),
        msg =>
            options.feePayer
                ? setTransactionMessageFeePayer(address(options.feePayer), msg)
                : setTransactionMessageFeePayerSigner(authority, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg =>
            appendTransactionMessageInstructions(
                [
                    getTransferSolInstruction({
                        amount: 1_000_000n,
                        destination: address(RECIPIENT),
                        source: authority,
                    }),
                    ...(options.extra ?? []),
                ],
                msg,
            ),
    );
    let message = base;
    if (config.computeUnitLimit !== undefined) {
        message = setTransactionMessageComputeUnitLimit(config.computeUnitLimit, message);
    }
    if (config.priorityFeeLamports !== undefined) {
        message = setTransactionMessagePriorityFeeLamports(
            config.priorityFeeLamports,
            message as never,
        ) as typeof message;
    }
    if (config.loadedAccountsDataSizeLimit !== undefined) {
        message = setTransactionMessageLoadedAccountsDataSizeLimit(config.loadedAccountsDataSizeLimit, message);
    }
    return getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(message));
}

const VALID_V1_CONFIG: TransactionV1Config = {
    computeUnitLimit: 200_000,
    loadedAccountsDataSizeLimit: MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    priorityFeeLamports: 1n,
};

describe('methodDetails.transactionVersions wire field', () => {
    const chargeWire = (transactionVersions: unknown) => ({
        amount: '1000',
        currency: USDC_MINT,
        methodDetails: { decimals: 6, network: 'localnet', tokenProgram: TOKEN_PROGRAM, transactionVersions },
        recipient: RECIPIENT,
    });
    const sessionWire = (transactionVersions: unknown) => ({
        amount: '100',
        currency: 'USDC',
        methodDetails: {
            channelProgram: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX',
            network: 'devnet',
            transactionVersions,
        },
        recipient: RECIPIENT,
    });

    test.each([[[0, 1]], [[1]], [[0]], [[1, 1]]])('round-trips %j on charge and session requests', versions => {
        expect(chargeMethod.schema.request.parse(chargeWire(versions)).methodDetails.transactionVersions).toEqual(
            versions,
        );
        expect(sessionMethod.schema.request.parse(sessionWire(versions)).methodDetails.transactionVersions).toEqual(
            versions,
        );
    });

    test('is optional', () => {
        const { transactionVersions: _absent, ...methodDetails } = chargeWire(undefined).methodDetails;
        const parsed = chargeMethod.schema.request.parse({ ...chargeWire(undefined), methodDetails });
        expect('transactionVersions' in parsed.methodDetails).toBe(false);
    });

    test.each([[['legacy']], [[0, 2]], [['1']], [1], [[true]]])('rejects %j', versions => {
        expect(() => chargeMethod.schema.request.parse(chargeWire(versions))).toThrow();
        expect(() => sessionMethod.schema.request.parse(sessionWire(versions))).toThrow();
    });
});

describe('negotiateTransactionVersion', () => {
    test('defaults to version 0 only when the field is absent', () => {
        expect(acceptedTransactionVersions(undefined)).toEqual([0]);
        expect(acceptedTransactionVersions([])).toEqual([]);
        expect(negotiateTransactionVersion(undefined)).toBe(0);
    });

    test('picks the highest advertised version the signer can sign', () => {
        expect(negotiateTransactionVersion([0, 1])).toBe(1);
        expect(negotiateTransactionVersion([1, 0])).toBe(1);
        expect(negotiateTransactionVersion([1, 1])).toBe(1);
        expect(negotiateTransactionVersion([0, 1], 0)).toBe(0);
        expect(negotiateTransactionVersion([0])).toBe(0);
    });

    test('refuses an empty advertisement and an unbuildable one', () => {
        expect(() => negotiateTransactionVersion([])).toThrow('advertises no transaction version');
        expect(() => negotiateTransactionVersion([1], 0)).toThrow(
            'the server accepts transaction versions [1] but the signer signs up to version 0',
        );
    });

    test('rounds the version-1 priority fee up', () => {
        expect(priorityFeeLamports(200_000, 1n)).toBe(1n);
        expect(priorityFeeLamports(20_000, 1n)).toBe(1n);
        expect(priorityFeeLamports(400_000, 5_000_000n)).toBe(2_000_000n);
        expect(priorityFeeLamports(200_000, 0n)).toBe(0n);
    });
});

describe('buildChargeTransaction transaction versions', () => {
    test('builds version 1 with the budget in the header when advertised', async () => {
        const signer = await generateKeyPairSigner();
        const tx = await buildChargeTransaction({ request: solRequest({ transactionVersions: [0, 1] }), signer });
        const message = decode(tx);
        expect(message.version).toBe(1);
        expect(message.config).toEqual({
            computeUnitLimit: 200_000,
            loadedAccountsDataSizeLimit: MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
            priorityFeeLamports: 1n,
        });
        expect(message.instructions.map(ix => message.staticAccounts[ix.programAddressIndex])).not.toContain(
            COMPUTE_BUDGET_PROGRAM,
        );
        await expect(verifyChargeTransaction(tx, solRequest({ transactionVersions: [0, 1] }))).resolves.toBeUndefined();
    });

    test('carries a custom compute budget in the version-1 header', async () => {
        const signer = await generateKeyPairSigner();
        const tx = await buildChargeTransaction({
            computeUnitLimit: 50_000,
            computeUnitPrice: 30n,
            request: solRequest({ transactionVersions: [1] }),
            signer,
        });
        expect(decode(tx).config).toMatchObject({ computeUnitLimit: 50_000, priorityFeeLamports: 2n });
    });

    test('builds version 0 when absent, advertised alone, or the signer stops at version 0', async () => {
        const signer = await generateKeyPairSigner();
        for (const [transactionVersions, maxTransactionVersion] of [
            [undefined, undefined],
            [[0], undefined],
            [[0, 1], 0],
        ] as const) {
            const tx = await buildChargeTransaction({
                maxTransactionVersion,
                request: solRequest(transactionVersions ? { transactionVersions } : {}),
                signer,
            });
            const message = decode(tx);
            expect(message.version).toBe(0);
            expect(message.staticAccounts).toContain(COMPUTE_BUDGET_PROGRAM);
        }
    });

    test('refuses a challenge with no buildable version before signing', async () => {
        const signer = await generateKeyPairSigner();
        await expect(
            buildChargeTransaction({
                maxTransactionVersion: 0,
                request: solRequest({ transactionVersions: [1] }),
                signer,
            }),
        ).rejects.toThrow('signs up to version 0');
        await expect(
            buildChargeTransaction({ request: solRequest({ transactionVersions: [] }), signer }),
        ).rejects.toThrow('advertises no transaction version');
    });

    test('refuses an out-of-range compute unit limit', async () => {
        const signer = await generateKeyPairSigner();
        for (const computeUnitLimit of [0, 1_400_001, 1.5]) {
            await expect(buildChargeTransaction({ computeUnitLimit, request: solRequest(), signer })).rejects.toThrow(
                'computeUnitLimit must be an integer',
            );
        }
        await expect(
            buildChargeTransaction({ computeUnitPrice: 1n << 64n, request: solRequest(), signer }),
        ).rejects.toThrow('computeUnitPrice must fit in a u64');
    });

    test('a sponsored version-1 build leaves the fee payer slot for the server, which co-signs it', async () => {
        const signer = await generateKeyPairSigner();
        const feePayer = await generateKeyPairSigner();
        const request = solRequest({ feePayer: true, feePayerKey: feePayer.address, transactionVersions: [0, 1] });
        const tx = await buildChargeTransaction({ request, signer });
        const message = decode(tx);
        expect(message.version).toBe(1);
        expect(message.staticAccounts[0]).toBe(feePayer.address);
        await expect(verifyChargeTransaction(tx, request)).resolves.toBeUndefined();
        await expect(assertTransactionSignaturesVerify(tx)).rejects.toThrow('signature verification failed');
        const cosigned = await coSignBase64Transaction(feePayer, tx);
        await expect(assertTransactionSignaturesVerify(cosigned)).resolves.toBeUndefined();
    });
});

describe('verifyChargeTransaction transaction versions', () => {
    let authority: KeyPairSigner;
    beforeEach(async () => {
        authority = await generateKeyPairSigner();
    });

    test('admits by the advertised set', async () => {
        const v1 = await buildV1Payment(authority, VALID_V1_CONFIG);
        await expect(verifyChargeTransaction(v1, solRequest({ transactionVersions: [0, 1] }))).resolves.toBeUndefined();
        await expect(verifyChargeTransaction(v1, solRequest({ transactionVersions: [1] }))).resolves.toBeUndefined();
        await expect(verifyChargeTransaction(v1, solRequest())).rejects.toThrow(
            'transaction version 1 is not accepted; accepted versions: 0',
        );
        await expect(verifyChargeTransaction(v1, solRequest({ transactionVersions: [0] }))).rejects.toThrow(
            'transaction version 1 is not accepted; accepted versions: 0',
        );
        const v0 = await buildChargeTransaction({ request: solRequest(), signer: authority });
        await expect(verifyChargeTransaction(v0, solRequest({ transactionVersions: [1] }))).rejects.toThrow(
            'transaction version 0 is not accepted; accepted versions: 1',
        );
        await expect(verifyChargeTransaction(v0, solRequest({ transactionVersions: [0, 1] }))).resolves.toBeUndefined();
    });

    test.each<[string, TransactionV1Config, RegExp]>([
        ['no computeUnitLimit', { ...VALID_V1_CONFIG, computeUnitLimit: undefined }, /must set computeUnitLimit/],
        [
            'no loadedAccountsDataSizeLimit',
            { ...VALID_V1_CONFIG, loadedAccountsDataSizeLimit: undefined },
            /loaded accounts data size limit must be 67108864/,
        ],
        [
            'a reduced loadedAccountsDataSizeLimit',
            { ...VALID_V1_CONFIG, loadedAccountsDataSizeLimit: 4_194_304 },
            /loaded accounts data size limit must be 67108864/,
        ],
        [
            'a computeUnitLimit over the cap',
            { ...VALID_V1_CONFIG, computeUnitLimit: 200_001 },
            /compute unit limit 200001 exceeds maximum 200000/,
        ],
        [
            'a priority fee over the client-paid price cap',
            { ...VALID_V1_CONFIG, priorityFeeLamports: 1_000_001n },
            /compute unit price 5000005 exceeds maximum 5000000/,
        ],
    ])('rejects a version-1 header with %s', async (_label, config, error) => {
        const tx = await buildV1Payment(authority, config);
        await expect(verifyChargeTransaction(tx, solRequest({ transactionVersions: [1] }))).rejects.toThrow(error);
    });

    test('accepts a priority fee at the client-paid price cap', async () => {
        const tx = await buildV1Payment(authority, { ...VALID_V1_CONFIG, priorityFeeLamports: 1_000_000n });
        await expect(verifyChargeTransaction(tx, solRequest({ transactionVersions: [1] }))).resolves.toBeUndefined();
    });

    test('holds a sponsored version-1 priority fee to the sponsor price cap', async () => {
        const feePayer = await generateKeyPairSigner();
        const request = solRequest({ feePayer: true, feePayerKey: feePayer.address, transactionVersions: [1] });
        const atCap = await buildV1Payment(
            authority,
            { ...VALID_V1_CONFIG, priorityFeeLamports: 2_000n },
            { feePayer: feePayer.address },
        );
        await expect(verifyChargeTransaction(atCap, request)).resolves.toBeUndefined();
        const overCap = await buildV1Payment(
            authority,
            { ...VALID_V1_CONFIG, priorityFeeLamports: 2_001n },
            { feePayer: feePayer.address },
        );
        await expect(verifyChargeTransaction(overCap, request)).rejects.toThrow(
            'compute unit price 10005 exceeds maximum 10000',
        );
        // One lamport over 50 units is 20000 micro-lamports per unit.
        const reducedLimit = await buildV1Payment(
            authority,
            { ...VALID_V1_CONFIG, computeUnitLimit: 50 },
            { feePayer: feePayer.address },
        );
        await expect(verifyChargeTransaction(reducedLimit, request)).rejects.toThrow(
            'compute unit price 20000 exceeds maximum 10000',
        );
    });

    test('rejects a ComputeBudget instruction in a version-1 transaction', async () => {
        const tx = await buildV1Payment(authority, VALID_V1_CONFIG, {
            extra: [getSetComputeUnitLimitInstruction({ units: 200_000 })],
        });
        await expect(verifyChargeTransaction(tx, solRequest({ transactionVersions: [1] }))).rejects.toThrow(
            'version 1 transactions must not contain ComputeBudget instructions',
        );
    });
});

describe('checkTransactionEnvelope limits', () => {
    const view = (overrides: Partial<ReturnType<typeof normalizeCompiledMessage>>) => ({
        addressTableLookups: [],
        config: VALID_V1_CONFIG,
        header: { numSignerAccounts: 1 },
        instructions: [],
        lifetimeToken: BLOCKHASH,
        staticAccounts: [SYSTEM_PROGRAM],
        version: 1 as const,
        ...overrides,
    });

    test('applies the version-1 size, account, instruction and signature limits', () => {
        expect(checkTransactionEnvelope(view({}), 4096, [1])).toBe(1);
        expect(() => checkTransactionEnvelope(view({}), 4097, [1])).toThrow(
            'version 1 transaction is 4097 bytes, over the 4096-byte limit',
        );
        expect(() =>
            checkTransactionEnvelope(view({ staticAccounts: Array(65).fill(SYSTEM_PROGRAM) }), 100, [1]),
        ).toThrow('version 1 transaction has 65 accounts, over the limit of 64');
        const ix = { accountIndices: [], data: new Uint8Array(), programAddressIndex: 0 };
        expect(() => checkTransactionEnvelope(view({ instructions: Array(65).fill(ix) }), 100, [1])).toThrow(
            'version 1 transaction has 65 instructions, over the limit of 64',
        );
        expect(() => checkTransactionEnvelope(view({ header: { numSignerAccounts: 13 } }), 100, [1])).toThrow(
            'version 1 transaction requires 13 signatures, over the limit of 12',
        );
        expect(() => checkTransactionEnvelope(view({ addressTableLookups: [{}] }), 100, [1])).toThrow(
            'address lookup tables are not supported',
        );
    });

    test('applies the version-0 limits', () => {
        const v0 = view({ config: undefined, version: 0 });
        expect(checkTransactionEnvelope(v0, 1232, [0])).toBe(0);
        expect(() => checkTransactionEnvelope(v0, 1233, [0])).toThrow(
            'version 0 transaction is 1233 bytes, over the 1232-byte limit',
        );
        expect(() =>
            checkTransactionEnvelope({ ...v0, staticAccounts: Array(65).fill(SYSTEM_PROGRAM) }, 100, [0]),
        ).toThrow('version 0 transaction has 65 accounts, over the limit of 64');
    });

    test('rejects a malformed version-1 config mask', () => {
        const decoded = {
            configMask: 0b01,
            configValues: [{ kind: 'u64', value: 1n }],
            header: { numSignerAccounts: 1 },
            instructionHeaders: [],
            instructionPayloads: [],
            lifetimeToken: BLOCKHASH,
            staticAccounts: [],
            version: 1,
        };
        expect(() => normalizeCompiledMessage(decoded)).toThrow('one of the two priority fee bits');
        expect(() => normalizeCompiledMessage({ ...decoded, configMask: 0b100000 })).toThrow('unknown mask bit');
        expect(() => normalizeCompiledMessage({ ...decoded, configMask: 0b100, configValues: [] })).toThrow(
            'missing a value',
        );
        expect(() =>
            normalizeCompiledMessage({ ...decoded, instructionHeaders: [{ programAccountIndex: 0 }] }),
        ).toThrow('headers and payloads differ');
        expect(() => normalizeCompiledMessage({ ...decoded, version: 2 })).toThrow('unsupported transaction version 2');
        expect(
            normalizeCompiledMessage({ ...decoded, configMask: 0b10000, configValues: [{ value: 32768 }] }).config,
        ).toEqual({ heapSize: 32768 });
    });
});

describe('server charge advertises transactionVersions', () => {
    const request = async (transactionVersions?: ReadonlyArray<0 | 1>) => {
        const method = charge({ network: 'devnet', recipient: RECIPIENT, store: Store.memory(), transactionVersions });
        // A credential skips the blockhash prefetch.
        const built = await (
            method as unknown as {
                request: (args: unknown) => Promise<{ methodDetails: Record<string, unknown> }>;
            }
        ).request({ credential: {}, request: { amount: '1000', currency: 'sol' } });
        return built.methodDetails;
    };

    test('omits the default [0] and lists any other set', async () => {
        expect(await request()).not.toHaveProperty('transactionVersions');
        expect(await request([0])).not.toHaveProperty('transactionVersions');
        expect((await request([1, 0])).transactionVersions).toEqual([0, 1]);
        expect((await request([1, 1])).transactionVersions).toEqual([1]);
    });

    test('refuses an empty or unknown set at construction', () => {
        expect(() => charge({ recipient: RECIPIENT, transactionVersions: [] })).toThrow('at least one');
        expect(() => charge({ recipient: RECIPIENT, transactionVersions: [2 as 0] })).toThrow('must be 0 or 1');
    });
});

describe('server charge settles a version-1 pull credential', () => {
    const originalFetch = globalThis.fetch;
    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    test('co-signs, broadcasts and verifies a sponsored version-1 transaction', async () => {
        const client = await generateKeyPairSigner();
        const feePayer = await generateKeyPairSigner();
        const method = charge({
            network: 'devnet',
            recipient: RECIPIENT,
            rpcUrl: 'https://mock-rpc',
            signer: feePayer,
            store: Store.memory(),
            transactionVersions: [0, 1],
        });
        const challengeRequest = solRequest({
            feePayer: true,
            feePayerKey: feePayer.address,
            transactionVersions: [0, 1],
        });
        const transaction = await buildChargeTransaction({ request: challengeRequest, signer: client });
        let sent: string | undefined;
        globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
            const body = JSON.parse(init?.body as string);
            const result = (() => {
                switch (body.method) {
                    case 'simulateTransaction':
                        return { value: { err: null, logs: [] } };
                    case 'sendTransaction':
                        sent = body.params[0];
                        return 'sig';
                    case 'getSignatureStatuses':
                        return { value: [{ confirmationStatus: 'confirmed', err: null }] };
                    case 'getTransaction':
                        return {
                            meta: { err: null },
                            transaction: {
                                message: {
                                    instructions: [
                                        {
                                            parsed: {
                                                info: { destination: RECIPIENT, lamports: 1_000_000 },
                                                type: 'transfer',
                                            },
                                            program: 'system',
                                        },
                                    ],
                                },
                            },
                            version: 1,
                        };
                    default:
                        throw new Error(`unexpected RPC method ${body.method}`);
                }
            })();
            return new Response(JSON.stringify({ id: 1, jsonrpc: '2.0', result }));
        }) as typeof fetch;

        const receipt = await method.verify({
            credential: {
                challenge: { id: 'c1', request: challengeRequest },
                payload: { transaction, type: 'transaction' },
            },
            request: {},
        } as never);
        expect(receipt.status).toBe('success');
        expect(sent).toBeDefined();
        await expect(assertTransactionSignaturesVerify(sent!)).resolves.toBeUndefined();
    });
});
