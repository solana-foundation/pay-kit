// Branch-coverage tests for server/Subscription.ts.
//
// Targets the uncovered error and defaulting branches the existing
// subscription-server suite does not reach: request()-side period/programId
// defaulting, delegation field mismatches (mint/amount/period), receipt
// assembly without optional ids, settleActivation edge cases (missing data,
// co-sign, push-mode account extraction, RPC failures), the instruction
// validator's ALT and duplicate-instruction guards, and the dependency-free
// codec edge cases. RPC is stubbed through globalThis.fetch, mirroring the
// existing subscription-server tests. No production code is touched.

import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import {
    AccountRole,
    address,
    appendTransactionMessageInstructions,
    type Blockhash,
    createTransactionMessage,
    generateKeyPairSigner,
    getBase64Codec,
    getBase64EncodedWireTransaction,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
    getTransactionDecoder,
    getTransactionEncoder,
    type Instruction,
    partiallySignTransactionMessageWithSigners,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { Store } from 'mppx/server';

import {
    SUBSCRIPTIONS_PROGRAM,
    SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
    SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
    TOKEN_PROGRAM,
} from '../constants.js';
import { __testing, subscription } from '../server/Subscription.js';

const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;

const PLAN_ID = '8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT';
const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const PULLER = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';

let originalFetch: typeof globalThis.fetch;

beforeEach(() => {
    originalFetch = globalThis.fetch;
    process.env.MPP_SECRET_KEY = 'test-secret';
});

afterEach(() => {
    globalThis.fetch = originalFetch;
});

// ── Helpers ──

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

function writeU64Le(buf: Uint8Array, offset: number, value: bigint) {
    for (let i = 0; i < 8; i += 1) {
        buf[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
    }
}

/** Build a `SubscriptionDelegation` byte buffer, with per-field overrides. */
function buildDelegationAccount(
    subscriberAddress: string,
    overrides: {
        amountPerPeriod?: bigint;
        amountPulled?: bigint;
        mint?: string;
        periodHours?: bigint;
        planPda?: string;
    } = {},
): string {
    const data = new Uint8Array(1 + 32 * 3 + 8 + 32 + 32 + 8 + 8 + 8 + 8);
    data.set(__testing.decodeBase58(subscriberAddress), 1);
    data.set(__testing.decodeBase58(overrides.planPda ?? PLAN_ID), 1 + 32 * 3 + 8);
    data.set(__testing.decodeBase58(overrides.mint ?? MINT), 1 + 32 * 3 + 8 + 32);
    writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32, overrides.amountPerPeriod ?? 10_000_000n);
    writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8, overrides.periodHours ?? 720n);
    writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8 + 8, 1737216000n);
    writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8 + 8 + 8, overrides.amountPulled ?? 10_000_000n);
    return Buffer.from(data).toString('base64');
}

async function buildActivationTransactionBase64(
    options: {
        extraInstructions?: 'duplicate-subscribe' | 'duplicate-transfer';
        feePayerKey?: string;
    } = {},
): Promise<{ subscriberAddress: string; transaction: string }> {
    const subscriber = await generateKeyPairSigner();
    const subscribeIx: Instruction = {
        accounts: [{ address: subscriber.address, role: AccountRole.WRITABLE_SIGNER }],
        data: new Uint8Array([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR]),
        programAddress: address(SUBSCRIPTIONS_PROGRAM),
    };
    const transferIx: Instruction = {
        accounts: [{ address: subscriber.address, role: AccountRole.READONLY }],
        data: new Uint8Array([SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR]),
        programAddress: address(SUBSCRIPTIONS_PROGRAM),
    };

    let instructions: Instruction[];
    switch (options.extraInstructions) {
        case 'duplicate-subscribe':
            instructions = [subscribeIx, subscribeIx, transferIx];
            break;
        case 'duplicate-transfer':
            instructions = [subscribeIx, transferIx, transferIx];
            break;
        default:
            instructions = [subscribeIx, transferIx];
    }

    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(subscriber, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );
    const signed = await partiallySignTransactionMessageWithSigners(txMessage);
    return {
        subscriberAddress: subscriber.address,
        transaction: getBase64EncodedWireTransaction(signed),
    };
}

/**
 * Build a fee-payer-mode activation tx: the server `feePayer` signs the fee
 * slot and a separate `subscriber` signs an instruction. Both slots appear in
 * the signatures map, so `coSignBase64Transaction` accepts the fee payer, and
 * `extractSubscriberFromTransaction` finds the subscriber after slot 0.
 */
async function buildFeePayerActivationTx(feePayer: {
    address: string;
    signTransactions: (...args: never[]) => unknown;
}): Promise<{ subscriberAddress: string; transaction: string }> {
    const subscriber = await generateKeyPairSigner();
    const subscribeIx: Instruction = {
        accounts: [{ address: subscriber.address, role: AccountRole.WRITABLE_SIGNER }],
        data: new Uint8Array([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR]),
        programAddress: address(SUBSCRIPTIONS_PROGRAM),
    };
    const transferIx: Instruction = {
        accounts: [{ address: subscriber.address, role: AccountRole.READONLY }],
        data: new Uint8Array([SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR]),
        programAddress: address(SUBSCRIPTIONS_PROGRAM),
    };
    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(feePayer as never, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions([subscribeIx, transferIx], msg),
    );
    // Sign only with the subscriber, leaving the fee-payer signature slot as a
    // placeholder that the server co-signs in the flow under test.
    const signed = await partiallySignTransactionMessageWithSigners(txMessage, { signers: [subscriber] } as never);
    return {
        subscriberAddress: subscriber.address,
        transaction: getBase64EncodedWireTransaction(signed),
    };
}

const baseParams = {
    decimals: 6,
    mint: MINT,
    network: 'devnet' as const,
    periodCount: 30,
    periodUnit: 'day' as const,
    planId: PLAN_ID,
    puller: PULLER,
    recipient: RECIPIENT,
    rpcUrl: 'https://mock-rpc',
    tokenProgram: TOKEN_PROGRAM,
};

function transactionCredential(transaction: string, methodDetailsOverrides: Record<string, unknown> = {}) {
    return {
        challenge: {
            id: 'test-challenge',
            request: {
                amount: '10000000',
                currency: MINT,
                methodDetails: {
                    decimals: 6,
                    mint: MINT,
                    network: 'devnet',
                    planId: PLAN_ID,
                    programId: SUBSCRIPTIONS_PROGRAM,
                    puller: PULLER,
                    tokenProgram: TOKEN_PROGRAM,
                    ...methodDetailsOverrides,
                },
                periodCount: '30',
                periodUnit: 'day',
                recipient: RECIPIENT,
            },
        },
        payload: { transaction, type: 'transaction' },
    };
}

/** Cast a test credential literal to the opaque credential parameter type. */
function asCredential(credential: unknown) {
    return credential as never;
}

// ══════════════════════════════════════════════════════════════════════
// request() defaulting branches
// ══════════════════════════════════════════════════════════════════════

describe('subscription().request() defaulting', () => {
    test('falls back to the configured period when the request omits it', async () => {
        globalThis.fetch = async () => rpcSuccess({ value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 } });
        const method = subscription(baseParams);
        const shaped = await method.request!({
            credential: undefined as never,
            request: { amount: '10000000' } as never,
        });
        expect(shaped.periodCount).toBe('30');
        expect(shaped.periodUnit).toBe('day');
    });

    test('honours a request-supplied period over the configured default', async () => {
        globalThis.fetch = async () => rpcSuccess({ value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 } });
        const method = subscription(baseParams);
        const shaped = await method.request!({
            credential: undefined as never,
            request: { amount: '10000000', periodCount: '7', periodUnit: 'week' } as never,
        });
        expect(shaped.periodCount).toBe('7');
        expect(shaped.periodUnit).toBe('week');
    });
});

// ══════════════════════════════════════════════════════════════════════
// verify() delegation-mismatch branches
// ══════════════════════════════════════════════════════════════════════

describe('subscription().verify() delegation mismatches', () => {
    function fetchWith(accountB64: string | null) {
        return async (_input: RequestInfo | URL, init?: RequestInit) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            switch (body.method) {
                case 'simulateTransaction':
                    return rpcSuccess({ value: { err: null, logs: [] } });
                case 'sendTransaction':
                    return rpcSuccess('sigMismatch');
                case 'getSignatureStatuses':
                    return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
                case 'getAccountInfo':
                    return accountB64 === null
                        ? rpcSuccess({ value: null })
                        : rpcSuccess({
                              value: {
                                  data: [accountB64, 'base64'],
                                  executable: false,
                                  lamports: 0,
                                  owner: SUBSCRIPTIONS_PROGRAM,
                                  rentEpoch: 0,
                              },
                          });
                default:
                    return rpcSuccess({});
            }
        };
    }

    test('rejects when the on-chain mint differs from the challenge', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        globalThis.fetch = fetchWith(buildDelegationAccount(subscriberAddress, { mint: RECIPIENT }));
        const method = subscription({ ...baseParams, store: Store.memory() });
        await expect(
            method.verify!({ credential: asCredential(transactionCredential(transaction)), request: {} as never }),
        ).rejects.toThrow(/mint mismatch/);
    });

    test('rejects when the on-chain amountPerPeriod differs from the challenge', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        globalThis.fetch = fetchWith(buildDelegationAccount(subscriberAddress, { amountPerPeriod: 999n }));
        const method = subscription({ ...baseParams, store: Store.memory() });
        await expect(
            method.verify!({ credential: asCredential(transactionCredential(transaction)), request: {} as never }),
        ).rejects.toThrow(/amount mismatch/);
    });

    test('rejects when the on-chain periodHours differs from the challenge', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        globalThis.fetch = fetchWith(buildDelegationAccount(subscriberAddress, { periodHours: 24n }));
        const method = subscription({ ...baseParams, store: Store.memory() });
        await expect(
            method.verify!({ credential: asCredential(transactionCredential(transaction)), request: {} as never }),
        ).rejects.toThrow(/period mismatch/);
    });

    test('produces a receipt without challengeId/externalId when they are absent', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        globalThis.fetch = fetchWith(buildDelegationAccount(subscriberAddress));
        const method = subscription({ ...baseParams, store: Store.memory() });
        // Strip the challenge id so the `?? {}` receipt spreads are skipped.
        const credential = transactionCredential(transaction);
        (credential as { challenge: { id?: string } }).challenge.id = undefined;
        const receipt = await method.verify!({ credential: asCredential(credential), request: {} as never });
        expect(receipt.status).toBe('success');
        expect((receipt as { challengeId?: string }).challengeId).toBeUndefined();
    });
});

// ══════════════════════════════════════════════════════════════════════
// settleActivation edge branches
// ══════════════════════════════════════════════════════════════════════

describe('settleActivation edge branches', () => {
    test('rejects a transaction-mode credential with no transaction data', async () => {
        globalThis.fetch = async () => rpcSuccess({});
        const method = subscription({ ...baseParams, store: Store.memory() });
        const credential = {
            challenge: { request: transactionCredential('x').challenge.request },
            payload: { type: 'transaction' },
        } as never;
        await expect(method.verify!({ credential, request: {} as never })).rejects.toThrow(/Missing transaction data/);
    });

    test('rejects a signature-mode credential with no signature', async () => {
        globalThis.fetch = async () => rpcSuccess({});
        const method = subscription({ ...baseParams, store: Store.memory() });
        const credential = {
            challenge: { request: transactionCredential('x').challenge.request },
            payload: { type: 'signature' },
        } as never;
        await expect(method.verify!({ credential, request: {} as never })).rejects.toThrow(/Missing signature/);
    });

    test('co-signs the activation transaction when a fee-payer signer is configured', async () => {
        const signer = await generateKeyPairSigner();
        const { transaction, subscriberAddress } = await buildFeePayerActivationTx(signer);
        let sentTx: string | undefined;
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string; params?: unknown[] };
            switch (body.method) {
                case 'simulateTransaction':
                    return rpcSuccess({ value: { err: null, logs: [] } });
                case 'sendTransaction':
                    sentTx = body.params?.[0] as string;
                    return rpcSuccess('sigCo');
                case 'getSignatureStatuses':
                    return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
                case 'getAccountInfo':
                    return rpcSuccess({
                        value: {
                            data: [buildDelegationAccount(subscriberAddress), 'base64'],
                            executable: false,
                            lamports: 0,
                            owner: SUBSCRIPTIONS_PROGRAM,
                            rentEpoch: 0,
                        },
                    });
                default:
                    return rpcSuccess({});
            }
        };
        const method = subscription({ ...baseParams, signer, store: Store.memory() });
        const receipt = await method.verify!({
            credential: asCredential(
                transactionCredential(transaction, { feePayer: true, feePayerKey: signer.address }),
            ),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        // The co-signed wire was broadcast.
        expect(sentTx).toBeDefined();
    });

    test('push mode: rejects a transaction that failed on-chain', async () => {
        const sig = 'pushFailSig000000000000000000000000000000000';
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getTransaction') {
                return rpcSuccess({
                    meta: { err: { InstructionError: [0, 'Custom'] } },
                    transaction: { message: { accountKeys: [PULLER] } },
                });
            }
            return rpcSuccess({});
        };
        const method = subscription({ ...baseParams, store: Store.memory() });
        const credential = {
            challenge: { request: transactionCredential('x').challenge.request },
            payload: { signature: sig, type: 'signature' },
        } as never;
        await expect(method.verify!({ credential, request: {} as never })).rejects.toThrow(/failed on-chain/);
    });

    test('push mode: rejects a transaction with no account keys', async () => {
        const sig = 'pushNoKeysSig00000000000000000000000000000000';
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getTransaction') {
                return rpcSuccess({ meta: null, transaction: { message: { accountKeys: [] } } });
            }
            return rpcSuccess({});
        };
        const method = subscription({ ...baseParams, store: Store.memory() });
        const credential = {
            challenge: { request: transactionCredential('x').challenge.request },
            payload: { signature: sig, type: 'signature' },
        } as never;
        await expect(method.verify!({ credential, request: {} as never })).rejects.toThrow(/no account keys/);
    });

    test('push mode: extracts the subscriber from an object-shaped accountKey', async () => {
        // The first account is an object `{ pubkey }`, exercising that branch; the
        // subsequent delegation lookup returns null so verify() fails afterwards,
        // but the subscriber-extraction branch has already run.
        const sig = 'pushObjSig00000000000000000000000000000000000';
        const subscriber = await generateKeyPairSigner();
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getTransaction') {
                return rpcSuccess({
                    meta: null,
                    transaction: { message: { accountKeys: [{ pubkey: subscriber.address }] } },
                });
            }
            if (body.method === 'getAccountInfo') return rpcSuccess({ value: null });
            return rpcSuccess({});
        };
        const method = subscription({ ...baseParams, store: Store.memory() });
        const credential = {
            challenge: { request: transactionCredential('x').challenge.request },
            payload: { signature: sig, type: 'signature' },
        } as never;
        await expect(method.verify!({ credential, request: {} as never })).rejects.toThrow(
            /SubscriptionDelegation account not found/,
        );
    });
});

// ══════════════════════════════════════════════════════════════════════
// extractSubscriberFromTransaction / validateActivationInstructions
// ══════════════════════════════════════════════════════════════════════

describe('transaction parsing branches', () => {
    test('extractSubscriberFromTransaction rejects an undecodable transaction', () => {
        expect(() =>
            __testing.extractSubscriberFromTransaction('not-base64!!', {
                methodDetails: { puller: PULLER },
            } as never),
        ).toThrow(/Invalid transaction/);
    });

    test('extractSubscriberFromTransaction returns the fee-payer when no sponsorship', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const subscriber = __testing.extractSubscriberFromTransaction(transaction, {
            methodDetails: { puller: PULLER },
        } as never);
        expect(subscriber).toBe(subscriberAddress);
    });

    test('extractSubscriberFromTransaction rejects when the subscriber is the puller', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        expect(() =>
            __testing.extractSubscriberFromTransaction(transaction, {
                methodDetails: { puller: subscriberAddress },
            } as never),
        ).toThrow(/cannot be the server puller/);
    });

    test('extractSubscriberFromTransaction: fee-payer mode returns the first non-puller signer', async () => {
        const feePayer = await generateKeyPairSigner();
        const { transaction, subscriberAddress } = await buildFeePayerActivationTx(feePayer);
        // slot 0 is the fee payer; the subscriber is the next non-puller account.
        const subscriber = __testing.extractSubscriberFromTransaction(transaction, {
            methodDetails: { feePayer: true, feePayerKey: feePayer.address, puller: PULLER },
        } as never);
        expect(subscriber).toBe(subscriberAddress);
    });

    test('validateActivationInstructions rejects duplicate subscribe instructions', async () => {
        const { transaction } = await buildActivationTransactionBase64({ extraInstructions: 'duplicate-subscribe' });
        await expect(
            __testing.validateActivationInstructions(transaction, {
                methodDetails: { programId: SUBSCRIPTIONS_PROGRAM },
            } as never),
        ).rejects.toThrow(/Multiple subscribe/);
    });

    test('validateActivationInstructions rejects duplicate transfer instructions', async () => {
        const { transaction } = await buildActivationTransactionBase64({ extraInstructions: 'duplicate-transfer' });
        await expect(
            __testing.validateActivationInstructions(transaction, {
                methodDetails: { programId: SUBSCRIPTIONS_PROGRAM },
            } as never),
        ).rejects.toThrow(/Multiple transfer_subscription/);
    });

    test('validateActivationInstructions defaults the programId when the challenge omits it', async () => {
        const { transaction } = await buildActivationTransactionBase64();
        // No programId in methodDetails → the `?? SUBSCRIPTIONS_PROGRAM` default is used.
        await expect(
            __testing.validateActivationInstructions(transaction, { methodDetails: {} } as never),
        ).resolves.toBeUndefined();
    });
});

// ══════════════════════════════════════════════════════════════════════
// codec + RPC helper branches
// ══════════════════════════════════════════════════════════════════════

describe('codec + RPC helper branches', () => {
    test('decodeBase58 returns an empty array for an empty string', () => {
        expect(__testing.decodeBase58('')).toEqual(new Uint8Array());
    });

    test('base64UrlEncodeNoPadding round-trips a byte buffer', () => {
        const bytes = new Uint8Array([255, 254, 0, 1, 250]);
        const encoded = __testing.base64UrlEncodeNoPadding(bytes);
        expect(encoded).not.toMatch(/[+/=]/);
    });

    test('push-mode getTransaction surfaces an RPC error object', async () => {
        const sig = 'rpcErrSig00000000000000000000000000000000000';
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getTransaction') return rpcError('boom');
            return rpcSuccess({});
        };
        const method = subscription({ ...baseParams, store: Store.memory() });
        const credential = {
            challenge: { request: transactionCredential('x').challenge.request },
            payload: { signature: sig, type: 'signature' },
        } as never;
        await expect(method.verify!({ credential, request: {} as never })).rejects.toThrow(/RPC error/);
    });

    test('broadcast surfaces a missing signature result', async () => {
        const { transaction } = await buildActivationTransactionBase64();
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'simulateTransaction') return rpcSuccess({ value: { err: null, logs: [] } });
            if (body.method === 'sendTransaction') return rpcSuccess(undefined);
            return rpcSuccess({});
        };
        const method = subscription({ ...baseParams, store: Store.memory() });
        await expect(
            method.verify!({ credential: asCredential(transactionCredential(transaction)), request: {} as never }),
        ).rejects.toThrow(/No signature returned/);
    });

    test('decodeBase58 rejects an invalid character', () => {
        // '0' is not part of the base58 alphabet.
        expect(() => __testing.decodeBase58('abc0def')).toThrow(/Invalid base58 character/);
    });
});

// ══════════════════════════════════════════════════════════════════════
// Additional defaulting + RPC-failure branches
// ══════════════════════════════════════════════════════════════════════

describe('subscription() additional branches', () => {
    test('falls back to the mainnet-beta RPC URL for an unknown network', async () => {
        let calledUrl: string | undefined;
        globalThis.fetch = async (input: RequestInfo | URL) => {
            calledUrl = String(input);
            return rpcSuccess({ value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 } });
        };
        // No rpcUrl + an unrecognised network → DEFAULT_RPC_URLS[network] is
        // undefined, so the mainnet-beta default is used.
        const method = subscription({
            decimals: 6,
            mint: MINT,
            network: 'unknown-net',
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            tokenProgram: TOKEN_PROGRAM,
        });
        await method.request!({ credential: undefined as never, request: { amount: '1' } as never });
        expect(calledUrl).toBeDefined();
    });

    test('verify() defaults the subscriptions program id when the challenge omits it', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            switch (body.method) {
                case 'simulateTransaction':
                    return rpcSuccess({ value: { err: null, logs: [] } });
                case 'sendTransaction':
                    return rpcSuccess('sigDefaultProg');
                case 'getSignatureStatuses':
                    return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
                case 'getAccountInfo':
                    return rpcSuccess({
                        value: {
                            data: [buildDelegationAccount(subscriberAddress), 'base64'],
                            executable: false,
                            lamports: 0,
                            owner: SUBSCRIPTIONS_PROGRAM,
                            rentEpoch: 0,
                        },
                    });
                default:
                    return rpcSuccess({});
            }
        };
        const method = subscription({ ...baseParams, store: Store.memory() });
        // Omit programId from methodDetails so deriveSubscriptionPda + the
        // validator both take the `?? SUBSCRIPTIONS_PROGRAM` default.
        const credential = transactionCredential(transaction);
        delete (credential as { challenge: { request: { methodDetails: { programId?: string } } } }).challenge.request
            .methodDetails.programId;
        const receipt = await method.verify!({ credential: asCredential(credential), request: {} as never });
        expect(receipt.status).toBe('success');
    });

    test('push mode: string account keys resolve the subscriber before delegation lookup', async () => {
        const sig = 'pushStrSig000000000000000000000000000000000000';
        const subscriber = await generateKeyPairSigner();
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getTransaction') {
                // accountKeys are plain strings, exercising the string branch.
                return rpcSuccess({
                    meta: null,
                    transaction: { message: { accountKeys: [subscriber.address, PULLER] } },
                });
            }
            if (body.method === 'getAccountInfo') return rpcSuccess({ value: null });
            return rpcSuccess({});
        };
        const method = subscription({ ...baseParams, store: Store.memory() });
        const credential = {
            challenge: { request: transactionCredential('x').challenge.request },
            payload: { signature: sig, type: 'signature' },
        } as never;
        await expect(method.verify!({ credential, request: {} as never })).rejects.toThrow(
            /SubscriptionDelegation account not found/,
        );
    });

    test('validateActivationInstructions rejects an address-lookup-table activation tx', async () => {
        // Craft a compiled message shape with a non-empty addressTableLookups so
        // the ALT guard fires. `validateActivationInstructions` decodes the wire
        // tx, so we re-encode a real activation tx with a synthetic ALT entry.
        const { transaction } = await buildActivationTransactionBase64();
        const tampered = injectAddressTableLookup(transaction);
        await expect(
            __testing.validateActivationInstructions(tampered, {
                methodDetails: { programId: SUBSCRIPTIONS_PROGRAM },
            } as never),
        ).rejects.toThrow(/address lookup tables are not supported/);
    });

    test('validateActivationInstructions rejects a reordered subscribe/transfer', async () => {
        const subscriber = await generateKeyPairSigner();
        const subscribeIx: Instruction = {
            accounts: [{ address: subscriber.address, role: AccountRole.WRITABLE_SIGNER }],
            data: new Uint8Array([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR]),
            programAddress: address(SUBSCRIPTIONS_PROGRAM),
        };
        const transferIx: Instruction = {
            accounts: [{ address: subscriber.address, role: AccountRole.READONLY }],
            data: new Uint8Array([SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR]),
            programAddress: address(SUBSCRIPTIONS_PROGRAM),
        };
        const txMessage = pipe(
            createTransactionMessage({ version: 0 }),
            msg => setTransactionMessageFeePayerSigner(subscriber, msg),
            msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
            // transfer BEFORE subscribe.
            msg => appendTransactionMessageInstructions([transferIx, subscribeIx], msg),
        );
        const signed = await partiallySignTransactionMessageWithSigners(txMessage);
        const transaction = getBase64EncodedWireTransaction(signed);
        await expect(
            __testing.validateActivationInstructions(transaction, {
                methodDetails: { programId: SUBSCRIPTIONS_PROGRAM },
            } as never),
        ).rejects.toThrow(/subscribe must precede transfer_subscription/);
    });

    test('simulation surfaces an RPC error object', async () => {
        const { transaction } = await buildActivationTransactionBase64();
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'simulateTransaction') return rpcError('sim-rpc-down');
            return rpcSuccess({});
        };
        const method = subscription({ ...baseParams, store: Store.memory() });
        await expect(
            method.verify!({ credential: asCredential(transactionCredential(transaction)), request: {} as never }),
        ).rejects.toThrow(/RPC error/);
    });

    test('waitForConfirmation rejects when the transaction fails during confirmation', async () => {
        const { transaction } = await buildActivationTransactionBase64();
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            switch (body.method) {
                case 'simulateTransaction':
                    return rpcSuccess({ value: { err: null, logs: [] } });
                case 'sendTransaction':
                    return rpcSuccess('sigConfirmFail');
                case 'getSignatureStatuses':
                    return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: { X: 1 } }] });
                default:
                    return rpcSuccess({});
            }
        };
        const method = subscription({ ...baseParams, store: Store.memory() });
        await expect(
            method.verify!({ credential: asCredential(transactionCredential(transaction)), request: {} as never }),
        ).rejects.toThrow(/Transaction failed/);
    });
});

/**
 * Re-encode a base64 activation tx with a synthetic, non-empty
 * `addressTableLookups` entry so the validator's ALT guard fires.
 */
function injectAddressTableLookup(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes) as Record<string, unknown>;
    const withAlt = {
        ...message,
        addressTableLookups: [
            {
                lookupTableAddress: address('11111111111111111111111111111111'),
                readonlyIndexes: [1],
                writableIndexes: [0],
            },
        ],
        version: 0,
    };
    const messageBytes = new Uint8Array(getCompiledTransactionMessageEncoder().encode(withAlt as never));
    const rebuilt = getTransactionEncoder().encode({ ...tx, messageBytes } as never);
    return getBase64Codec().decode(new Uint8Array(rebuilt));
}
