/**
 * Behavioral tests for the server-side Solana subscription handler.
 *
 * Covers configuration validation, request() shaping, and the verify() flow
 * across pull and push modes — with RPC interactions stubbed via globalThis.fetch.
 * Internal pure helpers (instruction validators, base58/base64url codecs,
 * SubscriptionDelegation decoder) are exercised directly through the
 * `__testing` export.
 */
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import {
    AccountRole,
    address,
    appendTransactionMessageInstructions,
    type Blockhash,
    createTransactionMessage,
    generateKeyPairSigner,
    getBase64EncodedWireTransaction,
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
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
} from '../constants.js';
import { __testing, subscription } from '../server/Subscription.js';

const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;

const PLAN_ID = '8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT';
const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const PULLER = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';

// ── Test setup ──

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

/** Build a compiled-message-style activation transaction (subscriber-signed). */
async function buildActivationTransactionBase64(
    options: {
        extraInstructions?: 'duplicate-subscribe' | 'duplicate-transfer' | 'reorder' | 'no-subscribe' | 'no-transfer';
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
        case 'reorder':
            instructions = [transferIx, subscribeIx];
            break;
        case 'no-subscribe':
            instructions = [transferIx];
            break;
        case 'no-transfer':
            instructions = [subscribeIx];
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

// ══════════════════════════════════════════════════════════════════════
// Configuration validation
// ══════════════════════════════════════════════════════════════════════

describe('subscription() config validation', () => {
    const baseParams = {
        decimals: 6,
        mint: MINT,
        periodCount: 30,
        periodUnit: 'day' as const,
        planId: PLAN_ID,
        puller: PULLER,
        recipient: RECIPIENT,
        tokenProgram: TOKEN_PROGRAM,
    };

    test('rejects an unrecognised tokenProgram', () => {
        expect(() => subscription({ ...baseParams, tokenProgram: 'not-a-token-program' })).toThrow(
            /tokenProgram must be/,
        );
    });

    test('rejects a periodCount that is out of range for `day`', () => {
        expect(() => subscription({ ...baseParams, periodCount: 400 })).toThrow(/exceeds 365/);
    });

    test('rejects a periodCount that is out of range for `week`', () => {
        expect(() => subscription({ ...baseParams, periodCount: 60, periodUnit: 'week' })).toThrow(/exceeds 52/);
    });

    test('rejects a non-signer object passed as signer', () => {
        expect(() => subscription({ ...baseParams, signer: {} as never })).toThrow(/signTransactions/);
    });

    test('accepts a valid Token-2022 configuration', () => {
        expect(() => subscription({ ...baseParams, tokenProgram: TOKEN_2022_PROGRAM })).not.toThrow();
    });
});

// ══════════════════════════════════════════════════════════════════════
// request() shaping
// ══════════════════════════════════════════════════════════════════════

describe('subscription().request()', () => {
    test('builds canonical methodDetails when no credential is present', async () => {
        globalThis.fetch = async () => rpcSuccess({ value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 } });
        const method = subscription({
            decimals: 6,
            mint: MINT,
            network: 'devnet',
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            tokenProgram: TOKEN_PROGRAM,
        });
        const result = await method.request!({
            credential: null,
            request: {
                amount: '10000000',
                currency: MINT,
                methodDetails: {
                    decimals: 6,
                    mint: MINT,
                    planId: PLAN_ID,
                    puller: PULLER,
                    tokenProgram: TOKEN_PROGRAM,
                },
                periodCount: '30',
                periodUnit: 'day',
                recipient: RECIPIENT,
            } as never,
        });
        expect(result.methodDetails.network).toBe('devnet');
        expect(result.methodDetails.planId).toBe(PLAN_ID);
        expect(result.methodDetails.programId).toBe(SUBSCRIPTIONS_PROGRAM);
        expect(result.methodDetails.recentBlockhash).toBe(BLOCKHASH);
        expect(result.methodDetails.puller).toBe(PULLER);
        expect(result.recipient).toBe(RECIPIENT);
    });

    test('skips blockhash fetch when a credential is present (verify path)', async () => {
        let fetchCalls = 0;
        globalThis.fetch = async () => {
            fetchCalls += 1;
            return rpcSuccess({});
        };
        const method = subscription({
            decimals: 6,
            mint: MINT,
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            tokenProgram: TOKEN_PROGRAM,
        });
        await method.request!({
            credential: { challenge: { request: { amount: '1', currency: MINT } } } as never,
            request: {
                amount: '10000000',
                currency: MINT,
                methodDetails: {
                    decimals: 6,
                    mint: MINT,
                    planId: PLAN_ID,
                    puller: PULLER,
                    tokenProgram: TOKEN_PROGRAM,
                },
                periodCount: '30',
                periodUnit: 'day',
                recipient: RECIPIENT,
            } as never,
        });
        expect(fetchCalls).toBe(0);
    });

    test('tolerates blockhash fetch failure', async () => {
        globalThis.fetch = async () => {
            throw new Error('rpc unreachable');
        };
        const method = subscription({
            decimals: 6,
            mint: MINT,
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            tokenProgram: TOKEN_PROGRAM,
        });
        const result = await method.request!({
            credential: null,
            request: {
                amount: '10000000',
                currency: MINT,
                methodDetails: {
                    decimals: 6,
                    mint: MINT,
                    planId: PLAN_ID,
                    puller: PULLER,
                    tokenProgram: TOKEN_PROGRAM,
                },
                periodCount: '30',
                periodUnit: 'day',
                recipient: RECIPIENT,
            } as never,
        });
        expect(result.methodDetails.recentBlockhash).toBeUndefined();
    });

    test('emits feePayer/feePayerKey when a signer is configured', async () => {
        const signer = await generateKeyPairSigner();
        globalThis.fetch = async () => rpcSuccess({ value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 } });
        const method = subscription({
            decimals: 6,
            mint: MINT,
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            signer,
            tokenProgram: TOKEN_PROGRAM,
        });
        const result = await method.request!({
            credential: null,
            request: {
                amount: '10000000',
                currency: MINT,
                methodDetails: {
                    decimals: 6,
                    mint: MINT,
                    planId: PLAN_ID,
                    puller: PULLER,
                    tokenProgram: TOKEN_PROGRAM,
                },
                periodCount: '30',
                periodUnit: 'day',
                recipient: RECIPIENT,
            } as never,
        });
        expect(result.methodDetails.feePayer).toBe(true);
        expect(result.methodDetails.feePayerKey).toBe(signer.address);
    });

    test('echoes optional splits and subscriptionExpires when supplied', async () => {
        globalThis.fetch = async () => rpcSuccess({ value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 } });
        const method = subscription({
            decimals: 6,
            mint: MINT,
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            splits: [{ bps: 100, recipient: RECIPIENT }],
            subscriptionExpires: '2026-07-14T12:00:00Z',
            tokenProgram: TOKEN_PROGRAM,
        });
        const result = await method.request!({
            credential: null,
            request: {
                amount: '10000000',
                currency: MINT,
                methodDetails: {
                    decimals: 6,
                    mint: MINT,
                    planId: PLAN_ID,
                    puller: PULLER,
                    tokenProgram: TOKEN_PROGRAM,
                },
                periodCount: '30',
                periodUnit: 'day',
                recipient: RECIPIENT,
            } as never,
        });
        expect(result.methodDetails.splits).toEqual([{ bps: 100, recipient: RECIPIENT }]);
        expect(result.subscriptionExpires).toBe('2026-07-14T12:00:00Z');
    });
});

// ══════════════════════════════════════════════════════════════════════
// validateActivationInstructions (pure)
// ══════════════════════════════════════════════════════════════════════

describe('validateActivationInstructions', () => {
    const challenge = {
        methodDetails: { programId: SUBSCRIPTIONS_PROGRAM },
    } as never;

    test('accepts a well-formed [subscribe, transfer_subscription] sequence', async () => {
        const { transaction } = await buildActivationTransactionBase64();
        expect(() => __testing.validateActivationInstructions(transaction, challenge)).not.toThrow();
    });

    test('rejects a transaction missing subscribe', async () => {
        const { transaction } = await buildActivationTransactionBase64({ extraInstructions: 'no-subscribe' });
        expect(() => __testing.validateActivationInstructions(transaction, challenge)).toThrow(/missing subscribe/);
    });

    test('rejects a transaction missing transfer_subscription', async () => {
        const { transaction } = await buildActivationTransactionBase64({ extraInstructions: 'no-transfer' });
        expect(() => __testing.validateActivationInstructions(transaction, challenge)).toThrow(
            /missing transfer_subscription/,
        );
    });

    test('rejects multiple subscribe instructions', async () => {
        const { transaction } = await buildActivationTransactionBase64({ extraInstructions: 'duplicate-subscribe' });
        expect(() => __testing.validateActivationInstructions(transaction, challenge)).toThrow(/Multiple subscribe/);
    });

    test('rejects multiple transfer_subscription instructions', async () => {
        const { transaction } = await buildActivationTransactionBase64({ extraInstructions: 'duplicate-transfer' });
        expect(() => __testing.validateActivationInstructions(transaction, challenge)).toThrow(
            /Multiple transfer_subscription/,
        );
    });

    test('rejects when transfer_subscription precedes subscribe', async () => {
        const { transaction } = await buildActivationTransactionBase64({ extraInstructions: 'reorder' });
        expect(() => __testing.validateActivationInstructions(transaction, challenge)).toThrow(
            /subscribe must precede/,
        );
    });

    test('rejects an undecodable base64 input', () => {
        expect(() => __testing.validateActivationInstructions('not-a-real-tx', challenge)).toThrow(
            /Invalid transaction/,
        );
    });
});

// ══════════════════════════════════════════════════════════════════════
// extractSubscriberFromTransaction
// ══════════════════════════════════════════════════════════════════════

describe('extractSubscriberFromTransaction', () => {
    test('returns the first signer when fee sponsorship is off', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const challenge = {
            methodDetails: { feePayer: false, puller: PULLER },
        } as never;
        const subscriber = __testing.extractSubscriberFromTransaction(transaction, challenge);
        expect(subscriber.toString()).toBe(subscriberAddress);
    });

    test('rejects when the first signer is the puller', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const challenge = {
            methodDetails: { feePayer: false, puller: subscriberAddress },
        } as never;
        expect(() => __testing.extractSubscriberFromTransaction(transaction, challenge)).toThrow(
            /Subscriber cannot be the server puller/,
        );
    });

    test('walks past the server fee payer when fee sponsorship is on', async () => {
        // Build a tx whose fee payer is a server pubkey and the second signer is
        // the subscriber, so extractSubscriberFromTransaction must skip slot 0.
        const feePayer = await generateKeyPairSigner();
        const subscriber = await generateKeyPairSigner();
        const subscribeIx: Instruction = {
            accounts: [
                { address: feePayer.address, role: AccountRole.WRITABLE_SIGNER },
                { address: subscriber.address, role: AccountRole.WRITABLE_SIGNER },
            ],
            data: new Uint8Array([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR]),
            programAddress: address(SUBSCRIPTIONS_PROGRAM),
        };
        const transferIx: Instruction = {
            accounts: [
                { address: feePayer.address, role: AccountRole.WRITABLE_SIGNER },
                { address: subscriber.address, role: AccountRole.READONLY },
            ],
            data: new Uint8Array([SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR]),
            programAddress: address(SUBSCRIPTIONS_PROGRAM),
        };
        const txMessage = pipe(
            createTransactionMessage({ version: 0 }),
            msg => setTransactionMessageFeePayerSigner(feePayer, msg),
            msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
            msg => appendTransactionMessageInstructions([subscribeIx, transferIx], msg),
        );
        const signed = await partiallySignTransactionMessageWithSigners(txMessage);
        const txBase64 = getBase64EncodedWireTransaction(signed);
        const challenge = {
            methodDetails: { feePayer: true, feePayerKey: feePayer.address, puller: PULLER },
        } as never;
        expect(__testing.extractSubscriberFromTransaction(txBase64, challenge).toString()).toBe(subscriber.address);
    });
});

// ══════════════════════════════════════════════════════════════════════
// SubscriptionDelegation decoder
// ══════════════════════════════════════════════════════════════════════

describe('decodeSubscriptionDelegation', () => {
    test('reads each field at the expected offset', () => {
        const data = new Uint8Array(1 + 32 * 3 + 8 + 32 + 32 + 8 + 8 + 8 + 8);
        let off = 0;
        data[off] = 1; // discriminator
        off += 1;
        // subscriber, delegatee, payer pubkeys — fill with distinct patterns
        data.set(new Uint8Array(32).fill(0xaa), off);
        off += 32;
        data.set(new Uint8Array(32).fill(0xbb), off);
        off += 32;
        data.set(new Uint8Array(32).fill(0xcc), off);
        off += 32;
        // init_id u64
        off += 8;
        // plan_pda
        data.set(new Uint8Array(32).fill(0xdd), off);
        off += 32;
        // mint
        data.set(new Uint8Array(32).fill(0xee), off);
        off += 32;
        // amount_per_period u64 = 10_000_000
        writeU64Le(data, off, 10_000_000n);
        off += 8;
        // period_hours u64 = 720
        writeU64Le(data, off, 720n);
        off += 8;
        // current_period_start_ts i64 = 1737216000 (2025-01-18T16:00:00Z)
        writeU64Le(data, off, 1737216000n);
        off += 8;
        // amount_pulled_in_period u64 = 10_000_000
        writeU64Le(data, off, 10_000_000n);

        const decoded = __testing.decodeSubscriptionDelegation(data);
        expect(decoded.subscriber).toBe(__testing.encodeBase58(new Uint8Array(32).fill(0xaa)));
        expect(decoded.planPda).toBe(__testing.encodeBase58(new Uint8Array(32).fill(0xdd)));
        expect(decoded.mint).toBe(__testing.encodeBase58(new Uint8Array(32).fill(0xee)));
        expect(decoded.amountPerPeriod).toBe('10000000');
        expect(decoded.periodHours).toBe(720);
        expect(decoded.currentPeriodStartTs).toBe(1737216000);
        expect(decoded.amountPulledInPeriod).toBe('10000000');
    });

    function writeU64Le(buf: Uint8Array, offset: number, value: bigint) {
        for (let i = 0; i < 8; i += 1) {
            buf[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
        }
    }
});

// ══════════════════════════════════════════════════════════════════════
// base58 / base64url codecs (round-trip)
// ══════════════════════════════════════════════════════════════════════

describe('encoding helpers', () => {
    test('encodeBase58 and decodeBase58 roundtrip arbitrary bytes', () => {
        const bytes = new Uint8Array([0, 0, 1, 255, 128, 64, 32, 16, 8, 4, 2, 1]);
        const s = __testing.encodeBase58(bytes);
        const back = __testing.decodeBase58(s);
        expect(Array.from(back)).toEqual(Array.from(bytes));
    });

    test('encodeBase58 handles all-zero leading bytes', () => {
        const bytes = new Uint8Array([0, 0, 0, 42]);
        const s = __testing.encodeBase58(bytes);
        expect(s.startsWith('111')).toBe(true);
        const back = __testing.decodeBase58(s);
        expect(Array.from(back)).toEqual([0, 0, 0, 42]);
    });

    test('encodeBase58 handles the empty input', () => {
        expect(__testing.encodeBase58(new Uint8Array())).toBe('');
        expect(__testing.decodeBase58('').length).toBe(0);
    });

    test('decodeBase58 throws on invalid characters', () => {
        expect(() => __testing.decodeBase58('0OIl')).toThrow(/Invalid base58 character/);
    });

    test('base64UrlEncodeNoPadding strips padding and remaps + and /', () => {
        const bytes = new Uint8Array([0xfb, 0xff, 0xbf]);
        const s = __testing.base64UrlEncodeNoPadding(bytes);
        expect(s).not.toMatch(/=/);
        expect(s).not.toMatch(/\+/);
        expect(s).not.toMatch(/\//);
    });
});

// ══════════════════════════════════════════════════════════════════════
// verify() — end-to-end push-mode happy path
// ══════════════════════════════════════════════════════════════════════

describe('subscription().verify() (push mode)', () => {
    test('rejects activation when first-period charge did not execute', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const txSignature = '5J8KKfgKBLPDoCSk7B7TwAdSP3KtkfxYGYQH52SVgyM5XQXfeaG3xH8E3uYmGNLcoNNgWp3JjPdvzNwM4ZmJyREq';

        // Build a `SubscriptionDelegation` byte buffer with amount_pulled = 0 so
        // verify() raises "first-period charge not executed".
        const data = new Uint8Array(1 + 32 * 3 + 8 + 32 + 32 + 8 + 8 + 8 + 8);
        // Set subscriber bytes to match the activation tx signer (decoded base58).
        const subscriberBytes = __testing.decodeBase58(subscriberAddress);
        data.set(subscriberBytes, 1);
        // plan_pda, mint left as zeros — verify will fail on plan mismatch before
        // reaching amount checks. To exercise the "first charge" path we set them.
        const planBytes = __testing.decodeBase58(PLAN_ID);
        const mintBytes = __testing.decodeBase58(MINT);
        data.set(planBytes, 1 + 32 * 3 + 8);
        data.set(mintBytes, 1 + 32 * 3 + 8 + 32);
        // amount_per_period = 10_000_000
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32, 10_000_000n);
        // period_hours = 720
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8, 720n);
        // current_period_start_ts = anything
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8 + 8, 1737216000n);
        // amount_pulled_in_period = 0 (the failure we want to test)
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8 + 8 + 8, 0n);

        const accountB64 = Buffer.from(data).toString('base64');

        globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            switch (body.method) {
                case 'simulateTransaction':
                    return rpcSuccess({ value: { err: null, logs: [] } });
                case 'sendTransaction':
                    return rpcSuccess(txSignature);
                case 'getSignatureStatuses':
                    return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
                case 'getAccountInfo':
                    return rpcSuccess({
                        value: {
                            data: [accountB64, 'base64'],
                            owner: SUBSCRIPTIONS_PROGRAM,
                            lamports: 0,
                            executable: false,
                            rentEpoch: 0,
                        },
                    });
                default:
                    return rpcSuccess({});
            }
        };

        const method = subscription({
            decimals: 6,
            mint: MINT,
            network: 'devnet',
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            rpcUrl: 'https://mock-rpc',
            store: Store.memory(),
            tokenProgram: TOKEN_PROGRAM,
        });

        await expect(
            method.verify!({
                credential: {
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
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { transaction, type: 'transaction' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/first-period charge/);
    });

    test('rejects type="signature" with feePayer=true', async () => {
        globalThis.fetch = async () => rpcSuccess({});
        const method = subscription({
            decimals: 6,
            mint: MINT,
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            tokenProgram: TOKEN_PROGRAM,
        });
        await expect(
            method.verify!({
                credential: {
                    challenge: {
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                feePayer: true,
                                mint: MINT,
                                planId: PLAN_ID,
                                puller: PULLER,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { signature: 'abc', type: 'signature' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/fee sponsorship/);
    });

    test('rejects an unknown payload type', async () => {
        const method = subscription({
            decimals: 6,
            mint: MINT,
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            tokenProgram: TOKEN_PROGRAM,
        });
        await expect(
            method.verify!({
                credential: {
                    challenge: { request: { methodDetails: {} } },
                    payload: { type: 'mystery' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/payload type/);
    });

    test('returns a successful receipt when on-chain state matches the challenge (pull mode)', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const txSignature = '5J8KKfgKBLPDoCSk7B7TwAdSP3KtkfxYGYQH52SVgyM5XQXfeaG3xH8E3uYmGNLcoNNgWp3JjPdvzNwM4ZmJyREq';
        const data = new Uint8Array(1 + 32 * 3 + 8 + 32 + 32 + 8 + 8 + 8 + 8);
        data.set(__testing.decodeBase58(subscriberAddress), 1);
        data.set(__testing.decodeBase58(PLAN_ID), 1 + 32 * 3 + 8);
        data.set(__testing.decodeBase58(MINT), 1 + 32 * 3 + 8 + 32);
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32, 10_000_000n);
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8, 720n);
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8 + 8, 1737216000n);
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8 + 8 + 8, 10_000_000n);
        const accountB64 = Buffer.from(data).toString('base64');

        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            switch (body.method) {
                case 'simulateTransaction':
                    return rpcSuccess({ value: { err: null, logs: [] } });
                case 'sendTransaction':
                    return rpcSuccess(txSignature);
                case 'getSignatureStatuses':
                    return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
                case 'getAccountInfo':
                    return rpcSuccess({
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

        const method = subscription({
            decimals: 6,
            mint: MINT,
            network: 'devnet',
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            rpcUrl: 'https://mock-rpc',
            tokenProgram: TOKEN_PROGRAM,
        });
        const receipt = await method.verify!({
            credential: {
                challenge: {
                    id: 'test-challenge',
                    request: {
                        amount: '10000000',
                        currency: MINT,
                        externalId: 'order-99',
                        methodDetails: {
                            decimals: 6,
                            mint: MINT,
                            network: 'devnet',
                            planId: PLAN_ID,
                            programId: SUBSCRIPTIONS_PROGRAM,
                            puller: PULLER,
                            tokenProgram: TOKEN_PROGRAM,
                        },
                        periodCount: '30',
                        periodUnit: 'day',
                        recipient: RECIPIENT,
                    },
                },
                payload: { transaction, type: 'transaction' },
            } as never,
            request: {} as never,
        });
        expect((receipt as { status: string }).status).toBe('success');
    });

    test('rejects when on-chain delegation references a different plan', async () => {
        const { transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const wrongPlan = '11111111111111111111111111111111';
        const data = new Uint8Array(1 + 32 * 3 + 8 + 32 + 32 + 8 + 8 + 8 + 8);
        data.set(__testing.decodeBase58(subscriberAddress), 1);
        data.set(__testing.decodeBase58(wrongPlan), 1 + 32 * 3 + 8);
        data.set(__testing.decodeBase58(MINT), 1 + 32 * 3 + 8 + 32);
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32, 10_000_000n);
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8, 720n);
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8 + 8, 1737216000n);
        writeU64Le(data, 1 + 32 * 3 + 8 + 32 + 32 + 8 + 8 + 8, 10_000_000n);
        const accountB64 = Buffer.from(data).toString('base64');

        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            switch (body.method) {
                case 'simulateTransaction':
                    return rpcSuccess({ value: { err: null, logs: [] } });
                case 'sendTransaction':
                    return rpcSuccess('sigA');
                case 'getSignatureStatuses':
                    return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
                case 'getAccountInfo':
                    return rpcSuccess({
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
        const method = subscription({
            decimals: 6,
            mint: MINT,
            network: 'devnet',
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            rpcUrl: 'https://mock-rpc',
            tokenProgram: TOKEN_PROGRAM,
        });
        await expect(
            method.verify!({
                credential: {
                    challenge: {
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                planId: PLAN_ID,
                                programId: SUBSCRIPTIONS_PROGRAM,
                                puller: PULLER,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { transaction, type: 'transaction' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/plan mismatch/);
    });

    test('rejects when SubscriptionDelegation account is absent after activation', async () => {
        const { transaction } = await buildActivationTransactionBase64();
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            switch (body.method) {
                case 'simulateTransaction':
                    return rpcSuccess({ value: { err: null, logs: [] } });
                case 'sendTransaction':
                    return rpcSuccess('sigA');
                case 'getSignatureStatuses':
                    return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
                case 'getAccountInfo':
                    return rpcSuccess({ value: null });
                default:
                    return rpcSuccess({});
            }
        };
        const method = subscription({
            decimals: 6,
            mint: MINT,
            network: 'devnet',
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            rpcUrl: 'https://mock-rpc',
            tokenProgram: TOKEN_PROGRAM,
        });
        await expect(
            method.verify!({
                credential: {
                    challenge: {
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                planId: PLAN_ID,
                                programId: SUBSCRIPTIONS_PROGRAM,
                                puller: PULLER,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { transaction, type: 'transaction' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/SubscriptionDelegation account not found/);
    });

    test('rejects on simulation failure', async () => {
        const { transaction } = await buildActivationTransactionBase64();
        const errorSpy = ((): { calls: number; restore: () => void } => {
            const original = console.error;
            let calls = 0;
            console.error = () => {
                calls += 1;
            };
            return {
                calls,
                restore: () => {
                    console.error = original;
                },
            };
        })();
        try {
            globalThis.fetch = async (_input, init) => {
                const body = JSON.parse(init?.body as string) as { method?: string };
                if (body.method === 'simulateTransaction') {
                    return rpcSuccess({ value: { err: { InstructionError: [1, 'Custom'] }, logs: ['log line'] } });
                }
                return rpcSuccess({});
            };
            const method = subscription({
                decimals: 6,
                mint: MINT,
                network: 'devnet',
                periodCount: 30,
                periodUnit: 'day',
                planId: PLAN_ID,
                puller: PULLER,
                recipient: RECIPIENT,
                rpcUrl: 'https://mock-rpc',
                tokenProgram: TOKEN_PROGRAM,
            });
            await expect(
                method.verify!({
                    credential: {
                        challenge: {
                            request: {
                                amount: '10000000',
                                currency: MINT,
                                methodDetails: {
                                    decimals: 6,
                                    mint: MINT,
                                    planId: PLAN_ID,
                                    programId: SUBSCRIPTIONS_PROGRAM,
                                    puller: PULLER,
                                    tokenProgram: TOKEN_PROGRAM,
                                },
                                periodCount: '30',
                                periodUnit: 'day',
                                recipient: RECIPIENT,
                            },
                        },
                        payload: { transaction, type: 'transaction' },
                    } as never,
                    request: {} as never,
                }),
            ).rejects.toThrow(/simulation failed/);
        } finally {
            errorSpy.restore();
        }
    });

    test('rejects on broadcast RPC error', async () => {
        const { transaction } = await buildActivationTransactionBase64();
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'simulateTransaction') {
                return rpcSuccess({ value: { err: null, logs: [] } });
            }
            if (body.method === 'sendTransaction') {
                return new Response(
                    JSON.stringify({ jsonrpc: '2.0', id: 1, error: { message: 'simulation rejected' } }),
                    {
                        headers: { 'Content-Type': 'application/json' },
                    },
                );
            }
            return rpcSuccess({});
        };
        const method = subscription({
            decimals: 6,
            mint: MINT,
            network: 'devnet',
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            rpcUrl: 'https://mock-rpc',
            tokenProgram: TOKEN_PROGRAM,
        });
        await expect(
            method.verify!({
                credential: {
                    challenge: {
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                planId: PLAN_ID,
                                programId: SUBSCRIPTIONS_PROGRAM,
                                puller: PULLER,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { transaction, type: 'transaction' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/RPC error/);
    });

    test('rejects when push-mode signature is replayed (consumed)', async () => {
        const store = Store.memory();
        const sig = 'replayedSig0000000000000000000000000000000000';
        await store.put(`solana-subscription:consumed:${sig}`, true);
        globalThis.fetch = async () => rpcSuccess({});
        const method = subscription({
            decimals: 6,
            mint: MINT,
            network: 'devnet',
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            rpcUrl: 'https://mock-rpc',
            store,
            tokenProgram: TOKEN_PROGRAM,
        });
        await expect(
            method.verify!({
                credential: {
                    challenge: {
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                planId: PLAN_ID,
                                programId: SUBSCRIPTIONS_PROGRAM,
                                puller: PULLER,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { signature: sig, type: 'signature' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/already consumed/);
    });

    test('rejects when push-mode getTransaction returns null', async () => {
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getTransaction') return rpcSuccess(null);
            return rpcSuccess({});
        };
        const method = subscription({
            decimals: 6,
            mint: MINT,
            network: 'devnet',
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            rpcUrl: 'https://mock-rpc',
            tokenProgram: TOKEN_PROGRAM,
        });
        await expect(
            method.verify!({
                credential: {
                    challenge: {
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                planId: PLAN_ID,
                                programId: SUBSCRIPTIONS_PROGRAM,
                                puller: PULLER,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { signature: 'newsig', type: 'signature' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/not found/);
    });

    function writeU64Le(buf: Uint8Array, offset: number, value: bigint) {
        for (let i = 0; i < 8; i += 1) {
            buf[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
        }
    }
});
