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
    type MessagePartialSigner,
    partiallySignTransactionMessageWithSigners,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    type TransactionSigner,
} from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';
import { Challenge, Credential } from 'mppx';
import { Mppx, Store } from 'mppx/server';

import {
    SUBSCRIPTIONS_PROGRAM,
    SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
    SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
    MEMO_PROGRAM,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
} from '../constants.js';
import { __testing, subscription } from '../server/Subscription.js';
import { signSubscriptionAuthentication } from '../client/Subscription.js';
import { deriveSubscriptionAuthorityPda, deriveSubscriptionPda } from '../shared/subscription.js';

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

function buildDelegationData(
    subscriber: string,
    plan: string,
    amountPulled: bigint,
    currentPeriodStart = 1_737_216_000n,
    expiresAt = 0n,
): Uint8Array {
    const data = new Uint8Array(155);
    data[0] = 4;
    data[1] = 1;
    data[2] = 255;
    data.set(__testing.decodeBase58(subscriber), 3);
    data.set(__testing.decodeBase58(plan), 35);
    writeU64Le(data, 107, 10_000_000n);
    writeU64Le(data, 115, 720n);
    writeU64Le(data, 131, amountPulled);
    writeU64Le(data, 139, currentPeriodStart);
    writeU64Le(data, 147, expiresAt);
    return data;
}

function writeU64Le(buf: Uint8Array, offset: number, value: bigint) {
    for (let i = 0; i < 8; i += 1) {
        buf[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
    }
}

function buildAuthorityData(initId = 0n): Uint8Array {
    const data = new Uint8Array(106);
    data[0] = 0;
    writeU64Le(data, 98, initId);
    return data;
}

/** Build a compiled-message-style activation transaction (subscriber-signed). */
async function buildActivationTransactionBase64(
    options: {
        extraInstructions?:
            | 'duplicate-subscribe'
            | 'duplicate-transfer'
            | 'foreign-program'
            | 'reorder'
            | 'no-subscribe'
            | 'no-transfer';
        feePayerKey?: string;
        memo?: string;
        receiver?: string;
    } = {},
): Promise<{
    subscriber: TransactionSigner & MessagePartialSigner;
    subscriberAddress: string;
    transaction: string;
}> {
    const subscriber = await generateKeyPairSigner();
    const subscribeIx: Instruction = {
        accounts: [{ address: subscriber.address, role: AccountRole.WRITABLE_SIGNER }],
        data: new Uint8Array([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR]),
        programAddress: address(SUBSCRIPTIONS_PROGRAM),
    };
    const [recipientAta] = await findAssociatedTokenPda({
        mint: address(MINT),
        owner: address(options.receiver ?? RECIPIENT),
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const transferIx: Instruction = {
        // Previous nine-account client layout. The verifier also accepts the
        // Codama v0.5 ten-account layout and binds receiver_ata at slot 4.
        accounts: [
            { address: subscriber.address, role: AccountRole.READONLY },
            { address: address(PLAN_ID), role: AccountRole.READONLY },
            { address: subscriber.address, role: AccountRole.READONLY },
            { address: subscriber.address, role: AccountRole.READONLY },
            { address: subscriber.address, role: AccountRole.READONLY },
            { address: subscriber.address, role: AccountRole.READONLY },
            { address: recipientAta, role: AccountRole.WRITABLE },
            { address: address(MINT), role: AccountRole.READONLY },
            { address: address(TOKEN_PROGRAM), role: AccountRole.READONLY },
        ],
        data: new Uint8Array([SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR]),
        programAddress: address(SUBSCRIPTIONS_PROGRAM),
    };
    const foreignIx: Instruction = {
        accounts: [{ address: subscriber.address, role: AccountRole.WRITABLE_SIGNER }],
        data: new Uint8Array([2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
        programAddress: address(SYSTEM_PROGRAM),
    };
    const memoIx: Instruction = {
        data: new TextEncoder().encode(options.memo ?? ''),
        programAddress: address(MEMO_PROGRAM),
    };

    let instructions: Instruction[];
    switch (options.extraInstructions) {
        case 'duplicate-subscribe':
            instructions = [subscribeIx, subscribeIx, transferIx];
            break;
        case 'duplicate-transfer':
            instructions = [subscribeIx, transferIx, transferIx];
            break;
        case 'foreign-program':
            instructions = [subscribeIx, foreignIx, transferIx];
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
    if (options.memo !== undefined) instructions.push(memoIx);

    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(subscriber, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );
    const signed = await partiallySignTransactionMessageWithSigners(txMessage);
    return {
        subscriber,
        subscriberAddress: subscriber.address,
        transaction: getBase64EncodedWireTransaction(signed),
    };
}

async function buildAuthentication(challengeId: string, subscriber: TransactionSigner & MessagePartialSigner) {
    const subscriptionDelegation = await deriveSubscriptionPda({
        planPda: address(PLAN_ID),
        programId: address(SUBSCRIPTIONS_PROGRAM),
        subscriber: subscriber.address,
    });
    return signSubscriptionAuthentication({
        challengeId,
        signer: subscriber,
        subscriptionDelegation: subscriptionDelegation.toString(),
    });
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
        expect(result.methodDetails.planAddress).toBe(PLAN_ID);
        expect(result.methodDetails.subscriptionProgram).toBe(SUBSCRIPTIONS_PROGRAM);
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
            subscriptionExpires: '2100-07-14T12:00:00Z',
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
        expect(result.subscriptionExpires).toBe('2100-07-14T12:00:00Z');
    });
});

// ══════════════════════════════════════════════════════════════════════
// validateActivationInstructions (pure)
// ══════════════════════════════════════════════════════════════════════

describe('validateActivationInstructions', () => {
    const challenge = {
        amount: '10000000',
        methodDetails: {
            mint: MINT,
            subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
            tokenProgram: TOKEN_PROGRAM,
        },
        recipient: RECIPIENT,
    } as never;

    test('accepts a well-formed [subscribe, transfer_subscription] sequence', async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64();
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).resolves.toBeUndefined();
    });

    test('rejects a transaction missing subscribe', async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            extraInstructions: 'no-subscribe',
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/missing subscribe/);
    });

    test('rejects a transaction missing transfer_subscription', async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            extraInstructions: 'no-transfer',
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/missing transfer_subscription/);
    });

    test('rejects multiple subscribe instructions', async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            extraInstructions: 'duplicate-subscribe',
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/Multiple subscribe/);
    });

    test('rejects multiple transfer_subscription instructions', async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            extraInstructions: 'duplicate-transfer',
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/Multiple transfer_subscription/);
    });

    test('rejects an extra instruction to another program', async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            extraInstructions: 'foreign-program',
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/Unsupported program/);
    });

    test('rejects when transfer_subscription precedes subscribe', async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            extraInstructions: 'reorder',
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/subscribe must precede/);
    });

    test('rejects an undecodable base64 input', async () => {
        await expect(__testing.validateActivationInstructions('not-a-real-tx', challenge, RECIPIENT)).rejects.toThrow(
            /Invalid transaction/,
        );
    });

    test('rejects transfer_subscription to an ATA owned by another recipient', async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            receiver: '11111111111111111111111111111111',
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/receiver does not match the challenge recipient/);
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

    test('does not treat a non-signer account as the sponsored subscriber', async () => {
        const feePayer = await generateKeyPairSigner();
        const nonSigner = await generateKeyPairSigner();
        const ix: Instruction = {
            accounts: [{ address: nonSigner.address, role: AccountRole.READONLY }],
            data: new Uint8Array([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR]),
            programAddress: address(SUBSCRIPTIONS_PROGRAM),
        };
        const txMessage = pipe(
            createTransactionMessage({ version: 0 }),
            msg => setTransactionMessageFeePayerSigner(feePayer, msg),
            msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
            msg => appendTransactionMessageInstructions([ix], msg),
        );
        const signed = await partiallySignTransactionMessageWithSigners(txMessage);
        const challenge = {
            methodDetails: { feePayer: true, feePayerKey: feePayer.address, puller: PULLER },
        } as never;

        expect(() =>
            __testing.extractSubscriberFromTransaction(getBase64EncodedWireTransaction(signed), challenge),
        ).toThrow(/Could not identify subscriber/);
    });
});

// ══════════════════════════════════════════════════════════════════════
// SubscriptionDelegation decoder
// ══════════════════════════════════════════════════════════════════════

describe('decodeSubscriptionDelegation', () => {
    test('reads each field at the expected offset', () => {
        const data = new Uint8Array(155);
        data[0] = 4;
        data[1] = 1;
        data[2] = 255;
        data.set(new Uint8Array(32).fill(0xaa), 3);
        data.set(new Uint8Array(32).fill(0xbb), 35);
        writeU64Le(data, 107, 10_000_000n);
        writeU64Le(data, 115, 720n);
        writeU64Le(data, 131, 10_000_000n);
        writeU64Le(data, 139, 1_737_216_000n);

        const decoded = __testing.decodeSubscriptionDelegation(data);
        expect(decoded.subscriber).toBe(__testing.encodeBase58(new Uint8Array(32).fill(0xaa)));
        expect(decoded.planPda).toBe(__testing.encodeBase58(new Uint8Array(32).fill(0xbb)));
        expect(decoded.amountPerPeriod).toBe('10000000');
        expect(decoded.periodHours).toBe(720);
        expect(decoded.currentPeriodStartTs).toBe(1737216000);
        expect(decoded.amountPulledInPeriod).toBe('10000000');
    });
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
        const { subscriber, transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const authentication = await buildAuthentication('test-challenge', subscriber);
        const txSignature = '5J8KKfgKBLPDoCSk7B7TwAdSP3KtkfxYGYQH52SVgyM5XQXfeaG3xH8E3uYmGNLcoNNgWp3JjPdvzNwM4ZmJyREq';

        // Build a `SubscriptionDelegation` byte buffer with amount_pulled = 0 so
        // verify() raises "first-period charge not executed".
        const data = buildDelegationData(subscriberAddress, PLAN_ID, 0n);

        const accountB64 = Buffer.from(data).toString('base64');
        const authorityPda = await deriveSubscriptionAuthorityPda({
            mint: address(MINT),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: subscriber.address,
        });
        const authorityB64 = Buffer.from(buildAuthorityData()).toString('base64');

        globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
            const body = JSON.parse(init?.body as string) as { method?: string; params?: [string] };
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
                            data: [body.params?.[0] === authorityPda.toString() ? authorityB64 : accountB64, 'base64'],
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
                                planAddress: PLAN_ID,
                                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                                puller: PULLER,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { authentication, transaction, type: 'transaction' },
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

    test('rotates a stale bearer binding after a confirmed re-subscription', async () => {
        const { subscriber, transaction, subscriberAddress } = await buildActivationTransactionBase64({
            memo: 'order-99',
        });
        const authentication = await buildAuthentication('test-challenge', subscriber);
        const txSignature = '5J8KKfgKBLPDoCSk7B7TwAdSP3KtkfxYGYQH52SVgyM5XQXfeaG3xH8E3uYmGNLcoNNgWp3JjPdvzNwM4ZmJyREq';
        const data = buildDelegationData(
            subscriberAddress,
            PLAN_ID,
            10_000_000n,
            BigInt(Math.floor(Date.now() / 1000) - 60),
        );
        const accountB64 = Buffer.from(data).toString('base64');
        const authorityPda = await deriveSubscriptionAuthorityPda({
            mint: address(MINT),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: subscriber.address,
        });
        const authorityB64 = Buffer.from(buildAuthorityData()).toString('base64');

        const rpcMethods: string[] = [];
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string; params?: [string] };
            if (body.method) rpcMethods.push(body.method);
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
                            data: [body.params?.[0] === authorityPda.toString() ? authorityB64 : accountB64, 'base64'],
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

        const store = Store.memory();
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
        const credential = {
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
                        planAddress: PLAN_ID,
                        subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                        puller: PULLER,
                        tokenProgram: TOKEN_PROGRAM,
                    },
                    periodCount: '30',
                    periodUnit: 'day',
                    recipient: RECIPIENT,
                },
            },
            payload: { authentication, transaction, type: 'transaction' },
        };
        const subscriptionDelegation = await deriveSubscriptionPda({
            planPda: address(PLAN_ID),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: subscriber.address,
        });
        const bindingKey = `solana-subscription:authentication:${subscriptionDelegation}`;
        await store.put(bindingKey, {
            activationSignature: 'old-activation',
            authentication: { ...authentication, challengeId: 'old-challenge' },
            challengeId: 'old-challenge',
            periodStartTs: 0,
            subscriptionId: 'old-subscription',
        });
        const receipt = await method.verify!({
            credential: credential as never,
            request: {} as never,
        });
        expect((receipt as { status: string }).status).toBe('success');
        expect(await store.get(bindingKey)).toMatchObject({
            authentication,
            challengeId: 'test-challenge',
        });

        const recovered = await method.verify!({ credential: credential as never, request: {} as never });
        expect((recovered as { reference: string }).reference).toBe((receipt as { reference: string }).reference);
        expect(rpcMethods.filter(method => method === 'simulateTransaction')).toHaveLength(1);
        expect(rpcMethods.filter(method => method === 'sendTransaction')).toHaveLength(1);

        const accessCredential = {
            challenge: {
                ...credential.challenge,
                // Once activation has bound the proof, the opening challenge
                // expiry no longer invalidates that bearer proof.
                expires: '2000-01-01T00:00:00Z',
            },
            payload: {
                authentication,
                subscriptionDelegation: subscriptionDelegation.toString(),
                type: 'proof',
            },
        } as never;
        const firstAccess = await method.verify!({ credential: accessCredential, request: {} as never });
        const repeatedAccess = await method.verify!({ credential: accessCredential, request: {} as never });
        expect((firstAccess as { status: string }).status).toBe('success');
        expect((repeatedAccess as { status: string }).status).toBe('success');
        expect(firstAccess).toMatchObject({
            periodIndex: 0,
            reference: (receipt as { reference: string }).reference,
            subscriptionDelegation: subscriptionDelegation.toString(),
        });
    });

    test('public Mppx handler accepts a bound proof after activation challenge expiry', async () => {
        const subscriber = await generateKeyPairSigner();
        const periodStart = BigInt(Math.floor(Date.now() / 1000) - 60);
        const delegationData = buildDelegationData(subscriber.address, PLAN_ID, 10_000_000n, periodStart);
        const delegationB64 = Buffer.from(delegationData).toString('base64');
        const authorityB64 = Buffer.from(buildAuthorityData()).toString('base64');
        const authorityPda = await deriveSubscriptionAuthorityPda({
            mint: address(MINT),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: subscriber.address,
        });

        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string; params?: [string] };
            if (body.method === 'getAccountInfo') {
                return rpcSuccess({
                    value: {
                        data: [body.params?.[0] === authorityPda.toString() ? authorityB64 : delegationB64, 'base64'],
                        executable: false,
                        lamports: 0,
                        owner: SUBSCRIPTIONS_PROGRAM,
                        rentEpoch: 0,
                    },
                });
            }
            return rpcSuccess({});
        };

        const store = Store.memory();
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
        const mppx = Mppx.create({
            methods: [method],
            realm: 'api.example.com',
            secretKey: 'subscription-proof-test-secret-at-least-32-bytes',
        });
        const route = {
            amount: '10000000',
            currency: MINT,
            methodDetails: {
                decimals: 6,
                mint: MINT,
                planAddress: PLAN_ID,
                puller: PULLER,
                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                tokenProgram: TOKEN_PROGRAM,
            },
            periodCount: '30',
            periodUnit: 'day' as const,
            recipient: RECIPIENT,
        };
        const expiredRoute = mppx.subscription({
            ...route,
            expires: '2000-01-01T00:00:00Z',
        });
        const challengeResult = await expiredRoute(new Request('https://api.example.com/member'));
        expect(challengeResult.status).toBe(402);
        if (challengeResult.status !== 402) throw new Error('expected subscription challenge');
        const challenge = Challenge.fromResponse(challengeResult.challenge);
        const subscriptionDelegation = await deriveSubscriptionPda({
            planPda: address(PLAN_ID),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: subscriber.address,
        });
        const authentication = await buildAuthentication(challenge.id, subscriber);
        await store.put(`solana-subscription:authentication:${subscriptionDelegation}`, {
            activationSignature: 'confirmed-activation',
            authentication,
            challengeId: challenge.id,
            periodStartTs: Number(periodStart),
            subscriptionId: 'bound-subscription',
        });
        const proof = Credential.from({
            challenge,
            payload: {
                authentication,
                subscriptionDelegation: subscriptionDelegation.toString(),
                type: 'proof',
            },
        });

        const result = await mppx.subscription(route)(
            new Request('https://api.example.com/member', {
                headers: { Authorization: Credential.serialize(proof) },
            }),
        );

        expect(result.status).toBe(200);
        if (result.status === 200) {
            expect(result.withReceipt(new Response('member content')).headers.get('Payment-Receipt')).toBeTruthy();
        }
    });

    test('rejects an expired challenge before attempting activation', async () => {
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
                        expires: '2000-01-01T00:00:00Z',
                        id: 'expired-activation',
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                planAddress: PLAN_ID,
                                puller: PULLER,
                                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { transaction: 'not-a-transaction', type: 'transaction' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/challenge expired/);
    });

    test('rejects an expired subscription before attempting activation', async () => {
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
                        id: 'expired-subscription',
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                planAddress: PLAN_ID,
                                puller: PULLER,
                                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                            subscriptionExpires: '2000-01-01T00:00:00Z',
                        },
                    },
                    payload: { transaction: 'not-a-transaction', type: 'transaction' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/subscription expired/);
    });

    test('rejects when on-chain delegation references a different plan', async () => {
        const { subscriber, transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const authentication = await buildAuthentication('wrong-plan-challenge', subscriber);
        const wrongPlan = '11111111111111111111111111111111';
        const data = buildDelegationData(subscriberAddress, wrongPlan, 10_000_000n);
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
                        id: 'wrong-plan-challenge',
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                planAddress: PLAN_ID,
                                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                                puller: PULLER,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { authentication, transaction, type: 'transaction' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/plan mismatch/);
    });

    test('rejects when SubscriptionDelegation account is absent after activation', async () => {
        const { subscriber, transaction } = await buildActivationTransactionBase64();
        const authentication = await buildAuthentication('absent-account-challenge', subscriber);
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
                        id: 'absent-account-challenge',
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                planAddress: PLAN_ID,
                                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                                puller: PULLER,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { authentication, transaction, type: 'transaction' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/SubscriptionDelegation account not found/);
    });

    test('rejects on simulation failure', async () => {
        const { subscriber, transaction } = await buildActivationTransactionBase64();
        const authentication = await buildAuthentication('simulation-challenge', subscriber);
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
                            id: 'simulation-challenge',
                            request: {
                                amount: '10000000',
                                currency: MINT,
                                methodDetails: {
                                    decimals: 6,
                                    mint: MINT,
                                    planAddress: PLAN_ID,
                                    subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                                    puller: PULLER,
                                    tokenProgram: TOKEN_PROGRAM,
                                },
                                periodCount: '30',
                                periodUnit: 'day',
                                recipient: RECIPIENT,
                            },
                        },
                        payload: { authentication, transaction, type: 'transaction' },
                    } as never,
                    request: {} as never,
                }),
            ).rejects.toThrow(/simulation failed/);
        } finally {
            errorSpy.restore();
        }
    });

    test('rejects on broadcast RPC error', async () => {
        const { subscriber, transaction } = await buildActivationTransactionBase64();
        const authentication = await buildAuthentication('broadcast-challenge', subscriber);
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
                        id: 'broadcast-challenge',
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                planAddress: PLAN_ID,
                                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                                puller: PULLER,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    },
                    payload: { authentication, transaction, type: 'transaction' },
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
                                planAddress: PLAN_ID,
                                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
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

    test('concurrent push-mode activation returns exactly one receipt', async () => {
        const { subscriber, transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const authentication = await buildAuthentication('concurrent-challenge', subscriber);
        const accountB64 = Buffer.from(buildDelegationData(subscriberAddress, PLAN_ID, 10_000_000n)).toString('base64');
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getTransaction') {
                await Promise.resolve();
                return rpcSuccess({ meta: { err: null }, transaction: [transaction, 'base64'] });
            }
            if (body.method === 'getAccountInfo') {
                return rpcSuccess({
                    value: {
                        data: [accountB64, 'base64'],
                        executable: false,
                        lamports: 0,
                        owner: SUBSCRIPTIONS_PROGRAM,
                        rentEpoch: 0,
                    },
                });
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
            store: Store.memory(),
            tokenProgram: TOKEN_PROGRAM,
        });
        const credential = {
            challenge: {
                id: 'concurrent-challenge',
                request: {
                    amount: '10000000',
                    currency: MINT,
                    methodDetails: {
                        decimals: 6,
                        mint: MINT,
                        planAddress: PLAN_ID,
                        subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                        puller: PULLER,
                        tokenProgram: TOKEN_PROGRAM,
                    },
                    periodCount: '30',
                    periodUnit: 'day',
                    recipient: RECIPIENT,
                },
            },
            payload: { authentication, signature: 'same-activation-signature', type: 'signature' },
        } as never;

        const results = await Promise.allSettled(
            Array.from({ length: 16 }, () => method.verify!({ credential, request: {} as never })),
        );
        expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
        expect(results.filter(result => result.status === 'rejected')).toHaveLength(15);
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
                                planAddress: PLAN_ID,
                                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
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
