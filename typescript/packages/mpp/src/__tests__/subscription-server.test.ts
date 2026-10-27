/**
 * Behavioral tests for the server-side Solana subscription handler.
 *
 * Covers configuration validation, request() shaping, and the verify() flow
 * across pull and push modes — with RPC interactions stubbed via globalThis.fetch.
 * Internal pure helpers (instruction validators, base58/base64url codecs,
 * SubscriptionDelegation decoder) are exercised directly through the
 * `__testing` export.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
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
import { findAssociatedTokenPda, getCreateAssociatedTokenIdempotentInstruction } from '@solana-program/token';
import { Challenge, Credential } from 'mppx';
import { Mppx, Store } from 'mppx/server';

import {
    SUBSCRIPTIONS_INIT_AUTHORITY_DISCRIMINATOR,
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

/** The route request Mppx.create hands to verify(): this route's per-period amount. */
const ROUTE_REQUEST = { amount: '10000000' };

/** A challenge request bound to the default test route (mainnet-beta). */
const ROUTE_CHALLENGE_REQUEST = {
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
};

const TEST_SECRET = 'subscription-server-test-secret-of-32-bytes';
const TEST_REALM = 'subscription-test.example.com';

// ── Test setup ──

let originalFetch: typeof globalThis.fetch;

beforeEach(() => {
    originalFetch = globalThis.fetch;
    process.env.MPP_SECRET_KEY = TEST_SECRET;
    process.env.MPP_REALM = TEST_REALM;
});

afterEach(() => {
    globalThis.fetch = originalFetch;
    delete process.env.MPP_SECRET_KEY;
    delete process.env.MPP_REALM;
    vi.useRealTimers();
});

/**
 * Issue a challenge under the secret and realm `subscription()` resolves from
 * the environment, so the echoed challenge passes the HMAC binding in verify().
 */
function issueChallenge(fields: { expires?: string; intent: string; method: string; request: unknown }) {
    return Challenge.from({ ...fields, realm: TEST_REALM, secretKey: TEST_SECRET } as never);
}

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
        /** Create an ATA idempotently for this owner before subscribe. */
        ataOwner?: 'recipient' | 'subscriber';
        /** Override the ATA instruction's data (e.g. empty: non-idempotent Create). */
        ataData?: Uint8Array;
        /** Prepend an initialize_subscription_authority for this authority. */
        authorityInit?: 'subscriber' | 'unrelated';
        feePayerKey?: string;
        memo?: string;
        receiver?: string;
        /** Plan account named by the subscribe instruction (defaults to PLAN_ID). */
        subscribePlan?: string;
        version?: 'legacy' | 0;
    } = {},
): Promise<{
    subscriber: TransactionSigner & MessagePartialSigner;
    subscriberAddress: string;
    transaction: string;
}> {
    const subscriber = await generateKeyPairSigner();
    const subscriptionAuthority = await deriveSubscriptionAuthorityPda({
        mint: address(MINT),
        programId: address(SUBSCRIPTIONS_PROGRAM),
        subscriber: subscriber.address,
    });
    const subscribePlan = address(options.subscribePlan ?? PLAN_ID);
    const subscriptionDelegation = await deriveSubscriptionPda({
        planPda: subscribePlan,
        programId: address(SUBSCRIPTIONS_PROGRAM),
        subscriber: subscriber.address,
    });
    // Codama layout: subscriber, merchant, planPda, subscriptionPda,
    // subscriptionAuthorityPda, systemProgram, eventAuthority, selfProgram, payer.
    const subscribeIx: Instruction = {
        accounts: [
            { address: subscriber.address, role: AccountRole.WRITABLE_SIGNER },
            { address: address(PULLER), role: AccountRole.READONLY },
            { address: subscribePlan, role: AccountRole.READONLY },
            { address: subscriptionDelegation, role: AccountRole.WRITABLE },
            { address: subscriptionAuthority, role: AccountRole.READONLY },
            { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
            { address: address(RECIPIENT), role: AccountRole.READONLY },
            { address: address(SUBSCRIPTIONS_PROGRAM), role: AccountRole.READONLY },
            { address: subscriber.address, role: AccountRole.WRITABLE_SIGNER },
        ],
        data: new Uint8Array([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR]),
        programAddress: address(SUBSCRIPTIONS_PROGRAM),
    };
    const [subscriberAta] = await findAssociatedTokenPda({
        mint: address(MINT),
        owner: subscriber.address,
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const unrelated = await generateKeyPairSigner();
    const initAuthorityOwner = options.authorityInit === 'unrelated' ? unrelated.address : subscriber.address;
    const initAuthorityIx: Instruction = {
        accounts: [
            { address: subscriber.address, role: AccountRole.WRITABLE_SIGNER },
            {
                address: await deriveSubscriptionAuthorityPda({
                    mint: address(MINT),
                    programId: address(SUBSCRIPTIONS_PROGRAM),
                    subscriber: initAuthorityOwner,
                }),
                role: AccountRole.WRITABLE,
            },
            { address: address(MINT), role: AccountRole.READONLY },
            { address: subscriberAta, role: AccountRole.WRITABLE },
            { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
            { address: address(TOKEN_PROGRAM), role: AccountRole.READONLY },
        ],
        data: new Uint8Array([SUBSCRIPTIONS_INIT_AUTHORITY_DISCRIMINATOR]),
        programAddress: address(SUBSCRIPTIONS_PROGRAM),
    };
    const ataOwner = options.ataOwner === 'recipient' ? address(RECIPIENT) : subscriber.address;
    const [createdAta] = await findAssociatedTokenPda({
        mint: address(MINT),
        owner: ataOwner,
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const idempotentAtaIx = getCreateAssociatedTokenIdempotentInstruction({
        ata: createdAta,
        mint: address(MINT),
        owner: ataOwner,
        payer: subscriber,
        tokenProgram: address(TOKEN_PROGRAM),
    });
    const ataIx: Instruction = { ...idempotentAtaIx, data: options.ataData ?? idempotentAtaIx.data };
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
    if (options.authorityInit !== undefined) instructions.unshift(initAuthorityIx);
    if (options.ataOwner !== undefined) instructions.unshift(ataIx);

    const txMessage = pipe(
        createTransactionMessage({ version: options.version ?? 0 }),
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
            planAddress: PLAN_ID,
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

    test('accepts a legacy (unversioned) activation transaction under the version-0 rules', async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({ version: 'legacy' });
        expect(__testing.extractSubscriberFromTransaction(transaction, challenge)).toBe(subscriberAddress);
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).resolves.toBeUndefined();
    });

    test("accepts an idempotent creation of the subscriber's own ATA", async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({ ataOwner: 'subscriber' });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).resolves.toBeUndefined();
    });

    // draft-solana-subscription-00: the activation contains "no instructions
    // other than those above plus optional compute-budget and memo
    // instructions"; the recipient's ATA is not the server's to create.
    test("rejects creation of the recipient's ATA", async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({ ataOwner: 'recipient' });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/ATA creation owner does not match the activation subscriber/);
    });

    // §Authorization Scope Verification: "uses methodDetails.planAddress as the Plan account".
    test('rejects a subscribe instruction naming another Plan account', async () => {
        const other = await generateKeyPairSigner();
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            subscribePlan: other.address,
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/subscribe accounts do not match the challenged activation/);
    });

    test("accepts initialize_subscription_authority for the subscriber's (subscriber, mint) authority", async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            authorityInit: 'subscriber',
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).resolves.toBeUndefined();
    });

    test('rejects initialize_subscription_authority for an unrelated authority', async () => {
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            authorityInit: 'unrelated',
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/initialize_subscription_authority is not allowed/);
    });

    test('rejects an ATA instruction with empty data instead of crashing', async () => {
        // Empty data is the non-idempotent CreateAssociatedTokenAccount; the
        // kit decoder omits `data` for it.
        const { subscriberAddress, transaction } = await buildActivationTransactionBase64({
            ataData: new Uint8Array(),
            ataOwner: 'subscriber',
        });
        await expect(
            __testing.validateActivationInstructions(transaction, challenge, subscriberAddress),
        ).rejects.toThrow(/Only idempotent ATA creation is allowed/);
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

describe('subscription().verify()', () => {
    test('rejects activation when first-period charge did not execute', async () => {
        const { subscriber, transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const issued = issueChallenge({
            intent: 'subscription',
            method: 'solana',
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
        });
        const authentication = await buildAuthentication(issued.id, subscriber);
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
                    challenge: issued,
                    payload: { authentication, transaction, type: 'transaction' },
                } as never,
                request: ROUTE_REQUEST as never,
            }),
        ).rejects.toThrow(/first-period charge/);
    });

    test('rejects type="signature" with feePayer=true as push mode', async () => {
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
                    challenge: issueChallenge({
                        intent: 'subscription',
                        method: 'solana',
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                feePayer: true,
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
                    }),
                    payload: { signature: 'abc', type: 'signature' },
                } as never,
                request: ROUTE_REQUEST as never,
            }),
        ).rejects.toThrow(/Push-mode/);
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
                    challenge: issueChallenge({
                        intent: 'subscription',
                        method: 'solana',
                        request: ROUTE_CHALLENGE_REQUEST,
                    }),
                    payload: { type: 'mystery' },
                } as never,
                request: ROUTE_REQUEST as never,
            }),
        ).rejects.toThrow(/payload type/);
    });

    test('rotates a stale bearer binding after a confirmed re-subscription', async () => {
        const { subscriber, transaction, subscriberAddress } = await buildActivationTransactionBase64({
            memo: 'order-99',
        });
        const activationExpires = new Date(Date.now() + 60_000).toISOString();
        const issued = issueChallenge({
            expires: activationExpires,
            intent: 'subscription',
            method: 'solana',
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
        });
        const authentication = await buildAuthentication(issued.id, subscriber);
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
            challenge: issued,
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
            request: ROUTE_REQUEST as never,
        });
        expect((receipt as { status: string }).status).toBe('success');
        expect(await store.get(bindingKey)).toMatchObject({
            authentication,
            challengeId: issued.id,
        });

        const recovered = await method.verify!({ credential: credential as never, request: ROUTE_REQUEST as never });
        expect((recovered as { reference: string }).reference).toBe((receipt as { reference: string }).reference);
        expect(rpcMethods.filter(method => method === 'simulateTransaction')).toHaveLength(1);
        expect(rpcMethods.filter(method => method === 'sendTransaction')).toHaveLength(1);

        const accessCredential = {
            challenge: credential.challenge,
            payload: {
                authentication,
                subscriptionDelegation: subscriptionDelegation.toString(),
                type: 'proof',
            },
        } as never;
        // Once activation has bound the proof, the opening challenge expiry
        // no longer invalidates that bearer proof.
        vi.useFakeTimers({ now: Date.parse(activationExpires) + 60_000, toFake: ['Date'] });
        const firstAccess = await method.verify!({ credential: accessCredential, request: ROUTE_REQUEST as never });
        const repeatedAccess = await method.verify!({ credential: accessCredential, request: ROUTE_REQUEST as never });
        vi.useRealTimers();
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
                    challenge: issueChallenge({
                        intent: 'subscription',
                        method: 'solana',
                        expires: '2000-01-01T00:00:00Z',
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                network: 'devnet',
                                planAddress: PLAN_ID,
                                puller: PULLER,
                                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                                tokenProgram: TOKEN_PROGRAM,
                            },
                            periodCount: '30',
                            periodUnit: 'day',
                            recipient: RECIPIENT,
                        },
                    }),
                    payload: { transaction: 'not-a-transaction', type: 'transaction' },
                } as never,
                request: ROUTE_REQUEST as never,
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
                    challenge: issueChallenge({
                        intent: 'subscription',
                        method: 'solana',
                        request: {
                            amount: '10000000',
                            currency: MINT,
                            methodDetails: {
                                decimals: 6,
                                mint: MINT,
                                network: 'devnet',
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
                    }),
                    payload: { transaction: 'not-a-transaction', type: 'transaction' },
                } as never,
                request: ROUTE_REQUEST as never,
            }),
        ).rejects.toThrow(/subscription expired/);
    });

    test('rejects when on-chain delegation references a different plan', async () => {
        const { subscriber, transaction, subscriberAddress } = await buildActivationTransactionBase64();
        const issued = issueChallenge({
            intent: 'subscription',
            method: 'solana',
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
        });
        const authentication = await buildAuthentication(issued.id, subscriber);
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
                    challenge: issued,
                    payload: { authentication, transaction, type: 'transaction' },
                } as never,
                request: ROUTE_REQUEST as never,
            }),
        ).rejects.toThrow(/plan mismatch/);
    });

    test('rejects when SubscriptionDelegation account is absent after activation', async () => {
        const { subscriber, transaction } = await buildActivationTransactionBase64();
        const issued = issueChallenge({
            intent: 'subscription',
            method: 'solana',
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
        });
        const authentication = await buildAuthentication(issued.id, subscriber);
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
                    challenge: issued,
                    payload: { authentication, transaction, type: 'transaction' },
                } as never,
                request: ROUTE_REQUEST as never,
            }),
        ).rejects.toThrow(/SubscriptionDelegation account not found/);
    });

    test('rejects on simulation failure', async () => {
        const { subscriber, transaction } = await buildActivationTransactionBase64();
        const issued = issueChallenge({
            intent: 'subscription',
            method: 'solana',
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
        });
        const authentication = await buildAuthentication(issued.id, subscriber);
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
                        challenge: issued,
                        payload: { authentication, transaction, type: 'transaction' },
                    } as never,
                    request: ROUTE_REQUEST as never,
                }),
            ).rejects.toThrow(/simulation failed/);
        } finally {
            errorSpy.restore();
        }
    });

    test('rejects on broadcast RPC error', async () => {
        const { subscriber, transaction } = await buildActivationTransactionBase64();
        const issued = issueChallenge({
            intent: 'subscription',
            method: 'solana',
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
        });
        const authentication = await buildAuthentication(issued.id, subscriber);
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
                    challenge: issued,
                    payload: { authentication, transaction, type: 'transaction' },
                } as never,
                request: ROUTE_REQUEST as never,
            }),
        ).rejects.toThrow(/RPC error/);
    });

    // draft-solana-subscription-00 §Payload: "Solana subscription activation
    // uses type=\"transaction\"". A client-broadcast signature is refused as an
    // invalid payload before the server reads anything from the RPC.
    test('rejects a push-mode (type="signature") activation without touching the RPC', async () => {
        const { subscriber } = await buildActivationTransactionBase64();
        const issued = issueChallenge({
            intent: 'subscription',
            method: 'solana',
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
        });
        const authentication = await buildAuthentication(issued.id, subscriber);
        let rpcCalls = 0;
        globalThis.fetch = async () => {
            rpcCalls += 1;
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
                    challenge: issued,
                    payload: { authentication, signature: 'activation-signature', type: 'signature' },
                } as never,
                request: ROUTE_REQUEST as never,
            }),
        ).rejects.toThrow(/Push-mode \(type="signature"\) subscription activation is not supported/);
        expect(rpcCalls).toBe(0);
    });

    function writeU64Le(buf: Uint8Array, offset: number, value: bigint) {
        for (let i = 0; i < 8; i += 1) {
            buf[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
        }
    }
});

// draft-solana-subscription-00 §Source Verification: "If source is present,
// servers MUST verify that it uses the did:pkh:solana: method and that its
// address matches the subscriber signer extracted from the activation
// transaction."
describe('subscription().verify() credential source', () => {
    async function verifyWithSource(source: (subscriber: string) => string | undefined) {
        const { subscriber, subscriberAddress, transaction } = await buildActivationTransactionBase64();
        const issued = issueChallenge({
            intent: 'subscription',
            method: 'solana',
            request: {
                amount: '10000000',
                currency: MINT,
                methodDetails: {
                    decimals: 6,
                    mint: MINT,
                    network: 'devnet',
                    planAddress: PLAN_ID,
                    puller: PULLER,
                    subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                    tokenProgram: TOKEN_PROGRAM,
                },
                periodCount: '30',
                periodUnit: 'day',
                recipient: RECIPIENT,
            },
        });
        const authentication = await buildAuthentication(issued.id, subscriber);
        globalThis.fetch = () => Promise.reject(new Error('RPC reached'));
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
        const value = source(subscriberAddress);
        return method.verify!({
            credential: {
                challenge: issued,
                payload: { authentication, transaction, type: 'transaction' },
                ...(value === undefined ? {} : { source: value }),
            } as never,
            request: ROUTE_REQUEST as never,
        });
    }

    test('rejects a source naming another address', async () => {
        const other = (await generateKeyPairSigner()).address;
        await expect(verifyWithSource(() => `did:pkh:solana:devnet:${other}`)).rejects.toThrow(
            /Credential source does not match the activation subscriber/,
        );
    });

    test('rejects a source using another DID method', async () => {
        await expect(verifyWithSource(subscriber => `did:pkh:eip155:1:${subscriber}`)).rejects.toThrow(
            /Credential source must be a did:pkh:solana DID/,
        );
        await expect(verifyWithSource(subscriber => `did:pkh:solana:${subscriber}`)).rejects.toThrow(
            /Credential source must be a did:pkh:solana DID/,
        );
    });

    test('accepts a source matching the subscriber and an absent source', async () => {
        await expect(verifyWithSource(subscriber => `did:pkh:solana:devnet:${subscriber}`)).rejects.toThrow(
            /RPC reached/,
        );
        await expect(verifyWithSource(() => undefined)).rejects.toThrow(/RPC reached/);
    });
});
