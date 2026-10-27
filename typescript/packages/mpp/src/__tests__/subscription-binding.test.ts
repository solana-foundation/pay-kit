/**
 * Route binding inside `subscription().verify`, the stateless
 * `verifyActiveSubscription` check, and the subscriptions instruction-data
 * encoders.
 */
import { address } from '@solana/kit';
import { Challenge } from 'mppx';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import { SUBSCRIPTIONS_PROGRAM, TOKEN_PROGRAM } from '../constants.js';
import { __testing, subscription, verifyActiveSubscription } from '../server/Subscription.js';
import {
    deriveSubscriptionAuthorityPda,
    deriveSubscriptionPda,
    encodeSubscribeInstructionData,
    encodeTransferSubscriptionInstructionData,
} from '../shared/subscription.js';

const PLAN_ID = '8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT';
const OTHER_PLAN = 'AwCtiXLhCLxYytJ9Gz5qQBd8GxY6GrwfRdeevPysEgJy';
const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const PULLER = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const SUBSCRIBER = 'GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB';
const SECRET = 'subscription-binding-test-secret-of-32-bytes';
const REALM = 'api.example.com';
const NOW = 1_900_000_000;

function routeRequest(overrides: Record<string, unknown> = {}, details: Record<string, unknown> = {}) {
    return {
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
            ...details,
        },
        periodCount: '30',
        periodUnit: 'day',
        recipient: RECIPIENT,
        ...overrides,
    };
}

function issue(
    request: Record<string, unknown>,
    options: { intent?: string; method?: string; realm?: string; secretKey?: string } = {},
) {
    return Challenge.from({
        intent: options.intent ?? 'subscription',
        method: options.method ?? 'solana',
        realm: options.realm ?? REALM,
        request,
        secretKey: options.secretKey ?? SECRET,
    });
}

function server(overrides: Partial<Parameters<typeof subscription>[0]> = {}) {
    return subscription({
        decimals: 6,
        mint: MINT,
        network: 'devnet',
        periodCount: 30,
        periodUnit: 'day',
        planId: PLAN_ID,
        puller: PULLER,
        realm: REALM,
        recipient: RECIPIENT,
        rpcUrl: 'https://mock-rpc',
        secretKey: SECRET,
        tokenProgram: TOKEN_PROGRAM,
        ...overrides,
    });
}

/**
 * Verify `challenge` against `method`. A credential that passes binding
 * reaches the payload checks, whose "Missing transaction" refusal marks it.
 */
function verify(method: ReturnType<typeof subscription>, challenge: unknown, route: unknown = { amount: '10000000' }) {
    return method.verify!({
        credential: { challenge, payload: { type: 'transaction' } } as never,
        request: route as never,
    });
}

const BOUND = /Missing transaction data/;

describe('subscription().verify() route binding', () => {
    test('a challenge this route issued passes binding', async () => {
        await expect(verify(server(), issue(routeRequest()))).rejects.toThrow(BOUND);
    });

    test('refuses a challenge id that is not this server HMAC', async () => {
        const forged = { ...issue(routeRequest()), id: 'qT8wErYuI3oPlKjH6gFdSa' };
        await expect(verify(server(), forged)).rejects.toThrow(/HMAC mismatch/);
    });

    test('refuses a challenge issued under another secret', async () => {
        const other = issue(routeRequest(), { secretKey: 'another-secret-entirely-of-32-bytes!' });
        await expect(verify(server(), other)).rejects.toThrow(/did not issue/);
    });

    test('skips the HMAC check when no secretKey is configured', async () => {
        const forged = { ...issue(routeRequest()), id: 'forged' };
        await expect(verify(server({ secretKey: undefined }), forged)).rejects.toThrow(BOUND);
    });

    test('refuses another method, intent or realm', async () => {
        await expect(verify(server(), issue(routeRequest(), { method: 'other' }))).rejects.toThrow(
            /method `other` does not match this server/,
        );
        await expect(verify(server(), issue(routeRequest(), { intent: 'charge' }))).rejects.toThrow(
            /intent `charge` is not a subscription/,
        );
        await expect(verify(server(), issue(routeRequest(), { realm: 'other.example.com' }))).rejects.toThrow(
            /realm `other.example.com` does not match this server/,
        );
    });

    test('accepts any realm when none is configured', async () => {
        const challenge = issue(routeRequest(), { realm: 'other.example.com' });
        await expect(verify(server({ realm: undefined }), challenge)).rejects.toThrow(BOUND);
    });

    test('refuses another mint, recipient, program or plan', async () => {
        await expect(verify(server(), issue(routeRequest({ currency: PULLER })))).rejects.toThrow(
            /mint does not match this server/,
        );
        await expect(verify(server(), issue(routeRequest({ recipient: PULLER })))).rejects.toThrow(
            /recipient does not match this server/,
        );
        await expect(verify(server(), issue(routeRequest({}, { subscriptionProgram: TOKEN_PROGRAM })))).rejects.toThrow(
            /subscriptionProgram does not match this server/,
        );
        await expect(verify(server(), issue(routeRequest({}, { planAddress: OTHER_PLAN })))).rejects.toThrow(
            /planAddress does not match this server/,
        );
    });

    test('refuses another network, and an omitted network off mainnet', async () => {
        await expect(verify(server(), issue(routeRequest({}, { network: 'mainnet' })))).rejects.toThrow(
            /network does not match this server/,
        );
        await expect(verify(server(), issue(routeRequest({}, { network: undefined })))).rejects.toThrow(
            /network does not match this server/,
        );
    });

    test('treats an omitted network, mainnet and mainnet-beta as one cluster', async () => {
        const mainnet = server({ network: 'mainnet-beta' });
        await expect(verify(mainnet, issue(routeRequest({}, { network: undefined })))).rejects.toThrow(BOUND);
        await expect(verify(mainnet, issue(routeRequest({}, { network: 'mainnet' })))).rejects.toThrow(BOUND);
    });

    test('refuses a challenge for another route amount or period', async () => {
        await expect(verify(server(), issue(routeRequest()), { amount: '100000000' })).rejects.toThrow(
            /terms do not match this server/,
        );
        await expect(verify(server({ periodCount: 7 }), issue(routeRequest()))).rejects.toThrow(
            /terms do not match this server/,
        );
        await expect(verify(server(), issue(routeRequest({ periodCount: '030' })))).rejects.toThrow(
            /terms do not match this server/,
        );
    });

    test('requires the route request amount', async () => {
        await expect(verify(server(), issue(routeRequest()), {})).rejects.toThrow(/route request with its amount/);
    });

    test('refuses an empty secretKey or realm at configuration', () => {
        expect(() => server({ secretKey: '' })).toThrow(/secretKey must be a non-empty string/);
        expect(() => server({ realm: '' })).toThrow(/realm must be a non-empty string/);
    });
});

// ── verifyActiveSubscription ──

function writeU64Le(buf: Uint8Array, offset: number, value: bigint) {
    for (let i = 0; i < 8; i += 1) buf[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
}

function delegationData(
    options: {
        amountPulled?: bigint;
        expiresAt?: bigint;
        initId?: bigint;
        periodStart?: bigint;
        plan?: string;
        version?: number;
    } = {},
): Uint8Array {
    const data = new Uint8Array(155);
    data[0] = 4;
    data[1] = options.version ?? 1;
    data[2] = 255;
    data.set(__testing.decodeBase58(SUBSCRIBER), 3);
    data.set(__testing.decodeBase58(options.plan ?? PLAN_ID), 35);
    writeU64Le(data, 99, options.initId ?? 0n);
    writeU64Le(data, 107, 10_000_000n);
    writeU64Le(data, 115, 720n);
    writeU64Le(data, 131, options.amountPulled ?? 10_000_000n);
    writeU64Le(data, 139, options.periodStart ?? BigInt(NOW - 3600));
    writeU64Le(data, 147, options.expiresAt ?? 0n);
    return data;
}

function authorityData(initId = 0n, length = 106, discriminator = 0): Uint8Array {
    const data = new Uint8Array(length);
    data[0] = discriminator;
    if (length >= 106) writeU64Le(data, 98, initId);
    return data;
}

type Account = { data: Uint8Array; owner?: string } | null;

describe('verifyActiveSubscription', () => {
    let originalFetch: typeof globalThis.fetch;
    let originalNow: typeof Date.now;
    let delegationPda: string;
    let authorityPda: string;

    beforeEach(async () => {
        originalFetch = globalThis.fetch;
        originalNow = Date.now;
        Date.now = () => NOW * 1000;
        delegationPda = (
            await deriveSubscriptionPda({
                planPda: address(PLAN_ID),
                programId: address(SUBSCRIPTIONS_PROGRAM),
                subscriber: address(SUBSCRIBER),
            })
        ).toString();
        authorityPda = (
            await deriveSubscriptionAuthorityPda({
                mint: address(MINT),
                programId: address(SUBSCRIPTIONS_PROGRAM),
                subscriber: address(SUBSCRIBER),
            })
        ).toString();
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
        Date.now = originalNow;
    });

    function chain(delegation: Account, authority: Account) {
        globalThis.fetch = async (_input: RequestInfo | URL, init?: RequestInit) => {
            const body = JSON.parse(init?.body as string) as { id?: number; params?: [string] };
            const account =
                body.params?.[0] === authorityPda ? authority : body.params?.[0] === delegationPda ? delegation : null;
            const value = account
                ? {
                      data: [Buffer.from(account.data).toString('base64'), 'base64'],
                      executable: false,
                      lamports: 1,
                      owner: account.owner ?? SUBSCRIPTIONS_PROGRAM,
                      rentEpoch: 0,
                      space: account.data.length,
                  }
                : null;
            return new Response(
                JSON.stringify({ id: body.id ?? 1, jsonrpc: '2.0', result: { context: { slot: 1 }, value } }),
                {
                    headers: { 'Content-Type': 'application/json' },
                },
            );
        };
    }

    function check(overrides: Partial<Parameters<typeof verifyActiveSubscription>[0]> = {}) {
        return verifyActiveSubscription({
            amount: '10000000',
            mint: MINT,
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            rpcUrl: 'https://mock-rpc',
            subscriber: SUBSCRIBER,
            ...overrides,
        });
    }

    test('accepts a live, paid subscription and returns its period', async () => {
        chain({ data: delegationData() }, { data: authorityData() });
        const active = await check();
        expect(active.subscriptionDelegation).toBe(delegationPda);
        expect(active.periodStartTs).toBe(NOW - 3600);
        expect(active.periodEndTs).toBe(NOW - 3600 + 720 * 3600);
        expect(active.subscriber).toBe(SUBSCRIBER);
    });

    test('accepts the last second of the period and a cancellation still ahead', async () => {
        chain({ data: delegationData({ periodStart: BigInt(NOW - 720 * 3600 + 1) }) }, { data: authorityData() });
        await expect(check()).resolves.toBeDefined();
        chain({ data: delegationData({ expiresAt: BigInt(NOW + 60) }) }, { data: authorityData() });
        await expect(check()).resolves.toBeDefined();
    });

    test('refuses an ended, unpaid or not-yet-started period', async () => {
        chain({ data: delegationData({ periodStart: BigInt(NOW - 720 * 3600) }) }, { data: authorityData() });
        await expect(check()).rejects.toThrow(/not paid for the current billing period/);
        chain({ data: delegationData({ amountPulled: 0n }) }, { data: authorityData() });
        await expect(check()).rejects.toThrow(/not paid for the current billing period/);
        chain({ data: delegationData({ periodStart: BigInt(NOW + 1) }) }, { data: authorityData() });
        await expect(check()).rejects.toThrow(/not paid for the current billing period/);
        chain({ data: delegationData() }, { data: authorityData() });
        await expect(check({ amount: '20000000' })).rejects.toThrow(/not paid for the current billing period/);
    });

    test('refuses a cancellation that has taken effect', async () => {
        chain({ data: delegationData({ expiresAt: BigInt(NOW) }) }, { data: authorityData() });
        await expect(check()).rejects.toThrow(/cancellation has taken effect/);
    });

    test('refuses after the configured subscriptionExpires', async () => {
        chain({ data: delegationData() }, { data: authorityData() });
        await expect(check({ subscriptionExpires: new Date(NOW * 1000).toISOString() })).rejects.toThrow(
            /Subscription has expired/,
        );
        await expect(check({ subscriptionExpires: 'not-a-date' })).rejects.toThrow(/Invalid subscriptionExpires/);
    });

    test('refuses a missing, foreign-owned, mis-versioned or other-plan delegation', async () => {
        chain(null, { data: authorityData() });
        await expect(check()).rejects.toThrow(/SubscriptionDelegation account .* not found/);
        chain({ data: delegationData(), owner: TOKEN_PROGRAM }, { data: authorityData() });
        await expect(check()).rejects.toThrow(/SubscriptionDelegation owner mismatch/);
        chain({ data: delegationData({ version: 2 }) }, { data: authorityData() });
        await expect(check()).rejects.toThrow(/SubscriptionDelegation discriminator\/version/);
        chain({ data: delegationData({ plan: OTHER_PLAN }) }, { data: authorityData() });
        await expect(check()).rejects.toThrow(/does not match the bound plan and payer/);
    });

    test('refuses a missing, foreign-owned, malformed or reinitialized authority', async () => {
        chain({ data: delegationData() }, null);
        await expect(check()).rejects.toThrow(/SubscriptionAuthority account not found/);
        chain({ data: delegationData() }, { data: authorityData(), owner: TOKEN_PROGRAM });
        await expect(check()).rejects.toThrow(/SubscriptionAuthority owner mismatch/);
        chain({ data: delegationData() }, { data: authorityData(0n, 105) });
        await expect(check()).rejects.toThrow(/SubscriptionAuthority account length/);
        chain({ data: delegationData() }, { data: authorityData(0n, 106, 1) });
        await expect(check()).rejects.toThrow(/SubscriptionAuthority account discriminator/);
        chain({ data: delegationData() }, { data: authorityData(1n) });
        await expect(check()).rejects.toThrow(/authority has been invalidated/);
    });

    test('refuses an amount that is not an unsigned integer', async () => {
        await expect(check({ amount: '-1' })).rejects.toThrow(/unsigned integer/);
        await expect(check({ amount: '18446744073709551616' })).rejects.toThrow(/unsigned integer/);
    });
});

// ── Instruction-data encoders ──

describe('subscriptions instruction-data encoders', () => {
    test('encodes subscribe data (discriminator 11, 74 bytes)', () => {
        const bytes = encodeSubscribeInstructionData({
            amount: '10000000',
            authorityInitId: 77,
            createdAt: 1_700_000_000,
            mint: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
            periodHours: 720,
            planBump: 253,
            planId: 7,
        });
        expect(Buffer.from(bytes).toString('base64url')).toBe(
            'CwcAAAAAAAAA_TtELLORIVfxOpM9ATQoLQMrX_7NAaLb8bd5BgjfAC6ngJaYAAAAAADQAgAAAAAAAADxU2UAAAAATQAAAAAAAAA',
        );
    });

    test('encodes transfer_subscription data (discriminator 10, 73 bytes)', () => {
        const bytes = encodeTransferSubscriptionInstructionData({
            amount: 10_000_000n,
            delegator: SUBSCRIBER,
            mint: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
        });
        expect(Buffer.from(bytes).toString('base64url')).toBe(
            'CoCWmAAAAAAA6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw7RCyzkSFX8TqTPQE0KC0DK1_-zQGi2_G3eQYI3wAupw',
        );
    });

    test('refuses an amount outside the u64 wire format', () => {
        const base = { delegator: SUBSCRIBER, mint: MINT };
        expect(() => encodeTransferSubscriptionInstructionData({ ...base, amount: '010' })).toThrow(/leading zeros/);
        expect(() => encodeTransferSubscriptionInstructionData({ ...base, amount: 1n << 64n })).toThrow(/u64/);
        expect(() => encodeTransferSubscriptionInstructionData({ ...base, amount: -1 })).toThrow(/u64/);
    });
});
