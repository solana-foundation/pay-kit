/**
 * Tests for the Solana subscription intent: schema, period mapping, PDA
 * derivation, and the structural shape of activation transactions built by
 * the client. On-chain verification is exercised by the integration suite
 * once available; this suite covers the parts that don't need a live RPC.
 */
import { describe, expect, test } from 'vitest';
import { address, generateKeyPairSigner } from '@solana/kit';

import {
    SUBSCRIPTIONS_PROGRAM,
    SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
    SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
    TOKEN_PROGRAM,
} from '../constants.js';
import { subscription as subscriptionMethod } from '../Methods.js';
import {
    assertPeriodHoursInRange,
    deriveSubscriptionAuthorityPda,
    deriveSubscriptionPda,
    mapSubscriptionPeriodToHours,
} from '../shared/subscription.js';

const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const PLAN_ID = '8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT';
const PULLER = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';

describe('Methods.subscription', () => {
    test('accepts a minimal day-periodic request', () => {
        const parsed = subscriptionMethod.schema.request.safeParse({
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
        });
        expect(parsed.success).toBe(true);
    });

    test('accepts week period with subscriptionExpires', () => {
        const parsed = subscriptionMethod.schema.request.safeParse({
            amount: '5000000',
            currency: MINT,
            methodDetails: {
                decimals: 6,
                mint: MINT,
                planId: PLAN_ID,
                puller: PULLER,
                tokenProgram: TOKEN_PROGRAM,
            },
            periodCount: '2',
            periodUnit: 'week',
            recipient: RECIPIENT,
            subscriptionExpires: '2026-07-14T12:00:00Z',
        });
        expect(parsed.success).toBe(true);
    });

    test('rejects periodUnit="month" (Solana profile does not support calendar months)', () => {
        const parsed = subscriptionMethod.schema.request.safeParse({
            amount: '10000000',
            currency: MINT,
            methodDetails: {
                decimals: 6,
                mint: MINT,
                planId: PLAN_ID,
                puller: PULLER,
                tokenProgram: TOKEN_PROGRAM,
            },
            periodCount: '1',
            periodUnit: 'month',
            recipient: RECIPIENT,
        });
        expect(parsed.success).toBe(false);
    });

    test('rejects missing required methodDetails fields', () => {
        const parsed = subscriptionMethod.schema.request.safeParse({
            amount: '10000000',
            currency: MINT,
            methodDetails: {
                decimals: 6,
            },
            periodCount: '30',
            periodUnit: 'day',
            recipient: RECIPIENT,
        });
        expect(parsed.success).toBe(false);
    });

    test('accepts both pull and push credential payloads', () => {
        expect(
            subscriptionMethod.schema.credential.payload.safeParse({
                transaction: 'AQAAAA...base64...',
                type: 'transaction',
            }).success,
        ).toBe(true);
        expect(
            subscriptionMethod.schema.credential.payload.safeParse({
                signature: '5J8Kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk',
                type: 'signature',
            }).success,
        ).toBe(true);
    });
});

describe('mapSubscriptionPeriodToHours', () => {
    test('day maps to count * 24 hours', () => {
        expect(mapSubscriptionPeriodToHours('day', 1)).toBe(24);
        expect(mapSubscriptionPeriodToHours('day', 30)).toBe(720);
        expect(mapSubscriptionPeriodToHours('day', 365)).toBe(8760);
    });

    test('week maps to count * 168 hours', () => {
        expect(mapSubscriptionPeriodToHours('week', 1)).toBe(168);
        expect(mapSubscriptionPeriodToHours('week', 2)).toBe(336);
        expect(mapSubscriptionPeriodToHours('week', 52)).toBe(8736);
    });

    test('rejects out-of-range counts', () => {
        expect(() => mapSubscriptionPeriodToHours('day', 366)).toThrow(/exceeds 365/);
        expect(() => mapSubscriptionPeriodToHours('week', 53)).toThrow(/exceeds 52/);
        expect(() => mapSubscriptionPeriodToHours('day', 0)).toThrow(/positive integer/);
        expect(() => mapSubscriptionPeriodToHours('day', -1)).toThrow(/positive integer/);
        expect(() => mapSubscriptionPeriodToHours('day', 1.5)).toThrow(/positive integer/);
    });

    test('rejects month explicitly', () => {
        expect(() => mapSubscriptionPeriodToHours('month' as unknown as 'day', 1)).toThrow(
            /Solana subscription profile rejects/,
        );
    });
});

describe('assertPeriodHoursInRange', () => {
    test('accepts valid bounds', () => {
        expect(() => assertPeriodHoursInRange(1)).not.toThrow();
        expect(() => assertPeriodHoursInRange(8760)).not.toThrow();
    });
    test('rejects out-of-range values', () => {
        expect(() => assertPeriodHoursInRange(0)).toThrow();
        expect(() => assertPeriodHoursInRange(8761)).toThrow();
        expect(() => assertPeriodHoursInRange(-1)).toThrow();
    });
});

describe('PDA derivation', () => {
    test('derives a deterministic SubscriptionAuthority PDA', async () => {
        const subscriber = await generateKeyPairSigner();
        const pda1 = await deriveSubscriptionAuthorityPda({
            mint: address(MINT),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: subscriber.address,
        });
        const pda2 = await deriveSubscriptionAuthorityPda({
            mint: address(MINT),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: subscriber.address,
        });
        expect(pda1.toString()).toBe(pda2.toString());
    });

    test('derives a deterministic SubscriptionDelegation PDA', async () => {
        const subscriber = await generateKeyPairSigner();
        const pda1 = await deriveSubscriptionPda({
            planPda: address(PLAN_ID),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: subscriber.address,
        });
        const pda2 = await deriveSubscriptionPda({
            planPda: address(PLAN_ID),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: subscriber.address,
        });
        expect(pda1.toString()).toBe(pda2.toString());
    });

    test('different subscribers produce different PDAs', async () => {
        const a = await generateKeyPairSigner();
        const b = await generateKeyPairSigner();
        const pdaA = await deriveSubscriptionPda({
            planPda: address(PLAN_ID),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: a.address,
        });
        const pdaB = await deriveSubscriptionPda({
            planPda: address(PLAN_ID),
            programId: address(SUBSCRIPTIONS_PROGRAM),
            subscriber: b.address,
        });
        expect(pdaA.toString()).not.toBe(pdaB.toString());
    });
});

describe('Instruction discriminators', () => {
    test('match the subscriptions program (single-byte tags)', () => {
        expect(SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR).toBe(11);
        expect(SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR).toBe(10);
    });
});
