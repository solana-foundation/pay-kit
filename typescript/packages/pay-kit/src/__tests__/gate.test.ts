import { describe, expect, it } from 'vitest';

import { ConfigurationError, MixedCurrenciesError, ProtocolIncompatibleError } from '../errors.js';
import { Gate } from '../gate.js';
import { eur, usd } from '../price.js';
import { session, subscription } from '../pricing.js';

const SELLER = 'SeLLer1111111111111111111111111111111111111';
const PLATFORM = 'PLatform111111111111111111111111111111111111';
const PLAN = 'PLan11111111111111111111111111111111111111';
const DEFAULTS = { accept: ['mpp'] as const, payTo: SELLER };
const X402_MPP = { accept: ['x402', 'mpp'] as const, payTo: SELLER };
const SUB = { periodCount: 1, periodUnit: 'day' as const, planId: PLAN, puller: SELLER };

describe('Gate', () => {
    it('inherits payTo and accept from defaults', () => {
        const gate = Gate.create({ amount: usd('0.10'), name: 'report' }, DEFAULTS);
        expect(gate.payTo).toBe(SELLER);
        expect(gate.accept).toEqual(['mpp']);
        expect(gate.accepts('mpp')).toBe(true);
        expect(gate.accepts('x402')).toBe(false);
        expect(gate.hasFees()).toBe(false);
    });

    it('computes total and payout with within fees', () => {
        const gate = Gate.create(
            { amount: usd('10.00'), feeWithin: { [PLATFORM]: usd('0.30') }, name: 'marketplace' },
            DEFAULTS,
        );
        expect(gate.total().amount).toBe('10');
        expect(gate.payout(SELLER)?.amount).toBe('9.7');
        expect(gate.payout(PLATFORM)?.amount).toBe('0.3');
        expect(gate.payout('SomeoneElse')).toBeUndefined();
    });

    it('computes total and payout with on-top fees', () => {
        const gate = Gate.create(
            { amount: usd('10.00'), feeOnTop: { [PLATFORM]: usd('0.50') }, name: 'ticket' },
            DEFAULTS,
        );
        expect(gate.total().amount).toBe('10.5');
        expect(gate.payout(SELLER)?.amount).toBe('10');
        expect(gate.payout(PLATFORM)?.amount).toBe('0.5');
    });

    it('splits fees by kind', () => {
        const gate = Gate.create(
            {
                amount: usd('10.00'),
                feeOnTop: { [PLATFORM]: usd('0.50') },
                feeWithin: { [PLATFORM]: usd('0.30') },
                name: 'both',
            },
            DEFAULTS,
        );
        expect(gate.feeWithin().map(fee => fee.price.amount)).toEqual(['0.3']);
        expect(gate.feeOnTop().map(fee => fee.price.amount)).toEqual(['0.5']);
        expect(gate.payout(PLATFORM)?.amount).toBe('0.8');
    });

    it('rejects within fees that consume the whole amount', () => {
        expect(() =>
            Gate.create({ amount: usd('1.00'), feeWithin: { [PLATFORM]: usd('1.00') }, name: 'bad' }, DEFAULTS),
        ).toThrow(ConfigurationError);
    });

    it('rejects fees routed to payTo itself', () => {
        expect(() =>
            Gate.create({ amount: usd('1.00'), feeWithin: { [SELLER]: usd('0.10') }, name: 'bad' }, DEFAULTS),
        ).toThrow(ConfigurationError);
    });

    it('rejects fee currencies that differ from the amount', () => {
        expect(() =>
            Gate.create({ amount: usd('1.00'), feeWithin: { [PLATFORM]: eur('0.10') }, name: 'bad' }, DEFAULTS),
        ).toThrow(MixedCurrenciesError);
    });

    it('narrows inherited accept to mpp when fees are present', () => {
        const gate = Gate.create(
            { amount: usd('1.00'), feeWithin: { [PLATFORM]: usd('0.10') }, name: 'fees' },
            { accept: ['x402', 'mpp'], payTo: SELLER },
        );
        expect(gate.accept).toEqual(['mpp']);
    });

    it('rejects fees with an explicit x402 accept', () => {
        expect(() =>
            Gate.create(
                {
                    accept: ['x402'],
                    amount: usd('1.00'),
                    feeWithin: { [PLATFORM]: usd('0.10') },
                    name: 'bad',
                },
                DEFAULTS,
            ),
        ).toThrow(ProtocolIncompatibleError);
    });
});

describe('Gate — subscription kind', () => {
    it('builds an MPP-only subscription gate from the helper', () => {
        const gate = Gate.create({ ...subscription(usd('0.10'), { ...SUB }), name: 'feed' }, X402_MPP);
        expect(gate.kind).toBe('subscription');
        expect(gate.accept).toEqual(['mpp']); // narrowed off x402 even when defaults allow it
        expect(gate.subscription).toEqual(SUB);
    });

    it('requires a subscription plan binding', () => {
        expect(() => Gate.create({ amount: usd('0.10'), kind: 'subscription', name: 'feed' }, DEFAULTS)).toThrow(
            ConfigurationError,
        );
    });

    it('rejects fees on a subscription gate', () => {
        expect(() =>
            Gate.create(
                {
                    amount: usd('0.10'),
                    feeOnTop: { [PLATFORM]: usd('0.01') },
                    kind: 'subscription',
                    name: 'feed',
                    subscription: SUB,
                },
                DEFAULTS,
            ),
        ).toThrow(ProtocolIncompatibleError);
    });

    it('rejects an explicit x402 accept on a subscription gate', () => {
        expect(() =>
            Gate.create(
                { accept: ['x402'], amount: usd('0.10'), kind: 'subscription', name: 'feed', subscription: SUB },
                DEFAULTS,
            ),
        ).toThrow(ProtocolIncompatibleError);
    });
});

describe('Gate — session kind', () => {
    it('builds an MPP-only session gate from the helper', () => {
        const gate = Gate.create(
            { ...session(usd('1.00'), { closeDelayMs: 2000, unitPrice: usd('0.0001') }), name: 'stream' },
            X402_MPP,
        );
        expect(gate.kind).toBe('session');
        expect(gate.accept).toEqual(['mpp']);
        expect(gate.amount.baseUnits()).toBe(1_000_000n); // cap, 1.00 USDC
        expect(gate.session).toEqual({ closeDelayMs: 2000, unitPrice: 100n }); // 0.0001 USDC
    });

    it('requires a session config', () => {
        expect(() => Gate.create({ amount: usd('1.00'), kind: 'session', name: 'stream' }, DEFAULTS)).toThrow(
            ConfigurationError,
        );
    });

    it('rejects fees on a session gate', () => {
        expect(() =>
            Gate.create(
                {
                    amount: usd('1.00'),
                    feeOnTop: { [PLATFORM]: usd('0.01') },
                    kind: 'session',
                    name: 'stream',
                    session: { unitPrice: 100n },
                },
                DEFAULTS,
            ),
        ).toThrow(ProtocolIncompatibleError);
    });
});
