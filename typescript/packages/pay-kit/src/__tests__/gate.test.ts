import { describe, expect, it } from 'vitest';

import { ConfigurationError, MixedCurrenciesError, ProtocolIncompatibleError } from '../errors.js';
import { Gate } from '../gate.js';
import { eur, usd } from '../price.js';

const SELLER = 'SeLLer1111111111111111111111111111111111111';
const PLATFORM = 'PLatform111111111111111111111111111111111111';
const DEFAULTS = { accept: ['mpp'] as const, payTo: SELLER };

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
