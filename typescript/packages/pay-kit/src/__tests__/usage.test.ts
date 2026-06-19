import { describe, expect, it } from 'vitest';

import { ProtocolIncompatibleError } from '../errors.js';
import { Gate, type GateDefaults } from '../gate.js';
import { createPayKit } from '../paykit.js';
import { usd } from '../price.js';
import { usage } from '../pricing.js';

const DEFAULTS: GateDefaults = { accept: ['x402', 'mpp'], payTo: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY' };
const OTHER = '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin';

describe('usage() gate', () => {
    it('marks the gate kind and narrows to x402', () => {
        const gate = Gate.create({ ...usage(usd('1.00')), name: 'summarize' }, DEFAULTS);
        expect(gate.kind).toBe('usage');
        expect(gate.accept).toEqual(['x402']);
        expect(gate.amount.baseUnits().toString()).toBe('1000000');
    });

    it('rejects fees on a usage gate', () => {
        expect(() =>
            Gate.create(
                { amount: usd('1.00'), feeWithin: { [OTHER]: usd('0.10') }, kind: 'usage', name: 'u' },
                DEFAULTS,
            ),
        ).toThrow(ProtocolIncompatibleError);
    });

    it('rejects an explicit accept that excludes x402', () => {
        expect(() => Gate.create({ accept: ['mpp'], amount: usd('1.00'), kind: 'usage', name: 'u' }, DEFAULTS)).toThrow(
            ProtocolIncompatibleError,
        );
    });
});

describe('createPayKit usage flow', () => {
    it('challenges an unpaid usage route with the upto scheme', async () => {
        const pay = await createPayKit({
            accept: ['x402'],
            mpp: { challengeBindingSecret: 'usage-test-secret' },
            network: 'solana_localnet',
            pricing: { summarize: usage(usd('1.00')) },
        });

        const request = new Request('http://api.test/summarize');
        const result = await pay.requirePayment(request, 'summarize');

        expect('challenge' in result).toBe(true);
        if (!('challenge' in result)) return;
        expect(result.status).toBe(402);
        const entry = result.challenge.accepts[0];
        expect(entry?.scheme).toBe('upto');
        expect(entry?.protocol).toBe('x402');
        expect(entry?.amount).toBe('1000000');
        expect(result.challenge.headers['payment-required']).toBeTypeOf('string');
        expect(pay.charge(request)).toBeUndefined();
    });

    it('types gate names from the pricing catalogue', async () => {
        const pay = await createPayKit({
            accept: ['x402'],
            mpp: { challengeBindingSecret: 'usage-test-secret' },
            network: 'solana_localnet',
            pricing: { summarize: usage(usd('1.00')) },
        });
        expect(typeof pay.express('summarize')).toBe('function');
        // @ts-expect-error 'nope' is not a gate in the pricing catalogue
        void pay.express('nope');
    });
});
