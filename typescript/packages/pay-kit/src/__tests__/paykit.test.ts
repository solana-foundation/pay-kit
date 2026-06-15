import { describe, expect, it } from 'vitest';

import type { ProtocolAdapter } from '../adapter.js';
import { configure, type PayKitConfig } from '../config.js';
import { ConfigurationError, InvalidProofError, UnknownGateError } from '../errors.js';
import type { Payment } from '../payment.js';
import { createPayKit } from '../paykit.js';
import { usd } from '../price.js';
import { createPricing } from '../pricing.js';

const CREDENTIAL_HEADER = 'x-fake-credential';

function fakeAdapter(config: PayKitConfig): ProtocolAdapter {
    return {
        async acceptsEntry(gate) {
            return {
                amount: gate.amount.baseUnits().toString(),
                network: 'solana:test',
                payTo: gate.payTo,
                protocol: 'mpp',
                scheme: 'charge',
            };
        },
        async challengeHeaders() {
            return { 'www-authenticate': `Payment realm="${config.mpp.realm}"` };
        },
        detect(request) {
            return request.headers.has(CREDENTIAL_HEADER);
        },
        protocol: 'mpp',
        scheme: 'charge',
        async verifyAndSettle(gate, request): Promise<Payment> {
            const credential = request.headers.get(CREDENTIAL_HEADER);
            if (credential !== 'valid') throw new InvalidProofError('signature_consumed', 'already used');
            return {
                gateName: gate.name,
                payer: 'PayerPubkey',
                protocol: 'mpp',
                raw: credential,
                scheme: 'charge',
                settlementHeaders: { 'x-payment-settlement-signature': 'TxSig' },
                transaction: 'TxSig',
            };
        },
    };
}

async function setup() {
    const config = await configure({ mpp: { challengeBindingSecret: 's3cret' } });
    const pricing = createPricing(config, {
        report: { amount: usd('0.10'), description: 'Premium report' },
        tiered: request => usd(new URL(request.url).searchParams.get('tier') === 'pro' ? '5.00' : '0.10'),
    });
    return createPayKit(config, { adapters: [fakeAdapter(config)], pricing });
}

describe('createPayKit', () => {
    it('renders a 402 challenge when no credential is present', async () => {
        const paykit = await setup();
        const request = new Request('http://api.test/report');
        const result = await paykit.requirePayment(request, 'report');
        expect(result.status).toBe(402);
        if (result.status !== 402) return;
        expect(result.challenge.resource).toBe('/report');
        expect(result.challenge.accepts).toHaveLength(1);
        expect(result.challenge.accepts[0]?.amount).toBe('100000');
        expect(result.response.status).toBe(402);
        expect(result.response.headers.get('www-authenticate')).toContain('Payment realm=');
        const body = (await result.response.json()) as { accepts: unknown[] };
        expect(body.accepts).toHaveLength(1);
        expect(paykit.paid(request)).toBe(false);
    });

    it('settles a valid credential and exposes the payment', async () => {
        const paykit = await setup();
        const request = new Request('http://api.test/report', { headers: { [CREDENTIAL_HEADER]: 'valid' } });
        const result = await paykit.requirePayment(request, 'report');
        expect(result.status).toBe(200);
        if (result.status !== 200) return;
        expect(result.payment.transaction).toBe('TxSig');
        expect(result.payment.gateName).toBe('report');
        expect(result.payment.scheme).toBe('charge');
        expect(result.payment.payer).toBe('PayerPubkey');

        const sealed = result.withSettlement(Response.json({ ok: true }, { status: 201 }));
        expect(sealed.status).toBe(201);
        expect(sealed.headers.get('x-payment-settlement-signature')).toBe('TxSig');
        expect(((await sealed.json()) as { ok: boolean }).ok).toBe(true);

        expect(paykit.paid(request)).toBe(true);
        expect(paykit.paid(request, 'report')).toBe(true);
        expect(paykit.paid(request, 'other')).toBe(false);
        expect(paykit.payment(request)?.transaction).toBe('TxSig');
    });

    it('renders 402 with the canonical code on invalid proof', async () => {
        const paykit = await setup();
        const request = new Request('http://api.test/report', { headers: { [CREDENTIAL_HEADER]: 'replayed' } });
        const result = await paykit.requirePayment(request, 'report');
        expect(result.status).toBe(402);
        if (result.status !== 402) return;
        const body = (await result.response.json()) as { code: string; detail: string };
        expect(body.code).toBe('signature_consumed');
        expect(body.detail).toBe('already used');
        expect(paykit.paid(request)).toBe(false);
    });

    it('resolves gates by name, price, and resolver', async () => {
        const paykit = await setup();
        const denied = await paykit.requirePayment(new Request('http://api.test/x'), usd('0.25'));
        expect(denied.status).toBe(402);
        if (denied.status === 402) expect(denied.challenge.accepts[0]?.amount).toBe('250000');

        const pro = await paykit.requirePayment(new Request('http://api.test/x?tier=pro'), 'tiered');
        if (pro.status === 402) expect(pro.challenge.accepts[0]?.amount).toBe('5000000');

        const inline = await paykit.requirePayment(new Request('http://api.test/x'), () => usd('1.00'));
        if (inline.status === 402) expect(inline.challenge.accepts[0]?.amount).toBe('1000000');

        await expect(paykit.requirePayment(new Request('http://api.test/x'), 'missing')).rejects.toThrow(
            UnknownGateError,
        );
    });

    it('requires a pricing catalogue for name references', async () => {
        const config = await configure({ mpp: { challengeBindingSecret: 's3cret' } });
        const paykit = createPayKit(config, { adapters: [fakeAdapter(config)] });
        await expect(paykit.requirePayment(new Request('http://api.test/x'), 'report')).rejects.toThrow(
            ConfigurationError,
        );
    });
});
