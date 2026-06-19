import { describe, expect, it } from 'vitest';

import { createX402ExactAdapter } from '../adapters/x402.js';
import { Charge, X402Upto } from '../adapters/x402-upto.js';
import { configure, type PayKitConfig } from '../config.js';
import { Gate } from '../gate.js';
import { usd } from '../price.js';
import { gateDefaults } from '../pricing.js';

async function testConfig(): Promise<PayKitConfig> {
    return await configure({ mpp: { challengeBindingSecret: 'x402-test-secret' }, network: 'solana_localnet' });
}

function gateFor(config: PayKitConfig, amount = usd('0.10')): Gate {
    return Gate.create({ amount, name: 'test' }, gateDefaults(config));
}

describe('x402 exact adapter', () => {
    it('advertises a canonical x402 accepts entry', async () => {
        const config = await testConfig();
        const adapter = createX402ExactAdapter(config);
        const entry = await adapter.acceptsEntry(gateFor(config), new Request('http://localhost/r'));

        expect(entry.protocol).toBe('x402');
        expect(entry.scheme).toBe('exact');
        expect(entry.amount).toBe('100000'); // 0.10 USDC, 6 decimals
        expect(entry.payTo).toBe(config.operator.recipient);
        expect(typeof entry.network).toBe('string');
        expect(typeof entry.asset).toBe('string');
        expect((entry.extra as { feePayer?: string }).feePayer).toBe(config.operator.signer.pubkey);
    });

    it('detects the x402 payment header', async () => {
        const config = await testConfig();
        const adapter = createX402ExactAdapter(config);
        expect(adapter.detect(new Request('http://localhost/r'))).toBe(false);
        expect(adapter.detect(new Request('http://localhost/r', { headers: { 'x-payment': 'abc' } }))).toBe(true);
        expect(adapter.detect(new Request('http://localhost/r', { headers: { 'payment-signature': 'abc' } }))).toBe(
            true,
        );
    });

    it('emits the PAYMENT-REQUIRED challenge header', async () => {
        const config = await testConfig();
        const adapter = createX402ExactAdapter(config);
        const headers = await adapter.challengeHeaders(gateFor(config), new Request('http://localhost/r'));
        expect(typeof headers['payment-required']).toBe('string');
        expect(headers['payment-required'].length).toBeGreaterThan(0);
    });
});

describe('x402 upto engine', () => {
    it('advertises an upto accepts entry with the facilitator binding', async () => {
        const config = await testConfig();
        const upto = new X402Upto(config);
        const [entry] = upto.accepts(usd('1.00'));

        expect(entry.scheme).toBe('upto');
        expect(entry.amount).toBe('1000000'); // 1.00 USDC ceiling
        expect(entry.payTo).toBe(config.operator.recipient);
        expect((entry.extra as { facilitator?: string }).facilitator).toBe(config.operator.signer.pubkey);
        expect((entry.extra as { feePayer?: string }).feePayer).toBe(config.operator.signer.pubkey);
        expect((entry.extra as { profiles?: string[] }).profiles).toContain('payment-channel');
    });

    it('detects the payment header and emits a challenge', async () => {
        const config = await testConfig();
        const upto = new X402Upto(config);
        expect(upto.detect(new Request('http://localhost/u'))).toBe(false);
        expect(upto.detect(new Request('http://localhost/u', { headers: { 'x-payment': 'abc' } }))).toBe(true);
        const headers = await upto.challengeHeaders(usd('1.00'), new Request('http://localhost/u'));
        expect(typeof headers['payment-required']).toBe('string');
    });
});

describe('Charge meter', () => {
    it('defaults to a zero settlement', () => {
        expect(new Charge(1_000_000n).settledBaseUnits()).toBe(0n);
    });

    it('records the reported amount', () => {
        const charge = new Charge(1_000_000n);
        charge.charge(400_000n);
        expect(charge.settledBaseUnits()).toBe(400_000n);
    });

    it('clamps above the ceiling and floors negatives', () => {
        const overCharge = new Charge(1_000_000n);
        overCharge.charge(2_000_000n);
        expect(overCharge.settledBaseUnits()).toBe(1_000_000n);

        const negative = new Charge(1_000_000n);
        negative.charge(-5);
        expect(negative.settledBaseUnits()).toBe(0n);
    });

    it('accepts a plain number', () => {
        const charge = new Charge(1_000_000n);
        charge.charge(250_000);
        expect(charge.settledBaseUnits()).toBe(250_000n);
    });
});
