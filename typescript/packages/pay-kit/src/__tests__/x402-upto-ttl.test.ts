import { describe, expect, it, vi } from 'vitest';

// The upto engine broadcasts the open through an in-process @x402/core
// facilitator (real crypto + RPC). Stub verify so verifyOpen reaches the replay
// reservation offline; the point under test is the TTL the reservation gets.

vi.mock('@x402/core/facilitator', () => {
    class FakeFacilitator {
        register(): this {
            return this;
        }
        verify(): Promise<{ isValid: boolean; payer: string }> {
            return Promise.resolve({ isValid: true, payer: 'PAYER' });
        }
    }
    return { x402Facilitator: FakeFacilitator };
});

vi.mock('@x402/core/http', () => ({
    decodePaymentSignatureHeader: (header: string) => JSON.parse(header),
    encodePaymentRequiredHeader: () => 'ENCODED_PAYMENT_REQUIRED',
    encodePaymentResponseHeader: () => 'ENCODED_PAYMENT_RESPONSE',
}));

const { X402Upto } = await import('../adapters/x402-upto.js');
const { configure } = await import('../config.js');
const { usd } = await import('../price.js');

const NOW = () => Math.floor(Date.now() / 1000);

function recordingStore() {
    const reserve: { key: string; ttlSeconds?: number }[] = [];
    return {
        reserve,
        store: {
            delete: () => Promise.resolve(),
            get: () => Promise.resolve(null),
            put: () => Promise.resolve(),
            reserve: (key: string, _value: unknown, ttlSeconds?: number) => {
                reserve.push({ key, ttlSeconds });
                return Promise.resolve(true);
            },
        },
    };
}

async function uptoFor(expiresAt: number) {
    const recorder = recordingStore();
    const config = await configure({
        accept: ['x402'],
        network: 'solana_localnet',
        replayStore: recorder.store as never,
    });
    const upto = new X402Upto(config);
    const payload = JSON.stringify({
        accepted: { network: 'solana:localnet' },
        payload: { channelId: 'CH1', expiresAt, from: 'PAYER' },
    });
    await upto.verifyOpen(new Request('http://localhost/u', { headers: { 'x-payment': payload } }), usd('1.00'));
    return recorder.reserve.map(entry => entry.ttlSeconds);
}

describe('x402 upto reservation TTL is bounded by the payer-signed expiresAt', () => {
    it('caps a far-future expiresAt at the hard ceiling (24h)', async () => {
        const tenYears = NOW() + 10 * 365 * 24 * 3600;
        for (const ttl of await uptoFor(tenYears)) expect(ttl).toBe(24 * 60 * 60);
    });

    it('uses the remaining window when it sits between the floor and the ceiling', async () => {
        const inTenMinutes = NOW() + 600;
        for (const ttl of await uptoFor(inTenMinutes)) expect(ttl).toBeCloseTo(600, -1);
    });

    it('floors an already-expired channel at the completion window (300s)', async () => {
        const past = NOW() - 10;
        for (const ttl of await uptoFor(past)) expect(ttl).toBe(300);
    });
});
