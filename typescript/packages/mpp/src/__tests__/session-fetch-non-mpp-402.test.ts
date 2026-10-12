/**
 * Regression tests: a 402 that offers no MPP `Payment` challenge is
 * returned unchanged by `SessionFetchClient` instead of throwing from the
 * challenge parser; malformed Solana session challenges still throw.
 */
import { Challenge } from 'mppx';
import { describe, expect, test } from 'vitest';

import { createSessionFetch } from '../client/index.js';

const session = {
    id: 'non-mpp-402',
    intent: 'session',
    method: 'solana',
    realm: 'test',
    request: {
        amount: '1',
        currency: 'USDC',
        methodDetails: {
            channelProgram: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX',
            gracePeriodSeconds: 900,
            minVoucherDelta: '1',
            network: 'localnet',
            recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
            recentSlot: '9042',
        },
        recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
        suggestedDeposit: '1000000',
    },
} as const;

function clientFor(response: Response) {
    return createSessionFetch({
        fetch: () => Promise.resolve(response),
        opener: () => {
            throw new Error('opener must not run');
        },
    });
}

describe('SessionFetchClient with a 402 that offers no Solana session', () => {
    test.each([
        ['no WWW-Authenticate header (x402-only)', { 'Payment-Required': 'eyJ4NDAyVmVyc2lvbiI6Mn0=' }],
        ['a Bearer challenge', { 'WWW-Authenticate': 'Bearer realm="api"' }],
        ['a Basic realm containing Payment', { 'WWW-Authenticate': 'Basic realm="my Payment api"' }],
        ['a quoted comma and Payment', { 'WWW-Authenticate': 'Basic realm="a, Payment api"' }],
        ['an escaped quote and Payment', { 'WWW-Authenticate': 'Basic realm="a\\\", Payment api"' }],
        ['a parameter named Payment', { 'WWW-Authenticate': 'Digest realm="api", Payment = "text"' }],
        ['a token suffix', { 'WWW-Authenticate': 'NotPayment realm="api"' }],
        ['an empty WWW-Authenticate value', { 'WWW-Authenticate': '' }],
        [
            'a non-Solana MPP session challenge',
            { 'WWW-Authenticate': Challenge.serialize({ ...session, method: 'tempo' } as never) },
        ],
        [
            'a Solana charge challenge',
            { 'WWW-Authenticate': Challenge.serialize({ ...session, intent: 'charge' } as never) },
        ],
    ])('returns the original response for %s', async (_name, headers) => {
        const original = new Response(null, { headers, status: 402 });
        await expect(clientFor(original).fetch('https://api.test/resource')).resolves.toBe(original);
    });

    test('still rejects a malformed Solana session challenge', async () => {
        const malformed = new Response(null, {
            headers: {
                'WWW-Authenticate': Challenge.serialize({
                    ...session,
                    request: { amount: '1', currency: 'USDC' },
                } as never),
            },
            status: 402,
        });
        await expect(clientFor(malformed).fetch('https://api.test/resource')).rejects.toThrow(
            /Invalid Solana session challenge/,
        );
    });

    test('still opens when a Payment challenge follows another scheme', async () => {
        const mixed = new Response(null, {
            headers: { 'WWW-Authenticate': `Bearer realm="api", ${Challenge.serialize(session as never)}` },
            status: 402,
        });
        await expect(clientFor(mixed).fetch('https://api.test/resource')).rejects.toThrow('opener must not run');
    });

    test('does not split a valid Payment challenge at quoted Payment text', async () => {
        const mixed = new Response(null, {
            headers: {
                'WWW-Authenticate': `Basic realm="a, Payment api", ${Challenge.serialize({
                    ...session,
                    realm: 'my Payment api',
                    description: 'a, Payment description',
                })}, Bearer realm="api"`,
            },
            status: 402,
        });
        await expect(clientFor(mixed).fetch('https://api.test/resource')).rejects.toThrow('opener must not run');
    });

    test('still rejects a malformed Payment wire challenge', async () => {
        const malformed = new Response(null, {
            headers: { 'WWW-Authenticate': 'Payment id="missing-request", method="solana", intent="session"' },
            status: 402,
        });
        await expect(clientFor(malformed).fetch('https://api.test/resource')).rejects.toThrow('Missing request');
    });

    test('does not consume the original non-MPP 402 body', async () => {
        const original = new Response('payment terms', { status: 402 });
        const returned = await clientFor(original).fetch('https://api.test/resource');
        expect(returned).toBe(original);
        expect(returned.bodyUsed).toBe(false);
        expect(await returned.text()).toBe('payment terms');
    });
});
