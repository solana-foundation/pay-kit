import { describe, expect, it, vi } from 'vitest';

// The upto challenge/discovery paths require a server-fetched recentBlockhash
// + recentSlot and no longer degrade to a bare (unusable) offer; stub the RPC
// so these offline tests get a deterministic enriched requirement.
vi.mock('@solana/kit', async importOriginal => {
    const actual = await importOriginal<typeof import('@solana/kit')>();
    return {
        ...actual,
        createSolanaRpc: () => ({
            getLatestBlockhash: () => ({
                send: async () => ({
                    context: { slot: 314n },
                    value: {
                        blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                        lastValidBlockHeight: 100n,
                    },
                }),
            }),
        }),
    };
});

import type { ExpressRoutesApp } from '../express-routes.js';
import { createPayKit } from '../paykit.js';
import { usd } from '../price.js';
import { session, subscription, usage } from '../pricing.js';

type Offer = {
    amount: string;
    currency: string;
    description?: string;
    feePayer?: string;
    intent: string;
    method: string;
    planId?: string;
    scheme: string;
    unitPrice?: string;
};
type Operation = { 'x-payment-info'?: { offers: Offer[] }; summary?: string };

const PLAN = 'PLan11111111111111111111111111111111111111';

async function paykit() {
    return createPayKit({
        accept: ['x402', 'mpp'],
        mpp: { challengeBindingSecret: 'openapi-test-secret' },
        network: 'solana_localnet',
        pricing: {
            feed: subscription(usd('0.10'), {
                periodCount: 1,
                periodUnit: 'day',
                planId: PLAN,
                puller: 'PuLLer11111111111111111111111111111111111',
            }),
            joke: { accept: ['x402'], amount: usd('0.001') },
            quote: usd('0.01'),
            stream: session(usd('1.00'), { unitPrice: usd('0.0001') }),
            summarize: usage(usd('0.1')),
        },
    });
}

describe('pay.openapi', () => {
    it('emits an OpenAPI 3.1 document with x-payment-info per route', async () => {
        const pay = await paykit();
        const doc = (await pay.openapi([
            { gate: 'quote', method: 'GET', path: '/api/quote/{symbol}' },
            { gate: 'joke', method: 'GET', path: '/x402/joke' },
            { gate: 'summarize', method: 'POST', path: '/x402/summarize' },
        ])) as {
            openapi: string;
            paths: Record<string, Record<string, Operation>>;
        };

        expect(doc.openapi).toBe('3.1.0');

        // A charge gate advertises BOTH protocols (x402 exact + mpp charge).
        const quote = doc.paths['/api/quote/{symbol}'].get['x-payment-info']?.offers ?? [];
        expect(quote.map(o => o.method).sort()).toEqual(['mpp', 'x402']);
        expect(quote.every(o => o.intent === 'charge')).toBe(true);
        expect(quote.every(o => o.amount === '10000')).toBe(true); // 0.01 USDC, 6 decimals
        expect(quote.every(o => o.currency === 'USDC')).toBe(true);

        // x402-only gate.
        const joke = doc.paths['/x402/joke'].get['x-payment-info']?.offers ?? [];
        expect(joke).toHaveLength(1);
        expect(joke[0]).toMatchObject({ amount: '1000', intent: 'charge', method: 'x402', scheme: 'exact' });

        // Usage gate: a single x402 `upto` offer at the ceiling.
        const summarize = doc.paths['/x402/summarize'].post['x-payment-info']?.offers ?? [];
        expect(summarize).toHaveLength(1);
        expect(summarize[0]).toMatchObject({ amount: '100000', intent: 'charge', method: 'x402', scheme: 'upto' });
        expect(summarize[0]?.description).toBe('up to 0.1 USDC');
        expect(summarize[0]?.feePayer).toBe(pay.config.operator.signer.pubkey);
    });

    it('advertises subscription and session intents (so the UI can classify them)', async () => {
        const pay = await paykit();
        const doc = (await pay.openapi([
            { gate: 'feed', method: 'GET', path: '/api/v1/premium/feed' },
            { gate: 'stream', method: 'GET', path: '/sessions/stream' },
        ])) as { paths: Record<string, Record<string, Operation>> };

        // Subscription: MPP-only, intent `subscription`, scheme `subscription`, carries the planId.
        const feed = doc.paths['/api/v1/premium/feed'].get['x-payment-info']?.offers ?? [];
        expect(feed).toHaveLength(1);
        expect(feed[0]).toMatchObject({
            amount: '100000',
            intent: 'subscription',
            method: 'mpp',
            planId: PLAN,
            scheme: 'subscription',
        });

        // Session: MPP-only, intent `session`, carries the per-delivery unitPrice (0.0001 USDC).
        const stream = doc.paths['/sessions/stream'].get['x-payment-info']?.offers ?? [];
        expect(stream).toHaveLength(1);
        expect(stream[0]).toMatchObject({
            amount: '1000000',
            intent: 'session',
            method: 'mpp',
            scheme: 'session',
            unitPrice: '100',
        });
    });

    it('omits x-payment-info on a route with no offers and supports service info', async () => {
        const pay = await paykit();
        const doc = (await pay.openapi([{ gate: 'quote', method: 'GET', path: '/q', summary: 'Quote' }], {
            info: { title: 'Demo API', version: '2.0.0' },
            serviceInfo: { categories: ['finance'] },
        })) as {
            info: { title: string; version: string };
            paths: Record<string, Record<string, Operation>>;
            'x-service-info'?: unknown;
        };

        expect(doc.info).toEqual({ title: 'Demo API', version: '2.0.0' });
        expect(doc['x-service-info']).toEqual({ categories: ['finance'] });
        expect(doc.paths['/q'].get.summary).toBe('Quote');
    });

    it('introspects gated routes from a mounted Express app', async () => {
        const pay = await paykit();
        // A minimal Express-app shape: the route's handler stack holds the
        // gate-tagged middleware returned by pay.express.
        const app: ExpressRoutesApp = {
            _router: {
                stack: [
                    { route: { methods: { get: true }, path: '/x402/joke', stack: [{ handle: pay.express('joke') }] } },
                    {
                        route: {
                            methods: { post: true },
                            path: '/api/quote/:symbol',
                            stack: [{ handle: pay.express('quote') }],
                        },
                    },
                    // An untagged (free) route is ignored.
                    { route: { methods: { get: true }, path: '/health', stack: [{ handle: () => undefined }] } },
                ],
            },
        };

        const doc = (await pay.openapiFromExpress(app)) as { paths: Record<string, Record<string, Operation>> };
        expect(Object.keys(doc.paths).sort()).toEqual(['/api/quote/{symbol}', '/x402/joke']);
        expect(doc.paths['/x402/joke'].get['x-payment-info']?.offers[0]?.scheme).toBe('exact');
        expect(doc.paths['/api/quote/{symbol}'].post['x-payment-info']?.offers.map(o => o.method).sort()).toEqual([
            'mpp',
            'x402',
        ]);
    });
});
