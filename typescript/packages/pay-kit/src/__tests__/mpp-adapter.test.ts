import { Challenge } from '@solana/mpp/client';
import { Credential } from 'mppx';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createMppAdapter } from '../adapters/mpp.js';
import { configure } from '../config.js';
import { Gate } from '../gate.js';
import { usd } from '../price.js';
import { subscription } from '../pricing.js';
import { Signer } from '../signer.js';
import { createUnsafeMemorySubscriptionReplayStore } from '../subscription-replay-store.js';

const SELLER = 'AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj';
const PLATFORM = 'CXG3Pq3DwZb1HVckhPQbVxiwoNGM3jNGYvC2BSdkj1pK';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';
const originalFetch = globalThis.fetch;

afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
});

async function setup() {
    const config = await configure({
        mpp: { challengeBindingSecret: 'adapter-test-secret', realm: 'Adapter test' },
        operator: { recipient: SELLER, signer: await Signer.generate() },
    });
    return { adapter: createMppAdapter(config), config };
}

function createSharedTestReplayStore() {
    const entries = new Map<string, unknown>();
    return {
        delete: async (key: string) => {
            entries.delete(key);
        },
        get: async (key: string) => entries.get(key) ?? null,
        isDurable: true as const,
        isShared: true as const,
        put: async (key: string, value: unknown) => {
            entries.set(key, value);
        },
        putIfAbsent: async (key: string, value: unknown) => {
            if (entries.has(key)) return false;
            entries.set(key, value);
            return true;
        },
        reserve: async (key: string, value: unknown) => {
            if (entries.has(key)) return false;
            entries.set(key, value);
            return true;
        },
    };
}

function gate(params: Parameters<typeof Gate.create>[0]['feeWithin'] = undefined) {
    return Gate.create(
        { amount: usd('10.00'), feeWithin: params, name: 'marketplace', payTo: SELLER },
        { accept: ['mpp'], payTo: SELLER },
    );
}

describe('createMppAdapter', () => {
    it('rejects a process-local subscription replay store outside localnet', async () => {
        const config = await configure({
            accept: ['mpp'],
            mpp: { challengeBindingSecret: 'adapter-test-secret' },
            network: 'solana_devnet',
            operator: { feePayer: true, recipient: SELLER, signer: await Signer.generate() },
            replayStore: createUnsafeMemorySubscriptionReplayStore(),
        });
        const subscriptionGate = Gate.create(
            {
                ...subscription(usd('0.10'), {
                    merchant: SELLER,
                    periodCount: 1,
                    periodUnit: 'day',
                    planBump: 255,
                    planCreatedAt: 1_700_000_000n,
                    planId: PLATFORM,
                    planIdNumeric: 1n,
                    puller: config.operator.signer.pubkey,
                }),
                name: 'feed',
                payTo: SELLER,
            },
            { accept: ['mpp'], payTo: SELLER },
        );

        await expect(
            createMppAdapter(config).challengeHeaders(subscriptionGate, new Request('http://t/feed')),
        ).rejects.toThrow(/isShared=true or isDurable=true/);
    });

    it('binds subscription credentials to the exact request without serializing query values', async () => {
        const signer = await Signer.generate();
        const config = await configure({
            accept: ['mpp'],
            mpp: { challengeBindingSecret: 'adapter-test-secret', realm: 'Adapter test' },
            operator: { feePayer: true, recipient: SELLER, signer },
            replayStore: createSharedTestReplayStore(),
        });
        globalThis.fetch = async () =>
            new Response(JSON.stringify({ result: { value: { blockhash: BLOCKHASH } } }), {
                headers: { 'Content-Type': 'application/json' },
            });
        const subscriptionGate = Gate.create(
            {
                ...subscription(usd('0.10'), {
                    merchant: SELLER,
                    periodCount: 1,
                    periodUnit: 'day',
                    planBump: 255,
                    planCreatedAt: 1_700_000_000n,
                    planId: PLATFORM,
                    planIdNumeric: 1n,
                    puller: signer.pubkey,
                }),
                name: 'feed',
                payTo: SELLER,
            },
            { accept: ['mpp'], payTo: SELLER },
        );
        const adapter = createMppAdapter(config);
        const requested = 'http://t/feed?api_key=secret&tier=basic&tier=preview';
        const gateA = await adapter.challengeHeaders(subscriptionGate, new Request(requested));
        const challenge = Challenge.deserialize(gateA['www-authenticate'] as string);
        const resource = (challenge.request as { resource?: string }).resource;

        expect(resource).toMatch(/^pay-kit:mpp-subscription-resource:v1:hmac-sha256:[a-f0-9]{64}$/);
        expect(resource).not.toContain('api_key=secret');
        expect(resource).not.toContain('secret');

        const sameResource = (
            Challenge.deserialize(
                (await adapter.challengeHeaders(subscriptionGate, new Request(requested)))[
                    'www-authenticate'
                ] as string,
            ).request as { resource?: string }
        ).resource;
        expect(sameResource).toBe(resource);

        const mismatchedRequests = [
            'http://t/feed?api_key=other&tier=basic&tier=preview',
            'http://t/feed?tier=basic&tier=preview&api_key=secret',
            'http://t/feed?api_key=secret&tier=basic',
            'http://t/feed?api_key=sec%72et&tier=basic&tier=preview',
        ];
        for (const currentRequest of mismatchedRequests) {
            const currentResource = (
                Challenge.deserialize(
                    (await adapter.challengeHeaders(subscriptionGate, new Request(currentRequest)))[
                        'www-authenticate'
                    ] as string,
                ).request as { resource?: string }
            ).resource;
            expect(currentResource).not.toBe(resource);
        }

        const adapterWithDifferentSecret = createMppAdapter(
            await configure({
                accept: ['mpp'],
                mpp: { challengeBindingSecret: 'different-adapter-test-secret', realm: 'Adapter test' },
                operator: { feePayer: true, recipient: SELLER, signer },
                replayStore: createSharedTestReplayStore(),
            }),
        );
        const resourceWithDifferentSecret = (
            Challenge.deserialize(
                (await adapterWithDifferentSecret.challengeHeaders(subscriptionGate, new Request(requested)))[
                    'www-authenticate'
                ] as string,
            ).request as { resource?: string }
        ).resource;
        expect(resourceWithDifferentSecret).not.toBe(resource);

        const credential = Credential.serialize({
            challenge,
            payload: { transaction: '', type: 'transaction' },
        });
        const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);

        // The malformed transaction fails later, proving the exact query has
        // passed resource binding without requiring an on-chain fixture.
        await expect(
            adapter.verifyAndSettle(
                subscriptionGate,
                new Request(requested, { headers: { authorization: credential } }),
            ),
        ).rejects.toThrow('Payment verification failed.');
        expect(consoleError).not.toHaveBeenCalledWith(
            'mppx: internal verification error',
            expect.objectContaining({ message: 'Subscription credential resource does not match the current route' }),
        );

        for (const currentRequest of mismatchedRequests) {
            consoleError.mockClear();
            await expect(
                adapter.verifyAndSettle(
                    subscriptionGate,
                    new Request(currentRequest, { headers: { authorization: credential } }),
                ),
            ).rejects.toThrow('Payment verification failed.');
            expect(consoleError).toHaveBeenCalledWith(
                'mppx: internal verification error',
                expect.objectContaining({
                    message: 'Subscription credential resource does not match the current route',
                }),
            );
        }
    });

    it('detects MPP payment credentials', async () => {
        const { adapter } = await setup();
        expect(adapter.detect(new Request('http://t/', { headers: { authorization: 'Payment abc' } }))).toBe(true);
        expect(adapter.detect(new Request('http://t/', { headers: { authorization: 'Bearer abc' } }))).toBe(false);
        expect(adapter.detect(new Request('http://t/'))).toBe(false);
    });

    it('builds a spec-shaped accepts entry', async () => {
        const { adapter } = await setup();
        const entry = await adapter.acceptsEntry(gate(), new Request('http://t/marketplace'));
        expect(entry).toMatchObject({
            amount: '10000000',
            currency: 'USDC',
            network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
            payTo: SELLER,
            protocol: 'mpp',
            realm: 'Adapter test',
            scheme: 'charge',
        });
        expect(entry.splits).toBeUndefined();
    });

    it('lowers within fees to splits carved from the customer total', async () => {
        const { adapter } = await setup();
        const entry = await adapter.acceptsEntry(gate({ [PLATFORM]: usd('0.30') }), new Request('http://t/m'));
        // The wire amount is the customer total; the verifier derives the
        // primary transfer as amount − Σsplits (here 9_700_000 to the seller).
        expect(entry.amount).toBe('10000000');
        expect(entry.splits).toEqual([{ amount: '300000', recipient: PLATFORM }]);
    });

    it('adds on-top fees to the customer total', async () => {
        const { adapter } = await setup();
        const onTop = Gate.create(
            { amount: usd('10.00'), feeOnTop: { [PLATFORM]: usd('0.50') }, name: 'ticket', payTo: SELLER },
            { accept: ['mpp'], payTo: SELLER },
        );
        const entry = await adapter.acceptsEntry(onTop, new Request('http://t/m'));
        expect(entry.amount).toBe('10500000');
        expect(entry.splits).toEqual([{ amount: '500000', recipient: PLATFORM }]);
    });

    it('issues an MPP challenge for credential-less requests', async () => {
        const { adapter } = await setup();
        const headers = await adapter.challengeHeaders(gate(), new Request('http://t/marketplace'));
        expect(headers['www-authenticate']).toMatch(/^Payment /);
        expect(headers['www-authenticate']).toContain('intent="charge"');
        expect(headers['www-authenticate']).toContain('method="solana"');
        expect(headers['www-authenticate']).toContain('realm="Adapter test"');
    });

    it.each([
        ['description', 'Access to "premium" \\ API'],
        ['description', '\\"quoted\\"'],
    ])('round-trips a quote/backslash-bearing %s', async (_field, description) => {
        const { adapter } = await setup();
        const describedGate = Gate.create(
            { amount: usd('10.00'), description, name: 'quoted', payTo: SELLER },
            { accept: ['mpp'], payTo: SELLER },
        );
        const headers = await adapter.challengeHeaders(describedGate, new Request('http://t/quoted'));
        expect(Challenge.deserialize(headers['www-authenticate'] as string).description).toBe(description);
    });

    it('round-trips a quote/backslash-bearing realm', async () => {
        const realm = 'ac"me\\corp';
        const config = await configure({
            mpp: { challengeBindingSecret: 'adapter-test-secret', realm },
            operator: { recipient: SELLER, signer: await Signer.generate() },
            replayStore: createSharedTestReplayStore(),
        });
        const adapter = createMppAdapter(config);
        const headers = await adapter.challengeHeaders(gate(), new Request('http://t/marketplace'));
        expect(Challenge.deserialize(headers['www-authenticate'] as string).realm).toBe(realm);
    });

    it.each([
        ['carriage return', 'legit\rInjected-Header: evil'],
        ['newline', 'legit\nInjected-Header: evil'],
    ])('rejects a description containing a %s', async (_name, description) => {
        const { adapter } = await setup();
        const injectedGate = Gate.create(
            { amount: usd('10.00'), description, name: 'injected', payTo: SELLER },
            { accept: ['mpp'], payTo: SELLER },
        );
        await expect(adapter.challengeHeaders(injectedGate, new Request('http://t/injected'))).rejects.toThrow(
            /must not contain a carriage-return or newline/,
        );
    });

    it('rejects a realm containing CRLF', async () => {
        const config = await configure({
            mpp: {
                challengeBindingSecret: 'adapter-test-secret',
                realm: 'api.example.com\r\nInjected: evil',
            },
            operator: { recipient: SELLER, signer: await Signer.generate() },
            replayStore: createSharedTestReplayStore(),
        });
        const adapter = createMppAdapter(config);
        await expect(adapter.challengeHeaders(gate(), new Request('http://t/marketplace'))).rejects.toThrow(
            /must not contain a carriage-return or newline/,
        );
    });
});
