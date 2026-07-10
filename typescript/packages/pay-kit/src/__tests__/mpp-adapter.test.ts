import { Challenge } from '@solana/mpp/client';
import { describe, expect, it } from 'vitest';

import { createMppAdapter } from '../adapters/mpp.js';
import { configure } from '../config.js';
import { Gate } from '../gate.js';
import { usd } from '../price.js';
import { createUnsafeMemoryReplayStore } from '../replay-store.js';
import { Signer } from '../signer.js';

const SELLER = 'AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj';
const PLATFORM = 'CXG3Pq3DwZb1HVckhPQbVxiwoNGM3jNGYvC2BSdkj1pK';

async function setup() {
    const config = await configure({
        mpp: { challengeBindingSecret: 'adapter-test-secret', realm: 'Adapter test' },
        operator: { recipient: SELLER, signer: await Signer.generate() },
    });
    return { adapter: createMppAdapter(config), config };
}

function createSharedTestReplayStore() {
    return { ...createUnsafeMemoryReplayStore(), isDurable: true as const, isShared: true as const };
}

function gate(params: Parameters<typeof Gate.create>[0]['feeWithin'] = undefined) {
    return Gate.create(
        { amount: usd('10.00'), feeWithin: params, name: 'marketplace', payTo: SELLER },
        { accept: ['mpp'], payTo: SELLER },
    );
}

describe('createMppAdapter', () => {
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
