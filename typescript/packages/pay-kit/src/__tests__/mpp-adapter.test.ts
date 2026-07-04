import { Challenge } from '@solana/mpp/client';
import { describe, expect, it } from 'vitest';

import { createMppAdapter } from '../adapters/mpp.js';
import { configure } from '../config.js';
import { Gate } from '../gate.js';
import { usd } from '../price.js';
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

    it('round-trips a quote-bearing gate description through the emitted challenge', async () => {
        // A description with an inner double quote reaches mppx's raw serializer,
        // which interpolates it verbatim: the emitted `WWW-Authenticate` header
        // is malformed and a client-side `Challenge.deserialize` truncates the
        // description at the first inner quote. The adapter must escape the value
        // at the mppx boundary so the header stays parseable and lossless.
        const { adapter } = await setup();
        const description = 'Access to "premium" API';
        const withDescription = Gate.create(
            { amount: usd('10.00'), description, name: 'quoted', payTo: SELLER },
            { accept: ['mpp'], payTo: SELLER },
        );
        const headers = await adapter.challengeHeaders(withDescription, new Request('http://t/quoted'));
        const wwwAuthenticate = headers['www-authenticate'];
        expect(wwwAuthenticate).toBeDefined();
        const parsed = Challenge.deserialize(wwwAuthenticate as string);
        expect(parsed.description).toBe(description);
    });

    it('round-trips every quote/backslash-heavy description losslessly (no double-escape)', async () => {
        // Pins the escape symmetry: the adapter escapes once at the mppx
        // boundary and the client un-escapes once. A double-escape (or a missed
        // one) would corrupt any of these inputs.
        const { adapter } = await setup();
        const inputs = [
            'plain',
            'has "one" quote',
            'ends with backslash\\',
            'backslash \\ and "quote"',
            '\\"\\"\\"',
            'nested \\" escape',
            'many """ quotes """ here',
        ];
        for (const description of inputs) {
            const g = Gate.create(
                { amount: usd('10.00'), description, name: 'rt', payTo: SELLER },
                { accept: ['mpp'], payTo: SELLER },
            );
            const headers = await adapter.challengeHeaders(g, new Request('http://t/rt'));
            const parsed = Challenge.deserialize(headers['www-authenticate'] as string);
            expect(parsed.description).toBe(description);
        }
    });

    it('round-trips a quote-bearing realm through the emitted challenge', async () => {
        // The realm crosses into `Mppx.create` and is interpolated verbatim by
        // mppx's raw serializer, same as description.
        const config = await configure({
            mpp: { challengeBindingSecret: 'adapter-test-secret', realm: 'ac"me\\corp' },
            operator: { recipient: SELLER, signer: await Signer.generate() },
        });
        const adapter = createMppAdapter(config);
        const headers = await adapter.challengeHeaders(gate(), new Request('http://t/marketplace'));
        const wwwAuthenticate = headers['www-authenticate'];
        expect(wwwAuthenticate).toBeDefined();
        const parsed = Challenge.deserialize(wwwAuthenticate as string);
        expect(parsed.realm).toBe('ac"me\\corp');
    });

    it('rejects a gate description carrying a CRLF with a clear error, not a per-request 500', async () => {
        // A CR/LF in a challenge-bound value is a header-injection vector: mppx
        // interpolates it verbatim, splitting the emitted header (undici then
        // throws per request). The adapter must fail fast with a clear error when
        // the handler is built, not surface an opaque runtime failure.
        const { adapter } = await setup();
        const injected = Gate.create(
            { amount: usd('10.00'), description: 'legit\r\nInjected-Header: evil', name: 'inject', payTo: SELLER },
            { accept: ['mpp'], payTo: SELLER },
        );
        // A tight matcher: the current (unfixed) path throws undici's opaque
        // `... is an invalid header value` per request, whose base64 body
        // incidentally contains the substrings "cr"/"lf" — so this asserts on
        // the deliberate, human-readable config error, not that accident.
        await expect(adapter.challengeHeaders(injected, new Request('http://t/inject'))).rejects.toThrow(
            /must not contain a (carriage-return|newline)/i,
        );
    });

    it('rejects a realm carrying a newline with a clear error', async () => {
        const config = await configure({
            mpp: { challengeBindingSecret: 'adapter-test-secret', realm: 'api.example.com\nInjected: evil' },
            operator: { recipient: SELLER, signer: await Signer.generate() },
        });
        const adapter = createMppAdapter(config);
        await expect(adapter.challengeHeaders(gate(), new Request('http://t/marketplace'))).rejects.toThrow(
            /must not contain a (carriage-return|newline)/i,
        );
    });
});
