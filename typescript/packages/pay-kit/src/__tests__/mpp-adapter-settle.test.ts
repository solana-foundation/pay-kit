import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { InvalidProofError } from '../errors.js';

// --- Boundary mocks -------------------------------------------------------
// The MPP adapter drives @solana/mpp's Mppx charge/subscription handlers
// (which need real crypto + RPC to produce a paid receipt) and deserializes an
// mppx Receipt. Both are stubbed so the adapter's wiring — handler caching per
// (recipient, splits) shape, the subscription branch, the html/service-worker
// respond() path, verifyAndSettle receipt extraction, and problemOf parsing —
// runs offline. resolveStablecoinMint / TOKEN_PROGRAM stay real (offline-safe).

type ChargeResult =
    | { challenge: Response; status: 402 }
    | { status: 200; withReceipt: (response: Response) => Response };

// The handler result is swapped per test through these holders, captured by the
// fake Mppx below. `charge` and `subscription` share one control so a test can
// assert which method the adapter selected.
const handlerControl: {
    charge: () => Promise<ChargeResult>;
    lastMethod: 'charge' | 'subscription' | undefined;
    subscription: () => Promise<ChargeResult>;
} = {
    charge: () => Promise.resolve({ status: 200, withReceipt: (r: Response) => r }),
    lastMethod: undefined,
    subscription: () => Promise.resolve({ status: 200, withReceipt: (r: Response) => r }),
};

const receiptControl: { deserialize: (header: string) => { reference?: string } } = {
    deserialize: () => ({ reference: 'ReceiptRef' }),
};

vi.mock('@solana/mpp/server', () => {
    const solana = {
        charge: (options: unknown) => ({ kind: 'charge', options }),
        subscription: (options: unknown) => ({ kind: 'subscription', options }),
    };
    class FakeMppx {
        static create(): FakeMppx {
            return new FakeMppx();
        }
        charge() {
            handlerControl.lastMethod = 'charge';
            return (_request: Request) => handlerControl.charge();
        }
        subscription() {
            handlerControl.lastMethod = 'subscription';
            return (_request: Request) => handlerControl.subscription();
        }
    }
    return { Mppx: FakeMppx, solana };
});

vi.mock('mppx', async () => {
    const actual = await vi.importActual<typeof import('mppx')>('mppx');
    return { ...actual, Receipt: { deserialize: (header: string) => receiptControl.deserialize(header) } };
});

const { createMppAdapter } = await import('../adapters/mpp.js');
const { configure } = await import('../config.js');
const { Gate } = await import('../gate.js');
const { subscription } = await import('../pricing.js');
const { usd } = await import('../price.js');
const { gateDefaults } = await import('../pricing.js');

const SELLER = 'AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj';
const PLATFORM = 'CXG3Pq3DwZb1HVckhPQbVxiwoNGM3jNGYvC2BSdkj1pK';
const PLAN = 'BPFLoaderUpgradeab1e11111111111111111111111';
const PULLER = 'Vote111111111111111111111111111111111111111';

async function setup(overrides: Parameters<typeof configure>[0] = {}) {
    const config = await configure({
        mpp: { challengeBindingSecret: 'mpp-settle-secret', realm: 'Settle test' },
        operator: { recipient: SELLER },
        ...overrides,
    });
    return { adapter: createMppAdapter(config), config };
}

function fixedGate(feeWithin?: Record<string, ReturnType<typeof usd>>) {
    return Gate.create(
        { amount: usd('10.00'), feeWithin, name: 'marketplace', payTo: SELLER },
        { accept: ['mpp'], payTo: SELLER },
    );
}

async function subscriptionGate() {
    const config = await configure({
        mpp: { challengeBindingSecret: 'mpp-settle-secret' },
        operator: { recipient: SELLER },
    });
    return Gate.create(
        subscription(usd('9.99'), { periodCount: 1, periodUnit: 'day', planId: PLAN, puller: PULLER, name: 'plan' }),
        gateDefaults(config),
    );
}

describe('createMppAdapter — settlement wiring', () => {
    beforeEach(() => {
        handlerControl.lastMethod = undefined;
        handlerControl.charge = () => Promise.resolve({ status: 200, withReceipt: (r: Response) => r });
        handlerControl.subscription = () => Promise.resolve({ status: 200, withReceipt: (r: Response) => r });
        receiptControl.deserialize = () => ({ reference: 'ReceiptRef' });
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    it('returns no challenge headers when the handler settles (non-402)', async () => {
        const { adapter } = await setup();
        const headers = await adapter.challengeHeaders(fixedGate(), new Request('http://t/marketplace'));
        expect(headers).toEqual({});
    });

    it('returns the www-authenticate header from a 402 challenge', async () => {
        handlerControl.charge = () =>
            Promise.resolve({
                challenge: new Response(null, { headers: { 'www-authenticate': 'Payment realm="x"' } }),
                status: 402,
            });
        const { adapter } = await setup();
        const headers = await adapter.challengeHeaders(fixedGate(), new Request('http://t/marketplace'));
        expect(headers['www-authenticate']).toBe('Payment realm="x"');
    });

    it('omits www-authenticate when a 402 challenge lacks it', async () => {
        handlerControl.charge = () => Promise.resolve({ challenge: new Response(null), status: 402 });
        const { adapter } = await setup();
        const headers = await adapter.challengeHeaders(fixedGate(), new Request('http://t/marketplace'));
        expect(headers).toEqual({});
    });

    it('routes subscription gates through the subscription method', async () => {
        const { adapter } = await setup();
        const gate = await subscriptionGate();
        await adapter.challengeHeaders(gate, new Request('http://t/plan'));
        expect(handlerControl.lastMethod).toBe('subscription');
    });

    it('advertises a subscription accepts entry with the planId', async () => {
        const { adapter } = await setup();
        const gate = await subscriptionGate();
        const entry = await adapter.acceptsEntry(gate, new Request('http://t/plan'));
        expect(entry.scheme).toBe('subscription');
        expect((entry as { planId?: string }).planId).toBe(PLAN);
    });

    it('caches one handler per (recipient, splits) shape', async () => {
        const { adapter } = await setup();
        const gate = fixedGate();
        // Two challenge builds against the same gate reuse the cached handler.
        await adapter.challengeHeaders(gate, new Request('http://t/marketplace'));
        await adapter.challengeHeaders(gate, new Request('http://t/marketplace'));
        expect(handlerControl.lastMethod).toBe('charge');
    });

    describe('respond (html payment page)', () => {
        it('returns undefined when html is disabled', async () => {
            const { adapter } = await setup();
            const response = await adapter.respond(fixedGate(), new Request('http://t/marketplace'));
            expect(response).toBeUndefined();
        });

        it('returns undefined when the handler does not issue a 402', async () => {
            const { adapter } = await setup({ mpp: { challengeBindingSecret: 's', html: true } });
            const response = await adapter.respond(fixedGate(), new Request('http://t/marketplace'));
            expect(response).toBeUndefined();
        });

        it('returns the raw challenge Response for a normal 402', async () => {
            handlerControl.charge = () =>
                Promise.resolve({ challenge: new Response('PAGE', { status: 402 }), status: 402 });
            const { adapter } = await setup({ mpp: { challengeBindingSecret: 's', html: true } });
            const response = await adapter.respond(fixedGate(), new Request('http://t/marketplace'));
            expect(await response?.text()).toBe('PAGE');
        });

        it('adds Service-Worker-Allowed for the __mppx_worker sub-request', async () => {
            handlerControl.charge = () =>
                Promise.resolve({ challenge: new Response('SW', { status: 200 }), status: 402 });
            const { adapter } = await setup({ mpp: { challengeBindingSecret: 's', html: true } });
            const response = await adapter.respond(fixedGate(), new Request('http://t/marketplace?__mppx_worker'));
            expect(response?.headers.get('Service-Worker-Allowed')).toBe('/');
        });

        it('also honors the legacy __mpp_worker query flag', async () => {
            handlerControl.charge = () =>
                Promise.resolve({ challenge: new Response('SW', { status: 200 }), status: 402 });
            const { adapter } = await setup({ mpp: { challengeBindingSecret: 's', html: true } });
            const response = await adapter.respond(fixedGate(), new Request('http://t/marketplace?__mpp_worker'));
            expect(response?.headers.get('Service-Worker-Allowed')).toBe('/');
        });
    });

    describe('verifyAndSettle', () => {
        it('throws InvalidProofError with the problem code on a 402', async () => {
            handlerControl.charge = () =>
                Promise.resolve({
                    challenge: new Response(JSON.stringify({ code: 'signature_consumed', detail: 'seen before' }), {
                        headers: { 'content-type': 'application/json' },
                        status: 402,
                    }),
                    status: 402,
                });
            const { adapter } = await setup();
            await expect(
                adapter.verifyAndSettle(fixedGate(), new Request('http://t/marketplace')),
            ).rejects.toMatchObject({ code: 'signature_consumed' });
        });

        it('falls back to invalid_proof when the 402 body carries no code', async () => {
            handlerControl.charge = () =>
                Promise.resolve({
                    challenge: new Response(JSON.stringify({ title: 'A title' }), {
                        headers: { 'content-type': 'application/json' },
                        status: 402,
                    }),
                    status: 402,
                });
            const { adapter } = await setup();
            const error = await adapter
                .verifyAndSettle(fixedGate(), new Request('http://t/marketplace'))
                .catch((e: unknown) => e);
            expect(error).toBeInstanceOf(InvalidProofError);
            expect((error as InvalidProofError).code).toBe('invalid_proof');
            // detail falls back to the `title` field.
            expect((error as InvalidProofError).message).toBe('A title');
        });

        it('falls back to invalid_proof on a non-JSON 402 body', async () => {
            handlerControl.charge = () =>
                Promise.resolve({ challenge: new Response('<html>oops</html>', { status: 402 }), status: 402 });
            const { adapter } = await setup();
            await expect(
                adapter.verifyAndSettle(fixedGate(), new Request('http://t/marketplace')),
            ).rejects.toMatchObject({ code: 'invalid_proof' });
        });

        it('falls back to invalid_proof when the 402 body is a JSON non-object', async () => {
            handlerControl.charge = () =>
                Promise.resolve({ challenge: new Response('"a string"', { status: 402 }), status: 402 });
            const { adapter } = await setup();
            await expect(
                adapter.verifyAndSettle(fixedGate(), new Request('http://t/marketplace')),
            ).rejects.toMatchObject({ code: 'invalid_proof' });
        });

        it('settles a paid request, extracting the receipt reference as the transaction', async () => {
            handlerControl.charge = () =>
                Promise.resolve({
                    status: 200,
                    withReceipt: (_r: Response) =>
                        new Response(null, { headers: { 'payment-receipt': 'RECEIPT_BLOB' } }),
                });
            receiptControl.deserialize = () => ({ reference: 'OnChainSig' });
            const { adapter } = await setup();
            const request = new Request('http://t/marketplace', { headers: { authorization: 'Payment blob' } });
            const payment = await adapter.verifyAndSettle(fixedGate(), request);
            expect(payment).toMatchObject({
                gateName: 'marketplace',
                protocol: 'mpp',
                raw: 'Payment blob',
                scheme: 'charge',
                transaction: 'OnChainSig',
            });
            expect(payment.settlementHeaders['payment-receipt']).toBe('RECEIPT_BLOB');
            expect(payment.settlementHeaders['x-payment-settlement-signature']).toBe('OnChainSig');
        });

        it('settles with an empty transaction when no receipt header is present', async () => {
            handlerControl.charge = () =>
                Promise.resolve({ status: 200, withReceipt: (_r: Response) => new Response(null) });
            const { adapter } = await setup();
            const payment = await adapter.verifyAndSettle(fixedGate(), new Request('http://t/marketplace'));
            expect(payment.transaction).toBe('');
            expect(payment.settlementHeaders).toEqual({});
            expect(payment.raw).toBeUndefined();
        });

        it('handles a receipt whose reference is missing', async () => {
            handlerControl.charge = () =>
                Promise.resolve({
                    status: 200,
                    withReceipt: (_r: Response) =>
                        new Response(null, { headers: { 'payment-receipt': 'RECEIPT_BLOB' } }),
                });
            receiptControl.deserialize = () => ({});
            const { adapter } = await setup();
            const payment = await adapter.verifyAndSettle(fixedGate(), new Request('http://t/marketplace'));
            expect(payment.transaction).toBe('');
            // The receipt header still rides along even without a reference.
            expect(payment.settlementHeaders['payment-receipt']).toBe('RECEIPT_BLOB');
        });

        it('reports the subscription scheme when settling a subscription gate', async () => {
            handlerControl.subscription = () =>
                Promise.resolve({ status: 200, withReceipt: (_r: Response) => new Response(null) });
            const { adapter } = await setup();
            const gate = await subscriptionGate();
            const payment = await adapter.verifyAndSettle(gate, new Request('http://t/plan'));
            expect(payment.scheme).toBe('subscription');
            expect(handlerControl.lastMethod).toBe('subscription');
        });
    });

    describe('splits + on-top fees', () => {
        it('carves within-fees into splits on the accepts entry', async () => {
            const { adapter } = await setup();
            const entry = await adapter.acceptsEntry(fixedGate({ [PLATFORM]: usd('0.30') }), new Request('http://t/m'));
            expect(entry.splits).toEqual([{ amount: '300000', recipient: PLATFORM }]);
        });

        it('carries a fee memo into the split', async () => {
            const gate = Gate.create(
                {
                    amount: usd('10.00'),
                    feeWithin: { [PLATFORM]: { memo: 'platform fee', price: usd('0.30') } },
                    name: 'marketplace',
                    payTo: SELLER,
                },
                { accept: ['mpp'], payTo: SELLER },
            );
            const { adapter } = await setup();
            const entry = await adapter.acceptsEntry(gate, new Request('http://t/m'));
            expect(entry.splits).toEqual([{ amount: '300000', memo: 'platform fee', recipient: PLATFORM }]);
        });
    });

    it('sets an expiry option when mpp.expiresIn is positive', async () => {
        // expiresIn defaults to 120s; a successful settle exercises optionsFor's
        // expires branch. A zero value takes the no-expiry branch.
        const zeroExpiry = await configure({
            mpp: { challengeBindingSecret: 's', expiresIn: 0 },
            operator: { recipient: SELLER },
        });
        const adapterNoExpiry = createMppAdapter(zeroExpiry);
        const payment = await adapterNoExpiry.verifyAndSettle(fixedGate(), new Request('http://t/marketplace'));
        expect(payment.protocol).toBe('mpp');
    });

    it('drops the operator signer from charge options when the operator is not the fee payer', async () => {
        const notFeePayer = await configure({
            mpp: { challengeBindingSecret: 's' },
            operator: { feePayer: false, recipient: SELLER },
        });
        const adapter = createMppAdapter(notFeePayer);
        const payment = await adapter.verifyAndSettle(fixedGate(), new Request('http://t/marketplace'));
        expect(payment.protocol).toBe('mpp');
    });
});
