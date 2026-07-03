import type { ServerResponse } from 'node:http';
import { describe, expect, it, vi } from 'vitest';

import type { SessionEngine, SessionReceipt, SessionResult } from '../adapters/mpp-session.js';

const AUTH_HEADER = 'authorization';

// Per-test control over the mocked session engine's handler + receipt outcomes.
const control: {
    handler: (request: Request) => Promise<SessionResult>;
    receipt: (channelId: string) => Promise<SessionReceipt | undefined>;
    commit: (request: Request) => Promise<Response>;
    deliveries: (request: Request) => Promise<Response>;
    created: string[];
} = {
    commit: () => Promise.resolve(Response.json({ commit: true })),
    created: [],
    deliveries: () => Promise.resolve(Response.json({ deliveries: true })),
    handler: () => Promise.resolve({ challenge: Response.json({}, { status: 402 }), status: 402 }),
    receipt: () => Promise.resolve(undefined),
};

vi.mock('../adapters/mpp-session.js', async () => {
    const actual = await vi.importActual<typeof import('../adapters/mpp-session.js')>('../adapters/mpp-session.js');
    return {
        ...actual,
        createSessionEngine(_config: unknown, gate: { name: string }): SessionEngine {
            control.created.push(gate.name);
            return {
                commit: (request: Request) => control.commit(request),
                deliveries: (request: Request) => control.deliveries(request),
                handler: (request: Request) => control.handler(request),
                receipt: (channelId: string) => control.receipt(channelId),
            };
        },
    };
});

const { createPayKit } = await import('../paykit.js');
const { usd } = await import('../price.js');
const { session } = await import('../pricing.js');
const { configure } = await import('../config.js');
const { Gate } = await import('../gate.js');
const { gateDefaults } = await import('../pricing.js');

function resetControl(): void {
    control.created = [];
    control.commit = () => Promise.resolve(Response.json({ commit: true }));
    control.deliveries = () => Promise.resolve(Response.json({ deliveries: true }));
    control.handler = () => Promise.resolve({ challenge: Response.json({}, { status: 402 }), status: 402 });
    control.receipt = () => Promise.resolve(undefined);
}

async function sessionPaykit() {
    return createPayKit({
        accept: ['mpp'],
        mpp: { challengeBindingSecret: 's' },
        network: 'solana_localnet',
        operator: { feePayer: true },
        pricing: { stream: session(usd('1.00'), { unitPrice: usd('0.0001') }) },
    });
}

/** A minimal node ServerResponse spy capturing status, headers, and body. */
function fakeRes(): ServerResponse & { readonly captured: { body: string; headers: Record<string, string> } } {
    const captured = { body: '', headers: {} as Record<string, string> };
    const res = {
        captured,
        end(chunk?: unknown) {
            if (chunk !== undefined) captured.body += Buffer.isBuffer(chunk) ? chunk.toString() : String(chunk);
            return res;
        },
        setHeader(name: string, value: string) {
            captured.headers[name.toLowerCase()] = value;
            return res;
        },
        statusCode: 200,
        writeHead(status: number, headers?: Record<string, string>) {
            res.statusCode = status;
            if (headers) for (const [k, v] of Object.entries(headers)) captured.headers[k.toLowerCase()] = String(v);
            return res;
        },
    };
    return res as unknown as ServerResponse & { readonly captured: typeof captured };
}

describe('requireSession', () => {
    it('returns the engine 402 challenge for an unopened channel', async () => {
        resetControl();
        control.handler = () =>
            Promise.resolve({ challenge: Response.json({ need: 'channel' }, { status: 402 }), status: 402 });
        const pay = await sessionPaykit();
        const result = await pay.requirePayment(new Request('http://t/stream'), 'stream');
        expect('challenge' in result).toBe(true);
        if ('challenge' in result) {
            expect(result.status).toBe(402);
            expect(result.challenge.resource).toBe('/stream');
        }
    });

    it('grants and lifts the open-receipt headers when the channel opens', async () => {
        resetControl();
        control.handler = () =>
            Promise.resolve({
                status: 200,
                withReceipt(response: Response) {
                    const headers = new Headers(response.headers);
                    headers.set('payment-receipt', 'RECEIPT');
                    headers.set('x-payment-settlement-signature', 'OPEN_SIG');
                    headers.set('unrelated', 'ignored');
                    return new Response(response.body, { headers, status: response.status });
                },
            });
        const pay = await sessionPaykit();
        const request = new Request('http://t/stream', { headers: { [AUTH_HEADER]: 'Payment voucher' } });
        const result = await pay.requirePayment(request, 'stream');
        expect('payment' in result).toBe(true);
        if ('payment' in result) {
            expect(result.status).toBe(200);
            expect(result.payment.scheme).toBe('session');
            expect(result.payment.protocol).toBe('mpp');
            expect(result.payment.raw).toBe('Payment voucher');
            expect(result.payment.settlementHeaders['payment-receipt']).toBe('RECEIPT');
            expect(result.payment.settlementHeaders['x-payment-settlement-signature']).toBe('OPEN_SIG');
            expect(result.payment.settlementHeaders.unrelated).toBeUndefined();
            // settle() just replays the lifted headers (no out-of-band settlement here).
            expect(await result.settle()).toEqual(result.payment.settlementHeaders);
        }
        expect(pay.payment(request)?.scheme).toBe('session');
    });

    it('reuses one engine per session gate across calls', async () => {
        resetControl();
        const pay = await sessionPaykit();
        await pay.requirePayment(new Request('http://t/stream'), 'stream');
        await pay.requirePayment(new Request('http://t/stream'), 'stream');
        pay.sessionRoutes('stream');
        // createSessionEngine ran exactly once for the 'stream' gate.
        expect(control.created).toEqual(['stream']);
    });
});

describe('pay.sessionRoutes', () => {
    it('delegates commit and deliveries to the engine', async () => {
        resetControl();
        control.commit = () => Promise.resolve(Response.json({ committed: 'yes' }, { status: 202 }));
        control.deliveries = () => Promise.resolve(Response.json({ reserved: 'yes' }, { status: 201 }));
        const pay = await sessionPaykit();
        const routes = pay.sessionRoutes('stream');

        const commitRes = fakeRes();
        await routes.commit({ body: { voucher: 1 }, headers: { host: 't' }, method: 'POST' } as never, commitRes);
        expect(commitRes.statusCode).toBe(202);
        expect(commitRes.captured.body).toContain('committed');

        const deliveriesRes = fakeRes();
        await routes.deliveries({ headers: { host: 't' }, method: 'POST' } as never, deliveriesRes);
        expect(deliveriesRes.statusCode).toBe(201);
        expect(deliveriesRes.captured.body).toContain('reserved');
    });

    it('rejects a receipt request with a missing or empty channelId (400)', async () => {
        resetControl();
        const pay = await sessionPaykit();
        const routes = pay.sessionRoutes('stream');

        const noParam = fakeRes();
        await routes.receipt({ headers: { host: 't' }, method: 'GET' } as never, noParam);
        expect(noParam.statusCode).toBe(400);
        expect(noParam.captured.body).toContain('invalid-channel-id');

        const emptyParam = fakeRes();
        await routes.receipt({ headers: { host: 't' }, method: 'GET', params: { channelId: '' } } as never, emptyParam);
        expect(emptyParam.statusCode).toBe(400);
    });

    it('returns 404 when the channel is unknown', async () => {
        resetControl();
        control.receipt = () => Promise.resolve(undefined);
        const pay = await sessionPaykit();
        const routes = pay.sessionRoutes('stream');
        const res = fakeRes();
        await routes.receipt({ headers: { host: 't' }, method: 'GET', params: { channelId: 'chan-x' } } as never, res);
        expect(res.statusCode).toBe(404);
        expect(res.captured.body).toContain('channel-not-found');
    });

    it('returns 200 with the receipt state for a known channel', async () => {
        resetControl();
        const state: SessionReceipt = {
            channelId: 'chan-x',
            cumulative: '5',
            deposit: '100',
            finalized: false,
            settledSignature: null,
        };
        control.receipt = channelId => Promise.resolve(channelId === 'chan-x' ? state : undefined);
        const pay = await sessionPaykit();
        const routes = pay.sessionRoutes('stream');
        const res = fakeRes();
        await routes.receipt({ headers: { host: 't' }, method: 'GET', params: { channelId: 'chan-x' } } as never, res);
        expect(res.statusCode).toBe(200);
        expect(JSON.parse(res.captured.body)).toMatchObject({ channelId: 'chan-x', cumulative: '5' });
    });

    it('sends the engine 402 challenge from the voucher handler', async () => {
        resetControl();
        control.handler = () =>
            Promise.resolve({ challenge: Response.json({ need: 'auth' }, { status: 402 }), status: 402 });
        const pay = await sessionPaykit();
        const routes = pay.sessionRoutes('stream');
        const res = fakeRes();
        await routes.voucher({ headers: { host: 't' }, method: 'POST' } as never, res);
        expect(res.statusCode).toBe(402);
    });

    it('acks a committed voucher, sealing it with the open receipt', async () => {
        resetControl();
        control.handler = () =>
            Promise.resolve({
                status: 200,
                withReceipt(response: Response) {
                    const headers = new Headers(response.headers);
                    headers.set('payment-receipt', 'VOUCHER_RECEIPT');
                    return new Response(response.body, { headers, status: response.status });
                },
            });
        const pay = await sessionPaykit();
        const routes = pay.sessionRoutes('stream');
        const res = fakeRes();
        await routes.voucher(
            { body: { amount: '250', deliveryId: 'd-1' }, headers: { host: 't' }, method: 'POST' } as never,
            res,
        );
        expect(res.statusCode).toBe(200);
        expect(res.captured.headers['payment-receipt']).toBe('VOUCHER_RECEIPT');
        const body = JSON.parse(res.captured.body) as { amount: string; deliveryId: string; status: string };
        expect(body).toEqual({ amount: '250', deliveryId: 'd-1', status: 'committed' });
    });

    it('acks with defaults when the voucher body is absent', async () => {
        resetControl();
        control.handler = () => Promise.resolve({ status: 200, withReceipt: (response: Response) => response });
        const pay = await sessionPaykit();
        const routes = pay.sessionRoutes('stream');
        const res = fakeRes();
        await routes.voucher({ headers: { host: 't' }, method: 'POST' } as never, res);
        const body = JSON.parse(res.captured.body) as { amount: string; deliveryId: string; status: string };
        expect(body).toEqual({ amount: '0', deliveryId: '', status: 'committed' });
    });
});

describe('resolveStaticGate for session routes', () => {
    it('accepts a concrete Gate instance', async () => {
        resetControl();
        const config = await configure({
            accept: ['mpp'],
            mpp: { challengeBindingSecret: 's' },
            operator: { feePayer: true },
        });
        const gate = Gate.create(
            { amount: usd('1.00'), kind: 'session', name: 'inlineStream', session: { unitPrice: 100n } },
            gateDefaults(config),
        );
        const pay = await createPayKit({
            config,
            pricing: { stream: session(usd('1.00'), { unitPrice: usd('0.0001') }) },
        });
        expect(typeof pay.sessionRoutes(gate).commit).toBe('function');
        expect(control.created).toContain('inlineStream');
    });

    it('throws when a name is used but no pricing catalogue was configured', async () => {
        resetControl();
        const pay = await createPayKit({
            accept: ['mpp'],
            mpp: { challengeBindingSecret: 's' },
            operator: { feePayer: true },
        });
        expect(() => pay.sessionRoutes('stream')).toThrow(/no pricing catalogue/);
    });

    it('throws when the named gate resolves to a dynamic (request-resolved) gate', async () => {
        resetControl();
        const pay = await createPayKit({
            accept: ['mpp'],
            mpp: { challengeBindingSecret: 's' },
            operator: { feePayer: true },
            pricing: { dynamic: () => usd('1.00') },
        });
        // 'dynamic' resolves to a DynamicGate, invalid for session routes.
        expect(() => pay.sessionRoutes('dynamic')).toThrow(/cannot be request-resolved/);
    });
});
