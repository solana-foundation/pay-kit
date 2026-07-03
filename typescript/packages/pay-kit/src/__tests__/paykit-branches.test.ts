import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it, vi } from 'vitest';

import type { ProtocolAdapter } from '../adapter.js';
import { configure, type PayKitConfig } from '../config.js';
import { ConfigurationError, InvalidProofError } from '../errors.js';
import { Gate } from '../gate.js';
import type { Payment } from '../payment.js';
import type { PayKit } from '../paykit.js';
import type { PricingDef } from '../pricing.js';
import { createPayKit } from '../paykit.js';
import { usd } from '../price.js';
import { gateDefaults } from '../pricing.js';

const CREDENTIAL_HEADER = 'x-fake-credential';

/** An MPP-protocol adapter that verifies only the `valid` credential and can own the HTML response. */
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
            return { 'www-authenticate': 'Payment realm="test"' };
        },
        detect(request) {
            return request.headers.has(CREDENTIAL_HEADER);
        },
        protocol: 'mpp',
        async respond(_gate, request) {
            const wantsHtml = (request.headers.get('accept') ?? '').includes('text/html');
            const isWorker = new URL(request.url).searchParams.has('__mpp_worker');
            if (!wantsHtml && !isWorker) return undefined;
            return new Response('<!doctype html>', { headers: { 'content-type': 'text/html' }, status: 402 });
        },
        scheme: 'charge',
        async verifyAndSettle(gate, request): Promise<Payment> {
            if (request.headers.get(CREDENTIAL_HEADER) !== 'valid') {
                throw new InvalidProofError('signature_consumed', 'already used');
            }
            return {
                gateName: gate.name,
                payer: 'PayerPubkey',
                protocol: 'mpp',
                raw: 'valid',
                scheme: 'charge',
                settlementHeaders: { 'x-payment-settlement-signature': 'TxSig' },
                transaction: 'TxSig',
            };
        },
    };
}

async function setup() {
    const config = await configure({ mpp: { challengeBindingSecret: 's3cret', html: true } });
    const paykit = await createPayKit({
        adapters: [fakeAdapter(config)],
        config,
        pricing: { report: { amount: usd('0.10') } },
    });
    return { config, paykit };
}

describe('requirePayment protocol-owned (respond) branch', () => {
    it('serves the adapter HTML page for a browser on an unpaid request', async () => {
        const { paykit } = await setup();
        const result = await paykit.requirePayment(
            new Request('http://api.test/report', { headers: { accept: 'text/html' } }),
            'report',
        );
        expect('respond' in result).toBe(true);
        if ('respond' in result) {
            expect(result.respond.status).toBe(402);
            expect(result.respond.headers.get('content-type')).toContain('text/html');
        }
    });

    it('re-renders the adapter HTML page for a browser whose proof was rejected', async () => {
        const { paykit } = await setup();
        const result = await paykit.requirePayment(
            new Request('http://api.test/report', {
                headers: { accept: 'text/html', [CREDENTIAL_HEADER]: 'replayed' },
            }),
            'report',
        );
        expect('respond' in result).toBe(true);
        if ('respond' in result) expect(result.respond.status).toBe(402);
    });

    it('serves the worker response for the __mpp_worker param', async () => {
        const { paykit } = await setup();
        const result = await paykit.requirePayment(new Request('http://api.test/report?__mpp_worker=1'), 'report');
        expect('respond' in result).toBe(true);
    });
});

describe('requireFixed adapter-eligibility guard', () => {
    it('throws when the gate accepts a protocol no configured adapter serves', async () => {
        const config = await configure({
            accept: ['x402', 'mpp'],
            mpp: { challengeBindingSecret: 's3cret' },
        });
        // The gate accepts only x402, but the sole adapter speaks mpp.
        const paykit = await createPayKit({ adapters: [fakeAdapter(config)], config });
        const gate = Gate.create({ accept: ['x402'], amount: usd('0.10'), name: 'x402only' }, gateDefaults(config));
        await expect(paykit.requirePayment(new Request('http://api.test/x'), gate)).rejects.toThrow(ConfigurationError);
    });
});

describe('pay.express error and respond wiring', () => {
    async function startServer<P extends PricingDef>(pay: PayKit<P>, gate: Parameters<typeof pay.express>[0]) {
        const middleware = pay.express(gate);
        const server = createServer((req, res) => {
            void middleware(req, res, error => {
                if (error) {
                    res.writeHead(500, { 'content-type': 'text/plain' });
                    res.end(String(error));
                    return;
                }
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ ok: true, tx: pay.payment(req)?.transaction }));
            });
        });
        await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
        return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server };
    }

    it('forwards a thrown error to next() (500)', async () => {
        const config = await configure({ accept: ['x402', 'mpp'], mpp: { challengeBindingSecret: 's3cret' } });
        const pay = await createPayKit({ adapters: [fakeAdapter(config)], config });
        const gate = Gate.create({ accept: ['x402'], amount: usd('0.10'), name: 'x402only' }, gateDefaults(config));
        const { base, server } = await startServer(pay, gate);
        try {
            const response = await fetch(`${base}/x`);
            expect(response.status).toBe(500);
            expect(await response.text()).toContain('ConfigurationError');
        } finally {
            await new Promise<void>(resolve => server.close(() => resolve()));
        }
    });

    it('sends the adapter-owned HTML response verbatim for a browser', async () => {
        const { paykit } = await setup();
        const { base, server } = await startServer(paykit, 'report');
        try {
            const response = await fetch(`${base}/report`, { headers: { accept: 'text/html' } });
            expect(response.status).toBe(402);
            expect(response.headers.get('content-type')).toContain('text/html');
            expect(await response.text()).toContain('<!doctype html>');
        } finally {
            await new Promise<void>(resolve => server.close(() => resolve()));
        }
    });

    it('runs the fixed-gate handler with settlement headers on a valid credential', async () => {
        const { paykit } = await setup();
        const { base, server } = await startServer(paykit, 'report');
        try {
            const response = await fetch(`${base}/report`, { headers: { [CREDENTIAL_HEADER]: 'valid' } });
            expect(response.status).toBe(200);
            expect(response.headers.get('x-payment-settlement-signature')).toBe('TxSig');
            expect(((await response.json()) as { tx: string }).tx).toBe('TxSig');
        } finally {
            await new Promise<void>(resolve => server.close(() => resolve()));
        }
    });
});

describe('pay.fetch handler and settlement error paths', () => {
    it('settles (refunds) then re-throws when the handler throws', async () => {
        const { paykit } = await setup();
        const boom = new Error('handler exploded');
        const handler = paykit.fetch('report', () => {
            throw boom;
        });
        await expect(
            handler(new Request('http://t/report', { headers: { [CREDENTIAL_HEADER]: 'valid' } })),
        ).rejects.toBe(boom);
    });

    it('serves the response without settlement headers when withSettlement fails', async () => {
        const config = await configure({ mpp: { challengeBindingSecret: 's3cret' } });
        const warn = vi.fn();
        // An adapter whose settlement headers cannot be applied: withSettlement builds
        // a Headers() from them, so an invalid header name makes it throw.
        const adapter: ProtocolAdapter = {
            ...fakeAdapter(config),
            async verifyAndSettle(gate) {
                return {
                    gateName: gate.name,
                    payer: 'P',
                    protocol: 'mpp',
                    raw: 'valid',
                    scheme: 'charge',
                    settlementHeaders: { 'inv alid header': 'x' },
                    transaction: 'Tx',
                };
            },
        };
        const paykit = await createPayKit({
            adapters: [adapter],
            config,
            onSettleError: warn,
            pricing: { report: { amount: usd('0.10') } },
        });
        const handler = paykit.fetch('report', () => Response.json({ served: true }));
        const response = await handler(new Request('http://t/report', { headers: { [CREDENTIAL_HEADER]: 'valid' } }));
        expect(response.status).toBe(200);
        expect(((await response.json()) as { served: boolean }).served).toBe(true);
        expect(warn).toHaveBeenCalledOnce();
    });

    it('returns the 402 response for an unpaid fetch request', async () => {
        const { paykit } = await setup();
        const handler = paykit.fetch('report', () => Response.json({ ok: true }));
        const denied = await handler(new Request('http://t/report'));
        expect(denied.status).toBe(402);
    });

    it('returns the adapter-owned respond for a browser fetch request', async () => {
        const { paykit } = await setup();
        const handler = paykit.fetch('report', () => Response.json({ ok: true }));
        const result = await handler(new Request('http://t/report', { headers: { accept: 'text/html' } }));
        expect(result.status).toBe(402);
        expect(result.headers.get('content-type')).toContain('text/html');
    });
});

describe('pay.hono error and respond paths', () => {
    function context(request: Request): { req: { raw: Request }; res: Response } {
        return { req: { raw: request }, res: new Response('ok') };
    }

    it('returns the adapter-owned respond for a browser request', async () => {
        const { paykit } = await setup();
        const middleware = paykit.hono('report');
        const result = await middleware(
            context(new Request('http://t/report', { headers: { accept: 'text/html' } })),
            () => Promise.resolve(),
        );
        expect(result?.status).toBe(402);
        expect(result?.headers.get('content-type')).toContain('text/html');
    });

    it('runs next even when the handler throws, and reports a settle failure without masking', async () => {
        const config = await configure({ mpp: { challengeBindingSecret: 's3cret' } });
        const warn = vi.fn();
        const adapter: ProtocolAdapter = {
            ...fakeAdapter(config),
            async verifyAndSettle(gate) {
                return {
                    gateName: gate.name,
                    payer: 'P',
                    protocol: 'mpp',
                    raw: 'valid',
                    scheme: 'charge',
                    settlementHeaders: { 'inv alid header': 'x' },
                    transaction: 'Tx',
                };
            },
        };
        const paykit = await createPayKit({
            adapters: [adapter],
            config,
            onSettleError: warn,
            pricing: { report: { amount: usd('0.10') } },
        });
        const middleware = paykit.hono('report');
        const request = new Request('http://t/report', { headers: { [CREDENTIAL_HEADER]: 'valid' } });
        const c = context(request);
        const boom = new Error('downstream failed');
        await expect(
            middleware(c, () => {
                throw boom;
            }),
        ).rejects.toBe(boom);
        expect(warn).toHaveBeenCalledOnce();
    });
});
