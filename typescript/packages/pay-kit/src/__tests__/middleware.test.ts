import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { ProtocolAdapter } from '../adapter.js';
import { configure } from '../config.js';
import { InvalidProofError } from '../errors.js';
import { paid, payment, requirePayment, toWebRequest } from '../express.js';
import { withPayment } from '../handler.js';
import { requirePayment as honoRequirePayment, type WebContext } from '../hono.js';
import type { Payment } from '../payment.js';
import { createPayKit, type PayKit } from '../paykit.js';
import { usd } from '../price.js';
import { createPricing } from '../pricing.js';

const CREDENTIAL_HEADER = 'x-fake-credential';

const fakeAdapter: ProtocolAdapter = {
    acceptsEntry(gate) {
        return Promise.resolve({
            amount: gate.amount.baseUnits().toString(),
            network: 'solana:test',
            payTo: gate.payTo,
            protocol: 'mpp',
            scheme: 'charge',
        });
    },
    challengeHeaders() {
        return Promise.resolve({ 'www-authenticate': 'Payment realm="test"' });
    },
    detect(request) {
        return request.headers.has(CREDENTIAL_HEADER);
    },
    protocol: 'mpp',
    scheme: 'charge',
    verifyAndSettle(gate, request): Promise<Payment> {
        if (request.headers.get(CREDENTIAL_HEADER) !== 'valid') {
            return Promise.reject(new InvalidProofError('signature_consumed'));
        }
        return Promise.resolve({
            gateName: gate.name,
            payer: 'PayerPubkey',
            protocol: 'mpp',
            raw: 'valid',
            scheme: 'charge',
            settlementHeaders: { 'x-payment-settlement-signature': 'TxSig' },
            transaction: 'TxSig',
        });
    },
};

async function setup(): Promise<PayKit> {
    const config = await configure({ mpp: { challengeBindingSecret: 's3cret' } });
    const pricing = createPricing(config, { report: { amount: usd('0.10') } });
    return createPayKit(config, { adapters: [fakeAdapter], pricing });
}

describe('express middleware', () => {
    let server: Server;
    let base: string;

    beforeAll(async () => {
        const paykit = await setup();
        const middleware = requirePayment(paykit, 'report');
        server = createServer((req, res) => {
            void middleware(req, res, error => {
                if (error) {
                    res.writeHead(500);
                    res.end(String(error));
                    return;
                }
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(
                    JSON.stringify({
                        gatePaid: paid(req, 'report'),
                        otherPaid: paid(req, 'other'),
                        tx: payment(req)?.transaction,
                    }),
                );
            });
        });
        await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    });

    afterAll(() => new Promise<void>(resolve => server.close(() => resolve())));

    it('writes the 402 challenge when unpaid', async () => {
        const response = await fetch(`${base}/report`);
        expect(response.status).toBe(402);
        expect(response.headers.get('www-authenticate')).toBe('Payment realm="test"');
        const body = (await response.json()) as { accepts: unknown[] };
        expect(body.accepts).toHaveLength(1);
    });

    it('runs the handler with payment access and settlement headers on success', async () => {
        const response = await fetch(`${base}/report`, { headers: { [CREDENTIAL_HEADER]: 'valid' } });
        expect(response.status).toBe(200);
        expect(response.headers.get('x-payment-settlement-signature')).toBe('TxSig');
        const body = (await response.json()) as { gatePaid: boolean; otherPaid: boolean; tx: string };
        expect(body).toEqual({ gatePaid: true, otherPaid: false, tx: 'TxSig' });
    });

    it('renders 402 with the canonical code on invalid proof', async () => {
        const response = await fetch(`${base}/report`, { headers: { [CREDENTIAL_HEADER]: 'replayed' } });
        expect(response.status).toBe(402);
        const body = (await response.json()) as { code: string };
        expect(body.code).toBe('signature_consumed');
    });

    it('converts node requests preserving method, path, and headers', () => {
        const request = toWebRequest({
            headers: { authorization: 'Payment abc', host: 'api.test' },
            method: 'POST',
            originalUrl: '/report?tier=pro',
        } as never);
        expect(request.method).toBe('POST');
        expect(new URL(request.url).pathname).toBe('/report');
        expect(new URL(request.url).searchParams.get('tier')).toBe('pro');
        expect(request.headers.get('authorization')).toBe('Payment abc');
    });
});

describe('hono middleware', () => {
    function context(request: Request): WebContext & { res: Response } {
        return { req: { raw: request }, res: new Response('ok') };
    }

    it('returns the 402 challenge when unpaid', async () => {
        const paykit = await setup();
        const middleware = honoRequirePayment(paykit, 'report');
        const response = await middleware(context(new Request('http://t/report')), () => Promise.resolve());
        expect(response?.status).toBe(402);
        expect(response?.headers.get('www-authenticate')).toBe('Payment realm="test"');
    });

    it('continues the chain and merges settlement headers on success', async () => {
        const paykit = await setup();
        const middleware = honoRequirePayment(paykit, 'report');
        const request = new Request('http://t/report', { headers: { [CREDENTIAL_HEADER]: 'valid' } });
        const c = context(request);
        let ran = false;
        const result = await middleware(c, () => {
            ran = true;
            return Promise.resolve();
        });
        expect(result).toBeUndefined();
        expect(ran).toBe(true);
        expect(c.res.headers.get('x-payment-settlement-signature')).toBe('TxSig');
        expect(paykit.payment(request)?.transaction).toBe('TxSig');
    });
});

describe('withPayment', () => {
    it('gates a fetch handler', async () => {
        const paykit = await setup();
        const handler = withPayment(paykit, 'report', (_request, settled) =>
            Response.json({ tx: settled.transaction }),
        );

        const denied = await handler(new Request('http://t/report'));
        expect(denied.status).toBe(402);

        const granted = await handler(new Request('http://t/report', { headers: { [CREDENTIAL_HEADER]: 'valid' } }));
        expect(granted.status).toBe(200);
        expect(granted.headers.get('x-payment-settlement-signature')).toBe('TxSig');
        expect(((await granted.json()) as { tx: string }).tx).toBe('TxSig');
    });
});
