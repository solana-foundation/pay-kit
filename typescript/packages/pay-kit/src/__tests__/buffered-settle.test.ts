import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { Price } from '../price.js';

const CREDENTIAL_HEADER = 'x-fake-credential';

type SettleResult = { amount: string; settlementHeaders: Record<string, string>; transaction: string };

// The settle behavior is swapped per test through this holder, captured by the
// mocked `X402Upto.settle` below.
const settleControl: { impl: () => Promise<SettleResult> } = {
    impl: () => Promise.reject(new Error('settle not configured')),
};

vi.mock('../adapters/x402-upto.js', async () => {
    const actual = await vi.importActual<typeof import('../adapters/x402-upto.js')>('../adapters/x402-upto.js');
    class FakeX402Upto {
        detect(request: Request): boolean {
            return request.headers.has(CREDENTIAL_HEADER);
        }
        accepts(price: Price): readonly Record<string, unknown>[] {
            return [
                {
                    amount: price.baseUnits().toString(),
                    asset: 'mint',
                    maxTimeoutSeconds: 300,
                    network: 'solana:test',
                    payTo: 'PayTo',
                    scheme: 'upto',
                },
            ];
        }
        challengeHeaders(): Promise<Readonly<Record<string, string>>> {
            return Promise.resolve({});
        }
        verifyOpen(_request: Request, price: Price): Promise<Record<string, unknown>> {
            return Promise.resolve({
                maxBaseUnits: price.baseUnits(),
                payer: 'Payer',
                payload: { payload: { channelId: 'chan-1' } },
                requirements: { amount: price.baseUnits().toString(), asset: 'mint', scheme: 'upto' },
            });
        }
        settle(): Promise<SettleResult> {
            return settleControl.impl();
        }
    }
    return { ...actual, X402Upto: FakeX402Upto };
});

const { createPayKit } = await import('../paykit.js');
const { usage } = await import('../pricing.js');
const { usd } = await import('../price.js');

async function startServer(): Promise<{ base: string; server: Server }> {
    const pay = await createPayKit({
        accept: ['x402'],
        mpp: { challengeBindingSecret: 's' },
        network: 'solana_localnet',
        pricing: { summarize: usage(usd('1.00')) },
    });
    const middleware = pay.express('summarize');
    const server = createServer((req, res) => {
        void middleware(req, res, error => {
            if (error) {
                res.writeHead(500);
                res.end(String(error));
                return;
            }
            const meter = pay.charge(req);
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ hasMeter: meter !== undefined, ok: true }));
        });
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server };
}

describe('express usage gate settle-after-response', () => {
    let server: Server;
    let base: string;

    beforeEach(async () => {
        ({ base, server } = await startServer());
    });

    afterEach(async () => {
        await new Promise<void>(resolve => server.close(() => resolve()));
        vi.restoreAllMocks();
    });

    it('serves the handler body with settlement headers when settle succeeds', async () => {
        settleControl.impl = () =>
            Promise.resolve({
                amount: '0',
                settlementHeaders: { 'x-payment-response': 'SETTLED' },
                transaction: 'Tx',
            });
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

        const response = await fetch(`${base}/summarize`, { headers: { [CREDENTIAL_HEADER]: 'present' } });

        expect(response.status).toBe(200);
        expect(response.headers.get('x-payment-response')).toBe('SETTLED');
        const body = (await response.json()) as { hasMeter: boolean; ok: boolean };
        expect(body).toEqual({ hasMeter: true, ok: true });
        expect(warn).not.toHaveBeenCalled();
    });

    it('fails open: serves the handler body without settlement headers when settle fails', async () => {
        settleControl.impl = () => Promise.reject(new Error('rpc down'));
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

        const response = await fetch(`${base}/summarize`, { headers: { [CREDENTIAL_HEADER]: 'present' } });

        expect(response.status).toBe(200);
        expect(response.headers.get('x-payment-response')).toBeNull();
        const body = (await response.json()) as { hasMeter: boolean; ok: boolean };
        expect(body).toEqual({ hasMeter: true, ok: true });
        expect(warn).toHaveBeenCalled();
    });

    it('exposes the Charge meter to the handler on the usage path', async () => {
        settleControl.impl = () => Promise.resolve({ amount: '0', settlementHeaders: {}, transaction: 'Tx' });
        vi.spyOn(console, 'warn').mockImplementation(() => {});

        const response = await fetch(`${base}/summarize`, { headers: { [CREDENTIAL_HEADER]: 'present' } });

        const body = (await response.json()) as { hasMeter: boolean };
        expect(body.hasMeter).toBe(true);
    });

    it('challenges an unpaid request with a 402', async () => {
        const response = await fetch(`${base}/summarize`);
        expect(response.status).toBe(402);
    });
});
