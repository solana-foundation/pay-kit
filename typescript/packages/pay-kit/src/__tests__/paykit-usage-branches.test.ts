import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { InvalidProofError } from '../errors.js';
import type { Price } from '../price.js';

const CREDENTIAL_HEADER = 'x-fake-credential';

type SettleResult = { amount: string; settlementHeaders: Record<string, string>; transaction: string };

// Swapped per test. Mirrors the buffered-settle fixture: the mocked X402Upto
// delegates verify + settle to these holders so each test drives the outcome.
const verifyControl: { impl: (price: Price) => Promise<Record<string, unknown>> } = {
    impl: (price: Price) =>
        Promise.resolve({
            maxBaseUnits: price.baseUnits(),
            payer: 'Payer',
            payload: { payload: { channelId: 'chan-1' } },
            requirements: { amount: price.baseUnits().toString(), asset: 'mint', scheme: 'upto' },
        }),
};
const settleControl: { impl: () => Promise<SettleResult> } = {
    impl: () => Promise.resolve({ amount: '0', settlementHeaders: {}, transaction: 'Tx' }),
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
            return Promise.resolve({ 'payment-required': 'challenge' });
        }
        verifyOpen(_request: Request, price: Price): Promise<Record<string, unknown>> {
            return verifyControl.impl(price);
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
const { Gate } = await import('../gate.js');
const { configure } = await import('../config.js');
const { gateDefaults } = await import('../pricing.js');

async function usagePaykit() {
    return createPayKit({
        accept: ['x402'],
        mpp: { challengeBindingSecret: 's' },
        network: 'solana_localnet',
        pricing: { summarize: usage(usd('1.00')) },
    });
}

describe('requireUsage credential branches', () => {
    afterEach(() => {
        verifyControl.impl = (price: Price) =>
            Promise.resolve({
                maxBaseUnits: price.baseUnits(),
                payer: 'Payer',
                payload: { payload: { channelId: 'chan-1' } },
                requirements: { amount: price.baseUnits().toString(), asset: 'mint', scheme: 'upto' },
            });
        settleControl.impl = () => Promise.resolve({ amount: '0', settlementHeaders: {}, transaction: 'Tx' });
    });

    it('challenges an unpaid usage request (no credential)', async () => {
        const pay = await usagePaykit();
        const result = await pay.requirePayment(new Request('http://t/summarize'), 'summarize');
        expect('challenge' in result).toBe(true);
        if ('challenge' in result) {
            expect(result.status).toBe(402);
            expect(result.challenge.accepts[0]?.protocol).toBe('x402');
            expect(result.challenge.accepts[0]?.scheme).toBe('upto');
        }
    });

    it('renders a 402 with the canonical code when verifyOpen rejects an invalid proof', async () => {
        verifyControl.impl = () => Promise.reject(new InvalidProofError('signature_consumed', 'already used'));
        const pay = await usagePaykit();
        const result = await pay.requirePayment(
            new Request('http://t/summarize', { headers: { [CREDENTIAL_HEADER]: 'present' } }),
            'summarize',
        );
        expect('challenge' in result).toBe(true);
        if ('challenge' in result) {
            expect(result.status).toBe(402);
            const body = (await result.response.json()) as { code: string; detail: string };
            expect(body.code).toBe('signature_consumed');
            expect(body.detail).toBe('already used');
        }
    });

    it('propagates a non-InvalidProof error from verifyOpen', async () => {
        const boom = new Error('rpc down');
        verifyControl.impl = () => Promise.reject(boom);
        const pay = await usagePaykit();
        await expect(
            pay.requirePayment(
                new Request('http://t/summarize', { headers: { [CREDENTIAL_HEADER]: 'present' } }),
                'summarize',
            ),
        ).rejects.toBe(boom);
    });

    it('grants a verified usage request and exposes the Charge meter', async () => {
        const pay = await usagePaykit();
        const request = new Request('http://t/summarize', { headers: { [CREDENTIAL_HEADER]: 'present' } });
        const result = await pay.requirePayment(request, 'summarize');
        expect('payment' in result).toBe(true);
        if ('payment' in result) {
            expect(result.status).toBe(200);
            expect(result.charge).toBeDefined();
            expect(result.payment.scheme).toBe('upto');
            expect(pay.charge(request)).toBe(result.charge);
            // Drive settle so the in-flight channel is released for later tests.
            await result.settle();
            expect(pay.payment(request)?.transaction).toBe('Tx');
        }
    });

    it('rejects a concurrent replay of the same channel as in-flight', async () => {
        const pay = await usagePaykit();
        // Hold settle open so the first request keeps the channel in flight.
        let releaseSettle: () => void = () => {};
        settleControl.impl = () =>
            new Promise<SettleResult>(resolve => {
                releaseSettle = () => resolve({ amount: '0', settlementHeaders: {}, transaction: 'Tx' });
            });

        const first = await pay.requirePayment(
            new Request('http://t/summarize', { headers: { [CREDENTIAL_HEADER]: 'present' } }),
            'summarize',
        );
        expect('payment' in first).toBe(true);
        if (!('payment' in first)) return;
        const settlePromise = first.settle(); // acquires; stays pending until released

        const second = await pay.requirePayment(
            new Request('http://t/summarize', { headers: { [CREDENTIAL_HEADER]: 'present' } }),
            'summarize',
        );
        expect('challenge' in second).toBe(true);
        if ('challenge' in second) {
            const body = (await second.response.json()) as { code: string; detail: string };
            expect(body.code).toBe('upto_channel_in_flight');
            expect(body.detail).toBe('channel already being served');
        }

        releaseSettle();
        await settlePromise;
    });

    it('does not track an in-flight channel when the payload carries no channelId', async () => {
        verifyControl.impl = (price: Price) =>
            Promise.resolve({
                maxBaseUnits: price.baseUnits(),
                payer: 'Payer',
                payload: { payload: {} }, // no channelId
                requirements: { amount: price.baseUnits().toString(), asset: 'mint', scheme: 'upto' },
            });
        const pay = await usagePaykit();
        const result = await pay.requirePayment(
            new Request('http://t/summarize', { headers: { [CREDENTIAL_HEADER]: 'present' } }),
            'summarize',
        );
        expect('payment' in result).toBe(true);
        if ('payment' in result) await result.settle();
    });
});

describe('requireUsage without an x402 upto engine', () => {
    it('throws when a usage gate is dispatched but x402 is not accepted', async () => {
        const config = await configure({ accept: ['mpp'], mpp: { challengeBindingSecret: 's' } });
        // Build the usage Gate directly (bypassing pricing validation) so it reaches
        // requireUsage with no `upto` engine configured (config has no x402).
        const gate = Gate.create({ amount: usd('1.00'), kind: 'usage', name: 'u' }, gateDefaults(config));
        // A mpp adapter so createPayKit succeeds; the usage gate never uses it.
        const pay = await createPayKit({
            adapters: [
                {
                    acceptsEntry: g =>
                        Promise.resolve({
                            amount: g.amount.baseUnits().toString(),
                            network: 'solana:test',
                            payTo: g.payTo,
                            protocol: 'mpp',
                            scheme: 'charge',
                        }),
                    challengeHeaders: () => Promise.resolve({}),
                    detect: () => false,
                    protocol: 'mpp',
                    scheme: 'charge',
                    verifyAndSettle: () => Promise.reject(new InvalidProofError('nope')),
                },
            ],
            config,
        });
        await expect(pay.requirePayment(new Request('http://t/u'), gate)).rejects.toThrow(/requires x402/);
    });
});

describe('express usage settle-after-response replay edge cases', () => {
    let server: Server;

    afterEach(async () => {
        await new Promise<void>(resolve => server.close(() => resolve()));
        settleControl.impl = () => Promise.resolve({ amount: '0', settlementHeaders: {}, transaction: 'Tx' });
    });

    it('buffers writeHead/write/end before settle and replays after (streamed handler)', async () => {
        settleControl.impl = () =>
            Promise.resolve({ amount: '0', settlementHeaders: { 'x-payment-response': 'SETTLED' }, transaction: 'Tx' });
        const pay = await usagePaykit();
        const middleware = pay.express('summarize');
        server = createServer((req, res) => {
            void middleware(req, res, () => {
                // Exercise writeHead + multiple write chunks + end (all buffered).
                res.writeHead(200, { 'content-type': 'text/plain' });
                res.write('chunk-a');
                res.write('chunk-b');
                res.end('-done');
            });
        });
        await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
        const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

        const response = await fetch(`${base}/summarize`, { headers: { [CREDENTIAL_HEADER]: 'present' } });
        expect(response.status).toBe(200);
        expect(response.headers.get('x-payment-response')).toBe('SETTLED');
        expect(await response.text()).toBe('chunk-achunk-b-done');
    });

    it('finalizes the channel and forwards the error when the handler throws synchronously', async () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        settleControl.impl = () => Promise.resolve({ amount: '0', settlementHeaders: {}, transaction: 'Tx' });
        const pay = await usagePaykit();
        const middleware = pay.express('summarize');
        const boom = new Error('handler exploded');
        server = createServer((req, res) => {
            void middleware(req, res, error => {
                if (error) {
                    res.writeHead(500, { 'content-type': 'text/plain' });
                    res.end(error === boom ? 'forwarded' : 'other');
                    return;
                }
                throw boom;
            });
        });
        await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
        const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

        const response = await fetch(`${base}/summarize`, { headers: { [CREDENTIAL_HEADER]: 'present' } });
        expect(response.status).toBe(500);
        expect(await response.text()).toBe('forwarded');
        warn.mockRestore();
    });

    it('reports a settle failure on a synchronous handler throw without masking the error', async () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        settleControl.impl = () => Promise.reject(new Error('settle rpc down'));
        const pay = await usagePaykit();
        const middleware = pay.express('summarize');
        const boom = new Error('handler exploded');
        server = createServer((req, res) => {
            void middleware(req, res, error => {
                if (error) {
                    res.writeHead(500, { 'content-type': 'text/plain' });
                    res.end(error === boom ? 'forwarded' : 'other');
                    return;
                }
                throw boom;
            });
        });
        await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
        const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

        const response = await fetch(`${base}/summarize`, { headers: { [CREDENTIAL_HEADER]: 'present' } });
        expect(response.status).toBe(500);
        expect(await response.text()).toBe('forwarded');
        // The channel finalize (settle) rejected on the sync-throw path; warned, not masked.
        expect(warn).toHaveBeenCalled();
        warn.mockRestore();
    });
});
