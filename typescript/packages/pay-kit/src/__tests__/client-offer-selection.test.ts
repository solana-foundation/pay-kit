import { generateKeyPairSigner, type KeyPairSigner } from '@solana/kit';
import { Challenge, resolveStablecoinMint, SUBSCRIPTIONS_PROGRAM, TOKEN_PROGRAM } from '@solana/mpp/client';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// The client captures fetch when imported, before beforeEach can run.
const { mockFetch, createCredential, createSubscriptionCredential, buildX402, chargeOptions } = vi.hoisted(() => {
    const mockFetch = vi.fn<typeof fetch>();
    globalThis.fetch = mockFetch;
    const createCredential = vi.fn(({ challenge }: { challenge: { id: string } }) =>
        Promise.resolve(`Payment ${challenge.id}`),
    );
    const createSubscriptionCredential = vi.fn(({ challenge }: { challenge: { id: string } }) =>
        Promise.resolve(`Payment ${challenge.id}`),
    );
    const buildX402 = vi.fn((required: { accepts: { amount: string }[] }) =>
        Promise.resolve({ amount: required.accepts[0]?.amount }),
    );
    const chargeOptions = vi.fn();
    return { buildX402, chargeOptions, createCredential, createSubscriptionCredential, mockFetch };
});

vi.mock('@solana/mpp/client', async importOriginal => {
    const actual = await importOriginal<typeof import('@solana/mpp/client')>();
    return {
        ...actual,
        solana: {
            ...actual.solana,
            charge: (options: unknown) => {
                chargeOptions(options);
                return { createCredential };
            },
            subscription: () => ({ createCredential: createSubscriptionCredential }),
        },
    };
});

vi.mock('@x402/core/client', async importOriginal => {
    const actual = await importOriginal<typeof import('@x402/core/client')>();
    return {
        ...actual,
        x402HTTPClient: class {
            getPaymentRequiredResponse(getHeader: (name: string) => string | null) {
                return JSON.parse(atob(getHeader('payment-required')!));
            }
            createPaymentPayload = buildX402;
            encodePaymentSignatureHeader() {
                return { 'payment-signature': 'x402 credential' };
            }
        },
    };
});

import { ClientPermissions, createPayKitClient, PermissionDeniedError } from '../client/index.js';
import { ConfigurationError } from '../errors.js';

const RPC_URL = 'http://127.0.0.1:8899';
const UNKNOWN_MINT = '11111111111111111111111111111111';

function charge(id: string, amount: unknown = '500000', network: unknown = 'mainnet', currency = 'USDC'): string {
    return Challenge.serialize({
        id,
        intent: 'charge',
        method: 'solana',
        realm: 'test',
        request: { amount, currency, methodDetails: { decimals: 6, network }, recipient: UNKNOWN_MINT },
    });
}

function subscription(id: string, amount: string, periodUnit = 'day', periodCount = '1'): string {
    const mint = resolveStablecoinMint('USDC', 'mainnet');
    if (!mint) throw new Error('missing mainnet USDC mint');
    return Challenge.serialize({
        id,
        intent: 'subscription',
        method: 'solana',
        realm: 'test',
        request: {
            amount,
            currency: mint,
            recipient: UNKNOWN_MINT,
            periodCount,
            periodUnit,
            methodDetails: {
                decimals: 6,
                mint,
                network: 'mainnet',
                planAddress: UNKNOWN_MINT,
                puller: UNKNOWN_MINT,
                subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
                tokenProgram: TOKEN_PROGRAM,
            },
        },
    });
}

function incompleteSubscription(): string {
    return Challenge.serialize({
        id: 'missing-fields',
        intent: 'subscription',
        method: 'solana',
        realm: 'test',
        request: { amount: '1', currency: 'USDC', methodDetails: { network: 'mainnet' } },
    });
}

function session(): string {
    return Challenge.serialize({
        id: 'session',
        intent: 'session',
        method: 'solana',
        realm: 'test',
        request: {},
    });
}

function probe(challenges: string[], withX402 = false): Response {
    const headers = new Headers();
    for (const challenge of challenges) headers.append('www-authenticate', challenge);
    if (withX402) {
        headers.set(
            'payment-required',
            btoa(
                JSON.stringify({
                    accepts: [
                        {
                            amount: '400000',
                            asset: resolveStablecoinMint('USDC', 'mainnet'),
                            extra: {},
                            maxTimeoutSeconds: 60,
                            network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
                            payTo: UNKNOWN_MINT,
                            scheme: 'exact',
                        },
                    ],
                    x402Version: 2,
                }),
            ),
        );
    }
    return new Response(null, { headers, status: 402 });
}

function exact(amount: unknown = '500000', asset: unknown = resolveStablecoinMint('USDC', 'mainnet')) {
    return {
        amount,
        asset,
        extra: {},
        maxTimeoutSeconds: 60,
        network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
        payTo: UNKNOWN_MINT,
        scheme: 'exact',
    };
}

function x402Probe(accepts: ReturnType<typeof exact>[]): Response {
    return new Response(null, {
        headers: { 'payment-required': btoa(JSON.stringify({ accepts, x402Version: 2 })) },
        status: 402,
    });
}

describe('permissioned offer selection', () => {
    let signer: KeyPairSigner;

    beforeEach(async () => {
        signer = await generateKeyPairSigner();
        mockFetch.mockReset();
        createCredential.mockClear();
        createSubscriptionCredential.mockClear();
        buildX402.mockClear();
        chargeOptions.mockClear();
    });

    it.each([
        ['over-cap', charge('denied', '2000000')],
        ['disallowed network', charge('denied', '1000', 'devnet')],
        ['unsupported network', charge('denied', '1000', 'testnet')],
        ['invalid amount', charge('denied', 'invalid')],
        ['invalid schema', charge('denied', 1000)],
        ['unknown asset', charge('denied', '1', 'mainnet', UNKNOWN_MINT)],
        ['session', session()],
    ])('skips a %s offer and signs only the next permitted charge', async (_name, denied) => {
        mockFetch.mockResolvedValueOnce(probe([denied, charge('permitted')])).mockResolvedValueOnce(new Response('ok'));
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });

        const response = await client.fetch('https://api.test/paid');

        expect(response.status).toBe(200);
        expect(createCredential).toHaveBeenCalledTimes(1);
        expect(createCredential.mock.calls[0]?.[0].challenge.id).toBe('permitted');
        expect(chargeOptions.mock.calls[0]?.[0].maxAmount).toBe(1_000_000n);
        expect(mockFetch).toHaveBeenCalledTimes(2);
        expect((mockFetch.mock.calls[1]![0] as Request).headers.get('authorization')).toBe('Payment permitted');
    });

    it('preserves server order among permitted charges', async () => {
        mockFetch
            .mockResolvedValueOnce(probe([charge('first', '800000'), charge('cheaper', '1')]))
            .mockResolvedValueOnce(new Response('ok'));
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });
        await client.fetch('https://api.test/paid');
        expect(createCredential.mock.calls[0]?.[0].challenge.id).toBe('first');
    });

    it('continues to permitted subscription offers after denied charges and subscriptions', async () => {
        mockFetch
            .mockResolvedValueOnce(
                probe([
                    charge('over', '2000000'),
                    subscription('denied', '2000000'),
                    subscription('permitted', '500000'),
                ]),
            )
            .mockResolvedValueOnce(new Response('ok'));
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });
        await client.fetch('https://api.test/paid');
        expect(createCredential).not.toHaveBeenCalled();
        expect(createSubscriptionCredential).toHaveBeenCalledTimes(1);
        expect(createSubscriptionCredential.mock.calls[0]?.[0].challenge.id).toBe('permitted');
    });

    it.each([
        ['unsupported period unit', subscription('month', '500000', 'month')],
        ['missing required fields', incompleteSubscription()],
        ['zero period count', subscription('zero', '500000', 'day', '0')],
        ['invalid period count', subscription('bad', '500000', 'day', 'bad')],
        ['too many days', subscription('366days', '500000', 'day', '366')],
        ['too many weeks', subscription('53weeks', '500000', 'week', '53')],
    ])('rejects a subscription with %s before building the next valid offer', async (_name, invalid) => {
        mockFetch
            .mockResolvedValueOnce(probe([invalid, subscription('permitted', '500000')]))
            .mockResolvedValueOnce(new Response('ok'));
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });
        expect((await client.fetch('https://api.test/paid')).status).toBe(200);
        expect(createSubscriptionCredential).toHaveBeenCalledTimes(1);
        expect(createSubscriptionCredential.mock.calls[0]?.[0].challenge.id).toBe('permitted');
        expect(createCredential).not.toHaveBeenCalled();
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it.each([
        ['unsupported period unit', subscription('month', '500000', 'month')],
        ['missing required fields', incompleteSubscription()],
        ['zero period count', subscription('zero', '500000', 'day', '0')],
        ['invalid period count', subscription('bad', '500000', 'day', 'bad')],
        ['too many days', subscription('366days', '500000', 'day', '366')],
        ['too many weeks', subscription('53weeks', '500000', 'week', '53')],
    ])('falls back to x402 after a subscription with %s without signing it', async (_name, invalid) => {
        mockFetch.mockResolvedValueOnce(probe([invalid], true)).mockResolvedValueOnce(new Response('ok'));
        const client = await createPayKitClient({ rpcUrl: RPC_URL, signer });
        expect((await client.fetch('https://api.test/paid')).status).toBe(200);
        expect(createSubscriptionCredential).not.toHaveBeenCalled();
        expect(buildX402).toHaveBeenCalledTimes(1);
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it.each([
        ['maximum day period', subscription('365days', '500000', 'day', '365')],
        ['maximum week period', subscription('52weeks', '500000', 'week', '52')],
    ])('keeps the %s subscription valid', async (_name, valid) => {
        mockFetch.mockResolvedValueOnce(probe([valid])).mockResolvedValueOnce(new Response('ok'));
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });
        expect((await client.fetch('https://api.test/paid')).status).toBe(200);
        expect(createSubscriptionCredential).toHaveBeenCalledTimes(1);
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('denies all malformed subscriptions without constructing a credential', async () => {
        mockFetch.mockResolvedValue(probe([subscription('month', '500000', 'month'), incompleteSubscription()]));
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });
        const error = await client.fetch('https://api.test/paid').catch((e: unknown) => e);
        expect(error).toBeInstanceOf(PermissionDeniedError);
        expect((error as PermissionDeniedError).rejections.map(r => r.code)).toEqual([
            'invalid_challenge_terms',
            'invalid_challenge_terms',
        ]);
        expect(createSubscriptionCredential).not.toHaveBeenCalled();
        expect(createCredential).not.toHaveBeenCalled();
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it.each([
        ['null asset', exact('800000', null)],
        ['integer asset', exact('800000', 1)],
        ['list asset', exact('800000', [])],
        ['object asset', exact('800000', {})],
        ['boolean asset', exact('800000', true)],
        ['numeric amount', exact(1)],
        ['list amount', exact(['1'])],
    ])('filters an x402 %s before selecting a valid offer in either order', async (_name, invalid) => {
        const valid = exact();
        for (const offers of [
            [invalid, valid],
            [valid, invalid],
        ]) {
            mockFetch.mockReset();
            buildX402.mockClear();
            mockFetch.mockResolvedValueOnce(x402Probe(offers)).mockResolvedValueOnce(new Response('ok'));
            const client = await createPayKitClient({ accept: ['x402'], rpcUrl: RPC_URL, signer });
            expect((await client.fetch('https://api.test/paid')).status).toBe(200);
            expect(buildX402).toHaveBeenCalledTimes(1);
            expect(buildX402.mock.calls[0]?.[0].accepts).toEqual([valid]);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        }
    });

    it.each([
        ['assets', [null, 1, [], {}, true].map(asset => exact('1', asset))],
        ['amounts', [exact(1), exact(['1'])]],
    ])('reports all malformed x402 %s without building a credential', async (_name, offers) => {
        mockFetch.mockResolvedValue(x402Probe(offers));
        const client = await createPayKitClient({ accept: ['x402'], rpcUrl: RPC_URL, signer });
        const error = await client.fetch('https://api.test/paid').catch((e: unknown) => e);
        expect(error).toBeInstanceOf(PermissionDeniedError);
        expect((error as PermissionDeniedError).rejections.map(r => r.code)).toEqual(
            offers.map(() => 'invalid_challenge_terms'),
        );
        expect(buildX402).not.toHaveBeenCalled();
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it.each([
        ['Bearer', ['Bearer realm="api"']],
        ['quoted Payment', ['Basic realm="a, Payment api"']],
        ['unsupported MPP network', [charge('testnet', '1000', 'testnet')]],
        ['invalid MPP schema', [charge('invalid', 1)]],
        ['session-only', [session()]],
    ])('falls back to x402 with %s authentication', async (_name, challenges) => {
        mockFetch.mockResolvedValueOnce(probe(challenges, true)).mockResolvedValueOnce(new Response('ok'));
        const client = await createPayKitClient({ rpcUrl: RPC_URL, signer });
        expect((await client.fetch('https://api.test/paid')).status).toBe(200);
        expect(createCredential).not.toHaveBeenCalled();
        expect(buildX402).toHaveBeenCalledTimes(1);
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('parses Payment challenges with quoted scheme text among other authentication schemes', async () => {
        const valid = charge('permitted').replace('realm="test"', 'realm="a, Payment api\\\" quoted"');
        mockFetch
            .mockResolvedValueOnce(probe(['Basic realm="Payment api"', valid, 'Bearer realm="api"']))
            .mockResolvedValueOnce(new Response('ok'));
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });
        expect((await client.fetch('https://api.test/paid')).status).toBe(200);
        expect(createCredential.mock.calls[0]?.[0].challenge.id).toBe('permitted');
    });

    it('aggregates denials when no offer is permitted without building a credential', async () => {
        mockFetch.mockResolvedValue(probe([charge('over', '2000000'), charge('devnet', '1000', 'devnet')]));
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });
        const error = await client.fetch('https://api.test/paid').catch((e: unknown) => e);
        expect(error).toBeInstanceOf(PermissionDeniedError);
        expect((error as PermissionDeniedError).rejections.map(r => r.code)).toEqual([
            'amount_exceeds_limit',
            'network_not_allowed',
        ]);
        expect(createCredential).not.toHaveBeenCalled();
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('keeps malformed Payment headers strict before fallback', async () => {
        mockFetch.mockResolvedValue(probe(['Payment id="invalid"'], true));
        const client = await createPayKitClient({ rpcUrl: RPC_URL, signer });
        await expect(client.fetch('https://api.test/paid')).rejects.toThrow();
        expect(buildX402).not.toHaveBeenCalled();
    });

    it('keeps the session-only configuration error', async () => {
        mockFetch.mockResolvedValue(probe([session()]));
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });
        await expect(client.fetch('https://api.test/paid')).rejects.toBeInstanceOf(ConfigurationError);
    });

    it('propagates errors after sending a paid request without choosing another offer', async () => {
        const error = new PermissionDeniedError([
            { code: 'invalid_challenge_terms', message: 'retry transport failed' },
        ]);
        mockFetch.mockResolvedValueOnce(probe([charge('first'), charge('second')], true)).mockRejectedValueOnce(error);
        const client = await createPayKitClient({ rpcUrl: RPC_URL, signer });
        await expect(client.fetch('https://api.test/paid')).rejects.toBe(error);
        expect(createCredential).toHaveBeenCalledTimes(1);
        expect(buildX402).not.toHaveBeenCalled();
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('allows the next charge when the policy explicitly permits any asset', async () => {
        mockFetch
            .mockResolvedValueOnce(probe([charge('invalid', 'bad'), charge('custom', '1', 'mainnet', UNKNOWN_MINT)]))
            .mockResolvedValueOnce(new Response('ok'));
        const client = await createPayKitClient({
            accept: ['mpp'],
            permissions: ClientPermissions.builder().allowAnyAsset().build(),
            rpcUrl: RPC_URL,
            signer,
        });
        expect((await client.fetch('https://api.test/paid')).status).toBe(200);
        expect(createCredential.mock.calls[0]?.[0].challenge.id).toBe('custom');
    });
});
