import { generateKeyPairSigner, type KeyPairSigner } from '@solana/kit';
import { Challenge, resolveStablecoinMint } from '@solana/mpp/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// `createPayKitClient` binds `globalThis.fetch` into a module-level `nativeFetch`
// when its module first loads, so the stub must be installed before that import
// is evaluated — `vi.hoisted` runs ahead of the static imports below.
const { mockFetch } = vi.hoisted(() => {
    const mockFetch = vi.fn<typeof fetch>();
    globalThis.fetch = mockFetch;
    return { mockFetch };
});

import { createPayKitClient, PermissionDeniedError } from '../client/index.js';
import { ConfigurationError } from '../errors.js';

const RPC_URL = 'http://127.0.0.1:8899';

function response(status: number, headers: Record<string, string> = {}): Response {
    return new Response(null, { headers, status });
}

describe('createPayKitClient', () => {
    let signer: KeyPairSigner;

    beforeEach(async () => {
        signer = await generateKeyPairSigner();
        mockFetch.mockReset();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('passes a non-402 response through untouched without attempting payment', async () => {
        const ok = response(200);
        mockFetch.mockResolvedValue(ok);

        const client = await createPayKitClient({ accept: ['x402', 'mpp'], rpcUrl: RPC_URL, signer });
        const result = await client.fetch('http://api.test/joke');

        expect(result).toBe(ok);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('rejects a session intent with ConfigurationError before any signing', async () => {
        mockFetch.mockResolvedValue(response(402, { 'www-authenticate': 'Payment intent="session"' }));

        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer });

        await expect(client.fetch('http://api.test/stream')).rejects.toBeInstanceOf(ConfigurationError);
        await expect(client.fetch('http://api.test/stream')).rejects.toThrow(/session client/i);
        expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('returns the probe unchanged when no accepted protocol matches the challenge headers', async () => {
        const challenge = response(402);
        mockFetch.mockResolvedValue(challenge);

        const client = await createPayKitClient({ accept: ['x402'], rpcUrl: RPC_URL, signer });
        const result = await client.fetch('http://api.test/joke');

        expect(result).toBe(challenge);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('fails closed when a 402 was reached through an internal redirect', async () => {
        const challenge = response(402);
        Object.defineProperty(challenge, 'redirected', { value: true });
        mockFetch.mockResolvedValue(challenge);
        const client = await createPayKitClient({ rpcUrl: RPC_URL, signer });

        await expect(client.fetch('https://api.test/redirect')).rejects.toBeInstanceOf(PermissionDeniedError);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('denies an over-cap MPP challenge before signing or retrying', async () => {
        const mint = resolveStablecoinMint('USDC', 'mainnet');
        if (!mint) throw new Error('missing mainnet USDC mint');
        const challenge = Challenge.serialize({
            id: 'over-cap',
            intent: 'charge',
            method: 'solana',
            realm: 'test',
            request: {
                amount: '1000001',
                currency: mint,
                methodDetails: {
                    decimals: 6,
                    feePayer: false,
                    network: 'mainnet',
                },
                recipient: signer.address,
            },
        });
        mockFetch.mockResolvedValue(response(402, { 'www-authenticate': challenge }));
        const signTransactions = vi.fn(signer.signTransactions.bind(signer));
        const trackingSigner = new Proxy(signer, {
            get: (target, property, receiver) =>
                property === 'signTransactions' ? signTransactions : Reflect.get(target, property, receiver),
        });
        const client = await createPayKitClient({ accept: ['mpp'], rpcUrl: RPC_URL, signer: trackingSigner });

        await expect(client.fetch('https://api.test/paid')).rejects.toBeInstanceOf(PermissionDeniedError);

        expect(signTransactions).not.toHaveBeenCalled();
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('denies an unsupported x402 network before signing or retrying', async () => {
        const paymentRequired = btoa(
            JSON.stringify({
                accepts: [
                    {
                        amount: '500000',
                        asset: 'USDC',
                        extra: {},
                        maxTimeoutSeconds: 60,
                        network: 'solana:unsupported',
                        payTo: signer.address,
                        scheme: 'exact',
                    },
                ],
                x402Version: 2,
            }),
        );
        mockFetch.mockResolvedValue(response(402, { 'payment-required': paymentRequired }));
        const signTransactions = vi.fn(signer.signTransactions.bind(signer));
        const trackingSigner = new Proxy(signer, {
            get: (target, property, receiver) =>
                property === 'signTransactions' ? signTransactions : Reflect.get(target, property, receiver),
        });
        const client = await createPayKitClient({ accept: ['x402'], rpcUrl: RPC_URL, signer: trackingSigner });

        await expect(client.fetch('https://api.test/paid')).rejects.toBeInstanceOf(PermissionDeniedError);
        expect(signTransactions).not.toHaveBeenCalled();
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });
});
