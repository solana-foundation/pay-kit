import { generateKeyPairSigner, type KeyPairSigner } from '@solana/kit';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// `createPayKitClient` binds `globalThis.fetch` into a module-level `nativeFetch`
// when its module first loads, so the stub must be installed before that import
// is evaluated — `vi.hoisted` runs ahead of the static imports below.
const { mockFetch } = vi.hoisted(() => {
    const mockFetch = vi.fn<typeof fetch>();
    globalThis.fetch = mockFetch;
    return { mockFetch };
});

import { createPayKitClient } from '../client/index.js';
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
});
