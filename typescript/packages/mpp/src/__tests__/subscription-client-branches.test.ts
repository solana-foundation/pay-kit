// Branch-coverage tests for client/Subscription.ts.
//
// Targets branches the subscription-client suite leaves uncovered: the
// `network ?? 'mainnet'` defaulting inside createCredential, the
// `methodDetails.puller` fallback to the subscriber, the memo size guard, and
// the confirmTransaction error / finalized arms. RPC is stubbed through
// globalThis.fetch, mirroring the existing subscription-client suite.
// No production code is touched.

import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { generateKeyPairSigner } from '@solana/kit';

import { TOKEN_PROGRAM } from '../constants.js';
import { buildSubscriptionActivationTransaction, subscription as subscriptionClient } from '../client/Subscription.js';

const PLAN_ID = '8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT';
const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const PULLER = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';

let originalFetch: typeof globalThis.fetch;

beforeEach(() => {
    originalFetch = globalThis.fetch;
});

afterEach(() => {
    globalThis.fetch = originalFetch;
});

function rpcSuccess(result: unknown) {
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        headers: { 'Content-Type': 'application/json' },
    });
}

/** RPC mock: authority absent, blockhash + sendTransaction ok, status per opts. */
function mockFetch(opts: { signatureStatus?: unknown } = {}): typeof globalThis.fetch {
    return async (_input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(init?.body as string) as { method?: string };
        switch (body.method) {
            case 'getAccountInfo':
                return rpcSuccess({ context: { slot: 1 }, value: null });
            case 'getLatestBlockhash':
                return rpcSuccess({ context: { slot: 1 }, value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 } });
            case 'sendTransaction':
                return rpcSuccess(
                    '5J8KKfgKBLPDoCSk7B7TwAdSP3KtkfxYGYQH52SVgyM5XQXfeaG3xH8E3uYmGNLcoNNgWp3JjPdvzNwM4ZmJyREq',
                );
            case 'getSignatureStatuses':
                return rpcSuccess({
                    context: { slot: 1 },
                    value: [opts.signatureStatus ?? { confirmationStatus: 'confirmed', err: null }],
                });
            default:
                return rpcSuccess({});
        }
    };
}

function baseRequest(): Parameters<typeof buildSubscriptionActivationTransaction>[0]['request'] {
    return {
        amount: '10000000',
        currency: MINT,
        methodDetails: {
            decimals: 6,
            mint: MINT,
            network: 'devnet',
            planId: PLAN_ID,
            puller: PULLER,
            tokenProgram: TOKEN_PROGRAM,
        },
        periodCount: '30',
        periodUnit: 'day',
        recipient: RECIPIENT,
    };
}

// ── buildSubscriptionActivationTransaction defaulting ──

describe('buildSubscriptionActivationTransaction defaulting branches', () => {
    test('falls back to the subscriber as puller when methodDetails.puller is absent', async () => {
        globalThis.fetch = mockFetch();
        const signer = await generateKeyPairSigner();
        const req = baseRequest();
        delete (req.methodDetails as { puller?: string }).puller;
        const tx = await buildSubscriptionActivationTransaction({
            request: req,
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        expect(tx.length).toBeGreaterThan(0);
    });

    test('rejects an externalId memo above 566 bytes', async () => {
        globalThis.fetch = mockFetch();
        const signer = await generateKeyPairSigner();
        const req = baseRequest();
        req.externalId = 'z'.repeat(600);
        await expect(
            buildSubscriptionActivationTransaction({ request: req, rpcUrl: 'https://mock-rpc', signer }),
        ).rejects.toThrow(/memo cannot exceed 566 bytes/);
    });
});

// ── createCredential network defaulting ──

describe('subscription() createCredential defaulting', () => {
    async function challengeWithoutNetwork() {
        const req = baseRequest();
        delete (req.methodDetails as { network?: string }).network;
        return {
            id: 'test-id',
            realm: 'realm',
            method: 'solana',
            intent: 'subscription',
            request: req,
            expires: undefined,
        } as never;
    }

    test('defaults the RPC network to mainnet when methodDetails.network is absent', async () => {
        globalThis.fetch = mockFetch();
        const signer = await generateKeyPairSigner();
        const method = subscriptionClient({ rpcUrl: 'https://mock-rpc', signer });
        const cred = await method.createCredential!({ challenge: await challengeWithoutNetwork() });
        expect(typeof cred).toBe('string');
        expect(cred.length).toBeGreaterThan(0);
    });

    test('resolves the default RPC URL for a mainnet default when no rpcUrl and no network are given', async () => {
        // With no rpcUrl the `parameters.rpcUrl ??` fallback and the
        // `network ?? 'mainnet'` default arm are both evaluated. A
        // server-provided recentBlockhash avoids getLatestBlockhash, and fetch
        // is stubbed so no real RPC is contacted.
        const urls: string[] = [];
        globalThis.fetch = async (input, init) => {
            urls.push(String(input));
            return mockFetch()(input, init);
        };
        const signer = await generateKeyPairSigner();
        const req = baseRequest();
        delete (req.methodDetails as { network?: string }).network;
        (req.methodDetails as { recentBlockhash?: string }).recentBlockhash = BLOCKHASH;
        const challenge = {
            id: 'test-id',
            realm: 'realm',
            method: 'solana',
            intent: 'subscription',
            request: req,
            expires: undefined,
        } as never;
        const method = subscriptionClient({ signer });
        const cred = await method.createCredential!({ challenge });
        expect(typeof cred).toBe('string');
        expect(urls.some(u => u.includes('mainnet-beta'))).toBe(true);
    });
});

// ── confirmTransaction arms (push / broadcast mode) ──

describe('subscription() confirmTransaction arms', () => {
    async function buildChallenge() {
        return {
            id: 'test-id',
            realm: 'realm',
            method: 'solana',
            intent: 'subscription',
            request: baseRequest(),
            expires: undefined,
        } as never;
    }

    test('confirms on a finalized signature status', async () => {
        globalThis.fetch = mockFetch({ signatureStatus: { confirmationStatus: 'finalized', err: null } });
        const signer = await generateKeyPairSigner();
        const method = subscriptionClient({ broadcast: true, rpcUrl: 'https://mock-rpc', signer });
        const cred = await method.createCredential!({ challenge: await buildChallenge() });
        expect(cred).toBeTruthy();
    });

    test('throws when the signature status carries an error', async () => {
        // A string err survives the RPC transport as a string (numeric fields
        // are upcast to bigint by @solana/kit, which JSON.stringify rejects), so
        // it renders cleanly in the "Transaction failed" message.
        globalThis.fetch = mockFetch({ signatureStatus: { confirmationStatus: 'processed', err: 'AccountInUse' } });
        const signer = await generateKeyPairSigner();
        const method = subscriptionClient({ broadcast: true, rpcUrl: 'https://mock-rpc', signer });
        await expect(method.createCredential!({ challenge: await buildChallenge() })).rejects.toThrow(
            /Transaction failed/,
        );
    });
});
