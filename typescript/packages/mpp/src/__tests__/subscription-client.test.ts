/**
 * Behavioral tests for the client-side Solana subscription activation
 * transaction builder.
 *
 * Mocks `globalThis.fetch` to stand in for `createSolanaRpc()` so each test
 * controls exactly which RPC calls succeed and what they return.
 */
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import {
    type Address,
    address,
    type Blockhash,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    generateKeyPairSigner,
    getTransactionDecoder,
} from '@solana/kit';

import {
    SUBSCRIPTIONS_INIT_AUTHORITY_DISCRIMINATOR,
    SUBSCRIPTIONS_PROGRAM,
    SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
    SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
    TOKEN_PROGRAM,
} from '../constants.js';
import { buildSubscriptionActivationTransaction, subscription as subscriptionClient } from '../client/Subscription.js';

const PLAN_ID = '8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT';
const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const PULLER = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const FEE_PAYER = 'FeePayerJ7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';

// ── Test setup ──

let originalFetch: typeof globalThis.fetch;

beforeEach(() => {
    originalFetch = globalThis.fetch;
});

afterEach(() => {
    globalThis.fetch = originalFetch;
});

// ── Helpers ──

function rpcSuccess(result: unknown) {
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        headers: { 'Content-Type': 'application/json' },
    });
}

/**
 * Default RPC mock: pretend the SubscriptionAuthority does not exist, return a
 * blockhash for getLatestBlockhash, accept sendTransaction, and report the
 * signature as confirmed.
 */
function defaultMockFetch(opts: { authorityExists?: boolean } = {}): typeof globalThis.fetch {
    return async (_input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(init?.body as string) as { method?: string };
        switch (body.method) {
            case 'getAccountInfo':
                return rpcSuccess(
                    opts.authorityExists
                        ? {
                              context: { slot: 1 },
                              value: {
                                  data: ['', 'base64'],
                                  executable: false,
                                  lamports: 1,
                                  owner: SUBSCRIPTIONS_PROGRAM,
                                  rentEpoch: 0,
                                  space: 0,
                              },
                          }
                        : { context: { slot: 1 }, value: null },
                );
            case 'getLatestBlockhash':
                return rpcSuccess({ context: { slot: 1 }, value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 } });
            case 'sendTransaction':
                return rpcSuccess(
                    '5J8KKfgKBLPDoCSk7B7TwAdSP3KtkfxYGYQH52SVgyM5XQXfeaG3xH8E3uYmGNLcoNNgWp3JjPdvzNwM4ZmJyREq',
                );
            case 'getSignatureStatuses':
                return rpcSuccess({ context: { slot: 1 }, value: [{ confirmationStatus: 'confirmed', err: null }] });
            default:
                return rpcSuccess({});
        }
    };
}

type CompiledMessage = {
    instructions: readonly { data: Uint8Array; programAddressIndex: number }[];
    staticAccounts: readonly { toString(): string }[];
};

function decodeMessage(base64Tx: string): CompiledMessage {
    const txBytes = getBase64Codec().encode(base64Tx);
    const decoded = getTransactionDecoder().decode(txBytes);
    return getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as CompiledMessage;
}

function instructionDiscriminatorsByProgram(message: CompiledMessage, programId: string): number[] {
    return message.instructions
        .filter(ix => message.staticAccounts[ix.programAddressIndex].toString() === programId)
        .map(ix => ix.data[0]);
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

// ══════════════════════════════════════════════════════════════════════
// buildSubscriptionActivationTransaction
// ══════════════════════════════════════════════════════════════════════

describe('buildSubscriptionActivationTransaction', () => {
    test('includes initialize_subscription_authority when the authority does not exist', async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const tx = await buildSubscriptionActivationTransaction({
            request: baseRequest(),
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        const message = decodeMessage(tx);
        const discriminators = instructionDiscriminatorsByProgram(message, SUBSCRIPTIONS_PROGRAM);
        expect(discriminators).toEqual([
            SUBSCRIPTIONS_INIT_AUTHORITY_DISCRIMINATOR,
            SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
            SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
        ]);
    });

    test('omits initialize_subscription_authority when the authority already exists', async () => {
        globalThis.fetch = defaultMockFetch({ authorityExists: true });
        const signer = await generateKeyPairSigner();
        const tx = await buildSubscriptionActivationTransaction({
            request: baseRequest(),
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        const message = decodeMessage(tx);
        const discriminators = instructionDiscriminatorsByProgram(message, SUBSCRIPTIONS_PROGRAM);
        expect(discriminators).toEqual([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR, SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR]);
    });

    test('uses the server-provided recentBlockhash when present', async () => {
        let blockhashFetched = false;
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getLatestBlockhash') {
                blockhashFetched = true;
            }
            return defaultMockFetch()(_input, init);
        };
        const signer = await generateKeyPairSigner();
        const req = baseRequest();
        req.methodDetails.recentBlockhash = BLOCKHASH;
        await buildSubscriptionActivationTransaction({
            request: req,
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        expect(blockhashFetched).toBe(false);
    });

    test('appends a memo instruction when externalId is supplied', async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const req = baseRequest();
        req.externalId = 'order-42';
        const tx = await buildSubscriptionActivationTransaction({
            request: req,
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        const message = decodeMessage(tx);
        const memoAddress = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
        const memoIxs = message.instructions.filter(
            ix => message.staticAccounts[ix.programAddressIndex].toString() === memoAddress,
        );
        expect(memoIxs).toHaveLength(1);
        expect(new TextDecoder().decode(memoIxs[0].data)).toBe('order-42');
    });

    test('rejects feePayer=true without a feePayerKey', async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const req = baseRequest();
        req.methodDetails.feePayer = true;
        await expect(
            buildSubscriptionActivationTransaction({
                request: req,
                rpcUrl: 'https://mock-rpc',
                signer,
            }),
        ).rejects.toThrow(/feePayerKey/);
    });

    test('uses the server fee-payer when feePayer=true with a feePayerKey', async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const req = baseRequest();
        req.methodDetails.feePayer = true;
        req.methodDetails.feePayerKey = FEE_PAYER;
        const tx = await buildSubscriptionActivationTransaction({
            request: req,
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        const message = decodeMessage(tx);
        // First static account is the fee payer in a v0 message.
        expect(message.staticAccounts[0].toString()).toBe(FEE_PAYER);
    });

    test('rejects periodUnit="month" through the helper', async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const req = baseRequest();
        (req as unknown as { periodUnit: string }).periodUnit = 'month';
        await expect(
            buildSubscriptionActivationTransaction({
                request: req,
                rpcUrl: 'https://mock-rpc',
                signer,
            }),
        ).rejects.toThrow(/rejects periodUnit/);
    });

    test('rejects periodCount out of range for day', async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const req = baseRequest();
        req.periodCount = '400';
        await expect(
            buildSubscriptionActivationTransaction({
                request: req,
                rpcUrl: 'https://mock-rpc',
                signer,
            }),
        ).rejects.toThrow(/exceeds 365/);
    });

    test('invokes onProgress callbacks during build', async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const events: string[] = [];
        await buildSubscriptionActivationTransaction({
            onProgress: ev => events.push((ev as { type: string }).type),
            request: baseRequest(),
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        expect(events).toContain('challenge');
        expect(events).toContain('signing');
    });

    test('falls back to the default RPC URL when no rpcUrl is provided', async () => {
        const urls: string[] = [];
        globalThis.fetch = async (input, init) => {
            urls.push(String(input));
            return defaultMockFetch()(input, init);
        };
        const signer = await generateKeyPairSigner();
        await buildSubscriptionActivationTransaction({
            request: baseRequest(),
            signer,
        });
        // devnet network → public devnet RPC
        expect(urls.some(u => u.includes('devnet'))).toBe(true);
    });
});

// ══════════════════════════════════════════════════════════════════════
// subscription() — Method.toClient wrapper (createCredential)
// ══════════════════════════════════════════════════════════════════════

describe('subscription() client wrapper', () => {
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

    test('emits a credential in pull mode without broadcasting', async () => {
        const calls: string[] = [];
        globalThis.fetch = async (input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            calls.push(body.method ?? '');
            return defaultMockFetch()(input, init);
        };
        const signer = await generateKeyPairSigner();
        const method = subscriptionClient({
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        const cred = await method.createCredential!({ challenge: await buildChallenge() });
        // The mppx framework's Credential envelope is opaque; we assert the
        // builder ran end-to-end and that no broadcast happened.
        expect(typeof cred).toBe('string');
        expect(cred.length).toBeGreaterThan(0);
        expect(calls).not.toContain('sendTransaction');
    });

    test('broadcasts and emits a type="signature" credential when broadcast=true', async () => {
        const calls: string[] = [];
        globalThis.fetch = async (input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            calls.push(body.method ?? '');
            return defaultMockFetch()(input, init);
        };
        const signer = await generateKeyPairSigner();
        const method = subscriptionClient({
            broadcast: true,
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        const cred = await method.createCredential!({ challenge: await buildChallenge() });
        expect(cred).toBeTruthy();
        expect(calls).toContain('sendTransaction');
        expect(calls).toContain('getSignatureStatuses');
    });

    test('rejects broadcast=true combined with feePayer sponsorship', async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const method = subscriptionClient({
            broadcast: true,
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        const challenge = {
            id: 'test-id',
            realm: 'realm',
            method: 'solana',
            intent: 'subscription',
            request: {
                ...baseRequest(),
                methodDetails: {
                    ...baseRequest().methodDetails,
                    feePayer: true,
                    feePayerKey: FEE_PAYER,
                },
            },
        } as never;
        await expect(method.createCredential!({ challenge })).rejects.toThrow(/fee sponsorship/);
    });
});
