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
import { __testing as serverTesting } from '../server/Subscription.js';

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
 * Default RPC mock modelling a first-time subscriber. The SubscriptionAuthority
 * is absent on the first read; after the client broadcasts and confirms the
 * standalone init transaction the account reads back present. Returns a
 * blockhash for getLatestBlockhash, accepts sendTransaction, and reports the
 * signature as confirmed.
 *
 * Pass `authorityExists: true` to model a returning subscriber whose SA already
 * exists (no init broadcast happens).
 */
function defaultMockFetch(opts: { authorityExists?: boolean } = {}): typeof globalThis.fetch {
    let initBroadcast = false;
    let confirmed = false;
    const presentAccount = {
        context: { slot: 1 },
        value: {
            data: ['', 'base64'],
            executable: false,
            lamports: 1,
            owner: SUBSCRIPTIONS_PROGRAM,
            rentEpoch: 0,
            space: 0,
        },
    };
    return async (_input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(init?.body as string) as { method?: string };
        switch (body.method) {
            case 'getAccountInfo':
                // Present when the subscriber already had an SA, or once the
                // standalone init transaction has broadcast and confirmed.
                return rpcSuccess(
                    opts.authorityExists || (initBroadcast && confirmed)
                        ? presentAccount
                        : { context: { slot: 1 }, value: null },
                );
            case 'getLatestBlockhash':
                return rpcSuccess({ context: { slot: 1 }, value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 } });
            case 'sendTransaction':
                initBroadcast = true;
                return rpcSuccess(
                    '5J8KKfgKBLPDoCSk7B7TwAdSP3KtkfxYGYQH52SVgyM5XQXfeaG3xH8E3uYmGNLcoNNgWp3JjPdvzNwM4ZmJyREq',
                );
            case 'getSignatureStatuses':
                confirmed = true;
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
    test('pre-broadcasts initialize_subscription_authority instead of bundling it when the authority does not exist', async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const tx = await buildSubscriptionActivationTransaction({
            request: baseRequest(),
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        const message = decodeMessage(tx);
        const discriminators = instructionDiscriminatorsByProgram(message, SUBSCRIPTIONS_PROGRAM);
        // The init instruction (discriminator 0) is broadcast in its own
        // subscriber-paid transaction; the activation transaction the server
        // co-signs must carry ONLY subscribe + transfer_subscription so it
        // passes the server's strict allowlist.
        expect(discriminators).toEqual([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR, SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR]);
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
        const inner = defaultMockFetch();
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getLatestBlockhash') {
                blockhashFetched = true;
            }
            return inner(_input, init);
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
        const inner = defaultMockFetch();
        globalThis.fetch = async (input, init) => {
            urls.push(String(input));
            return inner(input, init);
        };
        const signer = await generateKeyPairSigner();
        await buildSubscriptionActivationTransaction({
            request: baseRequest(),
            signer,
        });
        // devnet network → public devnet RPC
        expect(urls.some(u => u.includes('devnet'))).toBe(true);
    });

    test('normalizes a mixed-case network slug when resolving the default RPC URL', async () => {
        const urls: string[] = [];
        const inner = defaultMockFetch();
        globalThis.fetch = async (input, init) => {
            urls.push(String(input));
            return inner(input, init);
        };
        const signer = await generateKeyPairSigner();
        const req = baseRequest();
        // Upper-case mainnet slug must normalize (mainnet/mainnet-beta → mainnet)
        // and resolve to the mainnet default RPC rather than falling through.
        (req.methodDetails as { network: string }).network = 'MAINNET';
        await buildSubscriptionActivationTransaction({
            request: req,
            signer,
        });
        expect(urls.some(u => u.includes('api.mainnet-beta.solana.com'))).toBe(true);
        expect(urls.some(u => u.includes('devnet'))).toBe(false);
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

    test('emits a credential in pull mode without broadcasting the activation tx', async () => {
        // A returning subscriber (SA already exists) so no standalone init tx is
        // broadcast; pull mode must then perform NO broadcast at all — the
        // activation transaction is handed to the server unsent.
        const calls: string[] = [];
        const inner = defaultMockFetch({ authorityExists: true });
        globalThis.fetch = async (input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            calls.push(body.method ?? '');
            return inner(input, init);
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
        const inner = defaultMockFetch({ authorityExists: true });
        globalThis.fetch = async (input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            calls.push(body.method ?? '');
            return inner(input, init);
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

// ══════════════════════════════════════════════════════════════════════
// First-time-subscriber activation must pass the strict server allowlist
// ══════════════════════════════════════════════════════════════════════
//
// The server's activation allowlist rejects every subscriptions-program
// instruction other than subscribe (11) / transfer_subscription (10). When the
// SubscriptionAuthority PDA does not yet exist, the client must NOT bundle the
// initialize_subscription_authority instruction (discriminator 0) into the
// activation transaction the server co-signs and broadcasts. Instead it
// broadcasts a standalone subscriber-paid init transaction first, waits for
// confirmation, and only then builds/signs the activation transaction — exactly
// as the Rust client does. These tests reproduce that first-time flow against a
// mock RPC sequenced absent -> confirmed -> present, capture every broadcast,
// and feed the activation transaction through the server's own allowlist.

/** A record of a captured sendTransaction broadcast, in call order. */
type CapturedBroadcast = { base64: string };

/**
 * Sequenced RPC mock for the first-time-subscriber flow. The first
 * getAccountInfo for the SubscriptionAuthority returns null (absent); after a
 * sendTransaction lands and its status is polled confirmed, subsequent
 * getAccountInfo calls return a present account. Every sendTransaction payload
 * is captured (in order), and the sequence of RPC method names is recorded so a
 * test can assert the init broadcast was confirmed before the activation was
 * signed.
 */
function firstTimeSubscriberMock(): {
    fetch: typeof globalThis.fetch;
    broadcasts: CapturedBroadcast[];
    methodOrder: string[];
} {
    const broadcasts: CapturedBroadcast[] = [];
    const methodOrder: string[] = [];
    let authorityInitBroadcast = false;
    let confirmedAfterBroadcast = false;
    const fetch: typeof globalThis.fetch = async (_input, init) => {
        const body = JSON.parse(init?.body as string) as { method?: string; params?: unknown[] };
        methodOrder.push(body.method ?? '');
        switch (body.method) {
            case 'getAccountInfo':
                // Absent until the init tx has broadcast AND confirmed.
                return rpcSuccess(
                    authorityInitBroadcast && confirmedAfterBroadcast
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
                broadcasts.push({ base64: (body.params?.[0] as string) ?? '' });
                authorityInitBroadcast = true;
                return rpcSuccess(
                    '5J8KKfgKBLPDoCSk7B7TwAdSP3KtkfxYGYQH52SVgyM5XQXfeaG3xH8E3uYmGNLcoNNgWp3JjPdvzNwM4ZmJyREq',
                );
            case 'getSignatureStatuses':
                confirmedAfterBroadcast = true;
                return rpcSuccess({ context: { slot: 1 }, value: [{ confirmationStatus: 'confirmed', err: null }] });
            default:
                return rpcSuccess({});
        }
    };
    return { broadcasts, fetch, methodOrder };
}

function decodeFullTransaction(base64Tx: string): {
    feePayer: string;
    message: CompiledMessage;
    signerCount: number;
} {
    const txBytes = getBase64Codec().encode(base64Tx);
    const decoded = getTransactionDecoder().decode(txBytes) as unknown as {
        messageBytes: Uint8Array;
        signatures: Record<string, unknown>;
    };
    const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as CompiledMessage;
    return {
        feePayer: message.staticAccounts[0].toString(),
        message,
        signerCount: Object.keys(decoded.signatures).length,
    };
}

describe('first-time subscriber activation and the server allowlist', () => {
    test('pre-broadcasts the SA init tx and produces an activation tx the server allowlist accepts', async () => {
        const { broadcasts, fetch, methodOrder } = firstTimeSubscriberMock();
        globalThis.fetch = fetch;
        const signer = await generateKeyPairSigner();

        const activationTx = await buildSubscriptionActivationTransaction({
            request: baseRequest(),
            rpcUrl: 'https://mock-rpc',
            signer,
        });

        // (core) The activation transaction the server co-signs/broadcasts must
        // pass the strict server allowlist. Before the fix the bundled init
        // instruction (discriminator 0) makes this throw.
        await expect(
            serverTesting.validateActivationInstructions(activationTx, {
                methodDetails: {
                    mint: MINT,
                    planId: PLAN_ID,
                    programId: SUBSCRIPTIONS_PROGRAM,
                    puller: PULLER,
                    tokenProgram: TOKEN_PROGRAM,
                },
                recipient: RECIPIENT,
            } as never),
        ).resolves.toBeUndefined();

        // The activation tx must carry ONLY subscribe + transfer_subscription
        // for the subscriptions program — never the init discriminator.
        const activationMessage = decodeMessage(activationTx);
        const activationDiscriminators = instructionDiscriminatorsByProgram(activationMessage, SUBSCRIPTIONS_PROGRAM);
        expect(activationDiscriminators).toEqual([
            SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
            SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
        ]);

        // (a) A separate, prior transaction carrying the discriminator-0 init
        // instruction was broadcast, with the subscriber as its fee payer.
        expect(broadcasts.length).toBe(1);
        const initTx = decodeFullTransaction(broadcasts[0].base64);
        const initDiscriminators = instructionDiscriminatorsByProgram(initTx.message, SUBSCRIPTIONS_PROGRAM);
        expect(initDiscriminators).toEqual([SUBSCRIPTIONS_INIT_AUTHORITY_DISCRIMINATOR]);
        expect(initTx.feePayer).toBe(signer.address);
        // The init tx is a standalone subscriber-paid/-signed transaction.
        expect(initTx.signerCount).toBe(1);

        // (b) Confirmation of the init broadcast was awaited BEFORE the
        // activation tx was signed. The activation builder re-reads the SA
        // account after confirmation, so the RPC order must show:
        //   sendTransaction (init) -> getSignatureStatuses (confirm) ->
        //   getAccountInfo (post-confirm SA re-read).
        const sendIdx = methodOrder.indexOf('sendTransaction');
        const confirmIdx = methodOrder.indexOf('getSignatureStatuses');
        const reReadIdx = methodOrder.lastIndexOf('getAccountInfo');
        expect(sendIdx).toBeGreaterThanOrEqual(0);
        expect(confirmIdx).toBeGreaterThan(sendIdx);
        expect(reReadIdx).toBeGreaterThan(confirmIdx);
    });

    test('surfaces a clear client error when the SA init broadcast fails', async () => {
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            switch (body.method) {
                case 'getAccountInfo':
                    return rpcSuccess({ context: { slot: 1 }, value: null });
                case 'getLatestBlockhash':
                    return rpcSuccess({
                        context: { slot: 1 },
                        value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 },
                    });
                case 'sendTransaction':
                    return new Response(
                        JSON.stringify({
                            jsonrpc: '2.0',
                            id: 1,
                            error: { code: -32002, message: 'blockhash expired' },
                        }),
                        { headers: { 'Content-Type': 'application/json' } },
                    );
                default:
                    return rpcSuccess({});
            }
        };
        const signer = await generateKeyPairSigner();
        await expect(
            buildSubscriptionActivationTransaction({ request: baseRequest(), rpcUrl: 'https://mock-rpc', signer }),
        ).rejects.toThrow(/subscription authority/i);
    });
});
