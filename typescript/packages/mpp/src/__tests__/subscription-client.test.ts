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
import { getPlanEncoder, getSubscriptionAuthorityEncoder } from '@solana/subscriptions';

import {
    ASSOCIATED_TOKEN_PROGRAM,
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
const ZERO = '11111111111111111111111111111111';

/** Pad a Plan address list to the program's fixed four slots with the zero address. */
function padded(list: readonly string[]): Address[] {
    return [...list, ZERO, ZERO, ZERO, ZERO].slice(0, 4).map(entry => address(entry));
}

function defaultMockFetch(
    opts: {
        authorityExists?: boolean;
        planDestinations?: readonly string[];
        planOwner?: string;
        planPullers?: readonly string[];
    } = { authorityExists: true },
): typeof globalThis.fetch {
    return async (_input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(init?.body as string) as { method?: string; params?: unknown[] };
        switch (body.method) {
            case 'getAccountInfo': {
                const requested = String(body.params?.[0]);
                if (requested === PLAN_ID) {
                    const encoded = getPlanEncoder().encode({
                        bump: 1,
                        data: {
                            destinations: padded(opts.planDestinations ?? [RECIPIENT]),
                            endTs: 0n,
                            metadataUri: '',
                            mint: address(MINT),
                            planId: 1n,
                            pullers: padded(opts.planPullers ?? [PULLER]),
                            terms: { amount: 10_000_000n, createdAt: 1n, periodHours: 720n },
                        },
                        discriminator: 1,
                        owner: address(opts.planOwner ?? PULLER),
                        status: 1,
                    });
                    return rpcSuccess({
                        context: { slot: 1 },
                        value: accountValue(getBase64Codec().decode(encoded)),
                    });
                }
                if (opts.authorityExists === false) return rpcSuccess({ context: { slot: 1 }, value: null });
                const encoded = getSubscriptionAuthorityEncoder().encode({
                    bump: 1,
                    discriminator: 0,
                    initId: 42n,
                    payer: address(PULLER),
                    tokenMint: address(MINT),
                    user: address(PULLER),
                });
                return rpcSuccess({ context: { slot: 1 }, value: accountValue(getBase64Codec().decode(encoded)) });
            }
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

function accountValue(data: string) {
    return {
        data: [data, 'base64'],
        executable: false,
        lamports: 1,
        owner: SUBSCRIPTIONS_PROGRAM,
        rentEpoch: 0,
        space: 491,
    };
}

type CompiledMessage = {
    instructions: readonly { accountIndices?: readonly number[]; data: Uint8Array; programAddressIndex: number }[];
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
            planAddress: PLAN_ID,
            subscriptionProgram: SUBSCRIPTIONS_PROGRAM,
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
    test('uses the current subscribe and transfer layouts', async () => {
        globalThis.fetch = defaultMockFetch();
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

    test('binds subscription activation to the supplied authority init id', async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const tx = await buildSubscriptionActivationTransaction({
            request: baseRequest(),
            rpcUrl: 'https://mock-rpc',
            signer,
            subscriptionAuthorityInitId: 42n,
        });
        const message = decodeMessage(tx);
        const discriminators = instructionDiscriminatorsByProgram(message, SUBSCRIPTIONS_PROGRAM);
        const subscribe = message.instructions.find(
            ix =>
                message.staticAccounts[ix.programAddressIndex].toString() === SUBSCRIPTIONS_PROGRAM &&
                ix.data[0] === SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
        );
        expect(subscribe?.data).toHaveLength(74);
        expect(new DataView(subscribe!.data.buffer, subscribe!.data.byteOffset).getBigInt64(66, true)).toBe(42n);
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

    test('normalizes a mixed-case network slug when resolving the default RPC URL', async () => {
        const urls: string[] = [];
        globalThis.fetch = async (input, init) => {
            urls.push(String(input));
            return defaultMockFetch()(input, init);
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
        const hosts = urls.map(u => new URL(u).host);
        expect(hosts).toContain('api.mainnet-beta.solana.com');
        expect(hosts.some(h => h.includes('devnet'))).toBe(false);
    });
});

// ══════════════════════════════════════════════════════════════════════
// Challenge and plan checks (draft-solana-subscription-00)
// ══════════════════════════════════════════════════════════════════════

/** An RPC that fails the test if the builder asks it anything. */
const noRpc: typeof globalThis.fetch = () => Promise.reject(new Error('the builder must refuse before any RPC call'));

describe('buildSubscriptionActivationTransaction challenge checks', () => {
    // §Activation: "no instructions other than those above plus optional
    // compute-budget and memo instructions" — only the subscriber's own ATA
    // (as the Rust kit builds) is created; never the recipient's.
    test("creates only the subscriber's ATA, not the recipient's", async () => {
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const tx = await buildSubscriptionActivationTransaction({
            request: baseRequest(),
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        const message = decodeMessage(tx);
        const ataCreations = message.instructions.filter(
            ix => message.staticAccounts[ix.programAddressIndex].toString() === ASSOCIATED_TOKEN_PROGRAM,
        );
        expect(ataCreations).toHaveLength(1);
        const owner = message.staticAccounts[ataCreations[0].accountIndices![2]].toString();
        expect(owner).toBe(signer.address);
    });

    // §Intent Semantics: "clients MUST validate that address before signing".
    test('refuses an untrusted subscriptionProgram before any RPC call', async () => {
        globalThis.fetch = noRpc;
        const signer = await generateKeyPairSigner();
        const request = baseRequest();
        request.methodDetails.subscriptionProgram = 'Vote111111111111111111111111111111111111111';
        await expect(
            buildSubscriptionActivationTransaction({ request, rpcUrl: 'https://mock-rpc', signer }),
        ).rejects.toThrow(/Untrusted subscription program Vote111111111111111111111111111111111111111/);
    });

    test('trusts the subscriptionProgram named by trustedSubscriptionProgram', async () => {
        const other = 'Vote111111111111111111111111111111111111111';
        // The pin passes; the mock plan is owned by the canonical program, so
        // the build then stops at the plan-owner check.
        globalThis.fetch = defaultMockFetch();
        const signer = await generateKeyPairSigner();
        const request = baseRequest();
        request.methodDetails.subscriptionProgram = other;
        await expect(
            buildSubscriptionActivationTransaction({
                request,
                rpcUrl: 'https://mock-rpc',
                signer,
                trustedSubscriptionProgram: other,
            }),
        ).rejects.toThrow(/owner does not match the program/);
    });

    // §Currency Formats: "Implementations MUST treat currency and
    // methodDetails.mint as the same value".
    test('refuses a challenge whose currency differs from methodDetails.mint', async () => {
        globalThis.fetch = noRpc;
        const signer = await generateKeyPairSigner();
        const request = { ...baseRequest(), currency: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU' };
        await expect(
            buildSubscriptionActivationTransaction({ request, rpcUrl: 'https://mock-rpc', signer }),
        ).rejects.toThrow(/currency must match methodDetails\.mint/);
    });

    // §Shared Fields: positive base-10 integers, no sign, decimal point,
    // exponent, whitespace, or leading zeros.
    test.each(['010000000', '0', '+10000000', '1e7', '10000000.0', ' 10000000', '-1', ''])(
        'refuses amount %j',
        async amount => {
            globalThis.fetch = noRpc;
            const signer = await generateKeyPairSigner();
            await expect(
                buildSubscriptionActivationTransaction({
                    request: { ...baseRequest(), amount },
                    rpcUrl: 'https://mock-rpc',
                    signer,
                }),
            ).rejects.toThrow(/amount must be a positive base-10 integer/);
        },
    );

    test('refuses an amount above u64', async () => {
        globalThis.fetch = noRpc;
        const signer = await generateKeyPairSigner();
        await expect(
            buildSubscriptionActivationTransaction({
                request: { ...baseRequest(), amount: '18446744073709551616' },
                rpcUrl: 'https://mock-rpc',
                signer,
            }),
        ).rejects.toThrow(/does not fit in a u64/);
    });

    test.each(['030', '+30', '30.0', '3e1', ' 30', '30 ', '0'])('refuses periodCount %j', async periodCount => {
        globalThis.fetch = noRpc;
        const signer = await generateKeyPairSigner();
        await expect(
            buildSubscriptionActivationTransaction({
                request: { ...baseRequest(), periodCount },
                rpcUrl: 'https://mock-rpc',
                signer,
            }),
        ).rejects.toThrow(/periodCount must be a positive base-10 integer/);
    });

    // §Method Details: tokenProgram "MUST be the SPL Token program or the SPL Token-2022 program".
    test('refuses a tokenProgram other than SPL Token or Token-2022', async () => {
        globalThis.fetch = noRpc;
        const signer = await generateKeyPairSigner();
        const request = baseRequest();
        request.methodDetails.tokenProgram = ZERO;
        await expect(
            buildSubscriptionActivationTransaction({ request, rpcUrl: 'https://mock-rpc', signer }),
        ).rejects.toThrow(/tokenProgram must be/);
    });

    // §Method Details: puller "MUST be plan.owner or appear in plan.pullers".
    test('refuses a puller that is neither plan.owner nor in plan.pullers', async () => {
        const stranger = (await generateKeyPairSigner()).address;
        globalThis.fetch = defaultMockFetch({ planOwner: stranger, planPullers: [stranger] });
        const signer = await generateKeyPairSigner();
        await expect(
            buildSubscriptionActivationTransaction({ request: baseRequest(), rpcUrl: 'https://mock-rpc', signer }),
        ).rejects.toThrow(/neither plan\.owner nor in plan\.pullers/);
    });

    test('accepts a puller listed in plan.pullers that is not plan.owner', async () => {
        const merchant = (await generateKeyPairSigner()).address;
        globalThis.fetch = defaultMockFetch({ planOwner: merchant, planPullers: [PULLER] });
        const signer = await generateKeyPairSigner();
        await expect(
            buildSubscriptionActivationTransaction({ request: baseRequest(), rpcUrl: 'https://mock-rpc', signer }),
        ).resolves.toBeTypeOf('string');
    });

    // §Method Details: "reject request objects referencing a plan with an
    // empty destination whitelist, more than one non-zero destination, or a
    // destination different from recipient".
    test.each([
        ['an empty destination whitelist', []],
        ['two non-zero destinations', [RECIPIENT, PULLER]],
        ['a destination other than recipient', [PULLER]],
    ])('refuses a plan with %s', async (_label, planDestinations) => {
        globalThis.fetch = defaultMockFetch({ planDestinations });
        const signer = await generateKeyPairSigner();
        await expect(
            buildSubscriptionActivationTransaction({ request: baseRequest(), rpcUrl: 'https://mock-rpc', signer }),
        ).rejects.toThrow(/plan\.destinations must be exactly one address equal to recipient/);
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

    test('requires explicit authority initialization in pull mode', async () => {
        const calls: string[] = [];
        globalThis.fetch = async (input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            calls.push(body.method ?? '');
            return defaultMockFetch({ authorityExists: false })(input, init);
        };
        const signer = await generateKeyPairSigner();
        const method = subscriptionClient({ rpcUrl: 'https://mock-rpc', signer });

        await expect(method.createCredential!({ challenge: await buildChallenge() })).rejects.toThrow(
            /initializeSubscriptionAuthority/,
        );
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

    test('refuses an untrusted subscriptionProgram before signing the bearer proof', async () => {
        globalThis.fetch = noRpc;
        const signer = await generateKeyPairSigner();
        let proofs = 0;
        const method = subscriptionClient({
            onAuthentication: () => {
                proofs += 1;
            },
            rpcUrl: 'https://mock-rpc',
            signer,
        });
        const request = baseRequest();
        request.methodDetails.subscriptionProgram = 'Vote111111111111111111111111111111111111111';
        const challenge = { ...((await buildChallenge()) as object), request } as never;
        await expect(method.createCredential!({ challenge })).rejects.toThrow(/Untrusted subscription program/);
        expect(proofs).toBe(0);
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
