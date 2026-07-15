import { afterEach, describe, expect, test } from 'vitest';
import {
    address,
    type Blockhash,
    generateKeyPairSigner,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
    getSignatureFromTransaction,
    getTransactionDecoder,
    getTransactionEncoder,
    type TransactionPartialSigner,
} from '@solana/kit';
import { Challenge, Credential } from 'mppx';
import { Mppx } from 'mppx/server';

import { buildSubscriptionActivationTransaction } from '../client/Subscription.js';
import { COMPUTE_BUDGET_PROGRAM, SUBSCRIPTIONS_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM } from '../constants.js';
import { getSubscriptionAuthorityEncoder } from '../generated/subscriptions/accounts/subscriptionAuthority.js';
import { getSubscriptionDelegationEncoder } from '../generated/subscriptions/accounts/subscriptionDelegation.js';
import { __testing, subscription, type SubscriptionReplayStore } from '../server/Subscription.js';
import { deriveSubscriptionAuthorityPda, deriveSubscriptionPda } from '../shared/subscription.js';

const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;
const PLAN_ID = '8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT';
const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const MERCHANT = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const INIT_ID = 9123n;

const originalFetch = globalThis.fetch;
afterEach(() => {
    globalThis.fetch = originalFetch;
});

class AtomicStore implements SubscriptionReplayStore {
    readonly isDurable?: boolean;
    readonly isShared?: boolean;
    readonly values = new Map<string, unknown>();

    constructor(capabilities: { isDurable?: boolean; isShared?: boolean } = { isDurable: true, isShared: true }) {
        this.isDurable = capabilities.isDurable;
        this.isShared = capabilities.isShared;
    }

    async get(key: string) {
        return this.values.get(key) ?? null;
    }

    async put(key: string, value: unknown) {
        this.values.set(key, value);
    }

    async delete(key: string) {
        this.values.delete(key);
    }

    async reserve(key: string, value: unknown = true) {
        if (this.values.has(key)) return false;
        this.values.set(key, value);
        return true;
    }
}

class DeleteFailingStore extends AtomicStore {
    deleteCalls = 0;

    async delete(key: string) {
        this.deleteCalls += 1;
        throw new Error(`delete failed for ${key}`);
    }
}

function request(serverAddress: string) {
    return {
        amount: '10000000',
        currency: MINT,
        externalId: 'invoice-42',
        methodDetails: {
            decimals: 6,
            expectedCreatedAt: '1700000000',
            expectedPeriodHours: '720',
            feePayer: true,
            feePayerKey: serverAddress,
            merchant: MERCHANT,
            mint: MINT,
            network: 'devnet',
            planBump: 254,
            planId: PLAN_ID,
            planIdNumeric: '7',
            programId: SUBSCRIPTIONS_PROGRAM,
            puller: serverAddress,
            recentBlockhash: BLOCKHASH,
            tokenProgram: TOKEN_PROGRAM,
        },
        periodCount: '30',
        periodUnit: 'day' as const,
        recipient: RECIPIENT,
    };
}

function serverParameters(signer: TransactionPartialSigner, store: SubscriptionReplayStore) {
    return {
        decimals: 6,
        merchant: MERCHANT,
        mint: MINT,
        network: 'devnet' as const,
        periodCount: 30,
        periodUnit: 'day' as const,
        planBump: 254,
        planCreatedAt: 1_700_000_000n,
        planId: PLAN_ID,
        planIdNumeric: 7n,
        puller: signer.address,
        recipient: RECIPIENT,
        rpcUrl: 'https://mock-rpc',
        signer,
        store,
        tokenProgram: TOKEN_PROGRAM,
    };
}

async function fixture() {
    const subscriber = await generateKeyPairSigner();
    const serverSigner = await generateKeyPairSigner();
    const challengedRequest = request(serverSigner.address);
    const transaction = await buildSubscriptionActivationTransaction({
        request: challengedRequest,
        signer: subscriber,
        subscriptionAuthorityInitId: INIT_ID,
    });
    const authority = await deriveSubscriptionAuthorityPda({
        mint: address(MINT),
        programId: address(SUBSCRIPTIONS_PROGRAM),
        subscriber: subscriber.address,
    });
    const delegation = await deriveSubscriptionPda({
        planPda: address(PLAN_ID),
        programId: address(SUBSCRIPTIONS_PROGRAM),
        subscriber: subscriber.address,
    });
    return {
        authority: authority.toString(),
        challengedRequest,
        delegation: delegation.toString(),
        serverSigner,
        subscriber,
        transaction,
    };
}

function authorityAccount(subscriber: string, server: string) {
    return getBase64Codec().decode(
        getSubscriptionAuthorityEncoder().encode({
            bump: 253,
            discriminator: 4,
            initId: INIT_ID,
            payer: address(server),
            tokenMint: address(MINT),
            user: address(subscriber),
        }),
    );
}

function delegationAccount(subscriber: string, server: string, amount = 10_000_000n) {
    return getBase64Codec().decode(
        getSubscriptionDelegationEncoder().encode({
            amountPulledInPeriod: amount,
            currentPeriodStartTs: 1_737_216_000n,
            expiresAtTs: 0n,
            header: {
                bump: 252,
                delegatee: address(PLAN_ID),
                delegator: address(subscriber),
                discriminator: 5,
                initId: 77n,
                payer: address(server),
                version: 1,
            },
            terms: {
                amount,
                createdAt: 1_700_000_000n,
                periodHours: 720n,
            },
        }),
    );
}

function accountInfo(encoded: string) {
    return {
        value: {
            data: [encoded, 'base64'],
            executable: false,
            lamports: 1,
            owner: SUBSCRIPTIONS_PROGRAM,
            rentEpoch: 0,
        },
    };
}

function credential(transaction: string, challengedRequest: ReturnType<typeof request>) {
    return {
        challenge: { id: 'challenge-id', request: challengedRequest },
        payload: { transaction, type: 'transaction' },
    };
}

function rewriteComputeUnitLimits(transactionBase64: string, count: 0 | 2): string {
    const transaction = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const message = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes) as unknown as {
        instructions: Array<{ accountIndices: number[]; data: Uint8Array; programAddressIndex: number }>;
        staticAccounts: string[];
    };
    const isComputeLimit = (instruction: (typeof message.instructions)[number]) =>
        message.staticAccounts[instruction.programAddressIndex] === COMPUTE_BUDGET_PROGRAM && instruction.data[0] === 2;
    const limit = message.instructions.find(isComputeLimit);
    if (!limit) throw new Error('fixture is missing SetComputeUnitLimit');
    const instructions = message.instructions.filter(instruction => !isComputeLimit(instruction));
    if (count === 2) instructions.unshift(limit, limit);
    const messageBytes = new Uint8Array(
        getCompiledTransactionMessageEncoder().encode({ ...message, instructions } as never),
    );
    const rebuilt = getTransactionEncoder().encode({ ...transaction, messageBytes } as never);
    return getBase64Codec().decode(new Uint8Array(rebuilt));
}

describe('subscription server configuration', () => {
    test('requires a signer/puller match and durable shared atomic replay storage outside localnet', async () => {
        const signer = await generateKeyPairSigner();
        expect(() =>
            subscription({ ...serverParameters(signer, new AtomicStore()), signer: undefined as never }),
        ).toThrow(/signer is required/);
        expect(() =>
            subscription({
                ...serverParameters(signer, new AtomicStore()),
                puller: MERCHANT,
            }),
        ).toThrow(/must equal puller/);
        expect(() =>
            subscription({
                ...serverParameters(signer, new AtomicStore()),
                store: { delete: async () => {}, get: async () => null, put: async () => {} } as never,
            }),
        ).toThrow(/atomic reserve/);
        expect(() => subscription({ ...serverParameters(signer, new AtomicStore({})) })).toThrow(
            /isShared=true and isDurable=true/,
        );
        expect(() => subscription({ ...serverParameters(signer, new AtomicStore({ isShared: true })) })).toThrow(
            /isShared=true and isDurable=true/,
        );
        expect(() => subscription({ ...serverParameters(signer, new AtomicStore({ isDurable: true })) })).toThrow(
            /isShared=true and isDurable=true/,
        );
        expect(() =>
            subscription({
                ...serverParameters(signer, new AtomicStore({})),
                network: 'localnet',
            }),
        ).not.toThrow();
    });
});

describe('canonical pre-sign validation', () => {
    test('accepts the generated activation and rejects every challenged snapshot divergence', async () => {
        const { challengedRequest, serverSigner, subscriber, transaction } = await fixture();
        globalThis.fetch = async () =>
            rpcSuccess(accountInfo(authorityAccount(subscriber.address, serverSigner.address)));

        await expect(
            __testing.validateActivationInstructions(transaction, challengedRequest, 'https://mock-rpc'),
        ).resolves.toBe(subscriber.address);

        const mutations: Array<[string, (value: ReturnType<typeof request>) => void]> = [
            ['merchant', value => (value.methodDetails.merchant = RECIPIENT)],
            ['plan', value => (value.methodDetails.planId = RECIPIENT)],
            ['plan id', value => (value.methodDetails.planIdNumeric = '8')],
            ['plan bump', value => (value.methodDetails.planBump = 1)],
            ['created at', value => (value.methodDetails.expectedCreatedAt = '1')],
            ['period', value => (value.methodDetails.expectedPeriodHours = '24')],
            ['amount', value => (value.amount = '999')],
            ['recipient', value => (value.recipient = MERCHANT)],
            ['puller', value => (value.methodDetails.puller = MERCHANT)],
            ['token program', value => (value.methodDetails.tokenProgram = SUBSCRIPTIONS_PROGRAM)],
        ];
        for (const [label, mutate] of mutations) {
            const changed = structuredClone(challengedRequest);
            mutate(changed);
            await expect(
                __testing.validateActivationInstructions(transaction, changed, 'https://mock-rpc'),
                label,
            ).rejects.toThrow();
        }
    });

    test('rejects when SubscribeData init id differs from the live authority account', async () => {
        const { challengedRequest, serverSigner, subscriber, transaction } = await fixture();
        const different = getBase64Codec().decode(
            getSubscriptionAuthorityEncoder().encode({
                bump: 253,
                discriminator: 4,
                initId: INIT_ID + 1n,
                payer: serverSigner.address,
                tokenMint: address(MINT),
                user: subscriber.address,
            }),
        );
        globalThis.fetch = async () => rpcSuccess(accountInfo(different));
        await expect(
            __testing.validateActivationInstructions(transaction, challengedRequest, 'https://mock-rpc'),
        ).rejects.toThrow(/init id/);
    });

    test('requires exactly one SetComputeUnitLimit instruction', async () => {
        const { challengedRequest, serverSigner, subscriber, transaction } = await fixture();
        globalThis.fetch = async () =>
            rpcSuccess(accountInfo(authorityAccount(subscriber.address, serverSigner.address)));

        await expect(
            __testing.validateActivationInstructions(
                rewriteComputeUnitLimits(transaction, 0),
                challengedRequest,
                'https://mock-rpc',
            ),
        ).rejects.toThrow(/exactly one SetComputeUnitLimit/);
        await expect(
            __testing.validateActivationInstructions(
                rewriteComputeUnitLimits(transaction, 2),
                challengedRequest,
                'https://mock-rpc',
            ),
        ).rejects.toThrow(/Duplicate compute unit limit/);
    });
});

describe('settlement proof and replay', () => {
    test('rejects signature/push activation before any RPC verification', async () => {
        const serverSigner = await generateKeyPairSigner();
        let fetchCalls = 0;
        globalThis.fetch = async () => {
            fetchCalls += 1;
            return rpcSuccess({});
        };
        const method = subscription(serverParameters(serverSigner, new AtomicStore()));
        await expect(
            method.verify!({
                credential: {
                    challenge: { request: request(serverSigner.address) },
                    payload: { signature: 'never-broadcast', type: 'signature' },
                } as never,
                request: {} as never,
            }),
        ).rejects.toThrow(/signature-mode activation is unsupported/);
        expect(fetchCalls).toBe(0);
    });

    test('does not treat an existing delegation as proof for a different never-broadcast activation', async () => {
        const { authority, challengedRequest, delegation, serverSigner, subscriber, transaction } = await fixture();
        let sendCalls = 0;
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method: string; params?: unknown[] };
            if (body.method === 'getAccountInfo') {
                const account = String(body.params?.[0]);
                if (account === authority) {
                    return rpcSuccess(accountInfo(authorityAccount(subscriber.address, serverSigner.address)));
                }
                if (account === delegation) {
                    return rpcSuccess(accountInfo(delegationAccount(subscriber.address, serverSigner.address)));
                }
                return rpcSuccess({ value: null });
            }
            if (body.method === 'getSignatureStatuses') return rpcSuccess({ value: [null] });
            if (body.method === 'sendTransaction') sendCalls += 1;
            return rpcSuccess({});
        };
        const method = subscription(serverParameters(serverSigner, new AtomicStore()));
        await expect(
            method.verify!({
                credential: credential(transaction, challengedRequest) as never,
                request: challengedRequest as never,
            }),
        ).rejects.toThrow(/submitted activation signature was not confirmed/);
        expect(sendCalls).toBe(0);
    });

    test('preserves an RPC failure when pre-settlement reservation cleanup fails', async () => {
        const { authority, challengedRequest, serverSigner, subscriber, transaction } = await fixture();
        const store = new DeleteFailingStore();
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method: string; params?: unknown[] };
            if (body.method === 'getAccountInfo') {
                if (String(body.params?.[0]) === authority) {
                    return rpcSuccess(accountInfo(authorityAccount(subscriber.address, serverSigner.address)));
                }
                return rpcSuccess({ value: null });
            }
            if (body.method === 'simulateTransaction') return rpcError('simulation unavailable');
            return rpcSuccess({});
        };

        const method = subscription(serverParameters(serverSigner, store));
        const run = () =>
            method.verify!({
                credential: credential(transaction, challengedRequest) as never,
                request: challengedRequest as never,
            });

        await expect(run()).rejects.toThrow(/RPC error: simulation unavailable/);
        expect(store.deleteCalls).toBe(1);
        await expect(run()).rejects.toThrow(/Activation signature already consumed/);
        expect(store.deleteCalls).toBe(1);
    });

    test('preserves a post-settlement terms failure when reservation cleanup fails', async () => {
        const { authority, challengedRequest, delegation, serverSigner, subscriber, transaction } = await fixture();
        const store = new DeleteFailingStore();
        let landed = false;
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method: string; params?: unknown[] };
            if (body.method === 'getAccountInfo') {
                const account = String(body.params?.[0]);
                if (account === authority) {
                    return rpcSuccess(accountInfo(authorityAccount(subscriber.address, serverSigner.address)));
                }
                if (account === delegation) {
                    return rpcSuccess(
                        landed
                            ? accountInfo(delegationAccount(subscriber.address, serverSigner.address, 1n))
                            : { value: null },
                    );
                }
                return rpcSuccess({ value: null });
            }
            if (body.method === 'simulateTransaction') return rpcSuccess({ value: { err: null, logs: [] } });
            if (body.method === 'sendTransaction') {
                landed = true;
                const wire = String(body.params?.[0]);
                const decoded = getTransactionDecoder().decode(getBase64Codec().encode(wire));
                return rpcSuccess(getSignatureFromTransaction(decoded));
            }
            if (body.method === 'getSignatureStatuses') {
                return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
            }
            return rpcSuccess({});
        };

        const method = subscription(serverParameters(serverSigner, store));
        const run = () =>
            method.verify!({
                credential: credential(transaction, challengedRequest) as never,
                request: challengedRequest as never,
            });

        await expect(run()).rejects.toThrow(/SubscriptionDelegation amount mismatch/);
        expect(store.deleteCalls).toBe(1);
        await expect(run()).rejects.toThrow(/Activation signature already consumed/);
        expect(store.deleteCalls).toBe(1);
    });

    test('two independent handlers sharing only an atomic store admit exactly one activation', async () => {
        const { authority, challengedRequest, delegation, serverSigner, subscriber, transaction } = await fixture();
        const store = new AtomicStore();
        let landed = false;
        let sendCalls = 0;
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method: string; params?: unknown[] };
            if (body.method === 'getAccountInfo') {
                const account = String(body.params?.[0]);
                if (account === authority) {
                    return rpcSuccess(accountInfo(authorityAccount(subscriber.address, serverSigner.address)));
                }
                if (account === delegation) {
                    return rpcSuccess(
                        landed
                            ? accountInfo(delegationAccount(subscriber.address, serverSigner.address))
                            : { value: null },
                    );
                }
                return rpcSuccess({ value: null });
            }
            if (body.method === 'simulateTransaction') return rpcSuccess({ value: { err: null, logs: [] } });
            if (body.method === 'sendTransaction') {
                sendCalls += 1;
                landed = true;
                const wire = String(body.params?.[0]);
                const decoded = getTransactionDecoder().decode(getBase64Codec().encode(wire));
                return rpcSuccess(getSignatureFromTransaction(decoded));
            }
            if (body.method === 'getSignatureStatuses') {
                return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
            }
            return rpcSuccess({});
        };

        const first = subscription(serverParameters(serverSigner, store));
        const second = subscription(serverParameters(serverSigner, store));
        const run = (method: ReturnType<typeof subscription>) =>
            method.verify!({
                credential: credential(transaction, challengedRequest) as never,
                request: challengedRequest as never,
            });
        const results = await Promise.allSettled([run(first), run(second)]);
        const fulfilled = results.filter(result => result.status === 'fulfilled');
        expect(fulfilled).toHaveLength(1);
        expect(results.filter(result => result.status === 'rejected')).toHaveLength(1);
        expect(sendCalls).toBe(1);
        expect(fulfilled[0]).toMatchObject({
            status: 'fulfilled',
            value: {
                challengeId: 'challenge-id',
                externalId: 'invoice-42',
                periodIndex: '0',
                planId: PLAN_ID,
            },
        });
        if (fulfilled[0]?.status !== 'fulfilled') throw new Error('expected one successful activation receipt');
        expect(fulfilled[0].value).toHaveProperty('subscriptionId');
        expect(fulfilled[0].value).toHaveProperty('periodStartTs');
        expect(fulfilled[0].value).toHaveProperty('periodEndTs');
    });
});

describe('cross-route subscription binding', () => {
    test('serializes an explicit empty split list for credential binding', async () => {
        const serverSigner = await generateKeyPairSigner();
        const gate = Mppx.create({
            methods: [subscription({ ...serverParameters(serverSigner, new AtomicStore()), splits: [] })],
            realm: 'subscription-empty-splits',
            secretKey: 'subscription-empty-splits-secret',
        });

        const issued = await gate.subscription({
            amount: '10000000',
            currency: MINT,
            expires: new Date(Date.now() + 60_000).toISOString(),
        })(new Request('https://example.test/gate'));

        expect(issued.status).toBe(402);
        if (issued.status !== 402) throw new Error('expected subscription challenge');
        expect((Challenge.fromResponse(issued.challenge).request.methodDetails as { splits?: unknown }).splits).toEqual(
            [],
        );
    });

    test('rejects a valid gate-A credential before RPC when gate-B subscription fields diverge', async () => {
        const { serverSigner, transaction } = await fixture();
        const secretKey = 'subscription-binding-test-secret';
        const expires = new Date(Date.now() + 60_000).toISOString();
        let fetchCalls = 0;
        globalThis.fetch = async () => {
            fetchCalls += 1;
            return rpcSuccess({});
        };

        const gateA = Mppx.create({
            methods: [subscription(serverParameters(serverSigner, new AtomicStore()))],
            realm: 'subscription-binding-test',
            secretKey,
        });
        const issued = await gateA.subscription({
            amount: '10000000',
            currency: MINT,
            expires,
            externalId: 'invoice-42',
            resource: '/gate-a',
        })(new Request('https://example.test/gate-a'));
        expect(issued.status).toBe(402);
        if (issued.status !== 402) throw new Error('expected subscription challenge');

        const credentialFromGateA = Credential.from({
            challenge: Challenge.fromResponse(issued.challenge),
            payload: { transaction, type: 'transaction' },
        });
        fetchCalls = 0;

        const alternateFeePayer = await generateKeyPairSigner();
        const variants = [
            {
                label: 'plan',
                parameters: {
                    ...serverParameters(serverSigner, new AtomicStore()),
                    planId: RECIPIENT,
                    planIdNumeric: 8n,
                },
            },
            {
                label: 'period',
                parameters: { ...serverParameters(serverSigner, new AtomicStore()), periodCount: 1 },
            },
            {
                label: 'puller and fee payer',
                parameters: {
                    ...serverParameters(alternateFeePayer, new AtomicStore()),
                    puller: alternateFeePayer.address,
                },
            },
            {
                label: 'token program',
                parameters: { ...serverParameters(serverSigner, new AtomicStore()), tokenProgram: TOKEN_2022_PROGRAM },
            },
            {
                label: 'subscription program',
                parameters: { ...serverParameters(serverSigner, new AtomicStore()), programId: RECIPIENT },
            },
            {
                label: 'external id',
                parameters: serverParameters(serverSigner, new AtomicStore()),
                request: { externalId: 'invoice-43' },
            },
            {
                label: 'resource',
                parameters: serverParameters(serverSigner, new AtomicStore()),
                request: { resource: '/gate-b' },
            },
        ];

        for (const variant of variants) {
            const gateB = Mppx.create({
                methods: [subscription(variant.parameters)],
                realm: 'subscription-binding-test',
                secretKey,
            });
            const result = await gateB.subscription({
                amount: '10000000',
                currency: MINT,
                expires,
                externalId: variant.request?.externalId ?? 'invoice-42',
                resource: variant.request?.resource ?? '/gate-a',
            })(
                new Request('https://example.test/gate-b', {
                    headers: { Authorization: Credential.serialize(credentialFromGateA) },
                }),
            );

            expect(result.status, variant.label).toBe(402);
            expect(fetchCalls, variant.label).toBe(0);
        }
    });

    test('uses the HMAC-bound resource to bind routes, not the top-level description', async () => {
        const { authority, delegation, serverSigner, subscriber } = await fixture();
        const secretKey = 'subscription-description-binding-test-secret';
        const expires = new Date(Date.now() + 60_000).toISOString();
        let fetchCalls = 0;
        let landed = false;
        globalThis.fetch = async (_input, init) => {
            fetchCalls += 1;
            const body = JSON.parse(init?.body as string) as { method: string; params?: unknown[] };
            if (body.method === 'getLatestBlockhash') return rpcSuccess({ value: { blockhash: BLOCKHASH } });
            if (body.method === 'getAccountInfo') {
                const account = String(body.params?.[0]);
                if (account === authority) {
                    return rpcSuccess(accountInfo(authorityAccount(subscriber.address, serverSigner.address)));
                }
                if (account === delegation) {
                    return rpcSuccess(
                        landed
                            ? accountInfo(delegationAccount(subscriber.address, serverSigner.address))
                            : { value: null },
                    );
                }
                return rpcSuccess({ value: null });
            }
            if (body.method === 'simulateTransaction') return rpcSuccess({ value: { err: null, logs: [] } });
            if (body.method === 'sendTransaction') {
                landed = true;
                const wire = String(body.params?.[0]);
                const decoded = getTransactionDecoder().decode(getBase64Codec().encode(wire));
                return rpcSuccess(getSignatureFromTransaction(decoded));
            }
            if (body.method === 'getSignatureStatuses') {
                return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
            }
            return rpcSuccess({});
        };

        const gateA = Mppx.create({
            methods: [subscription(serverParameters(serverSigner, new AtomicStore()))],
            realm: 'subscription-description-binding-test',
            secretKey,
        });
        const routeA = {
            amount: '10000000',
            currency: MINT,
            description: 'subscription access for team A',
            expires,
            resource: '/subscriptions/team-a',
        };
        const issued = await gateA.subscription(routeA)(new Request('https://example.test/gate-a'));

        expect(issued.status).toBe(402);
        if (issued.status !== 402) throw new Error('expected subscription challenge');
        const challenge = Challenge.fromResponse(issued.challenge);
        const transaction = await buildSubscriptionActivationTransaction({
            request: challenge.request as Parameters<typeof buildSubscriptionActivationTransaction>[0]['request'],
            signer: subscriber,
            subscriptionAuthorityInitId: INIT_ID,
        });
        const credentialFromGateA = Credential.from({
            challenge,
            payload: { transaction, type: 'transaction' },
        });

        fetchCalls = 0;
        const sameRoute = await gateA.subscription(routeA)(
            new Request('https://example.test/gate-a', {
                headers: { Authorization: Credential.serialize(credentialFromGateA) },
            }),
        );
        expect(sameRoute.status).toBe(200);
        expect(fetchCalls).toBeGreaterThan(0);

        const gateB = Mppx.create({
            methods: [subscription(serverParameters(serverSigner, new AtomicStore()))],
            realm: 'subscription-description-binding-test',
            secretKey,
        });
        const { resource: _resource, ...requestWithoutResource } = credentialFromGateA.challenge.request;
        const credentialVariants = [
            { credential: credentialFromGateA, label: 'original credential' },
            {
                credential: {
                    ...credentialFromGateA,
                    challenge: { ...credentialFromGateA.challenge, description: 'subscription access for team B' },
                },
                label: 'mutated description',
            },
            {
                credential: {
                    ...credentialFromGateA,
                    challenge: { ...credentialFromGateA.challenge, description: undefined },
                },
                label: 'stripped description',
            },
            {
                credential: {
                    ...credentialFromGateA,
                    challenge: {
                        ...credentialFromGateA.challenge,
                        request: { ...credentialFromGateA.challenge.request, resource: '/subscriptions/team-b' },
                    },
                },
                label: 'mutated resource',
            },
            {
                credential: {
                    ...credentialFromGateA,
                    challenge: { ...credentialFromGateA.challenge, request: requestWithoutResource },
                },
                label: 'stripped resource',
            },
        ];

        for (const variant of credentialVariants) {
            fetchCalls = 0;
            const result = await gateB.subscription({
                amount: '10000000',
                currency: MINT,
                description: 'subscription access for team B',
                expires,
                resource: '/subscriptions/team-b',
            })(
                new Request('https://example.test/gate-b', {
                    headers: { Authorization: Credential.serialize(variant.credential) },
                }),
            );

            expect(result.status, variant.label).toBe(402);
            expect(fetchCalls, variant.label).toBe(0);
        }
    });
});

function rpcSuccess(result: unknown) {
    return new Response(JSON.stringify({ id: 1, jsonrpc: '2.0', result }), {
        headers: { 'Content-Type': 'application/json' },
    });
}

function rpcError(message: string) {
    return new Response(JSON.stringify({ error: { message }, id: 1, jsonrpc: '2.0' }), {
        headers: { 'Content-Type': 'application/json' },
    });
}
