import { afterEach, describe, expect, test } from 'vitest';
import {
    address,
    type Blockhash,
    generateKeyPairSigner,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
} from '@solana/kit';

import { ASSOCIATED_TOKEN_PROGRAM, SUBSCRIPTIONS_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM } from '../constants.js';
import {
    buildSubscriptionActivationTransaction,
    initializeSubscriptionAuthority,
    subscription,
} from '../client/Subscription.js';
import { getSubscriptionAuthorityEncoder } from '../generated/subscriptions/accounts/subscriptionAuthority.js';
import {
    getSubscribeInstructionDataDecoder,
    SUBSCRIBE_DISCRIMINATOR,
} from '../generated/subscriptions/instructions/subscribe.js';
import {
    getTransferSubscriptionInstructionDataDecoder,
    TRANSFER_SUBSCRIPTION_DISCRIMINATOR,
} from '../generated/subscriptions/instructions/transferSubscription.js';
import { findEventAuthorityPda } from '../generated/subscriptions/pdas/eventAuthority.js';

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

function request(feePayerKey: string, tokenProgram = TOKEN_PROGRAM) {
    return {
        amount: '10000000',
        currency: MINT,
        externalId: 'invoice-42',
        methodDetails: {
            decimals: 6,
            expectedCreatedAt: '1700000000',
            expectedPeriodHours: '720',
            feePayer: true,
            feePayerKey,
            merchant: MERCHANT,
            mint: MINT,
            network: 'devnet',
            planBump: 254,
            planId: PLAN_ID,
            planIdNumeric: '7',
            programId: SUBSCRIPTIONS_PROGRAM,
            puller: feePayerKey,
            recentBlockhash: BLOCKHASH,
            tokenProgram,
        },
        periodCount: '30',
        periodUnit: 'day' as const,
        recipient: RECIPIENT,
    };
}

function decodeWire(encoded: string) {
    const transaction = getTransactionDecoder().decode(getBase64Codec().encode(encoded));
    return getCompiledTransactionMessageDecoder().decode(transaction.messageBytes) as unknown as {
        header: { numSignerAccounts: number };
        instructions: Array<{ accountIndices: number[]; data: Uint8Array; programAddressIndex: number }>;
        staticAccounts: string[];
    };
}

describe('canonical subscription activation builder', () => {
    test('uses generated canonical data/account layouts and never broadcasts', async () => {
        const subscriber = await generateKeyPairSigner();
        const server = await generateKeyPairSigner();
        let fetchCalls = 0;
        globalThis.fetch = async () => {
            fetchCalls += 1;
            throw new Error('builder must not access the network when the challenge pins a blockhash');
        };

        const encoded = await buildSubscriptionActivationTransaction({
            request: request(server.address),
            signer: subscriber,
            subscriptionAuthorityInitId: INIT_ID,
        });
        expect(fetchCalls).toBe(0);

        const message = decodeWire(encoded);
        expect(message.staticAccounts[0]).toBe(server.address);
        expect(message.header.numSignerAccounts).toBe(2);

        const programInstructions = message.instructions.filter(
            ix => message.staticAccounts[ix.programAddressIndex] === SUBSCRIPTIONS_PROGRAM,
        );
        expect(programInstructions).toHaveLength(2);

        const subscribeIx = programInstructions.find(ix => ix.data[0] === SUBSCRIBE_DISCRIMINATOR)!;
        const subscribeData = getSubscribeInstructionDataDecoder().decode(subscribeIx.data).subscribeData;
        expect(subscribeIx.accountIndices).toHaveLength(9);
        expect(subscribeData).toMatchObject({
            expectedAmount: 10_000_000n,
            expectedCreatedAt: 1_700_000_000n,
            expectedMint: address(MINT),
            expectedPeriodHours: 720n,
            expectedSubscriptionAuthorityInitId: INIT_ID,
            planBump: 254,
            planId: 7n,
        });

        const transferIx = programInstructions.find(ix => ix.data[0] === TRANSFER_SUBSCRIPTION_DISCRIMINATOR)!;
        const transferData = getTransferSubscriptionInstructionDataDecoder().decode(transferIx.data).transferData;
        expect(transferIx.accountIndices).toHaveLength(10);
        expect(transferData).toEqual({
            amount: 10_000_000n,
            delegator: subscriber.address,
            mint: address(MINT),
        });

        const ataInstructions = message.instructions.filter(
            ix => message.staticAccounts[ix.programAddressIndex] === ASSOCIATED_TOKEN_PROGRAM,
        );
        expect(ataInstructions).toHaveLength(2);
        expect(ataInstructions.every(ix => ix.data.length === 1 && ix.data[0] === 1)).toBe(true);
    });

    test('uses the challenged Token-2022 program for both ATA layouts', async () => {
        const subscriber = await generateKeyPairSigner();
        const server = await generateKeyPairSigner();
        const message = decodeWire(
            await buildSubscriptionActivationTransaction({
                request: request(server.address, TOKEN_2022_PROGRAM),
                signer: subscriber,
                subscriptionAuthorityInitId: INIT_ID,
            }),
        );
        const ataInstructions = message.instructions.filter(
            ix => message.staticAccounts[ix.programAddressIndex] === ASSOCIATED_TOKEN_PROGRAM,
        );
        for (const ix of ataInstructions) {
            expect(message.staticAccounts[ix.accountIndices[5]]).toBe(TOKEN_2022_PROGRAM);
        }
    });

    test('derives event authority and self-program from a challenged custom program', async () => {
        const subscriber = await generateKeyPairSigner();
        const server = await generateKeyPairSigner();
        const customProgram = (await generateKeyPairSigner()).address;
        const challenged = request(server.address);
        challenged.methodDetails.programId = customProgram;

        const message = decodeWire(
            await buildSubscriptionActivationTransaction({
                request: challenged,
                signer: subscriber,
                subscriptionAuthorityInitId: INIT_ID,
            }),
        );
        const [eventAuthority] = await findEventAuthorityPda({ programAddress: address(customProgram) });
        const transferIx = message.instructions.find(ix => ix.data[0] === TRANSFER_SUBSCRIPTION_DISCRIMINATOR)!;

        expect(message.staticAccounts[transferIx.accountIndices[8]]).toBe(eventAuthority);
        expect(message.staticAccounts[transferIx.accountIndices[9]]).toBe(customProgram);
    });

    test('rejects inconsistent snapshots and noncanonical fee-payer configuration', async () => {
        const subscriber = await generateKeyPairSigner();
        const server = await generateKeyPairSigner();
        const wrongPeriod = request(server.address);
        wrongPeriod.methodDetails.expectedPeriodHours = '24';
        await expect(
            buildSubscriptionActivationTransaction({
                request: wrongPeriod,
                signer: subscriber,
                subscriptionAuthorityInitId: INIT_ID,
            }),
        ).rejects.toThrow(/expectedPeriodHours/);

        const wrongPuller = request(server.address);
        wrongPuller.methodDetails.puller = MERCHANT;
        await expect(
            buildSubscriptionActivationTransaction({
                request: wrongPuller,
                signer: subscriber,
                subscriptionAuthorityInitId: INIT_ID,
            }),
        ).rejects.toThrow(/feePayerKey must equal puller/);
    });

    test('rejects broadcast:true instead of producing unsupported signature credentials', async () => {
        const subscriber = await generateKeyPairSigner();
        expect(() =>
            subscription({
                broadcast: true,
                signer: subscriber,
                subscriptionAuthorityInitId: INIT_ID,
            } as never),
        ).toThrow(/push activation is unsupported/i);
    });

    test('uses the challenged network RPC for initialization and activation', async () => {
        const subscriber = await generateKeyPairSigner();
        const server = await generateKeyPairSigner();
        const encodedAuthority = getSubscriptionAuthorityEncoder().encode({
            bump: 253,
            discriminator: 4,
            initId: INIT_ID,
            payer: subscriber.address,
            tokenMint: address(MINT),
            user: subscriber.address,
        });
        const requestedUrls: string[] = [];
        globalThis.fetch = async input => {
            requestedUrls.push(String(input));
            return rpcSuccess({
                value: {
                    data: [getBase64Codec().decode(encodedAuthority), 'base64'],
                    executable: false,
                    lamports: 1,
                    owner: SUBSCRIPTIONS_PROGRAM,
                    rentEpoch: 0,
                },
            });
        };

        const method = subscription({ initializeSubscriptionAuthority: true, signer: subscriber });
        await method.createCredential({
            challenge: {
                id: 'challenge-id',
                intent: 'subscription',
                method: 'solana',
                realm: 'test',
                request: request(server.address),
            } as never,
        });

        expect(requestedUrls).toEqual(['https://api.devnet.solana.com']);
    });
});

describe('explicit SubscriptionAuthority initialization', () => {
    test('returns the existing init id without broadcasting', async () => {
        const signer = await generateKeyPairSigner();
        const encoded = getSubscriptionAuthorityEncoder().encode({
            bump: 253,
            discriminator: 4,
            initId: INIT_ID,
            payer: signer.address,
            tokenMint: address(MINT),
            user: signer.address,
        });
        const methods: string[] = [];
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method: string };
            methods.push(body.method);
            return rpcSuccess({
                value: {
                    data: [getBase64Codec().decode(encoded), 'base64'],
                    executable: false,
                    lamports: 1,
                    owner: SUBSCRIPTIONS_PROGRAM,
                    rentEpoch: 0,
                },
            });
        };

        await expect(
            initializeSubscriptionAuthority({
                mint: MINT,
                rpcUrl: 'https://mock-rpc',
                signer,
                tokenProgram: TOKEN_PROGRAM,
            }),
        ).resolves.toBe(INIT_ID);
        expect(methods).toEqual(['getAccountInfo']);
    });

    test('broadcasts only when the explicit helper is invoked for a missing authority', async () => {
        const signer = await generateKeyPairSigner();
        const encoded = getSubscriptionAuthorityEncoder().encode({
            bump: 253,
            discriminator: 4,
            initId: INIT_ID,
            payer: signer.address,
            tokenMint: address(MINT),
            user: signer.address,
        });
        let accountReads = 0;
        const methods: string[] = [];
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method: string };
            methods.push(body.method);
            if (body.method === 'getAccountInfo') {
                accountReads += 1;
                if (accountReads === 1) return rpcSuccess({ value: null });
                return rpcSuccess({
                    value: {
                        data: [getBase64Codec().decode(encoded), 'base64'],
                        executable: false,
                        lamports: 1,
                        owner: SUBSCRIPTIONS_PROGRAM,
                        rentEpoch: 0,
                    },
                });
            }
            if (body.method === 'getLatestBlockhash') {
                return rpcSuccess({ value: { blockhash: BLOCKHASH, lastValidBlockHeight: 1 } });
            }
            if (body.method === 'sendTransaction') return rpcSuccess('init-signature');
            if (body.method === 'getSignatureStatuses') {
                return rpcSuccess({ value: [{ confirmationStatus: 'confirmed', err: null }] });
            }
            return rpcSuccess({});
        };

        await expect(
            initializeSubscriptionAuthority({
                mint: MINT,
                rpcUrl: 'https://mock-rpc',
                signer,
                tokenProgram: TOKEN_PROGRAM,
            }),
        ).resolves.toBe(INIT_ID);
        expect(methods).toContain('sendTransaction');
    });
});

function rpcSuccess(result: unknown) {
    return new Response(JSON.stringify({ id: 1, jsonrpc: '2.0', result }), {
        headers: { 'Content-Type': 'application/json' },
    });
}
