import { generateKeyPairSigner } from '@solana/kit';
import { describe, expect, test } from 'vitest';

import * as Methods from '../Methods.js';
import { ActiveSession, signSessionAuthentication, verifySessionAuthentication } from '../client/Session.js';
import { session as serverSession } from '../server/Session.js';
import { createMemorySessionStore } from '../server/session/store.js';

const CHANNEL_PROGRAM = 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX';
const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';

function request(recipient: string) {
    return {
        amount: '100',
        currency: 'USDC',
        description: 'metered inference',
        minimumDeposit: '1000',
        recipient,
        suggestedDeposit: '5000',
        unitType: 'request',
        methodDetails: {
            channelProgram: CHANNEL_PROGRAM,
            gracePeriodSeconds: 900,
            idleTimeoutOptionsSeconds: [60, 300],
            idleTimeoutSeconds: 300,
            network: 'devnet',
            tokenProgram: TOKEN_PROGRAM,
            voucherSigner: 'operator' as const,
        },
    };
}

describe('final session wire contract', () => {
    test('accepts the PR #309 request fields and rejects the superseded draft', () => {
        const recipient = '11111111111111111111111111111111';
        expect(Methods.session.schema.request.parse(request(recipient))).toEqual(request(recipient));

        expect(() =>
            Methods.session.schema.request.parse({
                cap: '5000',
                currency: 'USDC',
                network: 'devnet',
                programId: CHANNEL_PROGRAM,
                recipient,
            }),
        ).toThrow();
    });

    test('uses exact open/topUp field names and has no voucher nonce', async () => {
        const signer = await generateKeyPairSigner();
        const channel = await generateKeyPairSigner();
        const session = new ActiveSession({ channelId: channel.address, signer });
        const voucher = await session.signVoucher(25n);

        expect(voucher.voucher).toEqual({
            channelId: channel.address,
            cumulativeAmount: '25',
            expiresAt: session.expiresAt,
        });
        expect(voucher.voucher).not.toHaveProperty('nonce');
        expect(session.topUpAction(75n, 'wire')).toEqual({
            action: 'topUp',
            additionalAmount: '75',
            channelId: channel.address,
            transaction: 'wire',
        });
        expect(() =>
            Methods.session.schema.credential.payload.parse({
                action: 'topUp',
                channelId: channel.address,
                newDeposit: '75',
                signature: 'legacy',
            }),
        ).toThrow();
    });

    test('binds reusable authentication to the opening challenge, payer, and channel', async () => {
        const payer = await generateKeyPairSigner();
        const channel = await generateKeyPairSigner();
        const otherChannel = await generateKeyPairSigner();
        const proof = await signSessionAuthentication({
            challengeId: 'opening-challenge',
            channelId: channel.address,
            signer: payer,
        });

        await expect(verifySessionAuthentication(proof, channel.address)).resolves.toBe(true);
        await expect(verifySessionAuthentication(proof, otherChannel.address)).resolves.toBe(false);
        expect(proof).not.toHaveProperty('authenticationExpires');
    });

    test('allows an expired challenge for idempotent use after open', async () => {
        const payer = await generateKeyPairSigner();
        const operator = await generateKeyPairSigner();
        const channel = await generateKeyPairSigner();
        const store = createMemorySessionStore();
        const authentication = await signSessionAuthentication({
            challengeId: 'opening-challenge',
            channelId: channel.address,
            signer: payer,
        });
        await store.updateChannel(channel.address, () => ({
            authentication,
            authorizedSigner: operator.address,
            channelId: channel.address,
            committedDeliveries: [],
            cumulative: 0n,
            deposit: 1_000n,
            idleTimeoutSeconds: 300,
            lastActivityAt: Date.now(),
            nextDeliverySequence: 0n,
            openingChallengeId: 'opening-challenge',
            payer: payer.address,
            pendingDeliveries: [],
            processedUses: [],
            rentPayer: payer.address,
            sealed: false,
            settledOnChain: 0n,
            spentAmount: 0n,
            voucherSigner: 'operator',
        }));
        const method = serverSession({
            amount: 100n,
            currency: 'USDC',
            gracePeriodSeconds: 900,
            network: 'devnet',
            operatorVoucherSigner: operator,
            recipient: payer.address,
            rpc: {} as never,
            signer: operator,
            store,
            voucherSigner: 'operator',
        });
        const challenge = {
            expires: '2000-01-01T00:00:00.000Z',
            id: 'use-challenge',
            intent: 'session' as const,
            method: 'solana' as const,
            realm: 'example.test',
            request: request(payer.address),
        };
        const credential = {
            challenge,
            payload: { action: 'use' as const, authentication, channelId: channel.address },
        };
        const envelope = {
            capturedRequest: {
                headers: new Headers({ 'Idempotency-Key': 'request-1' }),
                method: 'POST',
                url: new URL('https://example.test/inference'),
            },
            challenge,
            credential,
            request: challenge.request,
        };

        await method.verify({ credential, envelope, request: challenge.request });
        const retryChallenge = {
            ...challenge,
            id: 'retry-challenge',
            request: { ...challenge.request, amount: '999' },
        };
        await method.verify({
            credential: { ...credential, challenge: retryChallenge },
            envelope: {
                ...envelope,
                challenge: retryChallenge,
                credential: { ...credential, challenge: retryChallenge },
                request: retryChallenge.request,
            },
            request: retryChallenge.request,
        });

        const state = await store.getChannel(channel.address);
        expect(state?.cumulative).toBe(100n);
        expect(state?.spentAmount).toBe(100n);
        expect(state?.processedUses).toHaveLength(1);
    });

    test('requires open to carry a still-valid challenge', async () => {
        const signer = await generateKeyPairSigner();
        const channel = await generateKeyPairSigner();
        const method = serverSession({
            amount: 100n,
            currency: 'USDC',
            gracePeriodSeconds: 900,
            network: 'devnet',
            recipient: signer.address,
            rpc: {} as never,
            signer,
        });
        const expiredChallenge = {
            expires: '2000-01-01T00:00:00.000Z',
            id: 'open-challenge',
            intent: 'session' as const,
            method: 'solana' as const,
            realm: 'example.test',
            request: request(signer.address),
        };

        const credential = {
            challenge: expiredChallenge,
            payload: {
                action: 'open' as const,
                authorizedSigner: signer.address,
                channelId: channel.address,
                depositAmount: '1000',
                gracePeriodSeconds: 900,
                mint: signer.address,
                openSlot: '1',
                payee: signer.address,
                payer: signer.address,
                salt: '1',
                transaction: 'wire',
            },
        };

        await expect(method.verify({ credential, request: expiredChallenge.request })).rejects.toThrow(
            'challenge expired',
        );
    });
});
