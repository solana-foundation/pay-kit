/**
 * Behavioral coverage for `SessionFetchClient` watermark isolation and commit
 * failure recovery: re-opening on a new channel flushes the old channel before
 * the swap, a failed commit surfaces exactly once without poisoning the
 * client, and retries re-sign the same cumulative instead of dropping deltas.
 *
 * Written against the reworked cascade session protocol: challenges carry
 * `methodDetails.recentBlockhash`/`recentSlot`, open payloads echo `openSlot`,
 * and commits POST the signed voucher in the JSON body.
 */
import { generateKeyPairSigner } from '@solana/kit';
import { Challenge } from 'mppx';
import { describe, expect, test } from 'vitest';

import {
    ActiveSession,
    createSessionFetch,
    type SessionChallenge,
    type SessionOpener,
    type SignedVoucher,
    USDC,
} from '../client/index.js';

type FetchInit = Parameters<typeof globalThis.fetch>[1];

const CHALLENGED_BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';
const CHALLENGED_SLOT = '9042';
const CHANNEL_PROGRAM = 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX';
const DIRECTIVE_EXPIRES_AT = 4_102_444_800;
const recipient = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';

interface CommitAttempt {
    readonly amount: string;
    readonly deliveryId: string;
    readonly voucherChannelId: string;
    readonly voucherCumulative: string;
}

interface DeliveryLog {
    readonly amount: string;
    readonly deliveryId: string;
    readonly sessionId: string;
}

interface GatewayMock {
    /** All commit attempts, including ones the gateway failed. */
    readonly commitAttempts: CommitAttempt[];
    /** Successfully committed vouchers. */
    readonly commits: CommitAttempt[];
    readonly deliveries: DeliveryLog[];
    failNextCommits: number;
    readonly fetch: typeof globalThis.fetch;
}

function sessionChallenge(): SessionChallenge {
    return {
        id: 'session-fetch-test',
        intent: 'session',
        method: 'solana',
        realm: 'test',
        request: {
            amount: '1',
            currency: 'USDC',
            methodDetails: {
                channelProgram: CHANNEL_PROGRAM,
                gracePeriodSeconds: 900,
                minVoucherDelta: '1',
                network: 'localnet',
                recentBlockhash: CHALLENGED_BLOCKHASH,
                recentSlot: CHALLENGED_SLOT,
            },
            recipient,
            suggestedDeposit: '1000000',
        },
    };
}

function createGatewayMock(): GatewayMock {
    const commitAttempts: CommitAttempt[] = [];
    const commits: CommitAttempt[] = [];
    const deliveries: DeliveryLog[] = [];
    const gateway: GatewayMock = {
        commitAttempts,
        commits,
        deliveries,
        failNextCommits: 0,
        fetch: async (input, init) => {
            const url = new URL(fetchUrl(input));
            const headers = new Headers(init?.headers);

            if (url.pathname === '/v1/work') {
                if (!headers.has('authorization')) {
                    return new Response(null, {
                        headers: { 'WWW-Authenticate': Challenge.serialize(sessionChallenge()) },
                        status: 402,
                    });
                }
                return new Response('ok', { status: 200 });
            }

            if (url.pathname === '/__402/session/deliveries') {
                const body = parseJsonBody(init);
                const delivery: DeliveryLog = {
                    amount: expectString(body.amount),
                    deliveryId: expectString(body.deliveryId),
                    sessionId: expectString(body.sessionId),
                };
                deliveries.push(delivery);
                return Response.json({
                    amount: delivery.amount,
                    commitUrl: 'https://api.test/session/commit',
                    currency: 'USDC',
                    deliveryId: delivery.deliveryId,
                    expiresAt: DIRECTIVE_EXPIRES_AT,
                    sequence: deliveries.length,
                    sessionId: delivery.sessionId,
                });
            }

            if (url.pathname === '/session/commit') {
                const body = parseJsonBody(init);
                const voucher = body.voucher as SignedVoucher;
                const attempt: CommitAttempt = {
                    amount: expectString(body.amount),
                    deliveryId: expectString(body.deliveryId),
                    voucherChannelId: voucher.voucher.channelId,
                    voucherCumulative: voucher.voucher.cumulativeAmount,
                };
                commitAttempts.push(attempt);
                if (gateway.failNextCommits > 0) {
                    gateway.failNextCommits -= 1;
                    return new Response('simulated outage', { status: 500 });
                }
                commits.push(attempt);
                return Response.json({
                    amount: attempt.amount,
                    cumulative: attempt.voucherCumulative,
                    deliveryId: attempt.deliveryId,
                    sessionId: attempt.voucherChannelId,
                    status: 'committed',
                });
            }

            return new Response(`unexpected ${url.href}`, { status: 500 });
        },
    };
    return gateway;
}

function makeOpener(sessions: ActiveSession[]): SessionOpener {
    return async ({ challenge }) => {
        const signer = await generateKeyPairSigner();
        const channel = await generateKeyPairSigner();
        const session = new ActiveSession({ channelId: channel.address, signer });
        sessions.push(session);
        return {
            payload: session.openPaymentChannelAction({
                depositAmount: challenge.request.suggestedDeposit ?? '0',
                gracePeriodSeconds: challenge.request.methodDetails.gracePeriodSeconds ?? 900,
                mint: USDC.mainnet!,
                openSlot: challenge.request.methodDetails.recentSlot ?? '0',
                payee: challenge.request.recipient,
                payer: signer.address,
                salt: '1',
                transaction: 'wire',
            }),
            session,
        };
    };
}

describe('SessionFetchClient watermark isolation', () => {
    test('re-opening on a new channel flushes the old channel and resets the watermark', async () => {
        const gateway = createGatewayMock();
        const sessions: ActiveSession[] = [];
        const client = createSessionFetch({
            fetch: gateway.fetch,
            liveCommitIntervalMs: 60_000,
            opener: makeOpener(sessions),
        });

        await client.fetch('https://api.test/v1/work');
        const sessionA = sessions[0]!;
        client.recordCumulative(100, { force: true });
        await client.flush();
        // Recorded inside the live commit interval, so this stays a pending target.
        client.recordCumulative(250);
        expect(client.targetCumulativeAmount).toBe('250');

        // A plain fetch has no authorization header, so the gateway issues a
        // fresh 402 and the opener creates a brand new channel.
        await client.fetch('https://api.test/v1/work');
        const sessionB = sessions[1]!;
        expect(sessionB.channelId).not.toBe(sessionA.channelId);

        // The pending 250 was flushed against the OLD channel before the swap
        // and the new channel starts with no inherited target.
        expect(sessionA.cumulative).toBe(250n);
        expect(client.targetCumulativeAmount).toBeUndefined();
        expect(client.cumulativeAmount).toBe('0');

        client.recordCumulative(50, { force: true });
        const receipt = await client.flush();
        expect(receipt).toMatchObject({ amount: '50', cumulative: '50', status: 'committed' });

        expect(gateway.commits.map(commit => [commit.voucherChannelId, commit.voucherCumulative])).toEqual([
            [sessionA.channelId, '100'],
            [sessionA.channelId, '250'],
            [sessionB.channelId, '50'],
        ]);
        // No voucher ever signed a cumulative the new channel did not meter.
        for (const commit of gateway.commitAttempts) {
            if (commit.voucherChannelId === sessionB.channelId) {
                expect(BigInt(commit.voucherCumulative) <= sessionB.cumulative).toBe(true);
            }
        }
    });

    test('a failed commit surfaces once, then a retry commits the same cumulative', async () => {
        const gateway = createGatewayMock();
        const sessions: ActiveSession[] = [];
        const client = createSessionFetch({
            fetch: gateway.fetch,
            liveCommitIntervalMs: 60_000,
            opener: makeOpener(sessions),
        });

        await client.fetch('https://api.test/v1/work');
        const session = sessions[0]!;

        gateway.failNextCommits = 1;
        client.recordCumulative(100, { force: true });
        await expect(client.flush()).rejects.toThrow('session commit returned 500');

        // The failure did not advance any local state…
        expect(session.cumulative).toBe(0n);
        // …and the client is not poisoned: the retry signs the same cumulative.
        const receipt = await client.flush();
        expect(receipt).toMatchObject({ amount: '100', cumulative: '100', status: 'committed' });
        expect(gateway.commitAttempts.map(attempt => attempt.voucherCumulative)).toEqual(['100', '100']);
        expect(gateway.commits.map(commit => commit.voucherCumulative)).toEqual(['100']);
        expect(session.cumulative).toBe(100n);

        // Subsequent commits keep working after recovery.
        client.recordCumulative(150, { force: true });
        await expect(client.flush()).resolves.toMatchObject({ amount: '50', cumulative: '150' });
    });

    test('commitCumulative recovers after a transient failure without dropping the delta', async () => {
        const gateway = createGatewayMock();
        const sessions: ActiveSession[] = [];
        const client = createSessionFetch({
            fetch: gateway.fetch,
            opener: makeOpener(sessions),
        });

        await client.fetch('https://api.test/v1/work');
        gateway.failNextCommits = 1;
        await expect(client.commitCumulative(75)).rejects.toThrow('session commit returned 500');
        await expect(client.commitCumulative(75)).resolves.toMatchObject({ amount: '75', cumulative: '75' });
        expect(sessions[0]!.cumulative).toBe(75n);
    });
});

function fetchUrl(input: Parameters<typeof globalThis.fetch>[0]): string {
    if (input instanceof Request) return input.url;
    return String(input);
}

function parseJsonBody(init: FetchInit): Record<string, unknown> {
    if (typeof init?.body !== 'string') {
        throw new Error('expected JSON string body');
    }
    const parsed: unknown = JSON.parse(init.body);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('expected JSON object body');
    }
    return parsed as Record<string, unknown>;
}

function expectString(value: unknown): string {
    if (typeof value !== 'string') {
        throw new Error('expected string');
    }
    return value;
}
