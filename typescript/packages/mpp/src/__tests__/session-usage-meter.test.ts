/**
 * Behavioral coverage for `SessionUsageMeter`: opening a session through the
 * patched fetch, baseline capture, monotonic usage watermarks, throttled and
 * trailing voucher commits, and price validation — all driven through
 * `SessionFetchClient` against a mocked session gateway speaking the reworked
 * cascade session protocol (open payload carries `openSlot`, commits carry the
 * signed voucher in the JSON body).
 */
import { generateKeyPairSigner } from '@solana/kit';
import { Challenge } from 'mppx';
import { describe, expect, test } from 'vitest';

import {
    ActiveSession,
    createSessionFetch,
    createSessionUsageMeter,
    type SessionChallenge,
    type SessionFetchEvent,
    type SessionOpener,
    type SignedVoucher,
    stripRequestHeaders,
    USDC,
} from '../client/index.js';

type FetchInit = Parameters<typeof globalThis.fetch>[1];

const CHALLENGED_BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';
const CHALLENGED_SLOT = '9042';
const CHANNEL_PROGRAM = 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX';
const DIRECTIVE_EXPIRES_AT = 4_102_444_800;
const recipient = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';

interface CommitLog {
    readonly amount: string;
    readonly deliveryId: string;
    readonly voucherCumulative: string;
    readonly voucherSigner: string;
}

interface DeliveryLog {
    readonly amount: string;
    readonly commitUrl: string;
    readonly deliveryId: string;
    readonly sessionId: string;
}

interface SessionGatewayMock {
    readonly commits: CommitLog[];
    readonly deliveries: DeliveryLog[];
    readonly fetch: typeof globalThis.fetch;
    lastAuthorization: string | null;
    retryCount: number;
    sawStrippedHeader: boolean;
}

function sessionChallenge(): SessionChallenge {
    return {
        id: 'gemini-session',
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

/**
 * Test-only opener: fabricates a fresh local channel and answers the challenge
 * with an `open` action shaped like the reworked wire payload. The `openSlot`
 * echoes the challenged `recentSlot`, matching the real openers.
 */
function makeSessionOpener(sessions: ActiveSession[] = []): SessionOpener {
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

function createSessionGatewayMock(): SessionGatewayMock {
    const commits: CommitLog[] = [];
    const deliveries: DeliveryLog[] = [];
    let committedCumulative = 0n;
    const gateway: SessionGatewayMock = {
        commits,
        deliveries,
        fetch: async (input, init) => {
            const url = new URL(fetchUrl(input));
            const headers = new Headers(init?.headers);

            if (url.pathname === '/v1/generate') {
                gateway.sawStrippedHeader ||= headers.has('x-goog-api-key');
                if (!headers.has('authorization')) {
                    return new Response(null, {
                        headers: {
                            'WWW-Authenticate': Challenge.serialize(sessionChallenge()),
                        },
                        status: 402,
                    });
                }

                gateway.lastAuthorization = headers.get('authorization');
                gateway.retryCount += 1;
                return new Response('ok', { status: 200 });
            }

            if (url.pathname === '/__402/session/deliveries') {
                const body = parseJsonBody(init);
                const delivery: DeliveryLog = {
                    amount: expectString(body.amount),
                    commitUrl: expectString(body.commitUrl),
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
                const amount = expectString(body.amount);
                const voucher = body.voucher as SignedVoucher;
                committedCumulative += BigInt(amount);
                commits.push({
                    amount,
                    deliveryId: expectString(body.deliveryId),
                    voucherCumulative: voucher.voucher.cumulativeAmount,
                    voucherSigner: voucher.signer,
                });
                return Response.json({
                    amount,
                    cumulative: committedCumulative.toString(),
                    deliveryId: expectString(body.deliveryId),
                    sessionId: voucher.voucher.channelId,
                    status: 'committed',
                });
            }

            return new Response(`unexpected ${url.href}`, { status: 500 });
        },
        lastAuthorization: null,
        retryCount: 0,
        sawStrippedHeader: false,
    };

    return gateway;
}

describe('SessionUsageMeter', () => {
    test('opens a session through patched fetch and commits throttled cumulative usage', async () => {
        const gateway = createSessionGatewayMock();
        const sessions: ActiveSession[] = [];
        const events: SessionFetchEvent[] = [];
        const client = createSessionFetch({
            fetch: gateway.fetch,
            liveCommitIntervalMs: 60_000,
            onEvent: event => events.push(event),
            opener: makeSessionOpener(sessions),
            prepareRequest: stripRequestHeaders(['x-goog-api-key']),
        });
        const meter = createSessionUsageMeter<number>({
            client,
            priceUsage: (tokens, context) => ({
                cumulativeAmount: (BigInt(context.baselineCumulativeAmount) + BigInt(tokens)).toString(),
                deltaAmount: tokens.toString(),
            }),
        });

        expect(meter.client).toBe(client);
        const response = await meter.withPatchedFetch(async () => {
            return await fetch('https://api.test/v1/generate', {
                headers: {
                    'x-goog-api-key': 'secret',
                },
            });
        });

        expect(response.status).toBe(200);
        expect(gateway.retryCount).toBe(1);
        // The gateway never saw the stripped header, and the paid retry
        // carried a serialized session credential.
        expect(gateway.sawStrippedHeader).toBe(false);
        expect(gateway.lastAuthorization?.startsWith('Payment ')).toBe(true);
        expect(meter.baselineCumulativeAmount).toBeUndefined();
        expect(meter.recordUsage(10)).toBe(true);
        expect(meter.recordUsage(10)).toBe(false);
        expect(meter.recordUsage(25)).toBe(true);

        const receipt = await meter.flush();

        expect(receipt).toMatchObject({ amount: '15', cumulative: '25', status: 'committed' });
        expect(gateway.deliveries.map(delivery => delivery.amount)).toEqual(['10', '15']);
        expect(gateway.commits.map(commit => commit.amount)).toEqual(['10', '15']);
        // Commits carry cumulative vouchers signed by the session key.
        expect(gateway.commits.map(commit => commit.voucherCumulative)).toEqual(['10', '25']);
        expect(gateway.commits.every(commit => commit.voucherSigner === sessions[0]!.authorizedSigner)).toBe(true);
        expect(events.map(event => event.type)).toEqual([
            'challenge',
            'open',
            'retry',
            'watermark',
            'watermark',
            'commit',
            'commit',
        ]);
        expect(client.cumulativeAmount).toBe('25');
    });

    test('schedules a trailing commit when usage advances inside the live commit interval', async () => {
        const gateway = createSessionGatewayMock();
        const events: SessionFetchEvent[] = [];
        const client = createSessionFetch({
            fetch: gateway.fetch,
            liveCommitIntervalMs: 100,
            onEvent: event => events.push(event),
            opener: makeSessionOpener(),
        });
        const meter = createSessionUsageMeter<number>({
            client,
            priceUsage: (tokens, context) => ({
                cumulativeAmount: (BigInt(context.baselineCumulativeAmount) + BigInt(tokens)).toString(),
                deltaAmount: tokens.toString(),
            }),
        });

        await client.fetch('https://api.test/v1/generate');

        expect(meter.recordUsage(10)).toBe(true);
        await waitUntil(() => gateway.commits.length === 1);

        expect(meter.recordUsage(25)).toBe(true);
        expect(gateway.commits.map(commit => commit.amount)).toEqual(['10']);

        await waitUntil(() => gateway.commits.length === 2);

        expect(gateway.deliveries.map(delivery => delivery.amount)).toEqual(['10', '15']);
        expect(gateway.commits.map(commit => commit.amount)).toEqual(['10', '15']);
        expect(events.map(event => event.type)).toEqual([
            'challenge',
            'open',
            'retry',
            'watermark',
            'commit',
            'watermark',
            'commit',
        ]);
        expect(client.cumulativeAmount).toBe('25');
    });

    test('resets the operation baseline while reusing an open session', async () => {
        const gateway = createSessionGatewayMock();
        const client = createSessionFetch({
            fetch: gateway.fetch,
            opener: makeSessionOpener(),
        });
        const meter = createSessionUsageMeter<number>({
            client,
            priceUsage: (tokens, context) => ({
                cumulativeAmount: BigInt(context.baselineCumulativeAmount) + BigInt(tokens),
            }),
        });

        await client.fetch('https://api.test/v1/generate');
        await meter.flush(20);

        meter.resetBaseline();
        await meter.flush(5);

        expect(gateway.commits.map(commit => commit.amount)).toEqual(['20', '5']);
        expect(client.cumulativeAmount).toBe('25');
        expect(meter.baselineCumulativeAmount).toBe('20');
    });

    test('ignores usage until a session is open or a price is available', async () => {
        const gateway = createSessionGatewayMock();
        const client = createSessionFetch({
            fetch: gateway.fetch,
            opener: makeSessionOpener(),
        });
        const meter = createSessionUsageMeter<number>({
            client,
            priceUsage: () => undefined,
        });

        expect(meter.recordUsage(1)).toBe(false);
        await client.fetch('https://api.test/v1/generate');
        expect(meter.recordUsage(1)).toBe(false);
        expect(await meter.flush()).toBeNull();
        expect(gateway.commits).toHaveLength(0);
    });

    test('rejects unsafe usage price amounts before they reach voucher signing', async () => {
        const gateway = createSessionGatewayMock();
        const client = createSessionFetch({
            fetch: gateway.fetch,
            opener: makeSessionOpener(),
        });
        const meter = createSessionUsageMeter<number>({
            client,
            priceUsage: () => ({ cumulativeAmount: -1 }),
        });

        await client.fetch('https://api.test/v1/generate');

        expect(() => meter.recordUsage(1)).toThrow('cumulativeAmount must be non-negative');
        expect(gateway.commits).toHaveLength(0);
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

async function waitUntil(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
    const start = Date.now();
    while (!predicate()) {
        if (Date.now() - start > timeoutMs) {
            throw new Error('timed out waiting for condition');
        }
        await sleep(5);
    }
}

async function sleep(ms: number): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, ms));
}
