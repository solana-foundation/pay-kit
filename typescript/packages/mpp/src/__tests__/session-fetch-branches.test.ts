// Branch-coverage tests for client/SessionFetch.ts.
//
// Targets the branches the watermark-isolation and opener suites leave
// uncovered: constructor `??` defaults, the non-402 and 402-without-challenge
// early returns, non-increasing recordCumulative, requireOpen-before-open,
// reservation failure, the directive.commitUrl fallback, the amount/integer
// parse guards, and a few createEphemeralSessionOpener arms (mode default,
// caller-built initMultiDelegateTx, and the non-SPL-currency refusal).
// No production code is touched.

import { generateKeyPairSigner } from '@solana/kit';
import { Challenge, Credential } from 'mppx';
import { describe, expect, test } from 'vitest';

import {
    ActiveSession,
    createEphemeralSessionOpener,
    createSessionFetch,
    DEFAULT_SESSION_EXPIRES_AT,
    type SessionChallenge,
    type SessionOpener,
    type SignedVoucher,
} from '../client/index.js';

const recipient = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';

function sessionChallenge(overrides: Partial<SessionChallenge['request']> = {}): SessionChallenge {
    return {
        id: 'session-fetch-branches',
        intent: 'session',
        method: 'solana',
        realm: 'test',
        request: {
            cap: '1000000',
            currency: 'USDC',
            decimals: 6,
            minVoucherDelta: '1',
            modes: ['push'],
            network: 'localnet',
            operator: recipient,
            recipient,
            ...overrides,
        },
    };
}

function makeOpener(sessions: ActiveSession[]): SessionOpener {
    return async ({ challenge }) => {
        const signer = await generateKeyPairSigner();
        const channel = await generateKeyPairSigner();
        const session = new ActiveSession({ channelId: channel.address, signer });
        sessions.push(session);
        return {
            payload: session.openAction(challenge.request.cap, '1'.repeat(64)),
            session,
        };
    };
}

function fetchUrl(input: Parameters<typeof globalThis.fetch>[0]): string {
    if (input instanceof Request) return input.url;
    return String(input);
}

function tryParseJson(init: Parameters<typeof globalThis.fetch>[1]): Record<string, unknown> | undefined {
    if (typeof init?.body !== 'string') return undefined;
    try {
        const parsed: unknown = JSON.parse(init.body);
        return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : undefined;
    } catch {
        return undefined;
    }
}

/**
 * Gateway mock that answers the work route, delivery reservation, and commit.
 * The reservation echoes a commitUrl only when `reserveCommitUrl` is set, so a
 * test can force the `directive.commitUrl ?? fallback` fallback arm. Commits POST
 * back to the work URL by default (the fallback), or to `reserveCommitUrl`.
 */
function createGatewayMock(opts: { failReservation?: boolean; reserveCommitUrl?: string | undefined } = {}) {
    const commits: { amount: string; deliveryId: string; cumulative: string }[] = [];
    const recordCommit = (headers: Headers, body: Record<string, unknown>) => {
        const credential = Credential.deserialize(headers.get('authorization') ?? '');
        const voucher = (credential.payload as { voucher: SignedVoucher }).voucher;
        const entry = {
            amount: String(body.amount),
            cumulative: voucher.data.cumulativeAmount,
            deliveryId: String(body.deliveryId),
        };
        commits.push(entry);
        return Response.json({ amount: entry.amount, cumulative: entry.cumulative, status: 'committed' });
    };

    const fetch: typeof globalThis.fetch = async (input, init) => {
        const url = new URL(fetchUrl(input));
        const headers = new Headers(init?.headers);
        const body = tryParseJson(init);

        if (url.pathname === '/__402/session/deliveries') {
            if (opts.failReservation) {
                return new Response('reservation refused', { status: 503 });
            }
            return Response.json({
                amount: String(body?.amount ?? '0'),
                ...(opts.reserveCommitUrl ? { commitUrl: opts.reserveCommitUrl } : {}),
                currency: 'USDC',
                deliveryId: String(body?.deliveryId ?? ''),
                expiresAt: DEFAULT_SESSION_EXPIRES_AT,
                sessionId: 'sid',
            });
        }

        // A JSON POST carrying a deliveryId is a voucher commit (default fallback URL
        // is the work route, or the reservation-provided commit URL).
        if (body && typeof body.deliveryId === 'string') {
            return recordCommit(headers, body);
        }

        // Otherwise this is the work route itself.
        if (!headers.has('authorization')) {
            return new Response(null, {
                headers: { 'WWW-Authenticate': Challenge.serialize(sessionChallenge()) },
                status: 402,
            });
        }
        return new Response('ok', { status: 200 });
    };
    return { commits, fetch };
}

// ── fetchWithSession early returns ──

describe('SessionFetchClient.fetchWithSession early returns', () => {
    test('returns a non-402 response unchanged without opening a session', async () => {
        let openerCalled = false;
        const client = createSessionFetch({
            // No liveCommitIntervalMs / fetch defaults are exercised here too.
            fetch: async () => new Response('hello', { status: 200 }),
            opener: async () => {
                openerCalled = true;
                throw new Error('opener must not run for a 200');
            },
        });
        const response = await client.fetch('https://api.test/v1/work');
        expect(response.status).toBe(200);
        expect(await response.text()).toBe('hello');
        expect(openerCalled).toBe(false);
    });

    test('returns a 402 whose challenge is not a Solana session challenge unchanged', async () => {
        // A well-formed WWW-Authenticate that parses but is not a session
        // challenge (different intent) makes challenge selection return
        // undefined, so the opener never runs and the 402 is returned as-is.
        let openerCalled = false;
        const nonSession = Challenge.serialize({ ...sessionChallenge(), intent: 'charge' } as never);
        const client = createSessionFetch({
            fetch: async () => new Response('nope', { headers: { 'WWW-Authenticate': nonSession }, status: 402 }),
            opener: async () => {
                openerCalled = true;
                throw new Error('opener must not run without a session challenge');
            },
        });
        const response = await client.fetch('https://api.test/v1/work');
        expect(response.status).toBe(402);
        expect(openerCalled).toBe(false);
    });
});

// ── recordCumulative / requireOpen guards ──

describe('SessionFetchClient watermark guards', () => {
    test('recordCumulative before opening a session throws', () => {
        const client = createSessionFetch({
            fetch: async () => new Response('ok'),
            opener: makeOpener([]),
        });
        expect(() => client.recordCumulative(10)).toThrow(/session has not been opened yet/);
    });

    test('recordCumulative ignores a non-increasing amount', async () => {
        const gateway = createGatewayMock();
        const client = createSessionFetch({
            fetch: gateway.fetch,
            liveCommitIntervalMs: 60_000,
            opener: makeOpener([]),
        });
        await client.fetch('https://api.test/v1/work');
        client.recordCumulative(100, { force: true });
        await client.flush();
        expect(gateway.commits).toHaveLength(1);
        // Records at-or-below the current cumulative are no-ops: they neither
        // advance the watermark nor queue a new commit.
        client.recordCumulative(100);
        client.recordCumulative(50);
        await client.flush();
        expect(gateway.commits).toHaveLength(1);
    });

    test('recordCumulative rejects a negative amount', async () => {
        const gateway = createGatewayMock();
        const client = createSessionFetch({ fetch: gateway.fetch, opener: makeOpener([]) });
        await client.fetch('https://api.test/v1/work');
        expect(() => client.recordCumulative(-5)).toThrow(/must be non-negative/);
    });

    test('recordCumulative rejects a non-integer string amount', async () => {
        const gateway = createGatewayMock();
        const client = createSessionFetch({ fetch: gateway.fetch, opener: makeOpener([]) });
        await client.fetch('https://api.test/v1/work');
        expect(() => client.recordCumulative('12.5')).toThrow(/must be an integer string/);
    });

    test('recordCumulative rejects an unsafe-integer number amount', async () => {
        const gateway = createGatewayMock();
        const client = createSessionFetch({ fetch: gateway.fetch, opener: makeOpener([]) });
        await client.fetch('https://api.test/v1/work');
        expect(() => client.recordCumulative(Number.MAX_SAFE_INTEGER + 2)).toThrow(/must be a safe integer/);
    });
});

// ── commit path branches ──

describe('SessionFetchClient commit path', () => {
    test('surfaces a delivery-reservation failure', async () => {
        const gateway = createGatewayMock({ failReservation: true });
        const client = createSessionFetch({ fetch: gateway.fetch, opener: makeOpener([]) });
        await client.fetch('https://api.test/v1/work');
        await expect(client.commitCumulative(100)).rejects.toThrow(/delivery reservation returned 503/);
    });

    test('commits to the reservation-provided commitUrl when present', async () => {
        const gateway = createGatewayMock({ reserveCommitUrl: 'https://api.test/session/commit' });
        const client = createSessionFetch({ fetch: gateway.fetch, opener: makeOpener([]) });
        await client.fetch('https://api.test/v1/work');
        const receipt = await client.commitCumulative(100);
        expect(receipt).toMatchObject({ amount: '100', cumulative: '100', status: 'committed' });
    });

    test('commitCumulative with a non-increasing target reserves nothing new', async () => {
        const gateway = createGatewayMock();
        const client = createSessionFetch({ fetch: gateway.fetch, opener: makeOpener([]) });
        await client.fetch('https://api.test/v1/work');
        await client.commitCumulative(100);
        // Re-committing the same cumulative issues no additional reservation.
        await client.commitCumulative(100);
        expect(gateway.commits).toHaveLength(1);
    });
});

// ── createEphemeralSessionOpener extra arms ──

describe('createEphemeralSessionOpener branch coverage', () => {
    const params = (challenge: SessionChallenge) => ({
        challenge,
        init: undefined,
        input: 'https://api.test/v1/work',
        response: new Response(null, { status: 402 }),
    });

    test('defaults the mode to the first advertised mode when none is configured', async () => {
        const opener = createEphemeralSessionOpener();
        const result = await opener(params(sessionChallenge({ modes: ['push'] })));
        expect(result.payload.mode).toBe('push');
    });

    test('accepts a caller-built initMultiDelegateTx with owner and tokenAccount', async () => {
        const opener = createEphemeralSessionOpener({
            initMultiDelegateTx: 'BASE64_INIT_TX',
            mode: 'pull',
            owner: recipient,
            tokenAccount: recipient,
        });
        const result = await opener(params(sessionChallenge({ modes: ['pull'] })));
        expect(result.payload.mode).toBe('pull');
        expect(result.payload.initMultiDelegateTx).toBe('BASE64_INIT_TX');
        expect(result.payload.tokenAccount).toBe(recipient);
    });

    test('rejects a caller-built initMultiDelegateTx without owner and tokenAccount', async () => {
        const opener = createEphemeralSessionOpener({ initMultiDelegateTx: 'BASE64_INIT_TX', mode: 'pull' });
        await expect(opener(params(sessionChallenge({ modes: ['pull'] })))).rejects.toThrow(
            /requires owner and tokenAccount/,
        );
    });

    test('refuses a delegated pull whose currency is not an SPL token', async () => {
        const wallet = await generateKeyPairSigner();
        const opener = createEphemeralSessionOpener({ mode: 'pull', signer: wallet });
        // currency 'SOL' resolves to no mint, so the SPL requirement fails.
        const challenge = sessionChallenge({
            currency: 'SOL',
            modes: ['pull'],
            pullVoucherStrategy: 'operatedVoucher',
            recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
        });
        await expect(opener(params(challenge))).rejects.toThrow(/requires an SPL token currency/);
    });

    test('falls back to push mode when no mode is configured and none is advertised', async () => {
        // options.mode is undefined and modes[0] is undefined → the final
        // `?? 'push'` default arm is taken.
        const opener = createEphemeralSessionOpener();
        const result = await opener(params(sessionChallenge({ modes: [] })));
        expect(result.payload.mode).toBe('push');
    });

    test('defaults the challenge network to mainnet when building a delegated pull', async () => {
        // No network on the request → `challenge.request.network ?? 'mainnet'`
        // takes the default arm while resolving the stablecoin mint.
        const wallet = await generateKeyPairSigner();
        const opener = createEphemeralSessionOpener({ mode: 'pull', signer: wallet });
        const challenge = sessionChallenge({
            currency: 'USDC',
            modes: ['pull'],
            network: undefined,
            pullVoucherStrategy: 'operatedVoucher',
            recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
        });
        const result = await opener(params(challenge));
        expect(result.payload.mode).toBe('pull');
    });
});

// ── input handling + parse guards ──

describe('SessionFetchClient input and default handling', () => {
    test('constructs with default fetch and live-commit interval', () => {
        // No fetch (defaults to globalThis.fetch.bind) and no
        // liveCommitIntervalMs (defaults to 1000). No request is made.
        const client = createSessionFetch({ opener: makeOpener([]) });
        expect(client.open).toBeUndefined();
        expect(client.session).toBeUndefined();
        expect(client.cumulativeAmount).toBe('0');
        expect(client.targetCumulativeAmount).toBeUndefined();
    });

    test('accepts a Request object as fetch input and opens a session', async () => {
        const gateway = createGatewayMock();
        const client = createSessionFetch({ fetch: gateway.fetch, opener: makeOpener([]) });
        const response = await client.fetch(new Request('https://api.test/v1/work'));
        expect(response.status).toBe(200);
        expect(client.open).toBeDefined();
    });

    test('recordCumulative rejects an amount above u64 max', async () => {
        const gateway = createGatewayMock();
        const client = createSessionFetch({ fetch: gateway.fetch, opener: makeOpener([]) });
        await client.fetch('https://api.test/v1/work');
        expect(() => client.recordCumulative((1n << 64n).toString())).toThrow(/exceeds u64 max/);
    });

    test('surfaces a non-Error thrown from the commit fetch', async () => {
        // A fetch that rejects with a plain string exercises toError's
        // `value instanceof Error` false arm.
        let calls = 0;
        const fetch: typeof globalThis.fetch = async (input, init) => {
            const url = new URL(fetchUrl(input));
            if (url.pathname === '/v1/work' && !new Headers(init?.headers).has('authorization')) {
                return new Response(null, {
                    headers: { 'WWW-Authenticate': Challenge.serialize(sessionChallenge()) },
                    status: 402,
                });
            }
            if (url.pathname === '/v1/work') return new Response('ok', { status: 200 });
            // Reservation and commit both reject with a non-Error value.
            calls += 1;
            // eslint-disable-next-line @typescript-eslint/no-throw-literal
            throw 'network exploded';
        };
        const client = createSessionFetch({ fetch, opener: makeOpener([]) });
        await client.fetch('https://api.test/v1/work');
        await expect(client.commitCumulative(100)).rejects.toThrow(/network exploded/);
        expect(calls).toBeGreaterThan(0);
    });
});
