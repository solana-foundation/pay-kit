/**
 * `SessionFetchClient` must reproduce native `fetch(input, init)` header
 * semantics on the paid retry and in `stripRequestHeaders`: headers carried by
 * a `Request` input apply unless `init.headers` is given, and an explicit
 * `init.headers` (even an empty one) replaces them.
 *
 * The recording fetch resolves each attempt with `new Request(input, init)`,
 * which is how native `fetch` derives the request it sends.
 */
import { generateKeyPairSigner } from '@solana/kit';
import { Challenge } from 'mppx';
import { describe, expect, test } from 'vitest';

import {
    ActiveSession,
    createSessionFetch,
    type PrepareSessionRequest,
    type SessionChallenge,
    type SessionOpener,
    stripRequestHeaders,
    USDC,
} from '../client/index.js';

const BODY = JSON.stringify({ prompt: 'hello' });
const GATEWAY = 'https://gateway.test/v1/work';
const RESOURCE = 'https://api.test/v1/work';

interface RecordedAttempt {
    readonly body: string;
    readonly headers: Record<string, string>;
    readonly url: string;
}

function sessionChallenge(): SessionChallenge {
    return {
        id: 'session-request-headers-test',
        intent: 'session',
        method: 'solana',
        realm: 'test',
        request: {
            amount: '1',
            currency: 'USDC',
            methodDetails: {
                channelProgram: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX',
                gracePeriodSeconds: 900,
                minVoucherDelta: '1',
                network: 'localnet',
                recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                recentSlot: '9042',
            },
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
            suggestedDeposit: '1000000',
        },
    };
}

const opener: SessionOpener = async ({ challenge }) => {
    const signer = await generateKeyPairSigner();
    const channel = await generateKeyPairSigner();
    const session = new ActiveSession({ channelId: channel.address, signer });
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

function createRecordingClient(prepareRequest?: PrepareSessionRequest) {
    const attempts: RecordedAttempt[] = [];
    const client = createSessionFetch({
        fetch: async (input, init) => {
            const request = new Request(input, init);
            attempts.push({
                body: await request.text(),
                headers: Object.fromEntries(request.headers.entries()),
                url: request.url,
            });
            if (!request.headers.get('authorization')?.startsWith('Payment ')) {
                return new Response(null, {
                    headers: { 'WWW-Authenticate': Challenge.serialize(sessionChallenge()) },
                    status: 402,
                });
            }
            return new Response('ok', { status: 200 });
        },
        opener,
        prepareRequest,
    });
    return { attempts, client };
}

function callerRequest(): Request {
    return new Request(RESOURCE, {
        body: BODY,
        headers: { 'content-type': 'application/json', 'x-client-tag': 'tag', 'x-secret': 'secret' },
        method: 'POST',
    });
}

function withoutAuthorization(headers: Record<string, string>): Record<string, string> {
    const { authorization: _authorization, ...rest } = headers;
    return rest;
}

describe('SessionFetchClient request headers', () => {
    test('keeps Request-owned headers and body on the paid retry', async () => {
        const { attempts, client } = createRecordingClient();
        const request = callerRequest();

        const response = await client.fetch(request);

        expect(response.status).toBe(200);
        expect(attempts).toHaveLength(2);
        expect(attempts[1]!.headers.authorization).toMatch(/^Payment /);
        expect(withoutAuthorization(attempts[1]!.headers)).toEqual(attempts[0]!.headers);
        expect(attempts[0]!.headers).toMatchObject({ 'content-type': 'application/json', 'x-client-tag': 'tag' });
        expect(attempts.map(attempt => attempt.body)).toEqual([BODY, BODY]);
        expect(request.bodyUsed).toBe(false);
        expect(request.headers.has('authorization')).toBe(false);
    });

    test('keeps the FormData boundary paired with the original body on the paid retry', async () => {
        const form = new FormData();
        form.set('prompt', 'hello');
        form.set('attachment', new Blob(['file contents'], { type: 'text/plain' }), 'input.txt');
        const request = new Request(RESOURCE, {
            body: form,
            headers: { 'x-client-tag': 'tag' },
            method: 'POST',
        });
        const originalBody = await request.clone().text();
        const contentType = request.headers.get('content-type');
        const { attempts, client } = createRecordingClient();

        const response = await client.fetch(request);

        expect(response.status).toBe(200);
        expect(contentType).toMatch(/^multipart\/form-data; boundary=/);
        expect(attempts.map(attempt => attempt.headers['content-type'])).toEqual([contentType, contentType]);
        expect(attempts.map(attempt => attempt.body)).toEqual([originalBody, originalBody]);
        expect(request.bodyUsed).toBe(false);
    });

    test.each<{ headers: HeadersInit; label: string }>([
        { headers: {}, label: 'empty object' },
        { headers: new Headers(), label: 'empty Headers' },
        { headers: [], label: 'empty list' },
        { headers: { 'x-override': 'yes' }, label: 'replacement object' },
    ])('lets $label init headers replace Request headers', async ({ headers }) => {
        const { attempts, client } = createRecordingClient();

        await client.fetch(callerRequest(), { headers });

        const expected = Object.fromEntries(new Headers(headers).entries());
        expect(attempts[0]!.headers).toEqual(expected);
        expect(withoutAuthorization(attempts[1]!.headers)).toEqual(expected);
    });

    test('does not mutate caller init headers', async () => {
        const { client } = createRecordingClient();
        const headers = { 'x-client-tag': 'tag' };

        await client.fetch(RESOURCE, { headers });

        expect(headers).toEqual({ 'x-client-tag': 'tag' });
    });

    test.each([
        { createInput: () => GATEWAY, expectedHeaders: {}, label: 'URL string' },
        { createInput: () => new URL(GATEWAY), expectedHeaders: {}, label: 'URL object' },
        {
            createInput: () => new Request(GATEWAY, { headers: { 'x-gateway-tag': 'gateway' } }),
            expectedHeaders: { 'x-gateway-tag': 'gateway' },
            label: 'Request',
        },
    ])(
        'uses the headers of the $label returned by prepareRequest on both attempts',
        async ({ createInput, expectedHeaders }) => {
            const hookAuthorizations: (string | null)[] = [];
            const { attempts, client } = createRecordingClient(request => {
                hookAuthorizations.push(new Headers(request.init?.headers).get('authorization'));
                return { ...request, input: createInput() };
            });
            const request = callerRequest();

            const response = await client.fetch(request);

            expect(response.status).toBe(200);
            expect(attempts).toHaveLength(2);
            expect(attempts.map(attempt => attempt.url)).toEqual([GATEWAY, GATEWAY]);
            expect(attempts[0]!.headers).toEqual(expectedHeaders);
            expect(withoutAuthorization(attempts[1]!.headers)).toEqual(expectedHeaders);
            expect(hookAuthorizations).toEqual([null, expect.stringMatching(/^Payment /)]);
            expect(request.bodyUsed).toBe(false);
            expect(request.headers.get('x-secret')).toBe('secret');
            expect(request.headers.has('authorization')).toBe(false);
        },
    );

    test.each<{ headers: HeadersInit; label: string }>([
        { headers: {}, label: 'empty object' },
        { headers: new Headers(), label: 'empty Headers' },
        { headers: [], label: 'empty list' },
        { headers: { 'x-override': 'yes' }, label: 'replacement object' },
    ])('lets $label init headers replace the Request returned by prepareRequest', async ({ headers }) => {
        const { attempts, client } = createRecordingClient(request => ({
            ...request,
            input: new Request(GATEWAY, { headers: { 'x-gateway-tag': 'gateway' } }),
        }));

        const expected = Object.fromEntries(new Headers(headers).entries());
        const response = await client.fetch(callerRequest(), { headers });

        expect(response.status).toBe(200);
        expect(attempts).toHaveLength(2);
        expect(attempts[0]!.headers).toEqual(expected);
        expect(withoutAuthorization(attempts[1]!.headers)).toEqual(expected);
        expect(Object.fromEntries(new Headers(headers).entries())).toEqual(expected);
    });

    test('applies hook header changes once per attempt', async () => {
        const { attempts, client } = createRecordingClient(request => {
            const headers = new Headers(
                request.init?.headers ?? (request.input instanceof Request ? request.input.headers : undefined),
            );
            headers.append('x-client-tag', 'prepared');
            return { ...request, init: { ...request.init, headers } };
        });

        const response = await client.fetch(callerRequest());

        expect(response.status).toBe(200);
        expect(attempts).toHaveLength(2);
        expect(attempts.map(attempt => attempt.headers['x-client-tag'])).toEqual(['tag, prepared', 'tag, prepared']);
        expect(withoutAuthorization(attempts[1]!.headers)).toEqual(attempts[0]!.headers);
    });

    test.each(['before', 'after'] as const)(
        'keeps header stripping %s input replacement consistent across attempts',
        async order => {
            const strip = stripRequestHeaders(['x-secret']);
            const { attempts, client } = createRecordingClient(request =>
                order === 'before' ? { ...strip(request), input: GATEWAY } : strip({ ...request, input: GATEWAY }),
            );

            const response = await client.fetch(callerRequest());

            expect(response.status).toBe(200);
            expect(attempts).toHaveLength(2);
            expect(attempts.map(attempt => attempt.url)).toEqual([GATEWAY, GATEWAY]);
            expect(attempts[0]!.headers).toEqual(
                order === 'before' ? { 'content-type': 'application/json', 'x-client-tag': 'tag' } : {},
            );
            expect(withoutAuthorization(attempts[1]!.headers)).toEqual(attempts[0]!.headers);
            expect(attempts[1]!.headers.authorization).toMatch(/^Payment /);
        },
    );

    test('lets prepareRequest remove payment authorization from the paid retry', async () => {
        const hookAuthorizations: (string | null)[] = [];
        const strip = stripRequestHeaders(['authorization', 'x-secret']);
        const { attempts, client } = createRecordingClient(request => {
            hookAuthorizations.push(new Headers(request.init?.headers).get('authorization'));
            return strip(request);
        });

        const response = await client.fetch(callerRequest());

        expect(response.status).toBe(402);
        expect(attempts).toHaveLength(2);
        expect(hookAuthorizations).toEqual([null, expect.stringMatching(/^Payment /)]);
        expect(attempts[1]!.headers).toEqual(attempts[0]!.headers);
        for (const attempt of attempts) {
            expect(attempt.headers.authorization).toBeUndefined();
            expect(attempt.headers['x-secret']).toBeUndefined();
            expect(attempt.headers).toMatchObject({ 'content-type': 'application/json', 'x-client-tag': 'tag' });
        }
    });

    test('keeps in-place header edits when prepareRequest replaces the input', async () => {
        const { attempts, client } = createRecordingClient(request => {
            const input = new Request(GATEWAY, {
                headers: { 'x-gateway-tag': 'gateway', 'x-secret': 'gateway-secret' },
            });
            const headers = request.init?.headers instanceof Headers ? request.init.headers : input.headers;
            headers.delete('x-secret');
            headers.set('x-client-tag', 'prepared');
            return { ...request, input };
        });

        const response = await client.fetch(callerRequest());

        expect(response.status).toBe(200);
        expect(attempts).toHaveLength(2);
        expect(attempts[0]!.headers).toEqual({ 'x-client-tag': 'prepared', 'x-gateway-tag': 'gateway' });
        expect(withoutAuthorization(attempts[1]!.headers)).toEqual(attempts[0]!.headers);
        expect(attempts[1]!.headers.authorization).toMatch(/^Payment /);
    });

    test('keeps an explicit in-place set even when the value matches an inherited header', async () => {
        const { attempts, client } = createRecordingClient(request => {
            const input = new Request(GATEWAY);
            const headers = request.init?.headers instanceof Headers ? request.init.headers : input.headers;
            headers.set('X-Secret', 'secret');
            return { ...request, input };
        });

        const response = await client.fetch(callerRequest());

        expect(response.status).toBe(200);
        expect(attempts).toHaveLength(2);
        expect(attempts[0]!.headers).toEqual({ 'x-secret': 'secret' });
        expect(withoutAuthorization(attempts[1]!.headers)).toEqual(attempts[0]!.headers);
    });

    test('keeps an in-place deletion of a header owned only by the replacement input', async () => {
        const { attempts, client } = createRecordingClient(request => {
            const input = new Request(GATEWAY, { headers: { 'x-gateway-secret': 'gateway-secret' } });
            const headers = request.init?.headers instanceof Headers ? request.init.headers : input.headers;
            headers.delete('X-Gateway-Secret');
            return { ...request, input };
        });

        const response = await client.fetch(callerRequest());

        expect(response.status).toBe(200);
        expect(attempts).toHaveLength(2);
        expect(attempts[0]!.headers).toEqual({});
        expect(withoutAuthorization(attempts[1]!.headers)).toEqual(attempts[0]!.headers);
    });

    test.each([undefined, 'Bearer caller'])(
        'keeps in-place authorization removal with caller authorization %s',
        async authorization => {
            const { attempts, client } = createRecordingClient(request => {
                if (request.init?.headers instanceof Headers) {
                    request.init.headers.delete('authorization');
                }
                return request;
            });
            const request = callerRequest();
            if (authorization !== undefined) {
                request.headers.set('authorization', authorization);
            }

            const response = await client.fetch(request);

            expect(response.status).toBe(402);
            expect(attempts).toHaveLength(2);
            expect(withoutAuthorization(attempts[1]!.headers)).toEqual(withoutAuthorization(attempts[0]!.headers));
            expect(attempts[1]!.headers.authorization).toBeUndefined();
            expect(request.headers.get('authorization')).toBe(authorization ?? null);
        },
    );

    test('stripRequestHeaders removes only the named Request headers on both attempts', async () => {
        const { attempts, client } = createRecordingClient(stripRequestHeaders(['X-Secret']));

        const response = await client.fetch(callerRequest());

        expect(response.status).toBe(200);
        for (const attempt of attempts) {
            expect(attempt.headers['x-secret']).toBeUndefined();
            expect(attempt.headers).toMatchObject({ 'content-type': 'application/json', 'x-client-tag': 'tag' });
            expect(attempt.body).toBe(BODY);
        }
    });

    test('stripRequestHeaders keeps native replacement when init headers are explicit', async () => {
        const { attempts } = await (async () => {
            const recording = createRecordingClient(stripRequestHeaders(['x-secret']));
            await recording.client.fetch(callerRequest(), { headers: { 'x-override': 'yes' } });
            return recording;
        })();

        expect(attempts[0]!.headers).toEqual({ 'x-override': 'yes' });
        expect(withoutAuthorization(attempts[1]!.headers)).toEqual({ 'x-override': 'yes' });
    });
});
