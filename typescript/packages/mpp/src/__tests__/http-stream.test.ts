import { generateKeyPairSigner } from '@solana/kit';

import {
    decodeMeteredSseStream,
    MeteredSseSession,
    parseMeteredSseEvent,
    parseSseEventBlock,
    SseDecoder,
} from '../client/HttpStream.js';
import {
    ActiveSession,
    DEFAULT_SESSION_EXPIRES_AT,
    type CommitPayload,
    type CommitReceipt,
} from '../client/Session.js';
import { type CommitTransport, SessionConsumer } from '../client/SessionConsumer.js';

class RecordingTransport implements CommitTransport {
    readonly commits: CommitPayload[] = [];

    async commit({ directive, payload }: CommitTransport.CommitParameters): Promise<CommitReceipt> {
        this.commits.push(payload);
        return {
            amount: directive.amount,
            cumulative: payload.voucher.data.cumulativeAmount,
            deliveryId: directive.deliveryId,
            sessionId: directive.sessionId,
            status: 'committed',
        };
    }
}

async function makeStreamSession(): Promise<{
    consumer: SessionConsumer<RecordingTransport>;
    metered: MeteredSseSession<RecordingTransport>;
    session: ActiveSession;
    transport: RecordingTransport;
}> {
    const signer = await generateKeyPairSigner();
    const channel = await generateKeyPairSigner();
    const session = new ActiveSession({ channelId: channel.address, signer });
    const transport = new RecordingTransport();
    const consumer = new SessionConsumer({ session, transport });
    return {
        consumer,
        metered: new MeteredSseSession(consumer),
        session,
        transport,
    };
}

describe('SseDecoder', () => {
    test('decodes chunked events, comments, id, and retry fields', () => {
        const decoder = new SseDecoder();

        expect(decoder.pushChunk(':comment\r\nevent: message\r\nid: 1\r\n')).toEqual([]);
        expect(decoder.pushChunk('retry: 10\r\ndata: hello\r\ndata: world\r\n\r\n')).toEqual([
            {
                data: 'hello\nworld',
                event: 'message',
                id: '1',
                retry: 10,
            },
        ]);
    });

    test('finish parses trailing events', () => {
        const decoder = new SseDecoder();

        decoder.pushChunk('event: done\ndata: [DONE]');

        expect(decoder.finish()).toEqual([{ data: '[DONE]', event: 'done' }]);
        expect(parseSseEventBlock('data')).toEqual({ data: '' });
        expect(parseSseEventBlock(':only-comment')).toBeNull();
    });
});

describe('parseMeteredSseEvent', () => {
    test('parses metering, usage, receipt, done, and messages', () => {
        const directive = {
            amount: '5',
            currency: 'USDC',
            deliveryId: 'delivery-1',
            expiresAt: DEFAULT_SESSION_EXPIRES_AT,
            sequence: 1,
            sessionId: 'session-1',
        };

        expect(parseMeteredSseEvent({ data: JSON.stringify(directive), event: 'mpp.metering' })).toEqual({
            directive,
            type: 'metering',
        });
        expect(
            parseMeteredSseEvent({
                data: JSON.stringify({ amount: '3', deliveryId: 'delivery-1' }),
                event: 'usage',
            }),
        ).toEqual({ type: 'usage', usage: { amount: '3', deliveryId: 'delivery-1' } });
        expect(parseMeteredSseEvent({ data: JSON.stringify({ ok: true }), event: 'payment-receipt' })).toEqual({
            receipt: { ok: true },
            type: 'receipt',
        });
        expect(parseMeteredSseEvent({ data: '[DONE]' })).toEqual({ type: 'done' });
        expect(parseMeteredSseEvent({ data: '{"token":"hi"}' }, JSON.parse)).toEqual({
            data: { token: 'hi' },
            type: 'message',
        });
    });
});

describe('MeteredSseSession', () => {
    test('tracks stream state and commits final usage', async () => {
        const { metered, session, transport } = await makeStreamSession();

        expect(
            metered.acceptEvent({
                data: JSON.stringify({
                    amount: '100',
                    currency: 'USDC',
                    deliveryId: 'reserved',
                    expiresAt: DEFAULT_SESSION_EXPIRES_AT,
                    sequence: 1,
                    sessionId: session.channelId,
                }),
                event: 'mpp.metering',
            }),
        ).toMatchObject({ type: 'metering' });
        expect(metered.directive).toMatchObject({ amount: '100', deliveryId: 'reserved' });
        expect(
            metered.acceptEvent({
                data: JSON.stringify({ amount: '64', deliveryId: 'reserved' }),
                event: 'mpp.usage',
            }),
        ).toMatchObject({ type: 'usage' });
        expect(metered.usage).toEqual({ amount: '64', deliveryId: 'reserved' });
        expect(metered.acceptEvent({ data: '[DONE]' })).toEqual({ type: 'done' });

        const receipt = await metered.ack();

        expect(metered.isDone).toBe(true);
        expect(receipt).toMatchObject({ amount: '64', cumulative: '64', deliveryId: 'reserved' });
        expect(transport.commits[0]).toMatchObject({
            deliveryId: 'reserved',
            voucher: { data: { cumulativeAmount: '64' } },
        });
    });

    test('falls back to reserved amount and requires a directive', async () => {
        const { metered, session } = await makeStreamSession();

        await expect(metered.ack()).rejects.toThrow('stream missing metering directive');

        metered.acceptEvent({
            data: JSON.stringify({
                amount: '9',
                currency: 'USDC',
                deliveryId: 'reserved',
                expiresAt: DEFAULT_SESSION_EXPIRES_AT,
                sequence: 1,
                sessionId: session.channelId,
            }),
            event: 'metering',
        });

        await expect(metered.ack()).resolves.toMatchObject({ amount: '9', cumulative: '9' });
    });
});

describe('decodeMeteredSseStream', () => {
    test('decodes a ReadableStream into metered events', async () => {
        const stream = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(
                    new TextEncoder().encode(
                        'event: mpp.metering\n' +
                            'data: {"amount":"5","currency":"USDC","deliveryId":"d1","expiresAt":4102444800,"sequence":1,"sessionId":"s1"}\n\n' +
                            'event: message\n' +
                            'data: {"delta":"hello"}\n\n' +
                            'data: [DONE]\n\n',
                    ),
                );
                controller.close();
            },
        });

        const events = [];
        for await (const event of decodeMeteredSseStream(stream, JSON.parse)) {
            events.push(event);
        }

        expect(events).toEqual([
            {
                directive: {
                    amount: '5',
                    currency: 'USDC',
                    deliveryId: 'd1',
                    expiresAt: 4_102_444_800,
                    sequence: 1,
                    sessionId: 's1',
                },
                type: 'metering',
            },
            { data: { delta: 'hello' }, type: 'message' },
            { type: 'done' },
        ]);
    });
});
