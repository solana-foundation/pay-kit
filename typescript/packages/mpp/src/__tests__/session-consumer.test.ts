import { generateKeyPairSigner } from '@solana/kit';

import {
    ActiveSession,
    DEFAULT_SESSION_EXPIRES_AT,
    type CommitPayload,
    type CommitReceipt,
    type MeteredEnvelope,
    type MeteringDirective,
} from '../client/Session.js';
import { HttpCommitTransport, type CommitTransport, SessionConsumer } from '../client/SessionConsumer.js';

class RecordingTransport implements CommitTransport {
    readonly commits: CommitPayload[] = [];
    fail = false;

    async commit({ directive, payload }: CommitTransport.CommitParameters): Promise<CommitReceipt> {
        if (this.fail) throw new Error('commit failed');
        this.commits.push(payload);
        return {
            amount: directive.amount,
            cumulative: payload.voucher.voucher.cumulativeAmount,
            deliveryId: directive.deliveryId,
            sessionId: directive.sessionId,
            status: 'committed',
        };
    }
}

async function makeConsumer(): Promise<{
    consumer: SessionConsumer<RecordingTransport>;
    session: ActiveSession;
    transport: RecordingTransport;
}> {
    const signer = await generateKeyPairSigner();
    const channel = await generateKeyPairSigner();
    const session = new ActiveSession({ channelId: channel.address, signer });
    const transport = new RecordingTransport();
    return {
        consumer: new SessionConsumer({ session, transport }),
        session,
        transport,
    };
}

function directive(sessionId: string, amount = '250'): MeteringDirective {
    return {
        amount,
        currency: 'USDC',
        deliveryId: 'delivery-1',
        expiresAt: DEFAULT_SESSION_EXPIRES_AT,
        sequence: 1,
        sessionId,
    };
}

describe('SessionConsumer', () => {
    test('ack sends a commit and advances the local watermark after success', async () => {
        const { consumer, session, transport } = await makeConsumer();
        const envelope: MeteredEnvelope<string> = {
            metering: directive(session.channelId),
            payload: 'work',
        };

        expect(consumer.session).toBe(session);
        expect(consumer.transport).toBe(transport);
        const delivery = consumer.accept(envelope);
        expect(delivery.payload).toBe('work');
        expect(delivery.metering.amount).toBe('250');

        const receipt = await delivery.ack();

        expect(receipt).toMatchObject({
            amount: '250',
            cumulative: '250',
            deliveryId: 'delivery-1',
            status: 'committed',
        });
        expect(session.cumulative).toBe(250n);
        expect(transport.commits).toHaveLength(1);
        expect(transport.commits[0]).toMatchObject({
            deliveryId: 'delivery-1',
            voucher: { voucher: { cumulativeAmount: '250' } },
        });
    });

    test('commit alias and direct commit share the same behavior', async () => {
        const { consumer, session, transport } = await makeConsumer();
        session.setExpiresAt(1234);

        await expect(
            consumer.accept({ metering: directive(session.channelId, '50'), payload: { ok: true } }).commit(),
        ).resolves.toMatchObject({ cumulative: '50' });
        expect(transport.commits[0]?.voucher.voucher.expiresAt).toBe(1234);

        await expect(consumer.commitDirective(directive(session.channelId, '75'))).resolves.toMatchObject({
            cumulative: '125',
        });
        expect(session.cumulative).toBe(125n);
    });

    test('intoParts returns payload and metering without committing', async () => {
        const { consumer, session, transport } = await makeConsumer();

        const parts = consumer.accept({ metering: directive(session.channelId, '10'), payload: 'payload' }).intoParts();

        expect(parts).toEqual({ metering: directive(session.channelId, '10'), payload: 'payload' });
        expect(transport.commits).toHaveLength(0);
        expect(session.cumulative).toBe(0n);
    });

    test('failed commits do not advance the local watermark', async () => {
        const { consumer, session, transport } = await makeConsumer();
        transport.fail = true;

        await expect(consumer.commitDirective(directive(session.channelId, '10'))).rejects.toThrow('commit failed');
        expect(session.cumulative).toBe(0n);
        expect(transport.commits).toHaveLength(0);
    });

    test('rejects mismatched sessions and invalid amounts', async () => {
        const { consumer, session } = await makeConsumer();
        const other = await generateKeyPairSigner();

        expect(() => consumer.accept({ metering: directive(other.address), payload: 'bad' })).toThrow(
            'does not match active session',
        );
        await expect(consumer.commitDirective(directive(session.channelId, '0'))).rejects.toThrow(
            'must be greater than zero',
        );
        await expect(consumer.commitDirective(directive(session.channelId, 'not-a-number'))).rejects.toThrow(
            'invalid metering amount',
        );
    });
});

describe('HttpCommitTransport', () => {
    test('posts commit payloads to directive commitUrl', async () => {
        const calls: Array<{ readonly body: string | null; readonly headers: Headers; readonly url: string }> = [];
        const fetch: typeof globalThis.fetch = async (input, init) => {
            calls.push({
                body: typeof init?.body === 'string' ? init.body : null,
                headers: new Headers(init?.headers),
                url: input.toString(),
            });
            return new Response(
                JSON.stringify({
                    amount: '5',
                    cumulative: '5',
                    deliveryId: 'delivery-1',
                    sessionId: 'session-1',
                    status: 'committed',
                }),
                { status: 200 },
            );
        };
        const transport = new HttpCommitTransport({ authorization: 'Bearer test', fetch });

        const receipt = await transport.commit({
            directive: { ...directive('session-1', '5'), commitUrl: 'https://example.test/commit' },
            payload: {
                deliveryId: 'delivery-1',
                voucher: {
                    voucher: {
                        channelId: 'session-1',
                        cumulativeAmount: '5',
                        expiresAt: DEFAULT_SESSION_EXPIRES_AT,
                    },
                    signature: 'sig',
                    signatureType: 'ed25519',
                    signer: 'session-signer',
                },
            },
        });

        expect(receipt.status).toBe('committed');
        expect(calls[0]?.url).toBe('https://example.test/commit');
        expect(calls[0]?.headers.get('authorization')).toBe('Bearer test');
        expect(calls[0]?.body).toContain('"deliveryId":"delivery-1"');
    });

    test('uses default commitUrl and reports HTTP failures', async () => {
        const okFetch: typeof globalThis.fetch = async () =>
            new Response(
                JSON.stringify({
                    amount: '1',
                    cumulative: '1',
                    deliveryId: 'delivery-1',
                    sessionId: 'session-1',
                    status: 'replayed',
                }),
                { status: 200 },
            );
        const transport = new HttpCommitTransport({ commitUrl: 'https://example.test/default', fetch: okFetch });

        await expect(
            transport.commit({
                directive: directive('session-1', '1'),
                payload: {
                    deliveryId: 'delivery-1',
                    voucher: {
                        voucher: {
                            channelId: 'session-1',
                            cumulativeAmount: '1',
                            expiresAt: DEFAULT_SESSION_EXPIRES_AT,
                        },
                        signature: 'sig',
                        signatureType: 'ed25519',
                        signer: 'session-signer',
                    },
                },
            }),
        ).resolves.toMatchObject({ status: 'replayed' });

        await expect(
            new HttpCommitTransport({ fetch: okFetch }).commit({
                directive: directive('session-1', '1'),
                payload: {
                    deliveryId: 'delivery-1',
                    voucher: {
                        voucher: {
                            channelId: 'session-1',
                            cumulativeAmount: '1',
                            expiresAt: DEFAULT_SESSION_EXPIRES_AT,
                        },
                        signature: 'sig',
                        signatureType: 'ed25519',
                        signer: 'session-signer',
                    },
                },
            }),
        ).rejects.toThrow('metering directive missing commitUrl');

        const failing = new HttpCommitTransport({
            commitUrl: 'https://example.test/default',
            fetch: async () => new Response('nope', { status: 500 }),
        });
        await expect(
            failing.commit({
                directive: directive('session-1', '1'),
                payload: {
                    deliveryId: 'delivery-1',
                    voucher: {
                        voucher: {
                            channelId: 'session-1',
                            cumulativeAmount: '1',
                            expiresAt: DEFAULT_SESSION_EXPIRES_AT,
                        },
                        signature: 'sig',
                        signatureType: 'ed25519',
                        signer: 'session-signer',
                    },
                },
            }),
        ).rejects.toThrow('commit endpoint returned 500: nope');
    });
});
