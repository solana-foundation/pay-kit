import { generateKeyPairSigner } from '@solana/kit';
import { describe, expect, test } from 'vitest';

import { MeteredSseSession } from '../client/HttpStream.js';
import { ActiveSession, DEFAULT_SESSION_EXPIRES_AT } from '../client/Session.js';
import { type CommitTransport, SessionConsumer } from '../client/SessionConsumer.js';

class RecordingTransport implements CommitTransport {
    readonly commits: CommitTransport.CommitParameters[] = [];

    async commit(parameters: CommitTransport.CommitParameters) {
        this.commits.push(parameters);
        return {
            amount: parameters.directive.amount,
            cumulative: parameters.payload.voucher.data.cumulativeAmount,
            deliveryId: parameters.payload.deliveryId,
            sessionId: parameters.directive.sessionId,
            status: 'committed' as const,
        };
    }
}

async function makeStreamSession() {
    const signer = await generateKeyPairSigner();
    const channel = await generateKeyPairSigner();
    const session = new ActiveSession({ channelId: channel.address, signer });
    const transport = new RecordingTransport();
    const consumer = new SessionConsumer({ session, transport });
    return { metered: new MeteredSseSession(consumer), session, transport };
}

function meteringEvent(sessionId: string, deliveryId: string, amount: string) {
    return {
        data: JSON.stringify({
            amount,
            currency: 'USDC',
            deliveryId,
            expiresAt: DEFAULT_SESSION_EXPIRES_AT,
            sequence: 1,
            sessionId,
        }),
        event: 'mpp.metering',
    };
}

describe('MeteredSseSession usage validation', () => {
    test('rejects usage whose deliveryId does not match the live directive', async () => {
        const { metered, session } = await makeStreamSession();
        metered.acceptEvent(meteringEvent(session.channelId, 'reserved', '100'));

        expect(() =>
            metered.acceptEvent({
                data: JSON.stringify({ amount: '64', deliveryId: 'other' }),
                event: 'mpp.usage',
            }),
        ).toThrow('usage delivery other does not match directive reserved');
        expect(metered.usage).toBeUndefined();
    });

    test('matching usage overrides the amount but never the deliveryId', async () => {
        const { metered, session, transport } = await makeStreamSession();
        metered.acceptEvent(meteringEvent(session.channelId, 'reserved', '100'));
        metered.acceptEvent({
            data: JSON.stringify({ amount: '64', deliveryId: 'reserved' }),
            event: 'mpp.usage',
        });

        const receipt = await metered.ack();

        expect(receipt).toMatchObject({ amount: '64', deliveryId: 'reserved' });
        expect(transport.commits[0]).toMatchObject({
            directive: { amount: '64', deliveryId: 'reserved' },
            payload: { deliveryId: 'reserved', voucher: { data: { cumulativeAmount: '64' } } },
        });
    });

    test('usage observed before any directive is accepted, matching the Rust state machine', async () => {
        const { metered, session } = await makeStreamSession();
        metered.acceptEvent({
            data: JSON.stringify({ amount: '7', deliveryId: 'early' }),
            event: 'mpp.usage',
        });
        expect(metered.usage).toEqual({ amount: '7', deliveryId: 'early' });

        metered.acceptEvent(meteringEvent(session.channelId, 'reserved', '100'));
        await expect(metered.ack()).resolves.toMatchObject({ amount: '7', deliveryId: 'reserved' });
    });
});
