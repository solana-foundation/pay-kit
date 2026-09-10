import { describe, expect, test } from 'vitest';

import { session } from '../server/Session.js';
import { type ChannelState, createMemorySessionStore } from '../server/session/store.js';

function channelState(channelId: string): ChannelState {
    return {
        authorizedSigner: '11111111111111111111111111111111',
        channelId,
        committedDeliveries: [],
        cumulative: 0n,
        deposit: 1_000n,
        nextDeliverySequence: 0n,
        payer: '11111111111111111111111111111111',
        pendingDeliveries: [],
        processedUses: [],
        rentPayer: '11111111111111111111111111111111',
        sealed: false,
        settledOnChain: 0n,
        spentAmount: 0n,
    };
}

describe('session side-channel routes', () => {
    test('advertises a path-only commit sibling that preserves a proxy mount prefix', async () => {
        const store = createMemorySessionStore();
        await store.updateChannel('channel-1', () => channelState('channel-1'));
        const routes = session.routes({ currency: 'USDC', network: 'devnet', store } as never);

        const response = await routes.deliveries(
            new Request('http://internal-api:3000/gateway/__402/session/deliveries', {
                body: JSON.stringify({ amount: '10', deliveryId: 'delivery-1', sessionId: 'channel-1' }),
                headers: { 'content-type': 'application/json' },
                method: 'POST',
            }),
        );

        expect(response.status).toBe(200);
        await expect(response.json()).resolves.toMatchObject({
            commitUrl: '/gateway/__402/session/commit',
            deliveryId: 'delivery-1',
        });
    });
});
