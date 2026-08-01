import { afterEach, describe, expect, it, vi } from 'vitest';

import { createLifecycle } from '../server/session/lifecycle.js';
import { createMemorySessionStore } from '../server/session/store.js';

async function seedChannel(
    store: ReturnType<typeof createMemorySessionStore>,
    channelId: string,
    idleTimeoutSeconds: number,
) {
    await store.updateChannel(channelId, () => ({
        authorizedSigner: channelId,
        channelId,
        committedDeliveries: [],
        cumulative: 0n,
        deposit: 1n,
        idleTimeoutSeconds,
        lastActivityAt: Date.now(),
        nextDeliverySequence: 0n,
        payer: channelId,
        pendingDeliveries: [],
        processedUses: [],
        rentPayer: channelId,
        sealed: false,
        settledOnChain: 0n,
        spentAmount: 0n,
    }));
}

describe('session lifecycle', () => {
    afterEach(() => vi.useRealTimers());

    it('uses and refreshes the negotiated per-channel timeout', async () => {
        vi.useFakeTimers();
        const closeOnIdle = vi.fn();
        const store = createMemorySessionStore();
        await seedChannel(store, 'channel-1', 2);
        const lifecycle = createLifecycle(store, closeOnIdle, 10_000);

        lifecycle.touch('channel-1', 2);
        await vi.advanceTimersByTimeAsync(1_500);
        await store.updateChannel('channel-1', current => ({ ...current!, lastActivityAt: Date.now() }));
        lifecycle.touch('channel-1', 2);
        await vi.advanceTimersByTimeAsync(1_999);
        expect(closeOnIdle).not.toHaveBeenCalled();

        await vi.advanceTimersByTimeAsync(1);
        expect(closeOnIdle).toHaveBeenCalledOnce();
        expect(closeOnIdle).toHaveBeenCalledWith('channel-1');
    });

    it('chunks negotiated timeouts above the Node timer limit', async () => {
        vi.useFakeTimers();
        const closeOnIdle = vi.fn();
        const store = createMemorySessionStore();
        const timeoutSeconds = 2_147_485;
        await seedChannel(store, 'channel-1', timeoutSeconds);
        const lifecycle = createLifecycle(store, closeOnIdle, 10_000);

        lifecycle.touch('channel-1', timeoutSeconds);
        await vi.advanceTimersByTimeAsync(2_147_483_647);
        expect(closeOnIdle).not.toHaveBeenCalled();

        await vi.advanceTimersByTimeAsync(timeoutSeconds * 1_000 - 2_147_483_647);
        expect(closeOnIdle).toHaveBeenCalledOnce();
    });
});
