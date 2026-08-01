import { afterEach, describe, expect, it, vi } from 'vitest';

import { createLifecycle } from '../server/session/lifecycle.js';
import { createMemorySessionStore } from '../server/session/store.js';

describe('session lifecycle', () => {
    afterEach(() => vi.useRealTimers());

    it('uses and refreshes the negotiated per-channel timeout', async () => {
        vi.useFakeTimers();
        const closeOnIdle = vi.fn();
        const lifecycle = createLifecycle(createMemorySessionStore(), closeOnIdle, 10_000);

        lifecycle.touch('channel-1', 2);
        await vi.advanceTimersByTimeAsync(1_500);
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
        const lifecycle = createLifecycle(createMemorySessionStore(), closeOnIdle, 10_000);
        const timeoutSeconds = 2_147_485;

        lifecycle.touch('channel-1', timeoutSeconds);
        await vi.advanceTimersByTimeAsync(2_147_483_647);
        expect(closeOnIdle).not.toHaveBeenCalled();

        await vi.advanceTimersByTimeAsync(timeoutSeconds * 1_000 - 2_147_483_647);
        expect(closeOnIdle).toHaveBeenCalledOnce();
    });
});
