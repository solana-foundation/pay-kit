/**
 * Unit tests for the per-channel idle-close lifecycle
 * (server/session/lifecycle.ts).
 *
 * The watchdog arms a single-shot timer per channel; `touch` resets it,
 * `removeChannel` cancels one, and `shutdown` cancels everything. When the
 * timer fires it invokes `closeOnIdle(channelId)`. `closeDelayMs <= 0`
 * disables the timer entirely (every operation becomes a no-op).
 *
 * Fake timers drive the single-shot timer deterministically.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { createLifecycle } from '../server/session/lifecycle.js';
import { createMemorySessionStore } from '../server/session/store.js';

describe('createLifecycle', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    test('closeDelayMs <= 0 makes touch a no-op — timer never fires', () => {
        const store = createMemorySessionStore();
        const closeOnIdle = vi.fn();
        const lifecycle = createLifecycle(store, closeOnIdle, 0);

        lifecycle.touch('channel-1');
        vi.advanceTimersByTime(1_000_000);
        expect(closeOnIdle).not.toHaveBeenCalled();
    });

    test('touch arms a timer that fires closeOnIdle after the delay', async () => {
        const store = createMemorySessionStore();
        const closeOnIdle = vi.fn();
        const lifecycle = createLifecycle(store, closeOnIdle, 5_000);

        lifecycle.touch('channel-1');
        expect(closeOnIdle).not.toHaveBeenCalled();

        await vi.advanceTimersByTimeAsync(5_000);
        expect(closeOnIdle).toHaveBeenCalledTimes(1);
        expect(closeOnIdle).toHaveBeenCalledWith('channel-1');
    });

    test('touch resets the timer so an active channel is never closed', async () => {
        const store = createMemorySessionStore();
        const closeOnIdle = vi.fn();
        const lifecycle = createLifecycle(store, closeOnIdle, 5_000);

        lifecycle.touch('channel-1');
        await vi.advanceTimersByTimeAsync(3_000);
        // Re-touch before the first timer would have fired: it must be cleared
        // and re-armed from zero.
        lifecycle.touch('channel-1');
        await vi.advanceTimersByTimeAsync(3_000);
        expect(closeOnIdle).not.toHaveBeenCalled();

        await vi.advanceTimersByTimeAsync(2_000);
        expect(closeOnIdle).toHaveBeenCalledTimes(1);
    });

    test('removeChannel cancels a pending idle timer', async () => {
        const store = createMemorySessionStore();
        const closeOnIdle = vi.fn();
        const lifecycle = createLifecycle(store, closeOnIdle, 5_000);

        lifecycle.touch('channel-1');
        lifecycle.removeChannel('channel-1');
        await vi.advanceTimersByTimeAsync(10_000);
        expect(closeOnIdle).not.toHaveBeenCalled();
    });

    test('removeChannel for an unknown channel is a no-op', () => {
        const store = createMemorySessionStore();
        const lifecycle = createLifecycle(store, vi.fn(), 5_000);
        // The `handle === undefined` branch inside `clear`.
        expect(() => lifecycle.removeChannel('never-touched')).not.toThrow();
    });

    test('shutdown cancels every outstanding timer', async () => {
        const store = createMemorySessionStore();
        const closeOnIdle = vi.fn();
        const lifecycle = createLifecycle(store, closeOnIdle, 5_000);

        lifecycle.touch('channel-1');
        lifecycle.touch('channel-2');
        lifecycle.shutdown();
        await vi.advanceTimersByTimeAsync(10_000);
        expect(closeOnIdle).not.toHaveBeenCalled();
    });

    test('a rejected closeOnIdle promise is swallowed (no unhandled rejection)', async () => {
        const store = createMemorySessionStore();
        const closeOnIdle = vi.fn(async () => {
            throw new Error('settle blew up');
        });
        const lifecycle = createLifecycle(store, closeOnIdle, 1_000);

        lifecycle.touch('channel-1');
        await vi.advanceTimersByTimeAsync(1_000);
        // The timer fired and invoked the handler; the rejection is caught
        // internally so this test simply completing is the assertion.
        expect(closeOnIdle).toHaveBeenCalledTimes(1);
    });

    test('touch tolerates a timer handle without unref()', () => {
        // Some environments return a plain numeric timer handle with no
        // `unref` method — exercise the `typeof handle.unref !== 'function'`
        // branch by returning a bare number from setTimeout.
        const store = createMemorySessionStore();
        const realSetTimeout = globalThis.setTimeout;
        const stub = ((fn: () => void, ms?: number) => {
            void realSetTimeout(fn, ms);
            return 12345 as unknown as ReturnType<typeof setTimeout>;
        }) as typeof setTimeout;
        vi.stubGlobal('setTimeout', stub);
        try {
            const lifecycle = createLifecycle(store, vi.fn(), 1_000);
            expect(() => lifecycle.touch('channel-1')).not.toThrow();
        } finally {
            vi.unstubAllGlobals();
        }
    });
});
