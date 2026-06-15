// Per-channel idle-close lifecycle.
//
// When the server accepts an `open`, we arm a single-shot timer keyed on
// the channel id. Every voucher / commit / topUp `touch()` resets the
// timer. When the timer fires, we invoke `closeOnIdle(channelId)` so the
// server can run its close-and-settle path without waiting for a client
// `close` action.
//
// The idle-close watchdog is a TS-only extension — the Rust
// `SessionServer` has no equivalent; host integrations there drive close
// explicitly. The timer is unref'd so it doesn't keep the event loop
// alive on shutdown.

import type { SessionStore } from './store.js';

/**
 * Idle-close watchdog handle. `touch` resets the per-channel timer,
 * `removeChannel` cancels it, and `shutdown` cancels everything.
 */
export interface Lifecycle {
    /** Cancel the idle timer for `channelId`. */
    removeChannel(channelId: string): void;
    /** Cancel every outstanding timer. */
    shutdown(): void;
    /** Reset the idle timer for `channelId`. No-op if `closeDelayMs` is 0. */
    touch(channelId: string): void;
}

/**
 * Create a lifecycle watchdog. `closeDelayMs <= 0` disables the timer
 * entirely (all operations become no-ops) — the right default for tests
 * and for callers that drive close explicitly.
 *
 * `closeOnIdle` is invoked with the channel id when a timer fires. The
 * lifecycle itself does not call `store` — `store` is passed for parity
 * with the Rust signature and for future extension (e.g. skip closing a
 * channel already finalized).
 */
export function createLifecycle(
    store: SessionStore,
    closeOnIdle: (channelId: string) => Promise<void> | void,
    closeDelayMs: number,
): Lifecycle {
    void store;
    const timers = new Map<string, NodeJS.Timeout>();

    function clear(channelId: string): void {
        const handle = timers.get(channelId);
        if (handle !== undefined) {
            clearTimeout(handle);
            timers.delete(channelId);
        }
    }

    return {
        removeChannel(channelId) {
            clear(channelId);
        },
        shutdown() {
            for (const handle of timers.values()) clearTimeout(handle);
            timers.clear();
        },
        touch(channelId) {
            if (closeDelayMs <= 0) return;
            clear(channelId);
            const handle = setTimeout(() => {
                timers.delete(channelId);
                // Errors during idle close are swallowed — there is no
                // synchronous caller to report them to. The handler is
                // expected to log internally.
                void Promise.resolve()
                    .then(() => closeOnIdle(channelId))
                    .catch(() => undefined);
            }, closeDelayMs);
            // Don't keep the process alive on test shutdown.
            if (typeof handle.unref === 'function') handle.unref();
            timers.set(channelId, handle);
        },
    };
}
