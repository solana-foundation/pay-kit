import type { SubscriptionReplayStore } from '@solana/mpp/server';

/** Atomic replay-store contract required by MPP subscription activation. */
export type AtomicSubscriptionReplayStore = SubscriptionReplayStore & {
    readonly isDurable?: boolean;
    readonly isShared?: boolean;
};

/**
 * Explicit process-local store for local development only.
 *
 * Production deployments must provide a shared, durable implementation of
 * {@link AtomicSubscriptionReplayStore} so reservations survive restarts and
 * coordinate across server instances.
 */
export function createUnsafeMemorySubscriptionReplayStore(): AtomicSubscriptionReplayStore {
    const values = new Map<string, unknown>();
    return {
        delete(key) {
            values.delete(key);
            return Promise.resolve();
        },
        get(key) {
            return Promise.resolve((values.get(key) ?? null) as never);
        },
        isDurable: false,
        isShared: false,
        put(key, value) {
            values.set(key, value);
            return Promise.resolve();
        },
        reserve(key, value = true) {
            if (values.has(key)) return Promise.resolve(false);
            values.set(key, value);
            return Promise.resolve(true);
        },
    };
}
