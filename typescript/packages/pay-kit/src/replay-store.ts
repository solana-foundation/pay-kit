import type { Store } from 'mppx';

/** Replay store capability required by x402's reserve-before-settle lifecycle. */
export interface ReservingReplayStore extends Store.Store {
    /** Alternative capability name for a durable shared backend. */
    readonly isDurable?: boolean;
    /** Explicitly affirm that reservations survive restarts and span replicas. */
    readonly isShared?: boolean;
    reserve(key: string, value?: unknown, ttlSeconds?: number): Promise<boolean>;
}

/** Whether a store provides an atomic reserve operation. */
export function isReservingReplayStore(store: Store.Store): store is ReservingReplayStore {
    return typeof (store as Partial<ReservingReplayStore>).reserve === 'function';
}

/** Whether a replay store has declared a production-safe shared/durable backend. */
export function isProductionReplayStore(store: Store.Store): boolean {
    const candidate = store as Partial<ReservingReplayStore>;
    return candidate.isShared === true && candidate.isDurable === true;
}

/**
 * Process-local atomic replay store for local development and explicit insecure
 * off-localnet opt-in. Share the returned instance between handlers when they
 * run in one process; production replicas should inject a durable implementation
 * whose `reserve` maps to a datastore-native compare-and-set (for example SET NX).
 */
export function createMemoryReplayStore(): ReservingReplayStore {
    const entries = new Map<string, { expiresAt?: number; value: unknown }>();

    function live(key: string): { expiresAt?: number; value: unknown } | undefined {
        const entry = entries.get(key);
        if (entry?.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
            entries.delete(key);
            return undefined;
        }
        return entry;
    }

    return {
        delete(key: string): Promise<void> {
            entries.delete(key);
            return Promise.resolve();
        },
        get(key: string) {
            return Promise.resolve(live(key)?.value ?? null);
        },
        isDurable: false,
        isShared: false,
        put(key: string, value: unknown): Promise<void> {
            entries.set(key, { value });
            return Promise.resolve();
        },
        reserve(key: string, value: unknown = true, ttlSeconds?: number): Promise<boolean> {
            if (live(key) !== undefined) return Promise.resolve(false);
            entries.set(key, {
                expiresAt: ttlSeconds === undefined ? undefined : Date.now() + ttlSeconds * 1000,
                value,
            });
            return Promise.resolve(true);
        },
    };
}
