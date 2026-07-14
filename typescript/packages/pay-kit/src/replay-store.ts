import {
    createAtomicReplayStoreView,
    createUnsafeMemoryReplayStore as createMppUnsafeMemoryReplayStore,
    isUnsafeMemoryReplayStore as isMppUnsafeMemoryReplayStore,
} from '@solana/mpp/server';
import type { Store } from 'mppx';

const productionReplayStores = new WeakSet<object>();
const unsafeMemoryReplayStores = new WeakSet<object>();

/** Atomic replay-store contract required by MPP server construction. */
export type ReplayStore = Store.Store & {
    readonly isDurable?: boolean;
    readonly isShared?: boolean;
    putIfAbsent(key: string, value: unknown): Promise<boolean>;
};

/** Narrow the legacy Store.Store surface to the atomic replay contract. */
export function isAtomicReplayStore(store: Store.Store): store is ReplayStore {
    return 'putIfAbsent' in store && typeof store.putIfAbsent === 'function';
}

/**
 * Declare an externally provided replay store safe for production use.
 *
 * This is an affirmative application trust boundary, not a runtime probe:
 * call it only after verifying that the backend is shared across every
 * worker, durable across restarts, and implements `putIfAbsent` atomically.
 * The declaration is retained by object identity, so copying capability
 * booleans onto an unknown or process-local store cannot grant it trust.
 */
export function declareProductionReplayStore<T extends ReplayStore>(store: T): T {
    if (isUnsafeMemoryReplayStore(store)) {
        throw new TypeError('Process-local memory stores cannot be declared production replay stores.');
    }
    if (!isAtomicReplayStore(store)) {
        throw new TypeError('Production replay stores must implement atomic putIfAbsent(key, value).');
    }
    if (store.isShared !== true || store.isDurable !== true) {
        throw new TypeError('Production replay stores must set isShared=true and isDurable=true.');
    }
    productionReplayStores.add(store);
    return store;
}

export function isProductionReplayStore(store: ReplayStore): boolean {
    return productionReplayStores.has(store);
}

export function isUnsafeMemoryReplayStore(store: Store.Store): boolean {
    return unsafeMemoryReplayStores.has(store) || isMppUnsafeMemoryReplayStore(store);
}

/** Only a built-in unsafe memory store may use the explicit development escape. */
export function isAuthorizedUnsafeMemoryReplayStore(store: Store.Store): boolean {
    return unsafeMemoryReplayStores.has(store);
}

/** Explicit process-local store used only behind the unsafe development flag. */
export function createUnsafeMemoryReplayStore(): ReplayStore {
    const store = createMppUnsafeMemoryReplayStore();
    unsafeMemoryReplayStores.add(store);
    return store;
}

/**
 * Adapt pay-kit's atomic store to the upstream get/put Store surface.
 *
 * #211 already serializes charge verification inside one process. This view
 * leaves that lock untouched and upgrades only the final consumed-marker write
 * to a cross-instance atomic reservation. It also exposes `reserve` (aliasing
 * `putIfAbsent`) so the same view satisfies the subscription server's store
 * contract without the operator having to implement two atomic primitives.
 */
export function atomicReplayStoreView(
    store: ReplayStore,
): ReplayStore & { reserve(key: string, value?: unknown, ttlSeconds?: number): Promise<boolean> } {
    return createAtomicReplayStoreView(store) as ReplayStore & {
        reserve(key: string, value?: unknown, ttlSeconds?: number): Promise<boolean>;
    };
}
