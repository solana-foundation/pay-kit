import { Errors, Store } from 'mppx';

/**
 * Optional capability declaration for replay stores.
 *
 * Production stores must affirm both capabilities. Unknown injected stores are
 * rejected; the explicit development
 * escape hatch can authorize only SDK-created memory stores.
 */
export type ReplayStoreCapability = {
    readonly isDurable?: boolean;
    readonly isShared?: boolean;
};

export type ReplayStore = ReplayStoreCapability &
    Store.Store & {
        readonly putIfAbsent: (key: string, value: unknown) => Promise<boolean>;
    };

const unsafeMemoryReplayStores = new WeakSet<object>();

function isProductionReplayStore(store: Store.Store): boolean {
    const candidate = store as ReplayStore;
    return candidate.isShared === true && candidate.isDurable === true;
}

/** True only for memory stores created by this SDK module. */
export function isUnsafeMemoryReplayStore(store: Store.Store): boolean {
    return unsafeMemoryReplayStores.has(store);
}

/** Create the only process-local replay store that the unsafe flag can authorize. */
export function createUnsafeMemoryReplayStore(): ReplayStore {
    const values = new Map<string, unknown>();
    const store: ReplayStore = {
        delete(key) {
            values.delete(key);
            return Promise.resolve();
        },
        get(key) {
            return Promise.resolve((values.get(key) ?? null) as never);
        },
        put(key, value) {
            values.set(key, value);
            return Promise.resolve();
        },
        putIfAbsent(key, value) {
            if (values.has(key)) return Promise.resolve(false);
            values.set(key, value);
            return Promise.resolve(true);
        },
    };
    unsafeMemoryReplayStores.add(store);
    return store;
}

/**
 * Adapt an atomic replay store to mppx's Store surface while preserving the
 * module-local unsafe-memory brand for pay-kit's low-level handlers.
 */
export function createAtomicReplayStoreView(store: ReplayStore): ReplayStore {
    const view: ReplayStore = {
        delete: key => store.delete(key),
        get: key => store.get(key),
        ...(store.isDurable === undefined ? {} : { isDurable: store.isDurable }),
        ...(store.isShared === undefined ? {} : { isShared: store.isShared }),
        async put(key, value) {
            if (key.startsWith('solana-charge:consumed:') || key.startsWith('solana-subscription:consumed:')) {
                if (!(await store.putIfAbsent(key, value))) {
                    throw new Errors.VerificationFailedError({ reason: 'MPP replay key is already reserved' });
                }
                return;
            }
            await store.put(key, value);
        },
        putIfAbsent: (key, value) => store.putIfAbsent(key, value),
    };
    if (isUnsafeMemoryReplayStore(store)) unsafeMemoryReplayStores.add(view);
    return view;
}

/** Resolve replay storage without silently falling back to process-local memory. */
export function resolveReplayStore(
    store: Store.Store | undefined,
    allowUnsafeMemoryStore: boolean | undefined,
    methodName: 'charge' | 'subscription',
): ReplayStore {
    if (store === undefined) {
        if (allowUnsafeMemoryStore === true) {
            console.warn(
                `[solana-mpp] ${methodName} explicitly enabled a process-local replay store. ` +
                    'Replay markers are lost on restart and are not shared across workers.',
            );
            return createUnsafeMemoryReplayStore();
        }
        throw new Error(
            `solana.${methodName} requires an explicit replay store; ` +
                'provide store or set allowUnsafeMemoryStore=true for development.',
        );
    }

    if (isUnsafeMemoryReplayStore(store)) {
        if (allowUnsafeMemoryStore === true) return store as ReplayStore;
        throw new Error(
            `solana.${methodName} replay store is process-local memory; ` +
                'set allowUnsafeMemoryStore=true for explicit development use.',
        );
    }

    if (!isProductionReplayStore(store) || !('putIfAbsent' in store) || typeof store.putIfAbsent !== 'function') {
        throw new Error(
            `solana.${methodName} replay store must implement atomic putIfAbsent and report ` +
                'isShared=true and isDurable=true.',
        );
    }

    return store as ReplayStore;
}
