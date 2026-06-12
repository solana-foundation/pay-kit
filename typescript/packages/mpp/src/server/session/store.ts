// Per-channel state store for the MPP session server.
//
// Mirrors the Rust `ChannelStore` trait + `MemoryChannelStore` impl in
// `rust/crates/mpp/src/store.rs`. The in-memory implementation serializes
// `updateChannel` calls per channel id via a promise chain, so the
// read-modify-write sequence inside the mutator is atomic from the
// perspective of any other caller targeting the same channel.
//
// The verifier (see ./voucher.ts) is intentionally side-effect-free —
// it computes a delta, and the caller persists it through
// `store.updateChannel`. That keeps the verifier easy to test and lets
// the integration layer pick its own consistency story (CAS, RMW, etc.).

/**
 * One delivery that the server has reserved against a channel but not yet
 * received a signed voucher for. Mirrors Rust `PendingDelivery`.
 */
export interface PendingDelivery {
    readonly amount: bigint;
    readonly deliveryId: string;
    readonly expiresAt: bigint;
    readonly sequence: bigint;
}

/**
 * A delivery that has been committed by a signed voucher. Kept for
 * idempotent commit replay. Mirrors Rust `CommittedDelivery`.
 */
export interface CommittedDelivery {
    readonly amount: bigint;
    readonly cumulative: bigint;
    readonly deliveryId: string;
    readonly voucherSignature: string;
}

/**
 * Persisted state of a single payment channel from the server's POV.
 * Field-for-field mirror of Rust `ChannelState`. `bigint` is used for
 * every Rust `u64` so we don't lose precision on > 2^53 amounts.
 */
export interface ChannelState {
    /** Public key authorized to sign vouchers for this session (base58). */
    readonly authorizedSigner: string;
    /**
     * On-chain channel address (base58).
     *
     * - Push sessions: payment-channel address.
     * - Pull sessions: FixedDelegation PDA address.
     */
    readonly channelId: string;
    /** Unix seconds when cooperative close was requested. Vouchers blocked once set. */
    readonly closeRequestedAt?: bigint | undefined;
    /** Recently committed deliveries (idempotent commit replay window). */
    readonly committedDeliveries: readonly CommittedDelivery[];
    /** Highest cumulative amount accepted by the server (settled watermark). */
    readonly cumulative: bigint;
    /** Total deposit / approved amount locked for this session (base units). */
    readonly deposit: bigint;
    /** True once the channel has been finalized on-chain. */
    readonly finalized: boolean;
    /** Expiry timestamp from the highest accepted voucher. */
    readonly highestVoucherExpiresAt?: bigint | undefined;
    /** Signature of the highest accepted voucher (base58). For idempotent replay. */
    readonly highestVoucherSignature?: string | undefined;
    /** Next server-side metered delivery sequence. */
    readonly nextDeliverySequence: bigint;
    /** Pull-mode only: client wallet pubkey (base58). `undefined` for push. */
    readonly operator?: string | undefined;
    /** Deliveries reserved but not yet committed. */
    readonly pendingDeliveries: readonly PendingDelivery[];
    /** On-chain settle_and_finalize transaction signature (base58), once submitted. */
    readonly settledSignature?: string | undefined;
}

/**
 * Optional filter for `listChannels`.
 */
export interface ListChannelsFilter {
    /** Only include channels that have an in-flight `closeRequestedAt`. */
    readonly closePending?: boolean | undefined;
    /** Only include channels matching this finalized state. */
    readonly finalized?: boolean | undefined;
}

/**
 * Mutator handed to `updateChannel`. Receives the current state
 * (or `undefined` if no channel exists) and returns the next state.
 *
 * Implementations MUST guarantee the mutator runs without interleaving
 * with other `updateChannel` calls for the same channel id.
 */
export type ChannelMutator = (current: ChannelState | undefined) => ChannelState | Promise<ChannelState>;

/**
 * Async store for per-channel state.
 *
 * `updateChannel` is the only safe way to mutate a channel — direct
 * `put` is not exposed because the verifier always needs an atomic
 * read-modify-write to avoid double-spend under concurrent vouchers.
 */
export interface SessionStore {
    /** Remove a channel from the store. */
    deleteChannel(channelId: string): Promise<void>;
    /** Read a channel. Returns `undefined` if it doesn't exist. */
    getChannel(channelId: string): Promise<ChannelState | undefined>;
    /** Snapshot list. Filter is applied after read. */
    listChannels(filter?: ListChannelsFilter): Promise<readonly ChannelState[]>;
    /**
     * Convenience: flip `finalized` to true. Throws if the channel is
     * not found, matching the Rust behavior.
     */
    markFinalized(channelId: string): Promise<ChannelState>;
    /** Atomically read-modify-write a channel's state. */
    updateChannel(channelId: string, mutator: ChannelMutator): Promise<ChannelState>;
}

/**
 * In-memory `SessionStore`. Per-channel async locking via a promise
 * chain keyed on channel id — so `updateChannel(id, …)` calls for the
 * same `id` run strictly sequentially, but calls for different ids
 * run concurrently.
 */
export function createMemorySessionStore(): SessionStore {
    const data = new Map<string, ChannelState>();
    // Per-channel tail of the serial-execution promise chain. Each
    // `updateChannel` appends its work to `locks.get(id)` and replaces
    // it with the new tail.
    const locks = new Map<string, Promise<unknown>>();

    function withLock<T>(channelId: string, work: () => Promise<T>): Promise<T> {
        const previous = locks.get(channelId) ?? Promise.resolve();
        // Swallow the previous result so one failed update doesn't poison
        // the chain for later updates on the same channel.
        const next = previous.then(work, work);
        locks.set(
            channelId,
            next.catch(() => undefined),
        );
        return next;
    }

    return {
        deleteChannel(channelId) {
            data.delete(channelId);
            return Promise.resolve();
        },

        getChannel(channelId) {
            return Promise.resolve(data.get(channelId));
        },

        listChannels(filter) {
            const all = Array.from(data.values());
            if (!filter) return Promise.resolve(all);
            return Promise.resolve(
                all.filter(state => {
                    if (filter.finalized !== undefined && state.finalized !== filter.finalized) {
                        return false;
                    }
                    if (filter.closePending !== undefined) {
                        const isCloseRequested = state.closeRequestedAt !== undefined;
                        if (filter.closePending !== isCloseRequested) return false;
                    }
                    return true;
                }),
            );
        },

        async markFinalized(channelId) {
            return await withLock(channelId, () => {
                const current = data.get(channelId);
                if (!current) {
                    throw new Error(`Channel ${channelId} not found`);
                }
                const next: ChannelState = { ...current, finalized: true };
                data.set(channelId, next);
                return Promise.resolve(next);
            });
        },

        async updateChannel(channelId, mutator) {
            return await withLock(channelId, async () => {
                const current = data.get(channelId);
                const nextState = await mutator(current);
                data.set(channelId, nextState);
                return nextState;
            });
        },
    };
}
