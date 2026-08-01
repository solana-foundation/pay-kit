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

import type { SessionAuthentication, SessionVoucherSigner } from '../../client/Session.js';

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

/** Cached operator-use result keyed by the HTTP idempotency key. */
export interface ProcessedUse {
    readonly challengeId: string;
    readonly cumulative: bigint;
    readonly idempotencyKey: string;
    readonly voucherSignature: string;
}

/**
 * Schema version stamped on every channel record this SDK writes.
 *
 * Durable store implementations MUST refuse to load a record whose
 * `schemaVersion` is newer than this value (decoding it would drop the
 * fields this SDK does not know, and a re-encode would destroy them for
 * every reader), and MUST round-trip unknown fields verbatim when they
 * serialize a record. Mirrors Rust `CHANNEL_STATE_SCHEMA_VERSION`.
 */
export const CHANNEL_STATE_SCHEMA_VERSION = 1;

/**
 * Persisted state of a single payment channel from the server's POV.
 * Field-for-field mirror of Rust `ChannelState`. `bigint` is used for
 * every Rust `u64` so we don't lose precision on > 2^53 amounts.
 */
export interface ChannelState {
    /** Reusable payer proof bound at open for operator-signed vouchers. */
    readonly authentication?: SessionAuthentication | undefined;
    /** Public key authorized to sign vouchers for this session (base58). */
    readonly authorizedSigner: string;
    /** On-chain payment-channel address (base58). */
    readonly channelId: string;
    /** Unix seconds when cooperative close was requested. Vouchers blocked once set. */
    readonly closeRequestedAt?: bigint | undefined;
    /** Recently committed deliveries (idempotent commit replay window). */
    readonly committedDeliveries: readonly CommittedDelivery[];
    /** Highest cumulative amount accepted by the server (settled watermark). */
    readonly cumulative: bigint;
    /** Total deposit / approved amount locked for this session (base units). */
    readonly deposit: bigint;
    /** Expiry timestamp from the highest accepted voucher. */
    readonly highestVoucherExpiresAt?: bigint | undefined;
    /** Signature of the highest accepted voucher (base58). For idempotent replay. */
    readonly highestVoucherSignature?: string | undefined;
    /** Effective negotiated inactivity threshold, in seconds. */
    readonly idleTimeoutSeconds?: number | undefined;
    /** Unix milliseconds of the most recent accepted channel activity. */
    readonly lastActivityAt?: number | undefined;
    /** Next server-side metered delivery sequence. */
    readonly nextDeliverySequence: bigint;
    /**
     * Slot the channel was opened at (a channel PDA seed). Needed to
     * re-derive the PDA and to gate reclaim (`slot > openSlot + 1500`).
     */
    readonly openSlot?: bigint | undefined;
    /** Challenge that was verified when the channel proof was bound. */
    readonly openingChallengeId?: string | undefined;
    /** On-chain channel payer and refund destination. */
    readonly payer: string;
    /** Deliveries reserved but not yet committed. */
    readonly pendingDeliveries: readonly PendingDelivery[];
    /**
     * Transaction signatures of top-ups already credited to `deposit`
     * (base58). Checked inside the atomic top-up mutator so a resubmitted or
     * concurrently duplicated top-up transaction credits exactly once.
     * `undefined` on records written before this field existed. Mirrors Rust
     * `processed_topup_signatures`.
     */
    readonly processedTopUpSignatures?: readonly string[] | undefined;
    /** Cached use results used to make retries exactly-once. */
    readonly processedUses: readonly ProcessedUse[];
    /** Account that funded and receives the channel rent. */
    readonly rentPayer: string;
    /**
     * Schema version stamped by the last writer. `undefined`/`0` for records
     * persisted before versioning. See `CHANNEL_STATE_SCHEMA_VERSION`.
     */
    readonly schemaVersion?: number | undefined;
    /** True once the channel has been sealed on-chain. */
    readonly sealed: boolean;
    /** Highest cumulative amount confirmed settled on-chain. */
    readonly settledOnChain: bigint;
    /** On-chain settle_and_seal transaction signature (base58), once submitted. */
    readonly settledSignature?: string | undefined;
    /** Cumulative amount charged for delivered service. */
    readonly spentAmount: bigint;
    /** Party responsible for signing cumulative vouchers. */
    readonly voucherSigner?: SessionVoucherSigner | undefined;
}

/**
 * Optional filter for `listChannels`.
 */
export interface ListChannelsFilter {
    /** Only include channels that have an in-flight `closeRequestedAt`. */
    readonly closePending?: boolean | undefined;
    /** Only include channels matching this sealed state. */
    readonly sealed?: boolean | undefined;
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
     * Convenience: flip `sealed` to true. Throws if the channel is
     * not found, matching the Rust behavior.
     */
    markSealed(channelId: string): Promise<ChannelState>;
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
                    if (filter.sealed !== undefined && state.sealed !== filter.sealed) {
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

        async markSealed(channelId) {
            return await withLock(channelId, () => {
                const current = data.get(channelId);
                if (!current) {
                    throw new Error(`Channel ${channelId} not found`);
                }
                const next: ChannelState = { ...current, sealed: true };
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
