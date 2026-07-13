import { createSolanaRpc } from '@solana/kit';

import type { PayKitConfig } from '../config.js';
import { ConfigurationError, InvalidProofError } from '../errors.js';
import { createMemoryReplayStore, isReservingReplayStore, type ReservingReplayStore } from '../replay-store.js';

export { isReservingReplayStore, type ReservingReplayStore } from '../replay-store.js';

/** Env opt-in that permits a process-local in-memory replay store off localnet. */
const ALLOW_INMEMORY_REPLAY_STORE_ENV = 'PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE';

/**
 * Resolve the reserving replay store an x402 adapter fences settlement against.
 *
 * A caller-supplied store wins (it must expose the atomic `reserve` capability).
 * With none supplied, localnet (or the explicit off-localnet opt-in) gets a
 * process-local in-memory store so a dev boot needs no wiring, mirroring how
 * the MPP session adapter provisions its store. Off localnet without the opt-in
 * this fails closed: no silent memory store on devnet/mainnet.
 */
export function resolveX402ReplayStore(config: PayKitConfig, scheme: string): ReservingReplayStore {
    const store = config.replayStore;
    if (store !== undefined) {
        if (!isReservingReplayStore(store)) {
            throw new ConfigurationError(`x402 ${scheme} requires a replayStore with atomic reserve capability.`);
        }
        return store;
    }
    if (config.network === 'solana_localnet' || process.env[ALLOW_INMEMORY_REPLAY_STORE_ENV] === '1') {
        return createMemoryReplayStore();
    }
    throw new ConfigurationError(`x402 ${scheme} requires a replayStore with atomic reserve capability.`);
}

/** The x402 payment credential header, read from either accepted name. */
export function x402PaymentHeader(request: Request): string | undefined {
    return request.headers.get('x-payment') ?? request.headers.get('payment-signature') ?? undefined;
}

/** The message of an Error-like value, or `undefined`. */
export function errorMessage(error: unknown): string | undefined {
    return error instanceof Error ? error.message : undefined;
}

/** Maximum UTF-8 byte length accepted for an x402 credential header. */
export const MAX_PAYMENT_SIGNATURE_HEADER_LEN = 16 * 1024;

/** Reject oversized credentials before base64 or JSON decoding. */
export function assertPaymentHeaderWithinCap(header: string): void {
    if (Buffer.byteLength(header, 'utf8') > MAX_PAYMENT_SIGNATURE_HEADER_LEN) {
        throw new InvalidProofError(
            'x402_payment_header_too_large',
            `payment header exceeds maximum size of ${MAX_PAYMENT_SIGNATURE_HEADER_LEN} bytes`,
        );
    }
}

export type CachedBlockhash = {
    readonly blockhash: string;
    readonly fetchedAtMs: number;
    readonly lastValidBlockHeight: string;
    readonly recentSlot: string;
};

/** Keep challenge blockhashes fresh while collapsing unauthenticated RPC bursts. */
export const CHALLENGE_BLOCKHASH_TTL_MS = 5_000;

/** Short-TTL, single-flight blockhash cache shared by the exact and upto adapters. */
export class ChallengeBlockhashCache {
    readonly #cache = new Map<string, CachedBlockhash>();
    readonly #inFlight = new Map<string, Promise<CachedBlockhash | undefined>>();

    async recentBlockhash(rpcUrl: string): Promise<CachedBlockhash | undefined> {
        const cached = this.#cache.get(rpcUrl);
        if (cached !== undefined && Date.now() - cached.fetchedAtMs < CHALLENGE_BLOCKHASH_TTL_MS) {
            return cached;
        }
        const pending = this.#inFlight.get(rpcUrl);
        if (pending !== undefined) return await pending;

        const fetchPromise = (async (): Promise<CachedBlockhash | undefined> => {
            try {
                const { context, value } = await createSolanaRpc(rpcUrl).getLatestBlockhash().send();
                const entry: CachedBlockhash = {
                    blockhash: value.blockhash,
                    fetchedAtMs: Date.now(),
                    lastValidBlockHeight: value.lastValidBlockHeight.toString(),
                    recentSlot: context.slot.toString(),
                };
                this.#cache.set(rpcUrl, entry);
                return entry;
            } catch {
                return undefined;
            } finally {
                this.#inFlight.delete(rpcUrl);
            }
        })();
        this.#inFlight.set(rpcUrl, fetchPromise);
        return await fetchPromise;
    }
}
