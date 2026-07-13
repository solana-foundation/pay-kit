import { createSolanaRpc } from '@solana/kit';

import { InvalidProofError } from '../errors.js';

export { isReservingReplayStore, type ReservingReplayStore } from '../replay-store.js';

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
