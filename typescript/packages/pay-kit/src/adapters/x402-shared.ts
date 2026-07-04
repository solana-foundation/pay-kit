import { createSolanaRpc } from '@solana/kit';

import { InvalidProofError } from '../errors.js';

/** The x402 payment credential header, read from either accepted name. */
export function x402PaymentHeader(request: Request): string | undefined {
    return request.headers.get('x-payment') ?? request.headers.get('payment-signature') ?? undefined;
}

/** The message of an Error-like value, or `undefined`. */
export function errorMessage(error: unknown): string | undefined {
    return error instanceof Error ? error.message : undefined;
}

/**
 * Maximum accepted size, in bytes, of the `X-PAYMENT` / `PAYMENT-SIGNATURE`
 * credential header. The header is base64-of-JSON (and, for exact, embeds a
 * full base64 transaction), so unbounded input drives proportionally larger
 * base64 + JSON decode work per request. Runtimes that do not enforce Node's
 * ~16 KiB HTTP header limit (workers, custom fetch front-ends) get no backstop
 * otherwise. Byte-based (not code-unit) to match the raw-header `len()` cap the
 * Rust upto/exact parsers enforce and the MPP challenge-guard's 16 KiB cap.
 */
export const MAX_PAYMENT_SIGNATURE_HEADER_LEN = 16 * 1024;

/**
 * Reject an over-cap credential header before any base64 / JSON decode work,
 * mirroring the Rust `parse_payment_signature` guard. Throws
 * {@link InvalidProofError} keyed `x402_payment_header_too_large`. The size is
 * measured in UTF-8 bytes ({@link Buffer.byteLength}) so it matches the raw
 * header length the on-wire limit and the Rust cap operate on.
 */
export function assertPaymentHeaderWithinCap(header: string): void {
    if (Buffer.byteLength(header, 'utf8') > MAX_PAYMENT_SIGNATURE_HEADER_LEN) {
        throw new InvalidProofError(
            'x402_payment_header_too_large',
            `payment header exceeds maximum size of ${MAX_PAYMENT_SIGNATURE_HEADER_LEN} bytes`,
        );
    }
}

/** A cached recent blockhash with the wall-clock time it was fetched. */
export type CachedBlockhash = {
    readonly blockhash: string;
    readonly fetchedAtMs: number;
    readonly lastValidBlockHeight: string;
};

/**
 * How long a challenge blockhash is reused before refetching. Every
 * unauthenticated 402 challenge otherwise fetches `getLatestBlockhash`, so an
 * unauthenticated burst amplifies straight into the RPC quota; caching collapses
 * it to at most one RPC per TTL. Kept well under the ~60s blockhash validity so
 * the stamped value stays fresh enough for the client to build its transaction.
 */
export const CHALLENGE_BLOCKHASH_TTL_MS = 5_000;

/**
 * A short-TTL, single-flight `getLatestBlockhash` cache shared by the exact and
 * upto adapters' 402 challenge builders. Entries are keyed by RPC url; a
 * concurrent burst collapses to a single RPC via the in-flight promise, and a
 * fetch failure yields `undefined` (the challenge degrades to no pre-fetched
 * blockhash) without poisoning the cache.
 */
export class ChallengeBlockhashCache {
    readonly #cache = new Map<string, CachedBlockhash>();
    readonly #inFlight = new Map<string, Promise<CachedBlockhash | undefined>>();

    /**
     * A recent blockhash for `rpcUrl`, served from cache when fresh, otherwise
     * fetched once (single-flight). Returns `undefined` on fetch failure.
     */
    async recentBlockhash(rpcUrl: string): Promise<CachedBlockhash | undefined> {
        const fresh = this.#cache.get(rpcUrl);
        if (fresh !== undefined && Date.now() - fresh.fetchedAtMs < CHALLENGE_BLOCKHASH_TTL_MS) {
            return fresh;
        }
        const pending = this.#inFlight.get(rpcUrl);
        if (pending !== undefined) return await pending;
        const fetchPromise = (async (): Promise<CachedBlockhash | undefined> => {
            try {
                const { value } = await createSolanaRpc(rpcUrl).getLatestBlockhash().send();
                const entry: CachedBlockhash = {
                    blockhash: value.blockhash,
                    fetchedAtMs: Date.now(),
                    lastValidBlockHeight: value.lastValidBlockHeight.toString(),
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
