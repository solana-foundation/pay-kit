// Replica-lag tolerance for the account read that follows a confirmed
// transaction.
//
// RPC providers can serve transaction status and account state from
// different replicas, so an account a just-confirmed transaction created or
// mutated can briefly read back missing or stale. A single unretried read
// turns that into a hard payment failure even though the funds are already
// escrowed on chain.
//
// Ported from x402-foundation/x402#3367 and widened to pay-kit's MPP sites.

/** Default number of reads, including the first. */
export const DEFAULT_CHANNEL_READ_MAX_ATTEMPTS = 6;

/** Default linear backoff step in ms. */
export const DEFAULT_CHANNEL_READ_BACKOFF_STEP_MS = 200;

/**
 * Tuning knobs for {@link readUntilVisible}. Both are optional and both
 * resolve to their default when unset or non-positive.
 */
export interface ChannelReadRetryOptions {
    /** Linear backoff step in ms. Defaults to 200. */
    readonly channelReadBackoffStepMs?: number | undefined;
    /** Total reads, including the first. Defaults to 6. */
    readonly channelReadMaxAttempts?: number | undefined;
}

function positiveOr(value: number | undefined, fallback: number): number {
    return value !== undefined && value > 0 ? value : fallback;
}

/**
 * Re-read `read()` with LINEAR backoff until `isVisible` accepts the result
 * or the attempt budget runs out, then return the last result either way.
 *
 * The delay before attempt N+1 is `backoffStep * N`, so the defaults
 * (6 attempts, 200ms step) schedule 200/400/600/800/1000ms: 3.0s total
 * with a 1s longest single wait. Linear, not exponential: replica lag is a
 * small multiple of Solana's ~400ms slot time, so doubling spends the
 * budget on single waits far longer than the lag it absorbs. There is no
 * sleep after the final attempt.
 *
 * `isVisible` must be false ONLY for the not-yet-visible state of that call
 * site. A visible-but-wrong state has to be reported as visible so the
 * caller rejects it on the spot, because retrying a wrong state on a money
 * path is worse than the lag it hides. A throwing `read()` (RPC transport
 * error) propagates immediately and is never retried.
 *
 * `options` is REQUIRED and its presence is the opt-in: pass `undefined`
 * and the read stays a single RPC call. Several of these reads double as
 * pre-broadcast existence probes where an absent account is the correct
 * answer, and those must not pay the retry budget on every first-time
 * request. An options object opts in; the two fields inside it fall back to
 * their defaults when unset or non-positive.
 */
export async function readUntilVisible<T>(
    read: () => Promise<T>,
    isVisible: (value: T) => boolean,
    options: ChannelReadRetryOptions | undefined,
): Promise<T> {
    if (options === undefined) return await read();
    const maxAttempts = positiveOr(options.channelReadMaxAttempts, DEFAULT_CHANNEL_READ_MAX_ATTEMPTS);
    const backoffStepMs = positiveOr(options.channelReadBackoffStepMs, DEFAULT_CHANNEL_READ_BACKOFF_STEP_MS);

    let result = await read();
    for (let attempt = 1; attempt < maxAttempts; attempt += 1) {
        if (isVisible(result)) return result;
        await new Promise(resolve => setTimeout(resolve, backoffStepMs * attempt));
        result = await read();
    }
    return result;
}
