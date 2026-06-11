import type { AmountLike, CommitReceipt } from './Session.js';
import { SessionFetchClient, type SessionFetchOpenState, withPatchedGlobalFetch } from './SessionFetch.js';

const U64_MAX = (1n << 64n) - 1n;

/**
 * Priced cumulative amount for the current metered operation.
 */
export interface SessionUsagePrice {
    /** Absolute cumulative amount to record, in base units. */
    readonly cumulativeAmount: AmountLike;
    /** Delta reported in the watermark event. Defaults to target − current. */
    readonly deltaAmount?: AmountLike | undefined;
}

/**
 * Context passed to a usage pricing function.
 */
export interface SessionUsagePricingContext {
    /** Session cumulative when the first usage sample of this operation arrived, in base units. */
    readonly baselineCumulativeAmount: string;
    /** Cumulative the session has accepted so far, in base units. */
    readonly currentCumulativeAmount: string;
    /** Open-session state from the fetch client. */
    readonly open: SessionFetchOpenState;
    /** Highest locally recorded watermark, in base units. */
    readonly targetCumulativeAmount?: string | undefined;
}

/**
 * Converts provider-specific usage into the absolute cumulative amount that
 * should be committed for the active session.
 */
export type SessionUsagePricer<Usage> = (
    usage: Usage,
    context: SessionUsagePricingContext,
) => SessionUsagePrice | null | undefined;

/**
 * High-level helper for SDK streams that expose provider-specific usage.
 *
 * The meter captures the session's cumulative watermark when the first usage
 * sample arrives, converts later usage samples into absolute cumulative amounts,
 * and delegates all voucher reservation/commit work to `SessionFetchClient`.
 *
 * @example
 * ```ts
 * const meter = createSessionUsageMeter({
 *     client,
 *     priceUsage: (usage, context) => ({
 *         cumulativeAmount: BigInt(context.baselineCumulativeAmount) + BigInt(usage.outputTokens),
 *     }),
 * });
 *
 * await meter.withPatchedFetch(async () => {
 *     const stream = await sdk.generateContentStream(request);
 *     for await (const chunk of stream) {
 *         meter.recordUsage(chunk.usage);
 *     }
 * });
 * await meter.flush();
 * ```
 */
export class SessionUsageMeter<Usage> {
    readonly #client: SessionFetchClient;
    readonly #priceUsage: SessionUsagePricer<Usage>;
    #baselineCumulativeAmount: string | undefined;
    #lastRecordedCumulative: bigint | undefined;

    constructor(parameters: SessionUsageMeter.Parameters<Usage>) {
        this.#client = parameters.client;
        this.#priceUsage = parameters.priceUsage;
    }

    /** Session fetch client used by this meter. */
    get client(): SessionFetchClient {
        return this.#client;
    }

    /** First cumulative watermark observed for the current metered operation. */
    get baselineCumulativeAmount(): string | undefined {
        return this.#baselineCumulativeAmount;
    }

    /**
     * Clears the per-operation baseline. Call this before reusing one meter for
     * another upstream stream on the same open session.
     */
    resetBaseline(): void {
        this.#baselineCumulativeAmount = undefined;
        this.#lastRecordedCumulative = undefined;
    }

    /**
     * Records a usage snapshot. Returns true when it accepted a new cumulative
     * watermark and queued session commit handling.
     */
    recordUsage(usage: Usage, options: SessionUsageMeter.RecordOptions = {}): boolean {
        const open = this.#client.open;
        if (!open) return false;

        const baseline = this.#baselineCumulativeAmount ?? this.#client.cumulativeAmount;
        this.#baselineCumulativeAmount = baseline;

        const price = this.#priceUsage(usage, {
            baselineCumulativeAmount: baseline,
            currentCumulativeAmount: this.#client.cumulativeAmount,
            open,
            targetCumulativeAmount: this.#client.targetCumulativeAmount,
        });
        if (!price) return false;

        const target = parseUsageAmount(price.cumulativeAmount, 'cumulativeAmount');
        if (!options.force && this.#lastRecordedCumulative !== undefined && target <= this.#lastRecordedCumulative) {
            return false;
        }
        this.#lastRecordedCumulative = target;

        this.#client.recordCumulative(price.cumulativeAmount, {
            deltaAmount: price.deltaAmount,
            force: options.force,
        });
        return true;
    }

    /**
     * Forces pricing for the latest usage sample, then waits for any queued
     * voucher commits to settle.
     */
    async flush(usage?: Usage): Promise<CommitReceipt | null> {
        if (usage !== undefined) {
            this.recordUsage(usage, { force: true });
        }
        return await this.#client.flush();
    }

    /**
     * Runs an SDK call while global `fetch` is temporarily replaced with the
     * session-aware fetch client.
     */
    async withPatchedFetch<Value>(operation: () => Promise<Value>): Promise<Value> {
        return await withPatchedGlobalFetch(this.#client.fetch, operation);
    }
}

export declare namespace SessionUsageMeter {
    interface Parameters<Usage> {
        /** Session fetch client that owns the open session and voucher commits. */
        readonly client: SessionFetchClient;
        /** Converts provider usage samples into absolute cumulative amounts. */
        readonly priceUsage: SessionUsagePricer<Usage>;
    }

    interface RecordOptions {
        /** Commit immediately instead of waiting for the live-commit interval. */
        readonly force?: boolean | undefined;
    }
}

/**
 * Creates a usage meter for an existing `SessionFetchClient`.
 */
export function createSessionUsageMeter<Usage>(
    parameters: SessionUsageMeter.Parameters<Usage>,
): SessionUsageMeter<Usage> {
    return new SessionUsageMeter(parameters);
}

function parseUsageAmount(value: AmountLike, name: string): bigint {
    let parsed: bigint;
    if (typeof value === 'bigint') {
        parsed = value;
    } else if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) throw new Error(`${name} must be a safe integer`);
        parsed = BigInt(value);
    } else {
        if (!/^\d+$/.test(value)) throw new Error(`${name} must be an integer string`);
        parsed = BigInt(value);
    }

    if (parsed < 0n) throw new Error(`${name} must be non-negative`);
    if (parsed > U64_MAX) throw new Error(`${name} exceeds u64 max`);
    return parsed;
}
