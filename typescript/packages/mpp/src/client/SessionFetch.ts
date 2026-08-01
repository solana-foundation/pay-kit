import { getBase58Decoder } from '@solana/kit';

import {
    selectSolanaSessionChallengeFromResponse,
    type SelectSolanaSessionChallengeOptions,
} from './ChallengeSelection.js';
import {
    ActiveSession,
    type AmountLike,
    type CommitReceipt,
    type MeteringDirective,
    type OpenPayload,
    serializeSessionCredential,
    type SessionChallenge,
    type SignedVoucher,
} from './Session.js';

type FetchInput = Parameters<typeof globalThis.fetch>[0];
type FetchInit = Parameters<typeof globalThis.fetch>[1];

const DEFAULT_LIVE_COMMIT_INTERVAL_MS = 1_000;
const U64_MAX = (1n << 64n) - 1n;

/**
 * Request tuple returned by request preparation hooks.
 */
export interface PreparedFetchRequest {
    /** Fetch init to use for the attempt. */
    readonly init?: FetchInit;
    /** Fetch input (URL or `Request`) to use for the attempt. */
    readonly input: FetchInput;
}

/**
 * Session details returned by an opener after local/on-chain setup succeeds.
 */
export interface SessionOpenResult {
    /** Open action that authorizes the paid retry. */
    readonly payload: OpenPayload & { readonly action: 'open' };
    /** Local session that signs vouchers from here on. */
    readonly session: ActiveSession;
    /** Optional client identifier serialized into the credential. */
    readonly source?: string | undefined;
}

/**
 * Parameters passed to a session opener.
 */
export interface SessionOpenParameters {
    /** Parsed Solana session challenge from the 402. */
    readonly challenge: SessionChallenge;
    /** Fetch init of the original attempt. */
    readonly init?: FetchInit;
    /** Fetch input of the original attempt. */
    readonly input: FetchInput;
    /** The raw 402 response. */
    readonly response: Response;
}

/**
 * Opens a payment session and returns the action that should authorize the retry.
 */
export type SessionOpener = (parameters: SessionOpenParameters) => Promise<SessionOpenResult> | SessionOpenResult;

/**
 * Hook for transforming requests before the first attempt and paid retry.
 */
export type PrepareSessionRequest = (request: PreparedFetchRequest) => PreparedFetchRequest;

/**
 * State created after a 402 session challenge has been paid.
 */
export interface SessionFetchOpenState extends SessionOpenResult {
    /** Serialized `Authorization` header value used on retries and commits. */
    readonly authorization: string;
    /** Challenge the session was opened against. */
    readonly challenge: SessionChallenge;
    /** URL voucher commits are POSTed back to (the opened resource by default). */
    readonly commitUrl: string;
}

/**
 * Parameters used to reserve a metered delivery.
 */
export interface ReserveSessionDeliveryParameters {
    /** Delivery price, in base units. */
    readonly amount: string;
    /** Endpoint the eventual commit should be POSTed to. */
    readonly commitUrl: string;
    /** Unique id for the delivery being reserved. */
    readonly deliveryId: string;
    /** Session the delivery is billed against. */
    readonly session: ActiveSession;
}

/**
 * Parameters used to commit a metered delivery.
 */
export interface CommitSessionDeliveryParameters {
    /** Committed amount, in base units. */
    readonly amount: string;
    /** Directive issued when the delivery was reserved. */
    readonly directive: MeteringDirective;
    /** Session signing the commit voucher. */
    readonly session: ActiveSession;
    /** Signed cumulative voucher covering the delivery. */
    readonly voucher: SignedVoucher;
}

/**
 * Events emitted by `SessionFetchClient`.
 */
export type SessionFetchEvent =
    | {
          readonly cumulativeAmount: string;
          readonly deltaAmount: string;
          readonly sessionId: string;
          readonly type: 'watermark';
      }
    | { readonly challenge: SessionChallenge; readonly type: 'challenge' }
    | { readonly open: SessionFetchOpenState; readonly type: 'open' }
    | { readonly receipt: CommitReceipt; readonly type: 'commit' }
    | { readonly response: Response; readonly type: 'retry' };

/**
 * High-level HTTP helper for Solana payment sessions.
 *
 * It handles session 402 challenges, paid retries, delivery reservations, and
 * throttled cumulative voucher commits. Apps only need to open the session and
 * report their current metered cumulative amount while they stream work.
 */
export class SessionFetchClient {
    readonly #fetch: typeof globalThis.fetch;
    readonly #liveCommitIntervalMs: number;
    readonly #onEvent: ((event: SessionFetchEvent) => void) | undefined;
    readonly #opener: SessionOpener;
    readonly #prepareRequest: PrepareSessionRequest | undefined;
    readonly #selectChallengeOptions: SelectSolanaSessionChallengeOptions | undefined;

    #commitFailure: Error | undefined;
    #commitQueue: Promise<CommitReceipt | null> = Promise.resolve(null);
    #lastCommitQueuedAt = 0;
    #lastQueuedCumulative = 0n;
    #open: SessionFetchOpenState | undefined;
    #targetCumulative: bigint | undefined;
    #trailingCommitTimer: ReturnType<typeof setTimeout> | undefined;

    constructor(parameters: SessionFetchClient.Parameters) {
        // Bind so Window.fetch's `this` check doesn't reject when the function
        // is invoked as a private-field method on this instance.
        this.#fetch = parameters.fetch ?? globalThis.fetch.bind(globalThis);
        this.#liveCommitIntervalMs = parameters.liveCommitIntervalMs ?? DEFAULT_LIVE_COMMIT_INTERVAL_MS;
        this.#onEvent = parameters.onEvent;
        this.#opener = parameters.opener;
        this.#prepareRequest = parameters.prepareRequest;
        this.#selectChallengeOptions = parameters.selectChallenge;
    }

    /**
     * Drop-in replacement for `fetch`.
     */
    readonly fetch: typeof globalThis.fetch = async (input, init) => {
        return await this.fetchWithSession(input, init);
    };

    /** Last open session state, when available. */
    get open(): SessionFetchOpenState | undefined {
        return this.#open;
    }

    /** Active local session, when available. */
    get session(): ActiveSession | undefined {
        return this.#open?.session;
    }

    /** Current accepted cumulative voucher amount. */
    get cumulativeAmount(): string {
        return this.#open?.session.cumulativeAmount ?? '0';
    }

    /** Highest locally observed cumulative watermark. */
    get targetCumulativeAmount(): string | undefined {
        return this.#targetCumulative?.toString();
    }

    /**
     * Fetches a resource, automatically opening a session when a Solana session
     * 402 challenge is returned.
     */
    async fetchWithSession(input: FetchInput, init?: FetchInit): Promise<Response> {
        this.throwCommitFailure();
        const prepared = this.prepare({ init, input: cloneFetchInput(input) });
        const response = await this.#fetch(prepared.input, prepared.init);
        if (response.status !== 402) {
            return response;
        }

        const challenge = selectSolanaSessionChallengeFromResponse(response, this.#selectChallengeOptions);
        if (!challenge) {
            return response;
        }

        this.emit({ challenge, type: 'challenge' });
        const opened = await this.#opener({
            challenge,
            init,
            input,
            response,
        });
        const authorization = serializeSessionCredential({
            challenge,
            payload: opened.payload,
            source: opened.source,
        });
        const open: SessionFetchOpenState = {
            ...opened,
            authorization,
            challenge,
            commitUrl: requestUrl(input),
        };
        await this.replaceOpenState(open);
        this.emit({ open, type: 'open' });

        const retry = this.prepare({
            init: withAuthorization(init, authorization),
            input: cloneFetchInput(input),
        });
        const retryResponse = await this.#fetch(retry.input, retry.init);
        this.emit({ response: retryResponse, type: 'retry' });
        return retryResponse;
    }

    /**
     * Records the latest absolute cumulative amount. The client emits the local
     * watermark immediately and sends a voucher commit at most once per interval.
     */
    recordCumulative(cumulativeAmount: AmountLike, options: SessionFetchClient.RecordOptions = {}): void {
        this.throwCommitFailure();
        const open = this.requireOpen();
        const target = parseAmount(cumulativeAmount, 'cumulativeAmount');
        const current = open.session.cumulative;
        if (target <= current) {
            return;
        }

        this.#targetCumulative =
            this.#targetCumulative === undefined || target > this.#targetCumulative ? target : this.#targetCumulative;

        this.emit({
            cumulativeAmount: target.toString(),
            deltaAmount: formatAmount(options.deltaAmount ?? target - current, 'deltaAmount'),
            sessionId: open.session.channelId,
            type: 'watermark',
        });

        const now = Date.now();
        if (options.force || now - this.#lastCommitQueuedAt >= this.#liveCommitIntervalMs) {
            this.clearTrailingCommit();
            this.#lastCommitQueuedAt = now;
            this.queueCommit(target);
        } else {
            this.scheduleTrailingCommit(this.#liveCommitIntervalMs - (now - this.#lastCommitQueuedAt));
        }
    }

    /**
     * Commits an absolute cumulative amount immediately.
     */
    async commitCumulative(cumulativeAmount: AmountLike): Promise<CommitReceipt | null> {
        this.recordCumulative(cumulativeAmount, { force: true });
        return await this.flush();
    }

    /**
     * Sends the latest recorded cumulative watermark and waits for all pending
     * commits to settle.
     */
    async flush(): Promise<CommitReceipt | null> {
        this.throwCommitFailure();
        if (this.#targetCumulative !== undefined) {
            this.clearTrailingCommit();
            this.queueCommit(this.#targetCumulative);
        }

        const receipt = await this.#commitQueue;
        this.throwCommitFailure();
        return receipt;
    }

    private prepare(request: PreparedFetchRequest): PreparedFetchRequest {
        return this.#prepareRequest ? this.#prepareRequest(request) : request;
    }

    /**
     * Installs a freshly opened session. When the channel changes, any pending
     * watermark is flushed against the previous channel first (best effort;
     * a failure latches as a recoverable commit failure) and the commit
     * watermark state is re-keyed to the new channel so no voucher can sign a
     * cumulative the new channel did not meter.
     */
    private async replaceOpenState(open: SessionFetchOpenState): Promise<void> {
        const previous = this.#open;
        if (previous?.session.channelId === open.session.channelId) {
            this.#open = open;
            return;
        }

        if (previous) {
            this.clearTrailingCommit();
            const target = this.#targetCumulative;
            if (target !== undefined && target > previous.session.cumulative) {
                this.queueCommitFor(previous, target);
            }
            await this.#commitQueue;
        }

        this.#open = open;
        this.clearTrailingCommit();
        this.#targetCumulative = undefined;
        this.#lastQueuedCumulative = open.session.cumulative;
        this.#lastCommitQueuedAt = 0;
    }

    private queueCommit(target: bigint): void {
        this.queueCommitFor(this.requireOpen(), target);
    }

    private queueCommitFor(open: SessionFetchOpenState, target: bigint): void {
        if (target <= this.#lastQueuedCumulative) {
            return;
        }
        this.#lastQueuedCumulative = target;
        this.#commitQueue = this.#commitQueue
            .then(async () => {
                const receipt = await this.commitTarget(open, target);
                // Re-advance in case an earlier failure rolled the queued
                // watermark back while this entry was already in flight.
                if (target > this.#lastQueuedCumulative) {
                    this.#lastQueuedCumulative = target;
                }
                return receipt;
            })
            .catch(error => {
                this.#commitFailure = toError(error);
                // Roll the queued watermark back to what the session actually
                // committed so a retry re-signs the same cumulative instead of
                // silently dropping the delta.
                const committed = open.session.cumulative;
                if (this.#lastQueuedCumulative > committed) {
                    this.#lastQueuedCumulative = committed;
                }
                return null;
            });
    }

    private scheduleTrailingCommit(delayMs: number): void {
        if (this.#trailingCommitTimer !== undefined) {
            return;
        }

        this.#trailingCommitTimer = setTimeout(
            () => {
                this.#trailingCommitTimer = undefined;
                if (this.#targetCumulative === undefined) {
                    return;
                }
                this.#lastCommitQueuedAt = Date.now();
                this.queueCommit(this.#targetCumulative);
            },
            Math.max(0, delayMs),
        );
    }

    private clearTrailingCommit(): void {
        if (this.#trailingCommitTimer === undefined) {
            return;
        }
        clearTimeout(this.#trailingCommitTimer);
        this.#trailingCommitTimer = undefined;
    }

    private async commitTarget(open: SessionFetchOpenState, target: bigint): Promise<CommitReceipt | null> {
        const current = open.session.cumulative;
        if (target <= current) {
            return null;
        }

        const amount = (target - current).toString();
        const directive = await this.reserveDelivery({
            amount,
            commitUrl: open.commitUrl,
            deliveryId: defaultDeliveryId(),
            session: open.session,
        });
        const voucher = await open.session.prepareVoucher(target);
        const receipt = await this.commitDelivery(
            {
                amount,
                directive,
                session: open.session,
                voucher,
            },
            open.commitUrl,
        );

        open.session.recordVoucher(voucher);
        this.emit({ receipt, type: 'commit' });
        return receipt;
    }

    private async reserveDelivery(parameters: ReserveSessionDeliveryParameters): Promise<MeteringDirective> {
        const url = new URL('/__402/session/deliveries', parameters.commitUrl);
        const response = await this.#fetch(url, {
            body: JSON.stringify({
                amount: parameters.amount,
                commitUrl: parameters.commitUrl,
                deliveryId: parameters.deliveryId,
                sessionId: parameters.session.channelId,
            }),
            headers: {
                accept: 'application/json',
                'content-type': 'application/json',
            },
            method: 'POST',
        });

        if (!response.ok) {
            throw new Error(`delivery reservation returned ${response.status}: ${await response.text()}`);
        }

        return (await response.json()) as MeteringDirective;
    }

    private async commitDelivery(
        parameters: CommitSessionDeliveryParameters,
        fallbackCommitUrl: string,
    ): Promise<CommitReceipt> {
        const response = await this.#fetch(parameters.directive.commitUrl ?? fallbackCommitUrl, {
            body: JSON.stringify({
                amount: parameters.amount,
                deliveryId: parameters.directive.deliveryId,
                voucher: parameters.voucher,
            }),
            headers: {
                accept: 'application/json',
                'content-type': 'application/json',
            },
            method: 'POST',
        });

        if (!response.ok) {
            throw new Error(`session commit returned ${response.status}: ${await response.text()}`);
        }

        return (await response.json()) as CommitReceipt;
    }

    private requireOpen(): SessionFetchOpenState {
        if (!this.#open) {
            throw new Error('session has not been opened yet');
        }
        return this.#open;
    }

    private throwCommitFailure(): void {
        const failure = this.#commitFailure;
        if (!failure) {
            return;
        }
        // Surface the failure once, then let the caller retry: the queued
        // watermark was not advanced, so the next record/flush re-commits the
        // same cumulative instead of leaving the client permanently poisoned.
        this.#commitFailure = undefined;
        throw failure;
    }

    private emit(event: SessionFetchEvent): void {
        this.#onEvent?.(event);
    }
}

export declare namespace SessionFetchClient {
    interface Parameters {
        /** Underlying fetch. Defaults to `globalThis.fetch`. */
        readonly fetch?: typeof globalThis.fetch | undefined;
        /** Minimum interval between live voucher commits, in ms. Defaults to 1000. */
        readonly liveCommitIntervalMs?: number | undefined;
        /** Observer for challenge / open / watermark / commit / retry events. */
        readonly onEvent?: ((event: SessionFetchEvent) => void) | undefined;
        /** Opens the session when a 402 challenge arrives (wallet approval, channel open). */
        readonly opener: SessionOpener;
        /** Hook applied to the first attempt and the paid retry (e.g. header stripping). */
        readonly prepareRequest?: PrepareSessionRequest | undefined;
        /** Currency / network filter for picking among multiple advertised challenges. */
        readonly selectChallenge?: SelectSolanaSessionChallengeOptions | undefined;
    }

    interface RecordOptions {
        /** Delta reported in the watermark event. Defaults to target − current. */
        readonly deltaAmount?: AmountLike | undefined;
        /** Commit immediately instead of waiting for the live-commit interval. */
        readonly force?: boolean | undefined;
    }
}

/**
 * Creates a high-level Solana session fetch client.
 */
export function createSessionFetch(parameters: SessionFetchClient.Parameters): SessionFetchClient {
    return new SessionFetchClient(parameters);
}

/**
 * Returns a request preparation hook that removes sensitive headers before
 * forwarding traffic through a payment gateway.
 */
export function stripRequestHeaders(names: readonly string[]): PrepareSessionRequest {
    const normalized = names.map(name => name.toLowerCase());
    return request => {
        const headers = new Headers(request.init?.headers);
        for (const name of normalized) {
            headers.delete(name);
        }
        return {
            ...request,
            init: {
                ...request.init,
                headers,
            },
        };
    };
}

let globalFetchPatchLock: Promise<void> = Promise.resolve();

/**
 * Temporarily patches `globalThis.fetch` while an SDK that does not accept a
 * fetch option performs its work.
 */
export async function withPatchedGlobalFetch<Value>(
    patchedFetch: typeof globalThis.fetch,
    operation: () => Promise<Value>,
): Promise<Value> {
    let release: () => void = () => undefined;
    const previous = globalFetchPatchLock;
    globalFetchPatchLock = new Promise<void>(resolve => {
        release = resolve;
    });

    await previous;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = patchedFetch;
    try {
        return await operation();
    } finally {
        globalThis.fetch = originalFetch;
        release();
    }
}

function withAuthorization(init: FetchInit, authorization: string): FetchInit {
    const headers = new Headers(init?.headers);
    headers.set('authorization', authorization);
    return { ...init, headers };
}

function toError(value: unknown): Error {
    return value instanceof Error ? value : new Error(String(value));
}

function cloneFetchInput(input: FetchInput): FetchInput {
    return input instanceof Request ? input.clone() : input;
}

function requestUrl(input: FetchInput): string {
    if (input instanceof Request) return input.url;
    return String(input);
}

function defaultDeliveryId(): string {
    return `mpp-${randomBase58(16)}`;
}

function randomBase58(length: number): string {
    return getBase58Decoder().decode(randomBytes(length));
}

function randomBytes(length: number): Uint8Array {
    const crypto = globalThis.crypto;
    if (!crypto?.getRandomValues) {
        throw new Error('crypto.getRandomValues is not available');
    }
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
}

function formatAmount(value: AmountLike, name: string): string {
    return parseAmount(value, name).toString();
}

function parseAmount(value: AmountLike, name: string): bigint {
    const parsed = parseInteger(value, name);
    if (parsed < 0n) throw new Error(`${name} must be non-negative`);
    if (parsed > U64_MAX) throw new Error(`${name} exceeds u64 max`);
    return parsed;
}

function parseInteger(value: AmountLike, name: string): bigint {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) throw new Error(`${name} must be a safe integer`);
        return BigInt(value);
    }
    if (!/^\d+$/.test(value)) throw new Error(`${name} must be an integer string`);
    return BigInt(value);
}
