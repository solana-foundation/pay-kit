import type { CommitReceipt, MeteringDirective, MeteringUsage } from './Session.js';
import { type CommitTransport, SessionConsumer } from './SessionConsumer.js';

/**
 * Raw Server-Sent Event.
 */
export interface SseEvent {
    readonly data: string;
    readonly event?: string | undefined;
    readonly id?: string | undefined;
    readonly retry?: number | undefined;
}

/**
 * Parsed metered SSE event.
 */
export type MeteredSseEvent<Message = string> =
    | { readonly data: Message; readonly type: 'message' }
    | { readonly directive: MeteringDirective; readonly type: 'metering' }
    | { readonly receipt: unknown; readonly type: 'receipt' }
    | { readonly type: 'done' }
    | { readonly type: 'usage'; readonly usage: MeteringUsage };

/**
 * Incremental SSE decoder for HTTP streaming responses.
 */
export class SseDecoder {
    readonly #decoder = new TextDecoder();
    #buffer = '';

    /**
     * Pushes a text or byte chunk and returns all complete SSE events.
     */
    pushChunk(chunk: Uint8Array | string): SseEvent[] {
        this.#buffer += typeof chunk === 'string' ? chunk : this.#decoder.decode(chunk, { stream: true });
        return this.drainCompleteEvents();
    }

    /**
     * Flushes the decoder and parses any trailing event.
     */
    finish(): SseEvent[] {
        this.#buffer += this.#decoder.decode();
        const events = this.drainCompleteEvents();
        if (this.#buffer.trim() === '') return events;

        const trailing = parseSseEventBlock(this.#buffer);
        this.#buffer = '';
        return trailing ? [...events, trailing] : events;
    }

    private drainCompleteEvents(): SseEvent[] {
        this.#buffer = this.#buffer.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

        const events: SseEvent[] = [];
        let boundary = this.#buffer.indexOf('\n\n');
        while (boundary !== -1) {
            const block = this.#buffer.slice(0, boundary);
            this.#buffer = this.#buffer.slice(boundary + 2);
            const event = parseSseEventBlock(block);
            if (event) events.push(event);
            boundary = this.#buffer.indexOf('\n\n');
        }
        return events;
    }
}

/**
 * Parses one raw SSE block into an event.
 */
export function parseSseEventBlock(block: string): SseEvent | null {
    const data: string[] = [];
    let event: string | undefined;
    let id: string | undefined;
    let retry: number | undefined;

    for (const line of block.split('\n')) {
        if (line === '' || line.startsWith(':')) continue;

        const separator = line.indexOf(':');
        const field = separator === -1 ? line : line.slice(0, separator);
        const value = separator === -1 ? '' : trimOneLeadingSpace(line.slice(separator + 1));

        switch (field) {
            case 'data':
                data.push(value);
                break;
            case 'event':
                event = value;
                break;
            case 'id':
                id = value;
                break;
            case 'retry':
                retry = Number.parseInt(value, 10);
                break;
        }
    }

    if (data.length === 0 && !event) return null;
    return {
        data: data.join('\n'),
        ...(event !== undefined ? { event } : {}),
        ...(id !== undefined ? { id } : {}),
        ...(retry !== undefined && Number.isFinite(retry) ? { retry } : {}),
    };
}

/**
 * Parses one raw SSE event into the metered event model used by session streams.
 */
export function parseMeteredSseEvent<Message = string>(
    event: SseEvent,
    parseMessage?: (data: string) => Message,
): MeteredSseEvent<Message> {
    const eventType = event.event ?? 'message';

    if (eventType === 'mpp.metering' || eventType === 'metering') {
        return { directive: JSON.parse(event.data) as MeteringDirective, type: 'metering' };
    }
    if (eventType === 'mpp.usage' || eventType === 'usage') {
        return { type: 'usage', usage: JSON.parse(event.data) as MeteringUsage };
    }
    if (eventType === 'payment-receipt') {
        return { receipt: JSON.parse(event.data) as unknown, type: 'receipt' };
    }
    if (eventType === 'done' || event.data === '[DONE]') {
        return { type: 'done' };
    }

    return { data: parseMessage ? parseMessage(event.data) : (event.data as Message), type: 'message' };
}

/**
 * Tracks metering state for an HTTP/SSE response and commits final usage on `ack()`.
 */
export class MeteredSseSession<Transport extends CommitTransport = CommitTransport> {
    readonly #consumer: SessionConsumer<Transport>;
    #directive: MeteringDirective | undefined;
    #done = false;
    #usage: MeteringUsage | undefined;

    constructor(consumer: SessionConsumer<Transport>) {
        this.#consumer = consumer;
    }

    /** Whether a terminal stream marker has been observed. */
    get isDone(): boolean {
        return this.#done;
    }

    /** Last server-issued metering directive. */
    get directive(): MeteringDirective | undefined {
        return this.#directive;
    }

    /** Final usage reported by the stream. */
    get usage(): MeteringUsage | undefined {
        return this.#usage;
    }

    /**
     * Accepts one SSE event and updates local metering state.
     */
    acceptEvent<Message = string>(event: SseEvent, parseMessage?: (data: string) => Message): MeteredSseEvent<Message> {
        const parsed = parseMeteredSseEvent(event, parseMessage);
        switch (parsed.type) {
            case 'metering':
                this.#directive = parsed.directive;
                break;
            case 'usage':
                // Mirror the Rust stream state machine: usage events may only
                // refine the live directive's amount, never re-target deliveries.
                if (this.#directive && parsed.usage.deliveryId !== this.#directive.deliveryId) {
                    throw new Error(
                        `usage delivery ${parsed.usage.deliveryId} does not match directive ${this.#directive.deliveryId}`,
                    );
                }
                this.#usage = parsed.usage;
                break;
            case 'done':
                this.#done = true;
                break;
        }
        return parsed;
    }

    /**
     * Commits the final usage amount, falling back to the reserved directive amount.
     */
    async ack(): Promise<CommitReceipt> {
        if (!this.#directive) throw new Error('stream missing metering directive');
        const directive = this.#usage
            ? {
                  ...this.#directive,
                  amount: this.#usage.amount,
              }
            : this.#directive;
        return await this.#consumer.commitDirective(directive);
    }
}

/**
 * Decodes a `ReadableStream` of SSE bytes into metered events.
 */
export async function* decodeMeteredSseStream<Message = string>(
    stream: ReadableStream<Uint8Array>,
    parseMessage?: (data: string) => Message,
): AsyncGenerator<MeteredSseEvent<Message>> {
    const reader = stream.getReader();
    const decoder = new SseDecoder();

    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            for (const event of decoder.pushChunk(value)) {
                yield parseMeteredSseEvent(event, parseMessage);
            }
        }
        for (const event of decoder.finish()) {
            yield parseMeteredSseEvent(event, parseMessage);
        }
    } finally {
        reader.releaseLock();
    }
}

function trimOneLeadingSpace(value: string): string {
    return value.startsWith(' ') ? value.slice(1) : value;
}
