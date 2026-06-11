import {
    ActiveSession,
    type CommitPayload,
    type CommitReceipt,
    type MeteredEnvelope,
    type MeteringDirective,
} from './Session.js';

/**
 * Commit transport used by `SessionConsumer`.
 */
export interface CommitTransport {
    commit(parameters: CommitTransport.CommitParameters): Promise<CommitReceipt>;
}

export declare namespace CommitTransport {
    interface CommitParameters {
        /** Directive issued when the delivery was reserved. */
        readonly directive: MeteringDirective;
        /** Signed commit body to send. */
        readonly payload: CommitPayload;
    }
}

/**
 * Client-side Kafka-style consumer for metered session deliveries.
 */
export class SessionConsumer<Transport extends CommitTransport = CommitTransport> {
    readonly #session: ActiveSession;
    readonly #transport: Transport;

    constructor(parameters: SessionConsumer.Parameters<Transport>) {
        this.#session = parameters.session;
        this.#transport = parameters.transport;
    }

    /** Active session used to sign commit vouchers. */
    get session(): ActiveSession {
        return this.#session;
    }

    /** Transport used to send commit payloads. */
    get transport(): Transport {
        return this.#transport;
    }

    /**
     * Accepts a metered envelope and returns a delivery handle.
     */
    accept<Payload>(envelope: MeteredEnvelope<Payload>): MeteredDelivery<Payload, Transport> {
        this.validateDirective(envelope.metering);
        return new MeteredDelivery({
            consumer: this,
            metering: envelope.metering,
            payload: envelope.payload,
        });
    }

    /**
     * Commits a directive directly, signing and sending the voucher under the hood.
     */
    async commitDirective(directive: MeteringDirective): Promise<CommitReceipt> {
        this.validateDirective(directive);
        const amount = BigInt(directive.amount);
        if (amount <= 0n) {
            throw new Error('metered delivery amount must be greater than zero');
        }

        const voucher = await this.#session.prepareIncrement(amount);
        const payload: CommitPayload = {
            deliveryId: directive.deliveryId,
            voucher,
        };

        const receipt = await this.#transport.commit({ directive, payload });
        this.#session.recordVoucher(voucher);
        return receipt;
    }

    private validateDirective(directive: MeteringDirective): void {
        if (directive.sessionId !== this.#session.channelId) {
            throw new Error(
                `metered delivery session ${directive.sessionId} does not match active session ${this.#session.channelId}`,
            );
        }
        if (!/^\d+$/.test(directive.amount)) {
            throw new Error(`invalid metering amount: ${directive.amount}`);
        }
    }
}

export declare namespace SessionConsumer {
    interface Parameters<Transport extends CommitTransport = CommitTransport> {
        /** Session that signs commit vouchers. */
        readonly session: ActiveSession;
        /** Transport that delivers commit payloads to the server. */
        readonly transport: Transport;
    }
}

/**
 * Delivered payload plus its metering directive.
 */
export class MeteredDelivery<Payload, Transport extends CommitTransport = CommitTransport> {
    readonly #consumer: SessionConsumer<Transport>;

    readonly metering: MeteringDirective;
    readonly payload: Payload;

    constructor(parameters: MeteredDelivery.Parameters<Payload, Transport>) {
        this.#consumer = parameters.consumer;
        this.metering = parameters.metering;
        this.payload = parameters.payload;
    }

    /**
     * Acknowledges successful processing and commits the voucher.
     */
    async ack(): Promise<CommitReceipt> {
        return await this.#consumer.commitDirective(this.metering);
    }

    /**
     * Alias for `ack()`, matching log/queue commit terminology.
     */
    async commit(): Promise<CommitReceipt> {
        return await this.ack();
    }

    /**
     * Takes ownership of the payload and directive without committing.
     */
    intoParts(): MeteredEnvelope<Payload> {
        return {
            metering: this.metering,
            payload: this.payload,
        };
    }
}

export declare namespace MeteredDelivery {
    interface Parameters<Payload, Transport extends CommitTransport = CommitTransport> {
        /** Consumer that commits the delivery on `ack()`. */
        readonly consumer: SessionConsumer<Transport>;
        /** Directive to commit once the payload is processed. */
        readonly metering: MeteringDirective;
        /** The delivered application payload. */
        readonly payload: Payload;
    }
}

/**
 * Fetch-backed transport for HTTP commit endpoints.
 */
export class HttpCommitTransport implements CommitTransport {
    readonly #authorization: string | undefined;
    readonly #commitUrl: string | undefined;
    readonly #fetch: typeof globalThis.fetch;
    readonly #headers: HeadersInit | undefined;

    constructor(parameters: HttpCommitTransport.Parameters = {}) {
        this.#authorization = parameters.authorization;
        this.#commitUrl = parameters.commitUrl;
        this.#fetch = parameters.fetch ?? globalThis.fetch;
        this.#headers = parameters.headers;
    }

    async commit({ directive, payload }: CommitTransport.CommitParameters): Promise<CommitReceipt> {
        const url = directive.commitUrl ?? this.#commitUrl;
        if (!url) throw new Error('metering directive missing commitUrl');

        const headers = new Headers(this.#headers);
        headers.set('accept', 'application/json');
        headers.set('content-type', 'application/json');
        if (this.#authorization) headers.set('authorization', this.#authorization);

        const response = await this.#fetch(url, {
            body: JSON.stringify(payload),
            headers,
            method: 'POST',
        });

        if (!response.ok) {
            throw new Error(`commit endpoint returned ${response.status}: ${await response.text()}`);
        }

        return (await response.json()) as CommitReceipt;
    }
}

export declare namespace HttpCommitTransport {
    interface Parameters {
        /** `Authorization` header value sent with each commit. */
        readonly authorization?: string | undefined;
        /** Fallback commit endpoint when a directive carries no `commitUrl`. */
        readonly commitUrl?: string | undefined;
        /** Underlying fetch. Defaults to `globalThis.fetch`. */
        readonly fetch?: typeof globalThis.fetch | undefined;
        /** Extra headers merged into each commit request. */
        readonly headers?: HeadersInit | undefined;
    }
}
