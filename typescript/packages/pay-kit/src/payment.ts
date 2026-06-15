import type { Protocol } from './protocol.js';

/**
 * A protocol-neutral receipt for one verified, settled payment. This is what
 * route handlers receive — application code never sees which protocol
 * settled beyond the `protocol` tag.
 */
export type Payment = {
    /** Name of the gate that was paid, when the gate came from a catalogue. */
    readonly gateName: string | undefined;
    /** Settling wallet address, when the protocol exposes it. */
    readonly payer: string | undefined;
    readonly protocol: Protocol;
    /** Raw credential as received (debugging, replay caches). */
    readonly raw: string | undefined;
    /** Protocol scheme that settled (`charge` for MPP, `exact` for x402). */
    readonly scheme: string;
    /** Headers to merge into the 2xx response (receipts, settlement signatures). */
    readonly settlementHeaders: Readonly<Record<string, string>>;
    /** Settlement transaction signature. */
    readonly transaction: string;
};
