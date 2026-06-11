import type { Protocol } from './protocol.js';

/**
 * One way to pay, advertised in the 402 body's `accepts[]` array. Carries
 * the cross-SDK wire invariants (`protocol`, `scheme`, CAIP-2 `network`,
 * base-unit `amount`, `payTo`) plus protocol-specific extras.
 */
export type AcceptsEntry = {
    readonly [key: string]: unknown;
    /** Base-unit integer string. */
    readonly amount: string;
    /** CAIP-2 chain identifier. */
    readonly network: string;
    readonly payTo: string;
    readonly protocol: Protocol;
    readonly scheme: string;
};

/** Everything needed to render a 402: the offer list and protocol headers. */
export type Challenge = {
    /** One entry per (accepted protocol, scheme) pair. */
    readonly accepts: readonly AcceptsEntry[];
    /** Protocol challenge headers (`WWW-Authenticate` for MPP, `Payment-Required` for x402). */
    readonly headers: Readonly<Record<string, string>>;
    /** The resource being paid for (request path). */
    readonly resource: string;
};
