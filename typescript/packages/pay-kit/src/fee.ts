import type { Price } from './price.js';

/**
 * How a fee interacts with the gate amount:
 * - `within` — taken out of the gate amount (the primary recipient nets less).
 * - `on_top` — added to the customer's total (the primary recipient nets the full amount).
 */
export type FeeKind = 'on_top' | 'within';

/** A fee line on a gate: who receives it, how much, and how it combines with the amount. */
export type Fee = {
    readonly kind: FeeKind;
    /** Optional on-chain memo attached to this fee's transfer (max 566 bytes). */
    readonly memo?: string;
    readonly price: Price;
    /** Base58 address of the fee recipient. */
    readonly recipient: string;
};
