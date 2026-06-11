import type { AcceptsEntry } from './challenge.js';
import type { Gate } from './gate.js';
import type { Payment } from './payment.js';
import type { Protocol } from './protocol.js';

/**
 * The protocol seam. Both x402 and MPP are instances of one loop —
 * challenge (402) → client credential → verify → settle → receipt headers —
 * so a payment protocol is exactly one object implementing this contract.
 * Adding a protocol never changes {@link Gate}, the request verbs, or any
 * framework integration.
 */
export type ProtocolAdapter = {
    /** This adapter's entry in the 402 `accepts[]` array for `gate`. */
    readonly acceptsEntry: (gate: Gate, request: Request) => Promise<AcceptsEntry>;
    /** Protocol-specific 402 headers for `gate`. */
    readonly challengeHeaders: (gate: Gate, request: Request) => Promise<Readonly<Record<string, string>>>;
    /** Whether `request` carries this protocol's payment credential. */
    readonly detect: (request: Request) => boolean;
    readonly protocol: Protocol;
    readonly scheme: string;
    /**
     * Verifies the credential and settles the payment.
     *
     * @throws {InvalidProofError} when the credential fails verification or settlement.
     */
    readonly verifyAndSettle: (gate: Gate, request: Request) => Promise<Payment>;
};
