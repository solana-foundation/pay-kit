/**
 * Client side of the x402 `payment-identifier` extension
 * (x402 specs/extensions/payment_identifier.md).
 *
 * The client "must provide `id` if server sets `required: true`". The id is
 * 16-128 characters of `[A-Za-z0-9_-]`; this one is `pay_` followed by 32
 * random hex characters. Every other field the server declared is echoed
 * untouched: `@x402/core` merges the server's extensions back over the
 * enriched payload, so an extension may only add fields.
 */
import type { ClientExtension } from '@x402/core/client';

import { PAYMENT_IDENTIFIER } from '../payment-identifier.js';

/** Fresh payment id: `pay_` + 16 random bytes in lowercase hex (36 characters). */
export function generatePaymentIdentifier(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return `pay_${Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')}`;
}

function record(value: unknown): Record<string, unknown> | undefined {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;
}

/** Fills `payment-identifier.info.id` when the server declared the extension as required. */
export const paymentIdentifierExtension: ClientExtension = {
    enrichPaymentPayload: (payload, paymentRequired) => {
        const declared = record(paymentRequired.extensions?.[PAYMENT_IDENTIFIER]);
        const info = record(declared?.info);
        if (info?.required !== true || info.id !== undefined) return Promise.resolve(payload);
        return Promise.resolve({
            ...payload,
            extensions: {
                ...payload.extensions,
                [PAYMENT_IDENTIFIER]: { ...declared, info: { ...info, id: generatePaymentIdentifier() } },
            },
        });
    },
    key: PAYMENT_IDENTIFIER,
};
