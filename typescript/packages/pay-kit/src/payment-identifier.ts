/**
 * The x402 `payment-identifier` extension (x402 specs/extensions/payment_identifier.md).
 *
 * A server advertises it in `PaymentRequired.extensions` with
 * `info.required`; the client echoes it and appends `info.id`, 16-128
 * characters of `[A-Za-z0-9_-]`. A server that requires the id answers a
 * payload without a valid one with 400 Bad Request.
 */
import { PaymentIdentifierError } from './errors.js';

/** Extension key on the `PaymentRequired` and `PaymentPayload` envelopes. */
export const PAYMENT_IDENTIFIER = 'payment-identifier';

/**
 * Whether a gate advertises the extension and, if so, whether the client must
 * send an id. A gate that leaves it unset does not advertise the extension.
 */
export type PaymentIdentifierPolicy = 'optional' | 'required';

const ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

/** A payment id that passed the spec's format check. Build with {@link PaymentIdentifier.parse}. */
export class PaymentIdentifier {
    readonly value: string;

    private constructor(value: string) {
        this.value = value;
        Object.freeze(this);
    }

    /** Parse a client-supplied id, or `undefined` when it violates the spec format. */
    static parse(value: unknown): PaymentIdentifier | undefined {
        return typeof value === 'string' && ID_PATTERN.test(value) ? new PaymentIdentifier(value) : undefined;
    }
}

/** The `extensions` entry a server advertises for `policy`. */
export function paymentIdentifierDeclaration(policy: PaymentIdentifierPolicy): Record<string, unknown> {
    return {
        [PAYMENT_IDENTIFIER]: {
            info: { required: policy === 'required' },
            schema: {
                $schema: 'https://json-schema.org/draft/2020-12/schema',
                properties: {
                    id: { maxLength: 128, minLength: 16, type: 'string' },
                    required: { type: 'boolean' },
                },
                required: ['required'],
                type: 'object',
            },
        },
    };
}

function record(value: unknown): Record<string, unknown> | undefined {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;
}

/**
 * Read the client's payment id from a payment payload's `extensions` under
 * `policy`. Returns the parsed id, or `undefined` when the policy is
 * `optional` and the client sent none. Throws {@link PaymentIdentifierError}
 * (HTTP 400) when the policy requires an id and none was sent, or when the
 * sent id is malformed.
 */
export function readPaymentIdentifier(
    extensions: unknown,
    policy: PaymentIdentifierPolicy,
): PaymentIdentifier | undefined {
    const raw = record(record(record(extensions)?.[PAYMENT_IDENTIFIER])?.info)?.id;
    if (raw === undefined) {
        if (policy === 'required') {
            throw new PaymentIdentifierError(
                'payment_identifier_required',
                'payment-identifier is required but the payload carries no id',
            );
        }
        return undefined;
    }
    const id = PaymentIdentifier.parse(raw);
    if (!id) {
        throw new PaymentIdentifierError(
            'invalid_payment_identifier',
            'payment-identifier id must be 16-128 characters of [A-Za-z0-9_-]',
        );
    }
    return id;
}
