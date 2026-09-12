import { getBase64Codec, getCompiledTransactionMessageDecoder, getTransactionDecoder } from '@solana/kit';
import { assertVersionedTransactionMessage } from '@solana/mpp/server';

import { InvalidProofError } from '../errors.js';

/** The x402 payment credential header, read from either accepted name. */
export function x402PaymentHeader(request: Request): string | undefined {
    return request.headers.get('x-payment') ?? request.headers.get('payment-signature') ?? undefined;
}

/** The message of an Error-like value, or `undefined`. */
export function errorMessage(error: unknown): string | undefined {
    return error instanceof Error ? error.message : undefined;
}

/**
 * Reject a legacy (unversioned) client transaction before it reaches the
 * vendored facilitator, which still decodes both encodings. A value that is
 * not a string or does not decode is left to the facilitator, whose own
 * malformed-transaction verdict stays canonical.
 *
 * @param code - The facilitator's reason code for a malformed transaction on this path.
 * @throws {InvalidProofError} carrying `code` and the shared legacy-rejection text.
 */
export function rejectLegacyTransaction(transactionBase64: unknown, code: string): void {
    if (typeof transactionBase64 !== 'string') return;
    let message: ReturnType<ReturnType<typeof getCompiledTransactionMessageDecoder>['decode']>;
    try {
        const decoded = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
        message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes);
    } catch {
        return;
    }
    try {
        assertVersionedTransactionMessage(message);
    } catch (error) {
        throw new InvalidProofError(code, errorMessage(error));
    }
}
