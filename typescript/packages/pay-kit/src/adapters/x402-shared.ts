/** The x402 payment credential header, read from either accepted name. */
export function x402PaymentHeader(request: Request): string | undefined {
    return request.headers.get('x-payment') ?? request.headers.get('payment-signature') ?? undefined;
}

/** The message of an Error-like value, or `undefined`. */
export function errorMessage(error: unknown): string | undefined {
    return error instanceof Error ? error.message : undefined;
}
