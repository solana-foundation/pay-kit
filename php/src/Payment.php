<?php

declare(strict_types=1);

namespace PayKit;

/**
 * Request-scoped proof attached to the PSR-7 request by the
 * RequirePayment middleware. Handlers read it via the namespace
 * functions in PayKit\Http\ (payment(), isPaid(), isPaidFor()).
 *
 * The settlement-headers array is a flat map of HTTP header name to
 * value that the framework adapter merges into the success response.
 */
final readonly class Payment
{
    /**
     * @param array<string,string> $settlementHeaders Headers to merge into the upstream 2xx response.
     */
    public function __construct(
        public Protocol $protocol,
        public string $transaction,
        public ?string $gateName,
        public array $settlementHeaders = [],
        public ?string $raw = null,
    ) {
    }
}
