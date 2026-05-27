<?php

declare(strict_types=1);

namespace PayKit\Exception;

use RuntimeException;

/**
 * Thrown when a request reaches a gated route without a valid
 * payment. Framework adapters convert this to an HTTP 402.
 */
final class PaymentRequiredException extends RuntimeException implements PayKitException
{
    public function httpStatus(): int
    {
        return 402;
    }
}
