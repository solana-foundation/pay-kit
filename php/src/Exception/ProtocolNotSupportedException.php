<?php

declare(strict_types=1);

namespace PayKit\Exception;

use RuntimeException;

/**
 * Thrown when a client requests a scheme the server's config does
 * not accept (e.g. x402 against an MPP-only deployment).
 */
final class ProtocolNotSupportedException extends RuntimeException implements PayKitException
{
    public function httpStatus(): int
    {
        return 406;
    }
}
