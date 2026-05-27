<?php

declare(strict_types=1);

namespace PayKit\Exception;

use RuntimeException;

/**
 * Thrown when a submitted payment proof is structurally invalid: a
 * malformed Authorization header, a transaction whose shape does not
 * match the offer, a signature that does not verify, etc. The
 * framework adapter typically renders this as HTTP 402 with a fresh
 * challenge.
 */
class InvalidProofException extends RuntimeException implements PayKitException
{
    public function httpStatus(): int
    {
        return 402;
    }
}
