<?php

declare(strict_types=1);

namespace PayKit\Exception;

use InvalidArgumentException;

/**
 * Thrown by Signer factories when a secret cannot be parsed
 * (malformed JSON array, wrong byte length, invalid base58, ...).
 * Boot-time only; never reaches a request handler.
 */
final class InvalidKeyException extends InvalidArgumentException implements PayKitException
{
}
