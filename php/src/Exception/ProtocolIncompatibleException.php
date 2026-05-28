<?php

declare(strict_types=1);

namespace PayKit\Exception;

use InvalidArgumentException;

/**
 * Boot-time failure: a Gate explicitly accepts a scheme that cannot
 * settle the gate's shape (e.g. x402 on a fee-bearing gate).
 */
final class ProtocolIncompatibleException extends InvalidArgumentException implements PayKitException
{
}
