<?php

declare(strict_types=1);

namespace PayKit\Exception;

use InvalidArgumentException;

/**
 * Boot-time failure: a Gate mixes prices in different denominations
 * (e.g. one USD fee and one EUR fee on the same gate).
 */
final class MixedCurrenciesException extends InvalidArgumentException implements PayKitException
{
}
