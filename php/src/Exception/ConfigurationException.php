<?php

declare(strict_types=1);

namespace PayKit\Exception;

use RuntimeException;

/**
 * Boot-time misconfiguration the operator must resolve before the
 * app can serve traffic. Examples: invalid network slug, preflight
 * check found the fee-payer has zero SOL on the configured RPC, the
 * recipient has no ATA for one of the accepted stablecoins.
 */
final class ConfigurationException extends RuntimeException implements PayKitException
{
}
