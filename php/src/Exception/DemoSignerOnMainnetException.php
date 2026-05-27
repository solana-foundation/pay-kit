<?php

declare(strict_types=1);

namespace PayKit\Exception;

use LogicException;

/**
 * Boot-time guard: the package-shipped demo keypair will never be
 * used as the operator on Solana mainnet. Production deployments
 * must load a real keypair via Signer::file / Signer::env.
 */
final class DemoSignerOnMainnetException extends LogicException implements PayKitException
{
}
