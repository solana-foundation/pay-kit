<?php

declare(strict_types=1);

namespace PayKit\Protocols\X402;

use PayKit\Signer\LocalSigner;

/**
 * x402 scheme sub-configuration.
 *
 * `facilitatorUrl` toggles between self-hosted (null, default) and
 * delegated mode (a real x402 facilitator endpoint). `signer` is an
 * advanced escape hatch for swapping the x402 facilitator key without
 * disturbing the operator's signer; null inherits from Operator.
 */
final readonly class X402Config
{
    public function __construct(
        public ?string $facilitatorUrl = null,
        public string $scheme = 'exact',
        public ?LocalSigner $signer = null,
    ) {
    }

    public function isDelegated(): bool
    {
        return $this->facilitatorUrl !== null && $this->facilitatorUrl !== '';
    }
}
