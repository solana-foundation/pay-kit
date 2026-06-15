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
 *
 * `advertisedExtensions` is the x402 v2 `extensions` object the server
 * publishes on the `PAYMENT-REQUIRED` challenge (e.g. a `payment-identifier`
 * with `info.required = true`). When it advertises a required
 * payment-identifier, the verify path rejects credentials that did not echo a
 * valid `pay_`-shaped id. Null/empty advertises nothing and the challenge
 * omits the `extensions` key entirely (mirrors rust
 * `skip_serializing_if = "Option::is_none"`).
 */
final readonly class X402Config
{
    /**
     * @param array<string,mixed>|null $advertisedExtensions x402 v2 extensions
     *        object advertised on the challenge; see class docblock.
     */
    public function __construct(
        public ?string $facilitatorUrl = null,
        public string $scheme = 'exact',
        public ?LocalSigner $signer = null,
        public ?array $advertisedExtensions = null,
    ) {
    }

    public function isDelegated(): bool
    {
        return $this->facilitatorUrl !== null && $this->facilitatorUrl !== '';
    }
}
