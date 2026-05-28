<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp;

use PayKit\Exception\ConfigurationException;

/**
 * MPP scheme sub-configuration. `challengeBindingSecret` is the
 * spec's HMAC key for stateless challenge binding
 * (draft-httpauth-payment-00 sec. 5.1.2.1.1).
 *
 * Null `challengeBindingSecret` triggers Preflight's resolution chain
 * (env / .env / generate + persist) so the example apps boot without
 * the operator having to set anything.
 */
final readonly class MppConfig
{
    public function __construct(
        public string $realm = 'App',
        public ?string $challengeBindingSecret = null,
        public int $expiresIn = 120,
    ) {
        if ($expiresIn <= 0) {
            throw new ConfigurationException(
                'pay_kit: mpp.expiresIn must be a positive number of seconds',
            );
        }
    }

    public function withChallengeBindingSecret(string $secret): self
    {
        return new self($this->realm, $secret, $this->expiresIn);
    }
}
