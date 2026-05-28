<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Server;

use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Credential;

/**
 * Carries the result of a payment credential verification attempt.
 *
 * On success, when the result was produced by {@see ChargeServer::verifyAuthorizationHeader()},
 * `challenge` and `credential` are populated with the verified payloads so
 * callers can mint a receipt without re-parsing the Authorization header.
 */
final class VerificationResult
{
    /**
     * Create an immutable verification result.
     */
    private function __construct(
        public readonly bool $ok,
        public readonly string $reason = '',
        public readonly string $reference = '',
        public readonly string $externalId = '',
        public readonly ?Challenge $challenge = null,
        public readonly ?Credential $credential = null,
    ) {
    }

    /**
     * Return a successful verification result with its settlement reference.
     */
    public static function success(string $reference, string $externalId = ''): self
    {
        return new self(ok: true, reference: $reference, externalId: $externalId);
    }

    /**
     * Return a failed verification result with a developer-readable reason.
     */
    public static function failure(string $reason): self
    {
        return new self(ok: false, reason: $reason);
    }

    /**
     * Return a copy with the verified challenge and credential attached.
     *
     * Intended for internal use by {@see ChargeServer} after a verifier
     * accepts a credential, so the receipt step does not need to re-parse the
     * Authorization header.
     */
    public function withVerified(Challenge $challenge, Credential $credential): self
    {
        return new self(
            ok: $this->ok,
            reason: $this->reason,
            reference: $this->reference,
            externalId: $this->externalId,
            challenge: $challenge,
            credential: $credential,
        );
    }
}
