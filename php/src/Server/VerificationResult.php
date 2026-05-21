<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

/**
 * Carries the result of a payment credential verification attempt.
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
}
