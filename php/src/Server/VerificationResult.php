<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

final class VerificationResult
{
    private function __construct(
        public readonly bool $ok,
        public readonly string $reason = '',
        public readonly string $reference = '',
        public readonly string $externalId = '',
    ) {
    }

    public static function success(string $reference, string $externalId = ''): self
    {
        return new self(ok: true, reference: $reference, externalId: $externalId);
    }

    public static function failure(string $reason): self
    {
        return new self(ok: false, reason: $reason);
    }
}
