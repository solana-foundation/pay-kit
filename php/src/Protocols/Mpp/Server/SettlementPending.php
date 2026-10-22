<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Server;

/**
 * A payment that was (or may have been) broadcast and is not yet resolved.
 *
 * It must not be answered with a fresh challenge: a client that paid the
 * original transaction and then a replacement would pay twice. The response
 * is a retryable 409 instead, and the client presents the same credential
 * again; the handler reconciles the pending signature on that retry and
 * returns the receipt once the transaction lands.
 *
 * Mirrors the shape of {@see PaymentRequiredResponse} (`status`, `headers`,
 * `body`) so callers can project every handler result uniformly.
 *
 * @phpstan-type ResponseHeaders array<string, string>
 * @phpstan-type ProblemBody array{detail: string, status: int, title: string, type: string}
 */
final class SettlementPending
{
    /**
     * @param ResponseHeaders $headers
     * @param ProblemBody $body
     */
    private function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly array $body,
    ) {
    }

    public static function withDetail(string $detail): self
    {
        return new self(
            status: 409,
            headers: [
                'cache-control' => 'no-store',
                'content-type' => 'application/problem+json',
                'retry-after' => '1',
            ],
            body: [
                'detail' => $detail,
                'status' => 409,
                'title' => 'Settlement Already In Progress',
                'type' => 'https://paymentauth.org/problems/settlement-in-progress',
            ],
        );
    }
}
