<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

/**
 * Successful charge settlement: on-chain signature plus the HTTP envelope.
 *
 * Mirrors the shape of {@see PaymentRequiredResponse} (`status`, `headers`,
 * `body`) so callers can project either result uniformly to their HTTP layer.
 * Also exposes `signature` and `receiptHeader` for introspection / logging.
 *
 * @phpstan-type ResponseHeaders array<string, string>
 * @phpstan-type SuccessBody array{ok: true, paid: true}
 */
final class ChargeSettlement
{
    /**
     * @param ResponseHeaders $headers
     * @param SuccessBody $body
     */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly array $body,
        public readonly string $signature,
        public readonly string $receiptHeader,
    ) {
    }
}
