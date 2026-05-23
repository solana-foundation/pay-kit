<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

/**
 * Protocol-canonical 402 Payment Required response payload.
 *
 * Carries the HTTP status, response headers, and `application/problem+json`
 * body that an MPP server emits when payment is required. Callers project
 * this into their framework of choice (raw PHP `header()` calls, Laravel
 * `response()->json`, PSR-7 builders, etc.).
 *
 * The body includes the L6 canonical structured `code` field (see
 * {@see ErrorCodes}) alongside the human-readable `detail` so polyglot
 * clients can branch on `code` regardless of message wording.
 *
 * @phpstan-type ResponseHeaders array{
 *     "cache-control": string,
 *     "content-type": string,
 *     "www-authenticate": string,
 * }
 * @phpstan-type ProblemBody array{
 *     code: string,
 *     detail: string,
 *     status: int,
 *     title: string,
 *     type: string,
 * }
 */
final class PaymentRequiredResponse
{
    /**
     * @param ResponseHeaders $headers
     * @param ProblemBody $body
     */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly array $body,
        public readonly string $code = ErrorCodes::PAYMENT_INVALID,
    ) {
    }
}
