<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

use SolanaMpp\Intent\ChargeRequest;

/**
 * Verifies Solana transaction payloads independent of HTTP credential parsing.
 */
interface TransactionPayloadVerifier
{
    /**
     * Verify a base64-encoded Solana transaction against the expected charge.
     */
    public function verifyTransactionPayload(string $transactionBase64, ChargeRequest $request): VerificationResult;
}
