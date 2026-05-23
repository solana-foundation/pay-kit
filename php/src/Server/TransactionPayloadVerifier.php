<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

use SolanaMpp\Intent\ChargeRequest;

/**
 * Verifies Solana transaction payloads independent of HTTP credential parsing.
 *
 * Pull mode hands the wire bytes off to the verifier before broadcast; push
 * mode does the same after fetching the confirmed transaction back from
 * `getTransaction`. Both paths share the same structural checks via this
 * interface so the rules cannot drift between modes.
 */
interface TransactionPayloadVerifier
{
    /**
     * Verify a base64-encoded Solana transaction against the expected charge.
     */
    public function verifyTransactionPayload(string $transactionBase64, ChargeRequest $request): VerificationResult;
}
