<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

use SolanaMpp\Intent\ChargeRequest;

/**
 * Verifies Solana transaction payloads independent of HTTP credential parsing.
 *
 * Used by {@see SolanaChargeHandler} on the push-mode (`type=signature`) path:
 * after the handler fetches the on-chain transaction by signature, it hands
 * the base64-encoded wire bytes plus the expected `ChargeRequest` to a
 * verifier implementing this interface so the same shape checks the pull-mode
 * pre-broadcast verifier runs (mint, decimals, amount, recipient ATA,
 * compute-budget cap, instruction allowlist) re-run against the settled
 * transaction.
 *
 * {@see SolanaChargeTransactionVerifier} implements both this and
 * {@see PaymentVerifier} so a single instance can be shared between the
 * pull-mode and push-mode paths.
 */
interface TransactionPayloadVerifier
{
    /**
     * Verify a base64-encoded Solana transaction against the expected charge.
     */
    public function verifyTransactionPayload(string $transactionBase64, ChargeRequest $request): VerificationResult;
}
