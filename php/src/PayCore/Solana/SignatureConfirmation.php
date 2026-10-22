<?php

declare(strict_types=1);

namespace PayKit\PayCore\Solana;

use PayKit\Exception\SettlementInProgressException;
use PayKit\Exception\TransactionFailedException;
use PayKit\PayCore\Rpc\RpcGateway;
use Throwable;

/**
 * Reads the outcome of a transaction the server broadcast (MPP charge and
 * x402 exact settlement share it).
 *
 * Only an execution error the chain reports rejects the payment
 * ({@see TransactionFailedException}). A status read that fails (an RPC
 * outage, a 5xx, a malformed reply) or a status that is missing or not yet
 * confirmed proves nothing about the transaction, which may already have
 * landed, so it leaves the payment pending
 * ({@see SettlementInProgressException}) and the client retries the same
 * credential instead of being handed a fresh challenge to pay again.
 */
final class SignatureConfirmation
{
    private function __construct()
    {
    }

    /**
     * One `getSignatureStatuses` read: true when confirmed or finalized,
     * false when the status is missing or still processing.
     *
     * @throws TransactionFailedException when the chain reports an execution error
     * @throws SettlementInProgressException when the status cannot be read
     */
    public static function isConfirmed(RpcGateway $rpc, string $signature, bool $searchTransactionHistory = false): bool
    {
        try {
            $statuses = $rpc->getSignatureStatuses([$signature], $searchTransactionHistory);
        } catch (Throwable $error) {
            throw new SettlementInProgressException(
                "Could not read the status of transaction $signature; retry the same credential: " . $error->getMessage(),
                0,
                $error,
            );
        }
        $status = $statuses[0] ?? null;
        if (!is_array($status)) {
            return false;
        }
        if (($status['err'] ?? null) !== null) {
            throw new TransactionFailedException(
                "Transaction $signature failed: " . json_encode($status['err'], JSON_THROW_ON_ERROR),
            );
        }
        $confirmationStatus = $status['confirmationStatus'] ?? null;

        return $confirmationStatus === 'confirmed' || $confirmationStatus === 'finalized';
    }

    /**
     * Poll until the transaction is confirmed. A failed read is retried like
     * an unconfirmed status; running out of attempts leaves the payment
     * pending, never failed.
     *
     * @throws TransactionFailedException when the chain reports an execution error
     * @throws SettlementInProgressException when no read confirmed it in time
     */
    public static function await(RpcGateway $rpc, string $signature, int $attempts, int $delayMicros): void
    {
        $lastReadError = null;
        for ($attempt = 0; $attempt < $attempts; $attempt += 1) {
            try {
                if (self::isConfirmed($rpc, $signature)) {
                    return;
                }
            } catch (SettlementInProgressException $unreadable) {
                $lastReadError = $unreadable;
            }
            usleep($delayMicros);
        }
        // A missing or unconfirmed status is never proof of non-execution:
        // the node may lag or lack history for a transaction that commits in
        // time.
        throw new SettlementInProgressException(
            "Timed out waiting for transaction $signature; retry the same credential"
                . ($lastReadError !== null ? ' (' . $lastReadError->getMessage() . ')' : ''),
            0,
            $lastReadError,
        );
    }
}
