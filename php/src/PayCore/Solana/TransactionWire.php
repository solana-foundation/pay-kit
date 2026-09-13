<?php

declare(strict_types=1);

namespace PayKit\PayCore\Solana;

use InvalidArgumentException;
use PayKit\Exception\LegacyTransactionException;
use SolanaPhpSdk\Transaction\VersionedTransaction;

/**
 * Decode boundary for every client-supplied Solana transaction the server
 * reads (MPP charge verification and settlement, x402 exact verification).
 *
 * Only version 0 messages are accepted. A legacy message (no version prefix
 * byte) is rejected with {@see self::LEGACY_UNSUPPORTED}; version 1 is not
 * implemented in this SDK and is rejected as an unsupported version.
 */
final class TransactionWire
{
    public const LEGACY_UNSUPPORTED = 'legacy transactions are not supported; use a version 0 or version 1 message';

    /**
     * @throws LegacyTransactionException for a legacy (unprefixed) message
     * @throws InvalidArgumentException for any other malformed wire
     */
    public static function deserialize(string $wire): VersionedTransaction
    {
        if ($wire === '') {
            throw new InvalidArgumentException('invalid transaction payload');
        }

        $version = VersionedTransaction::peekVersion($wire);
        if ($version === 'legacy') {
            throw new LegacyTransactionException(self::LEGACY_UNSUPPORTED);
        }
        if ($version !== 0) {
            throw new InvalidArgumentException('unsupported transaction version');
        }

        return VersionedTransaction::deserialize($wire);
    }
}
