<?php

declare(strict_types=1);

namespace PayKit\PayCore\Solana;

use InvalidArgumentException;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Transaction\CompiledInstructionV0;
use SolanaPhpSdk\Transaction\Transaction;
use SolanaPhpSdk\Transaction\VersionedTransaction;
use SolanaPhpSdk\Util\Base58;

/**
 * Decode boundary for every client-supplied Solana transaction the server
 * reads (MPP charge verification and settlement, x402 exact verification).
 *
 * Legacy (unprefixed) and version 0 messages are accepted. pay-kit clients
 * only build version 0, but a pre-cutover client's legacy message is still
 * verified under the same rules: same size limit, ComputeBudget instructions
 * in the body, no address lookup tables. Version 1 is not implemented in
 * this SDK and is rejected as an unsupported version.
 *
 * Both encodings are exposed through one accessor set so verifiers never
 * branch on the framing, and {@see self::serialize()} keeps the original
 * framing so the client's signatures stay valid after a fee-payer co-sign.
 */
final class TransactionWire
{
    private function __construct(
        private readonly Transaction|VersionedTransaction $transaction,
    ) {
    }

    /**
     * @throws InvalidArgumentException for a malformed wire or an unsupported message version
     */
    public static function deserialize(string $wire): self
    {
        if ($wire === '') {
            throw new InvalidArgumentException('invalid transaction payload');
        }

        $version = VersionedTransaction::peekVersion($wire);
        if ($version === 'legacy') {
            return new self(Transaction::deserialize($wire));
        }
        if ($version !== 0) {
            throw new InvalidArgumentException('unsupported transaction version');
        }

        return new self(VersionedTransaction::deserialize($wire));
    }

    /** `'legacy'` for an unprefixed message, `0` for version 0. */
    public function version(): string|int
    {
        return $this->transaction instanceof Transaction ? 'legacy' : 0;
    }

    /**
     * Static account keys in message order.
     *
     * @return list<PublicKey>
     */
    public function staticAccountKeys(): array
    {
        if ($this->transaction instanceof Transaction) {
            return array_values($this->transaction->message->accountKeys);
        }

        return array_values($this->transaction->message->staticAccountKeys);
    }

    /** Number of required signers: the first accounts of the key table. */
    public function numRequiredSignatures(): int
    {
        return $this->transaction->message->numRequiredSignatures;
    }

    /**
     * Top-level instructions in message order, in the v0 compiled shape for
     * both encodings.
     *
     * @return list<CompiledInstructionV0>
     */
    public function compiledInstructions(): array
    {
        if ($this->transaction instanceof Transaction) {
            return array_map(
                static fn (array $ix): CompiledInstructionV0 => new CompiledInstructionV0(
                    $ix['programIdIndex'],
                    array_values($ix['accounts']),
                    $ix['data'],
                ),
                array_values($this->transaction->message->instructions),
            );
        }

        return array_values($this->transaction->message->compiledInstructions);
    }

    /**
     * Address-table lookups; always empty for a legacy message, which cannot
     * carry any.
     *
     * @return list<object>
     */
    public function addressTableLookups(): array
    {
        if ($this->transaction instanceof Transaction) {
            return [];
        }

        return array_values($this->transaction->message->addressTableLookups);
    }

    /** Recent blockhash as base58 for both encodings. */
    public function recentBlockhash(): string
    {
        if ($this->transaction instanceof Transaction) {
            // Legacy `Message` stores the blockhash as raw 32 bytes.
            return Base58::encode($this->transaction->message->recentBlockhash);
        }

        return $this->transaction->message->recentBlockhash;
    }

    public function partialSign(Keypair ...$signers): void
    {
        $this->transaction->partialSign(...$signers);
    }

    /** Serialize in the original framing (legacy or v0). */
    public function serialize(bool $verifySignatures = true): string
    {
        return $this->transaction->serialize($verifySignatures);
    }
}
