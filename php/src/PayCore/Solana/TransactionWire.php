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
use SolanaPhpSdk\Util\CompactU16;

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
        private readonly string $messageBytes,
    ) {
    }

    /**
     * Decode a wire transaction whose signature list holds exactly
     * `header.num_required_signatures` entries. A shorter or longer list is
     * refused here rather than padded (the legacy decoder would otherwise
     * fill missing slots with empty signatures), so every later check sees
     * one slot per required signer (RULINGS SIG1).
     *
     * @throws InvalidArgumentException for a malformed wire, a signature count
     *         that differs from the header, or an unsupported message version
     */
    public static function deserialize(string $wire): self
    {
        if ($wire === '') {
            throw new InvalidArgumentException('invalid transaction payload');
        }

        $version = VersionedTransaction::peekVersion($wire);
        if ($version !== 'legacy' && $version !== 0) {
            throw new InvalidArgumentException('unsupported transaction version');
        }

        [$signatureCount, $consumed] = CompactU16::decodeAt($wire, 0);
        $messageOffset = $consumed + $signatureCount * 64;
        if (strlen($wire) <= $messageOffset) {
            throw new InvalidArgumentException('invalid transaction payload: truncated signatures');
        }
        // The header's first byte follows the version prefix in a v0 message.
        $headerOffset = $messageOffset + ($version === 'legacy' ? 0 : 1);
        if (strlen($wire) <= $headerOffset) {
            throw new InvalidArgumentException('invalid transaction payload: truncated message header');
        }
        $required = ord($wire[$headerOffset]);
        if ($signatureCount !== $required) {
            throw new InvalidArgumentException(sprintf(
                'invalid transaction: signature verification failed (expected %d signatures, got %d)',
                $required,
                $signatureCount,
            ));
        }

        $messageBytes = substr($wire, $messageOffset);
        if ($version === 'legacy') {
            return new self(Transaction::deserialize($wire), $messageBytes);
        }

        return new self(VersionedTransaction::deserialize($wire), $messageBytes);
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

    /**
     * Refuse a transaction unless every signature slot verifies over the
     * message for its required signer (RULINGS SIG1). Run before a server
     * claims, co-signs or sends a client transaction, and again after it
     * co-signs.
     *
     * `$unsignedFeePayer` is the server's own fee payer when it has not
     * co-signed yet: its slot (account 0) may still be empty. Every other
     * slot, and a non-empty fee-payer slot, must verify. Pass null once the
     * server has signed, so every slot must verify.
     *
     * @throws InvalidArgumentException naming the first slot that fails
     */
    public function assertSignaturesVerify(?PublicKey $unsignedFeePayer = null): void
    {
        $keys = $this->staticAccountKeys();
        $signatures = array_values($this->transaction->signatures);
        $required = $this->numRequiredSignatures();
        if (count($signatures) !== $required) {
            throw new InvalidArgumentException(sprintf(
                'invalid transaction: signature verification failed (expected %d signatures, got %d)',
                $required,
                count($signatures),
            ));
        }
        $empty = str_repeat("\x00", 64);
        foreach ($signatures as $i => $signature) {
            $signer = $keys[$i] ?? null;
            if ($signer === null) {
                throw new InvalidArgumentException("invalid transaction: signature verification failed (slot {$i} has no signer key)");
            }
            if (
                $signature === $empty
                && $i === 0
                && $unsignedFeePayer !== null
                && $signer->toBase58() === $unsignedFeePayer->toBase58()
            ) {
                continue;
            }
            if ($signature === $empty) {
                throw new InvalidArgumentException("invalid transaction: signature verification failed (slot {$i} is unsigned)");
            }
            if (!Keypair::verify($signature, $this->messageBytes, $signer)) {
                throw new InvalidArgumentException("invalid transaction: signature verification failed (slot {$i} does not verify)");
            }
        }
    }

    /** Serialize in the original framing (legacy or v0). */
    public function serialize(bool $verifySignatures = true): string
    {
        return $this->transaction->serialize($verifySignatures);
    }
}
