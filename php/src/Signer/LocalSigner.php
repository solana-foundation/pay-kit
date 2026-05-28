<?php

declare(strict_types=1);

namespace PayKit\Signer;

use PayKit\Exception\InvalidKeyException;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Util\Base58;
use Throwable;

/**
 * Local Ed25519 signer over the solana-php Keypair. Synchronous; no
 * I/O on sign(). Used by every Signer factory except {@see Demo}.
 */
class LocalSigner
{
    public function __construct(
        public readonly Keypair $keypair,
        public readonly bool $isDemoFlag = false,
        public readonly bool $isFeePayerFlag = true,
    ) {
    }

    public static function fromKeypair(Keypair $keypair, bool $isDemo = false): self
    {
        return new self($keypair, isDemoFlag: $isDemo);
    }

    /**
     * @param string|array<int,int> $secret
     */
    public static function fromBytes(string|array $secret): self
    {
        if (is_array($secret)) {
            if (count($secret) !== 64) {
                throw new InvalidKeyException(
                    'pay_kit: Signer::bytes expects 64 integers, got ' . count($secret),
                );
            }
            foreach ($secret as $i => $b) {
                if (!is_int($b) || $b < 0 || $b > 255) {
                    throw new InvalidKeyException(
                        sprintf('pay_kit: Signer::bytes[%d] must be an int in [0,255]', $i),
                    );
                }
            }
            $bytes = '';
            foreach ($secret as $b) {
                $bytes .= chr($b);
            }
            return self::fromKeypair(Keypair::fromSecretKey($bytes));
        }
        if (strlen($secret) !== 64) {
            throw new InvalidKeyException(
                sprintf('pay_kit: Signer::bytes expects a 64-byte secret, got %d bytes', strlen($secret)),
            );
        }
        return self::fromKeypair(Keypair::fromSecretKey($secret));
    }

    public static function fromBase58(string $base58Secret): self
    {
        if ($base58Secret === '') {
            throw new InvalidKeyException('pay_kit: Signer::base58 expects a non-empty string');
        }
        try {
            // Decode raw base58 bytes directly; PublicKey::fromBase58
            // hard-codes the 32-byte pubkey shape and rejects 64-byte
            // secret-key blobs.
            $decoded = Base58::decode($base58Secret);
        } catch (Throwable $e) {
            throw new InvalidKeyException(
                'pay_kit: Signer::base58 invalid base58: ' . $e->getMessage(),
                previous: $e,
            );
        }
        if (strlen($decoded) !== 64) {
            throw new InvalidKeyException(
                sprintf('pay_kit: Signer::base58 decoded length must be 64 bytes, got %d', strlen($decoded)),
            );
        }
        return self::fromKeypair(Keypair::fromSecretKey($decoded));
    }

    public static function fromHex(string $hexSecret): self
    {
        if (strlen($hexSecret) !== 128) {
            throw new InvalidKeyException(
                sprintf('pay_kit: Signer::hex expects 128 chars, got %d', strlen($hexSecret)),
            );
        }
        if (!ctype_xdigit($hexSecret)) {
            throw new InvalidKeyException('pay_kit: Signer::hex contains non-hex characters');
        }
        $bytes = hex2bin($hexSecret);
        if ($bytes === false) {
            throw new InvalidKeyException('pay_kit: Signer::hex decode failed');
        }
        return self::fromKeypair(Keypair::fromSecretKey($bytes));
    }

    public static function generate(): self
    {
        return self::fromKeypair(Keypair::generate());
    }

    public function pubkey(): string
    {
        return (string) $this->keypair->getPublicKey();
    }

    public function sign(string $message): string
    {
        return $this->keypair->sign($message);
    }

    public function isFeePayer(): bool
    {
        return $this->isFeePayerFlag;
    }

    public function isDemo(): bool
    {
        return $this->isDemoFlag;
    }

    /**
     * Raw 64-byte secret bytes. Reserved for internal cosign paths;
     * not part of the public surface.
     *
     * @internal
     */
    public function secretKey(): string
    {
        return $this->keypair->getSecretKey();
    }
}
