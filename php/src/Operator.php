<?php

declare(strict_types=1);

namespace PayKit;

use PayKit\Signer\LocalSigner;

/**
 * Merchant identity: recipient + signer + fee-payer flag.
 *
 * Null fields cascade through {@see Operator::withDefaults()} when
 * PayKit is constructed: recipient defaults to signer->pubkey(),
 * signer defaults to {@see Signer::demo()}.
 */
final readonly class Operator
{
    public function __construct(
        public ?string $recipient = null,
        public ?LocalSigner $signer = null,
        public bool $feePayer = true,
    ) {
    }

    /**
     * Resolve nulls into the package-shipped defaults. The PayKit
     * constructor calls this exactly once at boot.
     */
    public function withDefaults(): self
    {
        $signer = $this->signer ?? Signer::demo();
        $recipient = $this->recipient ?? $signer->pubkey();
        return new self($recipient, $signer, $this->feePayer);
    }

    /**
     * The recipient pubkey to settle to. Always non-null after
     * `withDefaults()`.
     */
    public function effectiveRecipient(): string
    {
        return $this->recipient ?? ($this->signer?->pubkey() ?? Signer::demo()->pubkey());
    }
}
