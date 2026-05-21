<?php

declare(strict_types=1);

namespace SolanaMpp\Core;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

/**
 * Represents a successful payment receipt header payload.
 */
final class Receipt
{
    /**
     * Create a verified payment receipt.
     */
    public function __construct(
        public readonly string $status,
        public readonly string $method,
        public readonly string $timestamp,
        public readonly string $reference,
        public readonly string $challengeId = '',
        public readonly string $externalId = '',
    ) {
        if ($this->status === '' || $this->method === '' || $this->timestamp === '' || $this->reference === '') {
            throw new InvalidArgumentException('Receipt is missing required fields');
        }
    }

    /**
     * Create a successful receipt with a UTC timestamp.
     */
    public static function success(
        string $method,
        string $reference,
        string $challengeId = '',
        string $externalId = '',
        ?DateTimeImmutable $now = null,
    ): self {
        return new self(
            status: 'success',
            method: $method,
            timestamp: ($now ?? new DateTimeImmutable())->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.v\Z'),
            reference: $reference,
            challengeId: $challengeId,
            externalId: $externalId,
        );
    }

    /**
     * Return true when the receipt represents a successful payment.
     */
    public function isSuccess(): bool
    {
        return $this->status === 'success';
    }

    /**
     * Convert the receipt to its JSON header payload.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $value = [
            'status' => $this->status,
            'method' => $this->method,
            'timestamp' => $this->timestamp,
            'reference' => $this->reference,
        ];
        if ($this->challengeId !== '') {
            $value['challengeId'] = $this->challengeId;
        }
        if ($this->externalId !== '') {
            $value['externalId'] = $this->externalId;
        }

        return $value;
    }

    /**
     * Decode a receipt from its JSON header payload.
     *
     * @param array<string, mixed> $value
     */
    public static function fromArray(array $value): self
    {
        return new self(
            status: Json::optionalString($value['status'] ?? null, 'status'),
            method: Json::optionalString($value['method'] ?? null, 'method'),
            timestamp: Json::optionalString($value['timestamp'] ?? null, 'timestamp'),
            reference: Json::optionalString($value['reference'] ?? null, 'reference'),
            challengeId: Json::optionalString($value['challengeId'] ?? null, 'challengeId'),
            externalId: Json::optionalString($value['externalId'] ?? null, 'externalId'),
        );
    }
}
