<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Core;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PayKit\PayCore\Rfc3339Parser;
use PayKit\PayCore\Wire\Json;

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
        $timestamp = Json::optionalString($value['timestamp'] ?? null, 'timestamp');
        // The canonical mpp-tools receipt vectors reject a non-ISO-8601
        // timestamp (error_non_iso8601_timestamp). Validate the wire timestamp
        // shape here, reusing the RFC 3339 grammar the challenge expiry path
        // already enforces, so the receipt parser fails loudly on a malformed
        // timestamp rather than carrying it forward.
        if ($timestamp !== '' && Rfc3339Parser::parse($timestamp) === null) {
            throw new InvalidArgumentException('Receipt timestamp must be an RFC 3339 / ISO 8601 date-time');
        }

        return new self(
            status: Json::optionalString($value['status'] ?? null, 'status'),
            method: Json::optionalString($value['method'] ?? null, 'method'),
            timestamp: $timestamp,
            reference: Json::optionalString($value['reference'] ?? null, 'reference'),
            challengeId: Json::optionalString($value['challengeId'] ?? null, 'challengeId'),
            externalId: Json::optionalString($value['externalId'] ?? null, 'externalId'),
        );
    }
}
