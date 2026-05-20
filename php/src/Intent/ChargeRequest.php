<?php

declare(strict_types=1);

namespace SolanaMpp\Intent;

use InvalidArgumentException;

final class ChargeRequest
{
    /**
     * @param array<string, mixed>|null $methodDetails
     */
    public function __construct(
        public readonly string $amount,
        public readonly string $currency,
        public readonly string $recipient = '',
        public readonly string $description = '',
        public readonly string $externalId = '',
        public readonly ?array $methodDetails = null,
    ) {
        self::assertBaseUnits($amount, 'amount');
        if ($currency === '') {
            throw new InvalidArgumentException('currency is required');
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $value = [
            'amount' => $this->amount,
            'currency' => $this->currency,
        ];
        if ($this->recipient !== '') {
            $value['recipient'] = $this->recipient;
        }
        if ($this->description !== '') {
            $value['description'] = $this->description;
        }
        if ($this->externalId !== '') {
            $value['externalId'] = $this->externalId;
        }
        if ($this->methodDetails !== null) {
            $value['methodDetails'] = $this->methodDetails;
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $value
     */
    public static function fromArray(array $value): self
    {
        $methodDetails = $value['methodDetails'] ?? null;
        if ($methodDetails !== null && !is_array($methodDetails)) {
            throw new InvalidArgumentException('methodDetails must be an object');
        }

        /** @var array<string, mixed>|null $methodDetails */
        return new self(
            amount: (string)($value['amount'] ?? ''),
            currency: (string)($value['currency'] ?? ''),
            recipient: (string)($value['recipient'] ?? ''),
            description: (string)($value['description'] ?? ''),
            externalId: (string)($value['externalId'] ?? ''),
            methodDetails: $methodDetails,
        );
    }

    private static function assertBaseUnits(string $value, string $field): void
    {
        if (
            $value === '' ||
            !ctype_digit($value) ||
            ltrim($value, '0') === '' ||
            (strlen($value) > 1 && str_starts_with($value, '0'))
        ) {
            throw new InvalidArgumentException(sprintf('%s must be a positive base-unit integer string', $field));
        }
    }
}
