<?php

declare(strict_types=1);

namespace SolanaMpp\Intent;

use InvalidArgumentException;
use SolanaMpp\Core\Json;

/**
 * Represents the MPP charge intent request embedded in a challenge.
 */
final class ChargeRequest
{
    /**
     * Create an MPP charge request using base-unit integer amounts.
     *
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
     * Convert the charge request to the Payment challenge request object.
     *
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
     * Decode a Payment challenge request object.
     *
     * @param array<string, mixed> $value
     */
    public static function fromArray(array $value): self
    {
        $methodDetails = $value['methodDetails'] ?? null;
        if ($methodDetails !== null && !is_array($methodDetails)) {
            throw new InvalidArgumentException('methodDetails must be an object');
        }

        return new self(
            amount: Json::optionalString($value['amount'] ?? null, 'amount'),
            currency: Json::optionalString($value['currency'] ?? null, 'currency'),
            recipient: Json::optionalString($value['recipient'] ?? null, 'recipient'),
            description: Json::optionalString($value['description'] ?? null, 'description'),
            externalId: Json::optionalString($value['externalId'] ?? null, 'externalId'),
            methodDetails: is_array($methodDetails) ? Json::object($methodDetails, 'methodDetails') : null,
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
