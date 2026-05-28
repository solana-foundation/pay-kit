<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Core;

use InvalidArgumentException;

/**
 * Represents the Payment authorization credential sent by a client.
 */
final class Credential
{
    /**
     * Create a credential that echoes a challenge and carries payment payload data.
     *
     * @param array<string, mixed> $payload
     */
    public function __construct(
        public readonly ChallengeEcho $challenge,
        public readonly array $payload = [],
        public readonly ?string $source = null,
    ) {
    }

    /**
     * Convert the credential to its JSON wire shape.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $value = [
            'challenge' => $this->challenge->toArray(),
            'payload' => $this->payload,
        ];
        if ($this->source !== null) {
            $value['source'] = $this->source;
        }

        return $value;
    }

    /**
     * Format the credential as an Authorization header value.
     */
    public function toAuthorizationHeader(): string
    {
        return 'Payment ' . Base64Url::encodeJson($this->toArray());
    }

    /**
     * Parse an Authorization header into a Payment credential.
     */
    public static function fromAuthorizationHeader(string $header): self
    {
        $token = self::extractPaymentToken($header);
        if (strlen($token) > 16 * 1024) {
            throw new InvalidArgumentException('Token exceeds maximum length of 16384 bytes');
        }

        $decoded = Base64Url::decodeJson($token);
        if (!isset($decoded['challenge']) || !is_array($decoded['challenge'])) {
            throw new InvalidArgumentException('Invalid credential JSON structure');
        }

        $payload = $decoded['payload'] ?? [];
        if (!is_array($payload)) {
            throw new InvalidArgumentException('Credential payload must be an object');
        }

        return new self(
            challenge: ChallengeEcho::fromArray(Json::object($decoded['challenge'], 'challenge')),
            payload: Json::object($payload, 'payload'),
            source: isset($decoded['source']) ? Json::string($decoded['source'], 'source') : null,
        );
    }

    private static function extractPaymentToken(string $header): string
    {
        foreach (explode(',', $header) as $part) {
            $part = trim($part);
            if (stripos($part, 'Payment ') === 0) {
                return trim(substr($part, strlen('Payment ')));
            }
        }

        throw new InvalidArgumentException('Expected Payment scheme');
    }
}
