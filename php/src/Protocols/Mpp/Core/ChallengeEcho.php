<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Core;

use InvalidArgumentException;
use PayKit\PayCore\Wire\Base64Url;
use PayKit\PayCore\Wire\Json;

/**
 * Carries the challenge fields echoed inside a Payment credential.
 */
final class ChallengeEcho
{
    /**
     * Create the challenge echo embedded in a Payment credential.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $realm,
        public readonly string $method,
        public readonly string $intent,
        public readonly string $request,
        public readonly string $expires = '',
        public readonly string $digest = '',
        public readonly ?string $opaque = null,
    ) {
    }

    /**
     * Convert the challenge echo to its credential JSON shape.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $value = [
            'id' => $this->id,
            'realm' => $this->realm,
            'method' => $this->method,
            'intent' => $this->intent,
            'request' => $this->request,
        ];
        if ($this->expires !== '') {
            $value['expires'] = $this->expires;
        }
        if ($this->digest !== '') {
            $value['digest'] = $this->digest;
        }
        if ($this->opaque !== null) {
            $value['opaque'] = $this->opaque;
        }

        return $value;
    }

    /**
     * Convert the echoed credential fields back into a challenge object.
     */
    public function toChallenge(): Challenge
    {
        return new Challenge(
            id: $this->id,
            realm: $this->realm,
            method: $this->method,
            intent: $this->intent,
            request: $this->request,
            expires: $this->expires,
            digest: $this->digest,
            opaque: $this->opaque,
        );
    }

    /**
     * Decode a credential challenge echo from JSON.
     *
     * @param array<string, mixed> $value
     */
    public static function fromArray(array $value): self
    {
        $request = $value['request'] ?? '';
        if (is_array($request)) {
            $request = Base64Url::encodeJson(Json::object($request, 'request'));
        }

        // The canonical mpp-tools credential vectors reject a credential whose
        // embedded challenge carries no `id` (error_missing_challenge_id). The
        // rust spine enforces this via a non-optional `id` on PaymentChallenge;
        // mirror that here so the credential parse fails loudly.
        $id = Json::optionalString($value['id'] ?? null, 'id');
        if ($id === '') {
            throw new InvalidArgumentException('Credential challenge is missing required field "id"');
        }

        return new self(
            id: $id,
            realm: Json::optionalString($value['realm'] ?? null, 'realm'),
            method: Json::optionalString($value['method'] ?? null, 'method'),
            intent: Json::optionalString($value['intent'] ?? null, 'intent'),
            request: Json::optionalString($request, 'request'),
            expires: Json::optionalString($value['expires'] ?? null, 'expires'),
            digest: Json::optionalString($value['digest'] ?? null, 'digest'),
            opaque: isset($value['opaque']) ? Json::string($value['opaque'], 'opaque') : null,
        );
    }
}
