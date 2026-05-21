<?php

declare(strict_types=1);

namespace SolanaMpp\Core;

use DateTimeImmutable;
use InvalidArgumentException;

/**
 * Represents a signed MPP challenge from a WWW-Authenticate header.
 */
final class Challenge
{
    /**
     * Create a validated Payment challenge object.
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
        if ($this->id === '' || $this->realm === '' || $this->method === '' || $this->intent === '' || $this->request === '') {
            throw new InvalidArgumentException('Challenge is missing required fields');
        }
        if (!preg_match('/^[a-z]+$/', $this->method)) {
            throw new InvalidArgumentException('Challenge method must be lowercase ASCII');
        }
    }

    /**
     * Build a signed challenge from a charge request payload.
     *
     * @param array<string, mixed> $request
     */
    public static function withSecret(
        string $secretKey,
        string $realm,
        string $method,
        string $intent,
        array $request,
        string $expires = '',
        string $digest = '',
        ?string $opaque = null,
    ): self {
        $encodedRequest = Base64Url::encodeJson($request);
        return new self(
            id: self::computeId($secretKey, $realm, $method, $intent, $encodedRequest, $expires, $digest, $opaque),
            realm: $realm,
            method: $method,
            intent: $intent,
            request: $encodedRequest,
            expires: $expires,
            digest: $digest,
            opaque: $opaque,
        );
    }

    /**
     * Compute the HMAC-backed challenge identifier.
     */
    public static function computeId(
        string $secretKey,
        string $realm,
        string $method,
        string $intent,
        string $request,
        string $expires = '',
        string $digest = '',
        ?string $opaque = null,
    ): string {
        $message = implode('|', [$realm, $method, $intent, $request, $expires, $digest, $opaque ?? '']);
        return Base64Url::encode(hash_hmac('sha256', $message, $secretKey, true));
    }

    /**
     * Verify that this challenge was issued with the expected secret key.
     */
    public function verify(string $secretKey): bool
    {
        $expected = self::computeId(
            $secretKey,
            $this->realm,
            $this->method,
            $this->intent,
            $this->request,
            $this->expires,
            $this->digest,
            $this->opaque,
        );

        return hash_equals($expected, $this->id);
    }

    /**
     * Decode the embedded base64url request object.
     *
     * @return array<string, mixed>
     */
    public function decodeRequest(): array
    {
        return Base64Url::decodeJson($this->request);
    }

    /**
     * Return true when the challenge expiry is invalid or in the past.
     */
    public function isExpired(?DateTimeImmutable $now = null): bool
    {
        if ($this->expires === '') {
            return false;
        }

        $expiresAt = DateTimeImmutable::createFromFormat(DATE_ATOM, $this->expires);
        if ($expiresAt === false) {
            return true;
        }

        return $expiresAt <= ($now ?? new DateTimeImmutable());
    }

    /**
     * Convert the challenge into the echo shape carried by credentials.
     */
    public function toEcho(): ChallengeEcho
    {
        return new ChallengeEcho(
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
}
