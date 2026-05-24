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
     * Strict RFC 3339 date-time grammar (sec 5.6); accepts lowercase t/z on parse, year 4 digits.
     */
    private const RFC3339_PATTERN = '/^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|z|([+-])(\d{2}):(\d{2}))$/';

    /**
     * Return true when the challenge expiry is invalid or in the past (fail-closed).
     */
    public function isExpired(?DateTimeImmutable $now = null): bool
    {
        if ($this->expires === '') {
            return false;
        }

        if (preg_match(self::RFC3339_PATTERN, $this->expires, $m) !== 1) {
            return true;
        }
        $year = (int)$m[1];
        $month = (int)$m[2];
        $day = (int)$m[3];
        $hour = (int)$m[4];
        $minute = (int)$m[5];
        $second = (int)$m[6];
        $offsetTag = $m[8];
        // RFC 3339 section 5.7 allows seconds = 60 for positive leap seconds.
        // Lua and Go SDKs accept the value at the parser level; PHP must too,
        // otherwise a credential timestamped exactly at 23:59:60 UTC is
        // wrongly flagged expired.
        if ($month < 1 || $month > 12 || $day < 1 || $day > 31 || $hour > 23 || $minute > 59 || $second > 60) {
            return true;
        }
        if ($year > 9999 || !checkdate($month, $day, $year)) {
            return true;
        }
        if ($offsetTag !== 'Z' && $offsetTag !== 'z') {
            $offHour = isset($m[10]) ? (int)$m[10] : 0;
            $offMin = isset($m[11]) ? (int)$m[11] : 0;
            if ($offHour > 23 || $offMin > 59) {
                return true;
            }
        }

        // Normalize lowercase t/z to uppercase before delegating to DateTimeImmutable (DATE_ATOM is strict).
        // PHP's `u` format only accepts exactly six fractional digits; RFC 3339 permits 1..9.
        // Truncate the regex-captured fractional component to microseconds (the regex already
        // bounded it to 1..9 digits, so truncation is safe). Sub-microsecond precision is dropped
        // for expiry comparison purposes which is acceptable since we only need second-level resolution.
        $normalized = strtr($this->expires, ['t' => 'T', 'z' => 'Z']);
        $frac = $m[7];
        if ($frac !== '') {
            $truncated = substr($frac, 0, 6);
            $normalized = preg_replace('/\.\d{1,9}/', '.' . $truncated, $normalized, 1) ?? $normalized;
        }
        $expiresAt = DateTimeImmutable::createFromFormat(DATE_ATOM, $normalized);
        if ($expiresAt === false) {
            $expiresAt = DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s.up', $normalized);
        }
        if ($expiresAt === false) {
            $expiresAt = DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s.uP', $normalized);
        }
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
