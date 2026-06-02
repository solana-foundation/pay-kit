<?php

declare(strict_types=1);

namespace PayKit\PayCore\Wire;

use InvalidArgumentException;
use JsonException;

/**
 * Encodes raw bytes and canonical JSON objects as unpadded base64url.
 */
final class Base64Url
{
    /**
     * Encode raw bytes as unpadded URL-safe base64.
     */
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Decode unpadded URL-safe base64 into raw bytes.
     */
    public static function decode(string $value): string
    {
        if ($value === '') {
            return '';
        }

        $decoded = base64_decode(strtr(self::pad($value), '-_', '+/'), true);
        if ($decoded === false) {
            throw new InvalidArgumentException('Invalid base64url value');
        }

        return $decoded;
    }

    /**
     * Canonicalize a JSON object and encode it as unpadded base64url.
     *
     * @param array<string, mixed> $value
     */
    public static function encodeJson(array $value): string
    {
        return self::encode(Json::canonicalize($value));
    }

    /**
     * Decode an unpadded base64url JSON object.
     *
     * @return array<string, mixed>
     */
    public static function decodeJson(string $value): array
    {
        try {
            $decoded = json_decode(self::decode($value), true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            throw new InvalidArgumentException('Invalid JSON value', previous: $error);
        }

        if (!is_array($decoded)) {
            throw new InvalidArgumentException('JSON value must be an object');
        }

        return Json::object($decoded, 'JSON value');
    }

    private static function pad(string $value): string
    {
        $remainder = strlen($value) % 4;
        if ($remainder === 0) {
            return $value;
        }

        return $value . str_repeat('=', 4 - $remainder);
    }
}
