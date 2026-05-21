<?php

declare(strict_types=1);

namespace SolanaMpp\Core;

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
        try {
            return self::encode(json_encode(self::canonicalizeJson($value), JSON_THROW_ON_ERROR));
        } catch (JsonException $error) {
            throw new InvalidArgumentException('Invalid JSON value', previous: $error);
        }
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

    /**
     * @param array<array-key, mixed>|bool|float|int|string|null $value
     * @return array<array-key, mixed>|bool|float|int|string|null
     */
    private static function canonicalizeJson(array|bool|float|int|string|null $value): array|bool|float|int|string|null
    {
        if (!is_array($value)) {
            return self::canonicalizeScalar($value);
        }

        if (array_is_list($value)) {
            $items = [];
            foreach ($value as $nested) {
                $items[] = is_array($nested) ? self::canonicalizeJson($nested) : self::canonicalizeScalar($nested);
            }

            return $items;
        }

        ksort($value, SORT_STRING);
        foreach ($value as $key => $nested) {
            unset($value[$key]);
            $value[(string)$key] = is_array($nested) ? self::canonicalizeJson($nested) : self::canonicalizeScalar($nested);
        }

        return $value;
    }

    /**
     * @return bool|float|int|string|null
     */
    private static function canonicalizeScalar(mixed $value): bool|float|int|string|null
    {
        if (
            $value === null ||
            is_bool($value) ||
            is_float($value) ||
            is_int($value) ||
            is_string($value)
        ) {
            return $value;
        }

        throw new InvalidArgumentException('JSON value must be a scalar, object, or list');
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
