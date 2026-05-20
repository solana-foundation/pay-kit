<?php

declare(strict_types=1);

namespace SolanaMpp\Core;

use InvalidArgumentException;
use JsonException;

final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

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

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    private static function pad(string $value): string
    {
        $remainder = strlen($value) % 4;
        if ($remainder === 0) {
            return $value;
        }

        return $value . str_repeat('=', 4 - $remainder);
    }

    /**
     * @param mixed $value
     * @return mixed
     */
    private static function canonicalizeJson(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        if (array_is_list($value)) {
            return array_map(self::canonicalizeJson(...), $value);
        }

        ksort($value, SORT_STRING);
        foreach ($value as $key => $nested) {
            unset($value[$key]);
            $value[(string)$key] = self::canonicalizeJson($nested);
        }

        return $value;
    }
}
