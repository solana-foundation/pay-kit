<?php

declare(strict_types=1);

namespace SolanaMpp\Core;

use InvalidArgumentException;

/**
 * Narrows decoded JSON values before protocol parsing.
 */
final class Json
{
    /**
     * Require a decoded JSON value to be an object-shaped array.
     *
     * @return array<string, mixed>
     */
    public static function object(mixed $value, string $field): array
    {
        if (!is_array($value)) {
            throw new InvalidArgumentException($field . ' must be an object');
        }

        $object = [];
        foreach ($value as $key => $item) {
            if (!is_string($key)) {
                throw new InvalidArgumentException($field . ' must be an object');
            }
            $object[$key] = $item;
        }

        return $object;
    }

    /**
     * Require a decoded JSON value to be a string.
     */
    public static function string(mixed $value, string $field): string
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException($field . ' must be a string');
        }

        return $value;
    }

    /**
     * Return a decoded JSON string or a default when the field is absent.
     */
    public static function optionalString(mixed $value, string $field, string $default = ''): string
    {
        if ($value === null) {
            return $default;
        }

        return self::string($value, $field);
    }

    /**
     * Return a decoded JSON integer or null when the field is absent.
     */
    public static function optionalInt(mixed $value, string $field): ?int
    {
        if ($value === null) {
            return null;
        }
        if (!is_int($value)) {
            throw new InvalidArgumentException($field . ' must be an integer');
        }

        return $value;
    }
}
