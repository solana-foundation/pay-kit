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
     * Encode a value as RFC 8785 canonical JSON.
     *
     * Sorts object keys by UTF-16 code-unit order, serializes numbers per ES6 ToString
     * (ECMA-262 7.1.12.1), and rejects NaN, Infinity, and lone surrogates.
     */
    public static function canonicalize(mixed $value): string
    {
        return self::encodeValue($value);
    }

    private static function encodeValue(mixed $value): string
    {
        if ($value === null) {
            return 'null';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_int($value)) {
            return (string)$value;
        }
        if (is_float($value)) {
            return self::encodeNumber($value);
        }
        if (is_string($value)) {
            return self::encodeString($value);
        }
        if (is_array($value)) {
            if (array_is_list($value)) {
                $parts = array_map(fn ($item) => self::encodeValue($item), $value);
                return '[' . implode(',', $parts) . ']';
            }
            return self::encodeObject($value);
        }
        throw new InvalidArgumentException('unsupported JSON value');
    }

    /**
     * @param array<array-key, mixed> $value
     */
    private static function encodeObject(array $value): string
    {
        $stringKeyed = [];
        foreach ($value as $key => $item) {
            $stringKey = (string)$key;
            if (array_key_exists($stringKey, $stringKeyed)) {
                throw new InvalidArgumentException('duplicate object key');
            }
            $stringKeyed[$stringKey] = $item;
        }
        $keys = array_keys($stringKeyed);
        usort($keys, static function (string $a, string $b): int {
            return self::compareUtf16($a, $b);
        });
        $parts = [];
        foreach ($keys as $key) {
            $parts[] = self::encodeString($key) . ':' . self::encodeValue($stringKeyed[$key]);
        }
        return '{' . implode(',', $parts) . '}';
    }

    /**
     * Compare two UTF-8 strings by UTF-16 code-unit order (RFC 8785 sec 3.2.3).
     */
    private static function compareUtf16(string $a, string $b): int
    {
        $au = mb_convert_encoding($a, 'UTF-16BE', 'UTF-8');
        $bu = mb_convert_encoding($b, 'UTF-16BE', 'UTF-8');
        $aLen = strlen($au);
        $bLen = strlen($bu);
        $n = min($aLen, $bLen);
        for ($i = 0; $i < $n; $i += 2) {
            $ax = (ord($au[$i]) << 8) | ord($au[$i + 1]);
            $bx = (ord($bu[$i]) << 8) | ord($bu[$i + 1]);
            if ($ax !== $bx) {
                return $ax <=> $bx;
            }
        }
        return $aLen <=> $bLen;
    }

    /**
     * ES6 ToString number serialization for JCS (RFC 8785 sec 3.2.2.3).
     */
    private static function encodeNumber(float $value): string
    {
        if (is_nan($value)) {
            throw new InvalidArgumentException('cannot encode NaN');
        }
        if (is_infinite($value)) {
            throw new InvalidArgumentException('cannot encode Infinity');
        }
        if ($value === 0.0 || $value === -0.0) {
            return '0';
        }
        if ($value === floor($value) && abs($value) < 1e21) {
            return (string)(int)$value;
        }
        // Use round-trip-precision serialization (PHP 7.1+ defaults to 17 with serialize_precision=-1).
        $repr = (string)$value;
        // PHP may emit "1.0E+21" or "1.0e+21"; normalize to ES6 form.
        if (stripos($repr, 'e') !== false) {
            $parts = preg_split('/[eE]/', $repr);
            if ($parts === false || count($parts) !== 2) {
                return $repr;
            }
            [$mantissa, $exp] = $parts;
            $mantissa = rtrim(rtrim($mantissa, '0'), '.');
            if ($mantissa === '' || $mantissa === '-') {
                $mantissa .= '0';
            }
            $expInt = (int)$exp;
            $sign = $expInt >= 0 ? '+' : '-';
            return $mantissa . 'e' . $sign . abs($expInt);
        }
        return $repr;
    }

    /**
     * Emit a JCS-conformant JSON string literal (RFC 8785 sec 3.2.2.2), rejecting lone surrogates.
     */
    private static function encodeString(string $value): string
    {
        // Validate UTF-8 then walk codepoints.
        if (!mb_check_encoding($value, 'UTF-8')) {
            throw new InvalidArgumentException('invalid UTF-8 in string');
        }
        $codepoints = mb_str_split($value, 1, 'UTF-8');
        $buf = '"';
        foreach ($codepoints as $char) {
            $cp = mb_ord($char, 'UTF-8');
            if ($cp >= 0xD800 && $cp <= 0xDFFF) {
                throw new InvalidArgumentException('lone surrogate in string');
            }
            $buf .= match (true) {
                $char === '\\' => '\\\\',
                $char === '"' => '\\"',
                $char === "\b" => '\\b',
                $char === "\t" => '\\t',
                $char === "\n" => '\\n',
                $char === "\f" => '\\f',
                $char === "\r" => '\\r',
                $cp < 0x20 => sprintf('\\u%04x', $cp),
                default => $char,
            };
        }
        return $buf . '"';
    }

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
