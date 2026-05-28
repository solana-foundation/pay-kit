<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Core;

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
     *
     * @see https://datatracker.ietf.org/doc/html/rfc8785 RFC 8785 JSON Canonicalization Scheme
     * @see https://tc39.es/ecma262/multipage/abstract-operations.html#sec-numeric-types-number-tostring
     *      ECMA-262 Number::toString algorithm
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
        $au = self::utf16CodeUnits($a);
        $bu = self::utf16CodeUnits($b);
        $aLen = count($au);
        $bLen = count($bu);
        $n = min($aLen, $bLen);
        for ($i = 0; $i < $n; $i++) {
            if ($au[$i] !== $bu[$i]) {
                return $au[$i] <=> $bu[$i];
            }
        }
        return $aLen <=> $bLen;
    }

    /**
     * Decode a UTF-8 byte string into UTF-16 code units (handles surrogate pair expansion).
     *
     * Pure-PHP so the package does not depend on ext-mbstring (composer.json only declares php
     * and the Solana SDK). Throws InvalidArgumentException for malformed UTF-8 or lone surrogates.
     *
     * @return list<int>
     */
    private static function utf16CodeUnits(string $value): array
    {
        $units = [];
        foreach (self::utf8Codepoints($value) as $cp) {
            if ($cp < 0x10000) {
                $units[] = $cp;
            } else {
                $offset = $cp - 0x10000;
                $units[] = 0xD800 + ($offset >> 10);
                $units[] = 0xDC00 + ($offset & 0x3FF);
            }
        }
        return $units;
    }

    /**
     * Decode a UTF-8 byte string into an array of Unicode codepoints.
     *
     * Rejects malformed UTF-8, overlong encodings, and surrogate codepoints encoded as UTF-8
     * (RFC 3629 sec 3 and RFC 8785 sec 3.2.2 require fail-closed behavior here).
     *
     * @return list<int>
     */
    private static function utf8Codepoints(string $value): array
    {
        $out = [];
        $len = strlen($value);
        $i = 0;
        while ($i < $len) {
            $b1 = ord($value[$i]);
            if ($b1 < 0x80) {
                $out[] = $b1;
                $i += 1;
                continue;
            }
            if ($b1 < 0xC2) {
                throw new InvalidArgumentException('invalid UTF-8 lead byte');
            }
            if ($b1 < 0xE0) {
                if ($i + 1 >= $len) {
                    throw new InvalidArgumentException('truncated UTF-8');
                }
                $b2 = ord($value[$i + 1]);
                if (($b2 & 0xC0) !== 0x80) {
                    throw new InvalidArgumentException('invalid UTF-8 continuation');
                }
                $out[] = (($b1 & 0x1F) << 6) | ($b2 & 0x3F);
                $i += 2;
                continue;
            }
            if ($b1 < 0xF0) {
                if ($i + 2 >= $len) {
                    throw new InvalidArgumentException('truncated UTF-8');
                }
                $b2 = ord($value[$i + 1]);
                $b3 = ord($value[$i + 2]);
                if (($b2 & 0xC0) !== 0x80 || ($b3 & 0xC0) !== 0x80) {
                    throw new InvalidArgumentException('invalid UTF-8 continuation');
                }
                $cp = (($b1 & 0x0F) << 12) | (($b2 & 0x3F) << 6) | ($b3 & 0x3F);
                if ($cp < 0x800) {
                    throw new InvalidArgumentException('overlong UTF-8 sequence');
                }
                if ($cp >= 0xD800 && $cp <= 0xDFFF) {
                    throw new InvalidArgumentException('lone surrogate in string');
                }
                $out[] = $cp;
                $i += 3;
                continue;
            }
            if ($b1 < 0xF5) {
                if ($i + 3 >= $len) {
                    throw new InvalidArgumentException('truncated UTF-8');
                }
                $b2 = ord($value[$i + 1]);
                $b3 = ord($value[$i + 2]);
                $b4 = ord($value[$i + 3]);
                if (($b2 & 0xC0) !== 0x80 || ($b3 & 0xC0) !== 0x80 || ($b4 & 0xC0) !== 0x80) {
                    throw new InvalidArgumentException('invalid UTF-8 continuation');
                }
                $cp = (($b1 & 0x07) << 18) | (($b2 & 0x3F) << 12) | (($b3 & 0x3F) << 6) | ($b4 & 0x3F);
                if ($cp < 0x10000 || $cp > 0x10FFFF) {
                    throw new InvalidArgumentException('UTF-8 codepoint out of range');
                }
                $out[] = $cp;
                $i += 4;
                continue;
            }
            throw new InvalidArgumentException('invalid UTF-8 lead byte');
        }
        return $out;
    }

    /**
     * ES6 ToString (ECMA-262 7.1.12.1) number serialization for JCS (RFC 8785 sec 3.2.2.3).
     *
     * Plain decimal notation when the shortest round-trip representation has decimal exponent k
     * with -6 < k <= 20, exponential form otherwise.
     */
    private static function encodeNumber(float $value): string
    {
        if (is_nan($value)) {
            throw new InvalidArgumentException('cannot encode NaN');
        }
        if (is_infinite($value)) {
            throw new InvalidArgumentException('cannot encode Infinity');
        }
        if ($value === 0.0) {
            return '0';
        }
        $sign = $value < 0 ? '-' : '';
        [$digits, $k] = self::shortestDigitsAndExponent(abs($value));
        return self::formatEs6Number($sign, $digits, $k);
    }

    /**
     * @return array{0: string, 1: int}
     */
    private static function shortestDigitsAndExponent(float $absValue): array
    {
        // ES6 ToString (ECMA-262 7.1.12.1) requires the shortest decimal representation that
        // round-trips back to the same double. Walk %.{p}g from p=1 to 17 and pick the first
        // that round-trips. Only checking %.15g misses values whose shortest form needs 16
        // digits (e.g. 333333333.33333329 -> "333333333.3333333", %.16g), and jumping to
        // %.17g for those produces a non-canonical encoder output that diverges from JS.
        $repr = sprintf('%.17g', $absValue);
        for ($p = 1; $p <= 17; $p++) {
            $candidate = sprintf('%.' . $p . 'g', $absValue);
            if ((float)$candidate === $absValue) {
                $repr = $candidate;
                break;
            }
        }
        if (stripos($repr, 'e') !== false) {
            $parts = preg_split('/[eE]/', $repr);
            if (!is_array($parts) || count($parts) !== 2) {
                return [$repr, 0];
            }
            $mantissa = $parts[0];
            $expInt = (int)$parts[1];
        } else {
            $mantissa = $repr;
            $expInt = 0;
        }
        $dotPos = strpos($mantissa, '.');
        if ($dotPos === false) {
            $intPart = $mantissa;
            $fracPart = '';
        } else {
            $intPart = substr($mantissa, 0, $dotPos);
            $fracPart = substr($mantissa, $dotPos + 1);
        }
        $combined = $intPart . $fracPart;
        $stripped = ltrim($combined, '0');
        $leadingZeros = strlen($combined) - strlen($stripped);
        $digits = rtrim($stripped, '0');
        if ($digits === '') {
            $digits = '0';
        }
        $decimalExponent = $expInt + strlen($intPart) - 1 - $leadingZeros;
        return [$digits, $decimalExponent];
    }

    private static function formatEs6Number(string $sign, string $digits, int $k): string
    {
        $n = strlen($digits);
        if ($k >= 0 && $k <= 20) {
            if ($n <= $k + 1) {
                return $sign . $digits . str_repeat('0', $k + 1 - $n);
            }
            return $sign . substr($digits, 0, $k + 1) . '.' . substr($digits, $k + 1);
        }
        if ($k < 0 && $k > -7) {
            return $sign . '0.' . str_repeat('0', -$k - 1) . $digits;
        }
        $mantissa = $n === 1 ? $digits : ($digits[0] . '.' . substr($digits, 1));
        $expSign = $k >= 0 ? '+' : '-';
        return $sign . $mantissa . 'e' . $expSign . abs($k);
    }

    /**
     * Emit a JCS-conformant JSON string literal (RFC 8785 sec 3.2.2.2), rejecting lone surrogates.
     *
     * Pure-PHP (no ext-mbstring dependency).
     */
    private static function encodeString(string $value): string
    {
        $buf = '"';
        foreach (self::utf8Codepoints($value) as $cp) {
            if ($cp === 0x5C) {
                $buf .= '\\\\';
            } elseif ($cp === 0x22) {
                $buf .= '\\"';
            } elseif ($cp === 0x08) {
                $buf .= '\\b';
            } elseif ($cp === 0x09) {
                $buf .= '\\t';
            } elseif ($cp === 0x0A) {
                $buf .= '\\n';
            } elseif ($cp === 0x0C) {
                $buf .= '\\f';
            } elseif ($cp === 0x0D) {
                $buf .= '\\r';
            } elseif ($cp < 0x20) {
                $buf .= sprintf('\\u%04x', $cp);
            } elseif ($cp < 0x80) {
                $buf .= chr($cp);
            } elseif ($cp < 0x800) {
                $buf .= chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
            } elseif ($cp < 0x10000) {
                $buf .= chr(0xE0 | ($cp >> 12))
                    . chr(0x80 | (($cp >> 6) & 0x3F))
                    . chr(0x80 | ($cp & 0x3F));
            } else {
                $buf .= chr(0xF0 | ($cp >> 18))
                    . chr(0x80 | (($cp >> 12) & 0x3F))
                    . chr(0x80 | (($cp >> 6) & 0x3F))
                    . chr(0x80 | ($cp & 0x3F));
            }
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
