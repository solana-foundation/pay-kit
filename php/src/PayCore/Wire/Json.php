<?php

declare(strict_types=1);

namespace PayKit\PayCore\Wire;

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
        // The empty-object marker set by {@see self::decodePreservingObject}
        // tells us this array was originally a JSON `{}` and must round-trip
        // back to `{}` (an empty array, by the §3.2.2 shape, would emit `[]`).
        if (count($value) === 1 && array_key_exists(self::OBJECT_SENTINEL_KEY, $value)) {
            return '{}';
        }
        // PHP coerces numeric strings back to ints when used as array
        // keys, so $stringKeyed[1] = $item is the same as
        // $stringKeyed['1'] = $item. We need to keep the keys as strings
        // for both the comparison (usort typed parameter) and the encoder
        // (encodeString requires string). Two parallel arrays preserve
        // the (key, value) pairing across the sort: pair-index `i` always
        // means the i-th pair in original iteration order.
        $pairs = [];
        $seen = [];
        foreach ($value as $key => $item) {
            $stringKey = (string)$key;
            if ($stringKey === self::OBJECT_SENTINEL_KEY) {
                // Marker is internal; never emit it.
                continue;
            }
            if (array_key_exists($stringKey, $seen)) {
                throw new InvalidArgumentException('duplicate object key');
            }
            $seen[$stringKey] = true;
            $pairs[] = [$stringKey, $item];
        }
        usort($pairs, static function (array $a, array $b): int {
            return self::compareUtf16($a[0], $b[0]);
        });
        $parts = [];
        foreach ($pairs as [$key, $item]) {
            $parts[] = self::encodeString($key) . ':' . self::encodeValue($item);
        }
        return '{' . implode(',', $parts) . '}';
    }

    /**
     * Sentinel key set by {@see self::decodePreservingObject} on a decoded
     * empty object so {@see self::encodeObject()} can distinguish it from
     * an empty array. The key is illegal in JCS because the marker string
     * contains characters a normal key never would (the \u{1F4A3} BOM
     * emoji surrounded by underscores); the encoder also drops the marker
     * key itself if it somehow leaks into a non-empty object.
     */
    private const OBJECT_SENTINEL_KEY = "\u{1F4A3}__object__\u{1F4A3}";

    /**
     * Decode JSON into a structure that preserves the `{}` vs `[]`
     * distinction. PHP's `json_decode($x, true)` collapses both into a
     * zero-length array; the harness runner needs to know which one
     * crossed the wire because canonical JCS round-trips them as `{}` and
     * `[]` respectively. The decoder tags every empty `{}` it sees with
     * {@see self::OBJECT_SENTINEL_KEY} on the resulting array; the
     * encoder recognizes that key and emits `{}`.
     *
     * @return mixed
     */
    public static function decodePreservingObject(string $json)
    {
        $pos = 0;
        $len = strlen($json);
        return self::decodeValuePreserving($json, $len, $pos);
    }

    private static function decodeValuePreserving(string $json, int $len, int &$pos)
    {
        self::skipWsPreserving($json, $len, $pos);
        if ($pos >= $len) {
            throw new InvalidArgumentException('unexpected end of input');
        }
        $c = $json[$pos];
        if ($c === '{') {
            return self::decodeObjectPreserving($json, $len, $pos);
        }
        if ($c === '[') {
            return self::decodeArrayPreserving($json, $len, $pos);
        }
        if ($c === '"') {
            return self::decodeStringPreserving($json, $len, $pos);
        }
        if ($c === 't' || $c === 'f') {
            return self::decodeBoolPreserving($json, $len, $pos);
        }
        if ($c === 'n') {
            self::consumeKeywordPreserving($json, $len, $pos, 'null');
            return null;
        }
        return self::decodeNumberPreserving($json, $len, $pos);
    }

    private static function skipWsPreserving(string $json, int $len, int &$pos): void
    {
        while ($pos < $len && in_array($json[$pos], [' ', "\t", "\n", "\r"], true)) {
            $pos++;
        }
    }

    private static function consumeKeywordPreserving(string $json, int $len, int &$pos, string $kw): void
    {
        if (substr($json, $pos, strlen($kw)) !== $kw) {
            throw new InvalidArgumentException("expected keyword $kw at position $pos");
        }
        $pos += strlen($kw);
    }

    private static function decodeStringPreserving(string $json, int $len, int &$pos): string
    {
        if ($json[$pos] !== '"') {
            throw new InvalidArgumentException("expected string at position $pos");
        }
        $pos++;
        $buf = '';
        while ($pos < $len) {
            $c = $json[$pos];
            if ($c === '\\') {
                $pos++;
                if ($pos >= $len) {
                    throw new InvalidArgumentException('unterminated escape');
                }
                $esc = $json[$pos];
                if ($esc === '"') $buf .= '"';
                elseif ($esc === '\\') $buf .= '\\';
                elseif ($esc === '/') $buf .= '/';
                elseif ($esc === 'b') $buf .= "\x08";
                elseif ($esc === 'f') $buf .= "\x0C";
                elseif ($esc === 'n') $buf .= "\n";
                elseif ($esc === 'r') $buf .= "\r";
                elseif ($esc === 't') $buf .= "\t";
                elseif ($esc === 'u') {
                    if ($pos + 4 >= $len) {
                        throw new InvalidArgumentException('truncated \\u escape');
                    }
                    $hex = substr($json, $pos + 1, 4);
                    if (!preg_match('/^[0-9a-fA-F]{4}$/', $hex)) {
                        throw new InvalidArgumentException("invalid \\u hex: $hex");
                    }
                    $pos += 4;
                    $buf .= mb_chr(hexdec($hex), 'UTF-8');
                } else {
                    throw new InvalidArgumentException("invalid escape: \\$esc");
                }
                $pos++;
                continue;
            }
            if ($c === '"') {
                $pos++;
                return $buf;
            }
            $buf .= $c;
            $pos++;
        }
        throw new InvalidArgumentException('unterminated string');
    }

    private static function decodeBoolPreserving(string $json, int $len, int &$pos): bool
    {
        if (substr($json, $pos, 4) === 'true') {
            $pos += 4;
            return true;
        }
        if (substr($json, $pos, 5) === 'false') {
            $pos += 5;
            return false;
        }
        throw new InvalidArgumentException('invalid bool literal at position ' . $pos);
    }

    private static function decodeNumberPreserving(string $json, int $len, int &$pos): int|float
    {
        $start = $pos;
        if ($json[$pos] === '-') {
            $pos++;
        }
        while ($pos < $len && preg_match('/[0-9.eE+\-]/', $json[$pos]) === 1) {
            $pos++;
        }
        $text = substr($json, $start, $pos - $start);
        if (str_contains($text, '.') || stripos($text, 'e') !== false) {
            return (float)$text;
        }
        return (int)$text;
    }

    private static function decodeObjectPreserving(string $json, int $len, int &$pos): array
    {
        if ($json[$pos] !== '{') {
            throw new InvalidArgumentException("expected { at position $pos");
        }
        $pos++;
        self::skipWsPreserving($json, $len, $pos);
        $obj = [];
        if ($pos < $len && $json[$pos] === '}') {
            $pos++;
            // Tag empty object so encodeObject can emit `{}` instead of
            // the array-shape `[]` the same zero-length array would
            // otherwise round-trip to.
            $obj[self::OBJECT_SENTINEL_KEY] = true;
            return $obj;
        }
        while (true) {
            self::skipWsPreserving($json, $len, $pos);
            if ($pos >= $len || $json[$pos] !== '"') {
                throw new InvalidArgumentException("expected string key at position $pos");
            }
            $key = self::decodeStringPreserving($json, $len, $pos);
            self::skipWsPreserving($json, $len, $pos);
            if ($pos >= $len || $json[$pos] !== ':') {
                throw new InvalidArgumentException("expected : at position $pos");
            }
            $pos++;
            $obj[$key] = self::decodeValuePreserving($json, $len, $pos);
            self::skipWsPreserving($json, $len, $pos);
            if ($pos < $len && $json[$pos] === ',') {
                $pos++;
                continue;
            }
            if ($pos < $len && $json[$pos] === '}') {
                $pos++;
                return $obj;
            }
            throw new InvalidArgumentException("expected , or } at position $pos");
        }
    }

    private static function decodeArrayPreserving(string $json, int $len, int &$pos): array
    {
        if ($json[$pos] !== '[') {
            throw new InvalidArgumentException("expected [ at position $pos");
        }
        $pos++;
        $arr = [];
        self::skipWsPreserving($json, $len, $pos);
        if ($pos < $len && $json[$pos] === ']') {
            $pos++;
            return $arr;
        }
        while (true) {
            $arr[] = self::decodeValuePreserving($json, $len, $pos);
            self::skipWsPreserving($json, $len, $pos);
            if ($pos < $len && $json[$pos] === ',') {
                $pos++;
                continue;
            }
            if ($pos < $len && $json[$pos] === ']') {
                $pos++;
                return $arr;
            }
            throw new InvalidArgumentException("expected , or ] at position $pos");
        }
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
