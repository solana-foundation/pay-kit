<?php

declare(strict_types=1);

namespace SolanaMpp\Core;

use InvalidArgumentException;

/**
 * Formats and parses MPP HTTP authentication headers.
 */
final class Headers
{
    public const PAYMENT_SCHEME = 'Payment';
    public const WWW_AUTHENTICATE = 'www-authenticate';
    public const AUTHORIZATION = 'authorization';
    public const PAYMENT_RECEIPT = 'payment-receipt';

    /**
     * Format a Payment challenge as a WWW-Authenticate header.
     */
    public static function formatWwwAuthenticate(Challenge $challenge): string
    {
        $parts = [
            sprintf('id="%s"', self::escapeQuoted($challenge->id)),
            sprintf('realm="%s"', self::escapeQuoted($challenge->realm)),
            sprintf('method="%s"', self::escapeQuoted($challenge->method)),
            sprintf('intent="%s"', self::escapeQuoted($challenge->intent)),
            sprintf('request="%s"', self::escapeQuoted($challenge->request)),
        ];
        if ($challenge->expires !== '') {
            $parts[] = sprintf('expires="%s"', self::escapeQuoted($challenge->expires));
        }
        if ($challenge->digest !== '') {
            $parts[] = sprintf('digest="%s"', self::escapeQuoted($challenge->digest));
        }
        if ($challenge->opaque !== null) {
            $parts[] = sprintf('opaque="%s"', self::escapeQuoted($challenge->opaque));
        }

        return self::PAYMENT_SCHEME . ' ' . implode(', ', $parts);
    }

    /**
     * Parse all Payment challenges across one or more WWW-Authenticate header values (RFC 7235 sec 4.1).
     *
     * @param iterable<string>|string $headers
     * @return array<int, Challenge>
     */
    public static function parseWwwAuthenticateAll(iterable|string $headers): array
    {
        $list = is_string($headers) ? [$headers] : $headers;
        $challenges = [];
        foreach ($list as $header) {
            foreach (self::splitPaymentChallengeValues($header) as $chunk) {
                $challenges[] = self::parseWwwAuthenticate($chunk);
            }
        }

        return $challenges;
    }

    /**
     * Split a header value into individual `Payment` challenge chunks (quote-aware).
     *
     * @return array<int, string>
     */
    private static function splitPaymentChallengeValues(string $header): array
    {
        $length = strlen($header);
        $starts = [];
        $inQuote = false;
        $escaped = false;
        $i = 0;
        $scheme = self::PAYMENT_SCHEME;
        $sLen = strlen($scheme);

        while ($i < $length) {
            $ch = $header[$i];
            if ($inQuote) {
                if ($escaped) {
                    $escaped = false;
                } elseif ($ch === '\\') {
                    $escaped = true;
                } elseif ($ch === '"') {
                    $inQuote = false;
                }
                $i++;
                continue;
            }
            if ($ch === '"') {
                $inQuote = true;
                $i++;
                continue;
            }
            if (self::isPaymentSchemeStart($header, $i, $scheme, $sLen, $length)) {
                $starts[] = $i;
                $i += $sLen;
                continue;
            }
            $i++;
        }

        if ($starts === []) {
            return [];
        }

        $chunks = [];
        foreach ($starts as $index => $start) {
            $end = $starts[$index + 1] ?? $length;
            $chunk = trim(substr($header, $start, $end - $start));
            $chunk = rtrim($chunk, ', ');
            if ($chunk !== '') {
                $chunks[] = $chunk;
            }
        }
        return $chunks;
    }

    private static function isPaymentSchemeStart(string $header, int $index, string $scheme, int $sLen, int $length): bool
    {
        if ($index + $sLen >= $length) {
            return false;
        }
        if (strcasecmp(substr($header, $index, $sLen), $scheme) !== 0) {
            return false;
        }
        $next = $header[$index + $sLen];
        if ($next !== ' ' && $next !== "\t") {
            return false;
        }
        $prev = $index - 1;
        while ($prev >= 0 && ($header[$prev] === ' ' || $header[$prev] === "\t")) {
            $prev--;
        }
        return $prev < 0 || $header[$prev] === ',';
    }

    /**
     * Parse a WWW-Authenticate header into a Payment challenge.
     */
    public static function parseWwwAuthenticate(string $header): Challenge
    {
        $payment = self::extractPaymentChallenge($header);
        if ($payment === null) {
            throw new InvalidArgumentException('Expected Payment scheme');
        }

        $params = self::parseAuthParams(trim(substr($payment, strlen(self::PAYMENT_SCHEME))));
        foreach (['id', 'realm', 'method', 'intent', 'request'] as $required) {
            if (($params[$required] ?? '') === '') {
                throw new InvalidArgumentException(sprintf('Missing "%s" field', $required));
            }
        }

        Base64Url::decodeJson($params['request']); // validate the encoded charge request

        return new Challenge(
            id: $params['id'],
            realm: $params['realm'],
            method: $params['method'],
            intent: $params['intent'],
            request: $params['request'],
            expires: $params['expires'] ?? '',
            digest: $params['digest'] ?? '',
            opaque: $params['opaque'] ?? null,
        );
    }

    /**
     * Format a receipt as an unpadded base64url payment-receipt header.
     */
    public static function formatReceipt(Receipt $receipt): string
    {
        return Base64Url::encodeJson($receipt->toArray());
    }

    /**
     * Parse a payment-receipt header into a receipt object.
     */
    public static function parseReceipt(string $header): Receipt
    {
        if (strlen($header) > 16 * 1024) {
            throw new InvalidArgumentException('Receipt exceeds maximum length of 16384 bytes');
        }

        return Receipt::fromArray(Base64Url::decodeJson(trim($header)));
    }

    private static function extractPaymentChallenge(string $header): ?string
    {
        $lower = strtolower($header);
        $needle = strtolower(self::PAYMENT_SCHEME . ' ');
        $position = strpos($lower, $needle);
        if ($position === false) {
            return null;
        }

        return trim(substr($header, $position));
    }

    /**
     * @return array<string, string>
     */
    private static function parseAuthParams(string $value): array
    {
        $params = [];
        $length = strlen($value);
        $index = 0;

        while ($index < $length) {
            while ($index < $length && ($value[$index] === ' ' || $value[$index] === "\t" || $value[$index] === ',')) {
                $index++;
            }
            if ($index >= $length) {
                break;
            }

            $keyStart = $index;
            while ($index < $length && $value[$index] !== '=' && $value[$index] !== ',' && $value[$index] !== ' ' && $value[$index] !== "\t") {
                $index++;
            }
            $key = substr($value, $keyStart, $index - $keyStart);
            while ($index < $length && ($value[$index] === ' ' || $value[$index] === "\t")) {
                $index++;
            }
            if ($key === '' || $index >= $length || $value[$index] !== '=') {
                throw new InvalidArgumentException('Invalid auth parameter');
            }
            $index++;
            while ($index < $length && ($value[$index] === ' ' || $value[$index] === "\t")) {
                $index++;
            }

            if ($index < $length && $value[$index] === '"') {
                [$parsed, $index] = self::parseQuotedValue($value, $index + 1);
                if (array_key_exists($key, $params)) {
                    throw new InvalidArgumentException('Duplicate auth parameter');
                }
                $params[$key] = $parsed;
                continue;
            }

            $valueStart = $index;
            while ($index < $length && $value[$index] !== ',') {
                $index++;
            }
            if (array_key_exists($key, $params)) {
                throw new InvalidArgumentException('Duplicate auth parameter');
            }
            $params[$key] = trim(substr($value, $valueStart, $index - $valueStart));
        }

        return $params;
    }

    /**
     * @return array{0: string, 1: int}
     */
    private static function parseQuotedValue(string $value, int $index): array
    {
        $buffer = '';
        $length = strlen($value);
        while ($index < $length) {
            $char = $value[$index];
            if ($char === '\\') {
                $index++;
                if ($index >= $length) {
                    throw new InvalidArgumentException('Invalid quoted value');
                }
                $buffer .= $value[$index];
                $index++;
                continue;
            }
            if ($char === '"') {
                return [$buffer, $index + 1];
            }
            $buffer .= $char;
            $index++;
        }

        throw new InvalidArgumentException('Unterminated quoted value');
    }

    private static function escapeQuoted(string $value): string
    {
        if (str_contains($value, "\r") || str_contains($value, "\n")) {
            throw new InvalidArgumentException('Invalid header value');
        }

        return str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
    }
}
