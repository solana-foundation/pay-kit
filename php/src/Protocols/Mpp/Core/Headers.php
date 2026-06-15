<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Core;

use InvalidArgumentException;
use PayKit\PayCore\Wire\Base64Url;

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
        // The canonical mpp-tools wire round-trips `description` as a first-class
        // WWW-Authenticate auth-param (parse keeps it, format emits it), so it
        // survives a parse/format cycle byte-for-byte against the golden vectors.
        if ($challenge->description !== null && $challenge->description !== '') {
            $parts[] = sprintf('description="%s"', self::escapeQuoted($challenge->description));
        }
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
     * Returns successfully-parsed challenges; malformed individual challenges are skipped, mirroring the
     * Rust spine which exposes Vec<Result<PaymentChallenge, Error>> and filters at the call site.
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
                try {
                    $challenges[] = self::parseWwwAuthenticate($chunk);
                } catch (InvalidArgumentException) {
                    // skip malformed challenge, keep parsing siblings
                }
            }
        }

        return $challenges;
    }

    /**
     * Split a header value into individual `Payment` challenge chunks (quote-aware).
     *
     * Detects RFC 7235 sec 2.1 auth-scheme boundaries (a token followed by whitespace and a
     * key=value pair), not just literal "Payment" occurrences. This is required to correctly
     * terminate a Payment chunk when a different scheme (e.g. Bearer) follows it on the same
     * header value, and to skip over non-Payment schemes that precede or interleave with
     * Payment schemes.
     *
     * @return array<int, string>
     */
    private static function splitPaymentChallengeValues(string $header): array
    {
        $length = strlen($header);
        $schemeStarts = []; // list of [offset, isPayment]
        $inQuote = false;
        $escaped = false;
        $i = 0;
        $atBoundary = true; // true at start of header or right after a top-level comma

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
                $atBoundary = false;
                $i++;
                continue;
            }
            if ($ch === ',') {
                $atBoundary = true;
                $i++;
                continue;
            }
            if ($ch === ' ' || $ch === "\t") {
                $i++;
                continue;
            }
            if ($atBoundary && self::isTokenChar($ch)) {
                $schemeMatch = self::matchAuthSchemeStart($header, $i, $length);
                if ($schemeMatch !== null) {
                    [$schemeEnd, $isPayment] = $schemeMatch;
                    $schemeStarts[] = [$i, $isPayment];
                    $i = $schemeEnd;
                    $atBoundary = false;
                    continue;
                }
            }
            $atBoundary = false;
            $i++;
        }

        if ($schemeStarts === []) {
            return [];
        }

        $chunks = [];
        foreach ($schemeStarts as $idx => [$start, $isPayment]) {
            if (!$isPayment) {
                continue;
            }
            $end = $schemeStarts[$idx + 1][0] ?? $length;
            $chunk = trim(substr($header, $start, $end - $start));
            $chunk = rtrim($chunk, ', ');
            if ($chunk !== '') {
                $chunks[] = $chunk;
            }
        }
        return $chunks;
    }

    /**
     * RFC 7230 sec 3.2.6 tchar.
     */
    private static function isTokenChar(string $ch): bool
    {
        return (ctype_alnum($ch) === true) || strpos("!#$%&'*+-.^_`|~", $ch) !== false;
    }

    /**
     * If `header[$index]` starts an auth-scheme (RFC 7235 sec 2.1), return
     * [offsetAfterScheme, isPaymentScheme]. Otherwise return null.
     *
     * A scheme requires: token, 1*SP, then non-empty content (either an
     * auth-param list `key=val,...` or a token68 credential). A bare
     * `token=` (no SP gap) is an auth-param continuation, not a new scheme.
     *
     * @return array{0: int, 1: bool}|null
     */
    private static function matchAuthSchemeStart(string $header, int $index, int $length): ?array
    {
        $tokenEnd = $index;
        while ($tokenEnd < $length && self::isTokenChar($header[$tokenEnd])) {
            $tokenEnd++;
        }
        if ($tokenEnd === $index) {
            return null;
        }
        if ($tokenEnd >= $length || ($header[$tokenEnd] !== ' ' && $header[$tokenEnd] !== "\t")) {
            return null;
        }
        $cursor = $tokenEnd;
        while ($cursor < $length && ($header[$cursor] === ' ' || $header[$cursor] === "\t")) {
            $cursor++;
        }
        if ($cursor >= $length || $header[$cursor] === ',') {
            return null;
        }
        $scheme = substr($header, $index, $tokenEnd - $index);
        return [$tokenEnd, strcasecmp($scheme, self::PAYMENT_SCHEME) === 0];
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
            description: $params['description'] ?? null,
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
            // A token with no `=` is not an auth-param: skip it and keep parsing,
            // matching the rust spine and the canonical permissive parser. This
            // makes the parser tolerate trailing tokens left after an unescaped
            // quote truncates a quoted value (e.g. a `description` whose value
            // contains a literal `"`), per the canonical
            // `unescaped_quotes_in_description` vector.
            if ($key === '' || $index >= $length || $value[$index] !== '=') {
                while ($index < $length && $value[$index] !== ',' && $value[$index] !== ' ' && $value[$index] !== "\t") {
                    $index++;
                }
                continue;
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
