<?php

declare(strict_types=1);

namespace PayKit\Tests\PayCore;

use PayKit\PayCore\Rfc3339Parser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * RFC 3339 date-time parser conformance.
 *
 * Vectors are taken from RFC 3339 section 5.8 ("Examples") and the
 * grammar in section 5.6, plus the leap-second case from section 5.7.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc3339#section-5.8
 */
final class Rfc3339Test extends TestCase
{
    /**
     * RFC 3339 sec 5.8 worked examples, plus the lowercase t/z parse
     * caveat (sec 5.6) and the leap-second extension (sec 5.7).
     *
     * @return array<string,array{0:string,1:string}>
     */
    public static function validVectors(): array
    {
        return [
            // RFC 3339 sec 5.8 example: a UTC instant.
            'utc zulu' => ['1985-04-12T23:20:50.52Z', '1985-04-12T23:20:50+00:00'],
            // RFC 3339 sec 5.8 example: the same instant in a -08:00 offset.
            'negative offset' => ['1996-12-19T16:39:57-08:00', '1996-12-19T16:39:57-08:00'],
            // RFC 3339 sec 5.8 example: the leap second at the end of 1990.
            'leap second' => ['1990-12-31T23:59:60Z', '1990-12-31T23:59:59+00:00'],
            // RFC 3339 sec 5.8 example: leap second in a -08:00 offset.
            'leap second offset' => ['1990-12-31T15:59:60-08:00', '1990-12-31T15:59:59-08:00'],
            // RFC 3339 sec 5.8 example: a fractional-second timestamp with offset.
            'fractional offset' => ['1937-01-01T12:00:27.87+00:20', '1937-01-01T12:00:27+00:20'],
            // RFC 3339 sec 5.6 PARSE caveat: lowercase t and z are accepted.
            'lowercase t and z' => ['2024-12-31t23:59:59z', '2024-12-31T23:59:59+00:00'],
            'positive offset' => ['2024-01-15T08:30:00+05:30', '2024-01-15T08:30:00+05:30'],
        ];
    }

    #[DataProvider('validVectors')]
    public function testParsesValidRfc3339(string $input, string $expectedIso): void
    {
        $parsed = Rfc3339Parser::parse($input);
        $this->assertNotNull($parsed);
        $this->assertSame($expectedIso, $parsed->format('c'));
    }

    /**
     * @return array<string,array{0:string}>
     */
    public static function invalidVectors(): array
    {
        return [
            'free text' => ['not-a-timestamp'],
            'date only' => ['2024-12-31'],
            'space separator' => ['2024-12-31 23:59:59Z'],
            'missing zone' => ['2024-12-31T23:59:59'],
            'month out of range' => ['2024-13-01T00:00:00Z'],
            'day out of range' => ['2024-01-32T00:00:00Z'],
            'hour out of range' => ['2024-01-01T24:00:00Z'],
            'minute out of range' => ['2024-01-01T00:60:00Z'],
            'second past leap' => ['2024-01-01T00:00:61Z'],
            'non-existent calendar day' => ['2023-02-29T00:00:00Z'],
            'offset hour out of range' => ['2024-01-01T00:00:00+24:00'],
            'offset minute out of range' => ['2024-01-01T00:00:00+00:60'],
            'two digit year' => ['24-01-01T00:00:00Z'],
        ];
    }

    #[DataProvider('invalidVectors')]
    public function testRejectsInvalidRfc3339(string $input): void
    {
        $this->assertNull(Rfc3339Parser::parse($input));
    }
}
