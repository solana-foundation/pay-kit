<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SolanaMpp\Core\Json;

final class JsonTest extends TestCase
{
    public function testObjectRequiresStringKeys(): void
    {
        self::assertSame(['amount' => '1000'], Json::object(['amount' => '1000'], 'request'));

        $this->expectException(InvalidArgumentException::class);
        Json::object(['valid', 'list'], 'request');
    }

    public function testStringRejectsNonStringValues(): void
    {
        self::assertSame('localnet', Json::string('localnet', 'network'));

        $this->expectException(InvalidArgumentException::class);
        Json::string(123, 'network');
    }

    public function testOptionalStringReturnsDefaultForAbsentValue(): void
    {
        self::assertSame('localnet', Json::optionalString(null, 'network', 'localnet'));
    }

    public function testOptionalIntRejectsStringNumbers(): void
    {
        self::assertSame(6, Json::optionalInt(6, 'decimals'));
        self::assertNull(Json::optionalInt(null, 'decimals'));

        $this->expectException(InvalidArgumentException::class);
        Json::optionalInt('6', 'decimals');
    }

    public function testCanonicalizeNestedKeyOrder(): void
    {
        self::assertSame('{"a":[{"a":false,"b":true}],"b":2}', Json::canonicalize(['b' => 2, 'a' => [['b' => true, 'a' => false]]]));
    }

    public function testCanonicalizeUtf16KeyOrder(): void
    {
        // 'é' (U+00E9 = 233) > 'f' (U+0066 = 102) in UTF-16, so 'f' sorts first.
        self::assertSame('{"f":2,"é":1}', Json::canonicalize(['é' => 1, 'f' => 2]));
    }

    public function testCanonicalizeNumbers(): void
    {
        self::assertSame('1e+21', Json::canonicalize(1e21));
        self::assertSame('0.1', Json::canonicalize(0.1));
        self::assertSame('0', Json::canonicalize(-0.0));
        self::assertSame('0', Json::canonicalize(0));
        self::assertSame('42', Json::canonicalize(42));
    }

    /**
     * ES6 ToString edge cases. The previous %.15g-then-%.17g fallback emitted
     * "333333333.33333331" for the first value (16-significant-digit shortest form).
     * See codex P2 finding on PR #102.
     *
     * @return array<string, array{0: float, 1: string}>
     */
    public static function es6NumberCases(): array
    {
        return [
            '16-digit-shortest' => [333333333.33333329, '333333333.3333333'],
            'point-one-plus-point-two' => [0.1 + 0.2, '0.30000000000000004'],
            'small-1e-7' => [1e-7, '1e-7'],
            'small-1e-6' => [1e-6, '0.000001'],
            'large-1e20' => [1e20, '100000000000000000000'],
            'large-1e21' => [1e21, '1e+21'],
        ];
    }

    /**
     * @dataProvider es6NumberCases
     */
    public function testCanonicalizeEs6ShortestRoundtrip(float $input, string $expected): void
    {
        self::assertSame($expected, Json::canonicalize($input));
    }

    public function testCanonicalizeRejectsLoneSurrogate(): void
    {
        $lone = "\xED\xA0\xB4"; // UTF-8 byte sequence for lone high surrogate U+D834
        $this->expectException(InvalidArgumentException::class);
        // PHP's mb_check_encoding rejects the surrogate byte sequence as invalid UTF-8 (stricter than RFC 8785),
        // which still satisfies the JCS lone-surrogate rejection requirement.
        Json::canonicalize(['k' => $lone]);
    }

    public function testCanonicalizeRejectsNonFinite(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Json::canonicalize(NAN);
    }

    public function testCanonicalizeEscapesControlChars(): void
    {
        self::assertSame('"\\u0001"', Json::canonicalize("\x01"));
        self::assertSame('"\\n"', Json::canonicalize("\n"));
        self::assertSame('"\\t"', Json::canonicalize("\t"));
    }
}
