<?php

declare(strict_types=1);

namespace PayKit\Tests\PayCore\Wire;

use InvalidArgumentException;
use PayKit\PayCore\Wire\Json;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) conformance for
 * {@see Json::canonicalize()}.
 *
 * The reference vectors come from RFC 8785 itself: the worked example in
 * appendix B (key ordering + number serialization) and the ECMAScript
 * Number serialization cases in section 3.2.2.3, which the spec sources
 * from the V8 test suite. Number literals below are the canonical
 * shortest round-trip forms mandated by RFC 8785 section 3.2.2.3.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8785
 */
final class JsonCanonicalTest extends TestCase
{
    public function testCanonicalizeRfc8785AppendixBExample(): void
    {
        // RFC 8785 appendix B style input: members deliberately out of
        // order, a number array exercising shortest-form serialization,
        // a string with an escape, and the three JSON literals.
        $input = [
            'numbers' => [333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001],
            'string' => "\u{20ac}\$\u{000A}A'B/",
            'literals' => [null, true, false],
        ];
        // Canonical output: members sorted by UTF-16 code unit, newline as
        // \n, the currency sign retained as a raw UTF-8 byte, shortest-form
        // numbers per RFC 8785 section 3.2.2.3.
        $expected = '{"literals":[null,true,false],'
            . '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
            . '"string":"€$\nA\'B/"}';
        self::assertSame($expected, Json::canonicalize($input));
    }

    public function testCanonicalizeNestedKeyOrder(): void
    {
        self::assertSame(
            '{"a":[{"a":false,"b":true}],"b":2}',
            Json::canonicalize(['b' => 2, 'a' => [['b' => true, 'a' => false]]]),
        );
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
     * ECMAScript Number serialization cases (RFC 8785 section 3.2.2.3),
     * the shortest round-trip forms the spec borrows from the V8 suite.
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

    #[DataProvider('es6NumberCases')]
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

    public function testCanonicalizeNullValue(): void
    {
        self::assertSame('null', Json::canonicalize(null));
        self::assertSame('{"a":null}', Json::canonicalize(['a' => null]));
    }

    public function testCanonicalizeBoolValues(): void
    {
        self::assertSame('true', Json::canonicalize(true));
        self::assertSame('false', Json::canonicalize(false));
    }

    public function testCanonicalizeEmptyArrayAndObject(): void
    {
        self::assertSame('[]', Json::canonicalize([]));
        // Non-list array with one item works through encodeObject; empty array is list-shape per array_is_list.
    }

    public function testCanonicalizeRejectsUnsupportedValue(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Json::canonicalize(fopen('php://memory', 'rb'));
    }

    public function testCanonicalizeAllEscapeSequences(): void
    {
        // Backslash and double quote escapes.
        self::assertSame('"\\\\"', Json::canonicalize('\\'));
        self::assertSame('"\\""', Json::canonicalize('"'));
        // Backspace, form feed, carriage return.
        self::assertSame('"\\b"', Json::canonicalize("\x08"));
        self::assertSame('"\\f"', Json::canonicalize("\x0C"));
        self::assertSame('"\\r"', Json::canonicalize("\r"));
    }

    public function testCanonicalizeMultiByteBmp(): void
    {
        // 2-byte UTF-8 (Latin-1 supplement, e.g. 'é' = U+00E9).
        self::assertSame("\"\xC3\xA9\"", Json::canonicalize("\xC3\xA9"));
        // 3-byte UTF-8 (CJK, e.g. U+4E2D '中').
        self::assertSame("\"\xE4\xB8\xAD\"", Json::canonicalize("\xE4\xB8\xAD"));
    }

    public function testCanonicalizeSupplementaryPlane(): void
    {
        // 4-byte UTF-8 codepoint U+1F600 ('😀') triggers surrogate pair handling
        // and the 4-byte UTF-8 re-encode path in encodeString.
        $emoji = "\xF0\x9F\x98\x80";
        self::assertSame("\"$emoji\"", Json::canonicalize($emoji));
        // Sort with supplementary plane to exercise utf16CodeUnits surrogate expansion in key sort.
        $result = Json::canonicalize([$emoji => 1, 'a' => 2]);
        // 'a' (0x61) sorts before high-surrogate (0xD83D), so 'a' first.
        self::assertSame("{\"a\":2,\"$emoji\":1}", $result);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function malformedUtf8Cases(): array
    {
        return [
            'invalid-lead-byte-0x80' => ["\x80"],
            'invalid-lead-byte-0xF5' => ["\xF5\x80\x80\x80"],
            'truncated-2byte' => ["\xC2"],
            'invalid-continuation-2byte' => ["\xC2\x20"],
            'truncated-3byte' => ["\xE0\xA0"],
            'invalid-continuation-3byte' => ["\xE0\xA0\x20"],
            'overlong-3byte' => ["\xE0\x80\x80"],
            'surrogate-as-3byte' => ["\xED\xA0\x80"],
            'truncated-4byte' => ["\xF0\x90\x80"],
            'invalid-continuation-4byte' => ["\xF0\x90\x80\x20"],
            '4byte-out-of-range' => ["\xF4\x90\x80\x80"], // U+110000
        ];
    }

    #[DataProvider('malformedUtf8Cases')]
    public function testCanonicalizeRejectsMalformedUtf8(string $invalid): void
    {
        $this->expectException(InvalidArgumentException::class);
        Json::canonicalize($invalid);
    }

    public function testCanonicalizeRejectsInfinity(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Json::canonicalize(INF);
    }

    public function testCanonicalizeNegativeNumber(): void
    {
        self::assertSame('-1.5', Json::canonicalize(-1.5));
        self::assertSame('-1e+21', Json::canonicalize(-1e21));
    }

    public function testCanonicalizeSmallExponentialNumber(): void
    {
        // k < -6 path: 1e-7 already covered; exercise -1e-7 for sign branch.
        self::assertSame('-1e-7', Json::canonicalize(-1e-7));
    }

    public function testCanonicalizeIntegerValuedFloatPadding(): void
    {
        // Forces n <= k+1 padding branch with trailing zero.
        self::assertSame('100', Json::canonicalize(100.0));
        self::assertSame('1000', Json::canonicalize(1000.0));
    }
}
