<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
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
        // Backslash and double quote escapes (lines 292, 294).
        self::assertSame('"\\\\"', Json::canonicalize('\\'));
        self::assertSame('"\\""', Json::canonicalize('"'));
        // Backspace, form feed, carriage return (lines 296, 302, 304).
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
        // 4-byte UTF-8 codepoint U+1F600 ('😀') triggers surrogate pair (lines 109-111)
        // and the 4-byte UTF-8 re-encode path in encodeString (lines 316-319).
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
            'invalid-lead-byte-0x80' => ["\x80"], // line 138
            'invalid-lead-byte-0xF5' => ["\xF5\x80\x80\x80"], // line 190
            'truncated-2byte' => ["\xC2"], // line 142
            'invalid-continuation-2byte' => ["\xC2\x20"], // line 146
            'truncated-3byte' => ["\xE0\xA0"], // line 154
            'invalid-continuation-3byte' => ["\xE0\xA0\x20"], // line 159
            'overlong-3byte' => ["\xE0\x80\x80"], // line 163
            'surrogate-as-3byte' => ["\xED\xA0\x80"], // lines 168-170 (re-cover)
            'truncated-4byte' => ["\xF0\x90\x80"], // line 174
            'invalid-continuation-4byte' => ["\xF0\x90\x80\x20"], // lines 176-180
            '4byte-out-of-range' => ["\xF4\x90\x80\x80"], // U+110000 (line 187)
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

    public function testObjectRejectsNonArray(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Json::object('not-an-object', 'request');
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
        // Forces n <= k+1 padding branch with trailing zero (line 270).
        self::assertSame('100', Json::canonicalize(100.0));
        self::assertSame('1000', Json::canonicalize(1000.0));
    }
}
