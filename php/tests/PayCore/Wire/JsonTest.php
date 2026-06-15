<?php

declare(strict_types=1);

namespace PayKit\Tests\PayCore\Wire;

use InvalidArgumentException;
use PayKit\PayCore\Wire\Json;
use PHPUnit\Framework\TestCase;

/**
 * Input-shape helpers on {@see Json} (typed field extraction). The RFC 8785
 * canonicalization surface lives in {@see JsonCanonicalTest}.
 */
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

    public function testObjectRejectsNonArray(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Json::object('not-an-object', 'request');
    }
}
