<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\Mpp\Core;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use PayKit\Protocols\Mpp\Core\Base64Url;

final class Base64UrlTest extends TestCase
{
    public function testEncodesAndDecodesBytesWithoutPadding(): void
    {
        $encoded = Base64Url::encode("hello?\xff");

        self::assertStringNotContainsString('=', $encoded);
        self::assertSame("hello?\xff", Base64Url::decode($encoded));
        self::assertSame('', Base64Url::decode(''));
    }

    public function testCanonicalJsonEncodingSortsNestedObjects(): void
    {
        $left = Base64Url::encodeJson([
            'b' => 2,
            'a' => ['z' => 1, 'm' => [['b' => true, 'a' => false]]],
        ]);
        $right = Base64Url::encodeJson([
            'a' => ['m' => [['a' => false, 'b' => true]], 'z' => 1],
            'b' => 2,
        ]);

        self::assertSame($left, $right);
        self::assertSame([
            'a' => ['m' => [['a' => false, 'b' => true]], 'z' => 1],
            'b' => 2,
        ], Base64Url::decodeJson($left));
    }

    public function testCanonicalJsonEncodingMatchesPreBase64UrlVector(): void
    {
        $encoded = Base64Url::encodeJson([
            'b' => 2,
            'a' => [
                [
                    'b' => true,
                    'a' => false,
                ],
            ],
        ]);

        self::assertSame('eyJhIjpbeyJhIjpmYWxzZSwiYiI6dHJ1ZX1dLCJiIjoyfQ', $encoded);
        self::assertSame('{"a":[{"a":false,"b":true}],"b":2}', Base64Url::decode($encoded));
    }

    public function testRejectsInvalidBase64Url(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid base64url value');

        Base64Url::decode('*');
    }

    public function testRejectsInvalidJsonPayload(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JSON value');

        Base64Url::decodeJson(Base64Url::encode('{'));
    }

    public function testRejectsNonJsonValuesDuringCanonicalization(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('unsupported JSON value');

        Base64Url::encodeJson(['object' => (object)['not' => 'json']]);
    }

    public function testRejectsJsonScalars(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('JSON value must be an object');

        Base64Url::decodeJson(Base64Url::encode('"not-an-object"'));
    }

    public function testRejectsJsonListsAtRoot(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('JSON value must be an object');

        Base64Url::decodeJson(Base64Url::encode('[1,2,3]'));
    }
}
