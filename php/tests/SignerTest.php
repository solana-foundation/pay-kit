<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Exception\InvalidKeyException;
use PayKit\Signer;
use PayKit\Signer\Demo;
use PHPUnit\Framework\TestCase;
use SolanaPhpSdk\Util\Base58;

final class SignerTest extends TestCase
{
    public function testDemoReturnsCanonicalPubkey(): void
    {
        $sgn = Signer::demo();
        $this->assertTrue($sgn->isDemo());
        $this->assertSame(Demo::PUBKEY, $sgn->pubkey());
        $this->assertSame(Demo::PUBKEY, $sgn->pubkey()); // cached
    }

    public function testGenerateProducesValidKeypair(): void
    {
        $sgn = Signer::generate();
        $this->assertFalse($sgn->isDemo());
        $this->assertSame(64, strlen($sgn->secretKey()));
        $this->assertNotEmpty($sgn->pubkey());
    }

    public function testBytesAcceptsArrayOfInts(): void
    {
        $arr = array_fill(0, 64, 1);
        $sgn = Signer::bytes($arr);
        $this->assertNotEmpty($sgn->pubkey());
    }

    public function testBytesRejectsWrongLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::bytes(array_fill(0, 32, 1));
    }

    public function testBytesRejectsOutOfRange(): void
    {
        $arr = array_fill(0, 64, 1);
        $arr[10] = 999;
        $this->expectException(InvalidKeyException::class);
        Signer::bytes($arr);
    }

    public function testJsonAcceptsCliFormat(): void
    {
        $bytes = array_fill(0, 64, 7);
        $sgn = Signer::json(json_encode($bytes, JSON_THROW_ON_ERROR));
        $this->assertNotEmpty($sgn->pubkey());
    }

    public function testJsonRejectsEmpty(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::json('');
    }

    public function testHexAcceptsValidHex(): void
    {
        $hex = str_repeat('aa', 64);
        $sgn = Signer::hex($hex);
        $this->assertNotEmpty($sgn->pubkey());
    }

    public function testHexRejectsWrongLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::hex('abc');
    }

    public function testEnvReturnsNullForUnset(): void
    {
        $this->assertNull(Signer::env('PAY_KIT_UNSET_X9Y8Z7'));
    }

    public function testEnvRejectsEmptyName(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::env('');
    }
    public function testBase58RejectsTooShortDecoded(): void
    {
        // Valid base58 but decoded length != 64 -> rejected.
        $this->expectException(InvalidKeyException::class);
        Signer::base58('abc123');
    }

    public function testBase58RejectsEmpty(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::base58('');
    }

    public function testJsonRejectsNonArrayPayload(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::json('42');
    }

    public function testEnvWhitespaceOnlyReturnsNull(): void
    {
        putenv('PAY_KIT_TEST_BLANK=   ');
        try {
            $this->assertNull(Signer::env('PAY_KIT_TEST_BLANK'));
        } finally {
            putenv('PAY_KIT_TEST_BLANK');
        }
    }

    public function testBase58SecretKeyRoundTrip(): void
    {
        $sgn = Signer::generate();
        $b58 = Base58::encode($sgn->secretKey());
        $rebuilt = Signer::base58($b58);
        $this->assertSame($sgn->pubkey(), $rebuilt->pubkey());
        $this->assertSame($sgn->secretKey(), $rebuilt->secretKey());
    }

    public function testDemoResetForTestsKeepsStableDemoPubkey(): void
    {
        $a = Signer::demo();
        Demo::resetForTests();
        $b = Signer::demo();
        $this->assertSame($a->pubkey(), $b->pubkey());
    }
}
