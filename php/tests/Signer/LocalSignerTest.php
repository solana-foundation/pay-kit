<?php

declare(strict_types=1);

namespace PayKit\Tests\Signer;

use PayKit\Exception\InvalidKeyException;
use PayKit\Signer;
use PHPUnit\Framework\TestCase;

final class LocalSignerTest extends TestCase
{
    public function testSignReturnsBytes(): void
    {
        $sgn = Signer::generate();
        $sig = $sgn->sign('hello world');
        $this->assertSame(64, strlen($sig));
    }

    public function testPubkeyBase58Shape(): void
    {
        $sgn = Signer::generate();
        $pubkey = $sgn->pubkey();
        $this->assertGreaterThanOrEqual(32, strlen($pubkey));
        $this->assertLessThanOrEqual(44, strlen($pubkey));
    }

    public function testIsFeePayerDefaultsTrue(): void
    {
        $sgn = Signer::generate();
        $this->assertTrue($sgn->isFeePayer());
        $this->assertFalse($sgn->isDemo());
    }

    public function testSecretKeyRoundTrip(): void
    {
        $sgn = Signer::generate();
        $bytes = $sgn->secretKey();
        $this->assertSame(64, strlen($bytes));
        $rebuilt = Signer::bytes($bytes);
        $this->assertSame($sgn->pubkey(), $rebuilt->pubkey());
    }

    public function testBytesAsStringMustBe64ByteString(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::bytes('too-short');
    }

    public function testHexRoundTrip(): void
    {
        $sgn = Signer::generate();
        $hex = bin2hex($sgn->secretKey());
        $rebuilt = Signer::hex($hex);
        $this->assertSame($sgn->pubkey(), $rebuilt->pubkey());
    }

    public function testHexNonHexCharsRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::hex(str_repeat('zz', 64));
    }

    public function testFileMissingPathRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::file('/tmp/nonexistent-paykit-signer-xyz.json');
    }

    public function testFileEmptyPathRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::file('');
    }

    public function testFileLoadsValidJson(): void
    {
        $sgn = Signer::generate();
        $bytes = array_values(unpack('C*', $sgn->secretKey()) ?: []);
        $path = tempnam(sys_get_temp_dir(), 'paykit-signer-') ?: '';
        file_put_contents($path, json_encode($bytes));
        try {
            $rebuilt = Signer::file($path);
            $this->assertSame($sgn->pubkey(), $rebuilt->pubkey());
        } finally {
            @unlink($path);
        }
    }

    public function testEnvAutoDetectsJson(): void
    {
        $sgn = Signer::generate();
        $bytes = array_values(unpack('C*', $sgn->secretKey()) ?: []);
        putenv('PAY_KIT_TEST_SIGNER_JSON=' . json_encode($bytes));
        try {
            $rebuilt = Signer::env('PAY_KIT_TEST_SIGNER_JSON');
            $this->assertNotNull($rebuilt);
            $this->assertSame($sgn->pubkey(), $rebuilt->pubkey());
        } finally {
            putenv('PAY_KIT_TEST_SIGNER_JSON');
        }
    }

    public function testEnvAutoDetectsHex(): void
    {
        $sgn = Signer::generate();
        $hex = bin2hex($sgn->secretKey());
        putenv("PAY_KIT_TEST_SIGNER_HEX=$hex");
        try {
            $rebuilt = Signer::env('PAY_KIT_TEST_SIGNER_HEX');
            $this->assertNotNull($rebuilt);
            $this->assertSame($sgn->pubkey(), $rebuilt->pubkey());
        } finally {
            putenv('PAY_KIT_TEST_SIGNER_HEX');
        }
    }

    public function testEnvRaisesOnMalformed(): void
    {
        putenv('PAY_KIT_TEST_SIGNER_BAD=this-is-not-valid-base58-or-hex-or-json');
        try {
            $this->expectException(InvalidKeyException::class);
            Signer::env('PAY_KIT_TEST_SIGNER_BAD');
        } finally {
            putenv('PAY_KIT_TEST_SIGNER_BAD');
        }
    }
}
