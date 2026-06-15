<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Protocols\Mpp\SecretResolver;
use PHPUnit\Framework\TestCase;

/**
 * Mirrors Ruby PR #142 caveat #4: env -> .env -> generate + persist.
 *
 * Each test points the resolver at a per-test temp file so the suite
 * doesn't leak .env files into the repo root.
 */
final class SecretResolverTest extends TestCase
{
    private string $tmpDotenv = '';

    protected function setUp(): void
    {
        $this->tmpDotenv = tempnam(sys_get_temp_dir(), 'paykit-dotenv-') ?: '';
        // tempnam creates the file; the writer expects "did the file
        // already exist" semantics, so leave it (empty).
    }

    protected function tearDown(): void
    {
        if ($this->tmpDotenv !== '' && is_file($this->tmpDotenv)) {
            @unlink($this->tmpDotenv);
        }
        putenv('PAY_KIT_TEST_SECRET_AAA');
    }

    // 32+ byte secrets (audit #24): the resolver now rejects weak
    // env/dotenv-supplied values, so test fixtures must clear the floor.
    private const STRONG_ENV = 'from-env-0123456789abcdef-0123456789';
    private const STRONG_DOTENV = 'from-dotenv-0123456789abcdef-012345';

    public function testEnvVarWinsOverDotenvAndGenerator(): void
    {
        putenv('PAY_KIT_TEST_SECRET_AAA=' . self::STRONG_ENV);
        file_put_contents($this->tmpDotenv, 'PAY_KIT_TEST_SECRET_AAA=' . self::STRONG_DOTENV . "\n");
        $r = SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $this->tmpDotenv);
        $this->assertSame(self::STRONG_ENV, $r['secret']);
        $this->assertSame('env', $r['source']);
    }

    public function testDotenvWinsWhenEnvUnset(): void
    {
        putenv('PAY_KIT_TEST_SECRET_AAA');
        file_put_contents($this->tmpDotenv, 'PAY_KIT_TEST_SECRET_AAA=' . self::STRONG_DOTENV . "\n");
        $r = SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $this->tmpDotenv);
        $this->assertSame(self::STRONG_DOTENV, $r['secret']);
        $this->assertSame('dotenv', $r['source']);
    }

    public function testQuotedDotenvValueStripped(): void
    {
        putenv('PAY_KIT_TEST_SECRET_AAA');
        file_put_contents($this->tmpDotenv, 'PAY_KIT_TEST_SECRET_AAA="' . self::STRONG_DOTENV . "\"\n");
        $r = SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $this->tmpDotenv);
        $this->assertSame(self::STRONG_DOTENV, $r['secret']);
    }

    public function testCommentsAndBlankLinesIgnoredInDotenv(): void
    {
        putenv('PAY_KIT_TEST_SECRET_AAA');
        file_put_contents($this->tmpDotenv, "# comment\n\nUNRELATED=foo\nPAY_KIT_TEST_SECRET_AAA=" . self::STRONG_DOTENV . "\n");
        $r = SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $this->tmpDotenv);
        $this->assertSame(self::STRONG_DOTENV, $r['secret']);
    }

    public function testRejectsWeakEnvSecret(): void
    {
        // audit #24: a short operator-supplied env secret is rejected at the
        // resolution boundary rather than accepted verbatim.
        putenv('PAY_KIT_TEST_SECRET_AAA=tooshort');
        $this->expectException(\InvalidArgumentException::class);
        SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $this->tmpDotenv);
    }

    public function testRejectsWeakDotenvSecret(): void
    {
        putenv('PAY_KIT_TEST_SECRET_AAA');
        file_put_contents($this->tmpDotenv, "PAY_KIT_TEST_SECRET_AAA=tooshort\n");
        $this->expectException(\InvalidArgumentException::class);
        SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $this->tmpDotenv);
    }

    public function testGenerateAndPersistWhenBothMissing(): void
    {
        putenv('PAY_KIT_TEST_SECRET_AAA');
        // Use a non-existent path so we exercise the create path.
        $path = $this->tmpDotenv . '-fresh';
        @unlink($path);
        $r = SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $path);
        $this->assertSame(64, strlen($r['secret'])); // 32 bytes hex
        $this->assertSame('generated+persisted', $r['source']);
        $this->assertTrue($r['persisted']);
        $this->assertFileExists($path);
        $this->assertStringContainsString('PAY_KIT_TEST_SECRET_AAA=', file_get_contents($path) ?: '');
        @unlink($path);
    }
}
