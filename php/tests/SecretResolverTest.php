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

    public function testEnvVarWinsOverDotenvAndGenerator(): void
    {
        putenv('PAY_KIT_TEST_SECRET_AAA=from-env');
        file_put_contents($this->tmpDotenv, "PAY_KIT_TEST_SECRET_AAA=from-dotenv\n");
        $r = SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $this->tmpDotenv);
        $this->assertSame('from-env', $r['secret']);
        $this->assertSame('env', $r['source']);
    }

    public function testDotenvWinsWhenEnvUnset(): void
    {
        putenv('PAY_KIT_TEST_SECRET_AAA');
        file_put_contents($this->tmpDotenv, "PAY_KIT_TEST_SECRET_AAA=from-dotenv\n");
        $r = SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $this->tmpDotenv);
        $this->assertSame('from-dotenv', $r['secret']);
        $this->assertSame('dotenv', $r['source']);
    }

    public function testQuotedDotenvValueStripped(): void
    {
        putenv('PAY_KIT_TEST_SECRET_AAA');
        file_put_contents($this->tmpDotenv, "PAY_KIT_TEST_SECRET_AAA=\"quoted-secret\"\n");
        $r = SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $this->tmpDotenv);
        $this->assertSame('quoted-secret', $r['secret']);
    }

    public function testCommentsAndBlankLinesIgnoredInDotenv(): void
    {
        putenv('PAY_KIT_TEST_SECRET_AAA');
        file_put_contents($this->tmpDotenv, "# comment\n\nUNRELATED=foo\nPAY_KIT_TEST_SECRET_AAA=value-here\n");
        $r = SecretResolver::resolveMppSecret('PAY_KIT_TEST_SECRET_AAA', $this->tmpDotenv);
        $this->assertSame('value-here', $r['secret']);
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
