<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Exception\ConfigurationException;
use PayKit\Protocols\Mpp\MppConfig;
use PHPUnit\Framework\TestCase;

final class MppConfigTest extends TestCase
{
    public function testDefaultsMatchCrossLanguageTarget(): void
    {
        $c = new MppConfig();
        $this->assertSame('App', $c->realm);
        $this->assertSame(120, $c->expiresIn);
        $this->assertNull($c->challengeBindingSecret);
    }

    public function testExpiresInZeroRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        new MppConfig(expiresIn: 0);
    }

    public function testExpiresInNegativeRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        new MppConfig(expiresIn: -1);
    }

    public function testWithChallengeBindingSecretReturnsCopy(): void
    {
        $a = new MppConfig(realm: 'Test');
        $b = $a->withChallengeBindingSecret('abc');
        $this->assertSame('Test', $b->realm);
        $this->assertSame('abc', $b->challengeBindingSecret);
        $this->assertNull($a->challengeBindingSecret);
    }
}
