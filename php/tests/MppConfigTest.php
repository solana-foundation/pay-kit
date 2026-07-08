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
        // audit #15: the default realm is now null (= derive per-recipient),
        // not a shared literal that would put servers sharing a secret on one
        // credential namespace.
        $this->assertNull($c->realm);
        $this->assertSame(120, $c->expiresIn);
        $this->assertNull($c->challengeBindingSecret);
        $this->assertFalse($c->acceptPushMode);
    }

    public function testEmptyRealmRejected(): void
    {
        // An explicit empty realm would re-introduce the shared namespace.
        $this->expectException(ConfigurationException::class);
        new MppConfig(realm: '');
    }

    public function testResolveRealmDerivesDeterministicPerRecipientDefault(): void
    {
        $a = new MppConfig();
        $recipientA = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';
        $recipientB = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';

        $realmA = $a->resolveRealm($recipientA);
        // Deterministic / restart-safe.
        $this->assertSame($realmA, $a->resolveRealm($recipientA));
        $this->assertMatchesRegularExpression('/^App Id - #\d{1,8}$/', $realmA);
        // Different recipients get different realms (closes the audit shape).
        $this->assertNotSame($realmA, $a->resolveRealm($recipientB));
    }

    public function testResolveRealmUsesExplicitRealmWhenSet(): void
    {
        $c = new MppConfig(realm: 'Acme API');
        $this->assertSame('Acme API', $c->resolveRealm('CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'));
    }

    public function testExpiresInZeroIsDevOnlyOptOut(): void
    {
        // expiresIn = 0 is the explicit, documented dev-only never-expires
        // opt-out. It must be accepted (not rejected); the Adapter turns it
        // into an empty `expires` so the challenge never expires.
        $c = new MppConfig(expiresIn: 0);
        $this->assertSame(0, $c->expiresIn);
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

    public function testResolveExpiresInAbsentUsesDefault(): void
    {
        // Mirrors the Laravel provider's `$cfg['mpp']['expires_in'] ?? null`:
        // an absent key must fall back to the safe 120s default.
        $this->assertSame(120, MppConfig::resolveExpiresIn(null));
        $this->assertSame(90, MppConfig::resolveExpiresIn(null, 90));
    }

    public function testResolveExpiresInEmptyStringRejectedNotNeverExpires(): void
    {
        // Regression: a mis-typed/empty `MPP_EXPIRES_IN` env arrives as "".
        // PHP's (int)"" is 0, which MppConfig accepts as never-expires. The
        // resolver must reject it instead of silently disabling expiry.
        $this->expectException(ConfigurationException::class);
        MppConfig::resolveExpiresIn('');
    }

    public function testResolveExpiresInNonNumericRejected(): void
    {
        // A non-numeric value (e.g. "abc", "120s") would (int)-cast to 0.
        $this->expectException(ConfigurationException::class);
        MppConfig::resolveExpiresIn('120s');
    }

    public function testResolveExpiresInBooleanRejected(): void
    {
        // (bool) true -> (int) 1, (bool) false -> (int) 0; both are wrong.
        $this->expectException(ConfigurationException::class);
        MppConfig::resolveExpiresIn(true);
    }

    public function testResolveExpiresInExplicitZeroIsOptOut(): void
    {
        // Only an explicit integer/numeric 0 yields the never-expires opt-out.
        $this->assertSame(0, MppConfig::resolveExpiresIn(0));
        $this->assertSame(0, MppConfig::resolveExpiresIn('0'));
        $this->assertSame(0, MppConfig::resolveExpiresIn(0.0));
    }

    public function testResolveExpiresInValidIntegerPreserved(): void
    {
        $this->assertSame(300, MppConfig::resolveExpiresIn(300));
        $this->assertSame(300, MppConfig::resolveExpiresIn('300'));
        $this->assertSame(300, MppConfig::resolveExpiresIn(' 300 '));
        $this->assertSame(300, MppConfig::resolveExpiresIn(300.0));
    }

    public function testResolveExpiresInFractionalRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        MppConfig::resolveExpiresIn(1.5);
    }
}
