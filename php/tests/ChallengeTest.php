<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\ChallengeEcho;

final class ChallengeTest extends TestCase
{
    public function testCreatesHmacBoundChallenge(): void
    {
        $challenge = Challenge::withSecret(
            secretKey: 'secret',
            realm: 'api',
            method: 'solana',
            intent: 'charge',
            request: ['amount' => '1000', 'currency' => 'USDC'],
            expires: '2099-01-01T00:00:00+00:00',
        );

        self::assertTrue($challenge->verify('secret'));
        self::assertFalse($challenge->verify('wrong-secret'));
        self::assertSame(['amount' => '1000', 'currency' => 'USDC'], $challenge->decodeRequest());
        self::assertFalse($challenge->isExpired(new DateTimeImmutable('2026-01-01T00:00:00+00:00')));
    }

    public function testChallengeWithoutExpiryIsNotExpired(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);

        self::assertFalse($challenge->isExpired(new DateTimeImmutable('2026-01-01T00:00:00+00:00')));
    }

    public function testInvalidExpiryFailsClosed(): void
    {
        $challenge = Challenge::withSecret(
            secretKey: 'secret',
            realm: 'api',
            method: 'solana',
            intent: 'charge',
            request: ['amount' => '1', 'currency' => 'USDC'],
            expires: 'not-a-date',
        );

        self::assertTrue($challenge->isExpired(new DateTimeImmutable('2026-01-01T00:00:00+00:00')));
    }

    public function testIsExpiredStrictRfc3339(): void
    {
        $now = new DateTimeImmutable('2026-01-01T00:00:00+00:00');
        $mk = fn (string $exp) => Challenge::withSecret('s', 'api', 'solana', 'charge', ['x' => '1'], expires: $exp);

        self::assertFalse($mk('2099-01-01T00:00:00Z')->isExpired($now));
        self::assertFalse($mk('2099-01-01T00:00:00.123Z')->isExpired($now));
        self::assertFalse($mk('2099-01-01T00:00:00+00:00')->isExpired($now));
        self::assertTrue($mk('tomorrow')->isExpired($now));
        self::assertTrue($mk('10000-01-01T00:00:00Z')->isExpired($now));
        self::assertTrue($mk('2099-02-30T00:00:00Z')->isExpired($now));
        self::assertTrue($mk('2099-13-01T00:00:00Z')->isExpired($now));
        self::assertTrue($mk('2099-01-01T24:00:00Z')->isExpired($now));
        // Offset hours/minutes out of range rejected.
        self::assertTrue($mk('2099-01-01T00:00:00+24:00')->isExpired($now));
        self::assertTrue($mk('2099-01-01T00:00:00+00:60')->isExpired($now));
        // Lowercase t/z accepted on parse.
        self::assertFalse($mk('2099-01-01t00:00:00z')->isExpired($now));
        // RFC 3339 section 5.7: positive leap-second seconds=60 must be accepted
        // (Lua + Go SDKs accept it; PHP previously rejected with $second > 59).
        self::assertFalse($mk('2099-12-31T23:59:60Z')->isExpired($now));
        // 61 stays rejected.
        self::assertTrue($mk('2099-01-01T00:00:61Z')->isExpired($now));

        // 7/8/9 fractional digit (nanosecond) precision must round-trip after
        // truncation to microseconds (codex P2 finding on PR #102; PHP's `u`
        // format only accepts 6 digits, so the prior parser fell through to
        // `return true` for any sub-microsecond expiry).
        self::assertFalse($mk('2099-01-01T00:00:00.1234567Z')->isExpired($now));
        self::assertFalse($mk('2099-01-01T00:00:00.12345678Z')->isExpired($now));
        self::assertFalse($mk('2099-01-01T00:00:00.123456789+00:00')->isExpired($now));
        self::assertFalse($mk('2099-01-01T00:00:00.123456789-05:00')->isExpired($now));
    }

    public function testRejectsMissingRequiredChallengeFields(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Challenge is missing required fields');

        new Challenge(id: '', realm: 'api', method: 'solana', intent: 'charge', request: 'request');
    }

    public function testRejectsNonLowercaseMethod(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Challenge method must be lowercase ASCII');

        new Challenge(id: 'id', realm: 'api', method: 'Solana', intent: 'charge', request: 'request');
    }

    public function testChallengeEchoPreservesWireFields(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);
        $echo = $challenge->toEcho()->toArray();

        self::assertSame($challenge->id, $echo['id']);
        self::assertSame('solana', $echo['method']);
        self::assertSame('charge', $echo['intent']);
        self::assertSame($challenge->request, $echo['request']);
    }

    public function testChallengeEchoConvertsBackToChallenge(): void
    {
        $challenge = Challenge::withSecret(
            secretKey: 'secret',
            realm: 'api',
            method: 'solana',
            intent: 'charge',
            request: ['amount' => '1', 'currency' => 'USDC'],
            expires: '2099-01-01T00:00:00+00:00',
            digest: 'sha-256=:digest:',
            opaque: 'opaque',
        );

        $verified = $challenge->toEcho()->toChallenge();

        self::assertSame($challenge->id, $verified->id);
        self::assertSame($challenge->realm, $verified->realm);
        self::assertSame($challenge->method, $verified->method);
        self::assertSame($challenge->intent, $verified->intent);
        self::assertSame($challenge->request, $verified->request);
        self::assertSame($challenge->expires, $verified->expires);
        self::assertSame($challenge->digest, $verified->digest);
        self::assertSame($challenge->opaque, $verified->opaque);
        self::assertTrue($verified->verify('secret'));
    }

    public function testObjectRequestEchoIsJsonOrderIndependent(): void
    {
        $challenge = Challenge::withSecret(
            secretKey: 'secret',
            realm: 'api',
            method: 'solana',
            intent: 'charge',
            request: [
                'currency' => 'USDC',
                'amount' => '1000',
                'methodDetails' => [
                    'network' => 'localnet',
                    'feePayer' => true,
                ],
            ],
        );
        $echo = ChallengeEcho::fromArray([
            'id' => $challenge->id,
            'realm' => $challenge->realm,
            'method' => $challenge->method,
            'intent' => $challenge->intent,
            'request' => [
                'methodDetails' => [
                    'feePayer' => true,
                    'network' => 'localnet',
                ],
                'amount' => '1000',
                'currency' => 'USDC',
            ],
        ]);
        $verified = new Challenge(
            id: $echo->id,
            realm: $echo->realm,
            method: $echo->method,
            intent: $echo->intent,
            request: $echo->request,
        );

        self::assertTrue($verified->verify('secret'));
    }
}
