<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\Mpp\Core;

use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Headers;
use PayKit\Protocols\Mpp\Core\Receipt;

final class HeadersTest extends TestCase
{
    public function testWwwAuthenticateRoundTrip(): void
    {
        $challenge = Challenge::withSecret(
            secretKey: 'secret',
            realm: 'api',
            method: 'solana',
            intent: 'charge',
            request: ['amount' => '1000', 'currency' => 'USDC'],
            expires: '2099-01-01T00:00:00+00:00',
            digest: 'sha-256=abc',
            opaque: 'opaque',
        );

        $parsed = Headers::parseWwwAuthenticate(Headers::formatWwwAuthenticate($challenge));

        self::assertSame($challenge->id, $parsed->id);
        self::assertSame($challenge->realm, $parsed->realm);
        self::assertSame($challenge->request, $parsed->request);
        self::assertSame($challenge->digest, $parsed->digest);
        self::assertTrue($parsed->verify('secret'));
    }

    public function testParsesPaymentChallengeFromMixedHeader(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);
        $header = 'Bearer realm="ignored", ' . Headers::formatWwwAuthenticate($challenge);

        self::assertSame($challenge->id, Headers::parseWwwAuthenticate($header)->id);
    }

    public function testParsesUnquotedAuthParams(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);
        $header = sprintf(
            'Payment id=%s, realm=api, method=solana, intent=charge, request=%s',
            $challenge->id,
            $challenge->request,
        );

        $parsed = Headers::parseWwwAuthenticate($header);

        self::assertSame($challenge->id, $parsed->id);
        self::assertSame('api', $parsed->realm);
    }

    public function testEscapesQuotedAuthParams(): void
    {
        $challenge = Challenge::withSecret(
            secretKey: 'secret',
            realm: 'api "quoted"',
            method: 'solana',
            intent: 'charge',
            request: ['amount' => '1', 'currency' => 'USDC'],
            opaque: 'opaque \\ value',
        );

        $parsed = Headers::parseWwwAuthenticate(Headers::formatWwwAuthenticate($challenge));

        self::assertSame('api "quoted"', $parsed->realm);
        self::assertSame('opaque \\ value', $parsed->opaque);
    }

    public function testRejectsInvalidChallengeHeader(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Expected Payment scheme');

        Headers::parseWwwAuthenticate('Bearer realm="api"');
    }

    public function testRejectsMissingChallengeFields(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing "request" field');

        Headers::parseWwwAuthenticate('Payment id="id", realm="api", method="solana", intent="charge"');
    }

    public function testSkipsTokenWithoutValueAndRejectsMissingRequired(): void
    {
        // A token with no `=` is not an auth-param: the canonical permissive
        // parser (and the rust spine) skip it rather than erroring, so a bare
        // `id` here is dropped and parsing fails on the now-missing required
        // `id` field instead of an "invalid auth parameter" error.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing "id" field');

        Headers::parseWwwAuthenticate('Payment id realm="api"');
    }

    public function testRejectsDuplicateAuthParams(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);
        $header = Headers::formatWwwAuthenticate($challenge) . ', method="solana"';

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Duplicate auth parameter');

        Headers::parseWwwAuthenticate($header);
    }

    public function testRejectsUnterminatedQuotedAuthParam(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unterminated quoted value');

        Headers::parseWwwAuthenticate('Payment id="id');
    }

    public function testRejectsDanglingQuotedEscape(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid quoted value');

        Headers::parseWwwAuthenticate('Payment id="id\\');
    }

    public function testRejectsCrlfInFormattedAuthParams(): void
    {
        $challenge = Challenge::withSecret(
            secretKey: 'secret',
            realm: "api\r\nx-injected: 1",
            method: 'solana',
            intent: 'charge',
            request: ['amount' => '1', 'currency' => 'USDC'],
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid header value');

        Headers::formatWwwAuthenticate($challenge);
    }

    public function testRejectsOversizedReceiptHeader(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Receipt exceeds maximum length');

        Headers::parseReceipt(str_repeat('a', 16 * 1024 + 1));
    }

    public function testRejectsInvalidReceiptJson(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid base64url value');

        Headers::parseReceipt('not-base64url!');
    }

    public function testParseWwwAuthenticateAllMultiChallenge(): void
    {
        $header = 'Payment id="a", realm="r1", method="solana", intent="charge", request="e30", '
                . 'Payment id="b", realm="r2", method="solana", intent="charge", request="e30"';

        $results = Headers::parseWwwAuthenticateAll($header);

        self::assertCount(2, $results);
        self::assertSame('a', $results[0]->id);
        self::assertSame('b', $results[1]->id);
    }

    public function testParseWwwAuthenticateAllPartialSuccess(): void
    {
        $header = 'Payment id="bad", realm="r", method="BAD", intent="charge", request="e30", '
                . 'Payment id="ok", realm="r", method="solana", intent="charge", request="e30"';

        $results = Headers::parseWwwAuthenticateAll($header);

        self::assertCount(1, $results);
        self::assertSame('ok', $results[0]->id);
    }

    public function testParseWwwAuthenticateAllIgnoresPaymentInsideQuotedValue(): void
    {
        $header = 'Payment id="a", realm="api, Payment realm", method="solana", intent="charge", request="e30", '
                . 'Payment id="b", realm="r2", method="solana", intent="charge", request="e30"';

        $results = Headers::parseWwwAuthenticateAll($header);

        self::assertCount(2, $results);
        self::assertSame('api, Payment realm', $results[0]->realm);
        self::assertSame('b', $results[1]->id);
    }

    public function testParseWwwAuthenticateAllSchemeBoundarySinglePayment(): void
    {
        $header = 'Payment id="a", realm="r", method="solana", intent="charge", request="e30"';
        $results = Headers::parseWwwAuthenticateAll($header);
        self::assertCount(1, $results);
        self::assertSame('a', $results[0]->id);
    }

    public function testParseWwwAuthenticateAllPaymentFollowedByBearer(): void
    {
        $header = 'Payment id="a", realm="r", method="solana", intent="charge", request="e30", '
                . 'Bearer realm="oauth"';
        $results = Headers::parseWwwAuthenticateAll($header);
        self::assertCount(1, $results);
        self::assertSame('a', $results[0]->id);
    }

    public function testParseWwwAuthenticateAllBearerFollowedByPayment(): void
    {
        $header = 'Bearer realm="oauth", '
                . 'Payment id="a", realm="r", method="solana", intent="charge", request="e30"';
        $results = Headers::parseWwwAuthenticateAll($header);
        self::assertCount(1, $results);
        self::assertSame('a', $results[0]->id);
    }

    public function testParseWwwAuthenticateAllMultiplePaymentSchemes(): void
    {
        $header = 'Payment id="a", realm="r", method="solana", intent="charge", request="e30", '
                . 'Payment id="b", realm="r", method="solana", intent="charge", request="e30"';
        $results = Headers::parseWwwAuthenticateAll($header);
        self::assertCount(2, $results);
        self::assertSame('a', $results[0]->id);
        self::assertSame('b', $results[1]->id);
    }

    public function testParseWwwAuthenticateAllInterleavedSchemes(): void
    {
        $header = 'Bearer realm="oauth", '
                . 'Payment id="a", realm="r", method="solana", intent="charge", request="e30", '
                . 'Basic realm="basic", '
                . 'Payment id="b", realm="r", method="solana", intent="charge", request="e30"';
        $results = Headers::parseWwwAuthenticateAll($header);
        self::assertCount(2, $results);
        self::assertSame('a', $results[0]->id);
        self::assertSame('b', $results[1]->id);
    }

    public function testReceiptHeaderRoundTrip(): void
    {
        $receipt = Receipt::success(
            method: 'solana',
            reference: 'reference',
            challengeId: 'challenge-id',
            externalId: 'order-001',
            now: new DateTimeImmutable('2026-05-19T00:00:00+00:00'),
        );

        $parsed = Headers::parseReceipt(Headers::formatReceipt($receipt));

        self::assertTrue($parsed->isSuccess());
        self::assertSame('solana', $parsed->method);
        self::assertSame('reference', $parsed->reference);
        self::assertSame('challenge-id', $parsed->challengeId);
        self::assertSame('order-001', $parsed->externalId);
    }

    public function testRejectsOversizedRequestParam(): void
    {
        // audit #9: the request param is base64url-decoded + JSON-parsed, so it
        // must be capped like the credential/receipt parsers (16 KiB).
        $oversized = str_repeat('A', 16 * 1024 + 1);
        $header = sprintf(
            'Payment id=x, realm=api, method=solana, intent=charge, request="%s"',
            $oversized,
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Challenge request parameter exceeds maximum length');
        Headers::parseWwwAuthenticate($header);
    }

    public function testAcceptsRequestParamAtMaxSize(): void
    {
        // Regression: an at-cap (well-formed) request param must not trip the
        // size gate. The encoded JSON of a real challenge is far below 16 KiB.
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);
        $parsed = Headers::parseWwwAuthenticate(Headers::formatWwwAuthenticate($challenge));
        self::assertSame($challenge->id, $parsed->id);
    }
}
