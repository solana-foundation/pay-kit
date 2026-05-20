<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Credential;
use SolanaMpp\Core\Headers;
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\PaymentVerifier;
use SolanaMpp\Server\VerificationResult;

final class ChargeServerTest extends TestCase
{
    public function testCreatesChallengeHeaderAndVerifiesCredential(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC', externalId: 'order-001');
        $challenge = Headers::parseWwwAuthenticate($server->createChallengeHeader($request));
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => 'sig'],
        );

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            new class implements PaymentVerifier {
                public function verify(Credential $credential, Challenge $challenge): VerificationResult
                {
                    TestCase::assertSame('sig', $credential->payload['signature']);
                    TestCase::assertSame('charge', $challenge->intent);

                    return VerificationResult::success(reference: 'tx-signature', externalId: 'order-001');
                }
            },
        );

        self::assertTrue($result->ok);
        self::assertSame('tx-signature', $result->reference);
        $receipt = Headers::parseReceipt($server->createReceiptHeader($challenge, $result));
        self::assertSame($challenge->id, $receipt->challengeId);
        self::assertSame('order-001', $receipt->externalId);
    }

    public function testRejectsCredentialsForWrongSecret(): void
    {
        $issuer = new ChargeServer(secretKey: 'issuer-secret', realm: 'api');
        $server = new ChargeServer(secretKey: 'server-secret', realm: 'api');
        $challenge = $issuer->createChallenge(new ChargeRequest(amount: '1', currency: 'USDC'));
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            $this->unusedVerifier(),
        );

        self::assertFalse($result->ok);
        self::assertSame('challenge verification failed', $result->reason);
    }

    public function testRejectsCredentialsForWrongRealm(): void
    {
        $issuer = new ChargeServer(secretKey: 'secret', realm: 'issuer-api');
        $server = new ChargeServer(secretKey: 'secret', realm: 'server-api');
        $challenge = $issuer->createChallenge(new ChargeRequest(amount: '1', currency: 'USDC'));
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            $this->unusedVerifier(),
        );

        self::assertFalse($result->ok);
        self::assertSame('challenge realm mismatch', $result->reason);
    }

    public function testRejectsExpiredChallenge(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $challenge = $server->createChallenge(
            new ChargeRequest(amount: '1', currency: 'USDC'),
            expires: '2026-01-01T00:00:00+00:00',
        );
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            $this->unusedVerifier(),
            new DateTimeImmutable('2026-05-19T00:00:00+00:00'),
        );

        self::assertFalse($result->ok);
        self::assertSame('challenge expired', $result->reason);
    }

    public function testRejectsCrossRouteChargeRequestReplay(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $cheapRequest = new ChargeRequest(amount: '500', currency: 'USDC', externalId: 'cheap');
        $expensiveRequest = new ChargeRequest(amount: '1000', currency: 'USDC', externalId: 'expensive');
        $challenge = $server->createChallenge($cheapRequest);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            $this->unusedVerifier(),
            expectedRequest: $expensiveRequest,
        );

        self::assertFalse($result->ok);
        self::assertSame('charge request mismatch', $result->reason);
    }

    public function testAcceptsMatchingExpectedChargeRequest(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC', externalId: 'order-001');
        $challenge = $server->createChallenge($request);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            new class implements PaymentVerifier {
                public function verify(Credential $credential, Challenge $challenge): VerificationResult
                {
                    return VerificationResult::success(reference: 'tx-signature', externalId: 'order-001');
                }
            },
            expectedRequest: $request,
        );

        self::assertTrue($result->ok);
        self::assertSame('tx-signature', $result->reference);
    }

    public function testExpectedChargeRequestIgnoresVolatileRecentBlockhash(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $challengeRequest = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            methodDetails: [
                'network' => 'localnet',
                'recentBlockhash' => 'old-blockhash',
            ],
        );
        $expectedRequest = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            methodDetails: [
                'network' => 'localnet',
                'recentBlockhash' => 'new-blockhash',
            ],
        );
        $challenge = $server->createChallenge($challengeRequest);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            new class implements PaymentVerifier {
                public function verify(Credential $credential, Challenge $challenge): VerificationResult
                {
                    return VerificationResult::success(reference: 'tx-signature');
                }
            },
            expectedRequest: $expectedRequest,
        );

        self::assertTrue($result->ok);
    }

    public function testExpectedChargeRequestComparisonIsJsonOrderIndependent(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $challengeRequest = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            methodDetails: [
                'network' => 'localnet',
                'feePayer' => true,
            ],
        );
        $expectedRequest = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            methodDetails: [
                'feePayer' => true,
                'network' => 'localnet',
            ],
        );
        $challenge = $server->createChallenge($challengeRequest);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            new class implements PaymentVerifier {
                public function verify(Credential $credential, Challenge $challenge): VerificationResult
                {
                    return VerificationResult::success(reference: 'tx-signature');
                }
            },
            expectedRequest: $expectedRequest,
        );

        self::assertTrue($result->ok);
    }

    public function testPropagatesVerifierFailure(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC');
        $challenge = $server->createChallenge($request);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            new class implements PaymentVerifier {
                public function verify(Credential $credential, Challenge $challenge): VerificationResult
                {
                    return VerificationResult::failure('missing transaction payload');
                }
            },
            expectedRequest: $request,
        );

        self::assertFalse($result->ok);
        self::assertSame('missing transaction payload', $result->reason);
    }

    private function unusedVerifier(): PaymentVerifier
    {
        return new class implements PaymentVerifier {
            public function verify(Credential $credential, Challenge $challenge): VerificationResult
            {
                TestCase::fail('verifier should not be called');
            }
        };
    }
}
