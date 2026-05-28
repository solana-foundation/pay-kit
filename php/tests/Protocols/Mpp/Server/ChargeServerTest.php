<?php

declare(strict_types=1);

namespace PayKit\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\Protocols\Mpp\Core\Headers;
use PayKit\Protocols\Mpp\Core\Json;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Protocols\Mpp\Server\ChargeServer;
use PayKit\Protocols\Mpp\Server\PaymentVerifier;
use PayKit\Protocols\Mpp\Server\VerificationResult;

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
            new class () implements PaymentVerifier {
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
        self::assertInstanceOf(Challenge::class, $result->challenge);
        self::assertSame($challenge->id, $result->challenge->id);
        self::assertInstanceOf(Credential::class, $result->credential);
        self::assertSame('sig', $result->credential->payload['signature']);

        $receipt = Headers::parseReceipt($server->createReceiptHeader($result));
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

    public function testRejectsMalformedAuthorizationHeader(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');

        $result = $server->verifyAuthorizationHeader('Bearer invalid', $this->unusedVerifier());

        self::assertFalse($result->ok);
        self::assertSame('Expected Payment scheme', $result->reason);
    }

    public function testRejectsChallengeMethodMismatch(): void
    {
        $issuer = new ChargeServer(secretKey: 'secret', realm: 'api', method: 'card');
        $server = new ChargeServer(secretKey: 'secret', realm: 'api', method: 'solana');
        $challenge = $issuer->createChallenge(new ChargeRequest(amount: '1', currency: 'USD'));
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'card']);

        $result = $server->verifyAuthorizationHeader($credential->toAuthorizationHeader(), $this->unusedVerifier());

        self::assertFalse($result->ok);
        self::assertSame('challenge method or intent mismatch', $result->reason);
    }

    public function testRejectsInvalidChargeRequestEcho(): void
    {
        $request = 'not-json';
        $challenge = new Challenge(
            id: Challenge::computeId('secret', 'api', 'solana', 'charge', $request),
            realm: 'api',
            method: 'solana',
            intent: 'charge',
            request: $request,
        );
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = (new ChargeServer(secretKey: 'secret', realm: 'api'))->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            $this->unusedVerifier(),
        );

        self::assertFalse($result->ok);
        self::assertSame('Invalid JSON value', $result->reason);
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

    public function testRejectsExpectedAmountMismatch(): void
    {
        $this->assertExpectedRequestMismatch(
            challengeRequest: new ChargeRequest(amount: '500', currency: 'USDC', recipient: 'recipient'),
            expectedRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'recipient'),
        );
    }

    public function testRejectsExpectedCurrencyMismatch(): void
    {
        $this->assertExpectedRequestMismatch(
            challengeRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'recipient'),
            expectedRequest: new ChargeRequest(amount: '1000', currency: 'PYUSD', recipient: 'recipient'),
        );
    }

    public function testRejectsExpectedRecipientMismatch(): void
    {
        $this->assertExpectedRequestMismatch(
            challengeRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'recipient-a'),
            expectedRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'recipient-b'),
        );
    }

    public function testRejectsExpectedExternalIdMismatch(): void
    {
        $this->assertExpectedRequestMismatch(
            challengeRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'recipient', externalId: 'order-a'),
            expectedRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'recipient', externalId: 'order-b'),
        );
    }

    public function testRejectsExpectedMethodDetailsMismatchExceptRecentBlockhash(): void
    {
        $this->assertExpectedRequestMismatch(
            challengeRequest: new ChargeRequest(
                amount: '1000',
                currency: 'USDC',
                recipient: 'recipient',
                methodDetails: ['network' => 'localnet', 'decimals' => 6, 'recentBlockhash' => 'old'],
            ),
            expectedRequest: new ChargeRequest(
                amount: '1000',
                currency: 'USDC',
                recipient: 'recipient',
                methodDetails: ['network' => 'devnet', 'decimals' => 6, 'recentBlockhash' => 'new'],
            ),
        );
    }

    public function testAcceptsMatchingExpectedChargeRequest(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC', externalId: 'order-001');
        $challenge = $server->createChallenge($request);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            new class () implements PaymentVerifier {
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
            new class () implements PaymentVerifier {
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
            new class () implements PaymentVerifier {
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
            new class () implements PaymentVerifier {
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

    public function testVerifierExceptionsFailClosed(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC');
        $challenge = $server->createChallenge($request);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            new class () implements PaymentVerifier {
                public function verify(Credential $credential, Challenge $challenge): VerificationResult
                {
                    throw new RuntimeException('sdk parser failed');
                }
            },
            expectedRequest: $request,
        );

        self::assertFalse($result->ok);
        self::assertSame('payment verification failed', $result->reason);
    }

    public function testRejectsReceiptForFailedVerification(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot create a receipt for a failed verification');

        $server->createReceiptHeader(VerificationResult::failure('missing transaction payload'));
    }

    public function testRejectsReceiptForResultWithoutChallenge(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Verification result is missing a challenge');

        $server->createReceiptHeader(VerificationResult::success(reference: 'tx-signature'));
    }

    public function testCreatesReceiptHeaderForExternalSettlementReference(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $challenge = $server->createChallenge(new ChargeRequest(amount: '1000', currency: 'USDC'));

        $receipt = Headers::parseReceipt($server->createReceiptHeaderForReference(
            $challenge,
            'settled-signature',
            externalId: 'order-1',
        ));

        self::assertSame('settled-signature', $receipt->reference);
        self::assertSame($challenge->id, $receipt->challengeId);
        self::assertSame('order-1', $receipt->externalId);
    }

    public function testRejectsReceiptWithoutSettlementReference(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $challenge = $server->createChallenge(new ChargeRequest(amount: '1000', currency: 'USDC'));
        $credential = new Credential(challenge: $challenge->toEcho(), payload: []);
        $result = VerificationResult::success(reference: '')->withVerified($challenge, $credential);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot create a receipt without a settlement reference');

        $server->createReceiptHeader($result);
    }

    public function testPaymentRequiredResponseShape(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC');

        $response = $server->paymentRequiredResponse($request);

        self::assertSame(402, $response->status);
        self::assertSame('no-store', $response->headers['cache-control']);
        self::assertSame('application/problem+json', $response->headers['content-type']);
        self::assertStringStartsWith('Payment ', $response->headers['www-authenticate']);
        self::assertSame('Payment is required.', $response->body['detail']);
        self::assertSame(402, $response->body['status']);
        self::assertSame('Payment Required', $response->body['title']);
        self::assertSame('https://paymentauth.org/problems/payment-required', $response->body['type']);
    }

    public function testPaymentRequiredResponseUsesCustomReason(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC');

        $response = $server->paymentRequiredResponse($request, 'charge request mismatch');

        self::assertSame('charge request mismatch', $response->body['detail']);
    }

    public function testBlockhashProviderInjectsRecentBlockhashIntoChallenge(): void
    {
        $server = new ChargeServer(
            secretKey: 'secret',
            realm: 'api',
            blockhashProvider: fn (): string => 'BlockhashFromRpc111111111111111111111111111',
        );
        $request = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            methodDetails: ['network' => 'localnet'],
        );

        $methodDetails = $this->decodedMethodDetails($server->createChallenge($request));

        self::assertSame('BlockhashFromRpc111111111111111111111111111', $methodDetails['recentBlockhash']);
        self::assertSame('localnet', $methodDetails['network']);
    }

    public function testBlockhashProviderDoesNotOverrideExistingValue(): void
    {
        $server = new ChargeServer(
            secretKey: 'secret',
            realm: 'api',
            blockhashProvider: fn (): string => 'FromRpc11111111111111111111111111111111111',
        );
        $request = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            methodDetails: ['network' => 'localnet', 'recentBlockhash' => 'CallerProvided111111111111111111111111111111'],
        );

        $methodDetails = $this->decodedMethodDetails($server->createChallenge($request));

        self::assertSame('CallerProvided111111111111111111111111111111', $methodDetails['recentBlockhash']);
    }

    public function testBlockhashProviderFailureIsBestEffort(): void
    {
        $server = new ChargeServer(
            secretKey: 'secret',
            realm: 'api',
            blockhashProvider: function (): string {
                throw new RuntimeException('rpc unreachable');
            },
        );
        $request = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            methodDetails: ['network' => 'localnet'],
        );

        $methodDetails = $this->decodedMethodDetails($server->createChallenge($request));

        self::assertArrayNotHasKey('recentBlockhash', $methodDetails);
        self::assertSame('localnet', $methodDetails['network']);
    }

    /** @return array<string, mixed> */
    private function decodedMethodDetails(Challenge $challenge): array
    {
        $details = $challenge->decodeRequest()['methodDetails'] ?? [];
        self::assertIsArray($details);
        return Json::object($details, 'methodDetails');
    }

    private function unusedVerifier(): PaymentVerifier
    {
        return new class () implements PaymentVerifier {
            public function verify(Credential $credential, Challenge $challenge): VerificationResult
            {
                TestCase::fail('verifier should not be called');
            }
        };
    }

    private function assertExpectedRequestMismatch(ChargeRequest $challengeRequest, ChargeRequest $expectedRequest): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $challenge = $server->createChallenge($challengeRequest);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            $this->unusedVerifier(),
            expectedRequest: $expectedRequest,
        );

        self::assertFalse($result->ok);
        self::assertSame('charge request mismatch', $result->reason);
    }
}
