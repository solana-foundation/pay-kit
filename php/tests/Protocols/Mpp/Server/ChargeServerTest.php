<?php

declare(strict_types=1);

namespace PayKit\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\Protocols\Mpp\Core\Headers;
use PayKit\PayCore\Wire\Json;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Protocols\Mpp\Server\ChargeServer;
use PayKit\Protocols\Mpp\Server\PaymentVerifier;
use PayKit\Protocols\Mpp\Server\VerificationResult;
use SolanaPhpSdk\Keypair\PublicKey;

final class ChargeServerTest extends TestCase
{
    private const SECRET = 'test-secret-0123456789abcdef-0123456789';
    private const RECIPIENT = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';
    private const SPLIT_RECIPIENT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';

    // audit #24 — secret key strength
    public function testConstructorRejectsShortSecretKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ChargeServer(secretKey: 'short', realm: 'api');
    }

    public function testConstructorAcceptsSecretKeyAtMinimumLength(): void
    {
        $secret = str_repeat('a', 32);
        $server = new ChargeServer(secretKey: $secret, realm: 'api');
        $challenge = $server->createChallenge(
            new ChargeRequest(amount: '1', currency: 'USDC', recipient: self::RECIPIENT),
        );
        self::assertTrue($challenge->verify($secret));
    }

    // audit #19 — issuance request validation
    public function testCreateChallengeRejectsMissingRecipient(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('recipient is required');
        $server->createChallenge(new ChargeRequest(amount: '1000', currency: 'USDC'));
    }

    public function testCreateChallengeRejectsNonPubkeyRecipient(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('recipient must be a valid Solana pubkey');
        $server->createChallenge(new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'not-a-pubkey'));
    }

    public function testCreateChallengeRejectsMismatchedPinnedCurrency(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api', pinnedCurrency: 'USDC');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('currency does not match server configuration');
        $server->createChallenge(new ChargeRequest(amount: '1000', currency: 'USDT', recipient: self::RECIPIENT));
    }

    public function testCreateChallengeRejectsMismatchedPinnedRecipient(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api', pinnedRecipient: self::RECIPIENT);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('recipient does not match server configuration');
        $server->createChallenge(new ChargeRequest(amount: '1000', currency: 'USDC', recipient: self::SPLIT_RECIPIENT));
    }

    public function testCreateChallengeRejectsMismatchedPinnedNetwork(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api', pinnedNetwork: 'localnet');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('network does not match server configuration');
        $server->createChallenge(new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['network' => 'mainnet'],
        ));
    }

    public function testCreateChallengeRejectsMismatchedPinnedDecimals(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api', pinnedDecimals: 6);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('decimals does not match server configuration');
        $server->createChallenge(new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['decimals' => 9],
        ));
    }

    public function testCreateChallengeAcceptsMatchingPinnedDecimals(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api', pinnedDecimals: 6);
        $challenge = $server->createChallenge(new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['decimals' => 6],
        ));
        self::assertTrue($challenge->verify(self::SECRET));
    }

    // audit #21 — split validation at issuance
    public function testCreateChallengeRejectsTooManySplits(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $splits = [];
        for ($i = 0; $i < 9; $i++) {
            // Distinct recipients so the count cap (not dedup) is what fires.
            $splits[] = ['recipient' => self::distinctPubkey($i), 'amount' => '1'];
        }
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('too many splits');
        $server->createChallenge(new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['splits' => $splits],
        ));
    }

    public function testCreateChallengeRejectsNonPubkeySplitRecipient(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('split recipient must be a valid Solana pubkey');
        $server->createChallenge(new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['splits' => [['recipient' => 'bogus', 'amount' => '100']]],
        ));
    }

    public function testCreateChallengeRejectsZeroSplitAmount(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('split amount must be a positive base-unit integer');
        $server->createChallenge(new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['splits' => [['recipient' => self::SPLIT_RECIPIENT, 'amount' => '0']]],
        ));
    }

    public function testCreateChallengeRejectsDuplicateSplitRecipient(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('duplicate split recipient');
        $server->createChallenge(new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['splits' => [
                ['recipient' => self::SPLIT_RECIPIENT, 'amount' => '100'],
                ['recipient' => self::SPLIT_RECIPIENT, 'amount' => '200'],
            ]],
        ));
    }

    public function testCreateChallengeRejectsSplitSumExceedingAmount(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('split amounts exceed total amount');
        $server->createChallenge(new ChargeRequest(
            amount: '100',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['splits' => [['recipient' => self::SPLIT_RECIPIENT, 'amount' => '200']]],
        ));
    }

    public function testCreateChallengeAcceptsWellFormedSplits(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $challenge = $server->createChallenge(new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['splits' => [['recipient' => self::SPLIT_RECIPIENT, 'amount' => '250']]],
        ));
        self::assertTrue($challenge->verify(self::SECRET));
    }

    // audit #38 — primary recipient in splits + ataCreationRequired
    public function testCreateChallengeRejectsPrimaryRecipientSplitWithAtaCreation(): void
    {
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('primary recipient cannot appear in splits with ataCreationRequired=true');
        $server->createChallenge(new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['splits' => [[
                'recipient' => self::RECIPIENT,
                'amount' => '250',
                'ataCreationRequired' => true,
            ]]],
        ));
    }

    public function testCreateChallengeAllowsPrimaryRecipientSplitWithoutAtaCreation(): void
    {
        // The legitimate use the strict ban would over-block: primary recipient
        // taking a split, with no fee-sponsored ATA creation.
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $challenge = $server->createChallenge(new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: self::RECIPIENT,
            methodDetails: ['splits' => [['recipient' => self::RECIPIENT, 'amount' => '250']]],
        ));
        self::assertTrue($challenge->verify(self::SECRET));
    }

    private static function distinctPubkey(int $seed): string
    {
        return (new PublicKey(str_repeat(chr(($seed % 254) + 1), 32)))->toBase58();
    }

    public function testCreatesChallengeHeaderAndVerifiesCredential(): void
    {
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY', externalId: 'order-001');
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
        $issuer = new ChargeServer(secretKey: 'issuer-secret-0123456789abcdef-012345', realm: 'api');
        $server = new ChargeServer(secretKey: 'server-secret-0123456789abcdef-012345', realm: 'api');
        $challenge = $issuer->createChallenge(new ChargeRequest(amount: '1', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'));
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
        $issuer = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'issuer-api');
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'server-api');
        $challenge = $issuer->createChallenge(new ChargeRequest(amount: '1', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'));
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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $challenge = $server->createChallenge(
            new ChargeRequest(amount: '1', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'),
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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');

        $result = $server->verifyAuthorizationHeader('Bearer invalid', $this->unusedVerifier());

        self::assertFalse($result->ok);
        self::assertSame('Expected Payment scheme', $result->reason);
    }

    public function testRejectsChallengeMethodMismatch(): void
    {
        $issuer = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api', method: 'card');
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api', method: 'solana');
        $challenge = $issuer->createChallenge(new ChargeRequest(amount: '1', currency: 'USD', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'));
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'card']);

        $result = $server->verifyAuthorizationHeader($credential->toAuthorizationHeader(), $this->unusedVerifier());

        self::assertFalse($result->ok);
        self::assertSame('challenge method or intent mismatch', $result->reason);
    }

    public function testRejectsInvalidChargeRequestEcho(): void
    {
        $request = 'not-json';
        $challenge = new Challenge(
            id: Challenge::computeId('test-secret-0123456789abcdef-0123456789', 'api', 'solana', 'charge', $request),
            realm: 'api',
            method: 'solana',
            intent: 'charge',
            request: $request,
        );
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = (new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api'))->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            $this->unusedVerifier(),
        );

        self::assertFalse($result->ok);
        self::assertSame('Invalid JSON value', $result->reason);
    }

    public function testRejectsCrossRouteChargeRequestReplay(): void
    {
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $cheapRequest = new ChargeRequest(amount: '500', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY', externalId: 'cheap');
        $expensiveRequest = new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY', externalId: 'expensive');
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
            challengeRequest: new ChargeRequest(amount: '500', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'),
            expectedRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'),
        );
    }

    public function testRejectsExpectedCurrencyMismatch(): void
    {
        $this->assertExpectedRequestMismatch(
            challengeRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'),
            expectedRequest: new ChargeRequest(amount: '1000', currency: 'PYUSD', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'),
        );
    }

    public function testRejectsExpectedRecipientMismatch(): void
    {
        $this->assertExpectedRequestMismatch(
            challengeRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'),
            expectedRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'),
        );
    }

    public function testRejectsExpectedExternalIdMismatch(): void
    {
        $this->assertExpectedRequestMismatch(
            challengeRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY', externalId: 'order-a'),
            expectedRequest: new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY', externalId: 'order-b'),
        );
    }

    public function testRejectsExpectedMethodDetailsMismatchExceptRecentBlockhash(): void
    {
        $this->assertExpectedRequestMismatch(
            challengeRequest: new ChargeRequest(
                amount: '1000',
                currency: 'USDC',
                recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
                methodDetails: ['network' => 'localnet', 'decimals' => 6, 'recentBlockhash' => 'old'],
            ),
            expectedRequest: new ChargeRequest(
                amount: '1000',
                currency: 'USDC',
                recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
                methodDetails: ['network' => 'devnet', 'decimals' => 6, 'recentBlockhash' => 'new'],
            ),
        );
    }

    public function testAcceptsMatchingExpectedChargeRequest(): void
    {
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY', externalId: 'order-001');
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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $challengeRequest = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
            methodDetails: [
                'network' => 'localnet',
                'recentBlockhash' => 'old-blockhash',
            ],
        );
        $expectedRequest = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $challengeRequest = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
            methodDetails: [
                'network' => 'localnet',
                'feePayer' => true,
            ],
        );
        $expectedRequest = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY');
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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY');
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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot create a receipt for a failed verification');

        $server->createReceiptHeader(VerificationResult::failure('missing transaction payload'));
    }

    public function testRejectsReceiptForResultWithoutChallenge(): void
    {
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Verification result is missing a challenge');

        $server->createReceiptHeader(VerificationResult::success(reference: 'tx-signature'));
    }

    public function testCreatesReceiptHeaderForExternalSettlementReference(): void
    {
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $challenge = $server->createChallenge(new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'));

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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $challenge = $server->createChallenge(new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'));
        $credential = new Credential(challenge: $challenge->toEcho(), payload: []);
        $result = VerificationResult::success(reference: '')->withVerified($challenge, $credential);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot create a receipt without a settlement reference');

        $server->createReceiptHeader($result);
    }

    public function testPaymentRequiredResponseShape(): void
    {
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY');

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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY');

        $response = $server->paymentRequiredResponse($request, 'charge request mismatch');

        self::assertSame('charge request mismatch', $response->body['detail']);
    }

    public function testBlockhashProviderInjectsRecentBlockhashIntoChallenge(): void
    {
        $server = new ChargeServer(
            secretKey: 'test-secret-0123456789abcdef-0123456789',
            realm: 'api',
            blockhashProvider: fn (): string => 'BlockhashFromRpc111111111111111111111111111',
        );
        $request = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
            methodDetails: ['network' => 'localnet'],
        );

        $methodDetails = $this->decodedMethodDetails($server->createChallenge($request));

        self::assertSame('BlockhashFromRpc111111111111111111111111111', $methodDetails['recentBlockhash']);
        self::assertSame('localnet', $methodDetails['network']);
    }

    public function testBlockhashProviderDoesNotOverrideExistingValue(): void
    {
        $server = new ChargeServer(
            secretKey: 'test-secret-0123456789abcdef-0123456789',
            realm: 'api',
            blockhashProvider: fn (): string => 'FromRpc11111111111111111111111111111111111',
        );
        $request = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
            methodDetails: ['network' => 'localnet', 'recentBlockhash' => 'CallerProvided111111111111111111111111111111'],
        );

        $methodDetails = $this->decodedMethodDetails($server->createChallenge($request));

        self::assertSame('CallerProvided111111111111111111111111111111', $methodDetails['recentBlockhash']);
    }

    public function testBlockhashProviderFailureIsBestEffort(): void
    {
        $server = new ChargeServer(
            secretKey: 'test-secret-0123456789abcdef-0123456789',
            realm: 'api',
            blockhashProvider: function (): string {
                throw new RuntimeException('rpc unreachable');
            },
        );
        $request = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
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

    public function testPinnedCurrencyRejectsCredentialWithDifferentCurrency(): void
    {
        // Tier-2 pinned-field backstop. A server pinned to USDC must reject a
        // credential claiming a different currency even when the caller does
        // not pass an expectedRequest, mirroring Rust verify_pinned_fields
        // (rust/crates/mpp/src/server/charge.rs:457-468), which runs
        // unconditionally on every credential.
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api', pinnedCurrency: 'USDC');
        // Issue from a non-pinned server (same secret/realm) so the off-currency
        // challenge can exist; the pinned server then rejects it at verify time.
        $issuer = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $challenge = $issuer->createChallenge(new ChargeRequest(amount: '1000', currency: 'USDT', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'));
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            $this->unusedVerifier(),
        );

        self::assertFalse($result->ok);
        self::assertSame('charge request mismatch', $result->reason);
    }

    public function testPinnedRecipientRejectsCredentialWithDifferentRecipient(): void
    {
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api', pinnedRecipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY');
        // Issue from a non-pinned server so the off-recipient challenge can
        // exist; the pinned server rejects it at verify time.
        $issuer = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $challenge = $issuer->createChallenge(
            new ChargeRequest(amount: '1000', currency: 'USDC', recipient: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'),
        );
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            $this->unusedVerifier(),
        );

        self::assertFalse($result->ok);
        self::assertSame('charge request mismatch', $result->reason);
    }

    public function testPinnedFieldsAcceptMatchingCredential(): void
    {
        // Happy-path guard: a credential whose currency and recipient match the
        // pinned configuration passes the backstop and reaches the verifier.
        $server = new ChargeServer(
            secretKey: 'test-secret-0123456789abcdef-0123456789',
            realm: 'api',
            pinnedCurrency: 'USDC',
            pinnedRecipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
        );
        $challenge = $server->createChallenge(
            new ChargeRequest(amount: '1000', currency: 'USDC', recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'),
        );
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $result = $server->verifyAuthorizationHeader(
            $credential->toAuthorizationHeader(),
            new class () implements PaymentVerifier {
                public function verify(Credential $credential, Challenge $challenge): VerificationResult
                {
                    return VerificationResult::success(reference: 'tx-signature');
                }
            },
        );

        self::assertTrue($result->ok, $result->reason);
        self::assertSame('tx-signature', $result->reference);
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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
