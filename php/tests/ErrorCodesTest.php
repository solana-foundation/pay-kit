<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use PHPUnit\Framework\TestCase;
use SolanaMpp\Core\Credential;
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\ErrorCodes;
use SolanaMpp\Server\MemoryReplayStore;
use SolanaMpp\Server\PaymentRequiredResponse;
use SolanaMpp\Server\SolanaChargeHandler;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Rpc\RpcClient;
use SolanaPhpSdk\Transaction\Message;
use SolanaPhpSdk\Transaction\Transaction;
use SolanaPhpSdk\Util\Base58;

/**
 * Regression coverage for the L6 canonical structured error codes emitted on
 * 402 Payment Required bodies. Every canonical code is exercised through a
 * realistic handler path so the cross-SDK contract stays in sync with
 * Python (PR #106), Ruby (PR #96), and Rust.
 */
final class ErrorCodesTest extends TestCase
{
    public function testFromReasonMapsKnownReasonsToCanonicalCodes(): void
    {
        self::assertSame(ErrorCodes::CHARGE_REQUEST_MISMATCH, ErrorCodes::fromReason('charge request mismatch'));
        self::assertSame(ErrorCodes::CHALLENGE_VERIFICATION_FAILED, ErrorCodes::fromReason('challenge verification failed'));
        self::assertSame(ErrorCodes::CHALLENGE_VERIFICATION_FAILED, ErrorCodes::fromReason('invalid payment credential'));
        self::assertSame(ErrorCodes::CHALLENGE_EXPIRED, ErrorCodes::fromReason('challenge expired'));
        self::assertSame(ErrorCodes::CHALLENGE_ROUTE_MISMATCH, ErrorCodes::fromReason('challenge method or intent mismatch'));
        self::assertSame(ErrorCodes::CHALLENGE_ROUTE_MISMATCH, ErrorCodes::fromReason('challenge realm mismatch'));
        self::assertSame(ErrorCodes::SIGNATURE_CONSUMED, ErrorCodes::fromReason('Transaction signature already consumed'));
        self::assertSame(ErrorCodes::WRONG_NETWORK, ErrorCodes::fromReason('Signed with a Surfpool localnet blockhash but the server expects devnet.'));
        self::assertSame(ErrorCodes::PAYMENT_INVALID, ErrorCodes::fromReason('anything else falls through'));
    }

    public function testAllReturnsTheSevenCanonicalCodes(): void
    {
        $codes = ErrorCodes::all();

        self::assertCount(7, $codes);
        self::assertSame(
            [
                'charge_request_mismatch',
                'challenge_route_mismatch',
                'challenge_verification_failed',
                'challenge_expired',
                'payment_invalid',
                'wrong_network',
                'signature_consumed',
            ],
            $codes,
        );
    }

    public function testBodyEmitsCodeAlphabeticallyBeforeOtherKeys(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');

        $response = $challenges->paymentRequiredResponse(
            $this->chargeRequest(),
            'Payment is required.',
            code: ErrorCodes::PAYMENT_INVALID,
        );

        $keys = array_keys($response->body);
        self::assertSame(['code', 'detail', 'status', 'title', 'type'], $keys);
        self::assertSame(ErrorCodes::PAYMENT_INVALID, $response->code);
        self::assertSame(ErrorCodes::PAYMENT_INVALID, $response->body['code']);
    }

    public function testChargeRequestMismatchCodeOnPinnedRequestDivergence(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $issuedFor = $this->chargeRequest(amount: '500');
        $challenge = $server->createChallenge($issuedFor);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => base64_encode('placeholder')],
        );
        $handler = $this->handler(challenges: $server);

        $result = $handler->handle($credential->toAuthorizationHeader(), $this->chargeRequest(amount: '1000'));

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(ErrorCodes::CHARGE_REQUEST_MISMATCH, $result->code);
        self::assertSame(ErrorCodes::CHARGE_REQUEST_MISMATCH, $result->body['code']);
    }

    public function testChallengeVerificationFailedCodeOnMalformedAuthHeader(): void
    {
        $handler = $this->handler();

        $result = $handler->handle('Bearer not-a-payment-credential', $this->chargeRequest());

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(ErrorCodes::CHALLENGE_VERIFICATION_FAILED, $result->code);
    }

    public function testChallengeVerificationFailedCodeOnRandomCredentialParseError(): void
    {
        // Trigger a credential-parse failure with a message the explicit
        // string mappings do not recognize. The auth-verification mapper
        // must still return challenge_verification_failed rather than
        // falling through to payment_invalid.
        $handler = $this->handler();

        $result = $handler->handle('Payment realm="api", id="!!!not-base64url!!!"', $this->chargeRequest());

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(ErrorCodes::CHALLENGE_VERIFICATION_FAILED, $result->code);
    }

    public function testPaymentInvalidCodeOnStructuralVerifierRejection(): void
    {
        // A credential whose payload decodes to a transaction that has no
        // matching transfer instruction. The default SolanaChargeTransactionVerifier
        // rejects with a structural error; the handler must tag this as
        // payment_invalid via VerificationResult::failure(code).
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $server->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $this->minimalLegacyTransactionBase64()],
        );

        // Default verifier (real structural decoder, no AlwaysAccept stub).
        $handler = $this->handler(challenges: $server);

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(ErrorCodes::PAYMENT_INVALID, $result->code);
    }

    public function testPaymentInvalidCodeOnMissingPayload(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $server->createChallenge($request);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: []);
        $handler = $this->handler(challenges: $server);

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(ErrorCodes::PAYMENT_INVALID, $result->code);
    }

    public function testWrongNetworkCodeOnSurfpoolBlockhashAgainstNonLocalnet(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $this->surfpoolSignedTransactionBase64()],
        );

        $handler = $this->handler(
            challenges: $challenges,
            verifier: new AlwaysAcceptVerifier(),
            network: 'devnet',
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(ErrorCodes::WRONG_NETWORK, $result->code);
    }

    public function testSignatureConsumedCodeOnPullReplay(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $this->minimalLegacyTransactionBase64()],
        );

        $http = new FakeJsonRpcHttpClient([
            'sendTransaction' => [
                ['result' => 'ReplaySigErrorCodeTest'],
                ['result' => 'ReplaySigErrorCodeTest'],
            ],
            'getSignatureStatuses' => [
                ['result' => ['value' => [['slot' => 1, 'confirmationStatus' => 'confirmed', 'err' => null]]]],
                ['result' => ['value' => [['slot' => 2, 'confirmationStatus' => 'confirmed', 'err' => null]]]],
            ],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            verifier: new AlwaysAcceptVerifier(),
        );

        $handler->handle($credential->toAuthorizationHeader(), $request);
        $second = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $second);
        self::assertSame(ErrorCodes::SIGNATURE_CONSUMED, $second->code);
    }

    public function testChallengeExpiredCodeOnPastExpires(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->chargeRequest();
        // Past timestamp so the credential is rejected as expired before the
        // structural verifier runs.
        $expired = '2000-01-01T00:00:00Z';
        $challenge = $server->createChallenge($request, expires: $expired);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => base64_encode('placeholder')],
        );
        $handler = $this->handler(challenges: $server);

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(ErrorCodes::CHALLENGE_EXPIRED, $result->code);
    }

    public function testChallengeRouteMismatchCodeOnRealmDivergence(): void
    {
        // Issue a challenge in one realm, then verify against a server
        // configured for a different realm: the verifier rejects with the
        // route mismatch class.
        $issuer = new ChargeServer(secretKey: 'secret', realm: 'realm-a');
        $request = $this->chargeRequest();
        $challenge = $issuer->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => base64_encode('placeholder')],
        );

        $verifierServer = new ChargeServer(secretKey: 'secret', realm: 'realm-b');
        $handler = $this->handler(challenges: $verifierServer);

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(ErrorCodes::CHALLENGE_ROUTE_MISMATCH, $result->code);
    }

    private function handler(
        ?ChargeServer $challenges = null,
        ?\SolanaMpp\Server\PaymentVerifier $verifier = null,
        ?RpcClient $rpc = null,
        string $network = 'mainnet-beta',
    ): SolanaChargeHandler {
        return new SolanaChargeHandler(
            challenges: $challenges ?? new ChargeServer(secretKey: 'secret', realm: 'api'),
            rpc: $rpc ?? new RpcClient('http://unused.invalid', new NullHttpClient()),
            replayStore: new MemoryReplayStore(),
            network: $network,
            verifier: $verifier,
            confirmationDelayMicros: 0,
        );
    }

    private function chargeRequest(string $amount = '1000'): ChargeRequest
    {
        return new ChargeRequest(
            amount: $amount,
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
            methodDetails: ['network' => 'localnet', 'decimals' => 6],
        );
    }

    private function minimalLegacyTransactionBase64(): string
    {
        $signer = Keypair::generate();
        $message = new Message(
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0,
            accountKeys: [$signer->getPublicKey()],
            recentBlockhash: str_repeat("\x00", 32),
            instructions: [],
        );
        $tx = new Transaction($message);
        $tx->partialSign($signer);
        return base64_encode($tx->serialize());
    }

    private function surfpoolSignedTransactionBase64(): string
    {
        $surfpoolBlockhashBytes = Base58::decode('SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx191cab2c');
        $signer = Keypair::generate();
        $message = new Message(
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0,
            accountKeys: [$signer->getPublicKey()],
            recentBlockhash: $surfpoolBlockhashBytes,
            instructions: [],
        );
        $tx = new Transaction($message);
        $tx->partialSign($signer);
        return base64_encode($tx->serialize());
    }
}
