<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use PHPUnit\Framework\TestCase;
use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Credential;
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\ChargeSettlement;
use SolanaMpp\Server\PaymentRequiredResponse;
use SolanaMpp\Server\PaymentVerifier;
use SolanaMpp\Server\SolanaChargeHandler;
use SolanaMpp\Server\VerificationResult;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Rpc\Http\HttpClient;
use SolanaPhpSdk\Rpc\RpcClient;
use SolanaPhpSdk\Transaction\Message;
use SolanaPhpSdk\Transaction\Transaction;

final class SolanaChargeHandlerTest extends TestCase
{
    public function testReturns402WhenAuthorizationMissing(): void
    {
        $handler = $this->handler();

        $result = $handler->handle(null, $this->chargeRequest());

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(402, $result->status);
        self::assertArrayHasKey('www-authenticate', $result->headers);
        self::assertStringStartsWith('Payment ', $result->headers['www-authenticate']);
        self::assertSame('Payment is required.', $result->body['detail']);
    }

    public function testReturns402WhenAuthorizationIsMalformed(): void
    {
        $handler = $this->handler();

        $result = $handler->handle('Bearer not-a-payment-credential', $this->chargeRequest());

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(402, $result->status);
        self::assertSame('Expected Payment scheme', $result->body['detail']);
    }

    public function testReturns402WhenCredentialIsMissingTransaction(): void
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $server->createChallenge($request);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: []);
        $handler = $this->handler(challenges: $server);

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame('missing transaction payload', $result->body['detail']);
    }

    public function testReturns402WhenChallengeMismatchesExpectedRequest(): void
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
        self::assertSame('charge request mismatch', $result->body['detail']);
    }

    public function testReturnsChargeSettlementAfterSuccessfulBroadcastAndConfirmation(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $this->minimalLegacyTransactionBase64()],
        );

        $http = new FakeJsonRpcHttpClient([
            'sendTransaction' => [['result' => 'OnChainSignatureFixtureValue']],
            'getSignatureStatuses' => [[
                'result' => [
                    'value' => [[
                        'slot' => 1,
                        'confirmationStatus' => 'confirmed',
                        'err' => null,
                    ]],
                ],
            ]],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            verifier: new AlwaysAcceptVerifier(),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(ChargeSettlement::class, $result);
        self::assertSame(200, $result->status);
        self::assertSame('OnChainSignatureFixtureValue', $result->signature);
        self::assertSame(['ok' => true, 'paid' => true], $result->body);
        self::assertSame('OnChainSignatureFixtureValue', $result->headers['x-payment-settlement-signature']);
        self::assertNotEmpty($result->headers['payment-receipt']);
    }

    public function testReturns402WhenSurfpoolBlockhashOnNonLocalnet(): void
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
        self::assertStringContainsString('Surfpool localnet blockhash', $result->body['detail']);
        self::assertStringContainsString('devnet', $result->body['detail']);
    }

    public function testReturns402WhenBroadcastReportsOnChainFailure(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $this->minimalLegacyTransactionBase64()],
        );

        $http = new FakeJsonRpcHttpClient([
            'sendTransaction' => [['result' => 'BroadcastSig']],
            'getSignatureStatuses' => [[
                'result' => [
                    'value' => [[
                        'slot' => 1,
                        'confirmationStatus' => 'confirmed',
                        'err' => ['InstructionError' => [0, 'Custom']],
                    ]],
                ],
            ]],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            verifier: new AlwaysAcceptVerifier(),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertStringContainsString('Transaction BroadcastSig failed', $result->body['detail']);
    }

    public function testFeePayerPubkeyReflectsConfiguredKeypair(): void
    {
        $keypair = Keypair::generate();

        $handler = $this->handler(feePayer: $keypair);
        $without = $this->handler();

        self::assertSame($keypair->getPublicKey()->toBase58(), $handler->feePayerPubkey());
        self::assertNull($without->feePayerPubkey());
    }

    private function handler(
        ?ChargeServer $challenges = null,
        ?Keypair $feePayer = null,
        string $network = 'mainnet-beta',
        ?RpcClient $rpc = null,
        ?PaymentVerifier $verifier = null,
    ): SolanaChargeHandler {
        return new SolanaChargeHandler(
            challenges: $challenges ?? new ChargeServer(secretKey: 'secret', realm: 'api'),
            rpc: $rpc ?? new RpcClient('http://unused.invalid', new NullHttpClient()),
            feePayer: $feePayer,
            network: $network,
            verifier: $verifier,
            confirmationDelayMicros: 0,
        );
    }

    /**
     * Builds a signed legacy transaction whose 32-byte recentBlockhash
     * base58-encodes to the Surfpool prefix (`SURFNET…`), so the handler's
     * blockhash sanity check fires when run against a non-localnet network.
     */
    private function surfpoolSignedTransactionBase64(): string
    {
        // Base58 string with the Surfpool prefix; 32 raw bytes once decoded.
        $surfpoolBlockhashBytes = \SolanaPhpSdk\Util\Base58::decode(
            'SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx191cab2c',
        );
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

    private function minimalLegacyTransactionBase64(): string
    {
        // The handler re-serializes the transaction with `verifySignatures = true`
        // before broadcasting, so the fixture must carry a real signature in
        // the only required slot.
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

    private function chargeRequest(string $amount = '1000'): ChargeRequest
    {
        return new ChargeRequest(
            amount: $amount,
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
            methodDetails: ['network' => 'localnet', 'decimals' => 6],
        );
    }
}

/**
 * Fake HTTP transport that fails on any actual call. Suitable for tests where
 * the handler must return 402 before reaching the RPC.
 */
final class NullHttpClient implements HttpClient
{
    /**
     * @param array<string, mixed> $jsonBody
     * @param array<string, string> $headers
     * @return array{0: array<string, mixed>, 1: int}
     */
    public function postJson(string $url, array $jsonBody, array $headers = []): array
    {
        throw new \RuntimeException('NullHttpClient should not be called in these tests');
    }
}

/**
 * Fake HTTP transport that dispatches JSON-RPC POSTs by `method`, returning
 * canned responses provided per-method as a FIFO list.
 */
final class FakeJsonRpcHttpClient implements HttpClient
{
    /** @param array<string, array<int, array<string, mixed>>> $responses */
    public function __construct(private array $responses)
    {
    }

    /**
     * @param array<string, mixed> $jsonBody
     * @param array<string, string> $headers
     * @return array{0: array<string, mixed>, 1: int}
     */
    public function postJson(string $url, array $jsonBody, array $headers = []): array
    {
        $method = isset($jsonBody['method']) && is_string($jsonBody['method']) ? $jsonBody['method'] : '';
        if (!isset($this->responses[$method]) || $this->responses[$method] === []) {
            throw new \RuntimeException("FakeJsonRpcHttpClient has no canned response for: $method");
        }
        $next = array_shift($this->responses[$method]);
        return [array_merge(['jsonrpc' => '2.0', 'id' => $jsonBody['id'] ?? 1], $next), 200];
    }
}

/**
 * PaymentVerifier stub that approves every credential without inspecting it.
 * Lets handler tests exercise the settle/broadcast/confirm path without
 * building a transaction the real `SolanaChargeTransactionVerifier` would
 * accept.
 */
final class AlwaysAcceptVerifier implements PaymentVerifier
{
    public function verify(Credential $credential, Challenge $challenge): VerificationResult
    {
        return VerificationResult::success(reference: '');
    }
}
