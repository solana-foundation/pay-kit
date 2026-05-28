<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PHPUnit\Framework\TestCase;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Protocols\Mpp\Server\ChargeServer;
use PayKit\Protocols\Mpp\Server\ChargeSettlement;
use PayKit\Protocols\Mpp\Server\PaymentRequiredResponse;
use PayKit\Protocols\Mpp\Server\PaymentVerifier;
use PayKit\Protocols\Mpp\Server\SolanaChargeHandler;
use PayKit\Protocols\Mpp\Server\TransactionPayloadVerifier;
use PayKit\Protocols\Mpp\Server\VerificationResult;
use PayKit\Store\FileStore;
use PayKit\Store\Store;
use SolanaPhpSdk\Util\Base58;
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
        self::assertSame('missing transaction or signature payload', $result->body['detail']);
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

    public function testRejectsSignatureReplayAfterSuccessfulSettlement(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $this->minimalLegacyTransactionBase64()],
        );

        $statusEntry = [
            'result' => [
                'value' => [[
                    'slot' => 1,
                    'confirmationStatus' => 'confirmed',
                    'err' => null,
                ]],
            ],
        ];
        $http = new FakeJsonRpcHttpClient([
            'sendTransaction' => [
                ['result' => 'ReplayProtectionFixtureSig'],
                ['result' => 'ReplayProtectionFixtureSig'],
            ],
            'getSignatureStatuses' => [$statusEntry, $statusEntry],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            verifier: new AlwaysAcceptVerifier(),
        );

        $first = $handler->handle($credential->toAuthorizationHeader(), $request);
        self::assertInstanceOf(ChargeSettlement::class, $first);
        self::assertSame('ReplayProtectionFixtureSig', $first->signature);

        $second = $handler->handle($credential->toAuthorizationHeader(), $request);
        self::assertInstanceOf(PaymentRequiredResponse::class, $second);
        self::assertStringContainsString('already consumed', $second->body['detail']);
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

    // ── Push-mode (type=signature) ────────────────────────────────────────

    public function testReturnsChargeSettlementAfterSuccessfulPushSignatureVerification(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->pushChargeRequest();
        $challenge = $challenges->createChallenge($request);
        $signature = $this->validSignature();
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $signature],
        );

        $http = new FakeJsonRpcHttpClient([
            'getTransaction' => [[
                'result' => [
                    'slot' => 1,
                    'meta' => ['err' => null],
                    'transaction' => [$this->minimalLegacyTransactionBase64(), 'base64'],
                ],
            ]],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            transactionVerifier: new AlwaysAcceptTransactionPayloadVerifier(),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(ChargeSettlement::class, $result);
        self::assertSame(200, $result->status);
        self::assertSame($signature, $result->signature);
        self::assertSame($signature, $result->headers['x-payment-settlement-signature']);
        self::assertNotEmpty($result->headers['payment-receipt']);
    }

    public function testReturns402WhenPushCredentialUsedOnFeePayerRoute(): void
    {
        // B34: routes that advertise `methodDetails.feePayer = true` MUST
        // reject push (type=signature) credentials before any RPC call. A
        // push credential references an already-landed transaction whose
        // fee the client paid, defeating the server-funded charge. The
        // canonical reject message is shared with Rust, Ruby, Lua, Python.
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
            methodDetails: [
                'network' => 'localnet',
                'decimals' => 6,
                'feePayer' => true,
                'feePayerKey' => Keypair::generate()->getPublicKey()->toBase58(),
            ],
        );
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $this->validSignature()],
        );
        // Use a NullHttpClient: B34 must reject before any RPC call. If the
        // handler reached `getTransaction` the test would fail with
        // NullHttpClient's RuntimeException.
        $handler = $this->handler(
            challenges: $challenges,
            transactionVerifier: new AlwaysAcceptTransactionPayloadVerifier(),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(
            'Push-mode credentials are not allowed when the route uses a server-side fee payer',
            $result->body['detail'],
        );
    }

    public function testReturns402WhenPushSignatureIsReplayed(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->pushChargeRequest();
        $challenge = $challenges->createChallenge($request);
        $signature = $this->validSignature();
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $signature],
        );

        $http = new FakeJsonRpcHttpClient([
            'getTransaction' => [
                [
                    'result' => [
                        'slot' => 1,
                        'meta' => ['err' => null],
                        'transaction' => [$this->minimalLegacyTransactionBase64(), 'base64'],
                    ],
                ],
                [
                    'result' => [
                        'slot' => 2,
                        'meta' => ['err' => null],
                        'transaction' => [$this->minimalLegacyTransactionBase64(), 'base64'],
                    ],
                ],
            ],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            transactionVerifier: new AlwaysAcceptTransactionPayloadVerifier(),
        );

        $first = $handler->handle($credential->toAuthorizationHeader(), $request);
        $second = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(ChargeSettlement::class, $first);
        self::assertInstanceOf(PaymentRequiredResponse::class, $second);
        self::assertStringContainsString('already consumed', $second->body['detail']);
    }

    public function testReturns402WhenPushTransactionFetchReportsOnChainFailure(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->pushChargeRequest();
        $challenge = $challenges->createChallenge($request);
        $signature = $this->validSignature();
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $signature],
        );

        $http = new FakeJsonRpcHttpClient([
            'getTransaction' => [[
                'result' => [
                    'slot' => 1,
                    'meta' => ['err' => ['InstructionError' => [0, 'Custom']]],
                    'transaction' => [$this->minimalLegacyTransactionBase64(), 'base64'],
                ],
            ]],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            transactionVerifier: new AlwaysAcceptTransactionPayloadVerifier(),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertStringContainsString('Transaction ' . $signature . ' failed', $result->body['detail']);
    }

    public function testReturns402WhenPushTransactionFetchOmitsMetadata(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->pushChargeRequest();
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $this->validSignature()],
        );

        $http = new FakeJsonRpcHttpClient([
            'getTransaction' => [[
                'result' => [
                    'slot' => 1,
                    'transaction' => [$this->minimalLegacyTransactionBase64(), 'base64'],
                ],
            ]],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            transactionVerifier: new AlwaysAcceptTransactionPayloadVerifier(),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame('getTransaction response is missing transaction metadata', $result->body['detail']);
    }

    public function testReturns402WhenPushTransactionIsNotFound(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->pushChargeRequest();
        $challenge = $challenges->createChallenge($request);
        $signature = $this->validSignature();
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $signature],
        );

        $http = new FakeJsonRpcHttpClient([
            'getTransaction' => [['result' => null]],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            transactionVerifier: new AlwaysAcceptTransactionPayloadVerifier(),
            confirmationAttempts: 1,
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame("Timed out waiting for transaction $signature", $result->body['detail']);
    }

    public function testReturns402WhenPushTransactionResponseIsMalformed(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->pushChargeRequest();
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $this->validSignature()],
        );

        $http = new FakeJsonRpcHttpClient([
            'getTransaction' => [['result' => ['meta' => ['err' => null], 'transaction' => []]]],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            transactionVerifier: new AlwaysAcceptTransactionPayloadVerifier(),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame('getTransaction response is missing base64 transaction data', $result->body['detail']);
    }

    public function testReturns402WhenPushTransactionResponseIsNotObject(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->pushChargeRequest();
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $this->validSignature()],
        );

        $http = new FakeJsonRpcHttpClient([
            'getTransaction' => [['result' => 'not-an-object']],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            transactionVerifier: new AlwaysAcceptTransactionPayloadVerifier(),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame('Invalid getTransaction response', $result->body['detail']);
    }

    public function testReturns402WhenFetchedPushTransactionFailsStructuralVerification(): void
    {
        $challenges = new ChargeServer(secretKey: 'secret', realm: 'api');
        $request = $this->pushChargeRequest();
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $this->validSignature()],
        );

        $http = new FakeJsonRpcHttpClient([
            'getTransaction' => [[
                'result' => [
                    'slot' => 1,
                    'meta' => ['err' => null],
                    'transaction' => $this->minimalLegacyTransactionBase64(),
                ],
            ]],
        ]);
        $handler = $this->handler(
            challenges: $challenges,
            rpc: new RpcClient('http://test.invalid', $http),
            transactionVerifier: new RejectingTransactionPayloadVerifier('wrong recipient'),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame('wrong recipient', $result->body['detail']);
    }

    public function testFileStoreAtomicReplayProtection(): void
    {
        // Cross-instance check: two FileStore instances pointed at the same
        // directory must observe each other's writes. This is the property
        // FileStore promises for single-host multi-worker deployments.
        $directory = sys_get_temp_dir() . '/mpp-file-store-' . bin2hex(random_bytes(6));
        $first = new FileStore($directory);
        $second = new FileStore($directory);

        self::assertTrue($first->putIfAbsent('solana-charge:consumed:testsig', true));
        self::assertFalse($second->putIfAbsent('solana-charge:consumed:testsig', true));
        self::assertTrue($second->putIfAbsent('solana-charge:consumed:other', true));
    }

    private function pushChargeRequest(): ChargeRequest
    {
        // Push-mode routes MUST NOT advertise feePayer=true (B34). This
        // helper builds a charge request whose methodDetails omits the
        // feePayer flag so the push path is exercised end-to-end.
        return new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
            methodDetails: ['network' => 'localnet', 'decimals' => 6],
        );
    }

    private function validSignature(): string
    {
        return Base58::encode(str_repeat("\x01", 64));
    }

    private function handler(
        ?ChargeServer $challenges = null,
        ?Keypair $feePayer = null,
        string $network = 'mainnet-beta',
        ?RpcClient $rpc = null,
        ?PaymentVerifier $verifier = null,
        ?TransactionPayloadVerifier $transactionVerifier = null,
        ?Store $replayStore = null,
        int $confirmationAttempts = 40,
    ): SolanaChargeHandler {
        return new SolanaChargeHandler(
            challenges: $challenges ?? new ChargeServer(secretKey: 'secret', realm: 'api'),
            rpc: $rpc ?? new RpcClient('http://unused.invalid', new NullHttpClient()),
            feePayer: $feePayer,
            network: $network,
            verifier: $verifier,
            transactionVerifier: $transactionVerifier,
            confirmationAttempts: $confirmationAttempts,
            confirmationDelayMicros: 0,
            replayStore: $replayStore,
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

/**
 * TransactionPayloadVerifier stub that approves fetched push-mode transactions.
 * Lets handler tests exercise the push path without building a real-shaped
 * transaction the live SolanaChargeTransactionVerifier would accept.
 */
final class AlwaysAcceptTransactionPayloadVerifier implements TransactionPayloadVerifier
{
    public function verifyTransactionPayload(string $transactionBase64, ChargeRequest $request): VerificationResult
    {
        return VerificationResult::success(reference: '');
    }
}

/**
 * TransactionPayloadVerifier stub that rejects fetched push-mode transactions
 * with a fixed reason. Used to exercise the handler's failure path on
 * structurally invalid settled transactions.
 */
final class RejectingTransactionPayloadVerifier implements TransactionPayloadVerifier
{
    public function __construct(private readonly string $reason)
    {
    }

    public function verifyTransactionPayload(string $transactionBase64, ChargeRequest $request): VerificationResult
    {
        return VerificationResult::failure($this->reason);
    }
}
