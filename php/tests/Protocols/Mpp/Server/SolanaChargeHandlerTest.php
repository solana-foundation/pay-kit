<?php

declare(strict_types=1);

namespace PayKit\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Protocols\Mpp\Server\ChargeServer;
use PayKit\Protocols\Mpp\Server\ChargeSettlement;
use PayKit\Protocols\Mpp\Server\PaymentRequiredResponse;
use PayKit\Protocols\Mpp\Server\PaymentVerifier;
use PayKit\Protocols\Mpp\Server\SettlementPending;
use PayKit\Protocols\Mpp\Server\SolanaChargeHandler;
use PayKit\Protocols\Mpp\Server\TransactionPayloadVerifier;
use PayKit\Protocols\Mpp\Server\VerificationResult;
use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Operator;
use PayKit\PayCore\Network;
use PayKit\PayCore\Rpc\RpcGateway;
use PayKit\Protocols\X402\Adapter as X402Adapter;
use PayKit\Signer;
use PayKit\Store\FileStore;
use PayKit\Store\MemoryStore;
use PayKit\Tests\PayCore\Rpc\FakeRpcGateway;
use ReflectionMethod;
use PayKit\Store\Store;
use SolanaPhpSdk\Exception\RpcException;
use SolanaPhpSdk\Util\Base58;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Rpc\Http\HttpClient;
use SolanaPhpSdk\Rpc\RpcClient;
use SolanaPhpSdk\Transaction\Message;
use SolanaPhpSdk\Transaction\MessageV0;
use SolanaPhpSdk\Transaction\Transaction;
use SolanaPhpSdk\Transaction\VersionedTransaction;

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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
        $server = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $challenges->createChallenge($request);
        $transaction = $this->minimalV0TransactionBase64();
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        );

        $http = new FakeJsonRpcHttpClient([
            'sendTransaction' => [['result' => $this->signatureOf($transaction)]],
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
        self::assertSame($this->signatureOf($transaction), $result->signature);
        self::assertSame(['ok' => true, 'paid' => true], $result->body);
        self::assertSame($this->signatureOf($transaction), $result->headers['x-payment-settlement-signature']);
        self::assertNotEmpty($result->headers['payment-receipt']);
    }

    public function testRejectsSignatureReplayAfterSuccessfulSettlement(): void
    {
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $challenges->createChallenge($request);
        $transaction = $this->minimalV0TransactionBase64();
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
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
                ['result' => $this->signatureOf($transaction)],
                ['result' => $this->signatureOf($transaction)],
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
        self::assertSame($this->signatureOf($transaction), $first->signature);

        $second = $handler->handle($credential->toAuthorizationHeader(), $request);
        self::assertInstanceOf(PaymentRequiredResponse::class, $second);
        self::assertStringContainsString('already consumed', $second->body['detail']);
    }

    public function testReturns402WhenSurfpoolBlockhashOnNonLocalnet(): void
    {
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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

    public function testSettlesALegacyTransactionLikeVersionZero(): void
    {
        // A pre-cutover client's legacy (unprefixed) wire is co-signed and
        // broadcast in its original framing, exactly like a v0 one.
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $challenges->createChallenge($request);
        $transaction = $this->minimalLegacyTransactionBase64();
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        );

        $http = new FakeJsonRpcHttpClient([
            'sendTransaction' => [['result' => $this->signatureOf($transaction)]],
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
        self::assertSame($this->signatureOf($transaction), $result->signature);
    }

    public function testReturns402WhenBroadcastReportsOnChainFailure(): void
    {
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $challenge = $challenges->createChallenge($request);
        $transaction = $this->minimalV0TransactionBase64();
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        );

        $http = new FakeJsonRpcHttpClient([
            'sendTransaction' => [['result' => $this->signatureOf($transaction)]],
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
        self::assertStringContainsString('Transaction ' . $this->signatureOf($transaction) . ' failed', $result->body['detail']);
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
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
                    'transaction' => [$this->minimalV0TransactionBase64(), 'base64'],
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

    public function testReturns402WhenPushModeNotOptedIn(): void
    {
        // audit #5: with push mode off (the default), a signature credential is
        // rejected at verification and never reaches the settlement path.
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->pushChargeRequest();
        $challenge = $challenges->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $this->validSignature()],
        );

        $handler = $this->handler(challenges: $challenges, acceptPushMode: false);

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);

        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame(402, $result->status);
    }

    public function testReturns402WhenPushCredentialUsedOnFeePayerRoute(): void
    {
        // B34: routes that advertise `methodDetails.feePayer = true` MUST
        // reject push (type=signature) credentials before any RPC call. A
        // push credential references an already-landed transaction whose
        // fee the client paid, defeating the server-funded charge. The
        // canonical reject message is shared with Rust, Ruby, Lua, Python.
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
                        'transaction' => [$this->minimalV0TransactionBase64(), 'base64'],
                    ],
                ],
                [
                    'result' => [
                        'slot' => 2,
                        'meta' => ['err' => null],
                        'transaction' => [$this->minimalV0TransactionBase64(), 'base64'],
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
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
                    'transaction' => [$this->minimalV0TransactionBase64(), 'base64'],
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
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
                    'transaction' => [$this->minimalV0TransactionBase64(), 'base64'],
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
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
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
                    'transaction' => $this->minimalV0TransactionBase64(),
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

    // One on-chain payment authorizes one request across protocols: a
    // signature settled through MPP cannot be presented again as an x402
    // payment on a gate sharing the store, nor the other way round.
    public function testSignatureConsumedByOneProtocolIsRejectedByTheOther(): void
    {
        $store = new MemoryStore();
        $x402 = new X402Adapter(
            new Config(
                network: Network::SolanaDevnet,
                operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate(), feePayer: true),
                preflight: false,
            ),
            replayStore: $store,
            recentBlockhashProvider: fn () => null,
        );
        // x402 settles by claiming before confirmation and authorizing after.
        $x402Settle = function (string $signature) use ($x402): void {
            (new ReflectionMethod(X402Adapter::class, 'consumeSignature'))->invoke($x402, $signature);
            (new ReflectionMethod(X402Adapter::class, 'authorizeSignature'))->invoke($x402, $signature);
        };

        $settle = function (string $transaction) use ($store): PaymentRequiredResponse|ChargeSettlement|SettlementPending {
            $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
            $request = $this->chargeRequest();
            $credential = new Credential(
                challenge: $challenges->createChallenge($request)->toEcho(),
                payload: ['type' => 'transaction', 'transaction' => $transaction],
            );
            $handler = $this->handler(
                challenges: $challenges,
                verifier: new AlwaysAcceptVerifier(),
                replayStore: $store,
                rpcGateway: new FakeRpcGateway(signature: $this->signatureOf($transaction)),
            );
            return $handler->handle($credential->toAuthorizationHeader(), $request);
        };

        $mppPaid = $this->minimalV0TransactionBase64();
        self::assertInstanceOf(ChargeSettlement::class, $settle($mppPaid));
        try {
            $x402Settle($this->signatureOf($mppPaid));
            self::fail('x402 accepted a signature already settled through MPP');
        } catch (InvalidProofException $e) {
            self::assertStringContainsString('signature_consumed', $e->getMessage());
        }

        $x402Paid = $this->minimalV0TransactionBase64();
        $x402Settle($this->signatureOf($x402Paid));
        $replayed = $settle($x402Paid);
        self::assertInstanceOf(PaymentRequiredResponse::class, $replayed);
        self::assertStringContainsString('already consumed', $replayed->body['detail']);

        // An unrelated payment is still accepted by either protocol.
        self::assertInstanceOf(ChargeSettlement::class, $settle($this->minimalV0TransactionBase64()));
        $x402Settle('UnrelatedSignature');
    }

    // A send error other than a preflight rejection does not prove the node
    // dropped the transaction (the response may be lost after it was
    // accepted), so the charge stays pending under the locally derived
    // signature instead of answering a fresh challenge the client could pay
    // a second time. The identical retry reconciles it once it lands.
    public function testAmbiguousSendErrorIsPendingNotFailed(): void
    {
        $store = new MemoryStore();
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $transaction = $this->minimalV0TransactionBase64();
        $signature = $this->signatureOf($transaction);
        $authorization = (new Credential(
            challenge: $challenges->createChallenge($request)->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        ))->toAuthorizationHeader();
        $handler = fn (FakeRpcGateway $rpc) => $this->handler(
            challenges: $challenges,
            verifier: new AlwaysAcceptVerifier(),
            replayStore: $store,
            rpcGateway: $rpc,
        );

        $lost = new RpcException('JSON-RPC error: response lost after the node accepted it', 200, -32099);
        $pending = $handler(new FakeRpcGateway(signature: $signature, sendError: $lost))->handle($authorization, $request);
        self::assertInstanceOf(SettlementPending::class, $pending);
        self::assertSame(409, $pending->status);
        self::assertSame('1', $pending->headers['retry-after']);
        self::assertArrayNotHasKey('www-authenticate', $pending->headers);
        self::assertSame('https://paymentauth.org/problems/settlement-in-progress', $pending->body['type']);

        // The transaction did land: the identical retry gets the receipt.
        $settled = $handler(new FakeRpcGateway(signature: $signature))->handle($authorization, $request);
        self::assertInstanceOf(ChargeSettlement::class, $settled);
        self::assertSame($signature, $settled->signature);

        $replayed = $handler(new FakeRpcGateway(signature: $signature))->handle($authorization, $request);
        self::assertInstanceOf(PaymentRequiredResponse::class, $replayed);
        self::assertStringContainsString('already consumed', $replayed->body['detail']);
    }

    // A signature copied from any landed transaction must not name the
    // charge: the node refuses a forged one without a preflight result, so it
    // would be kept as possibly sent and reconciled on the status of the
    // transaction that owns it. It is refused before anything is claimed or
    // sent, for both wire framings.
    public function testForgedClientSignatureIsRefusedBeforeItIsClaimed(): void
    {
        foreach ([$this->minimalV0TransactionBase64(), $this->minimalLegacyTransactionBase64()] as $signed) {
            $store = new MemoryStore();
            $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
            $request = $this->chargeRequest();
            $wire = (string) base64_decode($signed, true);
            $forged = base64_encode(substr($wire, 0, 1) . str_repeat("\x07", 64) . substr($wire, 65));
            $authorization = (new Credential(
                challenge: $challenges->createChallenge($request)->toEcho(),
                payload: ['type' => 'transaction', 'transaction' => $forged],
            ))->toAuthorizationHeader();
            $landed = new FakeRpcGateway(
                signature: $this->signatureOf($forged),
                sendError: new RpcException('JSON-RPC error: Transaction signature verification failure', 200, -32003),
            );
            $handler = $this->handler(
                challenges: $challenges,
                verifier: new AlwaysAcceptVerifier(),
                replayStore: $store,
                rpcGateway: $landed,
            );
            for ($attempt = 0; $attempt < 2; $attempt += 1) {
                $result = $handler->handle($authorization, $request);
                self::assertInstanceOf(PaymentRequiredResponse::class, $result);
                self::assertStringContainsString('signature verification failed', $result->body['detail']);
            }
            self::assertSame([], $landed->sentTransactions);
            self::assertFalse($store->has('solana:consumed-signature:' . $this->signatureOf($forged)));
        }
    }

    // A broadcast whose response was lost stays pending. A retry after the
    // challenge expired must still reconcile it (the payment may have
    // landed), without ever broadcasting it again; an expired credential with
    // no pending charge of its own is refused as expired.
    public function testPendingChargeReconcilesAfterItsChallengeExpires(): void
    {
        $store = new MemoryStore();
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $later = new DateTimeImmutable('+1 hour');
        $credentialFor = fn (string $transaction, string $at = '+5 minutes') => (new Credential(
            challenge: $challenges->createChallenge($request, (new DateTimeImmutable($at))->format('Y-m-d\TH:i:s\Z'))->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        ))->toAuthorizationHeader();
        $handler = fn (FakeRpcGateway $rpc) => $this->handler(
            challenges: $challenges,
            verifier: new AlwaysAcceptVerifier(),
            replayStore: $store,
            confirmationAttempts: 1,
            rpcGateway: $rpc,
        );
        $transaction = $this->minimalV0TransactionBase64();
        $signature = $this->signatureOf($transaction);
        $authorization = $credentialFor($transaction);

        $lost = new RpcException('JSON-RPC error: response lost after the node accepted it', 200, -32099);
        self::assertInstanceOf(
            SettlementPending::class,
            $handler(new FakeRpcGateway(signature: $signature, sendError: $lost))->handle($authorization, $request),
        );

        // Expired, still no status: in progress, not expired.
        $unknown = new FakeRpcGateway(signature: $signature, statuses: [null]);
        self::assertInstanceOf(SettlementPending::class, $handler($unknown)->handle($authorization, $request, $later));
        // It landed: the same credential is granted once, never re-broadcast.
        $landed = new FakeRpcGateway(signature: $signature);
        $settled = $handler($landed)->handle($authorization, $request, $later);
        self::assertInstanceOf(ChargeSettlement::class, $settled);
        self::assertSame($signature, $settled->signature);
        self::assertSame([], $unknown->sentTransactions);
        self::assertSame([], $landed->sentTransactions);
        $replayed = $handler(new FakeRpcGateway(signature: $signature))->handle($authorization, $request, $later);
        self::assertInstanceOf(PaymentRequiredResponse::class, $replayed);

        // An expired credential never starts a payment.
        $fresh = $this->minimalV0TransactionBase64();
        $rpc = new FakeRpcGateway(signature: $this->signatureOf($fresh));
        $expired = $handler($rpc)->handle($credentialFor($fresh), $request, $later);
        self::assertInstanceOf(PaymentRequiredResponse::class, $expired);
        self::assertStringContainsString('expired', $expired->body['detail']);
        self::assertSame([], $rpc->sentTransactions);

        // Nor reconciles a pending charge another challenge left behind.
        $other = $this->minimalV0TransactionBase64();
        self::assertInstanceOf(
            SettlementPending::class,
            $handler(new FakeRpcGateway(signature: $this->signatureOf($other), sendError: $lost))->handle($credentialFor($other), $request),
        );
        $stolen = $handler(new FakeRpcGateway(signature: $this->signatureOf($other)))->handle($credentialFor($other, '+6 minutes'), $request, $later);
        self::assertInstanceOf(PaymentRequiredResponse::class, $stolen);
        self::assertStringContainsString('expired', $stolen->body['detail']);
    }

    // The claim and its challenge binding are written before anything is
    // sent: bound only after an ambiguous send, a store failure would strand
    // a payment that may have landed, with nothing for the retry to
    // reconcile. A failure there sends nothing.
    public function testPendingBindingIsWrittenBeforeSending(): void
    {
        $inner = new MemoryStore();
        $store = new class ($inner) implements Store {
            public bool $fail = true;
            public function __construct(private readonly Store $inner)
            {
            }
            public function putIfAbsent(string $key, mixed $value): bool
            {
                if ($this->fail && str_starts_with($key, 'pay-kit:php:charge-pending:')) {
                    throw new \RuntimeException('injected store outage');
                }
                return $this->inner->putIfAbsent($key, $value);
            }
            public function has(string $key): bool
            {
                return $this->inner->has($key);
            }
        };
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $transaction = $this->minimalV0TransactionBase64();
        $signature = $this->signatureOf($transaction);
        $authorization = (new Credential(
            challenge: $challenges->createChallenge($request)->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        ))->toAuthorizationHeader();
        $rpc = new FakeRpcGateway(signature: $signature);
        $result = $this->handler(
            challenges: $challenges,
            verifier: new AlwaysAcceptVerifier(),
            replayStore: $store,
            rpcGateway: $rpc,
        )->handle($authorization, $request);
        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertSame([], $rpc->sentTransactions);
    }

    // The node already processed this exact transaction, yet this store held
    // no claim on it: it was settled where this store cannot see. A replay,
    // and it stays refused on retry.
    public function testAlreadyProcessedWithAFreshClaimIsAReplay(): void
    {
        $store = new MemoryStore();
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $transaction = $this->minimalV0TransactionBase64();
        $signature = $this->signatureOf($transaction);
        $authorization = (new Credential(
            challenge: $challenges->createChallenge($request)->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        ))->toAuthorizationHeader();
        $processed = new RpcException('JSON-RPC error: Transaction error: This transaction has already been processed', 200, -32603);
        foreach ([$processed, null] as $sendError) {
            $result = $this->handler(
                challenges: $challenges,
                verifier: new AlwaysAcceptVerifier(),
                replayStore: $store,
                rpcGateway: new FakeRpcGateway(signature: $signature, sendError: $sendError),
            )->handle($authorization, $request);
            self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        }
        self::assertFalse($store->has('solana:authorized-signature:' . $signature));
    }

    // A signature another SDK already settled on the shared ledger (it claims
    // the ledger key but never writes PHP's authorization key) is a replay.
    // Reconciling it would authorize it a second time, so only this
    // challenge's own pending charge is reconciled.
    public function testSignatureSettledByAnotherSdkIsNotGrantedAgain(): void
    {
        $store = new MemoryStore();
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $transaction = $this->minimalV0TransactionBase64();
        $signature = $this->signatureOf($transaction);
        foreach (['solana-charge:consumed:', 'x402-svm-exact:consumed:', 'solana:consumed-signature:'] as $prefix) {
            $store->putIfAbsent($prefix . $signature, true);
        }
        $authorization = (new Credential(
            challenge: $challenges->createChallenge($request)->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        ))->toAuthorizationHeader();
        foreach ([null, new RpcException('JSON-RPC error: This transaction has already been processed', 200, -32002, ['err' => 'AlreadyProcessed'])] as $sendError) {
            $result = $this->handler(
                challenges: $challenges,
                verifier: new AlwaysAcceptVerifier(),
                replayStore: $store,
                rpcGateway: new FakeRpcGateway(signature: $signature, sendError: $sendError),
            )->handle($authorization, $request);
            self::assertInstanceOf(PaymentRequiredResponse::class, $result);
            self::assertStringContainsString('already consumed', $result->body['detail']);
        }
        self::assertFalse($store->has('solana:authorized-signature:' . $signature));

        // A look-alike pending record another SDK wrote for this very
        // challenge is not this handler's to reconcile either.
        $challenge = Credential::fromAuthorizationHeader($authorization)->challenge;
        $store->putIfAbsent('solana-charge:pending:' . $signature . ':' . $challenge->id, true);
        $result = $this->handler(
            challenges: $challenges,
            verifier: new AlwaysAcceptVerifier(),
            replayStore: $store,
            rpcGateway: new FakeRpcGateway(signature: $signature),
        )->handle($authorization, $request);
        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertStringContainsString('already consumed', $result->body['detail']);
    }

    // A status read that fails after the broadcast (an RPC outage) proves
    // nothing about the transaction, which may already have landed: the
    // charge stays pending instead of answering a fresh challenge, on the
    // first attempt and on the retry that reconciles it. Only a reported
    // on-chain failure rejects it.
    public function testStatusReadOutageNeverFailsThePendingCharge(): void
    {
        $store = new MemoryStore();
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $transaction = $this->minimalV0TransactionBase64();
        $signature = $this->signatureOf($transaction);
        $authorization = (new Credential(
            challenge: $challenges->createChallenge($request)->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        ))->toAuthorizationHeader();
        $handler = fn (FakeRpcGateway $rpc) => $this->handler(
            challenges: $challenges,
            verifier: new AlwaysAcceptVerifier(),
            replayStore: $store,
            confirmationAttempts: 2,
            rpcGateway: $rpc,
        );
        $outage = new RpcException('HTTP 503 from RPC', 503, -32099);

        $sent = new FakeRpcGateway(signature: $signature, statuses: [$outage]);
        $pending = $handler($sent)->handle($authorization, $request);
        self::assertInstanceOf(SettlementPending::class, $pending);
        self::assertCount(1, $sent->sentTransactions);

        // The retry reconciles from the chain: still unreadable, still pending.
        $retry = new FakeRpcGateway(signature: $signature, statuses: [$outage]);
        self::assertInstanceOf(SettlementPending::class, $handler($retry)->handle($authorization, $request));
        self::assertSame([], $retry->sentTransactions);

        // Once the status reads as confirmed, the same credential is granted.
        $settled = $handler(new FakeRpcGateway(signature: $signature))->handle($authorization, $request);
        self::assertInstanceOf(ChargeSettlement::class, $settled);
        self::assertSame($signature, $settled->signature);

        // A reported on-chain failure is still definitive.
        $failed = $this->minimalV0TransactionBase64();
        $result = $handler(new FakeRpcGateway(
            signature: $this->signatureOf($failed),
            statuses: [$outage, ['err' => ['InstructionError' => [0, 'Custom']], 'confirmationStatus' => 'confirmed']],
        ))->handle((new Credential(
            challenge: $challenges->createChallenge($request)->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $failed],
        ))->toAuthorizationHeader(), $request);
        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertStringContainsString('failed', $result->body['detail']);
    }

    // A missing signature status is not proof the transaction never landed
    // (the node may lag or lack history), so an unconfirmed charge stays
    // pending instead of answering a fresh challenge; only an explicit
    // on-chain outcome resolves it.
    public function testMissingSignatureStatusNeverFailsThePendingCharge(): void
    {
        $store = new MemoryStore();
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $transaction = $this->minimalV0TransactionBase64();
        $signature = $this->signatureOf($transaction);
        $authorization = (new Credential(
            challenge: $challenges->createChallenge($request)->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        ))->toAuthorizationHeader();
        $handler = fn (FakeRpcGateway $rpc) => $this->handler(
            challenges: $challenges,
            verifier: new AlwaysAcceptVerifier(),
            replayStore: $store,
            confirmationAttempts: 2,
            rpcGateway: $rpc,
        );

        $unknown = $handler(new FakeRpcGateway(signature: $signature, statuses: [null]));
        self::assertInstanceOf(SettlementPending::class, $unknown->handle($authorization, $request));
        // Still no status on the retry: still pending, never failed.
        self::assertInstanceOf(SettlementPending::class, $unknown->handle($authorization, $request));

        // When the status surfaces, the same retry is granted.
        $settled = $handler(new FakeRpcGateway(signature: $signature))->handle($authorization, $request);
        self::assertInstanceOf(ChargeSettlement::class, $settled);
        self::assertSame($signature, $settled->signature);

        // An explicit on-chain failure is definitive.
        $failed = $this->minimalV0TransactionBase64();
        $result = $handler(new FakeRpcGateway(
            signature: $this->signatureOf($failed),
            statuses: [['err' => ['InstructionError' => [0, 'Custom']], 'confirmationStatus' => 'confirmed']],
        ))->handle((new Credential(
            challenge: $challenges->createChallenge($request)->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $failed],
        ))->toAuthorizationHeader(), $request);
        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertStringContainsString('failed', $result->body['detail']);
    }

    // A preflight rejection is definitive: the node never forwarded the
    // transaction, so the charge fails with a fresh challenge.
    public function testPreflightRejectionFailsTheCharge(): void
    {
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $transaction = $this->minimalV0TransactionBase64();
        $credential = new Credential(
            challenge: $challenges->createChallenge($request)->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        );
        $rejected = new RpcException(
            'JSON-RPC error: Transaction simulation failed: Error processing Instruction 0',
            200,
            -32002,
            ['err' => ['InstructionError' => [0, ['Custom' => 1]]], 'logs' => ['Program failed']],
        );
        $handler = $this->handler(
            challenges: $challenges,
            verifier: new AlwaysAcceptVerifier(),
            rpcGateway: new FakeRpcGateway(signature: $this->signatureOf($transaction), sendError: $rejected),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);
        self::assertInstanceOf(PaymentRequiredResponse::class, $result);
        self::assertStringContainsString('rejected by preflight', $result->body['detail']);
    }

    // The node's reported signature is not authoritative: a different one
    // leaves the transaction's own signature pending, never settled under
    // an identifier the payer did not sign.
    public function testMismatchedReportedSignatureIsPending(): void
    {
        $challenges = new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api');
        $request = $this->chargeRequest();
        $credential = new Credential(
            challenge: $challenges->createChallenge($request)->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $this->minimalV0TransactionBase64()],
        );
        $handler = $this->handler(
            challenges: $challenges,
            verifier: new AlwaysAcceptVerifier(),
            rpcGateway: new FakeRpcGateway(signature: 'SomeOtherSignature'),
        );

        $result = $handler->handle($credential->toAuthorizationHeader(), $request);
        self::assertInstanceOf(SettlementPending::class, $result);
    }

    /** The base58 first signature of a base64 wire transaction: its id. */
    private function signatureOf(string $transactionBase64): string
    {
        $wire = (string) base64_decode($transactionBase64, true);
        return Base58::encode(substr($wire, 1, 64));
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
        bool $acceptPushMode = true,
        ?RpcGateway $rpcGateway = null,
    ): SolanaChargeHandler {
        // Default to acceptPushMode=true here so the push-mode tests below
        // exercise the settlement path; audit #5's default-off posture is
        // covered by testReturns402WhenPushModeNotOptedIn.
        return new SolanaChargeHandler(
            challenges: $challenges ?? new ChargeServer(secretKey: 'test-secret-0123456789abcdef-0123456789', realm: 'api'),
            rpc: $rpcGateway ?? $rpc ?? new RpcClient('http://unused.invalid', new NullHttpClient()),
            feePayer: $feePayer,
            network: $network,
            verifier: $verifier,
            transactionVerifier: $transactionVerifier,
            confirmationAttempts: $confirmationAttempts,
            confirmationDelayMicros: 0,
            replayStore: $replayStore,
            acceptPushMode: $acceptPushMode,
        );
    }

    /**
     * Builds a signed v0 transaction whose 32-byte recentBlockhash
     * base58-encodes to the Surfpool prefix (`SURFNET…`), so the handler's
     * blockhash sanity check fires when run against a non-localnet network.
     */
    private function surfpoolSignedTransactionBase64(): string
    {
        // Base58 string with the Surfpool prefix; 32 raw bytes once decoded.
        return $this->minimalV0TransactionBase64(Base58::decode('SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx191cab2c'));
    }

    /**
     * Builds a signed v0 transaction with no instructions, the wire every
     * pay-kit client emits. The handler re-serializes the transaction with
     * `verifySignatures = true` before broadcasting, so the fixture must carry
     * a real signature in the only required slot.
     */
    private function minimalV0TransactionBase64(?string $recentBlockhashBytes = null): string
    {
        $signer = Keypair::generate();
        $message = new MessageV0();
        $message->numRequiredSignatures = 1;
        $message->numReadonlySignedAccounts = 0;
        $message->numReadonlyUnsignedAccounts = 0;
        $message->staticAccountKeys = [$signer->getPublicKey()];
        $message->recentBlockhash = Base58::encode($recentBlockhashBytes ?? str_repeat("\x00", 32));
        $message->compiledInstructions = [];
        $tx = new VersionedTransaction($message);
        $tx->partialSign($signer);
        return base64_encode($tx->serialize());
    }

    /**
     * Builds a signed legacy (unprefixed) transaction, as a pre-cutover
     * client sends; the handler still accepts it.
     */
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
