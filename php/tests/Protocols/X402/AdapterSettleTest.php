<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402;

use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Gate;
use PayKit\PayCore\Network;
use PayKit\PayCore\Solana\Mints;
use PayKit\Operator;
use PayKit\Payment;
use PayKit\Price;
use PayKit\Protocol;
use PayKit\Protocols\X402\Adapter;
use PayKit\Protocols\X402\X402Config;
use PayKit\Signer;
use PayKit\Signer\LocalSigner;
use PayKit\Store\MemoryStore;
use PayKit\Tests\PayCore\Rpc\FakeRpcGateway;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Transaction\CompiledInstructionV0;
use SolanaPhpSdk\Transaction\MessageV0;
use SolanaPhpSdk\Transaction\VersionedTransaction;
use SolanaPhpSdk\Util\Base58;

/**
 * End-to-end settlement coverage for the x402 exact adapter's
 * verifyAndSettle: the canonical (v2) and legacy (v1) happy paths through
 * the structural verifier, cosign, broadcast, replay-reserve and
 * confirm-before-success chain, plus the reject branches (payment-identifier
 * extension gate, credential mismatch, replay guard, broadcast/confirmation
 * failure, missing/malformed payload).
 *
 * A byte-perfect v0 transfer is assembled against the offer the adapter
 * itself builds via acceptsEntry, so the verifier passes and settlement
 * proceeds. RPC is a {@see FakeRpcGateway}: no network is touched.
 */
final class AdapterSettleTest extends TestCase
{
    private const COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111';
    private const MEMO_PROGRAM   = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';

    private LocalSigner $signer;

    protected function setUp(): void
    {
        $this->signer = Signer::generate();
    }

    private function makeConfig(?X402Config $x402 = null): Config
    {
        return new Config(
            network: Network::SolanaLocalnet,
            operator: new Operator(
                recipient: Signer::generate()->pubkey(),
                signer:    $this->signer,
                feePayer:  true,
            ),
            x402: $x402,
            preflight: false,
        );
    }

    private function makeAdapter(
        Config $config,
        FakeRpcGateway $rpc,
        ?MemoryStore $store = null,
    ): Adapter {
        return new Adapter(
            $config,
            replayStore: $store ?? new MemoryStore(),
            recentBlockhashProvider: fn () => null,
            rpc: $rpc,
            confirmationAttempts: 3,
            confirmationDelayMicros: 0,
        );
    }

    private function gate(): Gate
    {
        return new Gate(amount: Price::usd('0.10'));
    }

    private function request(): ServerRequestInterface
    {
        return (new Psr17Factory())->createServerRequest('GET', '/paid');
    }

    /**
     * Build a base64 v0 transfer wire transaction that satisfies the offer.
     *
     * @param array<string,mixed> $offer
     */
    private function transactionFor(array $offer): string
    {
        $feePayer  = $offer['extra']['feePayer']; // managed signer / fee payer
        $authority = Keypair::generate()->getPublicKey()->toBase58();
        $source    = Keypair::generate()->getPublicKey()->toBase58();
        $mint      = $offer['asset'];
        $tokenProgram = $offer['extra']['tokenProgram'];
        $payTo     = $offer['payTo'];
        $destination = Mints::deriveAta($payTo, $mint, $tokenProgram);
        $amount    = (int) $offer['amount'];
        $memo      = $offer['extra']['memo'];

        $keys = [];
        $indexOf = function (string $addr) use (&$keys): int {
            $i = array_search($addr, $keys, true);
            if ($i === false) {
                $keys[] = $addr;
                return count($keys) - 1;
            }
            return $i;
        };

        $instructions = [];
        $instructions[] = new CompiledInstructionV0(
            $indexOf(self::COMPUTE_BUDGET),
            [],
            chr(2) . pack('V', 200000),
        );
        $instructions[] = new CompiledInstructionV0(
            $indexOf(self::COMPUTE_BUDGET),
            [],
            chr(3) . pack('P', 1),
        );
        $instructions[] = new CompiledInstructionV0(
            $indexOf($tokenProgram),
            [$indexOf($source), $indexOf($mint), $indexOf($destination), $indexOf($authority)],
            chr(12) . pack('P', $amount) . chr(6),
        );
        if ($memo !== '') {
            $instructions[] = new CompiledInstructionV0(
                $indexOf(self::MEMO_PROGRAM),
                [],
                $memo,
            );
        }

        array_unshift($keys, $feePayer);
        foreach ($instructions as $ix) {
            $ix->programIdIndex += 1;
            $ix->accountKeyIndexes = array_map(static fn (int $i): int => $i + 1, $ix->accountKeyIndexes);
        }

        $message = new MessageV0();
        $message->numRequiredSignatures = 1;
        $message->numReadonlySignedAccounts = 0;
        $message->numReadonlyUnsignedAccounts = 0;
        $message->staticAccountKeys = array_map(
            static fn (string $addr): PublicKey => new PublicKey($addr),
            $keys,
        );
        $message->recentBlockhash = Base58::encode(str_repeat("\x01", 32));
        $message->compiledInstructions = $instructions;

        $tx = new VersionedTransaction($message);
        return base64_encode($tx->serialize(verifySignatures: false));
    }

    /**
     * @param array<string,mixed> $envelope
     */
    private function header(array $envelope): string
    {
        return base64_encode(json_encode($envelope, JSON_THROW_ON_ERROR));
    }

    // ── canonical (v2) happy path ──────────────────────────────────────────

    public function testVerifyAndSettleCanonicalHappyPath(): void
    {
        $adapter = $this->makeAdapter($this->makeConfig(), $rpc = new FakeRpcGateway());
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $tx = $this->transactionFor($offer);

        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $offer,
            'payload'     => ['transaction' => $tx, 'transactionHash' => 'payer_abc'],
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $payment = $adapter->verifyAndSettle($gate, $req);

        self::assertInstanceOf(Payment::class, $payment);
        self::assertSame(Protocol::X402, $payment->protocol);
        self::assertSame('5sigStubBASE58Signature1111111111111111111', $payment->transaction);
        // v2 uses PAYMENT-RESPONSE, not the legacy X-PAYMENT-RESPONSE.
        self::assertArrayHasKey('payment-response', $payment->settlementHeaders);
        self::assertArrayHasKey('x-payment-settlement-signature', $payment->settlementHeaders);
        // Broadcast happened exactly once with the cosigned wire.
        self::assertCount(1, $rpc->sentTransactions);
        // The success envelope echoes the payer hash from the payload.
        $decoded = json_decode(
            base64_decode($payment->settlementHeaders['payment-response'], true) ?: '{}',
            true,
        );
        self::assertTrue($decoded['success']);
        self::assertSame('payer_abc', $decoded['payer']);
    }

    // ── legacy (v1) happy path ──────────────────────────────────────────────

    public function testVerifyAndSettleLegacyHappyPathUsesLegacyResponseHeader(): void
    {
        $adapter = $this->makeAdapter($this->makeConfig(), new FakeRpcGateway());
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $tx = $this->transactionFor($offer);

        $header = $this->header([
            'x402Version' => 1,
            'scheme'      => 'exact',
            'network'     => 'localnet',
            'payload'     => ['transaction' => $tx, 'transactionHash' => 'payer_legacy'],
        ]);
        $req = $req->withHeader('X-PAYMENT', $header);

        $payment = $adapter->verifyAndSettle($gate, $req);
        // v1 credentials get the legacy x-payment-response receipt header.
        self::assertArrayHasKey('x-payment-response', $payment->settlementHeaders);
        self::assertArrayNotHasKey('payment-response', $payment->settlementHeaders);
        $decoded = json_decode(
            base64_decode($payment->settlementHeaders['x-payment-response'], true) ?: '{}',
            true,
        );
        // Legacy echoes the plain network slug it committed to.
        self::assertSame('localnet', $decoded['network']);
    }

    // ── payment-identifier extension gate ────────────────────────────────────

    private function requiringPaymentIdentifierConfig(): Config
    {
        return $this->makeConfig(new X402Config(
            advertisedExtensions: ['payment-identifier' => ['info' => ['required' => true]]],
        ));
    }

    public function testPaymentIdentifierValidIdSettles(): void
    {
        $adapter = $this->makeAdapter($this->requiringPaymentIdentifierConfig(), new FakeRpcGateway());
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $tx = $this->transactionFor($offer);

        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $offer,
            'extensions'  => ['payment-identifier' => ['info' => ['id' => 'pay_0123456789abcdef']]],
            'payload'     => ['transaction' => $tx, 'transactionHash' => 'payer_pi'],
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $payment = $adapter->verifyAndSettle($gate, $req);
        self::assertSame(Protocol::X402, $payment->protocol);
    }

    public function testPaymentIdentifierMissingWhenRequiredRejected(): void
    {
        $adapter = $this->makeAdapter($this->requiringPaymentIdentifierConfig(), new FakeRpcGateway());
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $tx = $this->transactionFor($offer);

        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $offer,
            'payload'     => ['transaction' => $tx],
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/payment-identifier required/');
        $adapter->verifyAndSettle($gate, $req);
    }

    public function testPaymentIdentifierInvalidIdRejected(): void
    {
        $adapter = $this->makeAdapter($this->requiringPaymentIdentifierConfig(), new FakeRpcGateway());
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $tx = $this->transactionFor($offer);

        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $offer,
            'extensions'  => ['payment-identifier' => ['info' => ['id' => 'too short']]],
            'payload'     => ['transaction' => $tx],
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/payment-identifier id is invalid/');
        $adapter->verifyAndSettle($gate, $req);
    }

    // ── canonical credential mismatch ────────────────────────────────────────

    public function testCanonicalCredentialAssetMismatchRejected(): void
    {
        $adapter = $this->makeAdapter($this->makeConfig(), new FakeRpcGateway());
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $tx = $this->transactionFor($offer);

        $tampered = $offer;
        $tampered['asset'] = 'So11111111111111111111111111111111111111112';
        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $tampered,
            'payload'     => ['transaction' => $tx],
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/charge_request_mismatch/');
        $adapter->verifyAndSettle($gate, $req);
    }

    public function testCanonicalCredentialExtraMemoMismatchRejected(): void
    {
        $adapter = $this->makeAdapter($this->makeConfig(), new FakeRpcGateway());
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $tx = $this->transactionFor($offer);

        $tampered = $offer;
        $tampered['extra']['memo'] = '/wrong';
        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $tampered,
            'payload'     => ['transaction' => $tx],
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/charge_request_mismatch \(extra\.memo\)/');
        $adapter->verifyAndSettle($gate, $req);
    }

    public function testCanonicalCredentialMissingAcceptedRejected(): void
    {
        $adapter = $this->makeAdapter($this->makeConfig(), new FakeRpcGateway());
        $gate = $this->gate();
        $req = $this->request();

        $header = $this->header([
            'x402Version' => 2,
            'payload'     => ['transaction' => 'AA=='],
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/envelope/');
        $adapter->verifyAndSettle($gate, $req);
    }

    // ── replay guard ─────────────────────────────────────────────────────────

    public function testReplayOfSameSignatureRejected(): void
    {
        $store = new MemoryStore();
        $adapter = $this->makeAdapter($this->makeConfig(), new FakeRpcGateway(), $store);
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $tx = $this->transactionFor($offer);
        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $offer,
            'payload'     => ['transaction' => $tx],
        ]);
        $signed = $req->withHeader('Payment-Signature', $header);

        // First settlement succeeds and reserves the signature.
        $adapter->verifyAndSettle($gate, $signed);

        // The FakeRpcGateway returns the SAME signature, so a replay of the
        // identical credential trips the consumed guard.
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/signature_consumed/');
        $adapter->verifyAndSettle($gate, $signed);
    }

    // ── broadcast + confirmation failure ─────────────────────────────────────

    public function testBroadcastFailureRejected(): void
    {
        $rpc = new FakeRpcGateway(sendError: new RuntimeException('rpc down'));
        $adapter = $this->makeAdapter($this->makeConfig(), $rpc);
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $tx = $this->transactionFor($offer);
        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $offer,
            'payload'     => ['transaction' => $tx],
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/broadcast failed/');
        $adapter->verifyAndSettle($gate, $req);
    }

    public function testConfirmationTimeoutRejected(): void
    {
        // RPC accepts the broadcast but the tx never confirms.
        $rpc = new FakeRpcGateway(
            statuses: [['err' => null, 'confirmationStatus' => 'processed']],
        );
        $adapter = $this->makeAdapter($this->makeConfig(), $rpc);
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $tx = $this->transactionFor($offer);
        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $offer,
            'payload'     => ['transaction' => $tx],
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/settlement not confirmed/');
        $adapter->verifyAndSettle($gate, $req);
    }

    // ── envelope / payload guards ────────────────────────────────────────────

    public function testNoPaymentHeaderRejected(): void
    {
        // No PAYMENT-SIGNATURE / X-PAYMENT header at all: the dual-accept read
        // falls through all four header names and rejects before settlement.
        $adapter = $this->makeAdapter($this->makeConfig(), new FakeRpcGateway());
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/payment required/');
        $adapter->verifyAndSettle($this->gate(), $this->request());
    }

    public function testNonArrayPayloadRejected(): void
    {
        $adapter = $this->makeAdapter($this->makeConfig(), new FakeRpcGateway());
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $offer,
            'payload'     => 'not-an-array',
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/envelope/');
        $adapter->verifyAndSettle($gate, $req);
    }

    public function testMissingTransactionInPayloadRejected(): void
    {
        $adapter = $this->makeAdapter($this->makeConfig(), new FakeRpcGateway());
        $gate = $this->gate();
        $req = $this->request();
        $offer = $adapter->acceptsEntry($gate, $req);
        $header = $this->header([
            'x402Version' => 2,
            'accepted'    => $offer,
            'payload'     => ['transactionHash' => 'x'],
        ]);
        $req = $req->withHeader('Payment-Signature', $header);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/missing_transaction/');
        $adapter->verifyAndSettle($gate, $req);
    }
}
