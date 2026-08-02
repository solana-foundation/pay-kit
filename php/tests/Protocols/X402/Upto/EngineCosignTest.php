<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402\Upto;

use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Operator;
use PayKit\PayCore\Network;
use PayKit\Protocols\X402\Upto\Engine;
use PayKit\Signer;
use PayKit\Tests\PayCore\Rpc\FakeRpcGateway;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Transaction\CompiledInstructionV0;
use SolanaPhpSdk\Transaction\MessageV0;
use SolanaPhpSdk\Transaction\VersionedTransaction;
use SolanaPhpSdk\Util\Base58;

/**
 * Offline cosign + fee-payer binding coverage (mocked RPC, no Surfpool).
 */
final class EngineCosignTest extends TestCase
{
    public function testRequirePubkeyWrapsInvalidBase58(): void
    {
        $engine = $this->engine(new FakeRpcGateway());
        $m = new ReflectionMethod(Engine::class, 'requirePubkey');
        $m->setAccessible(true);
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('invalid asset public key');
        $m->invoke($engine, 'not-a-pubkey!!!', 'asset');
    }

    public function testCosignRejectsWrongFeePayerAtSlotZero(): void
    {
        $operator = Signer::generate();
        $other = Keypair::generate();
        $engine = $this->engine(new FakeRpcGateway(), $operator);

        // Fee payer slot is someone else; operator cannot cosign this seat.
        $txB64 = $this->partialOpenTxBase64($other, $other);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('fee payer must be the advertised fee payer');
        $engine->cosignAndBroadcastOpenTransaction($txB64);
    }

    public function testCosignAndBroadcastSucceedsWithMatchingFeePayer(): void
    {
        $operator = Signer::generate();
        $payer = Keypair::generate();
        $rpc = new FakeRpcGateway(signature: 'OpenSig1111111111111111111111111111111111111');
        $engine = $this->engine($rpc, $operator, confirmationAttempts: 1, confirmationDelayMicros: 0);

        $opKp = Keypair::fromSecretKey($operator->secretKey());
        $txB64 = $this->partialOpenTxBase64($opKp, $payer);

        $sig = $engine->cosignAndBroadcastOpenTransaction($txB64);
        self::assertSame('OpenSig1111111111111111111111111111111111111', $sig);
        self::assertCount(1, $rpc->sentTransactions);
        self::assertNotSame('', $rpc->sentTransactions[0]);
    }

    public function testCosignBroadcastFailureSurfacesInvalidProof(): void
    {
        $operator = Signer::generate();
        $payer = Keypair::generate();
        $rpc = new FakeRpcGateway(
            sendError: new \RuntimeException('rpc down'),
        );
        $engine = $this->engine($rpc, $operator, confirmationAttempts: 1, confirmationDelayMicros: 0);
        $opKp = Keypair::fromSecretKey($operator->secretKey());
        $txB64 = $this->partialOpenTxBase64($opKp, $payer);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('open broadcast failed');
        $engine->cosignAndBroadcastOpenTransaction($txB64);
    }

    /**
     * Build a v0 open-shaped shell: fee payer first, payer second, both signers.
     * Empty instructions — structural cosign only (full open ix covered offline
     * by Verify + builders tests).
     */
    private function partialOpenTxBase64(Keypair $feePayer, Keypair $payer): string
    {
        $message = new MessageV0();
        $message->numRequiredSignatures = 2;
        $message->numReadonlySignedAccounts = 0;
        $message->numReadonlyUnsignedAccounts = 0;
        $message->staticAccountKeys = [
            $feePayer->getPublicKey(),
            $payer->getPublicKey(),
        ];
        $message->recentBlockhash = Base58::encode(str_repeat("\x02", 32));
        $message->compiledInstructions = [];
        $message->addressTableLookups = [];

        $tx = new VersionedTransaction($message);
        // Client only signs payer seat (index 1); fee payer slot left for cosign.
        $tx->partialSign($payer);

        return base64_encode($tx->serialize(verifySignatures: false));
    }

    private function engine(
        FakeRpcGateway $rpc,
        ?\PayKit\Signer\LocalSigner $operator = null,
        int $confirmationAttempts = 40,
        int $confirmationDelayMicros = 250_000,
    ): Engine {
        $operator ??= Signer::generate();
        $config = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(
                recipient: $operator->pubkey(),
                signer: $operator,
                feePayer: true,
            ),
            preflight: false,
            rpcUrl: 'http://127.0.0.1:8899',
        );

        return new Engine(
            $config,
            chainHintsProvider: static fn (): array => [
                'blockhash' => 'hint-blockhash',
                'slot'      => '4242',
            ],
            rpc: $rpc,
            confirmationAttempts: $confirmationAttempts,
            confirmationDelayMicros: $confirmationDelayMicros,
        );
    }
}
