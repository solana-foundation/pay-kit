<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402\Upto;

use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Operator;
use PayKit\PayCore\Network;
use PayKit\PayCore\PaymentChannels;
use PayKit\Protocols\X402\Upto\Engine;
use PayKit\Signer;
use PayKit\Tests\PayCore\Rpc\FakeRpcGateway;
use PHPUnit\Framework\TestCase;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Transaction\VersionedTransaction;

/**
 * Offline settle_and_seal + distribute broadcast coverage (FakeRpcGateway).
 */
final class EngineSettleTest extends TestCase
{
    private const BLOCKHASH = '4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs';
    private const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

    public function testSettleVoucherlessIsSingleInstruction(): void
    {
        $operator = Signer::generate();
        $rpc = new FakeRpcGateway(signature: 'SettleZero1111111111111111111111111111111111');
        $engine = $this->engine($rpc, $operator);

        $channel = $this->channelPda($operator);
        $sig = $engine->settleAndSealAndBroadcast(
            (string) $channel,
            actualBaseUnits: 0,
            maxBaseUnits: 100_000,
            expiresAt: time() + 300,
            recentBlockhash: self::BLOCKHASH,
        );

        self::assertSame('SettleZero1111111111111111111111111111111111', $sig);
        self::assertCount(1, $rpc->sentTransactions);
        $tx = VersionedTransaction::deserialize($rpc->sentTransactions[0]);
        self::assertCount(1, $tx->message->compiledInstructions);
        $ix = $tx->message->compiledInstructions[0];
        self::assertSame(PaymentChannels::SETTLE_AND_SEAL_DISCRIMINATOR, ord($ix->data[0]));
        self::assertSame(0, ord($ix->data[1])); // hasVoucher = 0
    }

    public function testSettleWithVoucherPrependsEd25519(): void
    {
        $operator = Signer::generate();
        $rpc = new FakeRpcGateway(signature: 'SettleVoucher1111111111111111111111111111111');
        $engine = $this->engine($rpc, $operator);

        $channel = $this->channelPda($operator);
        $actual = 50_000;
        $sig = $engine->settleAndSealAndBroadcast(
            (string) $channel,
            actualBaseUnits: $actual,
            maxBaseUnits: 100_000,
            expiresAt: time() + 300,
            recentBlockhash: self::BLOCKHASH,
        );

        self::assertSame('SettleVoucher1111111111111111111111111111111', $sig);
        self::assertCount(1, $rpc->sentTransactions);
        $tx = VersionedTransaction::deserialize($rpc->sentTransactions[0]);
        self::assertCount(2, $tx->message->compiledInstructions);

        $keys = array_map(static fn (PublicKey $k): string => (string) $k, $tx->message->staticAccountKeys);
        $ed25519Idx = $tx->message->compiledInstructions[0]->programIdIndex;
        $sealIdx = $tx->message->compiledInstructions[1]->programIdIndex;
        self::assertSame(PaymentChannels::ED25519_PROGRAM_ID, $keys[$ed25519Idx]);
        self::assertSame(PaymentChannels::PROGRAM_ID, $keys[$sealIdx]);
        self::assertSame(1, ord($tx->message->compiledInstructions[1]->data[1])); // hasVoucher
    }

    public function testSettleRejectsAboveCeiling(): void
    {
        $operator = Signer::generate();
        $engine = $this->engine(new FakeRpcGateway(), $operator);
        $channel = $this->channelPda($operator);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('invalid_upto_svm_payload_settlement_exceeds_amount');
        $engine->settleAndSealAndBroadcast(
            (string) $channel,
            actualBaseUnits: 100_001,
            maxBaseUnits: 100_000,
            expiresAt: time() + 300,
            recentBlockhash: self::BLOCKHASH,
        );
    }

    public function testDistributeBroadcastsSingleInstruction(): void
    {
        $operator = Signer::generate();
        $payer = Keypair::generate();
        $rpc = new FakeRpcGateway(signature: 'Distribute111111111111111111111111111111111');
        $engine = $this->engine($rpc, $operator);
        $channel = $this->channelPda($operator);

        $sig = $engine->distributeAndBroadcast(
            (string) $channel,
            payer: (string) $payer->getPublicKey(),
            mint: self::MINT,
            tokenProgram: PaymentChannels::tokenProgramId(),
            recipients: [],
            recentBlockhash: self::BLOCKHASH,
        );

        self::assertSame('Distribute111111111111111111111111111111111', $sig);
        self::assertCount(1, $rpc->sentTransactions);
        $tx = VersionedTransaction::deserialize($rpc->sentTransactions[0]);
        self::assertCount(1, $tx->message->compiledInstructions);
        $ix = $tx->message->compiledInstructions[0];
        self::assertSame(PaymentChannels::DISTRIBUTE_DISCRIMINATOR, ord($ix->data[0]));
        // fee payer is operator at static key 0
        self::assertSame($operator->pubkey(), (string) $tx->message->staticAccountKeys[0]);
    }

    public function testDistributeWithRecipientAppendsAtaMeta(): void
    {
        $operator = Signer::generate();
        $payer = Keypair::generate();
        $recipient = Keypair::generate()->getPublicKey();
        $rpc = new FakeRpcGateway(signature: 'DistributeRecip1111111111111111111111111111');
        $engine = $this->engine($rpc, $operator);
        $channel = $this->channelPda($operator);

        $engine->distributeAndBroadcast(
            (string) $channel,
            payer: (string) $payer->getPublicKey(),
            mint: self::MINT,
            tokenProgram: PaymentChannels::tokenProgramId(),
            recipients: [
                ['recipient' => (string) $recipient, 'bps' => 10_000],
            ],
            recentBlockhash: self::BLOCKHASH,
        );

        $tx = VersionedTransaction::deserialize($rpc->sentTransactions[0]);
        $ix = $tx->message->compiledInstructions[0];
        // 11 fixed + 1 recipient ATA
        self::assertCount(12, $ix->accountKeyIndexes);
        // recipients_len = 1 in data after disc
        self::assertSame(1, ord($ix->data[1]) | (ord($ix->data[2]) << 8) | (ord($ix->data[3]) << 16) | (ord($ix->data[4]) << 24));
    }

    public function testSettleBroadcastFailureIsInvalidProof(): void
    {
        $operator = Signer::generate();
        $rpc = new FakeRpcGateway(sendError: new \RuntimeException('rpc down'));
        $engine = $this->engine($rpc, $operator);
        $channel = $this->channelPda($operator);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('settle broadcast failed');
        $engine->settleAndSealAndBroadcast(
            (string) $channel,
            actualBaseUnits: 0,
            maxBaseUnits: 100_000,
            expiresAt: time() + 300,
            recentBlockhash: self::BLOCKHASH,
        );
    }

    private function channelPda(\PayKit\Signer\LocalSigner $operator): PublicKey
    {
        $op = new PublicKey($operator->pubkey());
        $mint = new PublicKey(self::MINT);
        [$channel] = PaymentChannels::findChannelPda(
            new PublicKey(str_repeat("\x11", 32)),
            $op, // payee = operator for upto
            $mint,
            $op, // authorized signer
            7,
            4242,
        );

        return $channel;
    }

    private function engine(
        FakeRpcGateway $rpc,
        \PayKit\Signer\LocalSigner $operator,
    ): Engine {
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
                'blockhash' => self::BLOCKHASH,
                'slot'      => '4242',
            ],
            rpc: $rpc,
            confirmationAttempts: 1,
            confirmationDelayMicros: 0,
        );
    }
}
