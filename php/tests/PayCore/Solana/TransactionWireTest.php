<?php

declare(strict_types=1);

namespace PayKit\Tests\PayCore\Solana;

use InvalidArgumentException;
use PayKit\PayCore\Solana\TransactionWire;
use PHPUnit\Framework\TestCase;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Programs\SystemProgram;
use SolanaPhpSdk\Transaction\MessageV0;
use SolanaPhpSdk\Transaction\Transaction;
use SolanaPhpSdk\Transaction\VersionedTransaction;

/**
 * RULINGS SIG1: the signature list holds exactly
 * header.num_required_signatures entries, and every slot verifies over the
 * message, except the server's own fee-payer slot before it co-signs.
 */
final class TransactionWireTest extends TestCase
{
    public function testEveryClientSlotSignedAndFeePayerEmptyVerifies(): void
    {
        [$feePayer, , $wire] = $this->sponsoredV0(signClient: true);

        TransactionWire::deserialize($wire)->assertSignaturesVerify($feePayer->getPublicKey());
        $this->addToAssertionCount(1);
    }

    public function testEmptyFeePayerSlotIsRefusedOnceTheServerMustHaveSigned(): void
    {
        [, , $wire] = $this->sponsoredV0(signClient: true);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('slot 0 is unsigned');
        TransactionWire::deserialize($wire)->assertSignaturesVerify();
    }

    public function testEmptyFeePayerSlotIsRefusedForAnotherKey(): void
    {
        [, , $wire] = $this->sponsoredV0(signClient: true);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('slot 0 is unsigned');
        TransactionWire::deserialize($wire)->assertSignaturesVerify(Keypair::generate()->getPublicKey());
    }

    public function testCoSignedTransactionVerifiesWithNoEmptySlot(): void
    {
        [$feePayer, , $wire] = $this->sponsoredV0(signClient: true);
        $tx = TransactionWire::deserialize($wire);
        $tx->partialSign($feePayer);

        $tx->assertSignaturesVerify();
        $this->addToAssertionCount(1);
    }

    public function testForgedClientSignatureIsRefused(): void
    {
        [$feePayer, , $wire] = $this->sponsoredV0(signClient: true);
        $wire[1 + 64] = chr(ord($wire[1 + 64]) ^ 0x01);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('slot 1 does not verify');
        TransactionWire::deserialize($wire)->assertSignaturesVerify($feePayer->getPublicKey());
    }

    public function testUnsignedClientSlotIsRefused(): void
    {
        [$feePayer, , $wire] = $this->sponsoredV0(signClient: false);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('slot 1 is unsigned');
        TransactionWire::deserialize($wire)->assertSignaturesVerify($feePayer->getPublicKey());
    }

    public function testShortV0SignatureListIsRefused(): void
    {
        [, , $wire] = $this->sponsoredV0(signClient: true);
        $truncated = chr(1) . substr($wire, 1, 64) . substr($wire, 1 + 128);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('expected 2 signatures, got 1');
        TransactionWire::deserialize($truncated);
    }

    /** The legacy decoder pads a short list; the wire boundary must not. */
    public function testShortLegacySignatureListIsRefused(): void
    {
        $feePayer = Keypair::generate();
        $client = Keypair::generate();
        $tx = Transaction::new(
            [SystemProgram::transfer($client->getPublicKey(), Keypair::generate()->getPublicKey(), 1)],
            $feePayer->getPublicKey(),
            str_repeat("\x09", 32),
        );
        $tx->partialSign($client);
        $wire = $tx->serialize(verifySignatures: false);
        self::assertSame(2, ord($wire[0]));
        TransactionWire::deserialize($wire)->assertSignaturesVerify($feePayer->getPublicKey());

        $truncated = chr(1) . substr($wire, 1, 64) . substr($wire, 1 + 128);
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('expected 2 signatures, got 1');
        TransactionWire::deserialize($truncated);
    }

    public function testLongerSignatureListIsRefused(): void
    {
        [, , $wire] = $this->sponsoredV0(signClient: true);
        $padded = chr(3) . substr($wire, 1, 128) . str_repeat("\x00", 64) . substr($wire, 1 + 128);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('expected 2 signatures, got 3');
        TransactionWire::deserialize($padded);
    }

    /**
     * A v0 SOL transfer from a client, fee-sponsored by a server key: slot 0
     * is the fee payer (left empty), slot 1 the client.
     *
     * @return array{Keypair, Keypair, string}
     */
    private function sponsoredV0(bool $signClient): array
    {
        $feePayer = Keypair::generate();
        $client = Keypair::generate();
        $tx = new VersionedTransaction(MessageV0::compile(
            $feePayer->getPublicKey(),
            [SystemProgram::transfer($client->getPublicKey(), Keypair::generate()->getPublicKey(), 1)],
            str_repeat("\x09", 32),
        ));
        if ($signClient) {
            $tx->partialSign($client);
        }

        return [$feePayer, $client, $tx->serialize(verifySignatures: false)];
    }
}
