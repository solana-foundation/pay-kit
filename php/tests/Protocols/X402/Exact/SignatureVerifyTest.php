<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402\Exact;

use PayKit\Exception\InvalidProofException;
use PayKit\PayCore\Solana\Mints;
use PayKit\Protocols\X402\Exact\Verifier;
use PHPUnit\Framework\TestCase;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Programs\ComputeBudgetProgram;
use SolanaPhpSdk\Programs\TokenProgram;
use SolanaPhpSdk\Transaction\MessageV0;
use SolanaPhpSdk\Transaction\VersionedTransaction;

/**
 * RULINGS SIG1 on the x402 exact verifier: the client's signature must
 * verify over the message before the facilitator co-signs or sends; only
 * the facilitator's own fee-payer slot may still be empty.
 */
final class SignatureVerifyTest extends TestCase
{
    private const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

    public function testClientSignedTransactionVerifies(): void
    {
        [$tx, $requirement, $facilitator] = $this->build(signClient: true);

        self::assertSame(1000, Verifier::verify($tx, $requirement, [$facilitator])['amount']);
    }

    public function testForgedClientSignatureIsRejected(): void
    {
        [$tx, $requirement, $facilitator] = $this->build(signClient: true);
        $wire = base64_decode($tx, true);
        self::assertIsString($wire);
        $wire[1 + 64] = chr(ord($wire[1 + 64]) ^ 0x01);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('invalid_exact_svm_payload_transaction_signature');
        Verifier::verify(base64_encode($wire), $requirement, [$facilitator]);
    }

    public function testUnsignedClientSlotIsRejected(): void
    {
        [$tx, $requirement, $facilitator] = $this->build(signClient: false);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('slot 1 is unsigned');
        Verifier::verify($tx, $requirement, [$facilitator]);
    }

    /** An empty fee-payer slot is allowed only for a key this server manages. */
    public function testEmptyFeePayerSlotOfAnUnmanagedKeyIsRejected(): void
    {
        [$tx, $requirement] = $this->build(signClient: true);

        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('slot 0 is unsigned');
        Verifier::verify($tx, $requirement, [Keypair::generate()->getPublicKey()->toBase58()]);
    }

    /** @return array{string, array<string, mixed>, string} */
    private function build(bool $signClient): array
    {
        $facilitator = Keypair::generate();
        $client = Keypair::generate();
        $payTo = Keypair::generate()->getPublicKey()->toBase58();
        $tokenProgram = TokenProgram::PROGRAM_ID;
        $tx = new VersionedTransaction(MessageV0::compile(
            $facilitator->getPublicKey(),
            [
                ComputeBudgetProgram::setComputeUnitLimit(200000),
                ComputeBudgetProgram::setComputeUnitPrice(1),
                TokenProgram::transferChecked(
                    Keypair::generate()->getPublicKey(),
                    new PublicKey(self::USDC_MINT),
                    new PublicKey(Mints::deriveAta($payTo, self::USDC_MINT, $tokenProgram)),
                    $client->getPublicKey(),
                    1000,
                    6,
                    TokenProgram::programId(),
                ),
            ],
            str_repeat("\x09", 32),
        ));
        if ($signClient) {
            $tx->partialSign($client);
        }
        $requirement = [
            'asset' => self::USDC_MINT,
            'payTo' => $payTo,
            'amount' => '1000',
            'extra' => ['tokenProgram' => $tokenProgram, 'memo' => ''],
        ];

        return [base64_encode($tx->serialize(verifySignatures: false)), $requirement, $facilitator->getPublicKey()->toBase58()];
    }
}
