<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use PHPUnit\Framework\TestCase;
use SolanaMpp\Core\Credential;
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\SolanaChargeTransactionVerifier;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Programs\AssociatedTokenProgram;
use SolanaPhpSdk\Programs\MemoProgram;
use SolanaPhpSdk\Programs\TokenProgram;
use SolanaPhpSdk\Transaction\Transaction;

final class SolanaChargeTransactionVerifierTest extends TestCase
{
    public function testAcceptsVerifierCompatibleSplTransactionWithSplitAtaAndMemo(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertTrue($result->ok, $result->reason);
        self::assertSame($transaction, $result->reference);
    }

    public function testRejectsSplTransactionWithWrongAmount(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture, amount: '1100');
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertStringContainsString('No matching SPL transferChecked', $result->reason);
    }

    public function testRejectsMissingRequiredSplitAtaCreation(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload($fixture, includeSplitAta: false);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertStringContainsString('Missing required ATA creation instruction', $result->reason);
    }

    /**
     * @param array<string, PublicKey> $fixture
     */
    private function request(array $fixture, string $amount = '1000'): ChargeRequest
    {
        return new ChargeRequest(
            amount: $amount,
            currency: $fixture['mint']->toBase58(),
            recipient: $fixture['recipient']->toBase58(),
            externalId: 'order-123',
            methodDetails: [
                'network' => 'localnet',
                'decimals' => 6,
                'tokenProgram' => TokenProgram::PROGRAM_ID,
                'feePayer' => true,
                'feePayerKey' => $fixture['feePayer']->toBase58(),
                'splits' => [
                    [
                        'recipient' => $fixture['splitRecipient']->toBase58(),
                        'amount' => '250',
                        'ataCreationRequired' => true,
                        'memo' => 'split memo',
                    ],
                ],
            ],
        );
    }

    /**
     * @param array<string, PublicKey> $fixture
     */
    private function transactionPayload(array $fixture, bool $includeSplitAta): string
    {
        $tokenProgram = TokenProgram::programId();
        $recipientAta = AssociatedTokenProgram::findAssociatedTokenAddress(
            $fixture['recipient'],
            $fixture['mint'],
            $tokenProgram,
        )[0];
        $splitAta = AssociatedTokenProgram::findAssociatedTokenAddress(
            $fixture['splitRecipient'],
            $fixture['mint'],
            $tokenProgram,
        )[0];

        $instructions = [];
        $instructions[] = TokenProgram::transferChecked(
            $fixture['sourceTokenAccount'],
            $fixture['mint'],
            $recipientAta,
            $fixture['payer'],
            750,
            6,
            $tokenProgram,
        );
        if ($includeSplitAta) {
            $instructions[] = AssociatedTokenProgram::createIdempotent(
                $fixture['feePayer'],
                $splitAta,
                $fixture['splitRecipient'],
                $fixture['mint'],
                $tokenProgram,
            );
        }
        $instructions[] = TokenProgram::transferChecked(
            $fixture['sourceTokenAccount'],
            $fixture['mint'],
            $splitAta,
            $fixture['payer'],
            250,
            6,
            $tokenProgram,
        );
        $instructions[] = MemoProgram::create('order-123');
        $instructions[] = MemoProgram::create('split memo');

        $transaction = Transaction::new(
            $instructions,
            $fixture['feePayer'],
            str_repeat("\x09", 32),
        );

        return base64_encode($transaction->serialize(verifySignatures: false));
    }

    private function verify(ChargeRequest $request, string $transaction): \SolanaMpp\Server\VerificationResult
    {
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $challenge = $server->createChallenge($request);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        );

        return (new SolanaChargeTransactionVerifier())->verify($credential, $challenge);
    }

    /**
     * @return array<string, PublicKey>
     */
    private function fixture(): array
    {
        return [
            'feePayer' => PublicKey::fromBytes(str_repeat("\x02", 32)),
            'payer' => PublicKey::fromBytes(str_repeat("\x03", 32)),
            'recipient' => PublicKey::fromBytes(str_repeat("\x04", 32)),
            'splitRecipient' => PublicKey::fromBytes(str_repeat("\x05", 32)),
            'mint' => new PublicKey('4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'),
            'sourceTokenAccount' => PublicKey::fromBytes(str_repeat("\x06", 32)),
        ];
    }
}
