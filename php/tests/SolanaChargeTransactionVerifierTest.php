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
use SolanaPhpSdk\Programs\ComputeBudgetProgram;
use SolanaPhpSdk\Programs\MemoProgram;
use SolanaPhpSdk\Programs\SystemProgram;
use SolanaPhpSdk\Programs\TokenProgram;
use SolanaPhpSdk\Transaction\AccountMeta;
use SolanaPhpSdk\Transaction\Transaction;
use SolanaPhpSdk\Transaction\TransactionInstruction;
use SolanaPhpSdk\Util\Base58;

final class SolanaChargeTransactionVerifierTest extends TestCase
{
    public function testAcceptsVerifierCompatibleSplTransactionWithSplitAtaAndMemo(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertTrue($result->ok, $result->reason);
        self::assertSame('', $result->reference);
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

    public function testRejectsMissingTransactionPayload(): void
    {
        $fixture = $this->fixture();
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $challenge = $server->createChallenge($this->request($fixture));
        $credential = new Credential(challenge: $challenge->toEcho(), payload: []);

        $result = (new SolanaChargeTransactionVerifier())->verify($credential, $challenge);

        self::assertFalse($result->ok);
        self::assertSame('missing transaction or signature payload', $result->reason);
    }

    public function testRejectsInvalidTransactionPayload(): void
    {
        $fixture = $this->fixture();
        $result = $this->verify($this->request($fixture), 'not-base64!');

        self::assertFalse($result->ok);
        self::assertSame('invalid transaction payload', $result->reason);
    }

    public function testAcceptsValidPushSignaturePayload(): void
    {
        // Push-mode credentials only carry a signature; the verifier just
        // shape-checks length and base58. Full on-chain artifact verification
        // happens later in the handler via fetchSettledTransaction +
        // verifyTransactionPayload.
        $fixture = $this->fixture();
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $challenge = $server->createChallenge($this->request($fixture));
        $signature = Base58::encode(str_repeat("\x01", 64));
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $signature],
        );

        $result = (new SolanaChargeTransactionVerifier())->verify($credential, $challenge);

        self::assertTrue($result->ok, $result->reason);
        self::assertSame($signature, $result->reference);
    }

    public function testRejectsPushSignaturePayloadWithWrongLength(): void
    {
        $fixture = $this->fixture();
        $server = new ChargeServer(secretKey: 'secret', realm: 'api');
        $challenge = $server->createChallenge($this->request($fixture));
        // 32-byte decoded value, not the required 64.
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => Base58::encode(str_repeat("\x01", 32))],
        );

        $result = (new SolanaChargeTransactionVerifier())->verify($credential, $challenge);

        self::assertFalse($result->ok);
        self::assertSame('invalid signature length', $result->reason);
    }

    public function testRejectsMalformedBinaryTransactionPayload(): void
    {
        $fixture = $this->fixture();
        $result = $this->verify($this->request($fixture), base64_encode("\xffnot-a-transaction"));

        self::assertFalse($result->ok);
        self::assertNotSame('', $result->reason);
    }

    public function testAcceptsNativeSolTransferWithSplitAndMemos(): void
    {
        $fixture = $this->fixture();
        $request = $this->solRequest($fixture);
        $transaction = $this->solTransactionPayload($fixture);
        $result = $this->verify($request, $transaction);

        self::assertTrue($result->ok, $result->reason);
    }

    public function testRejectsNativeSolAtaCreation(): void
    {
        $fixture = $this->fixture();
        $request = $this->solRequest($fixture, splitAtaRequired: true);
        $transaction = $this->solTransactionPayload($fixture);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('ataCreationRequired requires an SPL token charge', $result->reason);
    }

    public function testRejectsFeePayerFundingNativeSolPayment(): void
    {
        $fixture = $this->fixture();
        $request = $this->solRequest($fixture);
        $transaction = $this->solTransactionPayload($fixture, primarySource: $fixture['feePayer']);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('fee payer cannot fund the SOL payment transfer', $result->reason);
    }

    public function testRejectsTooManySplits(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture, splits: array_fill(0, 9, [
            'recipient' => $fixture['splitRecipient']->toBase58(),
            'amount' => '1',
        ]));
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('too many splits', $result->reason);
    }

    public function testRejectsSplitsThatConsumeTheWholeAmount(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture, splits: [[
            'recipient' => $fixture['splitRecipient']->toBase58(),
            'amount' => '1000',
        ]]);
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('split amounts exceed total amount', $result->reason);
    }

    public function testRejectsAmountBeyondPhpIntegerRange(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture, amount: '9223372036854775808');
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('amount exceeds PHP integer range', $result->reason);
    }

    public function testRejectsMissingRecipient(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture, recipient: '');
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('recipient is required', $result->reason);
    }

    public function testRejectsFeePayerMismatch(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture, feePayerKey: $fixture['payer']->toBase58());
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('transaction fee payer mismatch', $result->reason);
    }

    public function testRejectsMissingFeePayerKey(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture, feePayerKey: '');
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('feePayer=true requires feePayerKey', $result->reason);
    }

    public function testRejectsMalformedSplitsValue(): void
    {
        $fixture = $this->fixture();
        $request = new ChargeRequest(
            amount: '1000',
            currency: $fixture['mint']->toBase58(),
            recipient: $fixture['recipient']->toBase58(),
            externalId: 'order-123',
            methodDetails: [
                'network' => 'localnet',
                'decimals' => 6,
                'tokenProgram' => TokenProgram::PROGRAM_ID,
                'feePayer' => true,
                'feePayerKey' => $fixture['feePayer']->toBase58(),
                'splits' => 'invalid',
            ],
        );
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('splits must be an array', $result->reason);
    }

    public function testRejectsSplitWithoutRecipientAndAmount(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture, splits: [[]]);
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('split recipient and amount are required', $result->reason);
    }

    public function testRejectsFeePayerAuthorizingSplTransfer(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            authority: $fixture['feePayer'],
        );
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('fee payer cannot authorize the SPL payment transfer', $result->reason);
    }

    public function testRejectsFeePayerTokenAccountFundingSplTransfer(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $feePayerAta = AssociatedTokenProgram::findAssociatedTokenAddress(
            $fixture['feePayer'],
            $fixture['mint'],
            TokenProgram::programId(),
        )[0];
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            sourceTokenAccount: $feePayerAta,
        );
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('fee payer token account cannot fund the SPL payment transfer', $result->reason);
    }

    public function testRejectsMissingExternalIdMemo(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true, includeExternalIdMemo: false);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertStringContainsString('No memo instruction found for externalId memo', $result->reason);
    }

    public function testRejectsExcessiveComputeUnitLimit(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            extraInstructions: [ComputeBudgetProgram::setComputeUnitLimit(200_001)],
        );
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('compute unit limit exceeds maximum', $result->reason);
    }

    public function testRejectsExcessiveComputeUnitPrice(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            extraInstructions: [ComputeBudgetProgram::setComputeUnitPrice(5_000_001)],
        );
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('compute unit price exceeds maximum', $result->reason);
    }

    public function testRejectsComputeUnitPriceBeyondPhpIntegerRange(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            extraInstructions: [ComputeBudgetProgram::setComputeUnitPrice('9223372036854775808')],
        );
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('u64 value exceeds PHP integer range', $result->reason);
    }

    public function testAcceptsComputeBudgetWithinVerifierLimits(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            extraInstructions: [
                ComputeBudgetProgram::setComputeUnitLimit(200_000),
                ComputeBudgetProgram::setComputeUnitPrice(5_000_000),
            ],
        );
        $result = $this->verify($request, $transaction);

        self::assertTrue($result->ok, $result->reason);
    }

    public function testRejectsComputeBudgetInstructionWithAccounts(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $instruction = ComputeBudgetProgram::setComputeUnitLimit(1000);
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            extraInstructions: [
                new TransactionInstruction(
                    ComputeBudgetProgram::programId(),
                    [AccountMeta::readonly($fixture['recipient'])],
                    $instruction->data,
                ),
            ],
        );
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('compute budget instruction must not have accounts', $result->reason);
    }

    public function testRejectsUnexpectedProgramInstruction(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $program = PublicKey::fromBytes(str_repeat("\x07", 32));
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            extraInstructions: [new TransactionInstruction($program, [], '')],
        );
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertStringContainsString('Unexpected program instruction in payment transaction', $result->reason);
    }

    public function testRejectsNonIdempotentAtaCreation(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true, idempotentAta: false);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('Only idempotent ATA creation is allowed', $result->reason);
    }

    /**
     * @param array<string, PublicKey> $fixture
     * @param array<int, array<string, mixed>>|null $splits
     */
    private function request(
        array $fixture,
        string $amount = '1000',
        ?string $recipient = null,
        ?string $feePayerKey = null,
        ?array $splits = null,
    ): ChargeRequest {
        $splits ??= [
            [
                'recipient' => $fixture['splitRecipient']->toBase58(),
                'amount' => '250',
                'ataCreationRequired' => true,
                'memo' => 'split memo',
            ],
        ];

        return new ChargeRequest(
            amount: $amount,
            currency: $fixture['mint']->toBase58(),
            recipient: $recipient ?? $fixture['recipient']->toBase58(),
            externalId: 'order-123',
            methodDetails: [
                'network' => 'localnet',
                'decimals' => 6,
                'tokenProgram' => TokenProgram::PROGRAM_ID,
                'feePayer' => true,
                'feePayerKey' => $feePayerKey ?? $fixture['feePayer']->toBase58(),
                'splits' => $splits,
            ],
        );
    }

    /**
     * @param array<string, PublicKey> $fixture
     */
    private function solRequest(array $fixture, bool $splitAtaRequired = false): ChargeRequest
    {
        return new ChargeRequest(
            amount: '1000',
            currency: 'SOL',
            recipient: $fixture['recipient']->toBase58(),
            externalId: 'order-123',
            methodDetails: [
                'network' => 'localnet',
                'feePayer' => true,
                'feePayerKey' => $fixture['feePayer']->toBase58(),
                'splits' => [
                    [
                        'recipient' => $fixture['splitRecipient']->toBase58(),
                        'amount' => '250',
                        'ataCreationRequired' => $splitAtaRequired,
                        'memo' => 'split memo',
                    ],
                ],
            ],
        );
    }

    /**
     * @param array<string, PublicKey> $fixture
     * @param array<int, TransactionInstruction> $extraInstructions
     */
    private function transactionPayload(
        array $fixture,
        bool $includeSplitAta,
        ?PublicKey $authority = null,
        ?PublicKey $sourceTokenAccount = null,
        bool $includeExternalIdMemo = true,
        bool $idempotentAta = true,
        array $extraInstructions = [],
    ): string {
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
            $sourceTokenAccount ?? $fixture['sourceTokenAccount'],
            $fixture['mint'],
            $recipientAta,
            $authority ?? $fixture['payer'],
            750,
            6,
            $tokenProgram,
        );
        if ($includeSplitAta) {
            $instructions[] = $idempotentAta
                ? AssociatedTokenProgram::createIdempotent(
                    $fixture['feePayer'],
                    $splitAta,
                    $fixture['splitRecipient'],
                    $fixture['mint'],
                    $tokenProgram,
                )
                : AssociatedTokenProgram::create(
                    $fixture['feePayer'],
                    $splitAta,
                    $fixture['splitRecipient'],
                    $fixture['mint'],
                    $tokenProgram,
                );
        }
        $instructions[] = TokenProgram::transferChecked(
            $sourceTokenAccount ?? $fixture['sourceTokenAccount'],
            $fixture['mint'],
            $splitAta,
            $authority ?? $fixture['payer'],
            250,
            6,
            $tokenProgram,
        );
        if ($includeExternalIdMemo) {
            $instructions[] = MemoProgram::create('order-123');
        }
        $instructions[] = MemoProgram::create('split memo');
        array_push($instructions, ...$extraInstructions);

        $transaction = Transaction::new(
            $instructions,
            $fixture['feePayer'],
            str_repeat("\x09", 32),
        );

        return base64_encode($transaction->serialize(verifySignatures: false));
    }

    /**
     * @param array<string, PublicKey> $fixture
     */
    private function solTransactionPayload(array $fixture, ?PublicKey $primarySource = null): string
    {
        $instructions = [];
        $instructions[] = SystemProgram::transfer($primarySource ?? $fixture['payer'], $fixture['recipient'], 750);
        $instructions[] = SystemProgram::transfer($fixture['payer'], $fixture['splitRecipient'], 250);
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
