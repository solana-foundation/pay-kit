<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PHPUnit\Framework\TestCase;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Protocols\Mpp\Server\ChargeServer;
use PayKit\Protocols\Mpp\Server\SolanaChargeTransactionVerifier;
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
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
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
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $challenge = $server->createChallenge($this->request($fixture));
        $signature = Base58::encode(str_repeat("\x01", 64));
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => $signature],
        );

        // Push mode is opt-in (audit #5); construct the verifier with it enabled.
        $result = (new SolanaChargeTransactionVerifier(acceptPushMode: true))->verify($credential, $challenge);

        self::assertTrue($result->ok, $result->reason);
        self::assertSame($signature, $result->reference);
    }

    public function testRejectsUnknownMintWithoutEmbeddedTokenProgram(): void
    {
        // audit #28: for an arbitrary, unknown mint the token program cannot be
        // inferred (the legacy default is wrong for unknown Token-2022 mints),
        // so an absent methodDetails.tokenProgram must be rejected rather than
        // silently defaulting to legacy Token.
        $fixture = $this->fixture();
        $unknownMint = 'So11111111111111111111111111111111111111112';
        $request = new ChargeRequest(
            amount: '1000',
            currency: $unknownMint,
            recipient: $fixture['recipient']->toBase58(),
            externalId: 'order-123',
            methodDetails: [
                'network' => 'localnet',
                'decimals' => 6,
                // tokenProgram intentionally omitted.
            ],
        );
        $transaction = $this->transactionPayload($fixture, includeSplitAta: true);
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertStringContainsString('methodDetails.tokenProgram is required', $result->reason);
    }

    public function testRejectsPushSignaturePayloadWhenPushModeNotOptedIn(): void
    {
        // audit #5: push mode is off by default. A signature credential must be
        // rejected before any shape check unless the server opts in.
        $fixture = $this->fixture();
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $challenge = $server->createChallenge($this->request($fixture));
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => Base58::encode(str_repeat("\x01", 64))],
        );

        $result = (new SolanaChargeTransactionVerifier())->verify($credential, $challenge);

        self::assertFalse($result->ok);
        self::assertSame('push-mode credentials are not accepted by this server', $result->reason);
    }

    public function testRejectsPushSignaturePayloadWithWrongLength(): void
    {
        $fixture = $this->fixture();
        $server = new ChargeServer(secretKey: self::SECRET, realm: 'api');
        $challenge = $server->createChallenge($this->request($fixture));
        // 32-byte decoded value, not the required 64.
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => Base58::encode(str_repeat("\x01", 32))],
        );

        $result = (new SolanaChargeTransactionVerifier(acceptPushMode: true))->verify($credential, $challenge);

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

    public function testAcceptsComputeBudgetWithinFeeSponsoredTightCap(): void
    {
        // audit #25: the default request() is fee-sponsored (feePayer=true), so
        // the tight 10_000 µlamport cap applies. A price at the cap is accepted.
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            extraInstructions: [
                ComputeBudgetProgram::setComputeUnitLimit(200_000),
                ComputeBudgetProgram::setComputeUnitPrice(10_000),
            ],
        );
        $result = $this->verify($request, $transaction);

        self::assertTrue($result->ok, $result->reason);
    }

    public function testRejectsComputeBudgetPriceAboveFeeSponsoredTightCap(): void
    {
        // audit #25: in fee-sponsored mode the server pays the priority fee, so
        // a price above the tight cap (but below the general 5M ceiling) is
        // rejected to prevent draining the merchant fee-payer.
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            extraInstructions: [
                ComputeBudgetProgram::setComputeUnitPrice(10_001),
            ],
        );
        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('compute unit price exceeds maximum', $result->reason);
    }

    public function testAcceptsComputeBudgetPriceUpToGeneralCapWhenClientPaysFees(): void
    {
        // audit #25 regression: when the client pays its own fees (no server
        // fee payer), the tight cap MUST NOT apply — the general 5M ceiling
        // holds, since there is no merchant fee-payer at risk.
        $fixture = $this->fixture();
        $request = $this->clientPaysRequest($fixture);
        $transaction = $this->clientPaysTransactionPayload(
            $fixture,
            ataPayer: $fixture['payer'],
            extraInstructions: [
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

    public function testPushPathSkipsComputeBudgetPriceCap(): void
    {
        // Rust validate_parsed_instruction_allowlist (charge.rs:1873-1876)
        // skips the compute-budget caps on the settled (push) path: a confirmed
        // transaction with an above-cap unit price is accepted. The pull-mode
        // pre-broadcast path still rejects it (asserted below), so this is the
        // exact pull-vs-push divergence the fix introduces.
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            extraInstructions: [ComputeBudgetProgram::setComputeUnitPrice(5_000_001)],
        );

        $pull = $this->verify($request, $transaction);
        self::assertFalse($pull->ok);
        self::assertSame('compute unit price exceeds maximum', $pull->reason);

        $push = (new SolanaChargeTransactionVerifier())
            ->verifyTransactionPayload($transaction, $request);
        self::assertTrue($push->ok, $push->reason);
    }

    public function testPushPathSkipsComputeBudgetLimitCap(): void
    {
        $fixture = $this->fixture();
        $request = $this->request($fixture);
        $transaction = $this->transactionPayload(
            $fixture,
            includeSplitAta: true,
            extraInstructions: [ComputeBudgetProgram::setComputeUnitLimit(200_001)],
        );

        $pull = $this->verify($request, $transaction);
        self::assertFalse($pull->ok);
        self::assertSame('compute unit limit exceeds maximum', $pull->reason);

        $push = (new SolanaChargeTransactionVerifier())
            ->verifyTransactionPayload($transaction, $request);
        self::assertTrue($push->ok, $push->reason);
    }

    public function testClientPaysAtaCreationPayerMustMatchTransactionFeePayer(): void
    {
        // Client-pays-fees mode (methodDetails.feePayer absent). Rust defaults
        // expected_ata_payer to the transaction fee payer
        // (charge.rs:1299-1305), so an ATA-create funded by any other account
        // is rejected. Before the fix PHP passed a null expected payer and
        // skipped this binding entirely.
        $fixture = $this->fixture();
        $request = $this->clientPaysRequest($fixture);

        $strangerPayer = PublicKey::fromBytes(str_repeat("\x0a", 32));
        $transaction = $this->clientPaysTransactionPayload($fixture, ataPayer: $strangerPayer);

        $result = $this->verify($request, $transaction);

        self::assertFalse($result->ok);
        self::assertSame('ATA payer must match the transaction fee payer', $result->reason);
    }

    public function testClientPaysAtaCreationByTransactionFeePayerAccepted(): void
    {
        // Happy-path guard for the fix: when the ATA-create payer is the
        // transaction fee payer (the client paying its own fees), the charge
        // still verifies.
        $fixture = $this->fixture();
        $request = $this->clientPaysRequest($fixture);
        $transaction = $this->clientPaysTransactionPayload($fixture, ataPayer: $fixture['payer']);

        $result = $this->verify($request, $transaction);

        self::assertTrue($result->ok, $result->reason);
    }

    /**
     * Client-pays-fees charge request: no server-side feePayer, so the client
     * is both the transaction fee payer and the ATA-creation payer.
     *
     * @param array<string, PublicKey> $fixture
     */
    private function clientPaysRequest(array $fixture): ChargeRequest
    {
        return new ChargeRequest(
            amount: '1000',
            currency: $fixture['mint']->toBase58(),
            recipient: $fixture['recipient']->toBase58(),
            externalId: 'order-123',
            methodDetails: [
                'network' => 'localnet',
                'decimals' => 6,
                'tokenProgram' => TokenProgram::PROGRAM_ID,
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
     * Build a client-pays transaction whose fee payer (and transfer authority)
     * is $fixture['payer'] but whose ATA-creation payer is configurable.
     *
     * @param array<string, PublicKey> $fixture
     * @param array<int, TransactionInstruction> $extraInstructions
     */
    private function clientPaysTransactionPayload(array $fixture, PublicKey $ataPayer, array $extraInstructions = []): string
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

        $instructions = [
            TokenProgram::transferChecked(
                $fixture['sourceTokenAccount'],
                $fixture['mint'],
                $recipientAta,
                $fixture['payer'],
                750,
                6,
                $tokenProgram,
            ),
            AssociatedTokenProgram::createIdempotent(
                $ataPayer,
                $splitAta,
                $fixture['splitRecipient'],
                $fixture['mint'],
                $tokenProgram,
            ),
            TokenProgram::transferChecked(
                $fixture['sourceTokenAccount'],
                $fixture['mint'],
                $splitAta,
                $fixture['payer'],
                250,
                6,
                $tokenProgram,
            ),
            MemoProgram::create('order-123'),
            MemoProgram::create('split memo'),
        ];
        array_push($instructions, ...$extraInstructions);

        $transaction = Transaction::new(
            $instructions,
            $fixture['payer'],
            str_repeat("\x09", 32),
        );

        return base64_encode($transaction->serialize(verifySignatures: false));
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

    private function verify(ChargeRequest $request, string $transaction): \PayKit\Protocols\Mpp\Server\VerificationResult
    {
        // Build the signed challenge directly (not via ChargeServer::createChallenge)
        // so these tests exercise verify-time behavior in isolation. Issuance-time
        // request validation (audit #19/#21/#38) is covered by ChargeServerTest;
        // here we want to feed the verifier requests that issuance would reject.
        $challenge = \PayKit\Protocols\Mpp\Core\Challenge::withSecret(
            secretKey: self::SECRET,
            realm: 'api',
            method: 'solana',
            intent: 'charge',
            request: $request->toArray(),
        );
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'transaction', 'transaction' => $transaction],
        );

        return (new SolanaChargeTransactionVerifier())->verify($credential, $challenge);
    }

    private const SECRET = 'test-secret-0123456789abcdef-0123456789';

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
