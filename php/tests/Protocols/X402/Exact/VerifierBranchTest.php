<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402\Exact;

use PayKit\Exception\InvalidProofException;
use PayKit\PayCore\Solana\Mints;
use PayKit\Protocols\X402\Exact\Verifier;
use PHPUnit\Framework\TestCase;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Transaction\CompiledInstructionV0;
use SolanaPhpSdk\Transaction\MessageV0;
use SolanaPhpSdk\Transaction\VersionedTransaction;
use SolanaPhpSdk\Util\Base58;

/**
 * Full-branch coverage for the x402 11-rule structural verifier. Builds
 * real v0 wire transactions (so deserialize + the whole structural pass
 * run exactly as in production), then mutates a single field per test to
 * exercise every rejection branch: instruction-count bounds, the two
 * compute-budget instructions, the transfer program/data/account guards,
 * the authority (fee-payer) guard, mint / recipient / amount matching,
 * the optional-slot allowlist, and memo binding.
 */
final class VerifierBranchTest extends TestCase
{
    private const COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111';
    private const TOKEN_PROGRAM  = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
    private const TOKEN_2022     = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
    private const MEMO_PROGRAM   = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
    private const LIGHTHOUSE     = 'L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95';
    private const USDC_MINT      = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

    private const MAX_PRICE = 5000000;

    /**
     * Assemble a transfer transaction from tunable knobs and return
     * [base64Wire, requirement, managedSigners].
     *
     * @param array<string,mixed> $opts
     * @return array{0:string,1:array<string,mixed>,2:list<string>}
     */
    private function build(array $opts = []): array
    {
        $feePayer  = $opts['feePayer']  ?? Keypair::generate()->getPublicKey()->toBase58();
        $authority = $opts['authority'] ?? Keypair::generate()->getPublicKey()->toBase58();
        $source    = $opts['source']    ?? Keypair::generate()->getPublicKey()->toBase58();
        $payTo     = $opts['payTo']     ?? Keypair::generate()->getPublicKey()->toBase58();
        $mint      = $opts['mint']      ?? self::USDC_MINT;
        $tokenProgram = $opts['tokenProgram'] ?? self::TOKEN_PROGRAM;
        $amount    = $opts['amount']    ?? 100000;
        $memo      = $opts['memo']      ?? '';

        $destination = $opts['destination'] ?? Mints::deriveAta($payTo, $mint, $tokenProgram);

        // Instruction data blobs (tunable tags/lengths for the compute
        // instructions so the malformed branches can be reached).
        $computeLimitData = $opts['computeLimitData']
            ?? chr(2) . pack('V', 200000);          // tag 2 + u32
        $computePrice = $opts['computePrice'] ?? 1;
        $computePriceData = $opts['computePriceData']
            ?? chr(3) . pack('P', $computePrice);   // tag 3 + u64
        $transferData = $opts['transferData']
            ?? chr(12) . pack('P', $amount) . chr(6); // tag 12 + u64 + u8 decimals

        // Transfer account slots (source, mint, destination, authority).
        /** @var list<string> $transferAccounts */
        $transferAccounts = $opts['transferAccounts']
            ?? [$source, $mint, $destination, $authority];

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
        $instructions[] = new CompiledInstructionV0($indexOf(self::COMPUTE_BUDGET), [], $computeLimitData);
        $instructions[] = new CompiledInstructionV0($indexOf(self::COMPUTE_BUDGET), [], $computePriceData);
        $instructions[] = new CompiledInstructionV0(
            $indexOf($tokenProgram),
            array_map($indexOf, $transferAccounts),
            $transferData,
        );

        /** @var list<array{program:string,data:string,accounts:list<string>}> $optionals */
        $optionals = $opts['optionals'] ?? [];
        foreach ($optionals as $opt) {
            $instructions[] = new CompiledInstructionV0(
                $indexOf($opt['program']),
                array_map($indexOf, $opt['accounts']),
                $opt['data'],
            );
        }

        // Fee payer is the required first signer.
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
        $wire = $tx->serialize(verifySignatures: false);

        $requirement = [
            'asset'  => $opts['reqAsset']  ?? $mint,
            'payTo'  => $opts['reqPayTo']  ?? $payTo,
            'amount' => (string) ($opts['reqAmount'] ?? $amount),
            'extra'  => ['tokenProgram' => $tokenProgram, 'memo' => $opts['reqMemo'] ?? $memo],
        ];

        $managed = $opts['managed'] ?? ['unrelatedFacilitatorPubkeyNotInTx'];

        return [base64_encode($wire), $requirement, $managed];
    }

    private function expectReject(string $substr): void
    {
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/' . preg_quote($substr, '/') . '/');
    }

    // ── happy path ─────────────────────────────────────────────────────────

    public function testValidTransferVerifies(): void
    {
        [$tx, $req, $managed] = $this->build();
        $result = Verifier::verify($tx, $req, $managed);
        $this->assertSame(self::TOKEN_PROGRAM, $result['program']);
        $this->assertSame('100000', $result['amount']);
        $this->assertArrayHasKey('source', $result);
        $this->assertArrayHasKey('mint', $result);
        $this->assertArrayHasKey('destination', $result);
        $this->assertArrayHasKey('authority', $result);
    }

    public function testValidTransferWithToken2022ProgramVerifies(): void
    {
        [$tx, $req, $managed] = $this->build(['tokenProgram' => self::TOKEN_2022]);
        $result = Verifier::verify($tx, $req, $managed);
        $this->assertSame(self::TOKEN_2022, $result['program']);
    }

    public function testValidTransferWithMemoBindingVerifies(): void
    {
        [$tx, $req, $managed] = $this->build([
            'memo'    => '/paid',
            'reqMemo' => '/paid',
            'optionals' => [
                ['program' => self::MEMO_PROGRAM, 'data' => '/paid', 'accounts' => []],
            ],
        ]);
        $result = Verifier::verify($tx, $req, $managed);
        $this->assertSame('100000', $result['amount']);
    }

    public function testComputePriceAtMaxVerifies(): void
    {
        [$tx, $req, $managed] = $this->build(['computePrice' => self::MAX_PRICE]);
        $result = Verifier::verify($tx, $req, $managed);
        $this->assertSame('100000', $result['amount']);
    }

    // ── rule 1: instruction count ───────────────────────────────────────────

    public function testTooFewInstructionsRejected(): void
    {
        // Only the two compute instructions (no transfer) is below the floor.
        [$tx, $req] = $this->twoInstructionTx();
        $this->expectReject('instructions_length');
        Verifier::verify($tx, $req, ['facilitator']);
    }

    public function testTooManyInstructionsRejected(): void
    {
        // 3 optional Lighthouse slots -> 6 total is the max; add a 4th
        // optional to push to 7 which is over the bound.
        [$tx, $req, $managed] = $this->build([
            'optionals' => [
                ['program' => self::LIGHTHOUSE, 'data' => chr(0), 'accounts' => []],
                ['program' => self::LIGHTHOUSE, 'data' => chr(0), 'accounts' => []],
                ['program' => self::LIGHTHOUSE, 'data' => chr(0), 'accounts' => []],
                ['program' => self::LIGHTHOUSE, 'data' => chr(0), 'accounts' => []],
            ],
        ]);
        $this->expectReject('instructions_length');
        Verifier::verify($tx, $req, $managed);
    }

    /**
     * A 2-instruction transaction (below the count floor of 3).
     *
     * @return array{0:string,1:array<string,mixed>}
     */
    private function twoInstructionTx(): array
    {
        $feePayer = Keypair::generate()->getPublicKey()->toBase58();
        $keys = [];
        $indexOf = function (string $addr) use (&$keys): int {
            $i = array_search($addr, $keys, true);
            if ($i === false) {
                $keys[] = $addr;
                return count($keys) - 1;
            }
            return $i;
        };
        $instructions = [
            new CompiledInstructionV0($indexOf(self::COMPUTE_BUDGET), [], chr(2) . pack('V', 200000)),
            new CompiledInstructionV0($indexOf(self::COMPUTE_BUDGET), [], chr(3) . pack('P', 1)),
        ];
        array_unshift($keys, $feePayer);
        foreach ($instructions as $ix) {
            $ix->programIdIndex += 1;
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
        $wire = $tx->serialize(verifySignatures: false);
        $req = [
            'asset'  => self::USDC_MINT,
            'payTo'  => Keypair::generate()->getPublicKey()->toBase58(),
            'amount' => '100000',
            'extra'  => ['tokenProgram' => self::TOKEN_PROGRAM, 'memo' => ''],
        ];
        return [base64_encode($wire), $req];
    }

    // ── rule 2: compute-unit-limit ──────────────────────────────────────────

    public function testWrongComputeLimitTagRejected(): void
    {
        [$tx, $req, $managed] = $this->build(['computeLimitData' => chr(9) . pack('V', 200000)]);
        $this->expectReject('compute_limit_instruction');
        Verifier::verify($tx, $req, $managed);
    }

    public function testWrongComputeLimitLengthRejected(): void
    {
        [$tx, $req, $managed] = $this->build(['computeLimitData' => chr(2) . 'xx']);
        $this->expectReject('compute_limit_instruction');
        Verifier::verify($tx, $req, $managed);
    }

    // ── rule 3: compute-unit-price ──────────────────────────────────────────

    public function testWrongComputePriceTagRejected(): void
    {
        [$tx, $req, $managed] = $this->build(['computePriceData' => chr(7) . pack('P', 1)]);
        $this->expectReject('compute_price_instruction');
        Verifier::verify($tx, $req, $managed);
    }

    public function testComputePriceTooHighRejected(): void
    {
        [$tx, $req, $managed] = $this->build(['computePrice' => self::MAX_PRICE + 1]);
        $this->expectReject('compute_price_instruction_too_high');
        Verifier::verify($tx, $req, $managed);
    }

    // ── rule 4/11: transfer program + data ──────────────────────────────────

    public function testNonTokenProgramTransferRejected(): void
    {
        // Point the "transfer" slot at a non-token program id.
        [$tx, $req, $managed] = $this->build(['tokenProgram' => self::LIGHTHOUSE]);
        $this->expectReject('no_transfer_instruction');
        Verifier::verify($tx, $req, $managed);
    }

    public function testWrongTransferTagRejected(): void
    {
        [$tx, $req, $managed] = $this->build(['transferData' => chr(3) . pack('P', 100000) . chr(6)]);
        $this->expectReject('no_transfer_instruction');
        Verifier::verify($tx, $req, $managed);
    }

    public function testWrongTransferDataLengthRejected(): void
    {
        [$tx, $req, $managed] = $this->build(['transferData' => chr(12) . pack('P', 100000)]);
        $this->expectReject('no_transfer_instruction');
        Verifier::verify($tx, $req, $managed);
    }

    public function testTooFewTransferAccountsRejected(): void
    {
        [$tx, $req, $managed] = $this->build([
            'transferAccounts' => [
                Keypair::generate()->getPublicKey()->toBase58(),
                Keypair::generate()->getPublicKey()->toBase58(),
                Keypair::generate()->getPublicKey()->toBase58(),
            ],
        ]);
        $this->expectReject('no_transfer_instruction');
        Verifier::verify($tx, $req, $managed);
    }

    // ── rule 5: authority (fee-payer) guard ─────────────────────────────────

    public function testManagedSignerAsAuthorityRejected(): void
    {
        $managedAuth = Keypair::generate()->getPublicKey()->toBase58();
        [$tx, $req, $managed] = $this->build([
            'authority' => $managedAuth,
            'managed'   => [$managedAuth],
        ]);
        $this->expectReject('fee_payer_transferring_funds');
        Verifier::verify($tx, $req, $managed);
    }

    public function testManagedSignerAsSourceRejected(): void
    {
        $managedSrc = Keypair::generate()->getPublicKey()->toBase58();
        [$tx, $req, $managed] = $this->build([
            'source'  => $managedSrc,
            'managed' => [$managedSrc],
        ]);
        $this->expectReject('fee_payer_transferring_funds');
        Verifier::verify($tx, $req, $managed);
    }

    public function testManagedSignerAsSourceAtaRejected(): void
    {
        // The transfer authority is a legitimate customer key, but the source
        // ATA is the managed signer's OWN associated token account for the
        // mint. The canonical fund-mover guard must reject this drain even
        // though the managed signer is neither the raw source nor authority.
        $managed = Keypair::generate()->getPublicKey()->toBase58();
        $managedAta = Mints::deriveAta($managed, self::USDC_MINT, self::TOKEN_PROGRAM);
        [$tx, $req, $signers] = $this->build([
            'source'  => $managedAta,
            'managed' => [$managed],
        ]);
        $this->expectReject('fee_payer_transferring_funds');
        Verifier::verify($tx, $req, $signers);
    }

    public function testManagedSignerAsMintIsAccepted(): void
    {
        // A managed signer that is neither the transfer authority nor the
        // funding source, but merely appears elsewhere in the transfer's
        // account list (here as the mint slot), is NOT a fund move. The
        // canonical rule accepts it, matching the Rust reference and the
        // Go/Python/Ruby/Lua verifiers (the old over-broad instruction-
        // account sweep rejected this benign reference).
        $managedMint = self::USDC_MINT;
        [$tx, $req, $managed] = $this->build([
            'managed' => [$managedMint],
        ]);
        Verifier::verify($tx, $req, $managed);
        $this->addToAssertionCount(1);
    }

    // ── rule 6: mint match ──────────────────────────────────────────────────

    public function testWrongMintRejected(): void
    {
        [$tx, $req, $managed] = $this->build([
            'reqAsset' => 'So11111111111111111111111111111111111111112',
        ]);
        $this->expectReject('mint_mismatch');
        Verifier::verify($tx, $req, $managed);
    }

    // ── rule 7: destination ATA match ───────────────────────────────────────

    public function testWrongRecipientRejected(): void
    {
        // Destination ATA in the tx does not re-derive from the required payTo.
        [$tx, $req, $managed] = $this->build([
            'destination' => Keypair::generate()->getPublicKey()->toBase58(),
        ]);
        $this->expectReject('recipient_mismatch');
        Verifier::verify($tx, $req, $managed);
    }

    // ── rule 8: amount match (overpay / underpay / mismatch) ────────────────

    public function testUnderpayRejected(): void
    {
        [$tx, $req, $managed] = $this->build([
            'amount'    => 99999,
            'reqAmount' => 100000,
        ]);
        $this->expectReject('amount_mismatch');
        Verifier::verify($tx, $req, $managed);
    }

    public function testOverpayRejected(): void
    {
        [$tx, $req, $managed] = $this->build([
            'amount'    => 100001,
            'reqAmount' => 100000,
        ]);
        $this->expectReject('amount_mismatch');
        Verifier::verify($tx, $req, $managed);
    }

    public function testHighBitU64AmountComparesExactly(): void
    {
        // 2^63 — above PHP_INT_MAX as an unsigned wire value. A native
        // `(int)` requirement cast saturates and `unpack('P')` goes
        // negative, so before the BigInteger path this exact payment was
        // rejected as an amount mismatch.
        $high = '9223372036854775808';
        [$tx, $req, $managed] = $this->build([
            'reqAmount'    => $high,
            'transferData' => chr(12) . "\x00\x00\x00\x00\x00\x00\x00\x80" . chr(6),
        ]);
        $result = Verifier::verify($tx, $req, $managed);
        $this->assertSame($high, $result['amount']);
    }

    public function testU64MaxAmountComparesExactly(): void
    {
        $max = '18446744073709551615';
        [$tx, $req, $managed] = $this->build([
            'reqAmount'    => $max,
            'transferData' => chr(12) . str_repeat("\xff", 8) . chr(6),
        ]);
        $result = Verifier::verify($tx, $req, $managed);
        $this->assertSame($max, $result['amount']);
    }

    public function testHighBitU64AmountMismatchStillRejected(): void
    {
        // Same high-bit wire amount (2^63) against a requirement one unit
        // higher: both used to collapse under native-int handling and the
        // comparison could no longer tell exact from wrong.
        [$tx, $req, $managed] = $this->build([
            'reqAmount'    => '9223372036854775809',
            'transferData' => chr(12) . "\x00\x00\x00\x00\x00\x00\x00\x80" . chr(6),
        ]);
        $this->expectReject('amount_mismatch');
        Verifier::verify($tx, $req, $managed);
    }

    public function testAmountAboveU64RangeFailsClosed(): void
    {
        // 2^64 — not representable on the wire; the requirement itself is
        // invalid and must fail closed instead of wrapping or saturating.
        [$tx, $req, $managed] = $this->build([
            'reqAmount' => '18446744073709551616',
        ]);
        $this->expectReject('missing_field_amount');
        Verifier::verify($tx, $req, $managed);
    }

    // ── rule 9: optional-slot allowlist ─────────────────────────────────────

    public function testUnknownFourthInstructionRejected(): void
    {
        [$tx, $req, $managed] = $this->build([
            'optionals' => [
                ['program' => self::COMPUTE_BUDGET, 'data' => chr(0), 'accounts' => []],
            ],
        ]);
        $this->expectReject('unknown_fourth_instruction');
        Verifier::verify($tx, $req, $managed);
    }

    public function testUnknownFifthInstructionRejected(): void
    {
        [$tx, $req, $managed] = $this->build([
            'optionals' => [
                ['program' => self::LIGHTHOUSE, 'data' => chr(0), 'accounts' => []],
                ['program' => self::COMPUTE_BUDGET, 'data' => chr(0), 'accounts' => []],
            ],
        ]);
        $this->expectReject('unknown_fifth_instruction');
        Verifier::verify($tx, $req, $managed);
    }

    public function testUnknownSixthInstructionRejected(): void
    {
        [$tx, $req, $managed] = $this->build([
            'optionals' => [
                ['program' => self::LIGHTHOUSE, 'data' => chr(0), 'accounts' => []],
                ['program' => self::LIGHTHOUSE, 'data' => chr(0), 'accounts' => []],
                ['program' => self::COMPUTE_BUDGET, 'data' => chr(0), 'accounts' => []],
            ],
        ]);
        $this->expectReject('unknown_sixth_instruction');
        Verifier::verify($tx, $req, $managed);
    }

    // ── rule 10: memo binding ───────────────────────────────────────────────

    public function testMissingMemoWhenRequiredRejected(): void
    {
        // Offer requires a memo but the tx carries none.
        [$tx, $req, $managed] = $this->build([
            'reqMemo' => '/paid',
        ]);
        $this->expectReject('memo_count');
        Verifier::verify($tx, $req, $managed);
    }

    public function testDuplicateMemoRejected(): void
    {
        [$tx, $req, $managed] = $this->build([
            'reqMemo' => '/paid',
            'optionals' => [
                ['program' => self::MEMO_PROGRAM, 'data' => '/paid', 'accounts' => []],
                ['program' => self::MEMO_PROGRAM, 'data' => '/paid', 'accounts' => []],
            ],
        ]);
        $this->expectReject('memo_count');
        Verifier::verify($tx, $req, $managed);
    }

    public function testMemoMismatchRejected(): void
    {
        [$tx, $req, $managed] = $this->build([
            'reqMemo' => '/paid',
            'optionals' => [
                ['program' => self::MEMO_PROGRAM, 'data' => '/wrong', 'accounts' => []],
            ],
        ]);
        $this->expectReject('memo_mismatch');
        Verifier::verify($tx, $req, $managed);
    }

    // ── field guards (missing asset / payTo / amount) ───────────────────────

    public function testMissingAssetFieldRejected(): void
    {
        [$tx, , $managed] = $this->build();
        $req = ['payTo' => 'x', 'amount' => '100000', 'extra' => ['tokenProgram' => self::TOKEN_PROGRAM, 'memo' => '']];
        $this->expectReject('missing_field_asset');
        Verifier::verify($tx, $req, $managed);
    }

    public function testMissingPayToFieldRejected(): void
    {
        [$tx, , $managed] = $this->build();
        $req = ['asset' => self::USDC_MINT, 'amount' => '100000', 'extra' => ['tokenProgram' => self::TOKEN_PROGRAM, 'memo' => '']];
        $this->expectReject('missing_field_payTo');
        Verifier::verify($tx, $req, $managed);
    }

    public function testMissingAmountFieldRejected(): void
    {
        // asset + payTo present so the amount guard is reached; amount is a
        // non-string/non-int value.
        $payTo = Keypair::generate()->getPublicKey()->toBase58();
        [$tx, , $managed] = $this->build(['payTo' => $payTo]);
        $req = [
            'asset'  => self::USDC_MINT,
            'payTo'  => $payTo,
            'amount' => ['not', 'a', 'scalar'],
            'extra'  => ['tokenProgram' => self::TOKEN_PROGRAM, 'memo' => ''],
        ];
        $this->expectReject('missing_field_amount');
        Verifier::verify($tx, $req, $managed);
    }

    public function testAmountFromMaxAmountRequiredFallback(): void
    {
        // When `amount` is absent the verifier falls back to
        // `maxAmountRequired`.
        $payTo = Keypair::generate()->getPublicKey()->toBase58();
        [$tx, , $managed] = $this->build(['payTo' => $payTo]);
        $req = [
            'asset'             => self::USDC_MINT,
            'payTo'             => $payTo,
            'maxAmountRequired' => '100000',
            'extra'             => ['tokenProgram' => self::TOKEN_PROGRAM, 'memo' => ''],
        ];
        $result = Verifier::verify($tx, $req, $managed);
        $this->assertSame('100000', $result['amount']);
    }
}
