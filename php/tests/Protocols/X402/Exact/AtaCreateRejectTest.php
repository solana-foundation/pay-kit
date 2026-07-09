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
 * End-to-end structural-verifier coverage for Decision 1: the optional
 * instruction allowlist is Lighthouse + Memo ONLY. An Associated Token
 * Program ATA-create instruction MUST be rejected; the destination ATA
 * must pre-exist. Wallet-injected Lighthouse guards MUST be accepted.
 *
 * Builds a real v0 wire transaction so the verifier's deserialize +
 * structural pass run exactly as in production.
 */
final class AtaCreateRejectTest extends TestCase
{
    private const COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111';
    private const TOKEN_PROGRAM  = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
    private const MEMO_PROGRAM   = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
    private const LIGHTHOUSE     = 'L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95';
    private const ATA_PROGRAM    = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
    private const USDC_MINT      = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

    /**
     * Assemble the always-present prefix (compute limit/price + transfer)
     * plus the supplied optional instructions into a base64 wire tx, and
     * return [base64, requirement].
     *
     * @param list<array{program:string,data:string,accounts:list<string>}> $optionals
     * @return array{0:string,1:array<string,mixed>}
     */
    private function buildTransaction(array $optionals): array
    {
        $payer     = Keypair::generate()->getPublicKey()->toBase58();
        $authority = Keypair::generate()->getPublicKey()->toBase58();
        $source    = Keypair::generate()->getPublicKey()->toBase58();
        $payTo     = Keypair::generate()->getPublicKey()->toBase58();
        $mint      = self::USDC_MINT;
        $tokenProgram = self::TOKEN_PROGRAM;
        $destination  = Mints::deriveAta($payTo, $mint, $tokenProgram);
        $amount = 100000;

        // Instruction data blobs.
        $computeLimitData = chr(2) . pack('V', 200000);            // tag 2 + u32
        $computePriceData = chr(3) . pack('P', 1);                 // tag 3 + u64
        $transferData     = chr(12) . pack('P', $amount) . chr(6); // tag 12 + u64 + u8 decimals

        // Build the ordered account-key table and an index resolver.
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
            $computeLimitData,
        );
        $instructions[] = new CompiledInstructionV0(
            $indexOf(self::COMPUTE_BUDGET),
            [],
            $computePriceData,
        );
        $instructions[] = new CompiledInstructionV0(
            $indexOf($tokenProgram),
            [$indexOf($source), $indexOf($mint), $indexOf($destination), $indexOf($authority)],
            $transferData,
        );
        foreach ($optionals as $opt) {
            $accountIdxs = array_map($indexOf, $opt['accounts']);
            $instructions[] = new CompiledInstructionV0(
                $indexOf($opt['program']),
                $accountIdxs,
                $opt['data'],
            );
        }

        // Ensure the fee payer is the first account (required signer).
        array_unshift($keys, $payer);
        // Re-resolve every index now that we prepended one key: shift by 1.
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
            'asset'  => $mint,
            'payTo'  => $payTo,
            'amount' => (string) $amount,
            'extra'  => ['tokenProgram' => $tokenProgram, 'memo' => ''],
        ];

        return [base64_encode($wire), $requirement];
    }

    public function testTransactionWithoutOptionalsVerifies(): void
    {
        [$tx, $req] = $this->buildTransaction([]);
        $result = Verifier::verify($tx, $req, ['someFacilitatorPubkeyThatIsNotInTx']);
        $this->assertSame(self::TOKEN_PROGRAM, $result['program']);
        $this->assertSame(100000, $result['amount']);
        $this->assertArrayNotHasKey('destinationCreateAta', $result);
    }

    public function testLighthouseOptionalInstructionAccepted(): void
    {
        // Wallets (Phantom 1, Solflare 2) inject Lighthouse guard
        // instructions; the verifier MUST allow them in optional slots.
        [$tx, $req] = $this->buildTransaction([
            ['program' => self::LIGHTHOUSE, 'data' => chr(0), 'accounts' => []],
            ['program' => self::LIGHTHOUSE, 'data' => chr(0), 'accounts' => []],
        ]);
        $result = Verifier::verify($tx, $req, ['someFacilitatorPubkeyThatIsNotInTx']);
        $this->assertSame(100000, $result['amount']);
    }

    public function testMemoOptionalInstructionAccepted(): void
    {
        [$tx, $req] = $this->buildTransaction([
            ['program' => self::MEMO_PROGRAM, 'data' => 'abc123nonce', 'accounts' => []],
        ]);
        $result = Verifier::verify($tx, $req, ['someFacilitatorPubkeyThatIsNotInTx']);
        $this->assertSame(100000, $result['amount']);
    }

    public function testOfferWithoutExtraTokenProgramStillVerifies(): void
    {
        // Rule 11 transfer-program binding. Rust derives the program-id gate
        // from the actual transfer instruction (verify.rs:373), accepting any
        // canonical Token / Token-2022 transfer; it does NOT require a
        // seller-pinned extra.tokenProgram. An offer that omits it must still
        // verify a real Token-program transfer rather than rejecting with
        // missing_extra_tokenProgram.
        [$tx, $req] = $this->buildTransaction([]);
        unset($req['extra']['tokenProgram']);

        $result = Verifier::verify($tx, $req, ['someFacilitatorPubkeyThatIsNotInTx']);

        $this->assertSame(self::TOKEN_PROGRAM, $result['program']);
        $this->assertSame(100000, $result['amount']);
    }

    public function testAtaCreateOptionalInstructionRejected(): void
    {
        // An Associated-Token-Program create instruction must NOT be an
        // allowed optional slot. The destination ATA must pre-exist.
        [$tx, $req] = $this->buildTransaction([
            [
                'program'  => self::ATA_PROGRAM,
                'data'     => chr(1), // idempotent-create discriminator
                'accounts' => [
                    Keypair::generate()->getPublicKey()->toBase58(), // payer
                    Keypair::generate()->getPublicKey()->toBase58(), // ata
                    Keypair::generate()->getPublicKey()->toBase58(), // owner
                    self::USDC_MINT,
                    '11111111111111111111111111111111',              // system
                    self::TOKEN_PROGRAM,
                ],
            ],
        ]);
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/unknown_fourth_instruction/');
        Verifier::verify($tx, $req, ['someFacilitatorPubkeyThatIsNotInTx']);
    }
}
