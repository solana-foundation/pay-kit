<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402\Exact;

use PayKit\Exception\InvalidProofException;
use PayKit\Protocols\X402\Exact\Verifier;
use PHPUnit\Framework\TestCase;

/**
 * Early-rejection path coverage for the x402 11-rule structural
 * verifier. Synthesising a fully-valid v0 transaction at PHPUnit
 * level requires reconstructing the Solana wire format byte-for-byte;
 * the happy path is exercised end-to-end by the harness matrix step
 * (rust-x402 client -> php server). These tests cover the rejection
 * branches that fire before the structural pass runs.
 */
final class VerifierTest extends TestCase
{
    public function testMalformedBase64Rejected(): void
    {
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/invalid_exact_svm_payload_base64/');
        Verifier::verify(
            '@@@-not-base64-@@@',
            ['asset' => 'mint', 'payTo' => 'recipient', 'amount' => '1000', 'extra' => ['tokenProgram' => 'tp', 'memo' => '/r']],
            ['facilitator'],
        );
    }

    public function testParseFailureRejected(): void
    {
        $this->expectException(InvalidProofException::class);
        Verifier::verify(
            base64_encode('not-a-transaction-payload'),
            ['asset' => 'mint', 'payTo' => 'recipient', 'amount' => '1000', 'extra' => ['tokenProgram' => 'tp', 'memo' => '/r']],
            ['facilitator'],
        );
    }

    public function testRuleConstantsCanonical(): void
    {
        // Smoke that the canonical program ids the verifier compares
        // against haven't drifted.
        $this->assertSame('ComputeBudget111111111111111111111111111111', Verifier::COMPUTE_BUDGET_PROGRAM);
        $this->assertSame('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', Verifier::MEMO_PROGRAM);
        $this->assertSame('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', Verifier::TOKEN_PROGRAM);
        $this->assertSame('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb', Verifier::TOKEN_2022_PROGRAM);
        // Official x402 SVM exact Lighthouse program id.
        $this->assertSame('L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95', Verifier::LIGHTHOUSE_PROGRAM);
        // Canonical compute-unit-price cap matches the Rust spine
        // (rust/crates/x402/src/protocol/schemes/exact/verify.rs:17).
        $this->assertSame(5000000, Verifier::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS);
    }

    public function testAssociatedTokenProgramConstantRemoved(): void
    {
        // The optional-slot allowlist is Lighthouse + Memo ONLY; the
        // destination ATA must pre-exist. The Associated Token Program
        // ATA-create path was removed, so the constant must not exist.
        $this->assertFalse(
            defined(Verifier::class . '::ASSOCIATED_TOKEN_PROGRAM'),
            'ASSOCIATED_TOKEN_PROGRAM must be removed: ATA-create is not an allowed optional slot',
        );
    }
}
