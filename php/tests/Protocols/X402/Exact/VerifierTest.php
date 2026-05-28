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
        $this->assertSame('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb', Verifier::TOKEN_2022_PROGRAM);
        $this->assertSame('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL', Verifier::ASSOCIATED_TOKEN_PROGRAM);
        $this->assertSame(50000, Verifier::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS);
    }
}
