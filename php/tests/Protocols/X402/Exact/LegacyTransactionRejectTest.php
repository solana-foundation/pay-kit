<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402\Exact;

use PayKit\Exception\InvalidProofException;
use PayKit\Protocols\X402\Exact\Verifier;
use PHPUnit\Framework\TestCase;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Transaction\Message;
use SolanaPhpSdk\Transaction\Transaction;

/**
 * A legacy (unprefixed) Solana message is rejected at the x402 decode
 * boundary with the shared parse reject code and the project-wide reason
 * text, before any structural rule runs.
 */
final class LegacyTransactionRejectTest extends TestCase
{
    public function testLegacyMessageIsRejectedAtDecodeBoundary(): void
    {
        $signer = Keypair::generate();
        $message = new Message(
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0,
            accountKeys: [$signer->getPublicKey()],
            recentBlockhash: str_repeat("\x01", 32),
            instructions: [],
        );
        $wire = base64_encode((new Transaction($message))->serialize(verifySignatures: false));
        $requirement = ['asset' => '', 'payTo' => '', 'amount' => '1', 'extra' => []];

        try {
            Verifier::verify($wire, $requirement, []);
            self::fail('expected InvalidProofException');
        } catch (InvalidProofException $e) {
            self::assertSame(
                'invalid_exact_svm_payload_transaction_parse: legacy transactions are not supported; use a version 0 or version 1 message',
                $e->getMessage(),
            );
        }
    }
}
