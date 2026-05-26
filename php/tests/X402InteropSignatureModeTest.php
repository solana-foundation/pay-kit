<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use PHPUnit\Framework\TestCase;

use function SolanaMpp\X402\Interop\is_valid_base58_signature;
use function SolanaMpp\X402\Interop\verify_transaction_details;
use function SolanaMpp\X402\Interop\base58_encode_binary;
use function SolanaMpp\X402\Interop\associated_token_address;
use function SolanaMpp\X402\Interop\public_key_from_base58;

use const SolanaMpp\X402\Interop\DEFAULT_TOKEN_PROGRAM;

require_once __DIR__ . '/../src/x402/InteropServer.php';

/**
 * Regression coverage for the PaymentProof signature-mode path
 * (`rust/crates/x402/src/server/exact.rs` `PaymentProof::Signature` +
 * `protocol::schemes::exact::verify::verify_transaction_details`).
 *
 * The PHP interop server previously only accepted the
 * `payload.transaction` envelope variant, silently rejecting honest
 * clients that broadcast the transaction themselves and submit the
 * resulting on-chain signature. These tests pin down the signature
 * validator and the on-chain re-verification helper independently of
 * the full settle_exact_payment flow (covered by the procedural
 * regression suite).
 */
final class X402InteropSignatureModeTest extends TestCase
{
    private const ASSET = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'; // USDC devnet.
    private const PAY_TO = '7e7uXmkjyy3hVoEHaCEdjvX2yjK7y9bk6zMyf3jR58CC';

    /**
     * @return array{0: array<string, mixed>, 1: array<string, mixed>}
     */
    private function fixtureRequirementAndConfirmedTransaction(): array
    {
        $requirement = [
            'scheme' => 'exact',
            'network' => 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
            'asset' => self::ASSET,
            'amount' => '1000',
            'payTo' => self::PAY_TO,
            'maxTimeoutSeconds' => 60,
            'extra' => [
                'feePayer' => self::PAY_TO,
                'decimals' => 6,
                'tokenProgram' => DEFAULT_TOKEN_PROGRAM,
            ],
        ];
        $destination = base58_encode_binary(
            associated_token_address(
                public_key_from_base58(self::PAY_TO, 'payTo'),
                public_key_from_base58(DEFAULT_TOKEN_PROGRAM, 'tokenProgram'),
                public_key_from_base58(self::ASSET, 'asset'),
            ),
        );
        $confirmed = [
            'meta' => ['err' => null],
            'transaction' => [
                'message' => [
                    'accountKeys' => [],
                    'instructions' => [
                        [
                            'programId' => DEFAULT_TOKEN_PROGRAM,
                            'parsed' => [
                                'type' => 'transferChecked',
                                'info' => [
                                    'destination' => $destination,
                                    'mint' => self::ASSET,
                                    'tokenAmount' => [
                                        'amount' => '1000',
                                        'decimals' => 6,
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];

        return [$requirement, $confirmed];
    }

    public function testIsValidBase58SignatureAcceptsCanonicalLength(): void
    {
        // 64 zero bytes -> 64 leading '1' characters in base58.
        self::assertTrue(is_valid_base58_signature(str_repeat('1', 64)));
        // 64 high-bit bytes -> ~87-88 base58 characters.
        self::assertTrue(is_valid_base58_signature(base58_encode_binary(str_repeat("\xff", 64))));
    }

    public function testIsValidBase58SignatureRejectsMalformed(): void
    {
        self::assertFalse(is_valid_base58_signature(''));
        self::assertFalse(is_valid_base58_signature('too-short'));
        // Contains characters outside the base58 alphabet.
        self::assertFalse(is_valid_base58_signature(str_repeat('!', 80)));
        // Wrong byte length when decoded (32 bytes != 64).
        self::assertFalse(is_valid_base58_signature(base58_encode_binary(str_repeat("\x00", 32))));
    }

    public function testVerifyTransactionDetailsAcceptsCanonicalTransfer(): void
    {
        [$requirement, $confirmed] = $this->fixtureRequirementAndConfirmedTransaction();
        verify_transaction_details($confirmed, $requirement);
        self::assertTrue(true);
    }

    public function testVerifyTransactionDetailsRejectsWrongAmount(): void
    {
        [$requirement, $confirmed] = $this->fixtureRequirementAndConfirmedTransaction();
        $confirmed['transaction']['message']['instructions'][0]['parsed']['info']['tokenAmount']['amount'] = '999';
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid_exact_svm_payload_no_transfer_instruction');
        verify_transaction_details($confirmed, $requirement);
    }

    public function testVerifyTransactionDetailsRejectsWrongDestination(): void
    {
        [$requirement, $confirmed] = $this->fixtureRequirementAndConfirmedTransaction();
        $confirmed['transaction']['message']['instructions'][0]['parsed']['info']['destination'] = '11111111111111111111111111111111';
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid_exact_svm_payload_no_transfer_instruction');
        verify_transaction_details($confirmed, $requirement);
    }

    public function testVerifyTransactionDetailsRejectsFailedOnChain(): void
    {
        [$requirement, $confirmed] = $this->fixtureRequirementAndConfirmedTransaction();
        $confirmed['meta']['err'] = ['InstructionError' => [0, 'Custom']];
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid_exact_svm_payload_settlement_transaction_failed');
        verify_transaction_details($confirmed, $requirement);
    }

    public function testVerifyTransactionDetailsRejectsWrongTokenProgram(): void
    {
        [$requirement, $confirmed] = $this->fixtureRequirementAndConfirmedTransaction();
        $confirmed['transaction']['message']['instructions'][0]['programId'] = '11111111111111111111111111111111';
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid_exact_svm_payload_no_transfer_instruction');
        verify_transaction_details($confirmed, $requirement);
    }
}
