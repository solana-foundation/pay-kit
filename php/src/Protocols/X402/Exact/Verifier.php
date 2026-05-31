<?php

declare(strict_types=1);

namespace PayKit\Protocols\X402\Exact;

use PayKit\Exception\InvalidProofException;
use PayKit\PayCore\Solana\Mints;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Transaction\VersionedTransaction;
use Throwable;

/**
 * x402 SVM-exact 11-rule structural verifier. PHP port of the Lua
 * reference at lua/pay_kit/protocols/x402/exact/verify.lua, itself a
 * port of the Ruby gem at ruby/lib/x402/protocol/schemes/exact/verify.rb
 * and the Rust spine at rust/crates/x402/src/protocol/schemes/exact/verify.rs.
 *
 * Raises {@see InvalidProofException} with the same canonical reject
 * strings the cross-language harness substring-matches against.
 *
 * Rules:
 *   1. Instruction count 3..=6
 *   2. ix[0] = ComputeBudget SetComputeUnitLimit
 *   3. ix[1] = ComputeBudget SetComputeUnitPrice <= MAX
 *   4. ix[2] = SPL TransferChecked
 *   5. Authority guard (no fee-payer in transfer auth)
 *   6. Mint match
 *   7. Destination ATA match (re-derived)
 *   8. Amount match
 *   9. ix[3..6] in allowlist (Lighthouse + Memo ONLY). Per the official
 *      x402 SVM exact contract the destination ATA MUST pre-exist; an
 *      Associated-Token-Program create instruction is NOT an allowed
 *      optional slot. Wallets inject Lighthouse guard instructions
 *      (Phantom 1, Solflare 2), so Lighthouse is allowed in any optional
 *      slot.
 *  10. Memo binding (exactly one if extra.memo set)
 *  11. Token program strict bind to extra.tokenProgram
 */
final class Verifier
{
    public const COMPUTE_BUDGET_PROGRAM    = 'ComputeBudget111111111111111111111111111111';
    public const MEMO_PROGRAM              = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
    // Official x402 SVM exact Lighthouse program id (specs/schemes/exact/
    // scheme_exact_svm.md). The prior `L1TEVtgA75k...` value was wrong and
    // would have rejected wallet-injected Lighthouse guards.
    public const LIGHTHOUSE_PROGRAM        = 'L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95';
    public const TOKEN_PROGRAM             = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
    public const TOKEN_2022_PROGRAM        = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
    public const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5000000;

    /**
     * Verify a base64-encoded transaction against an offer.
     *
     * @param string               $transactionBase64
     * @param array<string,mixed>  $requirement   The x402 accepts[] entry.
     * @param list<string>         $managedSigners Server-managed pubkeys (typically the facilitator).
     *
     * @return array{program:string,source:string,mint:string,destination:string,authority:string,amount:int}
     */
    public static function verify(
        string $transactionBase64,
        array $requirement,
        array $managedSigners,
    ): array {
        $raw = base64_decode($transactionBase64, true);
        if ($raw === false || $raw === '') {
            throw new InvalidProofException('invalid_exact_svm_payload_base64');
        }

        try {
            $tx = VersionedTransaction::deserialize($raw);
        } catch (Throwable) {
            throw new InvalidProofException('invalid_exact_svm_payload_transaction_parse');
        }

        $message = $tx->message;
        $instructions = $message->compiledInstructions;

        // Rule 1: instruction count.
        $n = count($instructions);
        if ($n < 3 || $n > 6) {
            throw new InvalidProofException(
                'invalid_exact_svm_payload_transaction_instructions_length',
            );
        }

        $accountKeys = array_map(
            static fn (PublicKey $k): string => (string) $k,
            $message->staticAccountKeys,
        );

        // Rule 2: compute-budget set-compute-unit-limit.
        self::verifyComputeLimit($instructions[0], $accountKeys);
        // Rule 3: compute-budget set-compute-unit-price.
        self::verifyComputePrice($instructions[1], $accountKeys);
        // Rules 4 + 5 + 6 + 7 + 8 + 11.
        $transfer = self::verifyTransfer($instructions[2], $accountKeys, $requirement, $managedSigners);

        // Rule 9: ix[3..6] allowlist. Optional slots may carry ONLY
        // Lighthouse (wallet-injected guard) or SPL Memo. An
        // Associated-Token-Program ATA-create is NOT permitted: per the
        // official x402 SVM exact contract the destination ATA MUST
        // pre-exist. Lighthouse is allowed in any optional slot because
        // wallets inject a variable number of guards (Phantom 1,
        // Solflare 2).
        $reasons = [
            'invalid_exact_svm_payload_unknown_fourth_instruction',
            'invalid_exact_svm_payload_unknown_fifth_instruction',
            'invalid_exact_svm_payload_unknown_sixth_instruction',
        ];
        for ($i = 3; $i < $n; $i++) {
            $ix = $instructions[$i];
            $program = self::programOf($accountKeys, $ix);
            $slotIndex = $i - 3;
            $allowed = ($program === self::MEMO_PROGRAM)
                || ($program === self::LIGHTHOUSE_PROGRAM);
            if (!$allowed) {
                throw new InvalidProofException(
                    $reasons[$slotIndex] ?? 'invalid_exact_svm_payload_unknown_optional_instruction',
                );
            }
        }

        // Rule 10: memo binding.
        $expectedMemo = self::stringExtra($requirement, 'memo', false);
        if ($expectedMemo !== null && $expectedMemo !== '') {
            self::findMemoMatch($accountKeys, $instructions, $expectedMemo);
        }

        return $transfer;
    }

    /**
     * @param object{programIdIndex:int,data:string,accountKeyIndexes:array<int,int>} $ix
     * @param list<string> $accountKeys
     */
    private static function verifyComputeLimit(object $ix, array $accountKeys): void
    {
        $program = self::programOf($accountKeys, $ix);
        $data = $ix->data;
        if ($program !== self::COMPUTE_BUDGET_PROGRAM
            || strlen($data) !== 5
            || ord($data[0]) !== 2) {
            throw new InvalidProofException(
                'invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction',
            );
        }
    }

    /**
     * @param object{programIdIndex:int,data:string,accountKeyIndexes:array<int,int>} $ix
     * @param list<string> $accountKeys
     */
    private static function verifyComputePrice(object $ix, array $accountKeys): void
    {
        $program = self::programOf($accountKeys, $ix);
        $data = $ix->data;
        if ($program !== self::COMPUTE_BUDGET_PROGRAM
            || strlen($data) !== 9
            || ord($data[0]) !== 3) {
            throw new InvalidProofException(
                'invalid_exact_svm_payload_transaction_instructions_compute_price_instruction',
            );
        }
        $micro = self::readU64Le($data, 1);
        if ($micro > self::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS) {
            throw new InvalidProofException(
                'invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high',
            );
        }
    }

    /**
     * @param object{programIdIndex:int,data:string,accountKeyIndexes:array<int,int>} $ix
     * @param list<string> $accountKeys
     * @param array<string,mixed> $requirement
     * @param list<string> $managedSigners
     * @return array{program:string,source:string,mint:string,destination:string,authority:string,amount:int}
     */
    private static function verifyTransfer(
        object $ix,
        array $accountKeys,
        array $requirement,
        array $managedSigners,
    ): array {
        // Rule 11: the transfer program id must be one of the two canonical
        // SPL token programs. Rust derives the gate from the actual
        // instruction program (verify.rs:373), NOT from a seller-pinned
        // extra.tokenProgram, so an offer that omits extra.tokenProgram still
        // verifies against a real Token / Token-2022 transfer.
        $program = self::programOf($accountKeys, $ix);
        if ($program !== self::TOKEN_PROGRAM && $program !== self::TOKEN_2022_PROGRAM) {
            throw new InvalidProofException('invalid_exact_svm_payload_no_transfer_instruction');
        }
        $data = $ix->data;
        if (count($ix->accountKeyIndexes) < 4 || strlen($data) !== 10 || ord($data[0]) !== 12) {
            throw new InvalidProofException('invalid_exact_svm_payload_no_transfer_instruction');
        }

        $source      = self::accountAt($accountKeys, $ix, 0);
        $mint        = self::accountAt($accountKeys, $ix, 1);
        $destination = self::accountAt($accountKeys, $ix, 2);
        $authority   = self::accountAt($accountKeys, $ix, 3);

        // Rule 5: authority guard.
        foreach ($managedSigners as $managed) {
            if ($managed === $authority || $managed === $source) {
                throw new InvalidProofException(
                    'invalid_exact_svm_payload_transaction_fee_payer_transferring_funds',
                );
            }
        }
        foreach ($ix->accountKeyIndexes as $idx) {
            $key = $accountKeys[$idx] ?? null;
            if ($key === null) {
                continue;
            }
            foreach ($managedSigners as $managed) {
                if ($managed === $key) {
                    throw new InvalidProofException(
                        'invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts',
                    );
                }
            }
        }

        // Rule 6: mint match.
        $expectedMint = self::b58Field($requirement, 'asset');
        if ($mint !== $expectedMint) {
            throw new InvalidProofException('invalid_exact_svm_payload_mint_mismatch');
        }

        // Rule 7: destination ATA match.
        $payTo = self::b58Field($requirement, 'payTo');
        $expectedDestination = Mints::deriveAta($payTo, $expectedMint, $program);
        if ($destination !== $expectedDestination) {
            throw new InvalidProofException('invalid_exact_svm_payload_recipient_mismatch');
        }

        // Rule 8: amount match.
        $amount = self::readU64Le($data, 1);
        $expectedAmount = self::amountField($requirement);
        if ($amount !== $expectedAmount) {
            throw new InvalidProofException('invalid_exact_svm_payload_amount_mismatch');
        }

        return [
            'program'     => $program,
            'source'      => $source,
            'mint'        => $mint,
            'destination' => $destination,
            'authority'   => $authority,
            'amount'      => $amount,
        ];
    }

    /**
     * @param list<string> $accountKeys
     * @param list<object{programIdIndex:int,data:string,accountKeyIndexes:array<int,int>}> $instructions
     */
    private static function findMemoMatch(array $accountKeys, array $instructions, string $expectedMemo): void
    {
        $count = 0;
        $lastData = null;
        $n = count($instructions);
        for ($i = 3; $i < $n; $i++) {
            $ix = $instructions[$i];
            if (self::programOf($accountKeys, $ix) === self::MEMO_PROGRAM) {
                $count++;
                $lastData = $ix->data;
            }
        }
        if ($count !== 1) {
            throw new InvalidProofException('invalid_exact_svm_payload_memo_count');
        }
        if ($lastData !== $expectedMemo) {
            throw new InvalidProofException('invalid_exact_svm_payload_memo_mismatch');
        }
    }

    /**
     * @param list<string> $accountKeys
     * @param object{programIdIndex:int} $ix
     */
    private static function programOf(array $accountKeys, object $ix): string
    {
        return $accountKeys[$ix->programIdIndex] ?? '';
    }

    /**
     * @param list<string> $accountKeys
     * @param object{accountKeyIndexes:array<int,int>} $ix
     */
    private static function accountAt(array $accountKeys, object $ix, int $slot): string
    {
        $idx = $ix->accountKeyIndexes[$slot] ?? null;
        if ($idx === null) {
            throw new InvalidProofException('invalid_exact_svm_payload_no_transfer_instruction');
        }
        return $accountKeys[$idx] ?? '';
    }

    /**
     * @param array<string,mixed> $requirement
     */
    private static function b58Field(array $requirement, string $key): string
    {
        $v = $requirement[$key] ?? null;
        if (!is_string($v) || $v === '') {
            throw new InvalidProofException('invalid_exact_svm_payload_missing_field_' . $key);
        }
        return $v;
    }

    /**
     * @param array<string,mixed> $requirement
     */
    private static function stringExtra(array $requirement, string $key, bool $required): ?string
    {
        $extra = $requirement['extra'] ?? [];
        $v = is_array($extra) ? ($extra[$key] ?? null) : null;
        if (($v === null || $v === '') && $required) {
            throw new InvalidProofException('invalid_exact_svm_payload_missing_extra_' . $key);
        }
        return is_string($v) ? $v : null;
    }

    /**
     * @param array<string,mixed> $requirement
     */
    private static function amountField(array $requirement): int
    {
        $v = $requirement['amount'] ?? $requirement['maxAmountRequired'] ?? null;
        if (!is_string($v) && !is_int($v)) {
            throw new InvalidProofException('invalid_exact_svm_payload_missing_field_amount');
        }
        return (int) $v;
    }

    private static function readU64Le(string $data, int $offset): int
    {
        if (strlen($data) < $offset + 8) {
            throw new InvalidProofException('invalid_exact_svm_payload_no_transfer_instruction');
        }
        $b = unpack('P', substr($data, $offset, 8));
        return $b === false ? 0 : (int) $b[1];
    }
}
