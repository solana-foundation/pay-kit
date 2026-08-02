<?php

declare(strict_types=1);

namespace PayKit\Protocols\X402\Upto;

use PayKit\Exception\InvalidProofException;
use PayKit\PayCore\PaymentChannels;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Programs\AssociatedTokenProgram;
use SolanaPhpSdk\Programs\SystemProgram;

/**
 * Pure verification for the x402 `upto` payment-channel profile.
 *
 * No I/O: validates already-decoded structures and raises
 * {@see InvalidProofException} on rejection. Ordered checks mirror Rust/Go/
 * Python (`VerifyUptoPayload`, `validateUptoOpenInstruction`).
 */
final class Verify
{
    /** Unsigned 64-bit maximum as a decimal string. */
    private const U64_MAX = '18446744073709551615';

    /**
     * Parse a base-10 u64 amount string into a PHP int.
     *
     * Rejects non-digit input, values above u64 max, and values above
     * {@see PHP_INT_MAX} so the cast cannot saturate/truncate (values in
     * (PHP_INT_MAX, u64_max] would otherwise lose their wire value).
     *
     * @throws InvalidProofException
     */
    public static function parseBaseUnits(string $value, string $label): int
    {
        if ($value === '' || !preg_match('/^[0-9]+$/', $value)) {
            throw new InvalidProofException("invalid upto {$label} " . var_export($value, true));
        }
        // Strip leading zeros for length/lexicographic compare (keep "0").
        $normalized = ltrim($value, '0');
        if ($normalized === '') {
            $normalized = '0';
        }
        if (self::decimalGreaterThan($normalized, self::U64_MAX)) {
            throw new InvalidProofException("upto {$label} {$value} does not fit in u64");
        }
        $maxPlatform = (string) PHP_INT_MAX;
        if (self::decimalGreaterThan($normalized, $maxPlatform)) {
            throw new InvalidProofException(
                "upto {$label} {$value} does not fit in platform int (PHP_INT_MAX)",
            );
        }

        return (int) $normalized;
    }

    /**
     * Parse a strict base-10 integer (optional leading `-`) into a PHP int.
     *
     * Used for authorization timestamps so `"123abc"` cannot silently become
     * `123` via a cast. Rejects values outside [PHP_INT_MIN, PHP_INT_MAX].
     *
     * @param mixed $value
     *
     * @throws InvalidProofException
     */
    public static function parseStrictInt(mixed $value, string $label): int
    {
        if (is_int($value)) {
            return $value;
        }
        if (!is_string($value) || $value === '' || !preg_match('/^-?[0-9]+$/', $value)) {
            throw new InvalidProofException(
                "invalid upto {$label} " . var_export($value, true),
            );
        }
        // Exact platform min string (e.g. "-9223372036854775808") before
        // magnitude checks so we do not reject PHP_INT_MIN as > PHP_INT_MAX.
        if ($value === (string) PHP_INT_MIN) {
            return PHP_INT_MIN;
        }
        $negative = $value[0] === '-';
        $digits = $negative ? substr($value, 1) : $value;
        $normalized = ltrim($digits, '0');
        if ($normalized === '') {
            return 0;
        }
        if (self::decimalGreaterThan($normalized, (string) PHP_INT_MAX)) {
            throw new InvalidProofException(
                "upto {$label} {$value} does not fit in platform int",
            );
        }

        return $negative ? -((int) $normalized) : (int) $normalized;
    }

    /**
     * Lexicographic compare of non-negative decimal digit strings (no leading zeros).
     */
    private static function decimalGreaterThan(string $a, string $b): bool
    {
        $la = strlen($a);
        $lb = strlen($b);
        if ($la !== $lb) {
            return $la > $lb;
        }

        return $a > $b;
    }

    /**
     * Validate the client payload against the route-pinned requirement.
     *
     * @param array<string,mixed> $payload
     * @param array<string,mixed> $requirements accepts[] entry
     *
     * @throws InvalidProofException
     */
    public static function verifyUptoPayload(
        array $payload,
        array $requirements,
        string $receiverAuthorizer,
        int $now,
    ): void {
        $maxAmount = self::parseBaseUnits((string) ($requirements['amount'] ?? ''), 'amount');
        $signedMax = self::parseBaseUnits((string) ($payload['maxAmount'] ?? ''), 'maxAmount');
        if ($signedMax !== $maxAmount) {
            throw new InvalidProofException(
                "amount mismatch: expected {$maxAmount}, got {$signedMax}",
            );
        }

        $deposit = self::parseBaseUnits((string) ($payload['deposit'] ?? ''), 'deposit');
        if ($deposit !== $maxAmount) {
            throw new InvalidProofException(
                "channel deposit {$deposit} must equal the authorized maximum {$maxAmount}",
            );
        }

        $validAfter = self::parseStrictInt($payload['validAfter'] ?? 0, 'validAfter');
        $expiresAt = self::parseStrictInt($payload['expiresAt'] ?? 0, 'expiresAt');
        if ($now < $validAfter) {
            throw new InvalidProofException(
                "authorization not yet active (validAfter {$validAfter} > now {$now})",
            );
        }
        if ($expiresAt === 0 || $now >= $expiresAt) {
            throw new InvalidProofException(
                "authorization expired (expiresAt {$expiresAt} < now {$now})",
            );
        }

        if (($payload['authorizedSigner'] ?? null) !== $receiverAuthorizer) {
            throw new InvalidProofException(
                'voucher authorized_signer must be the advertised receiver authorizer',
            );
        }
    }

    /**
     * Enforce actual <= max at settlement.
     *
     * @throws InvalidProofException
     */
    public static function assertSettlementWithinCeiling(int $actual, int $maxAmount): void
    {
        if ($actual > $maxAmount) {
            throw new InvalidProofException(Types::ERROR_SETTLEMENT_EXCEEDS_AMOUNT);
        }
    }

    /**
     * Validate the client-built channel-open instruction byte-for-byte.
     *
     * The open transaction must contain exactly one instruction targeting the
     * payment-channels program with the open discriminator and the 14 accounts
     * in the fixed program order.
     *
     * @param list<string>                                                                 $accountKeys base58 pubkeys
     * @param list<array{programIdIndex: int, accounts: list<int>, data: string}>            $instructions
     *
     * @throws InvalidProofException
     */
    public static function validateUptoOpenInstruction(
        array $accountKeys,
        array $instructions,
        PublicKey $programId,
        PublicKey $feePayer,
        PublicKey $receiverAuthorizer,
        PublicKey $payer,
        PublicKey $payee,
        PublicKey $mint,
        PublicKey $tokenProgram,
        PublicKey $channelId,
        int $maxAmount,
        int $withdrawDelay,
        string $payloadNonce,
        string $payloadOpenSlot,
        ?int $recentSlot,
    ): void {
        if (count($instructions) !== 1) {
            throw new InvalidProofException(
                'open transaction must contain exactly one instruction, found ' . count($instructions),
            );
        }
        $ix = $instructions[0];
        $programIndex = (int) $ix['programIdIndex'];
        if ($programIndex >= count($accountKeys)) {
            throw new InvalidProofException('open instruction program id out of range');
        }
        if ($accountKeys[$programIndex] !== (string) $programId) {
            throw new InvalidProofException('open transaction targets an unexpected program');
        }
        $data = $ix['data'];
        if ($data === '' || ord($data[0]) !== PaymentChannels::OPEN_INSTRUCTION_DISCRIMINATOR) {
            throw new InvalidProofException('open transaction is not a channel-open instruction');
        }

        $indices = $ix['accounts'];
        if (count($indices) !== 14) {
            throw new InvalidProofException(
                'open instruction must reference exactly 14 accounts, found ' . count($indices),
            );
        }

        $accountAt = static function (int $pos, string $label) use ($indices, $accountKeys): string {
            if ($pos >= count($indices) || $indices[$pos] >= count($accountKeys)) {
                throw new InvalidProofException(
                    "open transaction {$label} mismatch: expected account at slot {$pos}, got <none>",
                );
            }

            return $accountKeys[$indices[$pos]];
        };

        $expect = static function (int $pos, PublicKey $want, string $label) use ($accountAt): void {
            $got = $accountAt($pos, $label);
            if ($got !== (string) $want) {
                throw new InvalidProofException(
                    "open transaction {$label} mismatch: expected {$want}, got {$got}",
                );
            }
        };

        [$payerToken] = PaymentChannels::findAssociatedTokenAddress($payer, $mint, $tokenProgram);
        [$channelToken] = PaymentChannels::findAssociatedTokenAddress($channelId, $mint, $tokenProgram);
        [$eventAuthority] = PaymentChannels::findEventAuthorityPda($programId);

        $expect(0, $payer, 'payer');
        $expect(1, $feePayer, 'rent_payer');
        $expect(2, $payee, 'payee');
        $expect(3, $mint, 'mint');
        $expect(4, $receiverAuthorizer, 'authorized_signer');
        $expect(5, $channelId, 'channel');
        $expect(6, $payerToken, 'payer_token_account');
        $expect(7, $channelToken, 'channel_token_account');
        $expect(8, $tokenProgram, 'token_program');
        $expect(9, new PublicKey(SystemProgram::PROGRAM_ID), 'system_program');
        $expect(10, new PublicKey(PaymentChannels::RENT_SYSVAR_ID), 'rent_sysvar');
        $expect(11, new PublicKey(AssociatedTokenProgram::PROGRAM_ID), 'associated_token_program');
        $expect(12, $eventAuthority, 'event_authority');
        $expect(13, $programId, 'self_program');

        try {
            $args = PaymentChannels::decodeOpenArgs($data);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidProofException($e->getMessage(), 0, $e);
        }

        if ($payloadNonce !== (string) $args['salt']) {
            throw new InvalidProofException(
                "open salt {$args['salt']} does not match payload nonce " . var_export($payloadNonce, true),
            );
        }
        if ($payloadOpenSlot !== (string) $args['openSlot']) {
            throw new InvalidProofException(
                "open slot {$args['openSlot']} does not match payload openSlot " . var_export($payloadOpenSlot, true),
            );
        }
        if ($args['gracePeriod'] !== $withdrawDelay) {
            throw new InvalidProofException(
                "open withdraw delay {$args['gracePeriod']} must equal the advertised withdrawDelay {$withdrawDelay}",
            );
        }

        [$derivedChannel] = PaymentChannels::findChannelPda(
            $payer,
            $payee,
            $mint,
            $receiverAuthorizer,
            $args['salt'],
            $args['openSlot'],
            $programId,
        );
        if (!$derivedChannel->equals($channelId)) {
            throw new InvalidProofException(
                "open channel PDA {$channelId} != derived {$derivedChannel}",
            );
        }
        if ($args['deposit'] !== $maxAmount) {
            throw new InvalidProofException(
                "open deposit {$args['deposit']} must equal the authorized maximum {$maxAmount}",
            );
        }
        if ($recentSlot !== null) {
            if ($args['openSlot'] > $recentSlot) {
                throw new InvalidProofException(
                    "open openSlot {$args['openSlot']} is ahead of the challenged recentSlot {$recentSlot}",
                );
            }
            if ($recentSlot - $args['openSlot'] > PaymentChannels::OPEN_SLOT_WINDOW) {
                throw new InvalidProofException(
                    "open openSlot {$args['openSlot']} is outside the "
                    . PaymentChannels::OPEN_SLOT_WINDOW
                    . "-slot freshness window of the challenged recentSlot {$recentSlot}",
                );
            }
        }
    }
}
