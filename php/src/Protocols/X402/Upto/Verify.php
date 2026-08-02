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
    /**
     * Parse a base-10 u64 amount string.
     *
     * @throws InvalidProofException
     */
    public static function parseBaseUnits(string $value, string $label): int
    {
        if ($value === '' || !preg_match('/^[0-9]+$/', $value)) {
            throw new InvalidProofException("invalid upto {$label} " . var_export($value, true));
        }
        // Reject values that overflow PHP platform int or u64.
        if (strlen($value) > 20 || (strlen($value) === 20 && $value > '18446744073709551615')) {
            throw new InvalidProofException("upto {$label} {$value} does not fit in u64");
        }
        $parsed = (int) $value;
        if ($parsed < 0) {
            throw new InvalidProofException("upto {$label} {$parsed} does not fit in u64");
        }

        return $parsed;
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

        $validAfter = (int) ($payload['validAfter'] ?? 0);
        $expiresAt = (int) ($payload['expiresAt'] ?? 0);
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
