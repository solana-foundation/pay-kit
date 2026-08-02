<?php

declare(strict_types=1);

namespace PayKit\PayCore;

use InvalidArgumentException;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Programs\AssociatedTokenProgram;
use SolanaPhpSdk\Programs\SystemProgram;
use SolanaPhpSdk\Programs\TokenProgram;

/**
 * Hand-written on-chain glue for the payment-channels program.
 *
 * Mirrors Go `paycore/paymentchannels` and Python `_paycore.paymentchannels`:
 * production program id, channel / event-authority PDA derivation, ATA
 * derivation, and the 50-byte voucher preimage. Instruction builders that
 * require the full Codama-generated client land in follow-up commits; this
 * module is the pure shared foundation for x402 `upto` verify + settle.
 *
 * Layout and seeds MUST stay byte-identical across language SDKs so the
 * on-chain program accepts them.
 */
final class PaymentChannels
{
    /** Canonical payment-channels program id deployed to the network. */
    public const PROGRAM_ID = 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX';

    /** Channel-open freshness window (slots). */
    public const OPEN_SLOT_WINDOW = 1500;

    /** Single-byte open instruction discriminator (not 8-byte Anchor). */
    public const OPEN_INSTRUCTION_DISCRIMINATOR = 1;

    /** Constant 2-byte magic prefixed to every signed voucher payload. */
    public const VOUCHER_MAGIC = "\x56\x01";

    public const RENT_SYSVAR_ID = 'SysvarRent111111111111111111111111111111111';
    public const ED25519_PROGRAM_ID = 'Ed25519SigVerify111111111111111111111111111';
    public const SYSVAR_INSTRUCTIONS = 'Sysvar1nstructions1111111111111111111111111';

    private const CHANNEL_SEED = 'channel';
    private const EVENT_AUTHORITY_SEED = 'event_authority';

    /**
     * 50-byte voucher preimage signed by the authorized signer.
     *
     * Layout: magic (2) || channelId (32) || cumulativeAmount LE u64 (8)
     * || expiresAt LE i64 (8). Matches generated VoucherArgs Borsh layout.
     *
     * @throws InvalidArgumentException when channel id is not 32 bytes
     */
    public static function voucherMessageBytes(PublicKey $channelId, int $cumulative, int $expiresAt): string
    {
        $id = $channelId->toBytes();
        if (strlen($id) !== 32) {
            throw new InvalidArgumentException(
                'channel id must be exactly 32 bytes, got ' . strlen($id),
            );
        }
        if ($cumulative < 0 || $cumulative > 0xFFFFFFFFFFFFFFFF) {
            throw new InvalidArgumentException('cumulative does not fit in u64');
        }

        return self::VOUCHER_MAGIC
            . $id
            . self::packU64Le($cumulative)
            . self::packI64Le($expiresAt);
    }

    /**
     * Derive the channel PDA.
     *
     * Seeds: ["channel", payer, payee, mint, authorizedSigner, salt u64 LE, openSlot u64 LE].
     *
     * @return array{0: PublicKey, 1: int} [address, bump]
     */
    public static function findChannelPda(
        PublicKey $payer,
        PublicKey $payee,
        PublicKey $mint,
        PublicKey $authorizedSigner,
        int $salt,
        int $openSlot,
        ?PublicKey $programId = null,
    ): array {
        self::assertU64($salt, 'salt');
        self::assertU64($openSlot, 'openSlot');
        $program = $programId ?? new PublicKey(self::PROGRAM_ID);

        return PublicKey::findProgramAddress(
            [
                self::CHANNEL_SEED,
                $payer->toBytes(),
                $payee->toBytes(),
                $mint->toBytes(),
                $authorizedSigner->toBytes(),
                self::packU64Le($salt),
                self::packU64Le($openSlot),
            ],
            $program,
        );
    }

    /**
     * Derive the event-authority PDA. Seeds: ["event_authority"].
     *
     * @return array{0: PublicKey, 1: int}
     */
    public static function findEventAuthorityPda(?PublicKey $programId = null): array
    {
        $program = $programId ?? new PublicKey(self::PROGRAM_ID);

        return PublicKey::findProgramAddress([self::EVENT_AUTHORITY_SEED], $program);
    }

    /**
     * Derive the associated token account for (owner, mint, token program).
     *
     * @return array{0: PublicKey, 1: int}
     */
    public static function findAssociatedTokenAddress(
        PublicKey $owner,
        PublicKey $mint,
        PublicKey $tokenProgram,
    ): array {
        return AssociatedTokenProgram::findAssociatedTokenAddress($owner, $mint, $tokenProgram);
    }

    /**
     * Encode open-instruction data (discriminator + openArgs without recipients).
     *
     * Layout: [u8 disc=1][u64 salt][u64 deposit][u32 grace][u64 openSlot][vec recipients…].
     * Empty recipients is a trailing u32 length of 0.
     */
    public static function encodeOpenInstructionData(
        int $salt,
        int $deposit,
        int $gracePeriod,
        int $openSlot,
    ): string {
        self::assertU64($salt, 'salt');
        self::assertU64($deposit, 'deposit');
        self::assertU32($gracePeriod, 'gracePeriod');
        self::assertU64($openSlot, 'openSlot');

        return chr(self::OPEN_INSTRUCTION_DISCRIMINATOR)
            . self::packU64Le($salt)
            . self::packU64Le($deposit)
            . self::packU32Le($gracePeriod)
            . self::packU64Le($openSlot)
            . self::packU32Le(0); // recipients len = 0
    }

    /**
     * Decode open instruction data (discriminator + openArgs).
     *
     * Pins the empty-recipients layout used by SVM `upto`:
     *   disc(1) + salt(8) + deposit(8) + grace(4) + openSlot(8) + recipients_len(4)=0
     * Total length must be exactly 33. Non-empty recipients or trailing bytes
     * are rejected so the open args stay byte-for-byte with the challenge path.
     *
     * @return array{salt: int, deposit: int, gracePeriod: int, openSlot: int}
     */
    public static function decodeOpenArgs(string $data): array
    {
        // disc(1) + salt(8) + deposit(8) + grace(4) + openSlot(8) + vec_len(4) = 33
        $expectedLen = 1 + 8 + 8 + 4 + 8 + 4;
        if (strlen($data) < $expectedLen) {
            throw new InvalidArgumentException(
                'open instruction data too short (' . strlen($data) . ' bytes)',
            );
        }
        if (ord($data[0]) !== self::OPEN_INSTRUCTION_DISCRIMINATOR) {
            throw new InvalidArgumentException('open transaction is not a channel-open instruction');
        }

        $recipientsLen = self::unpackU32Le(substr($data, 29, 4));
        if ($recipientsLen !== 0) {
            throw new InvalidArgumentException(
                "open instruction recipients length must be 0 for upto, got {$recipientsLen}",
            );
        }
        if (strlen($data) !== $expectedLen) {
            throw new InvalidArgumentException(
                'open instruction data has trailing bytes after empty recipients '
                . '(' . strlen($data) . ' bytes, expected ' . $expectedLen . ')',
            );
        }

        return [
            'salt'        => self::unpackU64Le(substr($data, 1, 8)),
            'deposit'     => self::unpackU64Le(substr($data, 9, 8)),
            'gracePeriod' => self::unpackU32Le(substr($data, 17, 4)),
            'openSlot'    => self::unpackU64Le(substr($data, 21, 8)),
        ];
    }

    public static function systemProgramId(): string
    {
        return SystemProgram::PROGRAM_ID;
    }

    public static function tokenProgramId(): string
    {
        return TokenProgram::PROGRAM_ID;
    }

    public static function associatedTokenProgramId(): string
    {
        return AssociatedTokenProgram::PROGRAM_ID;
    }

    private static function packU64Le(int $value): string
    {
        // Portable little-endian: works for unsigned values and for two's
        // complement negative i64s (arithmetic >> on signed PHP ints).
        $out = '';
        for ($i = 0; $i < 8; $i++) {
            $out .= chr(($value >> ($i * 8)) & 0xFF);
        }

        return $out;
    }

    private static function packI64Le(int $value): string
    {
        return self::packU64Le($value);
    }

    private static function packU32Le(int $value): string
    {
        $out = '';
        for ($i = 0; $i < 4; $i++) {
            $out .= chr(($value >> ($i * 8)) & 0xFF);
        }

        return $out;
    }

    private static function unpackU64Le(string $bytes): int
    {
        $value = 0;
        for ($i = 0; $i < 8; $i++) {
            $value |= ord($bytes[$i]) << ($i * 8);
        }

        return $value;
    }

    private static function unpackU32Le(string $bytes): int
    {
        $value = 0;
        for ($i = 0; $i < 4; $i++) {
            $value |= ord($bytes[$i]) << ($i * 8);
        }

        return $value;
    }

    private static function assertU64(int $value, string $label): void
    {
        if ($value < 0 || $value > 0xFFFFFFFFFFFFFFFF) {
            throw new InvalidArgumentException("{$label} {$value} does not fit in u64");
        }
    }

    private static function assertU32(int $value, string $label): void
    {
        if ($value < 0 || $value > 0xFFFFFFFF) {
            throw new InvalidArgumentException("{$label} {$value} does not fit in u32");
        }
    }
}
