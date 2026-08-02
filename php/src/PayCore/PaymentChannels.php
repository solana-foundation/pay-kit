<?php

declare(strict_types=1);

namespace PayKit\PayCore;

use InvalidArgumentException;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Programs\AssociatedTokenProgram;
use SolanaPhpSdk\Programs\SystemProgram;
use SolanaPhpSdk\Programs\TokenProgram;
use SolanaPhpSdk\Transaction\AccountMeta;
use SolanaPhpSdk\Transaction\TransactionInstruction;

/**
 * Hand-written on-chain glue for the payment-channels program.
 *
 * Mirrors Go `paycore/paymentchannels` and Python `_paycore.paymentchannels`:
 * production program id, channel / event-authority PDA derivation, ATA
 * derivation, 50-byte voucher preimage, and instruction builders
 * (open / settle_and_seal / distribute / ed25519) for x402 `upto`.
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


    public const SETTLE_AND_SEAL_DISCRIMINATOR = 4;
    public const DISTRIBUTE_DISCRIMINATOR = 7;

    /** Treasury owner baked into the deployed (mainnet-build) program. */
    public const TREASURY_OWNER = 'Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP';

    /**
     * Build the `open` instruction (14 accounts, disc=1 + openArgs).
     *
     * Account order and flags match Go `BuildOpenInstruction` /
     * Python `build_open_instruction`. Derives channel PDA, payer/channel ATAs,
     * and event-authority PDA. Empty recipients only (upto path).
     *
     * @return TransactionInstruction
     */
    public static function buildOpenInstruction(
        PublicKey $payer,
        PublicKey $rentPayer,
        PublicKey $payee,
        PublicKey $mint,
        PublicKey $authorizedSigner,
        int $salt,
        int $deposit,
        int $gracePeriod,
        int $openSlot,
        PublicKey $tokenProgram,
        ?PublicKey $programId = null,
    ): TransactionInstruction {
        $program = $programId ?? new PublicKey(self::PROGRAM_ID);
        [$channel] = self::findChannelPda(
            $payer,
            $payee,
            $mint,
            $authorizedSigner,
            $salt,
            $openSlot,
            $program,
        );
        [$payerToken] = self::findAssociatedTokenAddress($payer, $mint, $tokenProgram);
        [$channelToken] = self::findAssociatedTokenAddress($channel, $mint, $tokenProgram);
        [$eventAuthority] = self::findEventAuthorityPda($program);

        $accounts = [
            AccountMeta::signerWritable($payer),
            AccountMeta::signerWritable($rentPayer),
            AccountMeta::readonly($payee),
            AccountMeta::readonly($mint),
            AccountMeta::readonly($authorizedSigner),
            AccountMeta::writable($channel),
            AccountMeta::writable($payerToken),
            AccountMeta::writable($channelToken),
            AccountMeta::readonly($tokenProgram),
            AccountMeta::readonly(new PublicKey(self::systemProgramId())),
            AccountMeta::readonly(new PublicKey(self::RENT_SYSVAR_ID)),
            AccountMeta::readonly(new PublicKey(self::associatedTokenProgramId())),
            AccountMeta::readonly($eventAuthority),
            AccountMeta::readonly($program),
        ];

        $data = self::encodeOpenInstructionData($salt, $deposit, $gracePeriod, $openSlot);

        return new TransactionInstruction($program, $accounts, $data);
    }

    /**
     * Ed25519 precompile that verifies a voucher signature (sibling of settle).
     *
     * Layout mirrors Go/Python: pubkey @16, signature @48, message @112.
     */
    public static function buildEd25519VerifyInstruction(
        PublicKey $authorizedSigner,
        string $signature,
        string $message,
    ): TransactionInstruction {
        if (strlen($signature) !== 64) {
            throw new InvalidArgumentException(
                'ed25519 signature must be 64 bytes, got ' . strlen($signature),
            );
        }
        if (strlen($message) > 0xFFFF) {
            throw new InvalidArgumentException(
                'voucher message too long: ' . strlen($message) . ' bytes',
            );
        }

        $publicKeyOffset = 16;
        $signatureOffset = 48;
        $messageDataOffset = 112;
        $currentInstruction = 0xFFFF;

        $data = str_repeat("\x00", $messageDataOffset + strlen($message));
        $data[0] = chr(1); // num_signatures
        $data[1] = chr(0); // padding
        $data = self::pokeU16Le($data, 2, $signatureOffset);
        $data = self::pokeU16Le($data, 4, $currentInstruction);
        $data = self::pokeU16Le($data, 6, $publicKeyOffset);
        $data = self::pokeU16Le($data, 8, $currentInstruction);
        $data = self::pokeU16Le($data, 10, $messageDataOffset);
        $data = self::pokeU16Le($data, 12, strlen($message));
        $data = self::pokeU16Le($data, 14, $currentInstruction);

        $pk = $authorizedSigner->toBytes();
        for ($i = 0; $i < 32; $i++) {
            $data[$publicKeyOffset + $i] = $pk[$i];
        }
        for ($i = 0; $i < 64; $i++) {
            $data[$signatureOffset + $i] = $signature[$i];
        }
        for ($i = 0, $n = strlen($message); $i < $n; $i++) {
            $data[$messageDataOffset + $i] = $message[$i];
        }

        return new TransactionInstruction(
            new PublicKey(self::ED25519_PROGRAM_ID),
            [],
            $data,
        );
    }

    /**
     * Build settle_and_seal sequence: optional Ed25519 precompile + settleAndSeal.
     *
     * @param string|null $signature 64-byte Ed25519 voucher signature, or null for voucherless
     * @return list<TransactionInstruction>
     */
    public static function buildSettleAndSealInstructions(
        PublicKey $payee,
        PublicKey $channel,
        PublicKey $authorizedSigner,
        ?string $signature,
        int $cumulativeAmount,
        int $expiresAt,
        ?PublicKey $programId = null,
    ): array {
        $program = $programId ?? new PublicKey(self::PROGRAM_ID);
        $instructions = [];
        $hasVoucher = 0;

        if ($signature !== null) {
            $message = self::voucherMessageBytes($channel, $cumulativeAmount, $expiresAt);
            $instructions[] = self::buildEd25519VerifyInstruction(
                $authorizedSigner,
                $signature,
                $message,
            );
            $hasVoucher = 1;
        }

        $accounts = [
            AccountMeta::signerReadonly($payee),
            AccountMeta::writable($channel),
            AccountMeta::readonly(new PublicKey(self::SYSVAR_INSTRUCTIONS)),
        ];
        $data = chr(self::SETTLE_AND_SEAL_DISCRIMINATOR) . chr($hasVoucher);
        $instructions[] = new TransactionInstruction($program, $accounts, $data);

        return $instructions;
    }

    /**
     * Build distribute (11 fixed accounts + one writable recipient ATA per split).
     *
     * @param list<array{recipient: PublicKey, bps: int}> $recipients
     */
    public static function buildDistributeInstruction(
        PublicKey $channel,
        PublicKey $payer,
        PublicKey $rentPayer,
        PublicKey $payee,
        PublicKey $mint,
        PublicKey $tokenProgram,
        array $recipients = [],
        ?PublicKey $treasury = null,
        ?PublicKey $programId = null,
    ): TransactionInstruction {
        $program = $programId ?? new PublicKey(self::PROGRAM_ID);
        $treasuryOwner = $treasury ?? new PublicKey(self::TREASURY_OWNER);

        [$channelToken] = self::findAssociatedTokenAddress($channel, $mint, $tokenProgram);
        [$payerToken] = self::findAssociatedTokenAddress($payer, $mint, $tokenProgram);
        [$payeeToken] = self::findAssociatedTokenAddress($payee, $mint, $tokenProgram);
        [$treasuryToken] = self::findAssociatedTokenAddress($treasuryOwner, $mint, $tokenProgram);
        [$eventAuthority] = self::findEventAuthorityPda($program);

        $accounts = [
            AccountMeta::writable($channel),
            AccountMeta::writable($payer),
            AccountMeta::writable($rentPayer),
            AccountMeta::writable($channelToken),
            AccountMeta::writable($payerToken),
            AccountMeta::writable($payeeToken),
            AccountMeta::writable($treasuryToken),
            AccountMeta::readonly($mint),
            AccountMeta::readonly($tokenProgram),
            AccountMeta::readonly($eventAuthority),
            AccountMeta::readonly($program),
        ];

        $data = chr(self::DISTRIBUTE_DISCRIMINATOR) . self::packU32Le(count($recipients));
        foreach ($recipients as $entry) {
            $recipient = $entry['recipient'];
            $bps = $entry['bps'];
            if (!$recipient instanceof PublicKey) {
                throw new InvalidArgumentException('recipient must be a PublicKey');
            }
            if ($bps < 0 || $bps > 0xFFFF) {
                throw new InvalidArgumentException("recipient bps {$bps} does not fit in u16");
            }
            [$recipientToken] = self::findAssociatedTokenAddress($recipient, $mint, $tokenProgram);
            $accounts[] = AccountMeta::writable($recipientToken);
            $data .= $recipient->toBytes() . self::packU16Le($bps);
        }

        return new TransactionInstruction($program, $accounts, $data);
    }

    private static function pokeU16Le(string $data, int $offset, int $value): string
    {
        $data[$offset] = chr($value & 0xFF);
        $data[$offset + 1] = chr(($value >> 8) & 0xFF);

        return $data;
    }

    private static function packU16Le(int $value): string
    {
        return chr($value & 0xFF) . chr(($value >> 8) & 0xFF);
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
