<?php

declare(strict_types=1);

namespace PayKit\Tests\PayCore;

use PayKit\PayCore\PaymentChannels;
use PHPUnit\Framework\TestCase;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Transaction\TransactionInstruction;

/**
 * Offline instruction-builder parity with Go paycore/paymentchannels.
 */
final class PaymentChannelsBuildersTest extends TestCase
{
    private PublicKey $payer;
    private PublicKey $rentPayer;
    private PublicKey $payee;
    private PublicKey $mint;
    private PublicKey $authorizedSigner;
    private PublicKey $tokenProgram;

    protected function setUp(): void
    {
        $this->payer = new PublicKey(str_repeat("\x01", 32));
        $this->rentPayer = new PublicKey(str_repeat("\x02", 32));
        $this->payee = new PublicKey(str_repeat("\x03", 32));
        $this->mint = new PublicKey(str_repeat("\x04", 32));
        $this->authorizedSigner = new PublicKey(str_repeat("\x05", 32));
        $this->tokenProgram = new PublicKey(PaymentChannels::tokenProgramId());
    }

    public function testBuildOpenInstructionAccountOrderAndFlags(): void
    {
        $salt = 7;
        $deposit = 100_000;
        $grace = 900;
        $openSlot = 4242;

        $ix = PaymentChannels::buildOpenInstruction(
            $this->payer,
            $this->rentPayer,
            $this->payee,
            $this->mint,
            $this->authorizedSigner,
            $salt,
            $deposit,
            $grace,
            $openSlot,
            $this->tokenProgram,
        );

        self::assertInstanceOf(TransactionInstruction::class, $ix);
        self::assertSame(PaymentChannels::PROGRAM_ID, (string) $ix->programId);
        self::assertCount(14, $ix->accounts);

        [$channel] = PaymentChannels::findChannelPda(
            $this->payer,
            $this->payee,
            $this->mint,
            $this->authorizedSigner,
            $salt,
            $openSlot,
        );
        [$payerToken] = PaymentChannels::findAssociatedTokenAddress(
            $this->payer,
            $this->mint,
            $this->tokenProgram,
        );
        [$channelToken] = PaymentChannels::findAssociatedTokenAddress(
            $channel,
            $this->mint,
            $this->tokenProgram,
        );
        [$eventAuthority] = PaymentChannels::findEventAuthorityPda();

        $want = [
            [(string) $this->payer, true, true],
            [(string) $this->rentPayer, true, true],
            [(string) $this->payee, false, false],
            [(string) $this->mint, false, false],
            [(string) $this->authorizedSigner, false, false],
            [(string) $channel, false, true],
            [(string) $payerToken, false, true],
            [(string) $channelToken, false, true],
            [PaymentChannels::tokenProgramId(), false, false],
            [PaymentChannels::systemProgramId(), false, false],
            [PaymentChannels::RENT_SYSVAR_ID, false, false],
            [PaymentChannels::associatedTokenProgramId(), false, false],
            [(string) $eventAuthority, false, false],
            [PaymentChannels::PROGRAM_ID, false, false],
        ];

        foreach ($want as $i => [$pubkey, $signer, $writable]) {
            $meta = $ix->accounts[$i];
            self::assertSame($pubkey, (string) $meta->pubkey, "account[{$i}] pubkey");
            self::assertSame($signer, $meta->isSigner, "account[{$i}] signer");
            self::assertSame($writable, $meta->isWritable, "account[{$i}] writable");
        }
    }

    public function testBuildOpenInstructionDataRoundTrip(): void
    {
        $salt = 7;
        $deposit = 100_000;
        $grace = 900;
        $openSlot = 4242;

        $ix = PaymentChannels::buildOpenInstruction(
            $this->payer,
            $this->rentPayer,
            $this->payee,
            $this->mint,
            $this->authorizedSigner,
            $salt,
            $deposit,
            $grace,
            $openSlot,
            $this->tokenProgram,
        );

        $encoded = PaymentChannels::encodeOpenInstructionData($salt, $deposit, $grace, $openSlot);
        self::assertSame($encoded, $ix->data);
        self::assertSame(33, strlen($ix->data));

        $decoded = PaymentChannels::decodeOpenArgs($ix->data);
        self::assertSame($salt, $decoded['salt']);
        self::assertSame($deposit, $decoded['deposit']);
        self::assertSame($grace, $decoded['gracePeriod']);
        self::assertSame($openSlot, $decoded['openSlot']);
    }

    public function testBuildSettleAndSealVoucherlessIsSingleInstruction(): void
    {
        $channel = new PublicKey(str_repeat("\x09", 32));
        $ixs = PaymentChannels::buildSettleAndSealInstructions(
            $this->payee,
            $channel,
            $this->authorizedSigner,
            null,
            0,
            0,
        );
        self::assertCount(1, $ixs);
        $seal = $ixs[0];
        self::assertSame(PaymentChannels::PROGRAM_ID, (string) $seal->programId);
        self::assertCount(3, $seal->accounts);
        self::assertTrue($seal->accounts[0]->isSigner);
        self::assertFalse($seal->accounts[0]->isWritable);
        self::assertFalse($seal->accounts[1]->isSigner);
        self::assertTrue($seal->accounts[1]->isWritable);
        self::assertSame(PaymentChannels::SYSVAR_INSTRUCTIONS, (string) $seal->accounts[2]->pubkey);
        self::assertSame(
            chr(PaymentChannels::SETTLE_AND_SEAL_DISCRIMINATOR) . "\x00",
            $seal->data,
        );
    }

    public function testBuildSettleAndSealWithVoucherPrependsEd25519(): void
    {
        $channel = new PublicKey(str_repeat("\x09", 32));
        $signature = str_repeat("\xAB", 64);
        $cumulative = 50_000;
        $expiresAt = 1_700_000_000;

        $ixs = PaymentChannels::buildSettleAndSealInstructions(
            $this->payee,
            $channel,
            $this->authorizedSigner,
            $signature,
            $cumulative,
            $expiresAt,
        );
        self::assertCount(2, $ixs);

        $ed = $ixs[0];
        self::assertSame(PaymentChannels::ED25519_PROGRAM_ID, (string) $ed->programId);
        self::assertSame([], $ed->accounts);
        self::assertSame(1, ord($ed->data[0]));
        $message = PaymentChannels::voucherMessageBytes($channel, $cumulative, $expiresAt);
        self::assertSame(112 + strlen($message), strlen($ed->data));
        self::assertSame($this->authorizedSigner->toBytes(), substr($ed->data, 16, 32));
        self::assertSame($signature, substr($ed->data, 48, 64));
        self::assertSame($message, substr($ed->data, 112));

        $seal = $ixs[1];
        self::assertSame(
            chr(PaymentChannels::SETTLE_AND_SEAL_DISCRIMINATOR) . "\x01",
            $seal->data,
        );
    }

    public function testBuildDistributeEmptyRecipients(): void
    {
        $channel = new PublicKey(str_repeat("\x0A", 32));
        $ix = PaymentChannels::buildDistributeInstruction(
            $channel,
            $this->payer,
            $this->rentPayer,
            $this->payee,
            $this->mint,
            $this->tokenProgram,
            [],
        );

        self::assertCount(11, $ix->accounts);
        self::assertTrue($ix->accounts[0]->isWritable); // channel
        self::assertTrue($ix->accounts[1]->isWritable); // payer
        self::assertTrue($ix->accounts[2]->isWritable); // rentPayer
        self::assertSame(
            chr(PaymentChannels::DISTRIBUTE_DISCRIMINATOR) . "\x00\x00\x00\x00",
            $ix->data,
        );
        self::assertSame(PaymentChannels::PROGRAM_ID, (string) $ix->programId);
        self::assertSame(PaymentChannels::PROGRAM_ID, (string) $ix->accounts[10]->pubkey);
    }

    public function testBuildDistributeWithRecipientAppendsAta(): void
    {
        $channel = new PublicKey(str_repeat("\x0B", 32));
        $recipient = new PublicKey(str_repeat("\x0C", 32));
        $ix = PaymentChannels::buildDistributeInstruction(
            $channel,
            $this->payer,
            $this->rentPayer,
            $this->payee,
            $this->mint,
            $this->tokenProgram,
            [['recipient' => $recipient, 'bps' => 10_000]],
        );

        self::assertCount(12, $ix->accounts);
        [$recipientAta] = PaymentChannels::findAssociatedTokenAddress(
            $recipient,
            $this->mint,
            $this->tokenProgram,
        );
        self::assertSame((string) $recipientAta, (string) $ix->accounts[11]->pubkey);
        self::assertTrue($ix->accounts[11]->isWritable);
        self::assertSame(1 + 4 + 32 + 2, strlen($ix->data));
        self::assertSame(PaymentChannels::DISTRIBUTE_DISCRIMINATOR, ord($ix->data[0]));
        self::assertSame(1, unpack('V', substr($ix->data, 1, 4))[1]);
        self::assertSame($recipient->toBytes(), substr($ix->data, 5, 32));
        self::assertSame(10_000, unpack('v', substr($ix->data, 37, 2))[1]);
    }

    public function testBuildEd25519RejectsBadSignatureLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PaymentChannels::buildEd25519VerifyInstruction(
            $this->authorizedSigner,
            str_repeat("\x00", 32),
            'msg',
        );
    }
}
