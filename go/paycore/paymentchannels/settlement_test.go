package paymentchannels

// Settlement builder byte-equivalence tests.
//
// These pin the Ed25519 precompile layout and the settle_and_finalize,
// top_up, distribute, and open instruction bytes so any drift from the
// on-chain program encoding is caught at unit-test time.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	solana "github.com/gagliardetto/solana-go"
)

// fixedKey returns a deterministic 32-byte public key filled with b.
func fixedKey(b byte) solana.PublicKey {
	var key solana.PublicKey
	for i := range key {
		key[i] = b
	}
	return key
}

const zeroChannelID = "11111111111111111111111111111111"

// ── Ed25519 precompile ──

func TestBuildEd25519VerifyInstructionLayout(t *testing.T) {
	signer := fixedKey(0xAA)
	var signature [64]byte
	for i := range signature {
		signature[i] = 0xBB
	}
	message := bytes.Repeat([]byte{0xCC}, 48)

	ix, err := BuildEd25519VerifyInstruction(signer, signature, message)
	if err != nil {
		t.Fatalf("BuildEd25519VerifyInstruction: %v", err)
	}
	if !ix.ProgramID().Equals(Ed25519ProgramPubkey()) {
		t.Fatalf("program id = %s, want %s", ix.ProgramID(), Ed25519ProgramID)
	}
	if len(ix.Accounts()) != 0 {
		t.Fatalf("accounts = %d, want 0", len(ix.Accounts()))
	}

	data, err := ix.Data()
	if err != nil {
		t.Fatalf("ix.Data: %v", err)
	}
	if len(data) != 160 {
		t.Fatalf("data length = %d, want 160", len(data))
	}
	if data[0] != 1 || data[1] != 0 {
		t.Fatalf("header = [%d %d], want [1 0] (num_signatures, padding)", data[0], data[1])
	}
	// Offsets: signature 48, public key 16, message 112, size 48; every
	// instruction-index field is 0xFFFF (current instruction).
	expectHeader := []struct {
		offset int
		value  uint16
		label  string
	}{
		{2, 48, "signature_offset"},
		{4, 0xFFFF, "signature_instruction_index"},
		{6, 16, "public_key_offset"},
		{8, 0xFFFF, "public_key_instruction_index"},
		{10, 112, "message_data_offset"},
		{12, 48, "message_data_size"},
		{14, 0xFFFF, "message_instruction_index"},
	}
	for _, field := range expectHeader {
		if got := binary.LittleEndian.Uint16(data[field.offset : field.offset+2]); got != field.value {
			t.Fatalf("%s = %d, want %d", field.label, got, field.value)
		}
	}
	if !bytes.Equal(data[16:48], signer.Bytes()) {
		t.Fatal("public key bytes not at offset 16")
	}
	if !bytes.Equal(data[48:112], signature[:]) {
		t.Fatal("signature bytes not at offset 48")
	}
	if !bytes.Equal(data[112:160], message) {
		t.Fatal("message bytes not at offset 112")
	}
}

func TestBuildEd25519VerifyInstructionRejectsOversizedMessage(t *testing.T) {
	if _, err := BuildEd25519VerifyInstruction(fixedKey(1), [64]byte{}, make([]byte, 0x10000)); err == nil {
		t.Fatal("expected oversized-message rejection")
	}
}

// ── settle_and_finalize ──

func TestBuildSettleAndFinalizeVoucherless(t *testing.T) {
	merchant := fixedKey(0x05)
	channel := solana.MustPublicKeyFromBase58(zeroChannelID)

	instructions, err := BuildSettleAndFinalizeInstructions(SettleAndFinalizeParams{
		Merchant: merchant,
		Channel:  channel,
	})
	if err != nil {
		t.Fatalf("BuildSettleAndFinalizeInstructions: %v", err)
	}
	if len(instructions) != 1 {
		t.Fatalf("instructions = %d, want 1 (no precompile without a voucher)", len(instructions))
	}

	ix := instructions[0]
	if !ix.ProgramID().Equals(ProgramPubkey()) {
		t.Fatalf("program id = %s, want %s", ix.ProgramID(), ProgramID)
	}
	accounts := ix.Accounts()
	if len(accounts) != 3 {
		t.Fatalf("accounts = %d, want 3", len(accounts))
	}
	if !accounts[0].PublicKey.Equals(merchant) || !accounts[0].IsSigner || accounts[0].IsWritable {
		t.Fatalf("merchant meta = %+v, want readonly signer", accounts[0])
	}
	if !accounts[1].PublicKey.Equals(channel) || accounts[1].IsSigner || !accounts[1].IsWritable {
		t.Fatalf("channel meta = %+v, want writable non-signer", accounts[1])
	}
	if !accounts[2].PublicKey.Equals(solana.SysVarInstructionsPubkey) || accounts[2].IsSigner || accounts[2].IsWritable {
		t.Fatalf("sysvar meta = %+v, want readonly instructions sysvar", accounts[2])
	}

	data, err := ix.Data()
	if err != nil {
		t.Fatalf("ix.Data: %v", err)
	}
	// Voucher is read from the precompile, so settle_and_finalize carries only
	// [disc=4][hasVoucher=0] = 2 bytes.
	if len(data) != 2 {
		t.Fatalf("data length = %d, want 2", len(data))
	}
	if data[0] != 4 {
		t.Fatalf("discriminator = %d, want 4", data[0])
	}
	if data[1] != 0 {
		t.Fatalf("hasVoucher = %d, want 0", data[1])
	}
}

func TestBuildSettleAndFinalizeWithVoucherPrependsPrecompile(t *testing.T) {
	merchant := fixedKey(0x05)
	authorizedSigner := fixedKey(0x04)
	channel := solana.MustPublicKeyFromBase58(zeroChannelID)
	var signature [64]byte
	for i := range signature {
		signature[i] = 0xAA
	}

	instructions, err := BuildSettleAndFinalizeInstructions(SettleAndFinalizeParams{
		Merchant:         merchant,
		Channel:          channel,
		AuthorizedSigner: authorizedSigner,
		Signature:        &signature,
		CumulativeAmount: 500,
		ExpiresAt:        4_102_444_800,
	})
	if err != nil {
		t.Fatalf("BuildSettleAndFinalizeInstructions: %v", err)
	}
	if len(instructions) != 2 {
		t.Fatalf("instructions = %d, want 2 (precompile + settle_and_finalize)", len(instructions))
	}

	precompile := instructions[0]
	if !precompile.ProgramID().Equals(Ed25519ProgramPubkey()) {
		t.Fatalf("instruction 0 program = %s, want Ed25519 precompile", precompile.ProgramID())
	}
	precompileData, err := precompile.Data()
	if err != nil {
		t.Fatalf("precompile.Data: %v", err)
	}
	wantMessage, err := VoucherMessageBytes(channel, 500, 4_102_444_800)
	if err != nil {
		t.Fatalf("VoucherMessageBytes: %v", err)
	}
	if !bytes.Equal(precompileData[112:160], wantMessage) {
		t.Fatal("precompile message != canonical 48-byte voucher payload")
	}
	if !bytes.Equal(precompileData[48:112], signature[:]) {
		t.Fatal("precompile signature != voucher signature")
	}
	if !bytes.Equal(precompileData[16:48], authorizedSigner.Bytes()) {
		t.Fatal("precompile public key != authorized signer")
	}

	settleData, err := instructions[1].Data()
	if err != nil {
		t.Fatalf("settle.Data: %v", err)
	}
	// Voucher lives in the precompile; settle_and_finalize is [disc=4][hasVoucher=1].
	if len(settleData) != 2 {
		t.Fatalf("settle data length = %d, want 2", len(settleData))
	}
	if settleData[0] != 4 {
		t.Fatalf("discriminator = %d, want 4", settleData[0])
	}
	if settleData[1] != 1 {
		t.Fatalf("hasVoucher = %d, want 1", settleData[1])
	}
}

// ── distribute ──

func TestBuildDistributeAppendsRecipientTokenAccounts(t *testing.T) {
	channel := solana.MustPublicKeyFromBase58(zeroChannelID)
	payer := fixedKey(0x01)
	payee := fixedKey(0x03)
	mint := solana.MustPublicKeyFromBase58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
	tokenProgram := solana.TokenProgramID
	splitRecipient := solana.MustPublicKeyFromBase58("HQyfh1JGDB47A6Az4MD9KgF9LqcL3ESCkN8AT9Y8atGD")

	ix, err := BuildDistributeInstruction(DistributeParams{
		Channel: channel,
		Payer:   payer,
		Payee:   payee,
		Mint:    mint,
		Recipients: []Distribution{
			{Recipient: splitRecipient, Bps: 1000},
			{Recipient: splitRecipient, Bps: 250},
		},
		TokenProgram: tokenProgram,
	})
	if err != nil {
		t.Fatalf("BuildDistributeInstruction: %v", err)
	}
	if !ix.ProgramID().Equals(ProgramPubkey()) {
		t.Fatalf("program id = %s, want %s", ix.ProgramID(), ProgramID)
	}

	accounts := ix.Accounts()
	if len(accounts) != 12 {
		t.Fatalf("accounts = %d, want 12 (10 fixed + 2 recipient ATAs)", len(accounts))
	}
	recipientATA, _, err := solana.FindAssociatedTokenAddressWithProgram(splitRecipient, mint, tokenProgram)
	if err != nil {
		t.Fatalf("derive recipient ATA: %v", err)
	}
	for slot := 10; slot < 12; slot++ {
		if !accounts[slot].PublicKey.Equals(recipientATA) {
			t.Fatalf("tail account %d = %s, want recipient ATA %s", slot, accounts[slot].PublicKey, recipientATA)
		}
		if !accounts[slot].IsWritable || accounts[slot].IsSigner {
			t.Fatalf("tail account %d meta = %+v, want writable non-signer", slot, accounts[slot])
		}
	}
	treasuryATA, _, err := solana.FindAssociatedTokenAddressWithProgram(TreasuryOwner(), mint, tokenProgram)
	if err != nil {
		t.Fatalf("derive treasury ATA: %v", err)
	}
	if !accounts[5].PublicKey.Equals(treasuryATA) {
		t.Fatalf("treasury token account = %s, want %s", accounts[5].PublicKey, treasuryATA)
	}

	data, err := ix.Data()
	if err != nil {
		t.Fatalf("ix.Data: %v", err)
	}
	// [disc=7][recipients_count u32][(pubkey32 + bps u16) x 2].
	if data[0] != 7 {
		t.Fatalf("discriminator = %d, want 7", data[0])
	}
	if got := binary.LittleEndian.Uint32(data[1:5]); got != 2 {
		t.Fatalf("recipients count = %d, want 2", got)
	}
	if got := binary.LittleEndian.Uint16(data[5+32 : 5+34]); got != 1000 {
		t.Fatalf("first bps = %d, want 1000", got)
	}
	if got := binary.LittleEndian.Uint16(data[5+32+34 : 5+32+36]); got != 250 {
		t.Fatalf("second bps = %d, want 250", got)
	}
}

func TestBuildDistributeZeroSplits(t *testing.T) {
	ix, err := BuildDistributeInstruction(DistributeParams{
		Channel:      solana.MustPublicKeyFromBase58(zeroChannelID),
		Payer:        fixedKey(0x01),
		Payee:        fixedKey(0x03),
		Mint:         solana.MustPublicKeyFromBase58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
		TokenProgram: solana.TokenProgramID,
	})
	if err != nil {
		t.Fatalf("BuildDistributeInstruction: %v", err)
	}
	if len(ix.Accounts()) != 10 {
		t.Fatalf("accounts = %d, want 10 fixed accounts only", len(ix.Accounts()))
	}
	data, err := ix.Data()
	if err != nil {
		t.Fatalf("ix.Data: %v", err)
	}
	if len(data) != 5 {
		t.Fatalf("data length = %d, want 5 ([disc][count=0])", len(data))
	}
	if got := binary.LittleEndian.Uint32(data[1:5]); got != 0 {
		t.Fatalf("recipients count = %d, want 0", got)
	}
}

func TestBuildDistributeToken2022DerivesProgramSpecificATAs(t *testing.T) {
	channel := solana.MustPublicKeyFromBase58(zeroChannelID)
	payee := fixedKey(0x03)
	mint := solana.MustPublicKeyFromBase58("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo") // PYUSD mainnet
	token2022 := solana.MustPublicKeyFromBase58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")

	ix, err := BuildDistributeInstruction(DistributeParams{
		Channel:      channel,
		Payer:        fixedKey(0x01),
		Payee:        payee,
		Mint:         mint,
		TokenProgram: token2022,
	})
	if err != nil {
		t.Fatalf("BuildDistributeInstruction: %v", err)
	}
	accounts := ix.Accounts()
	if !accounts[7].PublicKey.Equals(token2022) {
		t.Fatalf("token program account = %s, want Token-2022", accounts[7].PublicKey)
	}
	want2022, _, err := solana.FindAssociatedTokenAddressWithProgram(payee, mint, token2022)
	if err != nil {
		t.Fatalf("derive token-2022 ATA: %v", err)
	}
	if !accounts[4].PublicKey.Equals(want2022) {
		t.Fatalf("payee token account = %s, want token-2022 ATA %s", accounts[4].PublicKey, want2022)
	}
	wantLegacy, _, err := solana.FindAssociatedTokenAddressWithProgram(payee, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("derive legacy ATA: %v", err)
	}
	if accounts[4].PublicKey.Equals(wantLegacy) {
		t.Fatal("payee token account was derived with the legacy token program")
	}
}

// ── open instruction golden ──

// TestBuildOpenInstructionMatchesTypescriptGolden pins the open instruction
// data for fixed inputs (salt=42, deposit=1_000_000, gracePeriod=900, one
// HQyfh.../250bps recipient) to the golden bytes shared with the vendored
// Codama TS client and the pre-Codama hand encoder, so all three agree byte
// for byte.
func TestBuildOpenInstructionMatchesTypescriptGolden(t *testing.T) {
	const goldenDataHex = "012a0000000000000040420f00000000008403000001000000f3df6c4f444efb2d860ce6dae0b568b6dadee3c402fc33edab10836490385896fa00"

	ix, err := BuildOpenInstruction(OpenChannelParams{
		Payer:            fixedKey(0x01),
		Payee:            fixedKey(0x03),
		Mint:             solana.MustPublicKeyFromBase58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
		AuthorizedSigner: fixedKey(0x04),
		Salt:             42,
		Deposit:          1_000_000,
		GracePeriod:      900,
		Recipients: []Distribution{
			{Recipient: solana.MustPublicKeyFromBase58("HQyfh1JGDB47A6Az4MD9KgF9LqcL3ESCkN8AT9Y8atGD"), Bps: 250},
		},
		TokenProgram: solana.TokenProgramID,
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	data, err := ix.Data()
	if err != nil {
		t.Fatalf("ix.Data: %v", err)
	}
	if got := hex.EncodeToString(data); got != goldenDataHex {
		t.Fatalf("open instruction data mismatch\n got: %s\nwant: %s", got, goldenDataHex)
	}
}
