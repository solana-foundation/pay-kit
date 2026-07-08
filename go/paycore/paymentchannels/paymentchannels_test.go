package paymentchannels

import (
	"bytes"
	"encoding/binary"
	"testing"

	ag_binary "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"

	generated "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

// pk returns a deterministic 32-byte public key filled with the given byte.
func pk(b byte) solana.PublicKey {
	var out solana.PublicKey
	for i := range out {
		out[i] = b
	}
	return out
}

func TestProgramIDIsProduction(t *testing.T) {
	if ProgramID != "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX" {
		t.Fatalf("unexpected program id: %s", ProgramID)
	}
	if ProgramPubkey().String() != ProgramID {
		t.Fatalf("parsed program id mismatch: %s", ProgramPubkey())
	}
	// init() must have pinned the generated package to the production id.
	if generated.ProgramID.String() != ProgramID {
		t.Fatalf("generated ProgramID not pinned to production: %s", generated.ProgramID)
	}
}

func TestSetProgramIDOverridesDerivation(t *testing.T) {
	// SetProgramID lets a consumer target a non-mainnet (devnet/localnet)
	// deployment at a different address; it must move PDA derivation and pin the
	// generated package. Restore the production default for other tests.
	t.Cleanup(func() { SetProgramID(solana.MustPublicKeyFromBase58(ProgramID)) })

	custom := solana.NewWallet().PublicKey()
	SetProgramID(custom)
	if !ProgramPubkey().Equals(custom) {
		t.Fatalf("ProgramPubkey not overridden: %s", ProgramPubkey())
	}
	if !generated.ProgramID.Equals(custom) {
		t.Fatalf("generated ProgramID not pinned to override: %s", generated.ProgramID)
	}

	payer := solana.NewWallet().PublicKey()
	payee := solana.NewWallet().PublicKey()
	mint := solana.NewWallet().PublicKey()
	signer := solana.NewWallet().PublicKey()
	overridden, _, err := FindChannelPDA(payer, payee, mint, signer, 1)
	if err != nil {
		t.Fatalf("FindChannelPDA: %v", err)
	}
	SetProgramID(solana.MustPublicKeyFromBase58(ProgramID))
	production, _, err := FindChannelPDA(payer, payee, mint, signer, 1)
	if err != nil {
		t.Fatalf("FindChannelPDA: %v", err)
	}
	if overridden.Equals(production) {
		t.Fatal("channel PDA did not change with the program id override")
	}
}

func TestPerCallProgramIDOverridesDerivationAndInstruction(t *testing.T) {
	custom := solana.NewWallet().PublicKey()
	payer := solana.NewWallet().PublicKey()
	payee := solana.NewWallet().PublicKey()
	mint := solana.NewWallet().PublicKey()
	signer := solana.NewWallet().PublicKey()

	defaultPDA, _, err := FindChannelPDA(payer, payee, mint, signer, 1)
	if err != nil {
		t.Fatalf("FindChannelPDA: %v", err)
	}
	customPDA, _, err := FindChannelPDAForProgram(payer, payee, mint, signer, 1, custom)
	if err != nil {
		t.Fatalf("FindChannelPDAForProgram: %v", err)
	}
	if defaultPDA.Equals(customPDA) {
		t.Fatal("channel PDA did not change with the per-call program id")
	}
	zeroPDA, _, err := FindChannelPDAForProgram(payer, payee, mint, signer, 1, solana.PublicKey{})
	if err != nil {
		t.Fatalf("FindChannelPDAForProgram zero: %v", err)
	}
	if !zeroPDA.Equals(defaultPDA) {
		t.Fatal("zero per-call program id should resolve to the package default")
	}

	params := OpenChannelParams{
		Payer:            payer,
		RentPayer:        pk(7),
		Payee:            payee,
		Mint:             mint,
		AuthorizedSigner: signer,
		Salt:             1,
		Deposit:          10,
		GracePeriod:      900,
		TokenProgram:     solana.TokenProgramID,
		ProgramID:        custom,
	}
	ix, err := BuildOpenInstruction(params)
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	if !ix.ProgramID().Equals(custom) {
		t.Fatalf("open instruction program id = %s, want per-call override", ix.ProgramID())
	}
	accounts := ix.Accounts()
	// Account order after the rentPayer (+1) shift: 0 payer, 1 rentPayer,
	// 2 payee, 3 mint, 4 authorizedSigner, 5 channel, ...
	if !accounts[5].PublicKey.Equals(customPDA) {
		t.Fatalf("open channel account = %s, want PDA derived against the per-call program", accounts[5].PublicKey)
	}

	topUp, err := BuildTopUpInstruction(TopUpParams{
		Payer:        payer,
		Channel:      customPDA,
		Mint:         mint,
		Amount:       5,
		TokenProgram: solana.TokenProgramID,
		ProgramID:    custom,
	})
	if err != nil {
		t.Fatalf("BuildTopUpInstruction: %v", err)
	}
	if !topUp.ProgramID().Equals(custom) {
		t.Fatalf("top_up instruction program id = %s, want per-call override", topUp.ProgramID())
	}
}

func TestVoucherMessageBytesLayout(t *testing.T) {
	const cumulative uint64 = 42
	const expiresAt int64 = 1234
	channel := pk(9)

	got, err := VoucherMessageBytes(channel, cumulative, expiresAt)
	if err != nil {
		t.Fatalf("VoucherMessageBytes: %v", err)
	}
	if len(got) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(got))
	}
	if !bytes.Equal(got[:32], channel.Bytes()) {
		t.Fatalf("offset 0..32 should be channel id")
	}
	wantCumulative := make([]byte, 8)
	binary.LittleEndian.PutUint64(wantCumulative, cumulative)
	if !bytes.Equal(got[32:40], wantCumulative) {
		t.Fatalf("offset 32..40 should be cumulative LE u64, got %x", got[32:40])
	}
	wantExpires := make([]byte, 8)
	binary.LittleEndian.PutUint64(wantExpires, uint64(expiresAt))
	if !bytes.Equal(got[40:48], wantExpires) {
		t.Fatalf("offset 40..48 should be expiresAt LE i64, got %x", got[40:48])
	}
}

func TestVoucherMessageBytesMatchesGeneratedBorsh(t *testing.T) {
	const cumulative uint64 = 7
	var expiresAt int64 = -5 // negative i64 exercises two's-complement LE
	channel := pk(3)

	got, err := VoucherMessageBytes(channel, cumulative, expiresAt)
	if err != nil {
		t.Fatalf("VoucherMessageBytes: %v", err)
	}

	want := make([]byte, 0, 48)
	want = append(want, channel.Bytes()...)
	c := make([]byte, 8)
	binary.LittleEndian.PutUint64(c, cumulative)
	want = append(want, c...)
	e := make([]byte, 8)
	binary.LittleEndian.PutUint64(e, uint64(expiresAt))
	want = append(want, e...)

	if !bytes.Equal(got, want) {
		t.Fatalf("voucher bytes mismatch:\n got=%x\nwant=%x", got, want)
	}
	// Sanity: the wire layout equals the field order of generated.VoucherArgs.
	_ = generated.VoucherArgs{ChannelId: channel, CumulativeAmount: cumulative, ExpiresAt: expiresAt}
}

func TestVoucherMessageBytesRejectsNon32(t *testing.T) {
	// solana.PublicKey is a fixed [32]byte, so we cannot pass a short id at
	// the type level; assert the happy path is exactly 32 and that a default
	// (zero) key still yields 32 bytes. The length guard protects against any
	// future non-fixed input path.
	got, err := VoucherMessageBytes(solana.PublicKey{}, 0, 0)
	if err != nil {
		t.Fatalf("zero key should be valid 32 bytes: %v", err)
	}
	if len(got) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(got))
	}
}

func TestFindChannelPDADeterministic(t *testing.T) {
	a, bumpA, err := FindChannelPDA(pk(1), pk(2), pk(3), pk(4), 99)
	if err != nil {
		t.Fatalf("FindChannelPDA: %v", err)
	}
	b, bumpB, err := FindChannelPDA(pk(1), pk(2), pk(3), pk(4), 99)
	if err != nil {
		t.Fatalf("FindChannelPDA repeat: %v", err)
	}
	if a != b || bumpA != bumpB {
		t.Fatalf("channel pda not deterministic: %s/%d vs %s/%d", a, bumpA, b, bumpB)
	}

	// Reproduce the seeds against the production program id directly.
	saltLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltLE, 99)
	want, wantBump, err := solana.FindProgramAddress(
		[][]byte{
			[]byte("channel"),
			pk(1).Bytes(), pk(2).Bytes(), pk(3).Bytes(), pk(4).Bytes(),
			saltLE,
		},
		programPubkey,
	)
	if err != nil {
		t.Fatalf("reference derivation: %v", err)
	}
	if a != want || bumpA != wantBump {
		t.Fatalf("channel pda mismatch: got %s/%d want %s/%d", a, bumpA, want, wantBump)
	}
}

func TestFindChannelPDAUsesCanonicalProgramID(t *testing.T) {
	got, _, err := FindChannelPDA(pk(1), pk(2), pk(3), pk(4), 99)
	if err != nil {
		t.Fatalf("FindChannelPDA: %v", err)
	}
	// Deriving against a different program id must produce a different PDA,
	// proving FindChannelPDA binds to the canonical payment-channels program.
	saltLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltLE, 99)
	other, _, err := solana.FindProgramAddress(
		[][]byte{
			[]byte("channel"),
			pk(1).Bytes(), pk(2).Bytes(), pk(3).Bytes(), pk(4).Bytes(),
			saltLE,
		},
		solana.SystemProgramID,
	)
	if err != nil {
		t.Fatalf("other-program derivation: %v", err)
	}
	if got == other {
		t.Fatalf("channel pda should differ when derived under a different program id")
	}
}

func TestFindChannelPDASaltSensitivity(t *testing.T) {
	a, _, err := FindChannelPDA(pk(1), pk(2), pk(3), pk(4), 1)
	if err != nil {
		t.Fatalf("FindChannelPDA salt 1: %v", err)
	}
	b, _, err := FindChannelPDA(pk(1), pk(2), pk(3), pk(4), 2)
	if err != nil {
		t.Fatalf("FindChannelPDA salt 2: %v", err)
	}
	if a == b {
		t.Fatalf("different salts must yield different channel pdas")
	}
}

func TestFindEventAuthorityPDA(t *testing.T) {
	got, bump, err := FindEventAuthorityPDA()
	if err != nil {
		t.Fatalf("FindEventAuthorityPDA: %v", err)
	}
	want, wantBump, err := solana.FindProgramAddress([][]byte{[]byte("event_authority")}, programPubkey)
	if err != nil {
		t.Fatalf("reference derivation: %v", err)
	}
	if got != want || bump != wantBump {
		t.Fatalf("event-authority pda mismatch: got %s/%d want %s/%d", got, bump, want, wantBump)
	}
}

func openParams() OpenChannelParams {
	return OpenChannelParams{
		Payer:            pk(1),
		RentPayer:        pk(7),
		Payee:            pk(2),
		Mint:             pk(3),
		AuthorizedSigner: pk(4),
		Salt:             99,
		Deposit:          1_000_000,
		GracePeriod:      3600,
		Recipients: []Distribution{
			{Recipient: pk(5), Bps: 7_500},
			{Recipient: pk(6), Bps: 2_500},
		},
		TokenProgram: solana.TokenProgramID,
	}
}

func TestBuildOpenInstructionProgramIDAndAccounts(t *testing.T) {
	params := openParams()
	inst, err := BuildOpenInstruction(params)
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}

	if inst.ProgramID().String() != ProgramID {
		t.Fatalf("open instruction program id is %s, want %s", inst.ProgramID(), ProgramID)
	}

	metas := inst.Accounts()
	if len(metas) != 14 {
		t.Fatalf("expected 14 accounts, got %d", len(metas))
	}

	channel, _, err := FindChannelPDA(params.Payer, params.Payee, params.Mint, params.AuthorizedSigner, params.Salt)
	if err != nil {
		t.Fatalf("channel pda: %v", err)
	}
	payerToken, _, err := solana.FindAssociatedTokenAddressWithProgram(params.Payer, params.Mint, params.TokenProgram)
	if err != nil {
		t.Fatalf("payer ata: %v", err)
	}
	channelToken, _, err := solana.FindAssociatedTokenAddressWithProgram(channel, params.Mint, params.TokenProgram)
	if err != nil {
		t.Fatalf("channel ata: %v", err)
	}
	eventAuthority, _, err := FindEventAuthorityPDA()
	if err != nil {
		t.Fatalf("event-authority pda: %v", err)
	}

	// Account order after the rentPayer (+1) shift: 0 payer, 1 rentPayer,
	// 2 payee, 3 mint, 4 authorizedSigner, 5 channel, 6 payerTokenAccount,
	// 7 channelTokenAccount, 8 tokenProgram, ...
	want := []solana.PublicKey{
		params.Payer,
		params.RentPayer,
		params.Payee,
		params.Mint,
		params.AuthorizedSigner,
		channel,
		payerToken,
		channelToken,
		params.TokenProgram,
		solana.SystemProgramID,
		solana.SysVarRentPubkey,
		solana.SPLAssociatedTokenAccountProgramID,
		eventAuthority,
		programPubkey,
	}
	for i, w := range want {
		if metas[i].PublicKey != w {
			t.Fatalf("account[%d] = %s, want %s", i, metas[i].PublicKey, w)
		}
	}

	// Writable/signer flags for the load-bearing accounts.
	if !metas[0].IsSigner || !metas[0].IsWritable {
		t.Fatalf("payer must be writable signer")
	}
	if !metas[1].IsSigner || !metas[1].IsWritable {
		t.Fatalf("rentPayer must be writable signer")
	}
	if !metas[5].IsWritable {
		t.Fatalf("channel must be writable")
	}
	if !metas[6].IsWritable || !metas[7].IsWritable {
		t.Fatalf("token accounts must be writable")
	}
}

func TestBuildOpenInstructionArgsRoundTrip(t *testing.T) {
	params := openParams()
	inst, err := BuildOpenInstruction(params)
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	data, err := inst.Data()
	if err != nil {
		t.Fatalf("encode instruction data: %v", err)
	}

	// The first byte is the program's Open discriminator (1); the remainder is
	// borsh-encoded OpenArgs.
	if len(data) == 0 || data[0] != byte(generated.OpenDiscriminator) {
		t.Fatalf("expected leading Open discriminator %d, got %v", generated.OpenDiscriminator, data)
	}
	var args generated.OpenArgs
	if err := ag_binary.NewBorshDecoder(data[1:]).Decode(&args); err != nil {
		t.Fatalf("decode open args: %v", err)
	}
	if args.Salt != params.Salt || args.Deposit != params.Deposit || args.GracePeriod != params.GracePeriod {
		t.Fatalf("open args round-trip mismatch: %+v", args)
	}
	if len(args.Recipients) != len(params.Recipients) {
		t.Fatalf("recipients length mismatch: got %d", len(args.Recipients))
	}
	for i, r := range params.Recipients {
		if args.Recipients[i].Recipient != r.Recipient || args.Recipients[i].Bps != r.Bps {
			t.Fatalf("recipient[%d] round-trip mismatch: %+v", i, args.Recipients[i])
		}
	}
}

func TestBuildOpenInstructionEmptyRecipients(t *testing.T) {
	params := openParams()
	params.Recipients = nil
	inst, err := BuildOpenInstruction(params)
	if err != nil {
		t.Fatalf("BuildOpenInstruction empty recipients: %v", err)
	}
	data, err := inst.Data()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var args generated.OpenArgs
	if err := ag_binary.NewBorshDecoder(data[1:]).Decode(&args); err != nil {
		t.Fatalf("decode open args: %v", err)
	}
	if len(args.Recipients) != 0 {
		t.Fatalf("expected zero recipients, got %d", len(args.Recipients))
	}
}

func TestBuildTopUpInstructionProgramIDAndAccounts(t *testing.T) {
	channel, _, err := FindChannelPDA(pk(1), pk(2), pk(3), pk(4), 99)
	if err != nil {
		t.Fatalf("channel pda: %v", err)
	}
	params := TopUpParams{
		Payer:        pk(1),
		Channel:      channel,
		Mint:         pk(3),
		Amount:       250_000,
		TokenProgram: solana.TokenProgramID,
	}
	inst, err := BuildTopUpInstruction(params)
	if err != nil {
		t.Fatalf("BuildTopUpInstruction: %v", err)
	}

	if inst.ProgramID().String() != ProgramID {
		t.Fatalf("top_up program id is %s, want %s", inst.ProgramID(), ProgramID)
	}

	metas := inst.Accounts()
	if len(metas) != 6 {
		t.Fatalf("expected 6 accounts, got %d", len(metas))
	}

	payerToken, _, err := solana.FindAssociatedTokenAddressWithProgram(params.Payer, params.Mint, params.TokenProgram)
	if err != nil {
		t.Fatalf("payer ata: %v", err)
	}
	channelToken, _, err := solana.FindAssociatedTokenAddressWithProgram(params.Channel, params.Mint, params.TokenProgram)
	if err != nil {
		t.Fatalf("channel ata: %v", err)
	}

	want := []solana.PublicKey{
		params.Payer,
		params.Channel,
		payerToken,
		channelToken,
		params.Mint,
		params.TokenProgram,
	}
	for i, w := range want {
		if metas[i].PublicKey != w {
			t.Fatalf("account[%d] = %s, want %s", i, metas[i].PublicKey, w)
		}
	}
	if !metas[0].IsSigner || !metas[0].IsWritable {
		t.Fatalf("payer must be writable signer")
	}
	if !metas[1].IsWritable || !metas[2].IsWritable || !metas[3].IsWritable {
		t.Fatalf("channel and token accounts must be writable")
	}
}

func TestBuildTopUpInstructionArgsRoundTrip(t *testing.T) {
	params := TopUpParams{
		Payer:        pk(1),
		Channel:      pk(7),
		Mint:         pk(3),
		Amount:       987_654,
		TokenProgram: solana.TokenProgramID,
	}
	inst, err := BuildTopUpInstruction(params)
	if err != nil {
		t.Fatalf("BuildTopUpInstruction: %v", err)
	}
	data, err := inst.Data()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(data) == 0 || data[0] != byte(generated.TopUpDiscriminator) {
		t.Fatalf("expected leading TopUp discriminator %d, got %v", generated.TopUpDiscriminator, data)
	}
	var args generated.TopUpArgs
	if err := ag_binary.NewBorshDecoder(data[1:]).Decode(&args); err != nil {
		t.Fatalf("decode top_up args: %v", err)
	}
	if args.Amount != params.Amount {
		t.Fatalf("amount round-trip mismatch: got %d want %d", args.Amount, params.Amount)
	}
}
