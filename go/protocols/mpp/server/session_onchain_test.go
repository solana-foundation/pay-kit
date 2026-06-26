package server

// Coverage of VerifyOpenTx and the settle-and-distribute composition:
// legacy and v0 transaction decoding, payload-signature binding, challenge
// validation failure modes, RPC-backed confirmation, and the settlement
// instruction sequence derived from stored channel state.

import (
	"bytes"
	"context"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// openTxFixture bundles a freshly built and signed payment-channel open
// transaction with the payload and challenge expectations that accept it.
type openTxFixture struct {
	payer      solana.PrivateKey    // channel payer keypair; fee payer and sole signer of the open tx
	payee      solana.PublicKey     // channel recipient the challenge expects
	authorized solana.PublicKey     // voucher-signing pubkey baked into the channel
	mint       solana.PublicKey     // SPL mint the channel settles in (mainnet USDC)
	channel    solana.PublicKey     // channel PDA derived from payer/payee/mint/authorized + salt
	signature  string               // fee-payer signature of the open tx (base58)
	payload    intents.OpenPayload  // open payload carrying the base64-encoded wire tx
	expected   VerifyOpenTxExpected // challenge-side expectations that accept this fixture
}

const (
	openFixtureSalt    = uint64(7)
	openFixtureDeposit = uint64(1_000_000)
	openFixtureGrace   = uint32(900)
)

// buildOpenTxFixture builds a payer-signed open transaction in the requested
// encoding (clients across the language SDKs emit either).
func buildOpenTxFixture(t *testing.T, v0 bool) openTxFixture {
	t.Helper()

	payer := testutil.NewPrivateKey()
	payee := testutil.NewPrivateKey().PublicKey()
	authorized := testutil.NewPrivateKey().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)

	channel, _, err := paymentchannels.FindChannelPDA(payer.PublicKey(), payee, mint, authorized, openFixtureSalt)
	if err != nil {
		t.Fatalf("FindChannelPDA: %v", err)
	}
	ix, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer: payer.PublicKey(),
		// In this single-signer fixture the fee payer / submitter is `payer`,
		// so rentPayer (slot 1) is pinned to it.
		RentPayer:        payer.PublicKey(),
		Payee:            payee,
		Mint:             mint,
		AuthorizedSigner: authorized,
		Salt:             openFixtureSalt,
		Deposit:          openFixtureDeposit,
		GracePeriod:      openFixtureGrace,
		TokenProgram:     solana.TokenProgramID,
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}

	fixture := openTxFixture{
		payer:      payer,
		payee:      payee,
		authorized: authorized,
		mint:       mint,
		channel:    channel,
	}
	fixture.signature, fixture.payload = signAndAttachOpenTx(t, &fixture, ix, v0)
	fixture.expected = VerifyOpenTxExpected{
		AuthorizedSigner: authorized.String(),
		Currency:         "USDC",
		MaxCap:           5_000_000,
		Network:          "localnet",
		Operator:         payer.PublicKey().String(),
		Recipient:        payee.String(),
	}
	return fixture
}

// signAndAttachOpenTx assembles, signs, and base64-encodes the open
// transaction for ix, returning the fee-payer signature and the open payload
// carrying the wire transaction.
func signAndAttachOpenTx(t *testing.T, fixture *openTxFixture, ix solana.Instruction, v0 bool) (string, intents.OpenPayload) {
	t.Helper()
	blockhash := solana.MustHashFromBase58("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")
	tx, err := solana.NewTransaction([]solana.Instruction{ix}, blockhash, solana.TransactionPayer(fixture.payer.PublicKey()))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	if v0 {
		tx.Message.SetVersion(solana.MessageVersionV0)
	}
	if _, err := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(fixture.payer.PublicKey()) {
			payerKey := fixture.payer
			return &payerKey
		}
		return nil
	}); err != nil {
		t.Fatalf("sign open transaction: %v", err)
	}
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("EncodeTransactionBase64: %v", err)
	}
	signature := tx.Signatures[0].String()
	payload := intents.OpenPayloadPaymentChannel(
		fixture.channel.String(),
		strconv.FormatUint(openFixtureDeposit, 10),
		fixture.payer.PublicKey().String(),
		fixture.payee.String(),
		fixture.mint.String(),
		openFixtureSalt,
		openFixtureGrace,
		fixture.authorized.String(),
		signature,
	).WithTransaction(encoded)
	return signature, payload
}

// ── VerifyOpenTx: accepted encodings ──

func TestVerifyOpenTxAcceptsLegacyEncoding(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	result, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil)
	if err != nil {
		t.Fatalf("VerifyOpenTx: %v", err)
	}
	if result.ChannelID != fixture.channel.String() {
		t.Fatalf("channelId = %s, want %s", result.ChannelID, fixture.channel)
	}
	if result.Deposit != openFixtureDeposit || result.GracePeriod != openFixtureGrace || result.Salt != openFixtureSalt {
		t.Fatalf("result = %+v, want deposit/grace/salt %d/%d/%d", result, openFixtureDeposit, openFixtureGrace, openFixtureSalt)
	}
}

func TestVerifyOpenTxAcceptsV0Encoding(t *testing.T) {
	fixture := buildOpenTxFixture(t, true)
	// Confirm the fixture really emits the v0 wire prefix before asserting it
	// verifies: the message must round-trip through the versioned decoder.
	decoded, err := solanatx.DecodeTransactionBase64(*fixture.payload.Transaction)
	if err != nil {
		t.Fatalf("decode v0 fixture: %v", err)
	}
	if decoded.Message.GetVersion() != solana.MessageVersionV0 {
		t.Fatalf("fixture message version = %v, want v0", decoded.Message.GetVersion())
	}

	result, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil)
	if err != nil {
		t.Fatalf("VerifyOpenTx: %v", err)
	}
	if result.ChannelID != fixture.channel.String() {
		t.Fatalf("channelId = %s, want %s", result.ChannelID, fixture.channel)
	}
}

func TestVerifyOpenTxHonorsExplicitMintAndProgramOverrides(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fixture.expected.Currency = "not-a-currency"
	fixture.expected.Mint = fixture.mint.String()
	programID := paymentchannels.ProgramPubkey()
	fixture.expected.ProgramID = &programID
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err != nil {
		t.Fatalf("VerifyOpenTx with explicit mint/program overrides: %v", err)
	}
}

// ── VerifyOpenTx: failure modes ──

func TestVerifyOpenTxRejectsUndecodableTransaction(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	garbage := "not-base64!"
	fixture.payload.Transaction = &garbage
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "decode open transaction") {
		t.Fatalf("err = %v, want decode rejection", err)
	}
}

func TestVerifyOpenTxRequiresTransaction(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fixture.payload.Transaction = nil
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "transaction is required") {
		t.Fatalf("err = %v, want transaction-required rejection", err)
	}
}

func TestVerifyOpenTxRejectsWrongPayee(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fixture.expected.Recipient = fixture.payer.PublicKey().String()
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "payee") {
		t.Fatalf("err = %v, want payee rejection", err)
	}
}

func TestVerifyOpenTxRejectsWrongMint(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fixture.expected.Currency = "USDT"
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "mint") {
		t.Fatalf("err = %v, want mint rejection", err)
	}
}

func TestVerifyOpenTxRejectsWrongAuthorizedSigner(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fixture.expected.AuthorizedSigner = testutil.NewPrivateKey().PublicKey().String()
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "authorizedSigner") {
		t.Fatalf("err = %v, want authorizedSigner rejection", err)
	}
}

func TestVerifyOpenTxRejectsOverCapDeposit(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fixture.expected.MaxCap = openFixtureDeposit - 1
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "exceeds max cap") {
		t.Fatalf("err = %v, want over-cap rejection", err)
	}
}

func TestVerifyOpenTxRejectsZeroDeposit(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	// Rebuild the open instruction with a zero deposit; the channel PDA does
	// not embed the deposit, so only the deposit check can reject it.
	ix, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer:            fixture.payer.PublicKey(),
		RentPayer:        fixture.payer.PublicKey(),
		Payee:            fixture.payee,
		Mint:             fixture.mint,
		AuthorizedSigner: fixture.authorized,
		Salt:             openFixtureSalt,
		Deposit:          0,
		GracePeriod:      openFixtureGrace,
		TokenProgram:     solana.TokenProgramID,
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	_, fixture.payload = signAndAttachOpenTx(t, &fixture, ix, false)
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "greater than zero") {
		t.Fatalf("err = %v, want zero-deposit rejection", err)
	}
}

func TestVerifyOpenTxRejectsUnboundSignature(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	other := testutil.NewPrivateKey()
	unrelated, err := other.Sign([]byte("unrelated transaction"))
	if err != nil {
		t.Fatalf("sign unrelated payload: %v", err)
	}
	fixture.payload.Signature = unrelated.String()
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "transaction signature") {
		t.Fatalf("err = %v, want signature-binding rejection", err)
	}
}

func TestVerifyOpenTxRejectsSignatureWithoutFeePayerSignature(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	tx, err := solanatx.DecodeTransactionBase64(*fixture.payload.Transaction)
	if err != nil {
		t.Fatalf("decode fixture transaction: %v", err)
	}
	tx.Signatures = []solana.Signature{{}}
	stripped, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("re-encode stripped transaction: %v", err)
	}
	fixture.payload.Transaction = &stripped
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "no fee-payer signature") {
		t.Fatalf("err = %v, want missing fee-payer-signature rejection", err)
	}
}

func TestVerifyOpenTxAcceptsPlaceholderSignatureWithoutBinding(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fixture.payload.Signature = strings.Repeat("1", 64)
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err != nil {
		t.Fatalf("VerifyOpenTx with placeholder signature: %v", err)
	}
}

func TestVerifyOpenTxRejectsMissingOpenInstruction(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	memo, err := solanatx.BuildMemoInstruction("not an open")
	if err != nil {
		t.Fatalf("BuildMemoInstruction: %v", err)
	}
	_, fixture.payload = signAndAttachOpenTx(t, &fixture, memo, false)
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "no payment-channels open instruction") {
		t.Fatalf("err = %v, want missing-open-instruction rejection", err)
	}
}

func TestVerifyOpenTxRejectsChannelPDAMismatch(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	ix, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer:            fixture.payer.PublicKey(),
		RentPayer:        fixture.payer.PublicKey(),
		Payee:            fixture.payee,
		Mint:             fixture.mint,
		AuthorizedSigner: fixture.authorized,
		Salt:             openFixtureSalt,
		Deposit:          openFixtureDeposit,
		GracePeriod:      openFixtureGrace,
		TokenProgram:     solana.TokenProgramID,
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	// Swap the channel account (slot 5, after the rentPayer +1 shift) for an
	// unrelated key while keeping the instruction data intact: the re-derived
	// PDA must catch it.
	data, err := ix.Data()
	if err != nil {
		t.Fatalf("ix.Data: %v", err)
	}
	accounts := make(solana.AccountMetaSlice, len(ix.Accounts()))
	copy(accounts, ix.Accounts())
	tampered := *accounts[5]
	tampered.PublicKey = testutil.NewPrivateKey().PublicKey()
	accounts[5] = &tampered
	forged := solana.NewInstruction(ix.ProgramID(), accounts, data)

	_, fixture.payload = signAndAttachOpenTx(t, &fixture, forged, false)
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "PDA") {
		t.Fatalf("err = %v, want channel-PDA rejection", err)
	}
}

func TestVerifyOpenTxRejectsPayloadChannelIDMismatch(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	other := testutil.NewPrivateKey().PublicKey().String()
	fixture.payload.ChannelID = &other
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "channelId") {
		t.Fatalf("err = %v, want payload-channelId rejection", err)
	}
}

// ── VerifyOpenTx: RPC liveness ──

func TestVerifyOpenTxConfirmsBoundSignatureViaRPC(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fakeRPC := testutil.NewFakeRPC()
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, fakeRPC); err != nil {
		t.Fatalf("VerifyOpenTx with confirmed signature: %v", err)
	}
}

func TestVerifyOpenTxSurfacesRPCFailure(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fakeRPC := testutil.NewFakeRPC()
	fakeRPC.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{Err: "InstructionError"}
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, fakeRPC); err == nil || !strings.Contains(err.Error(), "failed on-chain") {
		t.Fatalf("err = %v, want on-chain failure rejection", err)
	}
}

func TestVerifyOpenTxSurfacesRPCNotFound(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fakeRPC := testutil.NewFakeRPC()
	fakeRPC.Statuses[fixture.signature] = nil
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, fakeRPC); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want not-found rejection", err)
	}
}

func TestIsPlaceholderSignature(t *testing.T) {
	cases := []struct {
		signature string
		want      bool
	}{
		{"", true},
		{strings.Repeat("1", 64), true},
		{strings.Repeat("1", 40), true},
		{strings.Repeat("1", 39), false},
		{strings.Repeat("1", 63) + "2", false},
		{"5VERYrealLookingBase58SignatureValue11111111111111111111111111111", false},
	}
	for _, tc := range cases {
		if got := isPlaceholderSignature(tc.signature); got != tc.want {
			t.Fatalf("isPlaceholderSignature(%q) = %v, want %v", tc.signature, got, tc.want)
		}
	}
}

// ── NewOpenTxVerifier wiring ──

// openSessionConfig returns a session config whose challenge values accept
// the fixture's open transaction.
func openSessionConfig(fixture openTxFixture) SessionConfig {
	return SessionConfig{
		// The fixture pins rentPayer (the operator/fee payer) to its own payer.
		Operator:  fixture.payer.PublicKey().String(),
		Recipient: fixture.payee.String(),
		MaxCap:    5_000_000,
		Currency:  "USDC",
		Decimals:  6,
		Network:   "localnet",
		Modes:     []intents.SessionMode{intents.SessionModePush},
	}
}

func TestNewOpenTxVerifierAcceptsValidOpenThroughProcessOpen(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := openSessionConfig(fixture)
	config.VerifyOpenTx = NewOpenTxVerifier(config, nil)
	server := newSessionTestServer(config)

	state, err := server.ProcessOpen(context.Background(), &fixture.payload)
	if err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}
	if state.ChannelID != fixture.channel.String() {
		t.Fatalf("channelId = %s, want %s", state.ChannelID, fixture.channel)
	}
}

func TestNewOpenTxVerifierRejectsForeignRecipientThroughProcessOpen(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := openSessionConfig(fixture)
	config.Recipient = fixture.payer.PublicKey().String() // not the tx payee
	config.VerifyOpenTx = NewOpenTxVerifier(config, nil)
	server := newSessionTestServer(config)

	if _, err := server.ProcessOpen(context.Background(), &fixture.payload); err == nil || !strings.Contains(err.Error(), "payee") {
		t.Fatalf("err = %v, want payee rejection through the verifier seam", err)
	}
}

func TestNewOpenTxVerifierWithoutTransactionRequiresRPC(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := openSessionConfig(fixture)
	verifier := NewOpenTxVerifier(config, nil)
	payload := fixture.payload
	payload.Transaction = nil
	if _, err := verifier(context.Background(), &payload); err == nil || !strings.Contains(err.Error(), "RPC client") {
		t.Fatalf("err = %v, want rpc-required rejection", err)
	}
}

func TestNewOpenTxVerifierReturnsChannelPayerForTransaction(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := openSessionConfig(fixture)
	verifier := NewOpenTxVerifier(config, nil)
	payer, err := verifier(context.Background(), &fixture.payload)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	if payer != fixture.payer.PublicKey().String() {
		t.Fatalf("verifier payer = %q, want %q", payer, fixture.payer.PublicKey())
	}
}

func TestNewOpenTxVerifierWithoutTransactionConfirmsSignature(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := openSessionConfig(fixture)
	verifier := NewOpenTxVerifier(config, testutil.NewFakeRPC())
	payload := fixture.payload
	payload.Transaction = nil
	if _, err := verifier(context.Background(), &payload); err != nil {
		t.Fatalf("verifier with confirmed signature: %v", err)
	}
}

// ── NewTopUpTxVerifier ──

func TestNewTopUpTxVerifierNilRPCDisablesTheSeam(t *testing.T) {
	if verifier := NewTopUpTxVerifier(nil); verifier != nil {
		t.Fatal("NewTopUpTxVerifier(nil) must return nil so the seam stays trust-as-provided")
	}
}

func TestNewTopUpTxVerifierConfirmsSignature(t *testing.T) {
	signer := testutil.NewPrivateKey()
	signature, err := signer.Sign([]byte("top-up"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verifier := NewTopUpTxVerifier(testutil.NewFakeRPC())
	payload := &intents.TopUpPayload{ChannelID: "chan", NewDeposit: "2000000", Signature: signature.String()}
	if _, err := verifier(context.Background(), payload); err != nil {
		t.Fatalf("verifier with confirmed signature: %v", err)
	}
}

func TestNewTopUpTxVerifierSurfacesFailureAndNotFound(t *testing.T) {
	signer := testutil.NewPrivateKey()
	signature, err := signer.Sign([]byte("top-up"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	fakeRPC := testutil.NewFakeRPC()
	fakeRPC.Statuses[signature.String()] = &rpc.SignatureStatusesResult{Err: "InstructionError"}
	verifier := NewTopUpTxVerifier(fakeRPC)
	payload := &intents.TopUpPayload{ChannelID: "chan", NewDeposit: "2000000", Signature: signature.String()}
	if _, err := verifier(context.Background(), payload); err == nil || !strings.Contains(err.Error(), "top-up") {
		t.Fatalf("err = %v, want top-up failure rejection", err)
	}

	fakeRPC.Statuses[signature.String()] = nil
	if _, err := verifier(context.Background(), payload); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want not-found rejection", err)
	}

	if _, err := verifier(context.Background(), &intents.TopUpPayload{Signature: "not-base58!"}); err == nil || !strings.Contains(err.Error(), "invalid top-up tx signature") {
		t.Fatalf("err = %v, want invalid-signature rejection", err)
	}
}

// ── SettlementInstructions ──

// openSettlementChannel opens a payment-channel-shaped session (payer set, so
// the distribute refund account can be derived) and returns the voucher
// signer plus the channel id.
func openSettlementChannel(t *testing.T, server *SessionServer, payer solana.PublicKey) (testVoucherSigner, string) {
	t.Helper()
	signer := newTestVoucherSigner(t)
	channelID := testutil.NewPrivateKey().PublicKey().String()
	payload := intents.OpenPayloadPaymentChannel(
		channelID, "1000000",
		payer.String(),
		sessionTestRecipient,
		paycore.USDCMainnetMint,
		openFixtureSalt, openFixtureGrace,
		signer.Address(), "dummy_tx_sig",
	)
	if _, err := server.ProcessOpen(context.Background(), &payload); err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}
	return signer, channelID
}

func TestSettlementInstructionsWithVoucher(t *testing.T) {
	config := sessionTestConfig()
	config.Splits = []Split{{Recipient: testutil.NewPrivateKey().PublicKey(), BPS: 250}}
	server := newSessionTestServer(config)
	payer := testutil.NewPrivateKey().PublicKey()
	merchant := testutil.NewPrivateKey().PublicKey()
	signer, channelID := openSettlementChannel(t, server, payer)

	if _, err := submitVoucher(t, server, signer, channelID, 500); err != nil {
		t.Fatalf("submitVoucher: %v", err)
	}
	if _, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID}); err != nil {
		t.Fatalf("ProcessClose: %v", err)
	}

	instructions, err := server.SettlementInstructions(context.Background(), channelID, merchant)
	if err != nil {
		t.Fatalf("SettlementInstructions: %v", err)
	}
	if len(instructions) != 3 {
		t.Fatalf("instructions = %d, want 3 (ed25519 + settle_and_finalize + distribute)", len(instructions))
	}

	// Instruction 0: the Ed25519 precompile over the stored highest voucher.
	if !instructions[0].ProgramID().Equals(paymentchannels.Ed25519ProgramPubkey()) {
		t.Fatalf("instruction 0 program = %s, want Ed25519 precompile", instructions[0].ProgramID())
	}
	state, err := server.Store().GetChannel(context.Background(), channelID)
	if err != nil || state == nil {
		t.Fatalf("GetChannel: %v", err)
	}
	if state.HighestVoucherExpiresAt == nil {
		t.Fatal("expected a stored voucher expiry")
	}
	channel := solana.MustPublicKeyFromBase58(channelID)
	wantMessage, err := paymentchannels.VoucherMessageBytes(channel, 500, *state.HighestVoucherExpiresAt)
	if err != nil {
		t.Fatalf("VoucherMessageBytes: %v", err)
	}
	precompileData, err := instructions[0].Data()
	if err != nil {
		t.Fatalf("precompile.Data: %v", err)
	}
	if !bytes.Equal(precompileData[112:160], wantMessage) {
		t.Fatal("precompile message != stored voucher payload")
	}

	// Instruction 1: settle_and_finalize committing the watermark.
	settleData, err := instructions[1].Data()
	if err != nil {
		t.Fatalf("settle.Data: %v", err)
	}
	// The voucher (incl. cumulative=500) lives in the precompile, verified
	// above; settle_and_finalize carries only [disc=4][hasVoucher=1].
	if len(settleData) != 2 || settleData[0] != 4 || settleData[1] != 1 {
		t.Fatalf("settle data = %v, want [4 1]", settleData)
	}
	if !instructions[1].Accounts()[0].PublicKey.Equals(merchant) {
		t.Fatalf("settle merchant = %s, want %s", instructions[1].Accounts()[0].PublicKey, merchant)
	}

	// Instruction 2: distribute with the configured split appended.
	distributeData, err := instructions[2].Data()
	if err != nil {
		t.Fatalf("distribute.Data: %v", err)
	}
	if distributeData[0] != 7 {
		t.Fatalf("distribute discriminator = %d, want 7", distributeData[0])
	}
	// Distribute fixed head after the rentPayer (+1) shift: 0 channel, 1 payer,
	// 2 rentPayer, 3 channelTokenAccount, 4 payerTokenAccount, 5 payeeToken,
	// 6 treasuryToken, 7 mint, 8 tokenProgram, 9 eventAuthority, 10 selfProgram.
	if got := len(instructions[2].Accounts()); got != 12 {
		t.Fatalf("distribute accounts = %d, want 12 (11 fixed + 1 split ATA)", got)
	}
	payerATA, _, err := solana.FindAssociatedTokenAddressWithProgram(
		payer, solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint), solana.TokenProgramID)
	if err != nil {
		t.Fatalf("derive payer ATA: %v", err)
	}
	if !instructions[2].Accounts()[4].PublicKey.Equals(payerATA) {
		t.Fatalf("distribute payer token account = %s, want %s", instructions[2].Accounts()[4].PublicKey, payerATA)
	}
}

func TestSettlementInstructionsVoucherlessClose(t *testing.T) {
	config := sessionTestConfig()
	programID := paymentchannels.ProgramPubkey()
	config.ProgramID = &programID
	server := newSessionTestServer(config)
	payer := testutil.NewPrivateKey().PublicKey()
	merchant := testutil.NewPrivateKey().PublicKey()
	_, channelID := openSettlementChannel(t, server, payer)

	if _, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID}); err != nil {
		t.Fatalf("ProcessClose: %v", err)
	}
	instructions, err := server.SettlementInstructions(context.Background(), channelID, merchant)
	if err != nil {
		t.Fatalf("SettlementInstructions: %v", err)
	}
	if len(instructions) != 2 {
		t.Fatalf("instructions = %d, want 2 (no precompile without a voucher)", len(instructions))
	}
	settleData, err := instructions[0].Data()
	if err != nil {
		t.Fatalf("settle.Data: %v", err)
	}
	if settleData[len(settleData)-1] != 0 {
		t.Fatalf("hasVoucher = %d, want 0", settleData[len(settleData)-1])
	}
	if got := binary.LittleEndian.Uint64(settleData[33:41]); got != 0 {
		t.Fatalf("settled cumulative = %d, want 0", got)
	}
}

func TestSettlementInstructionsResolvesToken2022FromCurrency(t *testing.T) {
	config := sessionTestConfig()
	config.Currency = "PYUSD"
	config.Network = "mainnet"
	server := newSessionTestServer(config)
	payer := testutil.NewPrivateKey().PublicKey()
	merchant := testutil.NewPrivateKey().PublicKey()

	signer := newTestVoucherSigner(t)
	channelID := testutil.NewPrivateKey().PublicKey().String()
	payload := intents.OpenPayloadPaymentChannel(
		channelID, "1000000",
		payer.String(), sessionTestRecipient, paycore.PYUSDMainnetMint,
		openFixtureSalt, openFixtureGrace, signer.Address(), "dummy_tx_sig",
	)
	if _, err := server.ProcessOpen(context.Background(), &payload); err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}

	instructions, err := server.SettlementInstructions(context.Background(), channelID, merchant)
	if err != nil {
		t.Fatalf("SettlementInstructions: %v", err)
	}
	distribute := instructions[len(instructions)-1]
	accounts := distribute.Accounts()
	// After the rentPayer (+1) shift: mint is slot 7, tokenProgram slot 8.
	if got := accounts[7].PublicKey.String(); got != paycore.PYUSDMainnetMint {
		t.Fatalf("distribute mint = %s, want PYUSD mainnet mint", got)
	}
	if got := accounts[8].PublicKey.String(); got != paycore.Token2022Program {
		t.Fatalf("distribute token program = %s, want Token-2022", got)
	}
}

func TestSettlementInstructionsErrorPaths(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	merchant := testutil.NewPrivateKey().PublicKey()

	if _, err := server.SettlementInstructions(context.Background(), "missing-channel", merchant); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want channel-not-found rejection", err)
	}

	// A channel opened without a payer/owner has no refund token account.
	_, channelID := openTestChannel(t, server, 1_000_000)
	if _, err := server.SettlementInstructions(context.Background(), channelID, merchant); err == nil || !strings.Contains(err.Error(), "payer is unknown") {
		t.Fatalf("err = %v, want unknown-payer rejection", err)
	}

	// SOL is not an SPL token, so settlement cannot derive token accounts.
	solConfig := sessionTestConfig()
	solConfig.Currency = "SOL"
	solServer := newSessionTestServer(solConfig)
	payer := testutil.NewPrivateKey().PublicKey()
	_, solChannel := openSettlementChannel(t, solServer, payer)
	if _, err := solServer.SettlementInstructions(context.Background(), solChannel, merchant); err == nil || !strings.Contains(err.Error(), "SPL token") {
		t.Fatalf("err = %v, want SPL-token rejection", err)
	}

	// A pull-style session id that is not a base58 pubkey cannot be settled
	// through the payment-channels program.
	if _, err := server.ProcessOpen(context.Background(), sessionOpenPayload("not-a-pubkey!", 1_000_000, "signer1")); err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}
	if _, err := server.SettlementInstructions(context.Background(), "not-a-pubkey!", merchant); err == nil || !strings.Contains(err.Error(), "invalid channel id") {
		t.Fatalf("err = %v, want invalid-channel-id rejection", err)
	}

	// A challenge recipient that is not a valid pubkey fails distribute
	// derivation.
	badRecipientConfig := sessionTestConfig()
	badRecipientConfig.Recipient = "not-a-recipient!"
	badRecipientServer := newSessionTestServer(badRecipientConfig)
	_, badChannel := openSettlementChannel(t, badRecipientServer, payer)
	if _, err := badRecipientServer.SettlementInstructions(context.Background(), badChannel, merchant); err == nil || !strings.Contains(err.Error(), "invalid recipient") {
		t.Fatalf("err = %v, want invalid-recipient rejection", err)
	}
}
