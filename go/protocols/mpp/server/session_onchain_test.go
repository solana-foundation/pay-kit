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

	solana "github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

// openTxFixture bundles a freshly built and signed payment-channel open
// transaction with the payload and challenge expectations that accept it.
type openTxFixture struct {
	payer        solana.PrivateKey    // channel payer keypair; fee payer and sole signer of the open tx
	payee        solana.PublicKey     // channel recipient the challenge expects
	authorized   solana.PublicKey     // voucher-signing pubkey baked into the channel
	mint         solana.PublicKey     // SPL mint the channel settles in (mainnet USDC)
	tokenProgram solana.PublicKey     // token program owning mint
	channel      solana.PublicKey     // channel PDA derived from payer/payee/mint/authorized + salt
	signature    string               // fee-payer signature of the open tx (base58)
	payload      intents.OpenPayload  // open payload carrying the base64-encoded wire tx
	expected     VerifyOpenTxExpected // challenge-side expectations that accept this fixture
}

const (
	openFixtureSalt     = uint64(7)
	openFixtureDeposit  = uint64(1_000_000)
	openFixtureGrace    = uint32(900)
	openFixtureOpenSlot = uint64(321_654_987)
)

// buildOpenTxFixture builds a payer-signed open transaction in the requested
// encoding (clients across the language SDKs emit either).
func buildOpenTxFixture(t *testing.T, v0 bool) openTxFixture {
	t.Helper()

	payer := testutil.NewPrivateKey()
	payee := testutil.NewPrivateKey().PublicKey()
	authorized := testutil.NewPrivateKey().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)

	channel, _, err := paymentchannels.FindChannelPDA(payer.PublicKey(), payee, mint, authorized, openFixtureSalt, openFixtureOpenSlot)
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
		TokenProgram:     solana.TokenProgramID,
		AuthorizedSigner: authorized,
		Salt:             openFixtureSalt,
		OpenSlot:         openFixtureOpenSlot,
		Deposit:          openFixtureDeposit,
		GracePeriod:      openFixtureGrace,
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}

	fixture := openTxFixture{
		payer:        payer,
		payee:        payee,
		authorized:   authorized,
		mint:         mint,
		tokenProgram: solana.TokenProgramID,
		channel:      channel,
	}
	fixture.signature, fixture.payload = signAndAttachOpenTx(t, &fixture, ix, v0)
	fixture.expected = VerifyOpenTxExpected{
		AuthorizedSigner: authorized.String(),
		Currency:         "USDC",
		TokenProgram:     fixture.tokenProgram.String(),
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
		openFixtureOpenSlot,
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

func TestVerifyOpenTxRejectsDistributionMismatch(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	attacker := testutil.NewPrivateKey().PublicKey()
	ix, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer:            fixture.payer.PublicKey(),
		RentPayer:        fixture.payer.PublicKey(),
		Payee:            fixture.payee,
		Mint:             fixture.mint,
		AuthorizedSigner: fixture.authorized,
		Salt:             openFixtureSalt,
		OpenSlot:         openFixtureOpenSlot,
		Deposit:          openFixtureDeposit,
		GracePeriod:      openFixtureGrace,
		Recipients: []paymentchannels.Distribution{
			{Recipient: attacker, Bps: 10_000},
		},
		TokenProgram: solana.TokenProgramID,
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	_, fixture.payload = signAndAttachOpenTx(t, &fixture, ix, false)
	fixture.expected.Splits = []Split{{Recipient: fixture.payee, BPS: 10_000}}

	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "recipient[0]") {
		t.Fatalf("err = %v, want distribution-mismatch rejection", err)
	}
}

func TestVerifyOpenTxAcceptsMatchingDistribution(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	secondary := testutil.NewPrivateKey().PublicKey()
	splits := []Split{
		{Recipient: fixture.payee, BPS: 8_000},
		{Recipient: secondary, BPS: 2_000},
	}
	ix, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer:            fixture.payer.PublicKey(),
		RentPayer:        fixture.payer.PublicKey(),
		Payee:            fixture.payee,
		Mint:             fixture.mint,
		AuthorizedSigner: fixture.authorized,
		Salt:             openFixtureSalt,
		OpenSlot:         openFixtureOpenSlot,
		Deposit:          openFixtureDeposit,
		GracePeriod:      openFixtureGrace,
		Recipients: []paymentchannels.Distribution{
			{Recipient: fixture.payee, Bps: 8_000},
			{Recipient: secondary, Bps: 2_000},
		},
		TokenProgram: solana.TokenProgramID,
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	_, fixture.payload = signAndAttachOpenTx(t, &fixture, ix, false)
	fixture.expected.Splits = splits

	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err != nil {
		t.Fatalf("VerifyOpenTx: %v", err)
	}
}

func TestVerifyOpenTxRejectsAddressLookupTables(t *testing.T) {
	// FIX #7: a v0 open tx that uses address lookup tables must be rejected.
	// The fee-payer co-sign guard validates accounts from the STATIC keys, so
	// an ALT could hide the real payee/rentPayer/mint/authorizedSigner/channel
	// behind the guard. Inject an ALT lookup into an otherwise-valid v0 tx and
	// confirm it is rejected before any account check passes.
	fixture := buildOpenTxFixture(t, true)
	tx, err := solanatx.DecodeTransactionBase64(*fixture.payload.Transaction)
	if err != nil {
		t.Fatalf("decode v0 fixture: %v", err)
	}
	tx.Message.SetAddressTableLookups([]solana.MessageAddressTableLookup{{
		AccountKey:      testutil.NewPrivateKey().PublicKey(),
		WritableIndexes: solana.Uint8SliceAsNum{0},
		ReadonlyIndexes: solana.Uint8SliceAsNum{1},
	}})
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("re-encode tx with ALT: %v", err)
	}
	fixture.payload.Transaction = &encoded

	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "address lookup tables") {
		t.Fatalf("err = %v, want address-lookup-table rejection", err)
	}
}

func TestSubmitOpenTxRejectsExtraAndDuplicateInstructionsBeforeCosigning(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	openIx, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer: fixture.payer.PublicKey(), RentPayer: fixture.payer.PublicKey(), Payee: fixture.payee,
		Mint: fixture.mint, AuthorizedSigner: fixture.authorized, Salt: openFixtureSalt,
		OpenSlot: openFixtureOpenSlot, Deposit: openFixtureDeposit, GracePeriod: openFixtureGrace,
		TokenProgram: solana.TokenProgramID,
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	drain, err := solanatx.BuildSOLTransfer(fixture.payer.PublicKey(), testutil.NewPrivateKey().PublicKey(), 1)
	if err != nil {
		t.Fatalf("BuildSOLTransfer: %v", err)
	}

	for _, tc := range []struct {
		name string
		ix   []solana.Instruction
	}{
		{name: "operator drain", ix: []solana.Instruction{openIx, drain}},
		{name: "duplicate open", ix: []solana.Instruction{openIx, openIx}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := solana.NewTransaction(tc.ix,
				solana.MustHashFromBase58("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"),
				solana.TransactionPayer(fixture.payer.PublicKey()))
			if err != nil {
				t.Fatalf("NewTransaction: %v", err)
			}
			if _, err := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
				if key.Equals(fixture.payer.PublicKey()) {
					payer := fixture.payer
					return &payer
				}
				return nil
			}); err != nil {
				t.Fatalf("sign transaction: %v", err)
			}
			encoded, err := solanatx.EncodeTransactionBase64(tx)
			if err != nil {
				t.Fatalf("EncodeTransactionBase64: %v", err)
			}
			payload := fixture.payload
			payload.Transaction = &encoded
			payload.Signature = tx.Signatures[0].String()
			fake := testutil.NewFakeRPC()
			_, err = SubmitOpenTx(context.Background(), fixture.expected, &payload, nil, fake)
			if err == nil || !strings.Contains(err.Error(), "exactly one instruction") {
				t.Fatalf("SubmitOpenTx error = %v, want pre-sign instruction rejection", err)
			}
			if len(fake.Sent) != 0 {
				t.Fatalf("broadcasts = %d, want zero before co-sign/broadcast", len(fake.Sent))
			}
		})
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

func TestVerifySignatureOnlyOpenFetchesAndBindsTransaction(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	tx, err := solanatx.DecodeTransactionBase64(*fixture.payload.Transaction)
	if err != nil {
		t.Fatalf("DecodeTransactionBase64: %v", err)
	}
	fake := testutil.NewFakeRPC()
	fake.BySig[fixture.signature] = tx
	payload := fixture.payload
	payload.Transaction = nil

	verified, _, err := verifySignatureOnlyOpen(context.Background(), fixture.expected, &payload, fake)
	if err != nil {
		t.Fatalf("verifySignatureOnlyOpen: %v", err)
	}
	if verified.ChannelID != fixture.channel.String() || verified.Deposit != openFixtureDeposit {
		t.Fatalf("verified = %+v", verified)
	}

	unrelated := buildOpenTxFixture(t, false)
	unrelatedTx, err := solanatx.DecodeTransactionBase64(*unrelated.payload.Transaction)
	if err != nil {
		t.Fatalf("decode unrelated transaction: %v", err)
	}
	fake.BySig[unrelated.signature] = unrelatedTx
	payload.Signature = unrelated.signature
	if _, _, err := verifySignatureOnlyOpen(context.Background(), fixture.expected, &payload, fake); err == nil {
		t.Fatal("unrelated confirmed transaction was accepted")
	}
}

func TestConfirmTransactionSignatureRejectsProcessed(t *testing.T) {
	fake := testutil.NewFakeRPC()
	signature := confirmedSignature(0x91)
	fake.Statuses[signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusProcessed,
	}
	if err := confirmTransactionSignature(context.Background(), fake, signature, "open"); err == nil || !strings.Contains(err.Error(), "only processed") {
		t.Fatalf("processed status error = %v", err)
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

func TestVerifyOpenTxRejectsForgedMessageWithCopiedConfirmedSignature(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	tx, err := solanatx.DecodeTransactionBase64(*fixture.payload.Transaction)
	if err != nil {
		t.Fatalf("decode fixture transaction: %v", err)
	}
	// Copying a confirmed signature onto a different message preserves the
	// signature/status lookup but must fail cryptographic verification first.
	tx.Message.RecentBlockhash = solana.MustHashFromBase58("4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h")
	forgedWire, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("encode forged transaction: %v", err)
	}
	fixture.payload.Transaction = &forgedWire
	fakeRPC := testutil.NewFakeRPC()
	fakeRPC.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
	}
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, fakeRPC); err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Fatalf("err = %v, want forged-message signature rejection", err)
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
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Fatalf("err = %v, want missing fee-payer-signature rejection", err)
	}
}

func TestVerifyOpenTxRejectsPlaceholderSignature(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fixture.payload.Signature = strings.Repeat("1", 64)
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "must be a real transaction signature") {
		t.Fatalf("placeholder signature error = %v", err)
	}
}

func TestVerifyOpenTxRejectsTokenProgramMismatch(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	token2022 := solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	ix, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer:            fixture.payer.PublicKey(),
		RentPayer:        fixture.payer.PublicKey(),
		Payee:            fixture.payee,
		Mint:             fixture.mint,
		AuthorizedSigner: fixture.authorized,
		Salt:             openFixtureSalt,
		OpenSlot:         openFixtureOpenSlot,
		Deposit:          openFixtureDeposit,
		GracePeriod:      openFixtureGrace,
		TokenProgram:     token2022,
	})
	if err != nil {
		t.Fatalf("BuildOpenInstruction: %v", err)
	}
	_, fixture.payload = signAndAttachOpenTx(t, &fixture, ix, false)
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil || !strings.Contains(err.Error(), "token program") {
		t.Fatalf("err = %v, want token-program mismatch rejection", err)
	}
}

func TestVerifyOpenTxRejectsAdditionalInstructions(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	tx, err := solanatx.DecodeTransactionBase64(*fixture.payload.Transaction)
	if err != nil {
		t.Fatalf("decode fixture transaction: %v", err)
	}
	tx.Message.Instructions = append(tx.Message.Instructions, tx.Message.Instructions[0])
	if err := solanatx.SignTransaction(tx, fixture.payer); err != nil {
		t.Fatalf("re-sign transaction: %v", err)
	}
	wire, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("encode transaction: %v", err)
	}
	fixture.payload.Transaction = &wire
	fixture.payload.Signature = tx.Signatures[0].String()

	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, nil); err == nil ||
		!strings.Contains(err.Error(), "exactly one instruction") {
		t.Fatalf("additional-instruction error = %v", err)
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
		OpenSlot:         openFixtureOpenSlot,
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

func TestNewOpenTxVerifierWithoutTransactionVerifiesFetchedTransaction(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := openSessionConfig(fixture)
	fakeRPC := testutil.NewFakeRPC()
	tx, err := solanatx.DecodeTransactionBase64(*fixture.payload.Transaction)
	if err != nil {
		t.Fatalf("decode fixture transaction: %v", err)
	}
	fakeRPC.BySig[fixture.payload.Signature] = tx
	verifier := NewOpenTxVerifier(config, fakeRPC)
	payload := fixture.payload
	payload.Transaction = nil
	if _, err := verifier(context.Background(), &payload); err != nil {
		t.Fatalf("verifier with confirmed signature: %v", err)
	}
}

func TestNewOpenTxVerifierKeepsStructuralPlaceholderAcceptance(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := openSessionConfig(fixture)
	verifier := NewOpenTxVerifier(config, nil)
	payload := fixture.payload
	payload.Signature = strings.Repeat("1", 64)
	payer, err := verifier(context.Background(), &payload)
	if err != nil {
		t.Fatalf("structural verifier: %v", err)
	}
	if payer != fixture.payer.PublicKey().String() {
		t.Fatalf("verifier payer = %q, want %q", payer, fixture.payer.PublicKey())
	}
}

func authoritativeOpenSessionConfig(fixture openTxFixture) SessionConfig {
	config := openSessionConfig(fixture)
	config.Network = "mainnet"
	return config
}

func TestNewOpenStateTxVerifierRejectsPlaceholderTransaction(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := authoritativeOpenSessionConfig(fixture)
	verifier := NewOpenStateTxVerifier(config, testutil.NewFakeRPC())
	payload := fixture.payload
	payload.Signature = strings.Repeat("1", 64)

	if _, err := verifier(context.Background(), &payload); err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Fatalf("err = %v, want direct placeholder rejection", err)
	}
}

func TestNewOpenStateTxVerifierRejectsUnconfirmedTransactionBeforeAccountRead(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := authoritativeOpenSessionConfig(fixture)
	fake := testutil.NewFakeRPC()
	fake.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusProcessed,
		Slot:               777,
	}
	verifier := NewOpenStateTxVerifier(config, fake)

	if _, err := verifier(context.Background(), &fixture.payload); err == nil || !strings.Contains(err.Error(), "only processed") {
		t.Fatalf("err = %v, want unconfirmed rejection", err)
	}
	if fake.LastAccountInfoOpts != nil {
		t.Fatal("channel account was read before signature confirmation")
	}
}

func TestNewOpenStateTxVerifierRejectsStaleChannelAccount(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := authoritativeOpenSessionConfig(fixture)
	fake := testutil.NewFakeRPC()
	fake.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
		Slot:               777,
	}
	seedSessionChannelAccountWithSeeds(
		t, fake, fixture.channel, openFixtureDeposit, fixture.payer.PublicKey(), fixture.payee,
		fixture.authorized, fixture.mint, pcgen.ChannelStatus_Open, openFixtureSalt, openFixtureOpenSlot+1,
		fixture.payer.PublicKey(),
	)

	verifier := NewOpenStateTxVerifier(config, fake)
	if _, err := verifier(context.Background(), &fixture.payload); err == nil || !strings.Contains(err.Error(), "PDA") {
		t.Fatalf("err = %v, want stale-channel rejection", err)
	}
}

func TestNewOpenStateTxVerifierReturnsConfirmedAuthoritativeChannelFacts(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := authoritativeOpenSessionConfig(fixture)
	fake := testutil.NewFakeRPC()
	confirmedSlot := uint64(777)
	fake.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
		Slot:               confirmedSlot,
	}
	accountDeposit := openFixtureDeposit
	seedSessionChannelAccountWithSeeds(
		t, fake, fixture.channel, accountDeposit, fixture.payer.PublicKey(), fixture.payee,
		fixture.authorized, fixture.mint, pcgen.ChannelStatus_Open, openFixtureSalt, openFixtureOpenSlot,
		fixture.payer.PublicKey(),
	)

	result, err := NewOpenStateTxVerifier(config, fake)(context.Background(), &fixture.payload)
	if err != nil {
		t.Fatalf("state verifier: %v", err)
	}
	if result.ChannelID != fixture.channel.String() || result.Deposit != accountDeposit || result.Payer != fixture.payer.PublicKey().String() {
		t.Fatalf("result = %+v, want account-derived channel/deposit/payer", result)
	}
	if result.Salt != openFixtureSalt || result.OpenSlot != openFixtureOpenSlot || result.GracePeriod != openFixtureGrace {
		t.Fatalf("result = %+v, want account-derived seeds/grace", result)
	}
	if fake.LastAccountInfoOpts == nil || fake.LastAccountInfoOpts.MinContextSlot == nil ||
		*fake.LastAccountInfoOpts.MinContextSlot != confirmedSlot {
		t.Fatalf("account read minContextSlot = %#v, want %d", fake.LastAccountInfoOpts, confirmedSlot)
	}
}

func TestNewOpenStateTxVerifierRejectsAssertedDepositMismatch(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	config := authoritativeOpenSessionConfig(fixture)
	fake := testutil.NewFakeRPC()
	fake.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
		Slot:               777,
	}
	seedSessionChannelAccountWithSeeds(
		t, fake, fixture.channel, openFixtureDeposit, fixture.payer.PublicKey(), fixture.payee,
		fixture.authorized, fixture.mint, pcgen.ChannelStatus_Open, openFixtureSalt, openFixtureOpenSlot,
		fixture.payer.PublicKey(),
	)
	claimedDeposit := "999999"
	payload := fixture.payload
	payload.Deposit = &claimedDeposit
	verifier := NewOpenStateTxVerifier(config, fake)
	if _, err := verifier(context.Background(), &payload); err == nil || !strings.Contains(err.Error(), "!= asserted deposit") {
		t.Fatalf("err = %v, want asserted-deposit rejection", err)
	}
}

// ── NewTopUpTxVerifier ──

func TestNewTopUpTxVerifierNilRPCDisablesTheSeam(t *testing.T) {
	if verifier := NewTopUpTxVerifier(SessionConfig{}, nil); verifier != nil {
		t.Fatal("NewTopUpTxVerifier(nil) must return nil so the seam stays trust-as-provided")
	}
}

func buildTopUpTx(t *testing.T, channel solana.PublicKey, currentDeposit, amount uint64) (*solana.Transaction, *intents.TopUpPayload) {
	t.Helper()
	payer := testutil.NewPrivateKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	ix, err := paymentchannels.BuildTopUpInstruction(paymentchannels.TopUpParams{
		Payer:        payer.PublicKey(),
		Channel:      channel,
		Mint:         mint,
		Amount:       amount,
		TokenProgram: solana.TokenProgramID,
	})
	if err != nil {
		t.Fatalf("BuildTopUpInstruction: %v", err)
	}
	tx, err := solana.NewTransaction(
		[]solana.Instruction{ix},
		solana.MustHashFromBase58("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"),
		solana.TransactionPayer(payer.PublicKey()),
	)
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	if _, err := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(payer.PublicKey()) {
			return &payer
		}
		return nil
	}); err != nil {
		t.Fatalf("sign top-up transaction: %v", err)
	}
	return tx, &intents.TopUpPayload{
		ChannelID:  channel.String(),
		NewDeposit: strconv.FormatUint(currentDeposit+amount, 10),
		Signature:  tx.Signatures[0].String(),
	}
}

func TestNewTopUpTxVerifierBindsConfirmedTransaction(t *testing.T) {
	channel := testutil.NewPrivateKey().PublicKey()
	tx, payload := buildTopUpTx(t, channel, 1_000_000, 500_000)
	fakeRPC := testutil.NewFakeRPC()
	fakeRPC.BySig[payload.Signature] = tx
	verifier := NewTopUpTxVerifier(SessionConfig{}, fakeRPC)
	if err := verifier(context.Background(), payload, 1_000_000); err != nil {
		t.Fatalf("verifier: %v", err)
	}
}

func TestNewTopUpTxVerifierRequiresConfiguredProgram(t *testing.T) {
	channel := testutil.NewPrivateKey().PublicKey()
	tx, payload := buildTopUpTx(t, channel, 1_000_000, 500_000)
	fakeRPC := testutil.NewFakeRPC()
	fakeRPC.BySig[payload.Signature] = tx
	otherProgram := testutil.NewPrivateKey().PublicKey()
	verifier := NewTopUpTxVerifier(SessionConfig{ProgramID: &otherProgram}, fakeRPC)

	if err := verifier(context.Background(), payload, 1_000_000); err == nil || !strings.Contains(err.Error(), "no payment-channels top_up") {
		t.Fatalf("err = %v, want configured-program rejection", err)
	}
}

func TestNewTopUpTxVerifierRejectsUnrelatedOrMismatchedTransaction(t *testing.T) {
	channel := testutil.NewPrivateKey().PublicKey()

	t.Run("unrelated confirmed transaction", func(t *testing.T) {
		unrelated := buildOpenTxFixture(t, false)
		tx, err := solanatx.DecodeTransactionBase64(*unrelated.payload.Transaction)
		if err != nil {
			t.Fatalf("DecodeTransactionBase64: %v", err)
		}
		fakeRPC := testutil.NewFakeRPC()
		fakeRPC.BySig[unrelated.signature] = tx
		payload := &intents.TopUpPayload{ChannelID: channel.String(), NewDeposit: "5000000", Signature: unrelated.signature}
		verifier := NewTopUpTxVerifier(SessionConfig{}, fakeRPC)
		if err := verifier(context.Background(), payload, 1_000_000); err == nil || !strings.Contains(err.Error(), "no payment-channels top_up") {
			t.Fatalf("err = %v, want unrelated-transaction rejection", err)
		}
	})

	t.Run("wrong channel", func(t *testing.T) {
		otherChannel := testutil.NewPrivateKey().PublicKey()
		tx, payload := buildTopUpTx(t, otherChannel, 1_000_000, 500_000)
		payload.ChannelID = channel.String()
		fakeRPC := testutil.NewFakeRPC()
		fakeRPC.BySig[payload.Signature] = tx
		verifier := NewTopUpTxVerifier(SessionConfig{}, fakeRPC)
		if err := verifier(context.Background(), payload, 1_000_000); err == nil || !strings.Contains(err.Error(), "no payment-channels top_up") {
			t.Fatalf("err = %v, want wrong-channel rejection", err)
		}
	})

	t.Run("mismatched delta", func(t *testing.T) {
		tx, payload := buildTopUpTx(t, channel, 1_000_000, 1)
		payload.NewDeposit = "4999999"
		fakeRPC := testutil.NewFakeRPC()
		fakeRPC.BySig[payload.Signature] = tx
		verifier := NewTopUpTxVerifier(SessionConfig{}, fakeRPC)
		if err := verifier(context.Background(), payload, 1_000_000); err == nil || !strings.Contains(err.Error(), "claimed deposit delta") {
			t.Fatalf("err = %v, want delta-mismatch rejection", err)
		}
	})
}

func TestNewTopUpTxVerifierRejectsTwoMatchingInstructions(t *testing.T) {
	payer := testutil.NewPrivateKey()
	channelID := solana.NewWallet().PublicKey()
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	buildTopUp := func(amount uint64) solana.Instruction {
		t.Helper()
		instruction, err := paymentchannels.BuildTopUpInstruction(paymentchannels.TopUpParams{
			Payer: payer.PublicKey(), Channel: channelID, Mint: mint,
			Amount: amount, TokenProgram: solana.TokenProgramID,
		})
		if err != nil {
			t.Fatalf("BuildTopUpInstruction: %v", err)
		}
		return instruction
	}
	tx, err := solana.NewTransaction(
		[]solana.Instruction{buildTopUp(400), buildTopUp(600)},
		solana.MustHashFromBase58("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"),
		solana.TransactionPayer(payer.PublicKey()),
	)
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	if _, err := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(payer.PublicKey()) {
			return &payer
		}
		return nil
	}); err != nil {
		t.Fatalf("sign top-up transaction: %v", err)
	}

	fake := testutil.NewFakeRPC()
	signature := tx.Signatures[0]
	fake.BySig[signature.String()] = tx
	config := sessionTestConfig()
	config.Network = "mainnet"
	payload := &intents.TopUpPayload{
		ChannelID: channelID.String(), NewDeposit: "2000", Signature: signature.String(),
	}
	err = NewTopUpStateTxVerifier(config, fake)(context.Background(), payload, ChannelState{Deposit: 1_000})
	if err == nil || !strings.Contains(err.Error(), "exactly one") || !strings.Contains(err.Error(), "found 2") {
		t.Fatalf("duplicate top-up instruction error = %v", err)
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
	verifier := NewTopUpTxVerifier(SessionConfig{}, fakeRPC)
	channel := testutil.NewPrivateKey().PublicKey().String()
	payload := &intents.TopUpPayload{ChannelID: channel, NewDeposit: "2000000", Signature: signature.String()}
	if err := verifier(context.Background(), payload, 1_000_000); err == nil || !strings.Contains(err.Error(), "top-up") {
		t.Fatalf("err = %v, want top-up failure rejection", err)
	}

	fakeRPC.Statuses[signature.String()] = nil
	if err := verifier(context.Background(), payload, 1_000_000); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want not-found rejection", err)
	}

	if err := verifier(context.Background(), &intents.TopUpPayload{ChannelID: channel, NewDeposit: "2000000", Signature: "not-base58!"}, 1_000_000); err == nil || !strings.Contains(err.Error(), "invalid top-up tx signature") {
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
		openFixtureSalt, openFixtureGrace, openFixtureOpenSlot,
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
		t.Fatalf("instructions = %d, want 3 (ed25519 + settle_and_seal + distribute)", len(instructions))
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
	if !bytes.Equal(precompileData[112:162], wantMessage) {
		t.Fatal("precompile message != stored voucher payload")
	}

	// Instruction 1: settle_and_seal committing the watermark.
	settleData, err := instructions[1].Data()
	if err != nil {
		t.Fatalf("settle.Data: %v", err)
	}
	// The voucher (incl. cumulative=500) lives in the precompile, verified
	// above; settle_and_seal carries only [disc=4][hasVoucher=1].
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
	config.AllowUnsafeEphemeralStoreOffLocalnet = true
	config.VerifyOpenTx = func(_ context.Context, payload *intents.OpenPayload) (string, error) {
		return *payload.Payer, nil
	}
	config.VerifyOpenStateTx = func(_ context.Context, payload *intents.OpenPayload) (VerifyOpenTxResult, error) {
		return VerifyOpenTxResult{
			ChannelID: *payload.ChannelID,
			Deposit:   1_000_000,
			Payer:     *payload.Payer,
			Salt:      openFixtureSalt,
			OpenSlot:  openFixtureOpenSlot,
		}, nil
	}
	server := newSessionTestServer(config)
	payer := testutil.NewPrivateKey().PublicKey()
	merchant := testutil.NewPrivateKey().PublicKey()

	signer := newTestVoucherSigner(t)
	channelID := testutil.NewPrivateKey().PublicKey().String()
	payload := intents.OpenPayloadPaymentChannel(
		channelID, "1000000",
		payer.String(), sessionTestRecipient, paycore.PYUSDMainnetMint,
		openFixtureSalt, openFixtureGrace, openFixtureOpenSlot, signer.Address(), "dummy_tx_sig",
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

func TestSettlementInstructionsUsesConfiguredToken2022ForArbitraryMint(t *testing.T) {
	config := sessionTestConfig()
	arbitraryMint := testutil.NewPrivateKey().PublicKey()
	config.Currency = arbitraryMint.String()
	config.TokenProgram = paycore.Token2022Program
	server := newSessionTestServer(config)
	payer := testutil.NewPrivateKey().PublicKey()
	merchant := testutil.NewPrivateKey().PublicKey()
	signer := newTestVoucherSigner(t)
	channelID := testutil.NewPrivateKey().PublicKey().String()
	payload := intents.OpenPayloadPaymentChannel(
		channelID, "1000000", payer.String(), sessionTestRecipient,
		arbitraryMint.String(), openFixtureSalt, openFixtureGrace, openFixtureOpenSlot,
		signer.Address(), "dummy_tx_sig",
	)
	if _, err := server.ProcessOpen(context.Background(), &payload); err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}

	instructions, err := server.SettlementInstructions(context.Background(), channelID, merchant)
	if err != nil {
		t.Fatalf("SettlementInstructions: %v", err)
	}
	accounts := instructions[len(instructions)-1].Accounts()
	if !accounts[7].PublicKey.Equals(arbitraryMint) {
		t.Fatalf("distribute mint = %s, want arbitrary mint %s", accounts[7].PublicKey, arbitraryMint)
	}
	wantToken2022 := solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	if !accounts[8].PublicKey.Equals(wantToken2022) {
		t.Fatalf("distribute token program = %s, want Token-2022", accounts[8].PublicKey)
	}
	wantPayerATA, _, err := solana.FindAssociatedTokenAddressWithProgram(payer, arbitraryMint, wantToken2022)
	if err != nil {
		t.Fatalf("derive payer ATA: %v", err)
	}
	if !accounts[4].PublicKey.Equals(wantPayerATA) {
		t.Fatalf("distribute payer token account = %s, want %s", accounts[4].PublicKey, wantPayerATA)
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
