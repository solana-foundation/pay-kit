package client

import (
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

func u64ptr(v uint64) *uint64 { return &v }

func strptr(v string) *string { return &v }

// testRecentSlot is the challenge recentSlot used across these tests (the
// server pre-fetches it alongside recentBlockhash).
const testRecentSlot = uint64(321_654_987)

func testSessionRequest(operator, recipient solana.PublicKey) intents.SessionRequest {
	network := "localnet"
	strategy := intents.SessionPullVoucherStrategyClientVoucher
	recentSlot := intents.U64String(testRecentSlot)
	return intents.SessionRequest{
		Cap:                 "1000",
		Currency:            "USDC",
		Network:             &network,
		Operator:            operator.String(),
		Recipient:           recipient.String(),
		Modes:               []intents.SessionMode{intents.SessionModePull},
		PullVoucherStrategy: &strategy,
		RecentSlot:          &recentSlot,
	}
}

func decodeOpenTransaction(t *testing.T, encoded string) *solana.Transaction {
	t.Helper()
	tx, err := solanatx.DecodeTransactionBase64(encoded)
	if err != nil {
		t.Fatalf("decode open transaction: %v", err)
	}
	return tx
}

func TestDerivePaymentChannelOpenUsesChallengeDefaultsAndSplits(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	request.Splits = []intents.SessionSplit{{Recipient: splitRecipient.String(), BPS: 10}}

	payer := testutil.NewPrivateKey().PublicKey()
	authorizedSigner := testutil.NewPrivateKey().PublicKey()
	open, err := DerivePaymentChannelOpen(request, payer, authorizedSigner, PaymentChannelOpenOptions{
		Salt: u64ptr(42),
	})
	if err != nil {
		t.Fatalf("DerivePaymentChannelOpen: %v", err)
	}

	if !open.Payer.Equals(payer) {
		t.Fatalf("payer = %s, want %s", open.Payer, payer)
	}
	if !open.Payee.Equals(recipient) {
		t.Fatalf("payee = %s, want challenge recipient", open.Payee)
	}
	if !open.AuthorizedSigner.Equals(authorizedSigner) {
		t.Fatalf("authorizedSigner = %s", open.AuthorizedSigner)
	}
	// RentPayer is the challenge operator (the gasless fee payer) and must not
	// be conflated with the authorizedSigner.
	if !open.RentPayer.Equals(operator) {
		t.Fatalf("rentPayer = %s, want challenge operator %s", open.RentPayer, operator)
	}
	if !open.OpenChannelParams().RentPayer.Equals(operator) {
		t.Fatalf("OpenChannelParams().RentPayer = %s, want operator %s", open.OpenChannelParams().RentPayer, operator)
	}
	if open.Deposit != 1000 {
		t.Fatalf("deposit = %d, want challenge cap 1000", open.Deposit)
	}
	if open.GracePeriod != DefaultGracePeriodSeconds {
		t.Fatalf("gracePeriod = %d, want %d", open.GracePeriod, DefaultGracePeriodSeconds)
	}
	if open.Salt != 42 {
		t.Fatalf("salt = %d, want 42", open.Salt)
	}
	if open.OpenSlot != testRecentSlot {
		t.Fatalf("openSlot = %d, want challenge recentSlot %d", open.OpenSlot, testRecentSlot)
	}
	if len(open.Recipients) != 1 || !open.Recipients[0].Recipient.Equals(splitRecipient) || open.Recipients[0].Bps != 10 {
		t.Fatalf("recipients = %+v, want challenge split", open.Recipients)
	}
	// Localnet resolves to the mainnet USDC mint (Surfpool clones mainnet state).
	if open.Mint.String() != paycore.USDCMainnetMint {
		t.Fatalf("mint = %s, want mainnet USDC", open.Mint)
	}
	if open.TokenProgram.String() != paycore.TokenProgram {
		t.Fatalf("tokenProgram = %s, want SPL Token", open.TokenProgram)
	}
	if !open.ProgramID.Equals(paymentchannels.ProgramPubkey()) {
		t.Fatalf("programID = %s, want canonical", open.ProgramID)
	}
	expectedChannel, _, err := paymentchannels.FindChannelPDAForProgram(
		payer, recipient, open.Mint, authorizedSigner, 42, testRecentSlot, open.ProgramID)
	if err != nil {
		t.Fatalf("FindChannelPDAForProgram: %v", err)
	}
	if !open.ChannelID.Equals(expectedChannel) {
		t.Fatalf("channelID = %s, want %s", open.ChannelID, expectedChannel)
	}
}

func TestDerivePaymentChannelOpenHonorsExplicitOptions(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	splitRecipient := testutil.NewPrivateKey().PublicKey()
	programID := testutil.NewPrivateKey().PublicKey()
	tokenProgram := solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	request := testSessionRequest(operator, recipient)
	request.Cap = "not-a-number"
	request.Splits = []intents.SessionSplit{{Recipient: "not-a-pubkey", BPS: 999}}

	gracePeriod := uint32(12)
	open, err := DerivePaymentChannelOpen(
		request,
		testutil.NewPrivateKey().PublicKey(),
		testutil.NewPrivateKey().PublicKey(),
		PaymentChannelOpenOptions{
			Deposit:      u64ptr(55),
			GracePeriod:  &gracePeriod,
			ProgramID:    &programID,
			Recipients:   []paymentchannels.Distribution{{Recipient: splitRecipient, Bps: 25}},
			Salt:         u64ptr(7),
			TokenProgram: &tokenProgram,
		},
	)
	if err != nil {
		t.Fatalf("DerivePaymentChannelOpen: %v", err)
	}

	if open.Deposit != 55 {
		t.Fatalf("deposit = %d, want explicit 55", open.Deposit)
	}
	if open.GracePeriod != 12 {
		t.Fatalf("gracePeriod = %d, want explicit 12", open.GracePeriod)
	}
	if !open.ProgramID.Equals(programID) {
		t.Fatalf("programID = %s, want explicit", open.ProgramID)
	}
	if !open.TokenProgram.Equals(tokenProgram) {
		t.Fatalf("tokenProgram = %s, want explicit Token-2022", open.TokenProgram)
	}
	if len(open.Recipients) != 1 || !open.Recipients[0].Recipient.Equals(splitRecipient) || open.Recipients[0].Bps != 25 {
		t.Fatalf("recipients = %+v, want explicit", open.Recipients)
	}
}

func TestDerivePaymentChannelOpenResolvesToken2022FromCurrency(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	request.Currency = "PYUSD"

	open, err := DerivePaymentChannelOpen(
		request,
		testutil.NewPrivateKey().PublicKey(),
		testutil.NewPrivateKey().PublicKey(),
		PaymentChannelOpenOptions{Salt: u64ptr(1)},
	)
	if err != nil {
		t.Fatalf("DerivePaymentChannelOpen: %v", err)
	}
	if open.TokenProgram.String() != paycore.Token2022Program {
		t.Fatalf("tokenProgram = %s, want Token-2022 for PYUSD", open.TokenProgram)
	}
	if open.Mint.String() != paycore.PYUSDMainnetMint {
		t.Fatalf("mint = %s, want mainnet PYUSD", open.Mint)
	}
}

func TestDerivePaymentChannelOpenDefaultsToRandomSalt(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	payer := testutil.NewPrivateKey().PublicKey()
	authorizedSigner := testutil.NewPrivateKey().PublicKey()

	first, err := DerivePaymentChannelOpen(request, payer, authorizedSigner, PaymentChannelOpenOptions{})
	if err != nil {
		t.Fatalf("DerivePaymentChannelOpen: %v", err)
	}
	second, err := DerivePaymentChannelOpen(request, payer, authorizedSigner, PaymentChannelOpenOptions{})
	if err != nil {
		t.Fatalf("DerivePaymentChannelOpen: %v", err)
	}
	if first.Salt == second.Salt {
		t.Fatalf("two derived opens reused salt %d; want random default", first.Salt)
	}
	if first.ChannelID.Equals(second.ChannelID) {
		t.Fatal("two derived opens reused the channel PDA; want salt-unique channels")
	}
}

func TestDerivePaymentChannelOpenRejectsInvalidChallengeValues(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	payer := testutil.NewPrivateKey().PublicKey()
	authorizedSigner := testutil.NewPrivateKey().PublicKey()

	cases := []struct {
		name    string
		mutate  func(*intents.SessionRequest)
		wantErr string
	}{
		{"native SOL", func(r *intents.SessionRequest) { r.Currency = "SOL" }, "SPL token"},
		{"bad cap", func(r *intents.SessionRequest) { r.Cap = "not-a-number" }, "session cap"},
		{"bad recipient", func(r *intents.SessionRequest) { r.Recipient = "not-a-pubkey" }, "recipient"},
		{"bad programId", func(r *intents.SessionRequest) { r.ProgramID = strptr("not-a-program") }, "programId"},
		{"bad split", func(r *intents.SessionRequest) {
			r.Splits = []intents.SessionSplit{{Recipient: "not-a-pubkey", BPS: 10}}
		}, "split recipient"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := testSessionRequest(operator, recipient)
			tc.mutate(&request)
			_, err := DerivePaymentChannelOpen(request, payer, authorizedSigner, PaymentChannelOpenOptions{})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestDerivePaymentChannelOpenRequiresChallengeRecentSlot(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	request.RecentSlot = nil

	_, err := DerivePaymentChannelOpen(
		request,
		testutil.NewPrivateKey().PublicKey(),
		testutil.NewPrivateKey().PublicKey(),
		PaymentChannelOpenOptions{Salt: u64ptr(1)},
	)
	if err == nil || !strings.Contains(err.Error(), "recentSlot") {
		t.Fatalf("error = %v, want missing-recentSlot rejection", err)
	}

	// An explicit options override satisfies the requirement without a
	// challenge openSlot, and wins over the challenge when both are set.
	open, err := DerivePaymentChannelOpen(
		request,
		testutil.NewPrivateKey().PublicKey(),
		testutil.NewPrivateKey().PublicKey(),
		PaymentChannelOpenOptions{Salt: u64ptr(1), OpenSlot: u64ptr(777)},
	)
	if err != nil {
		t.Fatalf("DerivePaymentChannelOpen with override: %v", err)
	}
	if open.OpenSlot != 777 {
		t.Fatalf("openSlot = %d, want override 777", open.OpenSlot)
	}
}

func TestBuildOpenPaymentChannelTransactionPartiallySignsForOperatorBroadcast(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	payerSigner := testutil.NewPrivateKey()
	authorizedSigner := testutil.NewPrivateKey().PublicKey()
	blockhash := solana.HashFromBytes(testutil.NewPrivateKey().PublicKey().Bytes())

	built, err := BuildOpenPaymentChannelTransaction(BuildOpenPaymentChannelTransactionParams{
		Request:          request,
		Signer:           payerSigner,
		AuthorizedSigner: authorizedSigner,
		RecentBlockhash:  blockhash.String(),
		Options:          PaymentChannelOpenOptions{Salt: u64ptr(99)},
	})
	if err != nil {
		t.Fatalf("BuildOpenPaymentChannelTransaction: %v", err)
	}

	expected, err := DerivePaymentChannelOpen(request, payerSigner.PublicKey(), authorizedSigner, PaymentChannelOpenOptions{
		Salt: u64ptr(99),
	})
	if err != nil {
		t.Fatalf("DerivePaymentChannelOpen: %v", err)
	}
	if !built.ChannelID.Equals(expected.ChannelID) {
		t.Fatalf("channelID = %s, want %s", built.ChannelID, expected.ChannelID)
	}

	tx := decodeOpenTransaction(t, built.Transaction)
	if !tx.Message.AccountKeys[0].Equals(operator) {
		t.Fatalf("fee payer = %s, want challenge operator", tx.Message.AccountKeys[0])
	}
	if len(tx.Message.Instructions) != 1 {
		t.Fatalf("instructions = %d, want 1", len(tx.Message.Instructions))
	}
	if tx.Message.RecentBlockhash != blockhash {
		t.Fatalf("recentBlockhash = %s, want explicit %s", tx.Message.RecentBlockhash, blockhash)
	}

	// Fee-payer (operator) slot left zeroed for the server to complete.
	if !tx.Signatures[0].IsZero() {
		t.Fatalf("operator signature slot should be zeroed, got %s", tx.Signatures[0])
	}
	payerIndex := -1
	for i, key := range tx.Message.Signers() {
		if key.Equals(payerSigner.PublicKey()) {
			payerIndex = i
			break
		}
	}
	if payerIndex < 0 {
		t.Fatal("payer signer is not a required transaction signer")
	}
	if tx.Signatures[payerIndex].IsZero() {
		t.Fatal("payer signature missing; want partial sign")
	}
}

func TestBuildOpenPaymentChannelTransactionUsesOperatorFeePayerAndChallengeBlockhash(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	challengeBlockhash := solana.HashFromBytes(testutil.NewPrivateKey().PublicKey().Bytes())
	request.RecentBlockhash = strptr(challengeBlockhash.String())
	payerSigner := testutil.NewPrivateKey()

	// FeePayer explicitly set to the operator must succeed (gasless: the server
	// records rentPayer == operator).
	built, err := BuildOpenPaymentChannelTransaction(BuildOpenPaymentChannelTransactionParams{
		Request:          request,
		Signer:           payerSigner,
		AuthorizedSigner: testutil.NewPrivateKey().PublicKey(),
		FeePayer:         &operator,
		Options:          PaymentChannelOpenOptions{Salt: u64ptr(123)},
	})
	if err != nil {
		t.Fatalf("BuildOpenPaymentChannelTransaction: %v", err)
	}
	tx := decodeOpenTransaction(t, built.Transaction)
	if !tx.Message.AccountKeys[0].Equals(operator) {
		t.Fatalf("fee payer = %s, want operator", tx.Message.AccountKeys[0])
	}
	if tx.Message.RecentBlockhash != challengeBlockhash {
		t.Fatalf("recentBlockhash = %s, want challenge echo %s", tx.Message.RecentBlockhash, challengeBlockhash)
	}
}

func TestBuildOpenPaymentChannelTransactionRejectsNonOperatorFeePayer(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	nonOperatorFeePayer := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	challengeBlockhash := solana.HashFromBytes(testutil.NewPrivateKey().PublicKey().Bytes())
	request.RecentBlockhash = strptr(challengeBlockhash.String())

	_, err := BuildOpenPaymentChannelTransaction(BuildOpenPaymentChannelTransactionParams{
		Request:          request,
		Signer:           testutil.NewPrivateKey(),
		AuthorizedSigner: testutil.NewPrivateKey().PublicKey(),
		FeePayer:         &nonOperatorFeePayer,
		Options:          PaymentChannelOpenOptions{Salt: u64ptr(123)},
	})
	if err == nil || !strings.Contains(err.Error(), "FeePayer must equal the challenge operator") {
		t.Fatalf("error = %v, want non-operator fee payer rejection", err)
	}
}

func TestBuildOpenPaymentChannelTransactionRequiresABlockhash(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)

	_, err := BuildOpenPaymentChannelTransaction(BuildOpenPaymentChannelTransactionParams{
		Request:          request,
		Signer:           testutil.NewPrivateKey(),
		AuthorizedSigner: testutil.NewPrivateKey().PublicKey(),
		Options:          PaymentChannelOpenOptions{Salt: u64ptr(1)},
	})
	if err == nil || !strings.Contains(err.Error(), "recent blockhash") {
		t.Fatalf("error = %v, want recent blockhash requirement", err)
	}
}

func TestCreatePaymentChannelSessionOpenerBuildsPullClientVoucherAction(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	payerSigner := testutil.NewPrivateKey()
	sessionSigner := testutil.NewPrivateKey()
	blockhash := solana.HashFromBytes(testutil.NewPrivateKey().PublicKey().Bytes())

	opened, err := CreatePaymentChannelSessionOpener(
		request, payerSigner, sessionSigner, blockhash.String(),
		PaymentChannelSessionOpenOptions{Open: PaymentChannelOpenOptions{Salt: u64ptr(11)}},
	)
	if err != nil {
		t.Fatalf("CreatePaymentChannelSessionOpener: %v", err)
	}

	if !opened.Session.ChannelID().Equals(opened.Open.ChannelID) {
		t.Fatalf("session channel = %s, want %s", opened.Session.ChannelID(), opened.Open.ChannelID)
	}
	if opened.Action.Open == nil {
		t.Fatal("expected open action")
	}
	payload := opened.Action.Open
	if payload.Mode != intents.SessionModePull {
		t.Fatalf("mode = %s, want pull", payload.Mode)
	}
	if payload.ChannelID == nil || *payload.ChannelID != opened.Open.ChannelID.String() {
		t.Fatalf("channelId = %v, want %s", payload.ChannelID, opened.Open.ChannelID)
	}
	if payload.Payer == nil || *payload.Payer != payerSigner.PublicKey().String() {
		t.Fatalf("payer = %v, want payer signer", payload.Payer)
	}
	if payload.AuthorizedSigner != sessionSigner.PublicKey().String() {
		t.Fatalf("authorizedSigner = %s, want session signer", payload.AuthorizedSigner)
	}
	if payload.Signature != PendingServerSignature {
		t.Fatalf("signature = %s, want pending placeholder", payload.Signature)
	}
	if payload.Transaction == nil {
		t.Fatal("transaction missing; want payer-signed open tx attached")
	}
	if payload.TokenAccount != nil || payload.ApprovedAmount != nil ||
		payload.InitMultiDelegateTx != nil || payload.UpdateDelegationTx != nil {
		t.Fatal("pull SPL-delegation fields must be unset for payment-channel opens")
	}
	tx := decodeOpenTransaction(t, *payload.Transaction)
	if !tx.Message.AccountKeys[0].Equals(operator) {
		t.Fatalf("fee payer = %s, want operator", tx.Message.AccountKeys[0])
	}
}

func TestCreatePaymentChannelSessionOpenerAppliesSessionOptions(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	blockhash := solana.HashFromBytes(testutil.NewPrivateKey().PublicKey().Bytes())

	expiresAt := int64(1234)
	opened, err := CreatePaymentChannelSessionOpener(
		request, testutil.NewPrivateKey(), testutil.NewPrivateKey(), blockhash.String(),
		PaymentChannelSessionOpenOptions{
			Open:       PaymentChannelOpenOptions{Salt: u64ptr(19)},
			Signature:  strptr("operator-will-fill"),
			Cumulative: u64ptr(20),
			ExpiresAt:  &expiresAt,
		},
	)
	if err != nil {
		t.Fatalf("CreatePaymentChannelSessionOpener: %v", err)
	}
	if opened.Action.Open.Signature != "operator-will-fill" {
		t.Fatalf("signature = %s, want explicit", opened.Action.Open.Signature)
	}
	voucher, err := opened.Session.PrepareIncrement(5)
	if err != nil {
		t.Fatalf("PrepareIncrement: %v", err)
	}
	if voucher.Data.Cumulative != "25" {
		t.Fatalf("cumulative = %s, want resumed 20 + 5", voucher.Data.Cumulative)
	}
	if voucher.Data.ExpiresAt != 1234 {
		t.Fatalf("expiresAt = %d, want explicit 1234", voucher.Data.ExpiresAt)
	}
}

func TestCreateServerOpenedSessionOpenerUsesOperatorPayerWithoutTransaction(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	sessionSigner := testutil.NewPrivateKey()

	opened, err := CreateServerOpenedPaymentChannelSessionOpener(
		request, sessionSigner,
		ServerOpenedPaymentChannelSessionOpenOptions{Open: PaymentChannelOpenOptions{Salt: u64ptr(13)}},
	)
	if err != nil {
		t.Fatalf("CreateServerOpenedPaymentChannelSessionOpener: %v", err)
	}
	if !opened.Open.Payer.Equals(operator) {
		t.Fatalf("payer = %s, want operator", opened.Open.Payer)
	}
	payload := opened.Action.Open
	if payload == nil {
		t.Fatal("expected open action")
	}
	if payload.Mode != intents.SessionModePull {
		t.Fatalf("mode = %s, want pull", payload.Mode)
	}
	if payload.Payer == nil || *payload.Payer != request.Operator {
		t.Fatalf("payer = %v, want operator", payload.Payer)
	}
	if payload.AuthorizedSigner != sessionSigner.PublicKey().String() {
		t.Fatalf("authorizedSigner = %s", payload.AuthorizedSigner)
	}
	if payload.Signature != PendingServerSignature {
		t.Fatalf("signature = %s, want pending placeholder", payload.Signature)
	}
	if payload.Transaction != nil {
		t.Fatal("transaction must be unset for server-opened channels")
	}
	if payload.TokenAccount != nil || payload.ApprovedAmount != nil {
		t.Fatal("pull SPL-delegation fields must be unset")
	}
}

func TestSessionOpenerRejectsNonPullChallenge(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	request.Modes = []intents.SessionMode{intents.SessionModePush}
	request.PullVoucherStrategy = nil

	_, err := CreateServerOpenedPaymentChannelSessionOpener(
		request, testutil.NewPrivateKey(), ServerOpenedPaymentChannelSessionOpenOptions{})
	if err == nil || !strings.Contains(err.Error(), "pull mode") {
		t.Fatalf("error = %v, want pull-mode rejection", err)
	}
}

func TestSessionOpenerRejectsOperatedVoucherPullChallenge(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	request := testSessionRequest(operator, recipient)
	operated := intents.SessionPullVoucherStrategyOperatedVoucher
	request.PullVoucherStrategy = &operated

	_, err := CreateServerOpenedPaymentChannelSessionOpener(
		request, testutil.NewPrivateKey(), ServerOpenedPaymentChannelSessionOpenOptions{})
	if err == nil || !strings.Contains(err.Error(), "does not advertise pull + clientVoucher") {
		t.Fatalf("error = %v, want operated-voucher rejection", err)
	}
}

func TestNewEphemeralSessionSignerGeneratesDistinctKeys(t *testing.T) {
	a, err := NewEphemeralSessionSigner()
	if err != nil {
		t.Fatalf("NewEphemeralSessionSigner: %v", err)
	}
	b, err := NewEphemeralSessionSigner()
	if err != nil {
		t.Fatalf("NewEphemeralSessionSigner: %v", err)
	}
	if a.PublicKey().Equals(b.PublicKey()) {
		t.Fatal("two ephemeral session signers share a public key")
	}
	preimage := []byte("test-message")
	sig, err := a.Sign(preimage)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.IsZero() {
		t.Fatal("ephemeral signer produced a zero signature")
	}
}

func TestSessionOpenerErrorPaths(t *testing.T) {
	recipient := testutil.NewPrivateKey().PublicKey()
	operator := testutil.NewPrivateKey().PublicKey()
	blockhash := solana.HashFromBytes(testutil.NewPrivateKey().PublicKey().Bytes())

	badOperator := testSessionRequest(operator, recipient)
	badOperator.Operator = "not-a-pubkey"
	if _, err := CreatePaymentChannelSessionOpener(
		badOperator, testutil.NewPrivateKey(), testutil.NewPrivateKey(), blockhash.String(),
		PaymentChannelSessionOpenOptions{}); err == nil || !strings.Contains(err.Error(), "operator") {
		t.Fatalf("error = %v, want invalid operator", err)
	}
	if _, err := CreateServerOpenedPaymentChannelSessionOpener(
		badOperator, testutil.NewPrivateKey(),
		ServerOpenedPaymentChannelSessionOpenOptions{}); err == nil || !strings.Contains(err.Error(), "operator") {
		t.Fatalf("error = %v, want invalid operator", err)
	}

	solCurrency := testSessionRequest(operator, recipient)
	solCurrency.Currency = "SOL"
	if _, err := CreatePaymentChannelSessionOpener(
		solCurrency, testutil.NewPrivateKey(), testutil.NewPrivateKey(), blockhash.String(),
		PaymentChannelSessionOpenOptions{}); err == nil || !strings.Contains(err.Error(), "SPL token") {
		t.Fatalf("error = %v, want SPL token requirement", err)
	}
	if _, err := CreateServerOpenedPaymentChannelSessionOpener(
		solCurrency, testutil.NewPrivateKey(),
		ServerOpenedPaymentChannelSessionOpenOptions{}); err == nil || !strings.Contains(err.Error(), "SPL token") {
		t.Fatalf("error = %v, want SPL token requirement", err)
	}

	noBlockhash := testSessionRequest(operator, recipient)
	if _, err := CreatePaymentChannelSessionOpener(
		noBlockhash, testutil.NewPrivateKey(), testutil.NewPrivateKey(), "",
		PaymentChannelSessionOpenOptions{}); err == nil || !strings.Contains(err.Error(), "recent blockhash") {
		t.Fatalf("error = %v, want blockhash requirement", err)
	}
	if _, err := CreatePaymentChannelSessionOpener(
		noBlockhash, testutil.NewPrivateKey(), testutil.NewPrivateKey(), "!!bad-base58!!",
		PaymentChannelSessionOpenOptions{}); err == nil || !strings.Contains(err.Error(), "invalid recent blockhash") {
		t.Fatalf("error = %v, want invalid blockhash", err)
	}

	badOperatorTx := testSessionRequest(operator, recipient)
	badOperatorTx.Operator = "not-a-pubkey"
	if _, err := BuildOpenPaymentChannelTransaction(BuildOpenPaymentChannelTransactionParams{
		Request:          badOperatorTx,
		Signer:           testutil.NewPrivateKey(),
		AuthorizedSigner: testutil.NewPrivateKey().PublicKey(),
		RecentBlockhash:  blockhash.String(),
	}); err == nil || !strings.Contains(err.Error(), "operator") {
		t.Fatalf("error = %v, want invalid operator", err)
	}
}
