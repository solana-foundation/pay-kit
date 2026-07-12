package server

// Method-level coverage through the real credential layer: challenge
// issuance (canonical shape, cap clamping, pull advertisement, blockhash
// prefetch), the five verify() actions with their replay/hardening
// semantics, the side-channel routes, settlement retry, and the store
// sharing between the method and its routes.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

const sessionMethodSecret = "session-method-secret"

type rpcWithoutBlockHeight struct {
	solanatx.RPCClient
}

type typedNilSessionSigner struct{}

func (*typedNilSessionSigner) PublicKey() solana.PublicKey { panic("typed-nil signer used") }
func (*typedNilSessionSigner) Sign([]byte) (solana.Signature, error) {
	panic("typed-nil signer used")
}

var _ SettlementRPC = (*testutil.FakeRPC)(nil)

// confirmedSignature returns a base58 signature string registered as
// confirmed on the fake RPC.
func confirmedSignature(fill byte) string {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = fill
	}
	return solana.SignatureFromBytes(raw).String()
}

func newTestSession(t *testing.T, mutate func(*SessionOptions)) *Session {
	t.Helper()
	options := SessionOptions{
		Operator:  sessionTestRecipient,
		Recipient: sessionTestRecipient,
		Cap:       5_000_000,
		Currency:  "USDC",
		Decimals:  6,
		Network:   "localnet",
		SecretKey: sessionMethodSecret,
		Realm:     "api.test",
	}
	if mutate != nil {
		mutate(&options)
	}
	session, err := NewSession(options)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(session.Shutdown)
	return session
}

// sessionActionCredential issues a fresh challenge and wraps action into the
// credential a client would send.
func sessionActionCredential(t *testing.T, session *Session, action any) core.PaymentCredential {
	t.Helper()
	challenge, err := session.Challenge(context.Background(), SessionChallengeOptions{})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), action)
	if err != nil {
		t.Fatalf("NewPaymentCredential: %v", err)
	}
	return credential
}

func verifySessionAction(t *testing.T, session *Session, action any) (core.Receipt, error) {
	t.Helper()
	return session.VerifyCredential(context.Background(), sessionActionCredential(t, session, action))
}

func registerFetchedOpenTransaction(t *testing.T, fake *testutil.FakeRPC, fixture openTxFixture, slot uint64) {
	t.Helper()
	if fixture.payload.Transaction == nil {
		t.Fatal("open fixture is missing transaction bytes")
	}
	tx, err := solanatx.DecodeTransactionBase64(*fixture.payload.Transaction)
	if err != nil {
		t.Fatalf("decode fetched open transaction: %v", err)
	}
	fake.BySig[fixture.signature] = tx
	fake.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusConfirmed,
		Slot:               slot,
	}
}

// openTrustedChannel opens a transactionless push channel through the
// credential layer and returns the voucher signer plus channel id. RPC-backed
// tests register a matching fetched transaction for the signature-only payload.
func openTrustedChannel(t *testing.T, session *Session, deposit uint64) (testVoucherSigner, string) {
	t.Helper()
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	_, channelID = openSessionChannel(t, session, channelID, deposit, signer.Address(), confirmedSignature(0x99))
	return signer, channelID
}

func openSessionChannel(t *testing.T, session *Session, channelID string, deposit uint64, authorizedSigner, signature string) (core.Receipt, string) {
	t.Helper()
	payload := intents.OpenPayloadPush(channelID, fmt.Sprintf("%d", deposit), authorizedSigner, signature)
	// Record a channel payer (the distribute refund destination, which the
	// program pins to channel.payer) so the bare push open can later settle;
	// without it the settle path now refuses rather than refunding the merchant.
	payerKey := testutil.NewPrivateKey()
	payer := payerKey.PublicKey().String()
	payload.Payer = &payer
	if setter, ok := session.rpc.(interface {
		SetAccount(solana.PublicKey, solana.PublicKey, []byte)
	}); ok {
		derived, _, err := paymentchannels.FindChannelPDAForProgram(
			solana.MustPublicKeyFromBase58(payer),
			solana.MustPublicKeyFromBase58(session.recipient),
			solana.MustPublicKeyFromBase58(paycore.ResolveMint(session.currency, session.network)),
			solana.MustPublicKeyFromBase58(authorizedSigner),
			7,
			42,
			paymentchannels.ProgramPubkey(),
		)
		if err != nil {
			t.Fatalf("derive channel fixture: %v", err)
		}
		channelID = derived.String()
		payload.ChannelID = &channelID
		fake, ok := setter.(*testutil.FakeRPC)
		if !ok {
			// Embedded FakeRPC test doubles promote SetAccount but keep their own
			// dynamic type; seed through a small adapter below.
			seedSessionAccountThroughSetter(t, setter, session, channelID, deposit, payer, authorizedSigner)
		} else {
			seedSessionChannelAccount(
				t,
				fake,
				solana.MustPublicKeyFromBase58(channelID),
				deposit,
				solana.MustPublicKeyFromBase58(payer),
				solana.MustPublicKeyFromBase58(session.recipient),
				solana.MustPublicKeyFromBase58(authorizedSigner),
				solana.MustPublicKeyFromBase58(paycore.ResolveMint(session.currency, session.network)),
				pcgen.ChannelStatus_Open,
			)
		}
	}
	registerSignatureOnlyOpenTransaction(t, session, &payload, payerKey, deposit)
	receipt, err := verifySessionAction(t, session, intents.NewOpenAction(payload))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return receipt, channelID
}

func fakeRPCForSession(rpcClient solanatx.RPCClient) *testutil.FakeRPC {
	switch rpc := rpcClient.(type) {
	case *testutil.FakeRPC:
		return rpc
	case *failingBlockhashRPC:
		return rpc.FakeRPC
	case *countingBlockhashRPC:
		return rpc.FakeRPC
	default:
		return nil
	}
}

func registerSignatureOnlyOpenTransaction(
	t *testing.T,
	session *Session,
	payload *intents.OpenPayload,
	payer solana.PrivateKey,
	deposit uint64,
) {
	t.Helper()
	fake := fakeRPCForSession(session.rpc)
	if fake == nil || payload.Signature == "" {
		return
	}
	payee, err := solana.PublicKeyFromBase58(session.recipient)
	if err != nil {
		t.Fatalf("parse session recipient: %v", err)
	}
	mint, err := solana.PublicKeyFromBase58(paycore.ResolveMint(session.currency, session.network))
	if err != nil {
		t.Fatalf("parse session mint: %v", err)
	}
	authorized, err := solana.PublicKeyFromBase58(payload.AuthorizedSigner)
	if err != nil {
		t.Fatalf("parse authorized signer: %v", err)
	}
	operator, err := solana.PublicKeyFromBase58(session.core.config.Operator)
	if err != nil {
		t.Fatalf("parse session operator: %v", err)
	}
	tokenProgram, err := solana.PublicKeyFromBase58(paycore.DefaultTokenProgramForCurrency(session.currency, session.network))
	if err != nil {
		t.Fatalf("parse token program: %v", err)
	}
	recipients := make([]paymentchannels.Distribution, 0, len(session.core.config.Splits))
	for _, split := range session.core.config.Splits {
		recipients = append(recipients, paymentchannels.Distribution{Recipient: split.Recipient, Bps: split.BPS})
	}
	programID := paymentchannels.ProgramPubkey()
	if session.core.config.ProgramID != nil {
		programID = *session.core.config.ProgramID
	}
	ix, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer:            payer.PublicKey(),
		RentPayer:        operator,
		Payee:            payee,
		Mint:             mint,
		AuthorizedSigner: authorized,
		Salt:             7,
		OpenSlot:         42,
		Deposit:          deposit,
		GracePeriod:      expectedSessionGracePeriod(session.core.config),
		Recipients:       recipients,
		TokenProgram:     tokenProgram,
		ProgramID:        programID,
	})
	if err != nil {
		t.Fatalf("build fetched signature-only open: %v", err)
	}
	tx, err := solana.NewTransaction([]solana.Instruction{ix}, fake.Blockhash, solana.TransactionPayer(payer.PublicKey()))
	if err != nil {
		t.Fatalf("build fetched signature-only transaction: %v", err)
	}
	tx.Signatures = make([]solana.Signature, len(tx.Message.Signers()))
	signature, err := solana.SignatureFromBase58(payload.Signature)
	if err != nil {
		return
	}
	tx.Signatures[0] = signature
	fake.BySig[payload.Signature] = tx
}

func seedSessionAccountThroughSetter(
	t *testing.T,
	setter interface {
		SetAccount(solana.PublicKey, solana.PublicKey, []byte)
	},
	session *Session,
	channelID string,
	deposit uint64,
	payer string,
	authorizedSigner string,
) {
	t.Helper()
	account := pcgen.Channel{
		Discriminator:    1,
		Version:          1,
		Status:           uint8(pcgen.ChannelStatus_Open),
		Deposit:          deposit,
		GracePeriod:      900,
		DistributionHash: sessionDistributionHash(session.core.config.Splits),
		Payer:            solana.MustPublicKeyFromBase58(payer),
		Payee:            solana.MustPublicKeyFromBase58(session.recipient),
		AuthorizedSigner: solana.MustPublicKeyFromBase58(authorizedSigner),
		Mint:             solana.MustPublicKeyFromBase58(paycore.ResolveMint(session.currency, session.network)),
		RentPayer:        solana.MustPublicKeyFromBase58(session.core.config.Operator),
		Salt:             7,
		OpenSlot:         42,
	}
	buf := new(bytes.Buffer)
	if err := account.MarshalWithEncoder(bin.NewBorshEncoder(buf)); err != nil {
		t.Fatalf("encode channel account: %v", err)
	}
	setter.SetAccount(solana.MustPublicKeyFromBase58(channelID), paymentchannels.ProgramPubkey(), buf.Bytes())
}

func mustGetChannel(t *testing.T, session *Session, channelID string) *ChannelState {
	t.Helper()
	state, err := session.Core().Store().GetChannel(context.Background(), channelID)
	if err != nil {
		t.Fatalf("GetChannel: %v", err)
	}
	return state
}

// ── NewSession validation ──

func TestNewSessionValidation(t *testing.T) {
	base := func() SessionOptions {
		return SessionOptions{
			Operator:  sessionTestRecipient,
			Recipient: sessionTestRecipient,
			Cap:       1_000,
			SecretKey: sessionMethodSecret,
		}
	}

	zeroCap := base()
	zeroCap.Cap = 0
	if _, err := NewSession(zeroCap); err == nil || !strings.Contains(err.Error(), "cap must be positive") {
		t.Fatalf("zero cap error = %v", err)
	}

	noRecipient := base()
	noRecipient.Recipient = ""
	if _, err := NewSession(noRecipient); err == nil || !strings.Contains(err.Error(), "recipient is required") {
		t.Fatalf("missing recipient error = %v", err)
	}

	badRecipient := base()
	badRecipient.Recipient = "not-base58!"
	if _, err := NewSession(badRecipient); err == nil || !strings.Contains(err.Error(), "invalid recipient") {
		t.Fatalf("invalid recipient error = %v", err)
	}

	manySplits := base()
	for i := 0; i < 9; i++ {
		manySplits.Splits = append(manySplits.Splits, Split{Recipient: solana.NewWallet().PublicKey(), BPS: 1})
	}
	if _, err := NewSession(manySplits); err == nil || !strings.Contains(err.Error(), "splits cannot exceed") {
		t.Fatalf("splits error = %v", err)
	}

	pullNoStrategy := base()
	pullNoStrategy.Modes = []intents.SessionMode{intents.SessionModePull}
	if _, err := NewSession(pullNoStrategy); err == nil || !strings.Contains(err.Error(), "pullVoucherStrategy is required") {
		t.Fatalf("pull strategy error = %v", err)
	}

	badSubmitter := base()
	badSubmitter.OpenTxSubmitter = OpenTxSubmitter("relay")
	if _, err := NewSession(badSubmitter); err == nil || !strings.Contains(err.Error(), "openTxSubmitter") {
		t.Fatalf("openTxSubmitter error = %v", err)
	}

	t.Setenv(secretKeyEnvVar, "")
	noSecret := base()
	noSecret.SecretKey = ""
	if _, err := NewSession(noSecret); err == nil || !strings.Contains(err.Error(), "missing secret key") {
		t.Fatalf("missing secret error = %v", err)
	}

	legacyRPC := &rpcWithoutBlockHeight{RPCClient: testutil.NewFakeRPC()}
	missingSettlementRPC := base()
	missingSettlementRPC.Network = "localnet"
	missingSettlementRPC.Signer = testutil.NewPrivateKey()
	if _, err := NewSession(missingSettlementRPC); err == nil || !strings.Contains(err.Error(), "RPC is required") {
		t.Fatalf("missing settlement RPC error = %v", err)
	}

	typedNilSigner := base()
	typedNilSigner.Network = "localnet"
	var nilSigner *typedNilSessionSigner
	typedNilSigner.Signer = nilSigner
	if _, err := NewSession(typedNilSigner); err == nil || !strings.Contains(err.Error(), "typed nil") {
		t.Fatalf("typed-nil signer error = %v", err)
	}

	typedNilRPC := base()
	typedNilRPC.Network = "localnet"
	var nilRPC *testutil.FakeRPC
	typedNilRPC.RPC = nilRPC
	if _, err := NewSession(typedNilRPC); err == nil || !strings.Contains(err.Error(), "typed nil") {
		t.Fatalf("typed-nil RPC error = %v", err)
	}

	unsupportedSettlement := base()
	unsupportedSettlement.Network = "localnet"
	unsupportedSettlement.Signer = testutil.NewPrivateKey()
	unsupportedSettlement.RPC = legacyRPC
	if _, err := NewSession(unsupportedSettlement); err == nil || !strings.Contains(err.Error(), "GetBlockHeight") {
		t.Fatalf("settlement RPC capability error = %v", err)
	}

	validSettlement := base()
	validSettlement.Network = "localnet"
	validSettlement.Signer = testutil.NewPrivateKey()
	validSettlement.RPC = testutil.NewFakeRPC()
	session, err := NewSession(validSettlement)
	if err != nil {
		t.Fatalf("valid settlement configuration: %v", err)
	}
	session.Shutdown()

	verificationOnly := base()
	verificationOnly.Network = "localnet"
	verificationOnly.RPC = legacyRPC
	session, err = NewSession(verificationOnly)
	if err != nil {
		t.Fatalf("verification-only legacy RPC: %v", err)
	}
	session.Shutdown()
}

func TestNewSessionDefaults(t *testing.T) {
	session := newTestSession(t, func(o *SessionOptions) {
		o.Currency = ""
		o.Decimals = 0
		o.Network = ""
		o.OpenTxSubmitter = ""
		o.Store = durableTestChannelStore{ChannelStore: NewMemoryChannelStore()}
	})
	if session.currency != "USDC" || session.network != "mainnet" {
		t.Fatalf("defaults: currency=%q network=%q", session.currency, session.network)
	}
	if session.openTxSubmitter != OpenTxSubmitterClient {
		t.Fatalf("openTxSubmitter default = %q", session.openTxSubmitter)
	}
	if session.core.config.Decimals != 6 {
		t.Fatalf("decimals default = %d", session.core.config.Decimals)
	}
}

func TestNewSessionRequiresInjectedStoreOffLocalnet(t *testing.T) {
	options := SessionOptions{
		Operator:  sessionTestRecipient,
		Recipient: sessionTestRecipient,
		Cap:       1_000,
		Network:   "devnet",
		SecretKey: sessionMethodSecret,
	}
	if _, err := NewSession(options); err == nil || !strings.Contains(err.Error(), "session store is required") {
		t.Fatalf("missing off-localnet store error = %v", err)
	}

	options.Store = durableTestChannelStore{ChannelStore: NewMemoryChannelStore()}
	session, err := NewSession(options)
	if err != nil {
		t.Fatalf("NewSession with injected store: %v", err)
	}
	session.Shutdown()

	options.Store = struct{ ChannelStore }{ChannelStore: NewMemoryChannelStore()}
	if _, err := NewSession(options); err == nil || !strings.Contains(err.Error(), "explicitly declare durable shared") {
		t.Fatalf("unmarked off-localnet store error = %v", err)
	}
}

// ── Challenge ──

func TestSessionChallengeCanonicalShape(t *testing.T) {
	session := newTestSession(t, nil)
	challenge, err := session.Challenge(context.Background(), SessionChallengeOptions{
		Cap:         "1000000",
		Description: "Metered token stream",
	})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if !challenge.Verify(sessionMethodSecret) {
		t.Fatal("challenge HMAC does not verify")
	}
	if !challenge.Intent.IsSession() {
		t.Fatalf("intent = %q, want session", challenge.Intent)
	}
	if string(challenge.Method) != "solana" || challenge.Realm != "api.test" {
		t.Fatalf("method=%q realm=%q", challenge.Method, challenge.Realm)
	}
	var request intents.SessionRequest
	if err := challenge.Request.Decode(&request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if request.Cap != "1000000" || request.Currency != "USDC" {
		t.Fatalf("cap=%q currency=%q", request.Cap, request.Currency)
	}
	if request.Operator != sessionTestRecipient || request.Recipient != sessionTestRecipient {
		t.Fatalf("operator=%q recipient=%q", request.Operator, request.Recipient)
	}
	if request.Network == nil || *request.Network != "localnet" {
		t.Fatalf("network = %v", request.Network)
	}
	if request.Decimals == nil || *request.Decimals != 6 {
		t.Fatalf("decimals = %v", request.Decimals)
	}
	if request.Description == nil || *request.Description != "Metered token stream" {
		t.Fatalf("description = %v", request.Description)
	}
	if request.Modes != nil {
		t.Fatalf("modes should be omitted when push-only, got %v", request.Modes)
	}
	if request.RecentBlockhash != nil {
		t.Fatalf("recentBlockhash should be absent without an RPC client, got %v", *request.RecentBlockhash)
	}
}

func TestSessionChallengeClampsRequestedCap(t *testing.T) {
	session := newTestSession(t, func(o *SessionOptions) { o.Cap = 1_000_000 })
	challenge, err := session.Challenge(context.Background(), SessionChallengeOptions{Cap: "50000000"})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	var request intents.SessionRequest
	if err := challenge.Request.Decode(&request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if request.Cap != "1000000" {
		t.Fatalf("cap = %q, want clamped 1000000", request.Cap)
	}
}

func TestSessionChallengeInvalidCapRejected(t *testing.T) {
	session := newTestSession(t, nil)
	if _, err := session.Challenge(context.Background(), SessionChallengeOptions{Cap: "1.5"}); err == nil {
		t.Fatal("expected invalid cap error")
	}
}

func TestSessionChallengeIncludesBlockhashWithRPC(t *testing.T) {
	fake := testutil.NewFakeRPC()
	session := newTestSession(t, func(o *SessionOptions) { o.RPC = fake })
	challenge, err := session.Challenge(context.Background(), SessionChallengeOptions{})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	var request intents.SessionRequest
	if err := challenge.Request.Decode(&request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if request.RecentBlockhash == nil || *request.RecentBlockhash != fake.Blockhash.String() {
		t.Fatalf("recentBlockhash = %v, want %s", request.RecentBlockhash, fake.Blockhash)
	}
}

func TestSessionChallengeAdvertisesPullStrategy(t *testing.T) {
	strategy := intents.SessionPullVoucherStrategyClientVoucher
	session := newTestSession(t, func(o *SessionOptions) {
		o.Modes = []intents.SessionMode{intents.SessionModePull, intents.SessionModePush}
		o.PullVoucherStrategy = &strategy
	})
	challenge, err := session.Challenge(context.Background(), SessionChallengeOptions{ExternalID: "ref-7"})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	var request intents.SessionRequest
	if err := challenge.Request.Decode(&request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if len(request.Modes) != 2 {
		t.Fatalf("modes = %v", request.Modes)
	}
	if request.PullVoucherStrategy == nil || *request.PullVoucherStrategy != strategy {
		t.Fatalf("pullVoucherStrategy = %v", request.PullVoucherStrategy)
	}
	if request.ExternalID == nil || *request.ExternalID != "ref-7" {
		t.Fatalf("externalId = %v", request.ExternalID)
	}
}

// ── VerifyCredential: tier-1 + tier-2 ──

func TestVerifyCredentialRejectsTamperedAndExpiredChallenges(t *testing.T) {
	session := newTestSession(t, nil)
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	action := intents.NewOpenAction(intents.OpenPayloadPush(channelID, "1000", signer.Address(), "sig"))

	credential := sessionActionCredential(t, session, action)
	credential.Challenge.Realm = "tampered.example"
	if _, err := session.VerifyCredential(context.Background(), credential); err == nil ||
		!strings.Contains(err.Error(), "challenge ID mismatch") {
		t.Fatalf("tampered realm error = %v", err)
	}

	request, err := core.NewBase64URLJSONValue(session.core.BuildChallengeRequest(1_000))
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	expired := core.NewChallengeWithSecretFull(
		sessionMethodSecret, "api.test", core.NewMethodName("solana"), core.NewIntentName("session"),
		request, "2020-01-01T00:00:00Z", "", "", nil)
	expiredCredential, err := core.NewPaymentCredential(expired.ToEcho(), action)
	if err != nil {
		t.Fatalf("NewPaymentCredential: %v", err)
	}
	if _, err := session.VerifyCredential(context.Background(), expiredCredential); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired challenge error = %v", err)
	}
}

func TestVerifyCredentialPinnedFieldBackstop(t *testing.T) {
	session := newTestSession(t, nil)
	signer := newTestVoucherSigner(t)
	action := intents.NewOpenAction(intents.OpenPayloadPush(
		solana.NewWallet().PublicKey().String(), "1000", signer.Address(), "sig"))

	issue := func(intent string, request intents.SessionRequest) core.PaymentCredential {
		encoded, err := core.NewBase64URLJSONValue(request)
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		challenge := core.NewChallengeWithSecretFull(
			sessionMethodSecret, "api.test", core.NewMethodName("solana"), core.NewIntentName(intent),
			encoded, core.Minutes(5), "", "", nil)
		credential, err := core.NewPaymentCredential(challenge.ToEcho(), action)
		if err != nil {
			t.Fatalf("NewPaymentCredential: %v", err)
		}
		return credential
	}

	chargeIntent := issue("charge", session.core.BuildChallengeRequest(1_000))
	if _, err := session.VerifyCredential(context.Background(), chargeIntent); err == nil ||
		!strings.Contains(err.Error(), "not a session") {
		t.Fatalf("wrong intent error = %v", err)
	}

	wrongCurrency := session.core.BuildChallengeRequest(1_000)
	wrongCurrency.Currency = "USDT"
	if _, err := session.VerifyCredential(context.Background(), issue("session", wrongCurrency)); err == nil ||
		!strings.Contains(err.Error(), "currency") {
		t.Fatalf("wrong currency error = %v", err)
	}

	wrongRecipient := session.core.BuildChallengeRequest(1_000)
	wrongRecipient.Recipient = solana.NewWallet().PublicKey().String()
	if _, err := session.VerifyCredential(context.Background(), issue("session", wrongRecipient)); err == nil ||
		!strings.Contains(err.Error(), "recipient") {
		t.Fatalf("wrong recipient error = %v", err)
	}

	unknownAction := sessionActionCredential(t, session, map[string]string{"action": "refund"})
	if _, err := session.VerifyCredential(context.Background(), unknownAction); err == nil ||
		!strings.Contains(err.Error(), "decode session action") {
		t.Fatalf("unknown action error = %v", err)
	}
}

// ── open ──

func TestSessionOpenTrustsChannelIDAndDeposit(t *testing.T) {
	session := newTestSession(t, nil)
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()

	receipt, channelID := openSessionChannel(t, session, channelID, 1_000_000, signer.Address(), "sig-1")
	if receipt.Status != core.ReceiptStatusSuccess {
		t.Fatalf("status = %q", receipt.Status)
	}
	if receipt.Reference != "sig-1" {
		t.Fatalf("reference = %q, want sig-1", receipt.Reference)
	}
	state := mustGetChannel(t, session, channelID)
	if state == nil || state.Deposit != 1_000_000 || state.Cumulative != 0 || state.AuthorizedSigner != signer.Address() {
		t.Fatalf("stored state = %+v", state)
	}
}

func TestSessionSignatureOnlyOpenBindsFetchedTransactionAndDeposit(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fake := testutil.NewFakeRPC()
	registerFetchedOpenTransaction(t, fake, fixture, 777)
	session := newTestSession(t, func(o *SessionOptions) {
		o.Operator = fixture.payer.PublicKey().String()
		o.Recipient = fixture.payee.String()
		o.Network = "mainnet"
		o.RPC = fake
		o.Store = durableTestChannelStore{ChannelStore: NewMemoryChannelStore()}
	})
	seedSessionChannelAccountWithSeeds(
		t, fake, fixture.channel, openFixtureDeposit, fixture.payer.PublicKey(), fixture.payee,
		fixture.authorized, fixture.mint, pcgen.ChannelStatus_Open, openFixtureSalt, openFixtureOpenSlot,
		fixture.payer.PublicKey(),
	)

	payload := fixture.payload
	payload.Transaction = nil
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(payload)); err != nil {
		t.Fatalf("signature-only open: %v", err)
	}
	state := mustGetChannel(t, session, fixture.channel.String())
	if state == nil || state.Deposit != openFixtureDeposit || state.OpenSlot != openFixtureOpenSlot {
		t.Fatalf("state = %+v, want fetched transaction/account facts", state)
	}

	claimedDeposit := "999999"
	payload.Deposit = &claimedDeposit
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(payload)); err == nil ||
		!strings.Contains(err.Error(), "!= asserted deposit") {
		t.Fatalf("deposit mismatch error = %v", err)
	}
}

func TestSessionSignatureOnlyOpenRejectsUnrelatedConfirmedTransaction(t *testing.T) {
	target := buildOpenTxFixture(t, false)
	unrelated := buildOpenTxFixture(t, false)
	fake := testutil.NewFakeRPC()
	registerFetchedOpenTransaction(t, fake, unrelated, 778)
	session := newTestSession(t, func(o *SessionOptions) {
		o.Operator = target.payer.PublicKey().String()
		o.Recipient = target.payee.String()
		o.Network = "mainnet"
		o.RPC = fake
		o.Store = durableTestChannelStore{ChannelStore: NewMemoryChannelStore()}
	})
	seedSessionChannelAccountWithSeeds(
		t, fake, target.channel, openFixtureDeposit, target.payer.PublicKey(), target.payee,
		target.authorized, target.mint, pcgen.ChannelStatus_Open, openFixtureSalt, openFixtureOpenSlot,
		target.payer.PublicKey(),
	)

	payload := target.payload
	payload.Transaction = nil
	payload.Signature = unrelated.signature
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(payload)); err == nil {
		t.Fatal("unrelated confirmed transaction authorized the target channel")
	}
	if state := mustGetChannel(t, session, target.channel.String()); state != nil {
		t.Fatalf("target channel persisted after unrelated transaction: %+v", state)
	}
}

func TestSignatureOnlyPushOpenBindsChallengeRecentSlot(t *testing.T) {
	session := newTestSession(t, nil)
	request := session.Core().BuildChallengeRequest(1_000)
	recentSlot := intents.U64String(42)
	request.RecentSlot = &recentSlot
	requestValue, err := core.NewBase64URLJSONValue(request)
	if err != nil {
		t.Fatalf("NewBase64URLJSONValue: %v", err)
	}
	challenge := core.NewChallengeWithSecretFull(
		sessionMethodSecret, "api.test", core.NewMethodName("solana"), core.NewIntentName("session"),
		requestValue, "", "", "", nil,
	)
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()

	missing := intents.OpenPayloadPush(channelID, "1000", signer.Address(), "sig")
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), intents.NewOpenAction(missing))
	if err != nil {
		t.Fatalf("missing credential: %v", err)
	}
	if _, err := session.VerifyCredential(context.Background(), credential); err == nil || !strings.Contains(err.Error(), "requires recentSlot") {
		t.Fatalf("missing recentSlot error = %v", err)
	}

	wrong := missing
	wrongSlot := uint64(43)
	wrong.RecentSlot = &wrongSlot
	credential, err = core.NewPaymentCredential(challenge.ToEcho(), intents.NewOpenAction(wrong))
	if err != nil {
		t.Fatalf("mismatched credential: %v", err)
	}
	if _, err := session.VerifyCredential(context.Background(), credential); err == nil || !strings.Contains(err.Error(), "does not match the challenge") {
		t.Fatalf("mismatched recentSlot error = %v", err)
	}

	matching := missing
	matchingSlot := uint64(recentSlot)
	matching.RecentSlot = &matchingSlot
	credential, err = core.NewPaymentCredential(challenge.ToEcho(), intents.NewOpenAction(matching))
	if err != nil {
		t.Fatalf("matching credential: %v", err)
	}
	if _, err := session.VerifyCredential(context.Background(), credential); err != nil {
		t.Fatalf("matching recentSlot open: %v", err)
	}
	state := mustGetChannel(t, session, channelID)
	if state == nil || state.OpenSlot != 42 {
		t.Fatalf("state = %+v, want challenge open slot 42", state)
	}
}

func TestSessionOpenRejectsUnadvertisedMode(t *testing.T) {
	session := newTestSession(t, nil)
	signer := newTestVoucherSigner(t)
	payload := intents.OpenPayloadPull(
		solana.NewWallet().PublicKey().String(), "1000",
		solana.NewWallet().PublicKey().String(), signer.Address(), "sig")
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(payload)); err == nil ||
		!strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unadvertised mode error = %v", err)
	}
}

func TestSessionOpenRejectsBadDeposits(t *testing.T) {
	session := newTestSession(t, func(o *SessionOptions) { o.Cap = 1_000 })
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()

	over := intents.OpenPayloadPush(channelID, "10000", signer.Address(), "sig")
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(over)); err == nil ||
		!strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("over-cap error = %v", err)
	}

	zero := intents.OpenPayloadPush(channelID, "0", signer.Address(), "sig")
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(zero)); err == nil ||
		!strings.Contains(err.Error(), "greater than zero") {
		t.Fatalf("zero deposit error = %v", err)
	}

	missing := intents.OpenPayload{Mode: intents.SessionModePush, AuthorizedSigner: signer.Address(), Signature: "sig"}
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(missing)); err == nil ||
		!strings.Contains(err.Error(), "missing transaction or channelId") {
		t.Fatalf("missing channel error = %v", err)
	}
}

// TestSessionOpenRejectsEmptyStringFields pins that empty strings count as
// missing on the push open path: transaction="" with no channelId (and the
// all-empty variant) must reject gracefully instead of dereferencing a nil
// ChannelID.
func TestSessionOpenRejectsEmptyStringFields(t *testing.T) {
	session := newTestSession(t, nil)
	signer := newTestVoucherSigner(t)
	empty := ""

	emptyTx := intents.OpenPayload{
		Mode: intents.SessionModePush, Transaction: &empty,
		AuthorizedSigner: signer.Address(), Signature: "sig",
	}
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(emptyTx)); err == nil ||
		!strings.Contains(err.Error(), "missing transaction or channelId") {
		t.Fatalf("empty transaction error = %v", err)
	}

	emptyBoth := intents.OpenPayload{
		Mode: intents.SessionModePush, Transaction: &empty, ChannelID: &empty,
		AuthorizedSigner: signer.Address(), Signature: "sig",
	}
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(emptyBoth)); err == nil ||
		!strings.Contains(err.Error(), "missing transaction or channelId") {
		t.Fatalf("empty transaction and channelId error = %v", err)
	}
}

func TestSessionOpenReplaySemantics(t *testing.T) {
	session := newTestSession(t, nil)
	signer, channelID := openTrustedChannel(t, session, 1_000)

	if _, err := submitMethodVoucher(t, session, signer, channelID, 250); err != nil {
		t.Fatalf("voucher: %v", err)
	}

	// Idempotent replay preserves the watermark.
	_, _ = openSessionChannel(t, session, channelID, 1_000, signer.Address(), "open-sig")
	state := mustGetChannel(t, session, channelID)
	if state.Cumulative != 250 || state.HighestVoucherSignature == nil {
		t.Fatalf("replay reset watermark: %+v", state)
	}

	// Different authorizedSigner rejects without overwriting.
	intruder := newTestVoucherSigner(t)
	payload := intents.OpenPayloadPush(channelID, "1000", intruder.Address(), "open-sig")
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(payload)); err == nil ||
		!strings.Contains(err.Error(), "authorizedSigner") {
		t.Fatalf("intruder replay error = %v", err)
	}
	if mustGetChannel(t, session, channelID).AuthorizedSigner != signer.Address() {
		t.Fatal("intruder replay overwrote the authorized signer")
	}

	// Sealed channel rejects replays.
	if _, err := session.Core().Store().MarkSealed(context.Background(), channelID); err != nil {
		t.Fatalf("MarkSealed: %v", err)
	}
	replay := intents.OpenPayloadPush(channelID, "1000", signer.Address(), "open-sig")
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(replay)); err == nil ||
		!strings.Contains(err.Error(), "sealed") {
		t.Fatalf("sealed replay error = %v", err)
	}
}

func TestSessionOpenVerifiesSignatureOnChain(t *testing.T) {
	fake := testutil.NewFakeRPC()
	okSig := confirmedSignature(0x11)
	ghostSig := confirmedSignature(0x22)
	failedSig := confirmedSignature(0x33)
	fake.Statuses[ghostSig] = nil
	fake.Statuses[failedSig] = &rpc.SignatureStatusesResult{Err: map[string]any{"InstructionError": []any{0, "Custom"}}}

	session := newTestSession(t, func(o *SessionOptions) { o.RPC = fake })
	signer := newTestVoucherSigner(t)

	channelID := solana.NewWallet().PublicKey().String()
	receipt, _ := openSessionChannel(t, session, channelID, 1_000, signer.Address(), okSig)
	if receipt.Reference != okSig {
		t.Fatalf("reference = %q", receipt.Reference)
	}

	ghostChannel := solana.NewWallet().PublicKey().String()
	ghost := intents.OpenPayloadPush(ghostChannel, "1000", signer.Address(), ghostSig)
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(ghost)); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("ghost signature error = %v", err)
	}
	if mustGetChannel(t, session, ghostChannel) != nil {
		t.Fatal("channel persisted despite unknown signature")
	}

	failed := intents.OpenPayloadPush(solana.NewWallet().PublicKey().String(), "1000", signer.Address(), failedSig)
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(failed)); err == nil ||
		!strings.Contains(err.Error(), "failed on-chain") {
		t.Fatalf("failed signature error = %v", err)
	}
}

func TestSessionPullOpenPrefersChannelIDOverTokenAccount(t *testing.T) {
	strategy := intents.SessionPullVoucherStrategyClientVoucher
	session := newTestSession(t, func(o *SessionOptions) {
		o.Modes = []intents.SessionMode{intents.SessionModePull}
		o.PullVoucherStrategy = &strategy
	})
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	tokenAccount := solana.NewWallet().PublicKey().String()

	payload := intents.OpenPayloadPull(tokenAccount, "1000", solana.NewWallet().PublicKey().String(), signer.Address(), "sig-1")
	payload.ChannelID = &channelID
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(payload)); err != nil {
		t.Fatalf("pull open: %v", err)
	}
	if mustGetChannel(t, session, channelID) == nil {
		t.Fatal("channel not keyed by channelId")
	}
	if mustGetChannel(t, session, tokenAccount) != nil {
		t.Fatal("channel unexpectedly keyed by tokenAccount")
	}
	// Pull opens record the owner as the channel operator.
	if state := mustGetChannel(t, session, channelID); state.Operator == nil {
		t.Fatal("pull open did not record the operator")
	}
}

// ── voucher ──

func submitMethodVoucher(t *testing.T, session *Session, signer testVoucherSigner, channelID string, cumulative uint64) (core.Receipt, error) {
	t.Helper()
	voucher := signer.SignVoucher(t, channelID, cumulative, farFuture())
	return verifySessionAction(t, session, intents.NewVoucherAction(intents.VoucherPayload{Voucher: voucher}))
}

func TestSessionVoucherAdvancesWatermark(t *testing.T) {
	session := newTestSession(t, nil)
	signer, channelID := openTrustedChannel(t, session, 1_000)

	voucher := signer.SignVoucher(t, channelID, 250, farFuture())
	receipt, err := verifySessionAction(t, session, intents.NewVoucherAction(intents.VoucherPayload{Voucher: voucher}))
	if err != nil {
		t.Fatalf("voucher: %v", err)
	}
	if receipt.Reference != channelID+":250" {
		t.Fatalf("reference = %q", receipt.Reference)
	}
	state := mustGetChannel(t, session, channelID)
	if state.Cumulative != 250 || state.HighestVoucherSignature == nil || *state.HighestVoucherSignature != voucher.Signature {
		t.Fatalf("state after voucher = %+v", state)
	}
}

func TestSessionVoucherUnknownChannelRejected(t *testing.T) {
	session := newTestSession(t, nil)
	signer := newTestVoucherSigner(t)
	if _, err := submitMethodVoucher(t, session, signer, solana.NewWallet().PublicKey().String(), 100); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown channel error = %v", err)
	}
}

func TestSessionVoucherNonMonotonicTaggedRejection(t *testing.T) {
	session := newTestSession(t, nil)
	signer, channelID := openTrustedChannel(t, session, 1_000)
	if _, err := submitMethodVoucher(t, session, signer, channelID, 100); err != nil {
		t.Fatalf("first voucher: %v", err)
	}
	if _, err := submitMethodVoucher(t, session, signer, channelID, 50); err == nil ||
		!strings.Contains(err.Error(), "cumulative-not-monotonic") {
		t.Fatalf("stale voucher error = %v", err)
	}
}

func TestSessionVoucherAcceptsCumulativeAliasOnTheWire(t *testing.T) {
	session := newTestSession(t, nil)
	signer, channelID := openTrustedChannel(t, session, 1_000)
	canonical := signer.SignVoucher(t, channelID, 250, farFuture())

	aliased := map[string]any{
		"action": "voucher",
		"voucher": map[string]any{
			"data": map[string]any{
				"channelId":  channelID,
				"cumulative": "250",
				"expiresAt":  canonical.Data.ExpiresAt,
			},
			"signature": canonical.Signature,
		},
	}
	receipt, err := verifySessionAction(t, session, aliased)
	if err != nil {
		t.Fatalf("aliased voucher: %v", err)
	}
	if receipt.Reference != channelID+":250" {
		t.Fatalf("reference = %q", receipt.Reference)
	}
	if mustGetChannel(t, session, channelID).Cumulative != 250 {
		t.Fatal("alias voucher did not advance the watermark")
	}

	neither := map[string]any{
		"action": "voucher",
		"voucher": map[string]any{
			"data":      map[string]any{"channelId": channelID, "expiresAt": canonical.Data.ExpiresAt},
			"signature": canonical.Signature,
		},
	}
	if _, err := verifySessionAction(t, session, neither); err == nil ||
		!strings.Contains(err.Error(), "cumulativeAmount") {
		t.Fatalf("missing cumulative error = %v", err)
	}
}

// ── topUp ──

func TestSessionTopUpUpdatesDeposit(t *testing.T) {
	session := newTestSession(t, nil)
	_, channelID := openTrustedChannel(t, session, 1_000)

	receipt, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "5000", Signature: "topup-sig",
	}))
	if err != nil {
		t.Fatalf("topUp: %v", err)
	}
	if receipt.Reference != "topup-sig" {
		t.Fatalf("reference = %q", receipt.Reference)
	}
	if mustGetChannel(t, session, channelID).Deposit != 5_000 {
		t.Fatal("deposit not raised")
	}
}

func TestSessionTopUpHardening(t *testing.T) {
	session := newTestSession(t, nil)
	_, channelID := openTrustedChannel(t, session, 5_000)

	if _, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "1000", Signature: "sig",
	})); err == nil || !strings.Contains(err.Error(), "must exceed current deposit") {
		t.Fatalf("below-current error = %v", err)
	}

	if _, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "99000000", Signature: "sig",
	})); err == nil || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("over-cap error = %v", err)
	}

	if _, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: solana.NewWallet().PublicKey().String(), NewDeposit: "9000", Signature: "sig",
	})); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown channel error = %v", err)
	}

	// Close-pending blocks top-ups.
	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID})); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "9000", Signature: "sig",
	})); err == nil || !strings.Contains(err.Error(), "close is pending") {
		t.Fatalf("close-pending error = %v", err)
	}

	// Sealed blocks top-ups.
	_, sealedChannel := openTrustedChannel(t, session, 5_000)
	if _, err := session.Core().Store().MarkSealed(context.Background(), sealedChannel); err != nil {
		t.Fatalf("MarkSealed: %v", err)
	}
	if _, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: sealedChannel, NewDeposit: "9000", Signature: "sig",
	})); err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Fatalf("sealed error = %v", err)
	}
}

func TestSessionTopUpVerifiesSignatureOnChain(t *testing.T) {
	fake := testutil.NewFakeRPC()
	openSig := confirmedSignature(0x44)
	topupSig := confirmedSignature(0x55)
	ghostSig := confirmedSignature(0x66)
	fake.Statuses[ghostSig] = nil

	session := newTestSession(t, func(o *SessionOptions) { o.RPC = fake })
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	_, channelID = openSessionChannel(t, session, channelID, 1_000, signer.Address(), openSig)
	state := mustGetChannel(t, session, channelID)
	seedSessionAccountThroughSetter(
		t, fake, session, channelID, 5_000, *state.Operator, signer.Address(),
	)

	receipt, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "5000", Signature: topupSig,
	}))
	if err != nil {
		t.Fatalf("topUp: %v", err)
	}
	if receipt.Reference != topupSig {
		t.Fatalf("reference = %q", receipt.Reference)
	}
	if mustGetChannel(t, session, channelID).Deposit != 5_000 {
		t.Fatal("deposit not raised")
	}

	if _, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "9000", Signature: ghostSig,
	})); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("ghost top-up error = %v", err)
	}
	if mustGetChannel(t, session, channelID).Deposit != 5_000 {
		t.Fatal("deposit raised despite unknown signature")
	}
}

// ── close ──

func TestSessionCloseFlipsClosePending(t *testing.T) {
	session := newTestSession(t, nil)
	_, channelID := openTrustedChannel(t, session, 1_000)

	receipt, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID}))
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if receipt.Reference != channelID {
		t.Fatalf("reference = %q, want channel id", receipt.Reference)
	}
	state := mustGetChannel(t, session, channelID)
	if state.CloseRequestedAt == nil || state.Sealed {
		t.Fatalf("state after close = %+v", state)
	}
}

func TestSessionCloseWithFinalVoucherAdvancesWatermark(t *testing.T) {
	session := newTestSession(t, nil)
	signer, channelID := openTrustedChannel(t, session, 1_000)

	final := signer.SignVoucher(t, channelID, 750, farFuture())
	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{
		ChannelID: channelID, Voucher: &final,
	})); err != nil {
		t.Fatalf("close: %v", err)
	}
	state := mustGetChannel(t, session, channelID)
	if state.Cumulative != 750 || state.CloseRequestedAt == nil {
		t.Fatalf("state after close = %+v", state)
	}
}

func TestSessionCloseNonMonotonicFinalVoucherHardError(t *testing.T) {
	session := newTestSession(t, nil)
	signer, channelID := openTrustedChannel(t, session, 1_000)
	if _, err := submitMethodVoucher(t, session, signer, channelID, 250); err != nil {
		t.Fatalf("voucher: %v", err)
	}

	stale := signer.SignVoucher(t, channelID, 100, farFuture())
	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{
		ChannelID: channelID, Voucher: &stale,
	})); err == nil || !strings.Contains(err.Error(), "cumulative-not-monotonic") {
		t.Fatalf("stale final voucher error = %v", err)
	}
	state := mustGetChannel(t, session, channelID)
	if state.CloseRequestedAt != nil || state.Cumulative != 250 {
		t.Fatalf("close mutated state on hard error: %+v", state)
	}
}

func TestSessionCloseAcceptsReplayOfHighestVoucher(t *testing.T) {
	session := newTestSession(t, nil)
	signer, channelID := openTrustedChannel(t, session, 1_000)
	voucher := signer.SignVoucher(t, channelID, 250, farFuture())
	if _, err := verifySessionAction(t, session, intents.NewVoucherAction(intents.VoucherPayload{Voucher: voucher})); err != nil {
		t.Fatalf("voucher: %v", err)
	}

	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{
		ChannelID: channelID, Voucher: &voucher,
	})); err != nil {
		t.Fatalf("close with replayed highest voucher: %v", err)
	}
	state := mustGetChannel(t, session, channelID)
	if state.CloseRequestedAt == nil || state.Cumulative != 250 {
		t.Fatalf("state after replay close = %+v", state)
	}
}

func TestSessionCloseRetryAfterFailedSettlement(t *testing.T) {
	fake := testutil.NewFakeRPC()
	merchant := testutil.NewPrivateKey()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.Signer = merchant
	})
	signer, channelID := openTrustedChannel(t, session, 1_000)
	if _, err := submitMethodVoucher(t, session, signer, channelID, 400); err != nil {
		t.Fatalf("voucher: %v", err)
	}

	// Submission fails before reaching the network and the signature remains
	// not found within its validity window. The exact outbox stays uncertain.
	crashRPC := &crashBeforeSendRPC{FakeRPC: fake}
	session.rpc = crashRPC
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := session.handleClose(ctx, &intents.ClosePayload{ChannelID: channelID}); err == nil ||
		!strings.Contains(err.Error(), "simulated process crash") {
		t.Fatalf("settlement failure error = %v", err)
	}
	state := mustGetChannel(t, session, channelID)
	if state.CloseRequestedAt == nil || state.Sealed || !state.Settling || state.SettledSignature == nil || state.SettlementWire == "" {
		t.Fatalf("state after failed settle = %+v", state)
	}

	// A retry idempotently submits the same wire. A definite failed status then
	// clears the outbox, allowing a later retry to build a fresh transaction.
	failureRPC := &definiteFailureRPC{FakeRPC: fake}
	failureRPC.fail.Store(true)
	session.rpc = failureRPC
	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID})); err == nil ||
		!strings.Contains(err.Error(), "failed on-chain") {
		t.Fatalf("pending settlement failure = %v", err)
	}
	state = mustGetChannel(t, session, channelID)
	if state.Sealed || state.Settling || state.SettledSignature != nil || state.SettlementWire != "" ||
		state.SettlementClaimOwner != "" || state.SettlementClaimedAt != 0 {
		t.Fatalf("state after definite pending failure = %+v", state)
	}
	failureRPC.fail.Store(false)
	receipt, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID}))
	if err != nil {
		t.Fatalf("close retry: %v", err)
	}
	if len(fake.Sent) != 2 {
		t.Fatalf("settlement broadcasts = %d, want 2", len(fake.Sent))
	}
	state = mustGetChannel(t, session, channelID)
	if !state.Sealed || state.SettledSignature == nil {
		t.Fatalf("state after settle = %+v", state)
	}
	if receipt.Reference != *state.SettledSignature {
		t.Fatalf("reference = %q, want settled signature %q", receipt.Reference, *state.SettledSignature)
	}

	// A later close on the sealed channel rejects.
	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID})); err == nil ||
		!strings.Contains(err.Error(), "sealed") {
		t.Fatalf("third close error = %v", err)
	}
}

func TestSessionCloseWithoutSignerDoesNotSettle(t *testing.T) {
	fake := testutil.NewFakeRPC()
	session := newTestSession(t, func(o *SessionOptions) { o.RPC = fake })
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	_, channelID = openSessionChannel(t, session, channelID, 1_000, signer.Address(), confirmedSignature(0x77))

	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID})); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(fake.Sent) != 0 {
		t.Fatalf("settlement broadcast without a merchant signer: %d sends", len(fake.Sent))
	}
}

// ── commit + routes ──

func reserveDelivery(t *testing.T, routes SessionRoutes, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/__402/session/deliveries", bytes.NewReader(encoded))
	recorder := httptest.NewRecorder()
	routes.Deliveries(recorder, request)
	return recorder
}

func commitDeliveryViaRoutes(t *testing.T, routes SessionRoutes, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/__402/session/commit", bytes.NewReader(encoded))
	recorder := httptest.NewRecorder()
	routes.Commit(recorder, request)
	return recorder
}

func TestSessionCommitForReservedDelivery(t *testing.T) {
	session := newTestSession(t, nil)
	signer, channelID := openTrustedChannel(t, session, 1_000)
	routes := session.Routes()

	reserve := reserveDelivery(t, routes, map[string]any{"amount": "200", "sessionId": channelID})
	if reserve.Code != http.StatusOK {
		t.Fatalf("reserve status = %d body=%s", reserve.Code, reserve.Body)
	}
	var directive intents.MeteringDirective
	if err := json.Unmarshal(reserve.Body.Bytes(), &directive); err != nil {
		t.Fatalf("decode directive: %v", err)
	}
	if directive.DeliveryID != channelID+":1" || directive.Sequence != 1 {
		t.Fatalf("directive = %+v", directive)
	}
	if directive.Currency != "USDC" || directive.Amount != "200" {
		t.Fatalf("directive fields = %+v", directive)
	}

	voucher := signer.SignVoucher(t, channelID, 150, farFuture())
	receipt, err := verifySessionAction(t, session, intents.NewCommitAction(intents.CommitPayload{
		DeliveryID: directive.DeliveryID, Voucher: voucher,
	}))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	wantReference := fmt.Sprintf("%s:%s:150", channelID, directive.DeliveryID)
	if receipt.Reference != wantReference {
		t.Fatalf("reference = %q, want %q", receipt.Reference, wantReference)
	}
	state := mustGetChannel(t, session, channelID)
	if state.Cumulative != 150 || len(state.CommittedDeliveries) != 1 || len(state.PendingDeliveries) != 0 {
		t.Fatalf("state after commit = %+v", state)
	}
}

func TestSessionRoutesValidation(t *testing.T) {
	session := newTestSession(t, nil)
	routes := session.Routes()

	if recorder := reserveDelivery(t, routes, map[string]any{"amount": "10", "sessionId": "ghost"}); recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown channel status = %d", recorder.Code)
	}
	if recorder := reserveDelivery(t, routes, map[string]any{"amount": "10"}); recorder.Code != http.StatusBadRequest ||
		!strings.Contains(recorder.Body.String(), "sessionId required") {
		t.Fatalf("missing sessionId: %d %s", recorder.Code, recorder.Body)
	}
	if recorder := reserveDelivery(t, routes, map[string]any{"amount": "0", "sessionId": "x"}); recorder.Code != http.StatusBadRequest ||
		!strings.Contains(recorder.Body.String(), "amount must be positive") {
		t.Fatalf("zero amount: %d %s", recorder.Code, recorder.Body)
	}
	if recorder := reserveDelivery(t, routes, map[string]any{"amount": "ten", "sessionId": "x"}); recorder.Code != http.StatusBadRequest {
		t.Fatalf("non-numeric amount status = %d", recorder.Code)
	}

	invalid := httptest.NewRequest(http.MethodPost, "/__402/session/deliveries", strings.NewReader("not-json"))
	recorder := httptest.NewRecorder()
	routes.Deliveries(recorder, invalid)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid request body") {
		t.Fatalf("invalid body: %d %s", recorder.Code, recorder.Body)
	}

	get := httptest.NewRequest(http.MethodGet, "/__402/session/deliveries", nil)
	recorder = httptest.NewRecorder()
	routes.Deliveries(recorder, get)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET deliveries status = %d", recorder.Code)
	}

	if recorder := commitDeliveryViaRoutes(t, routes, map[string]any{"voucher": map[string]any{}}); recorder.Code != http.StatusBadRequest ||
		!strings.Contains(recorder.Body.String(), "deliveryId required") {
		t.Fatalf("missing deliveryId: %d %s", recorder.Code, recorder.Body)
	}
	if recorder := commitDeliveryViaRoutes(t, routes, map[string]any{"deliveryId": "d-1"}); recorder.Code != http.StatusBadRequest ||
		!strings.Contains(recorder.Body.String(), "voucher required") {
		t.Fatalf("missing voucher: %d %s", recorder.Code, recorder.Body)
	}
	getCommit := httptest.NewRequest(http.MethodGet, "/__402/session/commit", nil)
	recorder = httptest.NewRecorder()
	routes.Commit(recorder, getCommit)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET commit status = %d", recorder.Code)
	}
}

func TestSessionRoutesCommitReplayStatus(t *testing.T) {
	session := newTestSession(t, nil)
	signer, channelID := openTrustedChannel(t, session, 1_000)
	routes := session.Routes()

	reserve := reserveDelivery(t, routes, map[string]any{"amount": "50", "sessionId": channelID})
	var directive intents.MeteringDirective
	if err := json.Unmarshal(reserve.Body.Bytes(), &directive); err != nil {
		t.Fatalf("decode directive: %v", err)
	}
	voucher := signer.SignVoucher(t, channelID, 50, farFuture())

	commitBody := map[string]any{"deliveryId": directive.DeliveryID, "voucher": voucher}
	first := commitDeliveryViaRoutes(t, routes, commitBody)
	if first.Code != http.StatusOK {
		t.Fatalf("first commit: %d %s", first.Code, first.Body)
	}
	var firstReceipt intents.CommitReceipt
	if err := json.Unmarshal(first.Body.Bytes(), &firstReceipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if firstReceipt.Status != intents.CommitStatusCommitted || firstReceipt.Amount != "50" {
		t.Fatalf("first receipt = %+v", firstReceipt)
	}

	replay := commitDeliveryViaRoutes(t, routes, commitBody)
	if replay.Code != http.StatusOK {
		t.Fatalf("replay commit: %d %s", replay.Code, replay.Body)
	}
	var replayReceipt intents.CommitReceipt
	if err := json.Unmarshal(replay.Body.Bytes(), &replayReceipt); err != nil {
		t.Fatalf("decode replay receipt: %v", err)
	}
	if replayReceipt.Status != intents.CommitStatusReplayed {
		t.Fatalf("replay status = %q", replayReceipt.Status)
	}
}

func TestSessionCommitReplayReVerifiesSignature(t *testing.T) {
	session := newTestSession(t, nil)
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	forged := solana.SignatureFromBytes(bytes.Repeat([]byte{0xAA}, 64)).String()

	// Seed a channel whose committed delivery carries a forged signature; a
	// replay must fail the signature re-verification.
	if _, err := session.Core().Store().UpdateChannel(context.Background(), channelID, func(*ChannelState) (ChannelState, error) {
		return ChannelState{
			ChannelID:            channelID,
			AuthorizedSigner:     signer.Address(),
			Deposit:              1_000,
			Cumulative:           50,
			NextDeliverySequence: 1,
			CommittedDeliveries: []CommittedDelivery{
				{DeliveryID: "d-1", Amount: 50, Cumulative: 50, VoucherSignature: forged},
			},
		}, nil
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	forgedVoucher := intents.SignedVoucher{
		Data: intents.VoucherData{
			ChannelID:  channelID,
			Cumulative: "50",
			ExpiresAt:  farFuture(),
		},
		Signature: forged,
	}
	if _, err := verifySessionAction(t, session, intents.NewCommitAction(intents.CommitPayload{
		DeliveryID: "d-1", Voucher: forgedVoucher,
	})); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("forged replay error = %v", err)
	}
}

func TestSessionRoutesShareStoreWithMethod(t *testing.T) {
	session := newTestSession(t, nil)
	_, channelID := openTrustedChannel(t, session, 1_000)

	recorder := reserveDelivery(t, session.Routes(), map[string]any{"amount": "100", "sessionId": channelID})
	if recorder.Code != http.StatusOK {
		t.Fatalf("reserve status = %d body=%s", recorder.Code, recorder.Body)
	}
	var directive intents.MeteringDirective
	if err := json.Unmarshal(recorder.Body.Bytes(), &directive); err != nil {
		t.Fatalf("decode directive: %v", err)
	}
	if directive.DeliveryID != channelID+":1" {
		t.Fatalf("deliveryId = %q", directive.DeliveryID)
	}
}

// ── open with a transaction ──

func TestSessionOpenVerifiesAttachedTransaction(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	session := newTestSession(t, func(o *SessionOptions) {
		o.Recipient = fixture.payee.String()
		// The fixture pins rentPayer (the operator/fee payer) to its own payer.
		o.Operator = fixture.payer.PublicKey().String()
		o.Network = "localnet"
	})

	receipt, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload))
	if err != nil {
		t.Fatalf("open with transaction: %v", err)
	}
	if receipt.Reference != fixture.signature {
		t.Fatalf("reference = %q, want tx signature", receipt.Reference)
	}
	state := mustGetChannel(t, session, fixture.channel.String())
	if state == nil || state.Deposit != openFixtureDeposit {
		t.Fatalf("state = %+v", state)
	}
	// Push channel opens record the channel payer as the operator.
	if state.Operator == nil || *state.Operator != fixture.payer.PublicKey().String() {
		t.Fatalf("operator = %v", state.Operator)
	}
}

func TestSessionOpenRejectsTransactionForWrongRecipient(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	session := newTestSession(t, nil) // recipient differs from the fixture payee
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err == nil ||
		!strings.Contains(err.Error(), "payee") {
		t.Fatalf("wrong recipient error = %v", err)
	}
}

func TestSessionServerSubmitterBroadcastsOnceAndReplaysWithoutRebroadcast(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fake := testutil.NewFakeRPC()
	session := newTestSession(t, func(o *SessionOptions) {
		o.Recipient = fixture.payee.String()
		// The fixture pins rentPayer (the operator/fee payer) to its own payer.
		o.Operator = fixture.payer.PublicKey().String()
		o.OpenTxSubmitter = OpenTxSubmitterServer
		o.RPC = fake
	})
	seedSessionChannelAccountWithSeeds(
		t, fake, fixture.channel, openFixtureDeposit, fixture.payer.PublicKey(), fixture.payee,
		fixture.authorized, fixture.mint, pcgen.ChannelStatus_Open, openFixtureSalt, openFixtureOpenSlot,
		fixture.payer.PublicKey(),
	)

	receipt, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload))
	if err != nil {
		t.Fatalf("server-submitted open: %v", err)
	}
	if len(fake.Sent) != 1 {
		t.Fatalf("broadcasts = %d, want 1", len(fake.Sent))
	}
	if receipt.Reference != fixture.signature {
		t.Fatalf("reference = %q, want broadcast signature", receipt.Reference)
	}

	// Idempotent replay of the persisted open must not rebroadcast.
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err != nil {
		t.Fatalf("open replay: %v", err)
	}
	if len(fake.Sent) != 1 {
		t.Fatalf("replay rebroadcast the open: %d sends", len(fake.Sent))
	}
}

func TestSessionServerSubmitterRequiresRPC(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	session := newTestSession(t, func(o *SessionOptions) {
		o.Recipient = fixture.payee.String()
		o.OpenTxSubmitter = OpenTxSubmitterServer
	})
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err == nil ||
		!strings.Contains(err.Error(), "requires an rpc client") {
		t.Fatalf("missing rpc error = %v", err)
	}
}

func TestSessionServerSubmitterCompletesFeePayerSignature(t *testing.T) {
	// Client partial-signs as the channel payer and leaves the fee-payer
	// (operator) slot for the server, with the pending placeholder as the
	// payload signature: the createServerOpenedPaymentChannelSessionOpener
	// flow.
	operator := testutil.NewPrivateKey()
	fixture := buildServerCompletedOpenFixture(t, operator)
	fake := testutil.NewFakeRPC()
	fake.Statuses[fixture.payload.Signature] = &rpc.SignatureStatusesResult{
		ConfirmationStatus: rpc.ConfirmationStatusProcessed,
		Slot:               1,
	}
	session := newTestSession(t, func(o *SessionOptions) {
		o.Recipient = fixture.payee.String()
		o.Operator = operator.PublicKey().String()
		o.OpenTxSubmitter = OpenTxSubmitterServer
		o.PaymentChannelPayerSigner = operator
		o.RPC = fake
	})
	seedSessionChannelAccountWithSeeds(
		t, fake, fixture.channel, openFixtureDeposit, fixture.payer.PublicKey(), fixture.payee,
		fixture.authorized, fixture.mint, pcgen.ChannelStatus_Open, openFixtureSalt, openFixtureOpenSlot,
		operator.PublicKey(),
	)

	receipt, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload))
	if err != nil {
		t.Fatalf("server-completed open: %v", err)
	}
	if len(fake.Sent) != 1 {
		t.Fatalf("broadcasts = %d, want 1", len(fake.Sent))
	}
	if fake.Sent[0].Signatures[0].IsZero() {
		t.Fatal("fee-payer signature was not completed before broadcast")
	}
	if receipt.Reference != fake.Sent[0].Signatures[0].String() {
		t.Fatalf("reference = %q, want broadcast signature", receipt.Reference)
	}
	replay, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload))
	if err != nil {
		t.Fatalf("server-completed open replay: %v", err)
	}
	if len(fake.Sent) != 1 {
		t.Fatalf("replay rebroadcast the open: %d sends", len(fake.Sent))
	}
	if replay.Reference != receipt.Reference {
		t.Fatalf("replay reference = %q, want %q", replay.Reference, receipt.Reference)
	}
}

// buildServerCompletedOpenFixture builds an open transaction whose fee payer
// is the operator (unsigned) while the channel payer has partial-signed,
// paired with a placeholder payload signature.
func buildServerCompletedOpenFixture(t *testing.T, operator solana.PrivateKey) openTxFixture {
	t.Helper()
	fixture := buildOpenTxFixture(t, false)
	// Rebuild the open transaction with the operator as fee payer; only the
	// channel payer partial-signs, leaving the fee-payer slot zeroed.
	ix, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer: fixture.payer.PublicKey(),
		// rentPayer is pinned to the operator / fee payer that completes and
		// broadcasts this open server-side.
		RentPayer:        operator.PublicKey(),
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
	blockhash := solana.MustHashFromBase58("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")
	tx, err := solana.NewTransaction([]solana.Instruction{ix}, blockhash, solana.TransactionPayer(operator.PublicKey()))
	if err != nil {
		t.Fatalf("NewTransaction: %v", err)
	}
	if err := solanatx.SignTransaction(tx, fixture.payer); err != nil {
		t.Fatalf("partial-sign open tx: %v", err)
	}
	encoded, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatalf("EncodeTransactionBase64: %v", err)
	}
	payload := fixture.payload
	payload.Signature = strings.Repeat("1", 64)
	payload.Transaction = &encoded
	fixture.payload = payload
	fixture.expected.Recipient = fixture.payee.String()
	// rentPayer (slot 1) is pinned to the operator that completes/broadcasts.
	fixture.expected.Operator = operator.PublicKey().String()
	return fixture
}

// ── middleware ──

func TestSessionMiddlewareChallengeAndVerifyFlow(t *testing.T) {
	session := newTestSession(t, nil)
	var receiptInContext *core.Receipt
	handler := SessionMiddleware(session, func(*http.Request) (SessionChallengeOptions, error) {
		return SessionChallengeOptions{Cap: "1000000", Description: "Stream"}, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if receipt, ok := ReceiptFromContext(r.Context()); ok {
			receiptInContext = &receipt
		}
		w.WriteHeader(http.StatusOK)
	}))
	server := httptest.NewServer(handler)
	defer server.Close()

	// No credential: 402 with a session challenge.
	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", response.StatusCode)
	}
	header := response.Header.Get(core.WWWAuthenticateHeader)
	challenge, err := core.ParseWWWAuthenticate(header)
	if err != nil {
		t.Fatalf("parse challenge: %v", err)
	}
	if !challenge.Intent.IsSession() {
		t.Fatalf("intent = %q", challenge.Intent)
	}
	var request intents.SessionRequest
	if err := challenge.Request.Decode(&request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if request.Cap != "1000000" {
		t.Fatalf("cap = %q", request.Cap)
	}

	// Open credential: passes through with a receipt.
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), intents.NewOpenAction(
		intents.OpenPayloadPush(channelID, "1000", signer.Address(), "open-sig")))
	if err != nil {
		t.Fatalf("NewPaymentCredential: %v", err)
	}
	authorization, err := core.FormatAuthorization(credential)
	if err != nil {
		t.Fatalf("FormatAuthorization: %v", err)
	}
	authedRequest, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	authedRequest.Header.Set(core.AuthorizationHeader, authorization)
	authedResponse, err := http.DefaultClient.Do(authedRequest)
	if err != nil {
		t.Fatalf("authed GET: %v", err)
	}
	defer authedResponse.Body.Close()
	if authedResponse.StatusCode != http.StatusOK {
		t.Fatalf("authed status = %d", authedResponse.StatusCode)
	}
	receiptHeader := authedResponse.Header.Get(core.PaymentReceiptHeader)
	if receiptHeader == "" {
		t.Fatal("missing Payment-Receipt header")
	}
	receipt, err := core.ParseReceipt(receiptHeader)
	if err != nil {
		t.Fatalf("ParseReceipt: %v", err)
	}
	if receipt.Reference != "open-sig" {
		t.Fatalf("receipt reference = %q", receipt.Reference)
	}
	if receiptInContext == nil || receiptInContext.Reference != "open-sig" {
		t.Fatalf("receipt in context = %+v", receiptInContext)
	}
	if mustGetChannel(t, session, channelID) == nil {
		t.Fatal("middleware did not persist the opened channel")
	}

	// Garbage credential: 402 with a problem+json body.
	badRequest, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	badRequest.Header.Set(core.AuthorizationHeader, "Payment not-base64url")
	badResponse, err := http.DefaultClient.Do(badRequest)
	if err != nil {
		t.Fatalf("bad GET: %v", err)
	}
	defer badResponse.Body.Close()
	if badResponse.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("bad credential status = %d", badResponse.StatusCode)
	}
	if contentType := badResponse.Header.Get("Content-Type"); contentType != "application/problem+json" {
		t.Fatalf("bad credential content type = %q", contentType)
	}
}

func TestSessionMiddlewareSkipsBlockhashPrefetchOnVerifyPath(t *testing.T) {
	fake := &countingBlockhashRPC{FakeRPC: testutil.NewFakeRPC()}
	session := newTestSession(t, func(o *SessionOptions) { o.RPC = fake })
	handler := SessionMiddleware(session, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Verify path: a valid credential never triggers the prefetch.
	challenge, err := session.Challenge(context.Background(), SessionChallengeOptions{})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	calls := fake.calls()
	signer := newTestVoucherSigner(t)
	payerKey := testutil.NewPrivateKey()
	payer := payerKey.PublicKey()
	channel, _, err := paymentchannels.FindChannelPDAForProgram(
		payer,
		solana.MustPublicKeyFromBase58(session.recipient),
		solana.MustPublicKeyFromBase58(paycore.ResolveMint(session.currency, session.network)),
		solana.MustPublicKeyFromBase58(signer.Address()),
		7,
		42,
		paymentchannels.ProgramPubkey(),
	)
	if err != nil {
		t.Fatalf("derive channel fixture: %v", err)
	}
	channelID := channel.String()
	seedSessionAccountThroughSetter(t, fake, session, channelID, 1_000, payer.String(), signer.Address())
	payload := intents.OpenPayloadPush(channelID, "1000", signer.Address(), confirmedSignature(0x88))
	registerSignatureOnlyOpenTransaction(t, session, &payload, payerKey, 1_000)
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), intents.NewOpenAction(payload))
	if err != nil {
		t.Fatalf("NewPaymentCredential: %v", err)
	}
	authorization, err := core.FormatAuthorization(credential)
	if err != nil {
		t.Fatalf("FormatAuthorization: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(core.AuthorizationHeader, authorization)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("verify path status = %d", recorder.Code)
	}
	if fake.calls() != calls {
		t.Fatalf("verify path fetched a blockhash: %d -> %d", calls, fake.calls())
	}

	// Challenge path fetches exactly once.
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("challenge path status = %d", recorder.Code)
	}
	if fake.calls() != calls+1 {
		t.Fatalf("challenge path blockhash calls = %d, want %d", fake.calls(), calls+1)
	}
}

// countingBlockhashRPC counts GetLatestBlockhash calls on top of FakeRPC.
// The counter is atomic because the idle-close watchdog reads blockhashes
// from its own goroutine.
type countingBlockhashRPC struct {
	// FakeRPC handles every RPC call; GetLatestBlockhash is counted first.
	*testutil.FakeRPC

	// blockhashCalls counts GetLatestBlockhash invocations; atomic because
	// the idle-close watchdog fetches blockhashes from its own goroutine.
	blockhashCalls atomic.Int64
}

// blockingConfirmationRPC pauses the first settlement confirmation poll so a
// competing close path can attempt to claim the same channel deterministically.
type blockingConfirmationRPC struct {
	*testutil.FakeRPC
	statusEntered chan struct{}
	releaseStatus chan struct{}
	block         atomic.Bool
	statusCalls   atomic.Int64
}

type definiteFailureRPC struct {
	*testutil.FakeRPC
	fail atomic.Bool
}

func (d *definiteFailureRPC) GetSignatureStatuses(ctx context.Context, searchHistory bool, signatures ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	if d.fail.Load() {
		return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{{
			Err: map[string]any{"InstructionError": []any{0, "Custom"}},
		}}}, nil
	}
	return d.FakeRPC.GetSignatureStatuses(ctx, searchHistory, signatures...)
}

type cancelOnConfirmationRPC struct {
	*testutil.FakeRPC
	cancel context.CancelFunc
	armed  atomic.Bool
}

func (c *cancelOnConfirmationRPC) GetSignatureStatuses(ctx context.Context, searchHistory bool, signatures ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	if c.armed.Load() {
		c.cancel()
	}
	return c.FakeRPC.GetSignatureStatuses(ctx, searchHistory, signatures...)
}

func (b *blockingConfirmationRPC) GetSignatureStatuses(ctx context.Context, searchHistory bool, signatures ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	if !b.block.Load() {
		return b.FakeRPC.GetSignatureStatuses(ctx, searchHistory, signatures...)
	}
	b.statusCalls.Add(1)
	select {
	case b.statusEntered <- struct{}{}:
	default:
	}
	select {
	case <-b.releaseStatus:
		return b.FakeRPC.GetSignatureStatuses(ctx, searchHistory, signatures...)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// calls returns the GetLatestBlockhash call count.
func (c *countingBlockhashRPC) calls() int64 { return c.blockhashCalls.Load() }

func (c *countingBlockhashRPC) GetLatestBlockhash(ctx context.Context, commitment rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	c.blockhashCalls.Add(1)
	return c.FakeRPC.GetLatestBlockhash(ctx, commitment)
}

// ── idle-close lifecycle ──

func TestSessionIdleCloseSettlesOnChain(t *testing.T) {
	fake := testutil.NewFakeRPC()
	merchant := testutil.NewPrivateKey()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.Signer = merchant
		o.CloseDelay = 25 * time.Millisecond
	})
	signer, channelID := openTrustedChannel(t, session, 1_000)
	if _, err := submitMethodVoucher(t, session, signer, channelID, 300); err != nil {
		t.Fatalf("voucher: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		state := mustGetChannel(t, session, channelID)
		if state != nil && state.Sealed && state.SettledSignature != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("idle close never settled; state = %+v", state)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(fake.Sent) != 1 {
		t.Fatalf("settlement broadcasts = %d, want 1", len(fake.Sent))
	}
}

func TestExplicitCloseRacingIdleCloseReusesSettlementWire(t *testing.T) {
	baseRPC := testutil.NewFakeRPC()
	fake := &blockingConfirmationRPC{
		FakeRPC:       baseRPC,
		statusEntered: make(chan struct{}, 1),
		releaseStatus: make(chan struct{}),
	}
	merchant := testutil.NewPrivateKey()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = baseRPC
		o.Signer = merchant
	})
	_, channelID := openTrustedChannel(t, session, 1_000)
	session.rpc = fake
	fake.block.Store(true)

	explicitDone := make(chan error, 1)
	go func() {
		_, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID}))
		explicitDone <- err
	}()

	select {
	case <-fake.statusEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("explicit close never reached confirmation")
	}

	// The idle path observes the persisted signature and joins confirmation
	// without broadcasting a competing transaction.
	idleDone := make(chan struct{})
	go func() {
		session.closeOnIdle(channelID)
		close(idleDone)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for fake.statusCalls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("idle close never joined pending confirmation")
		}
		time.Sleep(time.Millisecond)
	}
	if len(fake.Sent) != 2 {
		t.Fatalf("idempotent settlement submissions while first close is in flight = %d, want 2", len(fake.Sent))
	}
	close(fake.releaseStatus)
	<-idleDone
	if err := <-explicitDone; err != nil {
		t.Fatalf("explicit close: %v", err)
	}

	state := mustGetChannel(t, session, channelID)
	if !state.Sealed || state.Settling || state.SettledSignature == nil {
		t.Fatalf("state after winning settle = %+v", state)
	}
}

func TestSettlementConfirmationFailureReleasesClaimForRetry(t *testing.T) {
	baseRPC := testutil.NewFakeRPC()
	merchant := testutil.NewPrivateKey()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = baseRPC
		o.Signer = merchant
	})
	_, channelID := openTrustedChannel(t, session, 1_000)
	session.rpc = &failingStatusRPC{FakeRPC: baseRPC}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := session.closeAndSettleChannel(ctx, channelID); err == nil ||
		!strings.Contains(err.Error(), "confirm settlement transaction") {
		t.Fatalf("confirmation failure = %v", err)
	}
	state := mustGetChannel(t, session, channelID)
	if state.Sealed || !state.Settling || state.SettledSignature == nil || state.SettlementWire == "" {
		t.Fatalf("failed confirmation left channel non-retryable: %+v", state)
	}
	pendingSignature := *state.SettledSignature

	healthyRPC := testutil.NewFakeRPC()
	session.rpc = healthyRPC
	settled, err := session.closeAndSettleChannel(context.Background(), channelID)
	if err != nil {
		t.Fatalf("settlement retry: %v", err)
	}
	if settled != pendingSignature || len(healthyRPC.Sent) != 1 {
		t.Fatalf("settlement retry = %q with %d broadcasts", settled, len(healthyRPC.Sent))
	}
	state = mustGetChannel(t, session, channelID)
	if !state.Sealed || state.Settling || state.SettledSignature == nil {
		t.Fatalf("state after settlement retry = %+v", state)
	}
}

func TestDefiniteSettlementFailureClearsSignatureForRetry(t *testing.T) {
	baseRPC := testutil.NewFakeRPC()
	rpcClient := &definiteFailureRPC{FakeRPC: baseRPC}
	merchant := testutil.NewPrivateKey()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = baseRPC
		o.Signer = merchant
	})
	_, channelID := openTrustedChannel(t, session, 1_000)
	session.rpc = rpcClient
	rpcClient.fail.Store(true)

	if _, err := session.closeAndSettleChannel(context.Background(), channelID); err == nil ||
		!strings.Contains(err.Error(), "failed on-chain") {
		t.Fatalf("definite settlement failure = %v", err)
	}
	state := mustGetChannel(t, session, channelID)
	if state.Sealed || state.Settling || state.SettledSignature != nil || state.SettlementWire != "" ||
		state.SettlementClaimOwner != "" || state.SettlementClaimedAt != 0 {
		t.Fatalf("definite failure did not clear settlement state: %+v", state)
	}
	if len(baseRPC.Sent) != 1 {
		t.Fatalf("broadcasts after definite failure = %d, want 1", len(baseRPC.Sent))
	}

	rpcClient.fail.Store(false)
	if _, err := session.closeAndSettleChannel(context.Background(), channelID); err != nil {
		t.Fatalf("retry after definite failure: %v", err)
	}
	if len(baseRPC.Sent) != 2 {
		t.Fatalf("broadcasts after safe retry = %d, want 2", len(baseRPC.Sent))
	}
}

func TestConfirmedSettlementReconcilesAfterRequestCancellation(t *testing.T) {
	baseRPC := testutil.NewFakeRPC()
	_, stores := newSharedJSONChannelStores(1)
	merchant := testutil.NewPrivateKey()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = baseRPC
		o.Signer = merchant
		o.Store = stores[0]
	})
	_, channelID := openTrustedChannel(t, session, 1_000)
	ctx, cancel := context.WithCancel(context.Background())
	rpcClient := &cancelOnConfirmationRPC{FakeRPC: baseRPC, cancel: cancel}
	rpcClient.armed.Store(true)
	session.rpc = rpcClient

	settled, err := session.closeAndSettleChannel(ctx, channelID)
	if err != nil {
		t.Fatalf("settlement after confirmation-side cancellation: %v", err)
	}
	if settled == "" || ctx.Err() == nil {
		t.Fatalf("settlement=%q context error=%v", settled, ctx.Err())
	}
	state := mustGetChannel(t, session, channelID)
	if !state.Sealed || state.Settling || state.SettledSignature == nil || *state.SettledSignature != settled || state.SettlementWire != "" {
		t.Fatalf("confirmed settlement was not reconciled: %+v", state)
	}
}

func TestSessionIdleCloseWithoutSignerStillClosesOffChain(t *testing.T) {
	fake := testutil.NewFakeRPC()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.CloseDelay = 10 * time.Millisecond
	})
	_, channelID := openTrustedChannel(t, session, 1_000)

	time.Sleep(80 * time.Millisecond)
	state := mustGetChannel(t, session, channelID)
	if state.CloseRequestedAt == nil || state.Sealed || len(fake.Sent) != 0 {
		t.Fatalf("idle close without signer state=%+v sends=%d", state, len(fake.Sent))
	}
}
