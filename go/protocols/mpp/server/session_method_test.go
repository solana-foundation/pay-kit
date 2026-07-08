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

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

const sessionMethodSecret = "session-method-secret"

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

// openTrustedChannel opens a transactionless push channel through the
// credential layer and returns the voucher signer plus channel id. The open
// signature is a valid base58 signature so the helper also works on sessions
// with an RPC client configured (the fake RPC confirms unknown signatures).
func openTrustedChannel(t *testing.T, session *Session, deposit uint64) (testVoucherSigner, string) {
	t.Helper()
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	openSessionChannel(t, session, channelID, deposit, signer.Address(), confirmedSignature(0x99))
	return signer, channelID
}

func openSessionChannel(t *testing.T, session *Session, channelID string, deposit uint64, authorizedSigner, signature string) core.Receipt {
	t.Helper()
	payload := intents.OpenPayloadPush(channelID, fmt.Sprintf("%d", deposit), authorizedSigner, signature)
	// Record a channel payer (the distribute refund destination, which the
	// program pins to channel.payer) so the bare push open can later settle;
	// without it the settle path now refuses rather than refunding the merchant.
	payer := solana.NewWallet().PublicKey().String()
	payload.Payer = &payer
	receipt, err := verifySessionAction(t, session, intents.NewOpenAction(payload))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return receipt
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
}

func TestNewSessionDefaults(t *testing.T) {
	session := newTestSession(t, func(o *SessionOptions) {
		o.Currency = ""
		o.Decimals = 0
		o.Network = ""
		o.OpenTxSubmitter = ""
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

	receipt := openSessionChannel(t, session, channelID, 1_000_000, signer.Address(), "sig-1")
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
	openSessionChannel(t, session, channelID, 1_000, signer.Address(), "open-sig")
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

	// Finalized channel rejects replays.
	if _, err := session.Core().Store().MarkFinalized(context.Background(), channelID); err != nil {
		t.Fatalf("MarkFinalized: %v", err)
	}
	replay := intents.OpenPayloadPush(channelID, "1000", signer.Address(), "open-sig")
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(replay)); err == nil ||
		!strings.Contains(err.Error(), "finalized") {
		t.Fatalf("finalized replay error = %v", err)
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
	receipt := openSessionChannel(t, session, channelID, 1_000, signer.Address(), okSig)
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

	// Finalized blocks top-ups.
	_, finalizedChannel := openTrustedChannel(t, session, 5_000)
	if _, err := session.Core().Store().MarkFinalized(context.Background(), finalizedChannel); err != nil {
		t.Fatalf("MarkFinalized: %v", err)
	}
	if _, err := verifySessionAction(t, session, intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID: finalizedChannel, NewDeposit: "9000", Signature: "sig",
	})); err == nil || !strings.Contains(err.Error(), "finalized") {
		t.Fatalf("finalized error = %v", err)
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
	openSessionChannel(t, session, channelID, 1_000, signer.Address(), openSig)

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
	if state.CloseRequestedAt == nil || state.Finalized {
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

	// First close: settlement broadcast fails; close stays pending and
	// re-drivable.
	fake.SendErr = fmt.Errorf("blockhash not found")
	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID})); err == nil ||
		!strings.Contains(err.Error(), "blockhash not found") {
		t.Fatalf("settlement failure error = %v", err)
	}
	state := mustGetChannel(t, session, channelID)
	if state.CloseRequestedAt == nil || state.Finalized || state.SettledSignature != nil {
		t.Fatalf("state after failed settle = %+v", state)
	}

	// Retry succeeds and finalizes the channel.
	fake.SendErr = nil
	receipt, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID}))
	if err != nil {
		t.Fatalf("close retry: %v", err)
	}
	if len(fake.Sent) != 1 {
		t.Fatalf("settlement broadcasts = %d, want 1", len(fake.Sent))
	}
	state = mustGetChannel(t, session, channelID)
	if !state.Finalized || state.SettledSignature == nil {
		t.Fatalf("state after settle = %+v", state)
	}
	if receipt.Reference != *state.SettledSignature {
		t.Fatalf("reference = %q, want settled signature %q", receipt.Reference, *state.SettledSignature)
	}

	// A third close on the finalized channel rejects.
	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID})); err == nil ||
		!strings.Contains(err.Error(), "finalized") {
		t.Fatalf("third close error = %v", err)
	}
}

func TestSessionCloseWithoutSignerDoesNotSettle(t *testing.T) {
	fake := testutil.NewFakeRPC()
	session := newTestSession(t, func(o *SessionOptions) { o.RPC = fake })
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	openSessionChannel(t, session, channelID, 1_000, signer.Address(), confirmedSignature(0x77))

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
	session := newTestSession(t, func(o *SessionOptions) {
		o.Recipient = fixture.payee.String()
		o.Operator = operator.PublicKey().String()
		o.OpenTxSubmitter = OpenTxSubmitterServer
		o.PaymentChannelPayerSigner = operator
		o.RPC = fake
	})

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
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), intents.NewOpenAction(
		intents.OpenPayloadPush(solana.NewWallet().PublicKey().String(), "1000", signer.Address(), confirmedSignature(0x88))))
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
		if state != nil && state.Finalized && state.SettledSignature != nil {
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

func TestSessionIdleCloseWithoutSignerIsInert(t *testing.T) {
	fake := testutil.NewFakeRPC()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.CloseDelay = 10 * time.Millisecond
	})
	_, channelID := openTrustedChannel(t, session, 1_000)

	time.Sleep(80 * time.Millisecond)
	state := mustGetChannel(t, session, channelID)
	if state.Finalized || len(fake.Sent) != 0 {
		t.Fatalf("idle close ran without a signer: state=%+v sends=%d", state, len(fake.Sent))
	}
}
