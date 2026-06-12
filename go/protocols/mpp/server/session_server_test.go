package server

// Off-chain session handler coverage: open, voucher verification, top-up,
// delivery begin/commit, close, and challenge-request building.

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

const sessionTestRecipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"

func sessionTestConfig() SessionConfig {
	return SessionConfig{
		Operator:  sessionTestRecipient,
		Recipient: sessionTestRecipient,
		MaxCap:    10_000_000,
		Currency:  "USDC",
		Decimals:  6,
		Network:   "localnet",
		Modes:     []intents.SessionMode{intents.SessionModePush},
	}
}

func newSessionTestServer(config SessionConfig) *SessionServer {
	return NewSessionServer(config, NewMemoryChannelStore())
}

func sessionOpenPayload(channelID string, deposit uint64, signer string) *intents.OpenPayload {
	payload := intents.OpenPayloadPush(channelID, strconv.FormatUint(deposit, 10), signer, "dummy_tx_sig")
	return &payload
}

// openTestChannel opens a channel signed by a fresh keypair and returns the
// signer plus the channel id (a valid base58 32-byte key so vouchers can be
// signed against it).
func openTestChannel(t *testing.T, server *SessionServer, deposit uint64) (testVoucherSigner, string) {
	t.Helper()
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	if _, err := server.ProcessOpen(context.Background(), sessionOpenPayload(channelID, deposit, signer.Address())); err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}
	return signer, channelID
}

// submitVoucher signs and submits a voucher for cumulative, far in the future.
func submitVoucher(t *testing.T, server *SessionServer, signer testVoucherSigner, channelID string, cumulative uint64) (uint64, error) {
	t.Helper()
	voucher := signer.SignVoucher(t, channelID, cumulative, farFuture())
	return server.VerifyVoucher(context.Background(), &intents.VoucherPayload{Voucher: voucher})
}

// ── BuildChallengeRequest ──

func TestBuildChallengeRequestCanonicalShape(t *testing.T) {
	config := sessionTestConfig()
	config.MinVoucherDelta = 0
	server := newSessionTestServer(config)

	request := server.BuildChallengeRequest(1_000_000)
	if request.Cap != "1000000" {
		t.Fatalf("cap = %q, want 1000000", request.Cap)
	}
	if request.Currency != "USDC" || request.Operator != sessionTestRecipient || request.Recipient != sessionTestRecipient {
		t.Fatalf("unexpected request fields: %+v", request)
	}
	if request.Decimals == nil || *request.Decimals != 6 {
		t.Fatalf("decimals = %v, want 6", request.Decimals)
	}
	if request.Network == nil || *request.Network != "localnet" {
		t.Fatalf("network = %v, want localnet", request.Network)
	}
	// minVoucherDelta omitted when zero, modes omitted when push-only,
	// pullVoucherStrategy omitted when pull is not offered.
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	for _, absent := range []string{"minVoucherDelta", "modes", "pullVoucherStrategy", "recentBlockhash"} {
		if strings.Contains(string(raw), absent) {
			t.Fatalf("challenge JSON unexpectedly contains %q: %s", absent, raw)
		}
	}
}

func TestBuildChallengeRequestClampsCapToMax(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	request := server.BuildChallengeRequest(99_000_000)
	if request.Cap != "10000000" {
		t.Fatalf("cap = %q, want clamped 10000000", request.Cap)
	}
}

func TestBuildChallengeRequestIncludesMinVoucherDeltaWhenPositive(t *testing.T) {
	config := sessionTestConfig()
	config.MinVoucherDelta = 250
	server := newSessionTestServer(config)
	request := server.BuildChallengeRequest(1_000)
	if request.MinVoucherDelta == nil || *request.MinVoucherDelta != "250" {
		t.Fatalf("minVoucherDelta = %v, want 250", request.MinVoucherDelta)
	}
}

func TestBuildChallengeRequestAdvertisesPullModeAndStrategy(t *testing.T) {
	strategy := intents.SessionPullVoucherStrategyClientVoucher
	config := sessionTestConfig()
	config.Modes = []intents.SessionMode{intents.SessionModePush, intents.SessionModePull}
	config.PullVoucherStrategy = &strategy
	config.Splits = []Split{{Recipient: solana.MustPublicKeyFromBase58(sessionTestRecipient), BPS: 10}}
	server := newSessionTestServer(config)

	request := server.BuildChallengeRequest(1_000)
	if len(request.Modes) != 2 {
		t.Fatalf("modes = %v, want push+pull", request.Modes)
	}
	if request.PullVoucherStrategy == nil || *request.PullVoucherStrategy != strategy {
		t.Fatalf("pullVoucherStrategy = %v, want clientVoucher", request.PullVoucherStrategy)
	}
	if len(request.Splits) != 1 || request.Splits[0].Recipient != sessionTestRecipient || request.Splits[0].BPS != 10 {
		t.Fatalf("splits = %+v", request.Splits)
	}
}

// ── ProcessOpen ──

func TestProcessOpenStoresState(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	state, err := server.ProcessOpen(context.Background(), sessionOpenPayload("chan1", 1_000_000, "signer1"))
	if err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}
	if state.Deposit != 1_000_000 || state.Cumulative != 0 || state.Finalized {
		t.Fatalf("state = %+v", state)
	}
	if state.AuthorizedSigner != "signer1" {
		t.Fatalf("authorizedSigner = %q, want signer1", state.AuthorizedSigner)
	}
}

func TestProcessOpenZeroDepositRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	if _, err := server.ProcessOpen(context.Background(), sessionOpenPayload("chan1", 0, "signer1")); err == nil {
		t.Fatal("expected zero-deposit rejection")
	}
}

func TestProcessOpenExceedsCapRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	if _, err := server.ProcessOpen(context.Background(), sessionOpenPayload("chan1", 20_000_000, "signer1")); err == nil {
		t.Fatal("expected over-cap rejection")
	}
}

func TestProcessOpenRejectsUnadvertisedPullMode(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	payload := intents.OpenPayloadPaymentChannelWithMode(
		intents.SessionModePull,
		"chan1", "1000000", "payer", sessionTestRecipient, "mint",
		1, 900, "signer1", "pending",
	)
	_, err := server.ProcessOpen(context.Background(), &payload)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err = %v, want mode-not-supported", err)
	}
}

func TestProcessOpenAcceptsAdvertisedPullClientVoucherChannel(t *testing.T) {
	strategy := intents.SessionPullVoucherStrategyClientVoucher
	config := sessionTestConfig()
	config.Modes = []intents.SessionMode{intents.SessionModePull}
	config.PullVoucherStrategy = &strategy
	server := newSessionTestServer(config)
	payload := intents.OpenPayloadPaymentChannelWithMode(
		intents.SessionModePull,
		"chan1", "1000000", "payer", sessionTestRecipient, "mint",
		1, 900, "signer1", "pending",
	)
	state, err := server.ProcessOpen(context.Background(), &payload)
	if err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}
	if state.ChannelID != "chan1" || state.Deposit != 1_000_000 {
		t.Fatalf("state = %+v", state)
	}
	if state.Operator == nil || *state.Operator != "payer" {
		t.Fatalf("operator = %v, want payer fallback", state.Operator)
	}
}

func TestProcessOpenPrefersChannelIDOverTokenAccount(t *testing.T) {
	strategy := intents.SessionPullVoucherStrategyClientVoucher
	config := sessionTestConfig()
	config.Modes = []intents.SessionMode{intents.SessionModePull}
	config.PullVoucherStrategy = &strategy
	server := newSessionTestServer(config)

	payload := intents.OpenPayloadPull("token-acct", "1000", "owner", "signer1", "sig")
	channelID := "delegation-pda"
	payload.ChannelID = &channelID

	state, err := server.ProcessOpen(context.Background(), &payload)
	if err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}
	if state.ChannelID != "delegation-pda" {
		t.Fatalf("session key = %q, want channelId to win over tokenAccount", state.ChannelID)
	}
	if state.Operator == nil || *state.Operator != "owner" {
		t.Fatalf("operator = %v, want owner", state.Operator)
	}
}

func TestProcessOpenReplayPreservesWatermark(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	if _, err := submitVoucher(t, server, signer, channelID, 250); err != nil {
		t.Fatalf("voucher: %v", err)
	}

	replayed, err := server.ProcessOpen(context.Background(), sessionOpenPayload(channelID, 1_000_000, signer.Address()))
	if err != nil {
		t.Fatalf("replayed open: %v", err)
	}
	if replayed.Cumulative != 250 {
		t.Fatalf("replayed open reset the watermark: cumulative = %d, want 250", replayed.Cumulative)
	}
	if replayed.HighestVoucherSignature == nil {
		t.Fatal("replayed open erased the highest voucher signature")
	}
}

func TestProcessOpenReplayWithDifferentSignerRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000_000)

	other := newTestVoucherSigner(t)
	_, err := server.ProcessOpen(context.Background(), sessionOpenPayload(channelID, 1_000_000, other.Address()))
	if err == nil || !strings.Contains(err.Error(), "different authorized signer") {
		t.Fatalf("err = %v, want different-authorized-signer rejection", err)
	}
}

func TestProcessOpenReplayOnFinalizedChannelRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	if err := server.MarkFinalized(context.Background(), channelID); err != nil {
		t.Fatalf("MarkFinalized: %v", err)
	}
	_, err := server.ProcessOpen(context.Background(), sessionOpenPayload(channelID, 1_000_000, signer.Address()))
	if err == nil || !strings.Contains(err.Error(), "finalized") {
		t.Fatalf("err = %v, want finalized rejection", err)
	}
}

func TestProcessOpenInvokesVerifyOpenTxSeamForPush(t *testing.T) {
	verified := 0
	config := sessionTestConfig()
	config.VerifyOpenTx = func(_ context.Context, payload *intents.OpenPayload) error {
		verified++
		if payload.Signature != "dummy_tx_sig" {
			t.Fatalf("verifier got signature %q", payload.Signature)
		}
		return nil
	}
	server := newSessionTestServer(config)
	if _, err := server.ProcessOpen(context.Background(), sessionOpenPayload("chan1", 1_000, "signer1")); err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}
	if verified != 1 {
		t.Fatalf("VerifyOpenTx invoked %d times, want 1", verified)
	}
}

func TestProcessOpenVerifyOpenTxErrorRejectsWithoutPersisting(t *testing.T) {
	wantErr := errors.New("tx not found")
	config := sessionTestConfig()
	config.VerifyOpenTx = func(context.Context, *intents.OpenPayload) error { return wantErr }
	server := newSessionTestServer(config)

	_, err := server.ProcessOpen(context.Background(), sessionOpenPayload("chan1", 1_000, "signer1"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	state, err := server.Store().GetChannel(context.Background(), "chan1")
	if err != nil {
		t.Fatalf("GetChannel: %v", err)
	}
	if state != nil {
		t.Fatalf("channel persisted despite failed verification: %+v", state)
	}
}

func TestProcessOpenSkipsVerifyOpenTxForPull(t *testing.T) {
	strategy := intents.SessionPullVoucherStrategyClientVoucher
	config := sessionTestConfig()
	config.Modes = []intents.SessionMode{intents.SessionModePull}
	config.PullVoucherStrategy = &strategy
	config.VerifyOpenTx = func(context.Context, *intents.OpenPayload) error {
		t.Fatal("VerifyOpenTx must not run for pull opens")
		return nil
	}
	server := newSessionTestServer(config)

	payload := intents.OpenPayloadPull("token-acct", "1000", "owner", "signer1", "sig")
	if _, err := server.ProcessOpen(context.Background(), &payload); err != nil {
		t.Fatalf("ProcessOpen: %v", err)
	}
}

// ── VerifyVoucher ──

func TestVerifyVoucherAdvancesWatermark(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	cumulative, err := submitVoucher(t, server, signer, channelID, 100)
	if err != nil {
		t.Fatalf("VerifyVoucher: %v", err)
	}
	if cumulative != 100 {
		t.Fatalf("cumulative = %d, want 100", cumulative)
	}

	cumulative, err = submitVoucher(t, server, signer, channelID, 300)
	if err != nil {
		t.Fatalf("VerifyVoucher: %v", err)
	}
	if cumulative != 300 {
		t.Fatalf("cumulative = %d, want 300", cumulative)
	}

	state, err := server.Store().GetChannel(context.Background(), channelID)
	if err != nil || state == nil {
		t.Fatalf("GetChannel: state=%v err=%v", state, err)
	}
	if state.Cumulative != 300 || state.HighestVoucherSignature == nil || state.HighestVoucherExpiresAt == nil {
		t.Fatalf("state = %+v", state)
	}
}

func TestVerifyVoucherUnknownChannelRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer := newTestVoucherSigner(t)
	voucher := signer.SignVoucher(t, testVoucherChannelID, 100, farFuture())
	_, err := server.VerifyVoucher(context.Background(), &intents.VoucherPayload{Voucher: voucher})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want channel-not-found", err)
	}
}

func TestVerifyVoucherNonMonotonicRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	if _, err := submitVoucher(t, server, signer, channelID, 200); err != nil {
		t.Fatalf("voucher: %v", err)
	}
	// Decreasing cumulative.
	_, err := submitVoucher(t, server, signer, channelID, 150)
	if err == nil || !strings.Contains(err.Error(), "must exceed watermark") {
		t.Fatalf("err = %v, want non-monotonic rejection", err)
	}
	// Equal cumulative with a different signature (different expiry) is not a
	// replay and must also be rejected as non-monotonic.
	different := signer.SignVoucher(t, channelID, 200, farFuture()+60)
	_, err = server.VerifyVoucher(context.Background(), &intents.VoucherPayload{Voucher: different})
	if err == nil || !strings.Contains(err.Error(), "must exceed watermark") {
		t.Fatalf("err = %v, want non-monotonic rejection for equal cumulative", err)
	}
}

func TestVerifyVoucherIdempotentReplayReturnsSameCumulative(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	voucher := signer.SignVoucher(t, channelID, 150, farFuture())
	if _, err := server.VerifyVoucher(context.Background(), &intents.VoucherPayload{Voucher: voucher}); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	cumulative, err := server.VerifyVoucher(context.Background(), &intents.VoucherPayload{Voucher: voucher})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if cumulative != 150 {
		t.Fatalf("replay cumulative = %d, want 150", cumulative)
	}
}

func TestVerifyVoucherRespectsMinVoucherDelta(t *testing.T) {
	config := sessionTestConfig()
	config.MinVoucherDelta = 100
	server := newSessionTestServer(config)
	signer, channelID := openTestChannel(t, server, 1_000_000)

	if _, err := submitVoucher(t, server, signer, channelID, 50); err == nil {
		t.Fatal("expected below-min-delta rejection")
	}
	if _, err := submitVoucher(t, server, signer, channelID, 100); err != nil {
		t.Fatalf("delta == min must pass: %v", err)
	}
}

func TestVerifyVoucherAcceptsLegacyCumulativeAlias(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	signed := signer.SignVoucher(t, channelID, 400, farFuture())
	// Re-encode the voucher payload with the legacy "cumulative" wire alias.
	wire := []byte(`{"voucher":{"data":{"channelId":"` + channelID +
		`","cumulative":"400","expiresAt":` + strconv.FormatInt(signed.Data.ExpiresAt, 10) +
		`},"signature":"` + signed.Signature + `"}}`)
	var payload intents.VoucherPayload
	if err := json.Unmarshal(wire, &payload); err != nil {
		t.Fatalf("decode aliased payload: %v", err)
	}

	cumulative, err := server.VerifyVoucher(context.Background(), &payload)
	if err != nil {
		t.Fatalf("VerifyVoucher: %v", err)
	}
	if cumulative != 400 {
		t.Fatalf("cumulative = %d, want 400", cumulative)
	}
}

// ── ProcessTopUp ──

func TestProcessTopUpRaisesDeposit(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000_000)

	state, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{
		ChannelID:  channelID,
		NewDeposit: "2000000",
		Signature:  "topup_sig",
	})
	if err != nil {
		t.Fatalf("ProcessTopUp: %v", err)
	}
	if state.Deposit != 2_000_000 {
		t.Fatalf("deposit = %d, want 2000000", state.Deposit)
	}
}

func TestProcessTopUpRejectsNonIncreasingDeposit(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000_000)

	_, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "1000000", Signature: "sig",
	})
	if err == nil || !strings.Contains(err.Error(), "must exceed current deposit") {
		t.Fatalf("err = %v, want non-increasing rejection", err)
	}
}

func TestProcessTopUpRejectsOverMaxCap(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000_000)

	_, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "20000000", Signature: "sig",
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds max cap") {
		t.Fatalf("err = %v, want over-cap rejection", err)
	}
}

func TestProcessTopUpRejectsWhenFinalizedOrClosePending(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000_000)
	if _, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID}); err != nil {
		t.Fatalf("ProcessClose: %v", err)
	}
	_, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "2000000", Signature: "sig",
	})
	if err == nil || !strings.Contains(err.Error(), "close is pending") {
		t.Fatalf("err = %v, want close-pending rejection", err)
	}

	server2 := newSessionTestServer(sessionTestConfig())
	_, channelID2 := openTestChannel(t, server2, 1_000_000)
	if err := server2.MarkFinalized(context.Background(), channelID2); err != nil {
		t.Fatalf("MarkFinalized: %v", err)
	}
	_, err = server2.ProcessTopUp(context.Background(), &intents.TopUpPayload{
		ChannelID: channelID2, NewDeposit: "2000000", Signature: "sig",
	})
	if err == nil || !strings.Contains(err.Error(), "finalized") {
		t.Fatalf("err = %v, want finalized rejection", err)
	}
}

func TestProcessTopUpInvokesVerifyTopUpTxSeam(t *testing.T) {
	wantErr := errors.New("topup tx unknown")
	config := sessionTestConfig()
	config.VerifyTopUpTx = func(_ context.Context, payload *intents.TopUpPayload) error {
		if payload.Signature != "topup_sig" {
			t.Fatalf("verifier got signature %q", payload.Signature)
		}
		return wantErr
	}
	server := newSessionTestServer(config)
	_, channelID := openTestChannel(t, server, 1_000_000)

	_, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "2000000", Signature: "topup_sig",
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	state, getErr := server.Store().GetChannel(context.Background(), channelID)
	if getErr != nil || state == nil {
		t.Fatalf("GetChannel: state=%v err=%v", state, getErr)
	}
	if state.Deposit != 1_000_000 {
		t.Fatalf("deposit raised despite failed verification: %d", state.Deposit)
	}
}

func TestVoucherAcceptedAfterTopUpRaisesDeposit(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000)

	if _, err := submitVoucher(t, server, signer, channelID, 2_000); err == nil {
		t.Fatal("expected exceeds-deposit rejection before top-up")
	}
	if _, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{
		ChannelID: channelID, NewDeposit: "5000", Signature: "sig",
	}); err != nil {
		t.Fatalf("ProcessTopUp: %v", err)
	}
	if _, err := submitVoucher(t, server, signer, channelID, 2_000); err != nil {
		t.Fatalf("voucher after top-up: %v", err)
	}
}

// ── BeginDelivery ──

func TestBeginDeliveryAssignsSequenceAndDefaultDeliveryID(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000_000)

	first, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 100})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	if first.DeliveryID != channelID+":1" || first.Sequence != 1 {
		t.Fatalf("directive = %+v, want sequence 1 and default id", first)
	}
	if first.Amount != "100" || first.Currency != "USDC" || first.SessionID != channelID {
		t.Fatalf("directive = %+v", first)
	}
	if first.ExpiresAt != intents.DefaultSessionExpiresAt {
		t.Fatalf("expiresAt = %d, want default %d", first.ExpiresAt, intents.DefaultSessionExpiresAt)
	}

	second, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 50})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	if second.DeliveryID != channelID+":2" || second.Sequence != 2 {
		t.Fatalf("directive = %+v, want sequence 2", second)
	}
}

func TestBeginDeliveryHonorsExplicitFields(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000_000)

	expiresAt := time.Now().Unix() + 60
	directive, err := server.BeginDelivery(context.Background(), DeliveryRequest{
		SessionID:  channelID,
		Amount:     100,
		DeliveryID: "custom-id",
		CommitURL:  "https://example.test/commit",
		Proof:      "proof-blob",
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	if directive.DeliveryID != "custom-id" || directive.ExpiresAt != expiresAt {
		t.Fatalf("directive = %+v", directive)
	}
	if directive.CommitURL == nil || *directive.CommitURL != "https://example.test/commit" {
		t.Fatalf("commitUrl = %v", directive.CommitURL)
	}
	if directive.Proof == nil || *directive.Proof != "proof-blob" {
		t.Fatalf("proof = %v", directive.Proof)
	}
}

func TestBeginDeliveryRejectsZeroAmountAndUnknownChannel(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	if _, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: "ghost", Amount: 0}); err == nil {
		t.Fatal("expected zero-amount rejection")
	}
	if _, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: "ghost", Amount: 5}); err == nil {
		t.Fatal("expected unknown-channel rejection")
	}
}

func TestBeginDeliveryRejectsDuplicateDeliveryID(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000_000)

	if _, err := server.BeginDelivery(context.Background(), DeliveryRequest{
		SessionID: channelID, Amount: 10, DeliveryID: "dup",
	}); err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	_, err := server.BeginDelivery(context.Background(), DeliveryRequest{
		SessionID: channelID, Amount: 10, DeliveryID: "dup",
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want duplicate rejection", err)
	}
}

func TestBeginDeliveryReservationMath(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000)

	// Advance the watermark to 400 so the reservation has to account for it.
	if _, err := submitVoucher(t, server, signer, channelID, 400); err != nil {
		t.Fatalf("voucher: %v", err)
	}
	// Reserve 500: cumulative 400 + pending 500 = 900 <= 1000.
	if _, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 500}); err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	// Reserve 100 more: 400 + 500 + 100 = 1000 <= 1000 (boundary holds).
	if _, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 100}); err != nil {
		t.Fatalf("boundary reservation: %v", err)
	}
	// One more unit must fail: 400 + 600 + 1 > 1000.
	_, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 1})
	if err == nil || !strings.Contains(err.Error(), "exceeds available deposit") {
		t.Fatalf("err = %v, want reservation overflow rejection", err)
	}
}

func TestBeginDeliveryRejectedWhenClosePending(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000_000)
	if _, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID}); err != nil {
		t.Fatalf("ProcessClose: %v", err)
	}
	_, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 5})
	if err == nil || !strings.Contains(err.Error(), "close is pending") {
		t.Fatalf("err = %v, want close-pending rejection", err)
	}
}

// ── ProcessCommit ──

func TestProcessCommitCommitsReservedDelivery(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	directive, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 100})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	voucher := signer.SignVoucher(t, channelID, 100, farFuture())
	receipt, err := server.ProcessCommit(context.Background(), &intents.CommitPayload{
		DeliveryID: directive.DeliveryID,
		Voucher:    voucher,
	})
	if err != nil {
		t.Fatalf("ProcessCommit: %v", err)
	}
	if receipt.Status != intents.CommitStatusCommitted || receipt.Amount != "100" || receipt.Cumulative != "100" {
		t.Fatalf("receipt = %+v", receipt)
	}

	state, err := server.Store().GetChannel(context.Background(), channelID)
	if err != nil || state == nil {
		t.Fatalf("GetChannel: state=%v err=%v", state, err)
	}
	if state.Cumulative != 100 || len(state.PendingDeliveries) != 0 || len(state.CommittedDeliveries) != 1 {
		t.Fatalf("state = %+v", state)
	}
}

func TestProcessCommitReplayReturnsCachedReceipt(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	directive, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 100})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	voucher := signer.SignVoucher(t, channelID, 100, farFuture())
	payload := &intents.CommitPayload{DeliveryID: directive.DeliveryID, Voucher: voucher}

	if _, err := server.ProcessCommit(context.Background(), payload); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	replay, err := server.ProcessCommit(context.Background(), payload)
	if err != nil {
		t.Fatalf("replayed commit: %v", err)
	}
	if replay.Status != intents.CommitStatusReplayed || replay.Amount != "100" || replay.Cumulative != "100" {
		t.Fatalf("replay receipt = %+v", replay)
	}
}

func TestProcessCommitReplayWithDifferentVoucherRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	directive, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 200})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	first := signer.SignVoucher(t, channelID, 100, farFuture())
	if _, err := server.ProcessCommit(context.Background(), &intents.CommitPayload{
		DeliveryID: directive.DeliveryID, Voucher: first,
	}); err != nil {
		t.Fatalf("first commit: %v", err)
	}

	different := signer.SignVoucher(t, channelID, 150, farFuture())
	_, err = server.ProcessCommit(context.Background(), &intents.CommitPayload{
		DeliveryID: directive.DeliveryID, Voucher: different,
	})
	if err == nil || !strings.Contains(err.Error(), "already committed with different voucher") {
		t.Fatalf("err = %v, want different-voucher rejection", err)
	}
}

func TestProcessCommitReplayReVerifiesSignature(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	directive, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 100})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	voucher := signer.SignVoucher(t, channelID, 100, farFuture())
	if _, err := server.ProcessCommit(context.Background(), &intents.CommitPayload{
		DeliveryID: directive.DeliveryID, Voucher: voucher,
	}); err != nil {
		t.Fatalf("first commit: %v", err)
	}

	// Same signature and cumulative, but tampered expiry: the replayed
	// voucher no longer verifies and must be rejected.
	tampered := voucher
	tampered.Data.ExpiresAt = voucher.Data.ExpiresAt + 1
	_, err = server.ProcessCommit(context.Background(), &intents.CommitPayload{
		DeliveryID: directive.DeliveryID, Voucher: tampered,
	})
	if err == nil {
		t.Fatal("expected replayed-commit signature re-verification failure")
	}
}

func TestProcessCommitUnknownDeliveryRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	voucher := signer.SignVoucher(t, channelID, 100, farFuture())
	_, err := server.ProcessCommit(context.Background(), &intents.CommitPayload{DeliveryID: "ghost", Voucher: voucher})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want delivery-not-found", err)
	}
}

func TestProcessCommitExpiredDirectiveRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	directive, err := server.BeginDelivery(context.Background(), DeliveryRequest{
		SessionID: channelID,
		Amount:    100,
		ExpiresAt: time.Now().Unix() - 10,
	})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	voucher := signer.SignVoucher(t, channelID, 100, farFuture())
	_, err = server.ProcessCommit(context.Background(), &intents.CommitPayload{
		DeliveryID: directive.DeliveryID, Voucher: voucher,
	})
	if err == nil || !strings.Contains(err.Error(), "has expired") {
		t.Fatalf("err = %v, want expired-directive rejection", err)
	}
}

func TestProcessCommitOverReservedAmountRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	directive, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 100})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	// The voucher claims 150 against a 100 reservation.
	voucher := signer.SignVoucher(t, channelID, 150, farFuture())
	_, err = server.ProcessCommit(context.Background(), &intents.CommitPayload{
		DeliveryID: directive.DeliveryID, Voucher: voucher,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds reserved amount") {
		t.Fatalf("err = %v, want over-reservation rejection", err)
	}
}

// ── ProcessClose ──

func TestProcessCloseFlipsClosePendingAndBlocksFurtherActivity(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	state, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID})
	if err != nil {
		t.Fatalf("ProcessClose: %v", err)
	}
	if state.CloseRequestedAt == nil {
		t.Fatal("closeRequestedAt not set")
	}

	if _, err := submitVoucher(t, server, signer, channelID, 100); err == nil {
		t.Fatal("expected voucher rejection after close")
	}
	if _, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 1}); err == nil {
		t.Fatal("expected delivery rejection after close")
	}
}

func TestProcessCloseDoubleCloseRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, channelID := openTestChannel(t, server, 1_000_000)

	if _, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID}); err != nil {
		t.Fatalf("ProcessClose: %v", err)
	}
	_, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID})
	if err == nil || !strings.Contains(err.Error(), "close already requested") {
		t.Fatalf("err = %v, want double-close rejection", err)
	}
}

func TestProcessCloseFinalVoucherAdvancesWatermark(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	if _, err := submitVoucher(t, server, signer, channelID, 100); err != nil {
		t.Fatalf("voucher: %v", err)
	}
	final := signer.SignVoucher(t, channelID, 500, farFuture())
	state, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID, Voucher: &final})
	if err != nil {
		t.Fatalf("ProcessClose: %v", err)
	}
	if state.Cumulative != 500 {
		t.Fatalf("cumulative = %d, want 500", state.Cumulative)
	}
	if state.HighestVoucherSignature == nil || *state.HighestVoucherSignature != final.Signature {
		t.Fatalf("highest signature not updated: %+v", state)
	}
}

func TestProcessCloseNonMonotonicFinalVoucherIsHardError(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	if _, err := submitVoucher(t, server, signer, channelID, 300); err != nil {
		t.Fatalf("voucher: %v", err)
	}
	stale := signer.SignVoucher(t, channelID, 200, farFuture())
	_, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID, Voucher: &stale})
	if err == nil || !strings.Contains(err.Error(), "must exceed watermark") {
		t.Fatalf("err = %v, want non-monotonic hard error", err)
	}

	// The failed close must not flip close-pending.
	state, getErr := server.Store().GetChannel(context.Background(), channelID)
	if getErr != nil || state == nil {
		t.Fatalf("GetChannel: state=%v err=%v", state, getErr)
	}
	if state.CloseRequestedAt != nil {
		t.Fatal("failed close flipped close-pending")
	}
	if state.Cumulative != 300 {
		t.Fatalf("cumulative = %d, want unchanged 300", state.Cumulative)
	}
}

func TestProcessCloseAcceptsReplayOfCurrentHighestVoucher(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	highest := signer.SignVoucher(t, channelID, 300, farFuture())
	if _, err := server.VerifyVoucher(context.Background(), &intents.VoucherPayload{Voucher: highest}); err != nil {
		t.Fatalf("voucher: %v", err)
	}
	state, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID, Voucher: &highest})
	if err != nil {
		t.Fatalf("ProcessClose with replayed highest voucher: %v", err)
	}
	if state.CloseRequestedAt == nil || state.Cumulative != 300 {
		t.Fatalf("state = %+v", state)
	}
}

func TestProcessCloseFinalVoucherExceedingDepositRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000)

	final := signer.SignVoucher(t, channelID, 2_000, farFuture())
	_, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: channelID, Voucher: &final})
	if err == nil || !strings.Contains(err.Error(), "exceeds deposit") {
		t.Fatalf("err = %v, want exceeds-deposit rejection", err)
	}
}

func TestProcessCloseUnknownChannelRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	_, err := server.ProcessClose(context.Background(), &intents.ClosePayload{ChannelID: "ghost"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want channel-not-found", err)
	}
}
