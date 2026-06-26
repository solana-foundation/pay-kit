package server

// Remaining behavioral gaps on the session method layer: external id
// propagation onto receipts, the pull-strategy handler guard, server-submit
// pre-verification failures, lifecycle teardown on close, and settlement
// store-write failures.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// failingUpdateStore wraps a ChannelStore and fails UpdateChannel once armed.
type failingUpdateStore struct {
	// ChannelStore is the wrapped store used while fail is unset.
	ChannelStore

	// fail, once armed, makes every UpdateChannel return a write error.
	fail bool
}

func (f *failingUpdateStore) UpdateChannel(ctx context.Context, channelID string, mutator ChannelMutator) (ChannelState, error) {
	if f.fail {
		return ChannelState{}, errors.New("store write rejected")
	}
	return f.ChannelStore.UpdateChannel(ctx, channelID, mutator)
}

func TestSessionReceiptCarriesExternalID(t *testing.T) {
	session := newTestSession(t, nil)
	challenge, err := session.Challenge(context.Background(), SessionChallengeOptions{ExternalID: "order-42"})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	signer := newTestVoucherSigner(t)
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), intents.NewOpenAction(
		intents.OpenPayloadPush(solana.NewWallet().PublicKey().String(), "1000", signer.Address(), "sig")))
	if err != nil {
		t.Fatalf("NewPaymentCredential: %v", err)
	}
	receipt, err := session.VerifyCredential(context.Background(), credential)
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}
	if receipt.ExternalID != "order-42" {
		t.Fatalf("receipt externalId = %q", receipt.ExternalID)
	}
}

func TestSessionOpenPullRequiresStrategyAtHandler(t *testing.T) {
	strategy := intents.SessionPullVoucherStrategyClientVoucher
	session := newTestSession(t, func(o *SessionOptions) {
		o.Modes = []intents.SessionMode{intents.SessionModePull}
		o.PullVoucherStrategy = &strategy
	})
	// Simulate a misconfigured lower-level core (the constructor enforces the
	// invariant, but the handler re-checks it defensively).
	session.core.config.PullVoucherStrategy = nil
	signer := newTestVoucherSigner(t)
	payload := intents.OpenPayloadPull(
		solana.NewWallet().PublicKey().String(), "1000",
		solana.NewWallet().PublicKey().String(), signer.Address(), "sig")
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(payload)); err == nil ||
		!strings.Contains(err.Error(), "requires a pullVoucherStrategy") {
		t.Fatalf("missing strategy error = %v", err)
	}
}

func TestSessionServerSubmitterPreVerificationFailure(t *testing.T) {
	fixture := buildOpenTxFixture(t, false)
	fake := testutil.NewFakeRPC()
	// The session recipient differs from the fixture payee, so the decode-only
	// pre-verification fails before any broadcast.
	session := newTestSession(t, func(o *SessionOptions) {
		o.OpenTxSubmitter = OpenTxSubmitterServer
		o.RPC = fake
	})
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err == nil ||
		!strings.Contains(err.Error(), "payee") {
		t.Fatalf("pre-verification error = %v", err)
	}
	if len(fake.Sent) != 0 {
		t.Fatal("broadcast happened despite pre-verification failure")
	}
}

func TestSessionCloseCancelsIdleTimer(t *testing.T) {
	fake := testutil.NewFakeRPC()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.CloseDelay = 50 * time.Millisecond
	})
	_, channelID := openTrustedChannel(t, session, 1_000)
	if _, err := verifySessionAction(t, session, intents.NewCloseAction(intents.ClosePayload{ChannelID: channelID})); err != nil {
		t.Fatalf("close: %v", err)
	}
	// With no merchant signer the close never settles, and the canceled
	// watchdog must not fire afterward either.
	time.Sleep(120 * time.Millisecond)
	state := mustGetChannel(t, session, channelID)
	if state.Finalized || len(fake.Sent) != 0 {
		t.Fatalf("idle timer fired after close: %+v sends=%d", state, len(fake.Sent))
	}
}

func TestCloseAndSettleSurfacesStoreWriteFailure(t *testing.T) {
	fake := testutil.NewFakeRPC()
	merchant := testutil.NewPrivateKey()
	store := &failingUpdateStore{ChannelStore: NewMemoryChannelStore()}
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.Signer = merchant
		o.Store = store
	})
	_, channelID := openTrustedChannel(t, session, 1_000)

	store.fail = true
	if _, err := session.closeAndSettleChannel(context.Background(), channelID); err == nil ||
		!strings.Contains(err.Error(), "store write rejected") {
		t.Fatalf("store write failure = %v", err)
	}
}

// TestCloseAndSettleRefusesWhenPayerUnrecorded is the regression for the P1:
// a channel that never recorded a payer must refuse to settle rather than
// silently refunding the merchant (recipient). The program pins the distribute
// payer to channel.payer, so refunding the recipient would derive the wrong
// refund token account and fail on-chain.
func TestCloseAndSettleRefusesWhenPayerUnrecorded(t *testing.T) {
	fake := testutil.NewFakeRPC()
	merchant := testutil.NewPrivateKey()
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = fake
		o.Signer = merchant
	})
	// Seed a close-pending channel with no Operator (no payer recorded), as a
	// bare push open with neither owner nor payer would produce.
	signer := newTestVoucherSigner(t)
	channelID := solana.NewWallet().PublicKey().String()
	closeRequestedAt := uint64(1)
	seedChannel(t, session.Core().Store(), ChannelState{
		ChannelID:        channelID,
		AuthorizedSigner: signer.Address(),
		Deposit:          1_000,
		CloseRequestedAt: &closeRequestedAt,
	})

	if _, err := session.closeAndSettleChannel(context.Background(), channelID); err == nil ||
		!strings.Contains(err.Error(), "payer is unknown") {
		t.Fatalf("settle without recorded payer = %v, want unknown-payer refusal", err)
	}
	// The merchant must never receive the refund: nothing was broadcast.
	if len(fake.Sent) != 0 {
		t.Fatalf("settlement broadcast %d transactions despite missing payer", len(fake.Sent))
	}
}

func TestSettlementInstructionsInvalidMintCurrency(t *testing.T) {
	config := sessionTestConfig()
	// An unknown currency resolves to itself; a non-base58 value then fails
	// mint parsing.
	config.Currency = "not-a-mint!"
	server := NewSessionServer(config, NewMemoryChannelStore())
	operator := solana.NewWallet().PublicKey().String()
	channelID := solana.NewWallet().PublicKey().String()
	seedChannel(t, server.Store(), ChannelState{
		ChannelID:        channelID,
		AuthorizedSigner: newTestVoucherSigner(t).Address(),
		Deposit:          1_000,
		Operator:         &operator,
	})
	if _, err := server.SettlementInstructions(context.Background(), channelID, solana.NewWallet().PublicKey()); err == nil ||
		!strings.Contains(err.Error(), "invalid mint") {
		t.Fatalf("invalid mint = %v", err)
	}
}
