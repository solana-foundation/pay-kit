package server

// Adversarial coverage of the re-check-inside-the-mutator paths: the
// preflight runs outside the store lock, so every state-dependent check must
// hold again inside the atomic mutator. These tests interleave a competing
// write between the preflight read and the mutator using a racing store
// wrapper.

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// racingChannelStore wraps a ChannelStore and runs interleave exactly once,
// immediately before the next UpdateChannel applies its mutator. This
// simulates a concurrent writer that slips in between a handler's preflight
// read and its atomic read-modify-write.
type racingChannelStore struct {
	// ChannelStore is the wrapped real store the interleaved writes land in.
	ChannelStore

	// interleave runs once immediately before the next UpdateChannel applies
	// its mutator, then disarms itself.
	interleave func(ctx context.Context, store ChannelStore)
}

func (s *racingChannelStore) UpdateChannel(ctx context.Context, channelID string, mutator ChannelMutator) (ChannelState, error) {
	if s.interleave != nil {
		race := s.interleave
		s.interleave = nil
		race(ctx, s.ChannelStore)
	}
	return s.ChannelStore.UpdateChannel(ctx, channelID, mutator)
}

func TestVerifyVoucherDetectsConcurrentWatermarkAdvance(t *testing.T) {
	racing := &racingChannelStore{ChannelStore: NewMemoryChannelStore()}
	server := NewSessionServer(sessionTestConfig(), racing)
	signer, channelID := openTestChannel(t, server, 1_000_000)

	// Between the preflight and the mutator a competing voucher advances the
	// watermark past this voucher's cumulative.
	racing.interleave = func(ctx context.Context, store ChannelStore) {
		if _, err := store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
			next := *current
			next.Cumulative = 500
			return next, nil
		}); err != nil {
			t.Fatalf("interleaved update: %v", err)
		}
	}

	_, err := submitVoucher(t, server, signer, channelID, 100)
	if err == nil || !strings.Contains(err.Error(), "concurrent update") {
		t.Fatalf("err = %v, want concurrent-update rejection", err)
	}
}

func TestVerifyVoucherDetectsConcurrentClose(t *testing.T) {
	racing := &racingChannelStore{ChannelStore: NewMemoryChannelStore()}
	server := NewSessionServer(sessionTestConfig(), racing)
	signer, channelID := openTestChannel(t, server, 1_000_000)

	racing.interleave = func(ctx context.Context, store ChannelStore) {
		if _, err := store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
			next := *current
			closeAt := uint64(1)
			next.CloseRequestedAt = &closeAt
			return next, nil
		}); err != nil {
			t.Fatalf("interleaved update: %v", err)
		}
	}

	_, err := submitVoucher(t, server, signer, channelID, 100)
	if err == nil || !strings.Contains(err.Error(), "close is pending") {
		t.Fatalf("err = %v, want close-pending rejection inside the mutator", err)
	}
}

func TestVerifyVoucherDetectsConcurrentFinalize(t *testing.T) {
	racing := &racingChannelStore{ChannelStore: NewMemoryChannelStore()}
	server := NewSessionServer(sessionTestConfig(), racing)
	signer, channelID := openTestChannel(t, server, 1_000_000)

	racing.interleave = func(ctx context.Context, store ChannelStore) {
		if _, err := store.MarkFinalized(ctx, channelID); err != nil {
			t.Fatalf("interleaved finalize: %v", err)
		}
	}

	_, err := submitVoucher(t, server, signer, channelID, 100)
	if err == nil || !strings.Contains(err.Error(), "finalized") {
		t.Fatalf("err = %v, want finalized rejection inside the mutator", err)
	}
}

func TestVerifyVoucherConcurrentIdenticalReplayInsideMutator(t *testing.T) {
	racing := &racingChannelStore{ChannelStore: NewMemoryChannelStore()}
	server := NewSessionServer(sessionTestConfig(), racing)
	signer, channelID := openTestChannel(t, server, 1_000_000)

	voucher := signer.SignVoucher(t, channelID, 100, farFuture())
	// The same voucher lands twice concurrently: the slower submission sees
	// the watermark already advanced with its own signature and resolves as
	// an idempotent replay instead of a concurrent-update error.
	racing.interleave = func(ctx context.Context, store ChannelStore) {
		if _, err := store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
			next := *current
			next.Cumulative = 100
			signature := voucher.Signature
			next.HighestVoucherSignature = &signature
			expiresAt := voucher.Data.ExpiresAt
			next.HighestVoucherExpiresAt = &expiresAt
			return next, nil
		}); err != nil {
			t.Fatalf("interleaved update: %v", err)
		}
	}

	cumulative, err := server.VerifyVoucher(context.Background(), &intents.VoucherPayload{Voucher: voucher})
	if err != nil {
		t.Fatalf("VerifyVoucher: %v", err)
	}
	if cumulative != 100 {
		t.Fatalf("cumulative = %d, want 100", cumulative)
	}
}

func TestProcessCommitDetectsConcurrentReplayAndClose(t *testing.T) {
	racing := &racingChannelStore{ChannelStore: NewMemoryChannelStore()}
	server := NewSessionServer(sessionTestConfig(), racing)
	signer, channelID := openTestChannel(t, server, 1_000_000)

	directive, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 100})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	voucher := signer.SignVoucher(t, channelID, 100, farFuture())
	payload := &intents.CommitPayload{DeliveryID: directive.DeliveryID, Voucher: voucher}

	// A concurrent identical commit completes between preflight and mutator:
	// the mutator resolves it as a replay using the committed-deliveries log.
	racing.interleave = func(ctx context.Context, store ChannelStore) {
		if _, err := store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
			next := *current
			next.PendingDeliveries = nil
			next.Cumulative = 100
			signature := voucher.Signature
			next.HighestVoucherSignature = &signature
			next.CommittedDeliveries = []CommittedDelivery{{
				DeliveryID:       directive.DeliveryID,
				Amount:           100,
				Cumulative:       100,
				VoucherSignature: voucher.Signature,
			}}
			return next, nil
		}); err != nil {
			t.Fatalf("interleaved update: %v", err)
		}
	}
	receipt, err := server.ProcessCommit(context.Background(), payload)
	if err != nil {
		t.Fatalf("ProcessCommit: %v", err)
	}
	if receipt.Status != intents.CommitStatusReplayed {
		t.Fatalf("status = %s, want replayed", receipt.Status)
	}

	// A concurrent close between preflight and mutator rejects the commit.
	directive2, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 100})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	voucher2 := signer.SignVoucher(t, channelID, 200, farFuture())
	racing.interleave = func(ctx context.Context, store ChannelStore) {
		if _, err := store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
			next := *current
			closeAt := uint64(1)
			next.CloseRequestedAt = &closeAt
			return next, nil
		}); err != nil {
			t.Fatalf("interleaved close: %v", err)
		}
	}
	_, err = server.ProcessCommit(context.Background(), &intents.CommitPayload{
		DeliveryID: directive2.DeliveryID, Voucher: voucher2,
	})
	if err == nil || !strings.Contains(err.Error(), "close is pending") {
		t.Fatalf("err = %v, want close-pending rejection inside the mutator", err)
	}
}

func TestFitsInDepositOverflowGuards(t *testing.T) {
	cases := []struct {
		name                                  string
		cumulative, pendingTotal, amount, cap uint64
		want                                  bool
	}{
		{"boundary holds", 400, 500, 100, 1_000, true},
		{"one over cap", 400, 500, 101, 1_000, false},
		{"cumulative plus pending overflows", math.MaxUint64, 1, 1, math.MaxUint64, false},
		{"reserved plus amount overflows", math.MaxUint64 - 1, 1, 1, math.MaxUint64, false},
		{"max values without overflow", 0, 0, math.MaxUint64, math.MaxUint64, true},
	}
	for _, tc := range cases {
		if got := fitsInDeposit(tc.cumulative, tc.pendingTotal, tc.amount, tc.cap); got != tc.want {
			t.Errorf("%s: fitsInDeposit(%d, %d, %d, %d) = %v, want %v",
				tc.name, tc.cumulative, tc.pendingTotal, tc.amount, tc.cap, got, tc.want)
		}
	}
}

func TestVerifyVoucherForChannelMalformedSignatureEncodingRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	state := voucherTestState(signer.Address())
	voucher := signer.SignVoucher(t, state.ChannelID, 100, farFuture())
	voucher.Signature = "not base58!!"

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectInvalidSignature {
		t.Fatalf("result = %+v, want invalid-signature rejection", result)
	}
}

func TestVerifyVoucherForChannelMalformedAuthorizedSignerRejected(t *testing.T) {
	signer := newTestVoucherSigner(t)
	state := voucherTestState("not-a-pubkey")
	voucher := signer.SignVoucher(t, state.ChannelID, 100, farFuture())

	result := VerifyVoucherForChannel(VerifyVoucherArgs{State: state, Signed: voucher, Deposit: 1_000})
	if result.Status != VoucherVerifyRejected || result.Reason != VoucherRejectInvalidSignature {
		t.Fatalf("result = %+v, want invalid-signature rejection", result)
	}
}

func TestProcessCommitExpiredVoucherRejected(t *testing.T) {
	server := newSessionTestServer(sessionTestConfig())
	signer, channelID := openTestChannel(t, server, 1_000_000)

	directive, err := server.BeginDelivery(context.Background(), DeliveryRequest{SessionID: channelID, Amount: 100})
	if err != nil {
		t.Fatalf("BeginDelivery: %v", err)
	}
	// The directive is live but the voucher itself is expired.
	expired := signer.SignVoucher(t, channelID, 100, -10)
	_, err = server.ProcessCommit(context.Background(), &intents.CommitPayload{
		DeliveryID: directive.DeliveryID, Voucher: expired,
	})
	if err == nil || !strings.Contains(err.Error(), "voucher has expired") {
		t.Fatalf("err = %v, want expired-voucher rejection", err)
	}
}
