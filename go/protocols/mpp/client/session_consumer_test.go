package client

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// recordingTransport captures committed payloads and can be made to fail,
// mirroring the rust RecordingTransport test double. It also models the
// server-side delivery dedupe: a deliveryId already committed returns a
// "replayed" receipt carrying the originally committed cumulative, so the
// client does not double-count.
type recordingTransport struct {
	mu      sync.Mutex
	commits []intents.CommitPayload
	fail    bool

	// seen maps a deliveryId to the cumulative the server first committed for
	// it. A repeat deliveryId is acknowledged as replayed.
	seen map[string]string
}

func (r *recordingTransport) Commit(_ context.Context, directive intents.MeteringDirective, payload intents.CommitPayload) (intents.CommitReceipt, error) {
	if r.fail {
		return intents.CommitReceipt{}, errors.New("commit failed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen != nil {
		if cumulative, ok := r.seen[directive.DeliveryID]; ok {
			return intents.CommitReceipt{
				DeliveryID: directive.DeliveryID,
				SessionID:  directive.SessionID,
				Amount:     directive.Amount,
				Cumulative: cumulative,
				Status:     intents.CommitStatusReplayed,
			}, nil
		}
		r.seen[directive.DeliveryID] = payload.Voucher.Data.Cumulative
	}
	r.commits = append(r.commits, payload)
	return intents.CommitReceipt{
		DeliveryID: directive.DeliveryID,
		SessionID:  directive.SessionID,
		Amount:     directive.Amount,
		Cumulative: payload.Voucher.Data.Cumulative,
		Status:     intents.CommitStatusCommitted,
	}, nil
}

func (r *recordingTransport) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.commits)
}

func newConsumer(t *testing.T, fail bool) (*SessionConsumer, *recordingTransport) {
	t.Helper()
	session, _ := newSession(t)
	transport := &recordingTransport{fail: fail}
	return NewSessionConsumer(session, transport), transport
}

func directive(sessionID, amount string) intents.MeteringDirective {
	return intents.MeteringDirective{
		DeliveryID: "d1",
		SessionID:  sessionID,
		Amount:     amount,
		Currency:   "USDC",
		Sequence:   1,
		ExpiresAt:  intents.DefaultSessionExpiresAt,
	}
}

func TestSessionConsumerSessionAccessor(t *testing.T) {
	consumer, _ := newConsumer(t, false)
	if consumer.Session() == nil {
		t.Fatal("expected a session")
	}
}

func TestConsumerAckAdvancesWatermark(t *testing.T) {
	consumer, transport := newConsumer(t, false)
	sid := consumer.Session().ChannelIDString()

	delivery, err := Accept(consumer, intents.MeteredEnvelope[string]{
		Payload:  "work",
		Metering: directive(sid, "250"),
	})
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if delivery.Payload() != "work" {
		t.Fatalf("payload: %q", delivery.Payload())
	}
	if delivery.Metering().Amount != "250" {
		t.Fatalf("metering amount: %q", delivery.Metering().Amount)
	}

	receipt, err := delivery.Ack(context.Background())
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	if receipt.Cumulative != "250" {
		t.Fatalf("cumulative: %q", receipt.Cumulative)
	}
	if consumer.Session().Cumulative() != 250 {
		t.Fatalf("session cumulative: %d", consumer.Session().Cumulative())
	}
	if transport.count() != 1 {
		t.Fatalf("commits: %d", transport.count())
	}
}

func TestConsumerCommitAliasAndIntoParts(t *testing.T) {
	consumer, _ := newConsumer(t, false)
	consumer.Session().SetExpiresAt(1234)
	sid := consumer.Session().ChannelIDString()

	delivery, err := Accept(consumer, intents.MeteredEnvelope[string]{Payload: "payload", Metering: directive(sid, "50")})
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	receipt, err := delivery.Commit(context.Background())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if receipt.Cumulative != "50" {
		t.Fatalf("cumulative: %q", receipt.Cumulative)
	}

	second, err := Accept(consumer, intents.MeteredEnvelope[string]{Payload: "second", Metering: directive(sid, "75")})
	if err != nil {
		t.Fatalf("accept second: %v", err)
	}
	payload, metering := second.IntoParts()
	if payload != "second" {
		t.Fatalf("payload: %q", payload)
	}
	if metering.Amount != "75" {
		t.Fatalf("metering amount: %q", metering.Amount)
	}
	// IntoParts must not commit; only the first delivery advanced the watermark.
	if consumer.Session().Cumulative() != 50 {
		t.Fatalf("cumulative after into_parts: %d", consumer.Session().Cumulative())
	}
}

func TestConsumerCommitDirectiveDirect(t *testing.T) {
	consumer, transport := newConsumer(t, false)
	sid := consumer.Session().ChannelIDString()

	receipt, err := consumer.CommitDirective(context.Background(), directive(sid, "25"))
	if err != nil {
		t.Fatalf("commit directive: %v", err)
	}
	if receipt.Cumulative != "25" {
		t.Fatalf("cumulative: %q", receipt.Cumulative)
	}
	if transport.count() != 1 {
		t.Fatalf("commits: %d", transport.count())
	}
}

func TestConsumerRejectsWrongSession(t *testing.T) {
	consumer, transport := newConsumer(t, false)
	_, err := Accept(consumer, intents.MeteredEnvelope[struct{}]{
		Payload:  struct{}{},
		Metering: directive("other-session", "1"),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match active session") {
		t.Fatalf("expected wrong-session rejection, got %v", err)
	}
	if transport.count() != 0 {
		t.Fatalf("no commit expected: %d", transport.count())
	}
}

func TestConsumerRejectsZeroAndInvalidAmount(t *testing.T) {
	consumer, transport := newConsumer(t, false)
	sid := consumer.Session().ChannelIDString()

	if _, err := consumer.CommitDirective(context.Background(), directive(sid, "0")); err == nil || !strings.Contains(err.Error(), "greater than zero") {
		t.Fatalf("expected zero rejection, got %v", err)
	}
	if _, err := consumer.CommitDirective(context.Background(), directive(sid, "bad")); err == nil {
		t.Fatalf("expected invalid amount rejection")
	}
	if transport.count() != 0 {
		t.Fatalf("no commit expected: %d", transport.count())
	}
}

func TestConsumerFailedCommitDoesNotAdvanceWatermark(t *testing.T) {
	consumer, _ := newConsumer(t, true)
	sid := consumer.Session().ChannelIDString()

	_, err := consumer.CommitDirective(context.Background(), directive(sid, "250"))
	if err == nil || !strings.Contains(err.Error(), "commit failed") {
		t.Fatalf("expected commit failure, got %v", err)
	}
	if consumer.Session().Cumulative() != 0 {
		t.Fatalf("watermark advanced after failed commit: %d", consumer.Session().Cumulative())
	}
}

func TestConsumerDuplicateDeliveryReplayedNotDoubleCounted(t *testing.T) {
	// A server that dedupes by deliveryId returns a "replayed" receipt on the
	// second commit of the same deliveryId, carrying the cumulative it first
	// settled. The client honors that receipt and does not double-count: the
	// transport records exactly one commit.
	consumer, transport := newConsumer(t, false)
	transport.seen = map[string]string{}
	sid := consumer.Session().ChannelIDString()

	first, err := consumer.CommitDirective(context.Background(), directive(sid, "100"))
	if err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if first.Status != intents.CommitStatusCommitted {
		t.Fatalf("first status: %q", first.Status)
	}
	if first.Cumulative != "100" {
		t.Fatalf("first cumulative: %q", first.Cumulative)
	}

	// Replaying the same deliveryId yields a replayed receipt pinned to the
	// originally committed cumulative.
	replay, err := consumer.CommitDirective(context.Background(), directive(sid, "100"))
	if err != nil {
		t.Fatalf("replay commit: %v", err)
	}
	if replay.Status != intents.CommitStatusReplayed {
		t.Fatalf("replay status: %q", replay.Status)
	}
	if replay.Cumulative != "100" {
		t.Fatalf("replay cumulative not pinned to original: %q", replay.Cumulative)
	}
	if transport.count() != 1 {
		t.Fatalf("server must record exactly one commit, got %d", transport.count())
	}
}

func TestConsumerDuplicateDeliveryReplayMonotonic(t *testing.T) {
	// Two distinct deliveries advance the cumulative monotonically; the
	// transport sees increasing cumulative amounts.
	consumer, transport := newConsumer(t, false)
	sid := consumer.Session().ChannelIDString()

	if _, err := consumer.CommitDirective(context.Background(), directive(sid, "10")); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	d2 := directive(sid, "15")
	d2.DeliveryID = "d2"
	if _, err := consumer.CommitDirective(context.Background(), d2); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if consumer.Session().Cumulative() != 25 {
		t.Fatalf("cumulative: %d", consumer.Session().Cumulative())
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.commits[0].Voucher.Data.Cumulative != "10" || transport.commits[1].Voucher.Data.Cumulative != "25" {
		t.Fatalf("cumulative progression: %q %q",
			transport.commits[0].Voucher.Data.Cumulative, transport.commits[1].Voucher.Data.Cumulative)
	}
}
