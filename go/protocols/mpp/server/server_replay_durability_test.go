package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// confirmTimeoutRPC wraps a FakeRPC so that Simulate and Send succeed (the
// broadcast is accepted by the RPC) but GetSignatureStatuses always errors,
// so WaitForConfirmation never confirms and the caller's context deadline is
// what ultimately ends the poll. This models the dangerous case: the RPC
// accepted the transaction (it may still land on-chain) but the server times
// out waiting for confirmation.
type confirmTimeoutRPC struct {
	*testutil.FakeRPC
}

func (c *confirmTimeoutRPC) GetSignatureStatuses(_ context.Context, _ bool, _ ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	return nil, errors.New("rpc unavailable: confirmation status temporarily unknown")
}

// TestReplayMarkerRetainedOnConfirmationTimeout is the GO-5 regression. After
// SendTransaction returns ok the consumed marker must survive a confirmation
// timeout: the transaction may still land on-chain, so re-submitting the same
// credential must be rejected as already-consumed rather than reopening the
// credential for a double-pay.
func TestReplayMarkerRetainedOnConfirmationTimeout(t *testing.T) {
	fake := testutil.NewFakeRPC()
	rpcClient := &confirmTimeoutRPC{FakeRPC: fake}
	recipientSigner := testutil.NewPrivateKey()
	clientSigner := testutil.NewPrivateKey()

	handler, err := New(Config{
		Recipient: recipientSigner.PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       rpcClient,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}

	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeader(context.Background(), clientSigner, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}

	// First attempt: broadcast succeeds, confirmation times out.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := verifyCredentialEchoed(handler, ctx, credential); err == nil {
		t.Fatal("expected confirmation timeout to surface an error")
	}

	// The transaction was broadcast and accepted by the RPC.
	if len(fake.Sent) == 0 {
		t.Fatal("expected the transaction to have been broadcast")
	}

	// Second attempt with the SAME credential MUST be rejected: the marker
	// must still be reserved because the original broadcast may land.
	_, err = verifyCredentialEchoed(handler, context.Background(), credential)
	if err == nil {
		t.Fatal("expected re-submission after broadcast+timeout to be rejected as consumed")
	}
	if !isConsumedError(err) {
		t.Fatalf("expected signature-consumed rejection, got: %v", err)
	}
}

// TestBroadcastPathConcurrentReplayRejected pins the H2 guarantee for the
// server-broadcast ("pull", type="transaction") charge path: verifyTransaction
// derives the fee-payer signature and check-and-marks the consumed store via
// the atomic MemoryStore.PutIfAbsent before it broadcasts. When N goroutines
// present the SAME signed credential concurrently, exactly one must win the
// consumed marker and settle, and every other concurrent attempt must be
// rejected with ErrCodeSignatureConsumed. This is the concurrency invariant the
// TypeScript broadcast path lacked (it wrote a consumed marker but never checked
// it and held no per-signature lock, so one payment yielded many receipts); the
// test guards the Go path against a regression into that shape.
func TestBroadcastPathConcurrentReplayRejected(t *testing.T) {
	fake := testutil.NewFakeRPC()
	recipientSigner := testutil.NewPrivateKey()
	clientSigner := testutil.NewPrivateKey()

	handler, err := New(Config{
		Recipient: recipientSigner.PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       fake,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}

	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeader(context.Background(), clientSigner, fake, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}

	// Fan out the same credential across many goroutines, all released at once
	// so they race the check-and-mark. The winner runs the full simulate ->
	// broadcast -> confirm -> on-chain re-verify happy path; the losers must
	// bounce off the consumed marker.
	const workers = 16
	var start sync.WaitGroup
	start.Add(1)
	var wg sync.WaitGroup
	wg.Add(workers)

	results := make([]error, workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			start.Wait()
			_, results[idx] = verifyCredentialEchoed(handler, context.Background(), credential)
		}(i)
	}
	start.Done()
	wg.Wait()

	successes := 0
	consumed := 0
	for i, err := range results {
		switch {
		case err == nil:
			successes++
		case isConsumedError(err):
			consumed++
		default:
			t.Fatalf("worker %d got unexpected error: %v", i, err)
		}
	}

	if successes != 1 {
		t.Fatalf("expected exactly one successful settlement, got %d (consumed=%d)", successes, consumed)
	}
	if consumed != workers-1 {
		t.Fatalf("expected %d consumed-signature rejections, got %d", workers-1, consumed)
	}
	// One payment must mean one broadcast: the losers reject before touching
	// the RPC send path, so the same signed transaction is never re-broadcast.
	if len(fake.Sent) != 1 {
		t.Fatalf("expected exactly one broadcast for one payment, got %d", len(fake.Sent))
	}
}

func isConsumedError(err error) bool {
	var coreErr *core.Error
	if errors.As(err, &coreErr) {
		return coreErr.Code == core.ErrCodeSignatureConsumed
	}
	return false
}
