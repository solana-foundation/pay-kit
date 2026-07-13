package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	solana "github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/rpc"

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

// sendAfterSideEffectRPC records the transaction in FakeRPC, then simulates a
// lost response from the transport. The server must treat this as ambiguous.
type sendAfterSideEffectRPC struct {
	*testutil.FakeRPC
	sendCalls int
}

func (r *sendAfterSideEffectRPC) SendTransactionWithOpts(ctx context.Context, tx *solana.Transaction, opts rpc.TransactionOpts) (solana.Signature, error) {
	r.sendCalls++
	if _, err := r.FakeRPC.SendTransactionWithOpts(ctx, tx, opts); err != nil {
		return solana.Signature{}, err
	}
	return solana.Signature{}, errors.New("send response lost after broadcast")
}

type sharedReplayStore struct {
	*core.MemoryStore
}

func (*sharedReplayStore) IsShared() bool { return true }

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
		Store:     &sharedReplayStore{MemoryStore: core.NewMemoryStore()},
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

func TestReplayMarkerRetainedOnAmbiguousSendError(t *testing.T) {
	fake := testutil.NewFakeRPC()
	rpcClient := &sendAfterSideEffectRPC{FakeRPC: fake}
	recipientSigner := testutil.NewPrivateKey()
	clientSigner := testutil.NewPrivateKey()

	handler, err := New(Config{
		Recipient: recipientSigner.PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-0123456789abcdef",
		RPC:       rpcClient,
		Store:     &sharedReplayStore{MemoryStore: core.NewMemoryStore()},
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

	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected ambiguous send error")
	}
	if got := len(fake.Sent); got != 1 {
		t.Fatalf("expected the first send to reach the RPC once, got %d", got)
	}

	_, err = verifyCredentialEchoed(handler, context.Background(), credential)
	if err == nil {
		t.Fatal("expected retry after ambiguous send error to be rejected as consumed")
	}
	if !isConsumedError(err) {
		t.Fatalf("expected signature-consumed rejection, got: %v", err)
	}
	if got := rpcClient.sendCalls; got != 1 {
		t.Fatalf("expected SendTransaction to be called at most once, got %d", got)
	}
}

func TestReplayMarkerRolledBackOnSimulationFailure(t *testing.T) {
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
		Store:     &sharedReplayStore{MemoryStore: core.NewMemoryStore()},
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

	fake.SimulateErr = errors.New("deterministic simulation failure")
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected simulation failure")
	}
	fake.SimulateErr = nil

	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err != nil {
		t.Fatalf("expected retry after simulation rollback to succeed: %v", err)
	}
	if got := len(fake.Sent); got != 1 {
		t.Fatalf("expected one broadcast after simulation rollback, got %d", got)
	}
}

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
		Store:     &sharedReplayStore{MemoryStore: core.NewMemoryStore()},
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

	const workers = 16
	start := make(chan struct{})
	results := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			<-start
			_, results[idx] = verifyCredentialEchoed(handler, context.Background(), credential)
		}(i)
	}
	close(start)
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
		t.Fatalf("expected exactly one successful settlement, got %d", successes)
	}
	if consumed != workers-1 {
		t.Fatalf("expected %d consumed-signature rejections, got %d", workers-1, consumed)
	}
	if got := len(fake.Sent); got != 1 {
		t.Fatalf("expected exactly one broadcast, got %d", got)
	}
}

func isConsumedError(err error) bool {
	var coreErr *core.Error
	if errors.As(err, &coreErr) {
		return coreErr.Code == core.ErrCodeSignatureConsumed
	}
	return false
}
