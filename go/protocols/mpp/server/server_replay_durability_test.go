package server

import (
	"context"
	"errors"
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

func isConsumedError(err error) bool {
	var coreErr *core.Error
	if errors.As(err, &coreErr) {
		return coreErr.Code == core.ErrCodeSignatureConsumed
	}
	return false
}
