package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/jsonrpc"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
	x402client "github.com/solana-foundation/pay-kit/go/protocols/x402/client"
)

// This RPC has no network transport. It verifies real ephemeral signatures and
// returns the submitted transaction's actual primary signature, including when
// the same wire transaction is submitted twice.
type replayRPC struct {
	mu         sync.Mutex
	sends      int
	sendErr    error
	confirmErr any
	started    chan struct{}
	release    chan struct{}
}

func (r *replayRPC) SendEncodedTransactionWithOpts(_ context.Context, encoded string, _ rpc.TransactionOpts) (solana.Signature, error) {
	r.mu.Lock()
	r.sends++
	sendErr := r.sendErr
	r.mu.Unlock()
	tx, err := solanatx.DecodeTransactionBase64(encoded)
	if err != nil {
		return solana.Signature{}, err
	}
	if err := tx.VerifySignatures(); err != nil {
		return solana.Signature{}, fmt.Errorf("offline signature verification: %w", err)
	}
	if r.started != nil {
		r.started <- struct{}{}
		<-r.release
	}
	return tx.Signatures[0], sendErr
}

func (r *replayRPC) GetSignatureStatuses(context.Context, bool, ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{{
		ConfirmationStatus: rpc.ConfirmationStatusConfirmed, Err: r.confirmErr,
	}}}, nil
}

func (*replayRPC) GetLatestBlockhash(context.Context, rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return nil, errors.New("offline fixture must supply its blockhash")
}

func replayCredential(t *testing.T, credential proto.Credential, tx *solana.Transaction) string {
	t.Helper()
	wire, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		t.Fatal(err)
	}
	credential.Payload.Transaction = wire
	raw, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func replayIdentityFixture(t *testing.T, legacy bool, version int) (*Adapter, *paykit.Gate, *replayRPC, string, string) {
	t.Helper()
	a, gate, _ := settleFixture(t, &fakeRPC{})
	gate.Desc = "offline replay regression"
	entry := a.routeAccepts(gate)
	entry.Extra.RecentBlockhash = solana.Hash{7}.String()
	client := testutil.NewPrivateKey()
	header, err := x402client.BuildPaymentHeader(context.Background(), client, nil, &entry)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var credential proto.Credential
	if err := json.Unmarshal(raw, &credential); err != nil {
		t.Fatal(err)
	}
	tx, err := solanatx.DecodeTransactionBase64(credential.Payload.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	if legacy {
		tx.Message.SetVersion(solana.MessageVersionLegacy)
		if err := solanatx.SignTransaction(tx, client); err != nil {
			t.Fatal(err)
		}
	}
	if len(tx.Signatures) != 2 || !tx.Signatures[0].IsZero() {
		t.Fatal("fixture must leave only the operator signature missing")
	}
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !tx.Signatures[1].Verify(client.PublicKey(), message) {
		t.Fatal("fixture must carry a valid client signature")
	}
	if version == proto.X402VersionLegacy {
		credential.X402Version = version
		credential.Scheme = proto.ExactScheme
		credential.Network = "solana-devnet"
		credential.Accepted = nil
	}
	partial := replayCredential(t, credential, tx)
	operatorSignature, err := a.signer.Sign(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	copy(tx.Signatures[0][:], operatorSignature)
	if err := tx.VerifySignatures(); err != nil {
		t.Fatalf("fully signed fixture: %v", err)
	}
	full := replayCredential(t, credential, tx)
	rpcClient := &replayRPC{}
	a.rpc = rpcClient
	return a, gate, rpcClient, partial, full
}

func requireReplayCode(t *testing.T, err error, code string) {
	t.Helper()
	var paymentError *paykit.PaymentError
	if !errors.As(err, &paymentError) || paymentError.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

// Issue #365 tracks this missing piece from EfeDurmaz16's earlier #236 work.
func TestReplayIdentityMatchesBeforeAndAfterCosigning(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, version := range []int{proto.X402VersionLegacy, proto.X402Version} {
			for _, fullFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("legacy=%v/version=%d/full-first=%v", legacy, version, fullFirst), func(t *testing.T) {
					a, gate, rpcClient, partial, full := replayIdentityFixture(t, legacy, version)
					first, second := partial, full
					if fullFirst {
						first, second = full, partial
					}
					if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: first}); err != nil {
						t.Fatalf("first settlement: %v", err)
					}
					_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: second})
					requireReplayCode(t, err, "signature_consumed")
					if rpcClient.sends != 1 {
						t.Fatalf("same signed payment submitted %d times", rpcClient.sends)
					}
				})
			}
		}
	}
}

func TestReplayIdentityConcurrentRepresentations(t *testing.T) {
	a, gate, rpcClient, partial, full := replayIdentityFixture(t, false, proto.X402Version)
	start := make(chan struct{})
	results := make(chan error, 10)
	for i := range 10 {
		header := partial
		if i%2 == 1 {
			header = full
		}
		go func() {
			<-start
			_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: header})
			results <- err
		}()
	}
	close(start)
	successes := 0
	for range 10 {
		err := <-results
		if err == nil {
			successes++
		} else {
			requireReplayCode(t, err, "signature_consumed")
		}
	}
	if successes != 1 || rpcClient.sends != 1 {
		t.Fatalf("one payment admitted %d times, sent %d times", successes, rpcClient.sends)
	}
}

func TestReplayIdentityReservedWhileBroadcastPending(t *testing.T) {
	a, gate, rpcClient, partial, full := replayIdentityFixture(t, false, proto.X402Version)
	rpcClient.started = make(chan struct{}, 2)
	rpcClient.release = make(chan struct{})
	first := make(chan error, 1)
	second := make(chan error, 1)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(rpcClient.release) }) }
	defer release()
	go func() {
		_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: partial})
		first <- err
	}()
	select {
	case <-rpcClient.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first request never reached the offline broadcast")
	}
	go func() {
		_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: full})
		second <- err
	}()
	select {
	case err := <-second:
		requireReplayCode(t, err, "signature_consumed")
	case <-time.After(2 * time.Second):
		t.Fatal("alternate representation was not rejected while the first broadcast was pending")
	}
	release()
	if err := <-first; err != nil {
		t.Fatalf("original settlement: %v", err)
	}
	if rpcClient.sends != 1 {
		t.Fatalf("pending broadcast replay: sends=%d", rpcClient.sends)
	}
}

func TestReplayAlreadyProcessedRemainsConsumed(t *testing.T) {
	for name, sendErr := range map[string]error{
		"structured":         &jsonrpc.RPCError{Code: -32002, Message: "Transaction simulation failed", Data: map[string]any{"err": "AlreadyProcessed"}},
		"wrapped-structured": fmt.Errorf("broadcast: %w", &jsonrpc.RPCError{Code: -32002, Message: "Transaction simulation failed", Data: map[string]any{"err": "AlreadyProcessed"}}),
	} {
		t.Run(name, func(t *testing.T) {
			a, gate, rpcClient, partial, full := replayIdentityFixture(t, false, proto.X402Version)
			rpcClient.sendErr = sendErr
			_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: partial})
			requireReplayCode(t, err, "signature_consumed")
			rpcClient.sendErr = nil
			_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: full})
			requireReplayCode(t, err, "signature_consumed")
			if rpcClient.sends != 1 {
				t.Fatalf("already-processed payment resent %d times", rpcClient.sends)
			}
		})
	}
}

func TestReplayAcceptedBroadcastRemainsConsumed(t *testing.T) {
	a, gate, rpcClient, partial, full := replayIdentityFixture(t, false, proto.X402Version)
	rpcClient.confirmErr = "InstructionError"
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: partial})
	requireReplayCode(t, err, "settlement_failed")
	// Once the RPC accepted the transaction, a later confirmation failure must
	// not reopen the reservation. This is the existing MPP charge policy.
	rpcClient.confirmErr = nil
	for _, header := range []string{partial, full} {
		_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: header})
		requireReplayCode(t, err, "signature_consumed")
	}
	if rpcClient.sends != 1 {
		t.Fatalf("accepted broadcast resent %d times", rpcClient.sends)
	}
}

func TestReplaySendFailureCanRetry(t *testing.T) {
	for name, sendErr := range map[string]error{
		"transport":           context.DeadlineExceeded,
		"preflight":           &jsonrpc.RPCError{Code: -32002, Message: "Transaction simulation failed", Data: map[string]any{"err": "BlockhashNotFound"}},
		"plain replay text":   errors.New("Transaction simulation failed: This transaction has already been processed"),
		"wrapped replay text": fmt.Errorf("broadcast: %w", errors.New("THIS TRANSACTION HAS ALREADY BEEN PROCESSED")),
		"client-chosen log": &jsonrpc.RPCError{Code: -32002, Message: "Transaction simulation failed", Data: map[string]any{
			"err":  map[string]any{"InstructionError": []any{1, map[string]any{"Custom": 1}}},
			"logs": []string{"Program log: Memo: This transaction has already been processed"},
		}},
		"message only": &jsonrpc.RPCError{Code: -32002, Message: "This transaction has already been processed"},
	} {
		t.Run(name, func(t *testing.T) {
			a, gate, rpcClient, partial, _ := replayIdentityFixture(t, false, proto.X402Version)
			rpcClient.sendErr = sendErr
			_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: partial})
			requireReplayCode(t, err, "send_failed")
			rpcClient.sendErr = nil
			if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: partial}); err != nil {
				t.Fatalf("retry existing send-error policy: %v", err)
			}
			if rpcClient.sends != 2 {
				t.Fatalf("send-error retry: sends=%d", rpcClient.sends)
			}
		})
	}
}

type replayFailingSigner struct{ paykit.Signer }

func (replayFailingSigner) Sign(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("offline signer unavailable")
}

func TestReplaySigningFailureCanRetry(t *testing.T) {
	a, gate, rpcClient, partial, _ := replayIdentityFixture(t, false, proto.X402Version)
	workingSigner := a.signer
	a.signer = replayFailingSigner{workingSigner}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: partial})
	requireReplayCode(t, err, "invalid_payload")
	if rpcClient.sends != 0 {
		t.Fatal("signing failure reached RPC")
	}
	a.signer = workingSigner
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: partial}); err != nil {
		t.Fatalf("retry after signing failure: %v", err)
	}
}

type replayZeroSigner struct{ paykit.Signer }

func (replayZeroSigner) Sign(context.Context, []byte) ([]byte, error) {
	return make([]byte, 64), nil
}

func TestReplayRejectsMissingPostCosignPrimarySignature(t *testing.T) {
	a, gate, rpcClient, partial, _ := replayIdentityFixture(t, false, proto.X402Version)
	a.signer = replayZeroSigner{a.signer}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: partial})
	requireReplayCode(t, err, "invalid_payload")
	if rpcClient.sends != 0 {
		t.Fatal("missing post-cosign primary signature reached RPC")
	}
}

func TestReplayDistinctPaymentsRemainIndependent(t *testing.T) {
	a, gate, rpcClient, partial, _ := replayIdentityFixture(t, false, proto.X402Version)
	entry := a.routeAccepts(gate)
	entry.Extra.RecentBlockhash = solana.Hash{7}.String()
	second, err := x402client.BuildPaymentHeader(context.Background(), testutil.NewPrivateKey(), nil, &entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{partial, second} {
		if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: header}); err != nil {
			t.Fatalf("independent payment: %v", err)
		}
	}
	if rpcClient.sends != 2 {
		t.Fatalf("independent payments: sends=%d", rpcClient.sends)
	}
}
