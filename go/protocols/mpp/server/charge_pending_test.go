package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/jsonrpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// pullCredential issues a fresh challenge and returns a pull credential for
// it plus the transaction the client signed.
func pullCredential(t *testing.T, handler *Mpp, rpcClient *testutil.FakeRPC, payer solana.PrivateKey) (core.PaymentCredential, *solana.Transaction) {
	t.Helper()
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeader(context.Background(), payer, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	credential, err := core.ParseAuthorization(authHeader)
	if err != nil {
		t.Fatalf("parse authorization failed: %v", err)
	}
	var payload paycore.CredentialPayload
	if err := json.Unmarshal(*credential.Payload, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	tx, err := solanatx.DecodeTransactionBase64(payload.Transaction)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return credential, tx
}

// A send error other than a preflight rejection does not prove the node
// dropped the transaction (the response may be lost after it was accepted),
// so the charge stays pending under the locally derived signature and the
// identical retry reconciles it; only a preflight rejection fails it.
func TestAmbiguousSendErrorIsPendingNotFailed(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	credential, tx := pullCredential(t, handler, rpcClient, cfg.Client)
	signature := tx.Signatures[0]
	rpcClient.SendErr = &jsonrpc.RPCError{Code: -32099, Message: "response lost after the node accepted the transaction"}

	_, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if code := errCode(t, err); code != core.ErrCodeSettlementInProgress {
		t.Fatalf("code = %q, want %q (%v)", code, core.ErrCodeSettlementInProgress, err)
	}
	// The claim is kept: the same transaction cannot be broadcast again.
	if claimed, err := handler.consumed().Claim(context.Background(), signature.String()); err != nil || claimed {
		t.Fatalf("ambiguous send released the claim: claimed=%v err=%v", claimed, err)
	}

	// Status not visible yet: still in progress, nothing re-broadcast.
	rpcClient.SendErr = nil
	rpcClient.Statuses[signature.String()] = nil
	_, err = verifyCredentialEchoed(handler, context.Background(), credential)
	if code := errCode(t, err); code != core.ErrCodeSettlementInProgress {
		t.Fatalf("code = %q, want %q (%v)", code, core.ErrCodeSettlementInProgress, err)
	}
	if len(rpcClient.Sent) != 0 {
		t.Fatalf("retry re-broadcast the pending transaction: %d sends", len(rpcClient.Sent))
	}

	// The transaction did land: the identical retry gets the receipt, once.
	rpcClient.BySig[signature.String()] = tx
	rpcClient.Statuses[signature.String()] = &rpc.SignatureStatusesResult{ConfirmationStatus: rpc.ConfirmationStatusConfirmed}
	receipt, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if err != nil {
		t.Fatalf("reconciled retry failed: %v", err)
	}
	if receipt.Reference != signature.String() {
		t.Fatalf("receipt reference = %s, want %s", receipt.Reference, signature)
	}
	_, err = verifyCredentialEchoed(handler, context.Background(), credential)
	if code := errCode(t, err); code != core.ErrCodeSignatureConsumed {
		t.Fatalf("second grant: code = %q, want %q", code, core.ErrCodeSignatureConsumed)
	}
}

// A preflight rejection is definitive: the charge fails and the unsent
// transaction's claim is released so the payer may present it again.
func TestPreflightRejectionReleasesTheClaim(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	credential, tx := pullCredential(t, handler, rpcClient, cfg.Client)
	rpcClient.SendErr = &jsonrpc.RPCError{
		Code:    -32002,
		Message: "Transaction simulation failed: Error processing Instruction 0",
	}

	_, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if code := errCode(t, err); code != core.ErrCodeSimulationFailed {
		t.Fatalf("code = %q, want %q (%v)", code, core.ErrCodeSimulationFailed, err)
	}
	claimed, err := handler.consumed().Claim(context.Background(), tx.Signatures[0].String())
	if err != nil || !claimed {
		t.Fatalf("preflight rejection kept the claim: claimed=%v err=%v", claimed, err)
	}
}

// A pending charge only reconciles for the challenge it was recorded under.
func TestPendingChargeDoesNotReconcileForAnotherChallenge(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	credential, tx := pullCredential(t, handler, rpcClient, cfg.Client)
	signature := tx.Signatures[0].String()
	if err := handler.markPending(context.Background(), signature, "another-challenge", errors.New("lost")); err == nil {
		t.Fatal("markPending must return the in-progress error")
	}
	if _, err := handler.consumed().Claim(context.Background(), signature); err != nil {
		t.Fatal(err)
	}
	rpcClient.BySig[signature] = tx
	_, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if code := errCode(t, err); code != core.ErrCodeSignatureConsumed {
		t.Fatalf("code = %q, want %q", code, core.ErrCodeSignatureConsumed)
	}
}

// The middleware answers a pending charge with 409 and no challenge: a
// fresh challenge would let the client pay twice while the original lands.
func TestMiddlewareSettlementInProgressIsNotRechallenged(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	authHeader, err := client.BuildCredentialHeader(context.Background(), cfg.Client, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}
	rpcClient.SendErr = errors.New("connection reset after write")
	mw := PaymentMiddleware(handler, func(*http.Request) (string, ChargeOptions, error) {
		return "0.001", ChargeOptions{}, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	req.Header.Set(core.AuthorizationHeader, authHeader)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
	if rr.Header().Get(core.WWWAuthenticateHeader) != "" {
		t.Fatal("settlement-in-progress response must not carry a challenge")
	}
}
