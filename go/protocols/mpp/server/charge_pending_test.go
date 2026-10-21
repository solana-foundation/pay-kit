package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// expireChallenges moves the clock past every challenge's expiry for the
// rest of the test.
func expireChallenges(t *testing.T) {
	t.Helper()
	saved := now
	now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	t.Cleanup(func() { now = saved })
}

// A broadcast whose response was lost stays pending; a retry after the
// challenge expired must still reconcile it (the payment may have landed).
func TestPendingChargeReconcilesAfterItsChallengeExpires(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	credential, tx := pullCredential(t, handler, rpcClient, cfg.Client)
	signature := tx.Signatures[0]
	rpcClient.SendErr = &jsonrpc.RPCError{Code: -32099, Message: "response lost"}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); errCode(t, err) != core.ErrCodeSettlementInProgress {
		t.Fatalf("want settlement in progress, got %v", err)
	}
	rpcClient.SendErr = nil
	expireChallenges(t)

	// Expired but unresolved: still in progress, not expired.
	rpcClient.Statuses[signature.String()] = nil
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); errCode(t, err) != core.ErrCodeSettlementInProgress {
		t.Fatalf("want settlement in progress after expiry, got %v", err)
	}
	// It landed: the same credential is granted once, never re-broadcast.
	rpcClient.BySig[signature.String()] = tx
	rpcClient.Statuses[signature.String()] = &rpc.SignatureStatusesResult{ConfirmationStatus: rpc.ConfirmationStatusConfirmed}
	receipt, err := verifyCredentialEchoed(handler, context.Background(), credential)
	if err != nil {
		t.Fatalf("expired pending charge did not reconcile: %v", err)
	}
	if receipt.Reference != signature.String() {
		t.Fatalf("receipt reference = %s", receipt.Reference)
	}
	if len(rpcClient.Sent) != 0 {
		t.Fatalf("reconciling re-broadcast the transaction: %d sends", len(rpcClient.Sent))
	}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("an expired credential was granted twice")
	}
}

// An expired credential never starts a payment, and cannot reconcile a
// pending charge recorded under another challenge.
func TestExpiredCredentialNeverStartsAPayment(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	credential, tx := pullCredential(t, handler, rpcClient, cfg.Client)
	expireChallenges(t)
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); errCode(t, err) != core.ErrCodeChallengeExpired {
		t.Fatalf("want challenge expired, got %v", err)
	}
	if len(rpcClient.Sent) != 0 {
		t.Fatalf("an expired credential was broadcast: %d sends", len(rpcClient.Sent))
	}

	signature := tx.Signatures[0].String()
	_ = handler.markPending(context.Background(), signature, "another-challenge", errors.New("lost"))
	rpcClient.BySig[signature] = tx
	rpcClient.Statuses[signature] = &rpc.SignatureStatusesResult{ConfirmationStatus: rpc.ConfirmationStatusConfirmed}
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); errCode(t, err) != core.ErrCodeChallengeExpired {
		t.Fatalf("want challenge expired for another challenge's pending charge, got %v", err)
	}
}

// failingPendingStore refuses writes of pending-charge records.
type failingPendingStore struct {
	core.Store
	fail bool
}

func (s *failingPendingStore) Put(ctx context.Context, key string, value any) error {
	if s.fail && strings.HasPrefix(key, pendingChargePrefix) {
		return errors.New("injected store outage")
	}
	return s.Store.Put(ctx, key, value)
}

// The pending record a retry reconciles is written with the claim, before
// anything is sent. Written after an ambiguous send, a store failure would
// strand a payment that may have landed: claimed, with no record to
// reconcile, so every retry would be refused as consumed.
func TestPendingRecordIsWrittenBeforeSending(t *testing.T) {
	handler, rpcClient, cfg := newTestMpp(t)
	store := &failingPendingStore{Store: handler.store, fail: true}
	handler.store = store
	credential, tx := pullCredential(t, handler, rpcClient, cfg.Client)
	rpcClient.SendErr = &jsonrpc.RPCError{Code: -32099, Message: "response lost"}

	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); err == nil {
		t.Fatal("expected the store failure")
	}
	if len(rpcClient.Sent) != 0 {
		t.Fatalf("a transaction without a recovery record was sent: %d sends", len(rpcClient.Sent))
	}

	// Nothing was sent, so the claim was given back; with the store healthy
	// the same credential goes pending, recoverably.
	store.fail = false
	if _, err := verifyCredentialEchoed(handler, context.Background(), credential); errCode(t, err) != core.ErrCodeSettlementInProgress {
		t.Fatalf("want settlement in progress, got %v", err)
	}
	if _, found, _ := store.Get(context.Background(), pendingChargePrefix+tx.Signatures[0].String()); !found {
		t.Fatal("an ambiguous send must leave a pending record")
	}
}
