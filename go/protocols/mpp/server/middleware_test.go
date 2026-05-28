package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

func newMiddlewareTestMpp(t *testing.T) *Mpp {
	t.Helper()
	rpcClient := testutil.NewFakeRPC()
	handler, err := New(Config{
		Recipient: testutil.NewPrivateKey().PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-that-is-long-enough-for-hmac-sha256-operations",
		RPC:       rpcClient,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	return handler
}

func constantCharge(amount string) ChargeFunc {
	return func(r *http.Request) (string, ChargeOptions, error) {
		return amount, ChargeOptions{Description: "test charge"}, nil
	}
}

func hasVaryAuthorization(header http.Header) bool {
	for _, value := range header.Values("Vary") {
		for _, field := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(field), "Authorization") {
				return true
			}
		}
	}
	return false
}

func TestMiddlewareNoAuth402(t *testing.T) {
	m := newMiddlewareTestMpp(t)
	handler := PaymentMiddleware(m, constantCharge("0.001"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", rr.Code)
	}
	wwwAuth := rr.Header().Get(core.WWWAuthenticateHeader)
	if wwwAuth == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
	if !strings.HasPrefix(wwwAuth, core.PaymentScheme+" ") {
		t.Fatalf("expected Payment scheme in WWW-Authenticate, got %q", wwwAuth)
	}
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/problem+json") {
		t.Fatalf("expected problem+json content type, got %q", contentType)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected no-store cache control, got %q", rr.Header().Get("Cache-Control"))
	}
	if !hasVaryAuthorization(rr.Header()) {
		t.Fatalf("expected Vary: Authorization, got %q", rr.Header().Values("Vary"))
	}
}

func TestMiddlewareValidAuth(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	signer := testutil.NewPrivateKey()
	m, err := New(Config{
		Recipient: testutil.NewPrivateKey().PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-that-is-long-enough-for-hmac-sha256-operations",
		RPC:       rpcClient,
		Store:     core.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}

	challenge, err := m.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}

	authHeader, err := client.BuildCredentialHeader(context.Background(), signer, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential failed: %v", err)
	}

	var gotReceipt core.Receipt
	var hasReceipt bool
	handler := PaymentMiddleware(m, constantCharge("0.001"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReceipt, hasReceipt = ReceiptFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	req.Header.Set(core.AuthorizationHeader, authHeader)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !hasReceipt {
		t.Fatal("expected receipt in context")
	}
	if gotReceipt.Status != core.ReceiptStatusSuccess {
		t.Fatalf("expected success receipt, got %q", gotReceipt.Status)
	}
	if rr.Header().Get(core.PaymentReceiptHeader) == "" {
		t.Fatal("expected Payment-Receipt response header")
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected no-store cache control, got %q", rr.Header().Get("Cache-Control"))
	}
	if !hasVaryAuthorization(rr.Header()) {
		t.Fatalf("expected Vary: Authorization, got %q", rr.Header().Values("Vary"))
	}
}

func TestMiddlewareInvalidCredential402(t *testing.T) {
	m := newMiddlewareTestMpp(t)
	handler := PaymentMiddleware(m, constantCharge("0.001"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	req.Header.Set(core.AuthorizationHeader, "Payment invalid-base64-garbage")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 re-challenge, got %d", rr.Code)
	}
	if rr.Header().Get(core.WWWAuthenticateHeader) == "" {
		t.Fatal("expected WWW-Authenticate header on re-challenge")
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected no-store cache control, got %q", rr.Header().Get("Cache-Control"))
	}
	if !hasVaryAuthorization(rr.Header()) {
		t.Fatalf("expected Vary: Authorization, got %q", rr.Header().Values("Vary"))
	}
}

func TestMiddlewareBrowserHTML402(t *testing.T) {
	rpcClient := testutil.NewFakeRPC()
	m, err := New(Config{
		Recipient: testutil.NewPrivateKey().PublicKey().String(),
		Currency:  "sol",
		Decimals:  9,
		Network:   "localnet",
		SecretKey: "test-secret-key-that-is-long-enough-for-hmac-sha256-operations",
		RPC:       rpcClient,
		Store:     core.NewMemoryStore(),
		HTML:      true,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}

	handler := PaymentMiddleware(m, constantCharge("0.001"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", rr.Code)
	}
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Fatalf("expected HTML content type, got %q", contentType)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<!doctype html>") && !strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatal("expected HTML body")
	}
}

func TestMiddlewareServiceWorker(t *testing.T) {
	m := newMiddlewareTestMpp(t)
	handler := PaymentMiddleware(m, constantCharge("0.001"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/?__mpp_worker", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/javascript") {
		t.Fatalf("expected JavaScript content type, got %q", contentType)
	}
	if rr.Body.Len() == 0 {
		t.Fatal("expected service worker JS body")
	}
}

func TestMiddlewareChargeFuncError500(t *testing.T) {
	m := newMiddlewareTestMpp(t)
	errCharge := func(r *http.Request) (string, ChargeOptions, error) {
		return "", ChargeOptions{}, errors.New("pricing error")
	}
	handler := PaymentMiddleware(m, errCharge)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}

func TestMarkAuthorizationBoundResponsePreservesExistingVary(t *testing.T) {
	withAuthorization := http.Header{"Vary": {"Accept-Encoding, Authorization"}}
	markAuthorizationBoundResponse(withAuthorization)
	if got := withAuthorization.Values("Vary"); len(got) != 1 {
		t.Fatalf("expected existing authorization vary to be preserved, got %#v", got)
	}
	if withAuthorization.Get("Cache-Control") != "no-store" {
		t.Fatal("expected no-store cache control")
	}

	wildcard := http.Header{"Vary": {"*"}}
	markAuthorizationBoundResponse(wildcard)
	if got := wildcard.Values("Vary"); len(got) != 1 || got[0] != "*" {
		t.Fatalf("expected wildcard vary to be preserved, got %#v", got)
	}
}
