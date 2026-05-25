package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/errorcodes"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/server"
)

func newSmokeMpp(t *testing.T) *server.Mpp {
	t.Helper()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	handler, err := server.New(server.Config{
		Recipient: recipient,
		Currency:  defaultCurrency,
		Decimals:  6,
		Network:   defaultNetwork,
		RPCURL:    defaultRPCURL,
		SecretKey: defaultSecretKey,
		Realm:     defaultRealm,
		RPC:       testutil.NewFakeRPC(),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return handler
}

func newSmokeServer(t *testing.T) (*httptest.Server, *server.Mpp) {
	t.Helper()
	handler := newSmokeMpp(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/paid", paidHandler(handler, false))
	httpServer := httptest.NewUnstartedServer(mux)
	httpServer.Listener.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpServer.Listener = listener
	httpServer.Start()
	t.Cleanup(httpServer.Close)
	return httpServer, handler
}

func TestHealthReturns200(t *testing.T) {
	httpServer, _ := newSmokeServer(t)
	resp, err := http.Get(httpServer.URL + "/health")
	if err != nil {
		t.Fatalf("get /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var payload map[string]bool
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if !payload["ok"] {
		t.Fatalf("expected ok=true, got %v", payload)
	}
}

func TestPaidReturns402WithWWWAuthenticate(t *testing.T) {
	httpServer, _ := newSmokeServer(t)
	resp, err := http.Get(httpServer.URL + "/paid")
	if err != nil {
		t.Fatalf("get /paid: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", resp.StatusCode)
	}
	wwwAuth := resp.Header.Get(mpp.WWWAuthenticateHeader)
	if wwwAuth == "" {
		t.Fatal("expected WWW-Authenticate header to be set")
	}
	if !strings.HasPrefix(wwwAuth, "Payment ") {
		t.Fatalf("expected Payment scheme, got %q", wwwAuth)
	}
	challenge, err := mpp.ParseWWWAuthenticate(wwwAuth)
	if err != nil {
		t.Fatalf("parse WWW-Authenticate: %v", err)
	}
	if !challenge.Intent.IsCharge() {
		t.Fatalf("expected charge intent, got %q", challenge.Intent)
	}
	if challenge.Method != "solana" {
		t.Fatalf("expected solana method, got %q", challenge.Method)
	}
}

func TestPaidReturnsCanonicalNoCredentialBody(t *testing.T) {
	httpServer, _ := newSmokeServer(t)
	resp, err := http.Get(httpServer.URL + "/paid")
	if err != nil {
		t.Fatalf("get /paid: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("content-type"); got != "application/problem+json" {
		t.Fatalf("expected problem+json content type, got %q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if payload["code"] != errorcodes.PaymentInvalid {
		t.Fatalf("expected canonical code payment_invalid, got %#v", payload)
	}
	if payload["error"] != errorcodes.PaymentInvalid {
		t.Fatalf("expected error alias to match code, got %#v", payload)
	}
	if payload["status"] != float64(402) {
		t.Fatalf("expected status 402 in body, got %#v", payload["status"])
	}
}

func TestPaidRejectsMalformedAuthorizationWith402(t *testing.T) {
	httpServer, _ := newSmokeServer(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, httpServer.URL+"/paid", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(mpp.AuthorizationHeader, "Payment not-a-valid-credential")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected malformed authorization to re-issue 402, got %d", resp.StatusCode)
	}
	if resp.Header.Get(mpp.WWWAuthenticateHeader) == "" {
		t.Fatal("expected WWW-Authenticate on re-issued challenge")
	}
	body, _ := io.ReadAll(resp.Body)
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if payload["code"] != errorcodes.PaymentInvalid {
		t.Fatalf("expected canonical payment_invalid code, got %#v", payload)
	}
	if msg, _ := payload["message"].(string); msg == "" {
		t.Fatal("expected non-empty message on payment_invalid body")
	}
}

func TestPortFromEnvDefaultWhenUnset(t *testing.T) {
	t.Setenv("PORT", "x")
	if err := os.Unsetenv("PORT"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	port, err := portFromEnv()
	if err != nil {
		t.Fatalf("portFromEnv: %v", err)
	}
	if port != defaultPort {
		t.Fatalf("expected default port %d, got %d", defaultPort, port)
	}
}

func TestPortFromEnvRejectsExplicitEmpty(t *testing.T) {
	t.Setenv("PORT", "")
	if _, err := portFromEnv(); err == nil {
		t.Fatal("expected explicit empty PORT to fail")
	}
}

func TestPortFromEnvParses(t *testing.T) {
	t.Setenv("PORT", "8123")
	port, err := portFromEnv()
	if err != nil {
		t.Fatalf("portFromEnv: %v", err)
	}
	if port != 8123 {
		t.Fatalf("expected 8123, got %d", port)
	}
}

func TestPortFromEnvRejectsInvalid(t *testing.T) {
	t.Setenv("PORT", "not-a-number")
	if _, err := portFromEnv(); err == nil {
		t.Fatal("expected invalid PORT to fail")
	}
}

func TestPortFromEnvRejectsOutOfRange(t *testing.T) {
	t.Setenv("PORT", "70000")
	if _, err := portFromEnv(); err == nil {
		t.Fatal("expected out-of-range PORT to fail")
	}
}

func TestLoadFeePayerFromEnvNilWhenAbsent(t *testing.T) {
	t.Setenv("MPP_FEE_PAYER_SECRET_KEY", "")
	signer, err := loadFeePayerFromEnv()
	if err != nil {
		t.Fatalf("loadFeePayerFromEnv: %v", err)
	}
	if signer != nil {
		t.Fatal("expected nil signer when env var is empty")
	}
}

func TestLoadFeePayerFromEnvRejectsInvalidLength(t *testing.T) {
	t.Setenv("MPP_FEE_PAYER_SECRET_KEY", "[1,2,3]")
	if _, err := loadFeePayerFromEnv(); err == nil {
		t.Fatal("expected short fee payer key to fail")
	}
}

func TestLoadFeePayerFromEnvRejectsInvalidJSON(t *testing.T) {
	t.Setenv("MPP_FEE_PAYER_SECRET_KEY", "not-json")
	if _, err := loadFeePayerFromEnv(); err == nil {
		t.Fatal("expected invalid JSON fee payer key to fail")
	}
}

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("MPP_EXAMPLE_OVERRIDE", "override")
	if got := envOrDefault("MPP_EXAMPLE_OVERRIDE", "fallback"); got != "override" {
		t.Fatalf("expected override, got %q", got)
	}
	t.Setenv("MPP_EXAMPLE_OVERRIDE", "")
	if got := envOrDefault("MPP_EXAMPLE_OVERRIDE", "fallback"); got != "" {
		t.Fatalf("expected preserved empty value, got %q", got)
	}
	if err := os.Unsetenv("MPP_EXAMPLE_OVERRIDE"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if got := envOrDefault("MPP_EXAMPLE_OVERRIDE", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback when unset, got %q", got)
	}
}
