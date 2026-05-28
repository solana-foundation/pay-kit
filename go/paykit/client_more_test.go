package paykit_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go/paykit"
	_ "github.com/solana-foundation/pay-kit/go/protocols/mpp"
	_ "github.com/solana-foundation/pay-kit/go/protocols/x402"
	_ "github.com/solana-foundation/pay-kit/go/signer"
)

func TestClientCloseIsNoop(t *testing.T) {
	c := mustClient(t)
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestX402OnlyDoesNotRequireMPPSecretWithPreflightOff(t *testing.T) {
	// Regression for codex finding #8: an x402-only caller with
	// Preflight disabled must not be forced to supply an MPP secret.
	c, err := paykit.New(paykit.Config{
		Network:   paykit.SolanaLocalnet,
		Accept:    []paykit.Scheme{paykit.X402},
		Preflight: disabled(),
	})
	if err != nil {
		t.Fatalf("x402-only New should not require MPP secret: %v", err)
	}
	if c.MppAdapter() != nil {
		t.Error("expected no MPP adapter for x402-only Accept")
	}
	if c.X402Adapter() == nil {
		t.Error("expected x402 adapter")
	}
}

func TestSetErrorHandlerOverridesResponse(t *testing.T) {
	c := mustClient(t)
	c.SetErrorHandler(func(w http.ResponseWriter, _ *http.Request, _ error) {
		w.Header().Set("X-Custom", "yes")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("custom"))
	})
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "/x"}
	srv := httptest.NewServer(c.Require(gate)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status: got %d want 418", resp.StatusCode)
	}
	if resp.Header.Get("X-Custom") != "yes" {
		t.Error("custom header missing; error handler not invoked")
	}
}

func TestSetErrorHandlerNilRestoresDefault(t *testing.T) {
	c := mustClient(t)
	c.SetErrorHandler(func(w http.ResponseWriter, _ *http.Request, _ error) {
		w.WriteHeader(http.StatusTeapot)
	})
	c.SetErrorHandler(nil) // restore default
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "/x"}
	srv := httptest.NewServer(c.Require(gate)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Errorf("status: got %d want 402 after restoring default", resp.StatusCode)
	}
}

func TestDefaultErrorHandlerNonPaymentError(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	paykit.DefaultErrorHandler(rec, req, errFor("boom"))
	if rec.Code != http.StatusPaymentRequired {
		t.Errorf("status: got %d want 402", rec.Code)
	}
}

func Test402BodyIsTypedAndCarriesAccepts(t *testing.T) {
	c := mustClient(t)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "/x"}
	srv := httptest.NewServer(c.Require(gate)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Error    string `json:"error"`
		Resource string `json:"resource"`
		Accepts  []struct {
			Protocol string `json:"protocol"`
		} `json:"accepts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "payment_required" {
		t.Errorf("error: got %q", body.Error)
	}
	if len(body.Accepts) != 2 {
		t.Errorf("expected 2 accepts (x402+mpp), got %d", len(body.Accepts))
	}
}

func TestNewWarnsOnDeprecatedEnv(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	t.Setenv("PAY_KIT_PAY_TO", "SomeRecipient")
	_, err := paykit.New(paykit.Config{
		Network:   paykit.SolanaLocalnet,
		Accept:    []paykit.Scheme{paykit.X402},
		Preflight: disabled(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "PAY_KIT_PAY_TO") || !strings.Contains(buf.String(), "PAY_KIT_OPERATOR_RECIPIENT") {
		t.Errorf("expected deprecation warning naming old+new var, got: %s", buf.String())
	}
}
