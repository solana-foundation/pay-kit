package paykit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go/paykit"
	_ "github.com/solana-foundation/pay-kit/go/protocols/mpp"
	_ "github.com/solana-foundation/pay-kit/go/protocols/x402"
	"github.com/solana-foundation/pay-kit/go/signer"
)

func disabled() *bool { f := false; return &f }

func TestNewRejectsMissingNetwork(t *testing.T) {
	if _, err := paykit.New(paykit.Config{Preflight: disabled()}); err == nil {
		t.Fatal("expected error for missing Network")
	}
}

func TestNewRejectsDemoSignerOnMainnet(t *testing.T) {
	_, err := paykit.New(paykit.Config{
		Network:   paykit.SolanaMainnet,
		Preflight: disabled(),
	})
	if err == nil {
		t.Fatal("expected ErrDemoSignerOnMainnet")
	}
	if err != paykit.ErrDemoSignerOnMainnet {
		t.Fatalf("expected ErrDemoSignerOnMainnet, got %v", err)
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	client, err := paykit.New(paykit.Config{
		Network:   paykit.SolanaLocalnet,
		Preflight: disabled(),
		MPP: paykit.MPPConfig{
			ChallengeBindingSecret: []byte("test-secret"),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.Config.RPCURL == "" {
		t.Error("expected default RPCURL on localnet")
	}
	if client.Config.Operator.Signer == nil {
		t.Error("expected default demo signer")
	}
	if client.Config.Operator.Recipient == "" {
		t.Error("expected recipient cascade to signer pubkey")
	}
	if len(client.Config.Accept) != 2 {
		t.Errorf("expected 2 default schemes, got %d", len(client.Config.Accept))
	}
}

func TestMiddleware402EmitsBothAccepts(t *testing.T) {
	client := mustClient(t)
	gate := paykit.Gate{
		Amount: paykit.MustParseUSD("0.10"),
		Desc:   "Premium",
	}
	srv := httptest.NewServer(client.Require(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status: got %d want 402", resp.StatusCode)
	}
	if resp.Header.Get("payment-required") == "" {
		t.Error("missing x402 payment-required header")
	}
	if resp.Header.Get(strings.ToLower("WWW-Authenticate")) == "" {
		t.Error("missing MPP www-authenticate header")
	}
}

func TestMiddlewareInvalidGateValidate(t *testing.T) {
	client := mustClient(t)
	mixedDenom := paykit.Gate{
		Amount:   paykit.MustParseUSD("10.00"),
		PayTo:    paykit.Address("R111"),
		FeeOnTop: paykit.Fees{paykit.Address("F1"): paykit.MustParseEUR("0.10")},
	}
	srv := httptest.NewServer(client.Require(mixedDenom)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status: got %d want 402", resp.StatusCode)
	}
}

func TestPaymentFromAndIsPaidNilContext(t *testing.T) {
	if _, ok := paykit.PaymentFrom(context.Background()); ok {
		t.Error("expected false for empty context")
	}
	if paykit.IsPaid(context.Background()) {
		t.Error("expected IsPaid false")
	}
	if paykit.IsPaidFor(context.Background(), paykit.Gate{Name: "x"}) {
		t.Error("expected IsPaidFor false")
	}
}

func TestPricePositiveAndDenoms(t *testing.T) {
	p := paykit.MustParseUSD("0.10")
	if p.Currency() != paykit.USD {
		t.Error("currency mismatch")
	}
	if p.Amount().String() != "0.1" {
		t.Errorf("amount: got %s want 0.1", p.Amount().String())
	}
}

func TestPriceRejectsNegative(t *testing.T) {
	if _, err := paykit.ParseUSD("-1"); err == nil {
		t.Error("expected error for negative")
	}
}

func TestPriceRejectsMalformed(t *testing.T) {
	if _, err := paykit.ParseUSD("abc"); err == nil {
		t.Error("expected error for malformed")
	}
}

func TestGateValidateMixedDenoms(t *testing.T) {
	g := paykit.Gate{
		Amount: paykit.MustParseUSD("10.00"),
		PayTo:  "R",
		FeeOnTop: paykit.Fees{
			"F": paykit.MustParseEUR("0.10"),
		},
	}
	if err := g.Validate(); err == nil {
		t.Error("expected mixed currencies error")
	}
}

func TestGateValidateSumWithinExceedsAmount(t *testing.T) {
	g := paykit.Gate{
		Amount: paykit.MustParseUSD("1.00"),
		FeeWithin: paykit.Fees{
			"F": paykit.MustParseUSD("2.00"),
		},
	}
	if err := g.Validate(); err == nil {
		t.Error("expected sum>amount error")
	}
}

func TestGateValidateX402WithFees(t *testing.T) {
	g := paykit.Gate{
		Amount: paykit.MustParseUSD("10.00"),
		Accept: []paykit.Scheme{paykit.X402},
		FeeOnTop: paykit.Fees{
			"F": paykit.MustParseUSD("0.10"),
		},
	}
	if err := g.Validate(); err == nil {
		t.Error("expected x402+fees incompatible")
	}
}

func TestGateTotalAddsFeeOnTop(t *testing.T) {
	g := paykit.Gate{
		Amount: paykit.MustParseUSD("10.00"),
		FeeOnTop: paykit.Fees{
			"F": paykit.MustParseUSD("0.50"),
		},
	}
	if g.Total().Amount().String() != "10.5" {
		t.Errorf("total: got %s want 10.5", g.Total().Amount())
	}
}

func TestSignerDemoStableAcrossCalls(t *testing.T) {
	a := signer.Demo()
	b := signer.Demo()
	if a.Pubkey() != b.Pubkey() {
		t.Error("demo pubkey unstable")
	}
	if !a.IsDemo() {
		t.Error("demo flag false")
	}
}

func TestSignerGenerateProducesValidKeypair(t *testing.T) {
	s := signer.Generate()
	if s.Pubkey() == "" {
		t.Error("empty pubkey")
	}
	sig, err := s.Sign(context.Background(), []byte("hello"))
	if err != nil || len(sig) != 64 {
		t.Errorf("sign: len=%d err=%v", len(sig), err)
	}
}

func TestSignerFromEnvUnsetReturnsNil(t *testing.T) {
	s, err := signer.FromEnv("PAY_KIT_TEST_UNSET_VAR_X")
	if err != nil {
		t.Fatal(err)
	}
	if s != nil {
		t.Error("expected nil signer for unset var")
	}
}

func TestSignerFromBytesRejectsWrongLength(t *testing.T) {
	if _, err := signer.FromBytes(make([]byte, 32)); err == nil {
		t.Error("expected length error")
	}
}

func TestSignerFromJSONRejectsEmpty(t *testing.T) {
	if _, err := signer.FromJSON(""); err == nil {
		t.Error("expected empty error")
	}
}

func TestSignerFromHexRejectsWrongLength(t *testing.T) {
	if _, err := signer.FromHex("abc"); err == nil {
		t.Error("expected length error")
	}
}

func TestNetworkCAIP2Mainnet(t *testing.T) {
	want := "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	if paykit.SolanaMainnet.CAIP2() != want {
		t.Errorf("mainnet caip2: got %s", paykit.SolanaMainnet.CAIP2())
	}
}

func TestNetworkDefaultRPCLocalnet(t *testing.T) {
	if paykit.SolanaLocalnet.DefaultRPCURL() != "https://402.surfnet.dev:8899" {
		t.Errorf("localnet rpc: got %s", paykit.SolanaLocalnet.DefaultRPCURL())
	}
}

func TestResolveMintLocalnetFallsBackToMainnet(t *testing.T) {
	// Caveat #1: Surfpool localnet clones mainnet state.
	mainnet := paykit.ResolveMint(paykit.USDC, paykit.SolanaMainnet)
	local := paykit.ResolveMint(paykit.USDC, paykit.SolanaLocalnet)
	if mainnet == "" {
		t.Fatal("mainnet USDC mint missing")
	}
	if local != mainnet {
		t.Errorf("localnet should fall back to mainnet mint; got %s want %s", local, mainnet)
	}
}

func mustClient(t *testing.T) *paykit.Client {
	t.Helper()
	c, err := paykit.New(paykit.Config{
		Network:   paykit.SolanaLocalnet,
		Preflight: disabled(),
		MPP: paykit.MPPConfig{
			ChallengeBindingSecret: []byte("test-secret"),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}
