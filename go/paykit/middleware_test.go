package paykit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	_ "github.com/solana-foundation/pay-kit/go/protocols/mpp"
	_ "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

func TestRequireFuncGateResolutionError(t *testing.T) {
	c := mustClient(t)
	mw := c.RequireFunc(func(_ *http.Request) (paykit.Gate, error) {
		return paykit.Gate{}, errFor("boom")
	})
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Errorf("status: got %d want 402", resp.StatusCode)
	}
}

func TestRequireFuncInvalidGateReturns402(t *testing.T) {
	c := mustClient(t)
	bad := paykit.Gate{
		Amount: paykit.MustParseUSD("10.00"),
		FeeWithin: paykit.Fees{
			paykit.Address("F"): paykit.MustParseUSD("99.00"), // sum > amount
		},
	}
	srv := httptest.NewServer(c.Require(bad)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Errorf("status: got %d want 402", resp.StatusCode)
	}
}

func TestIsPaidForUnnamedGateMatchesAnyPayment(t *testing.T) {
	pmt := &paykit.Payment{Protocol: paykit.MPP, Gate: "x"}
	ctx := withPayment(context.Background(), pmt)
	if !paykit.IsPaidFor(ctx, paykit.Gate{}) {
		t.Error("expected match for unnamed gate")
	}
}

func TestIsPaidForNamedGateMatch(t *testing.T) {
	pmt := &paykit.Payment{Protocol: paykit.MPP, Gate: "report"}
	ctx := withPayment(context.Background(), pmt)
	if !paykit.IsPaidFor(ctx, paykit.Gate{Name: "report"}) {
		t.Error("expected match")
	}
	if paykit.IsPaidFor(ctx, paykit.Gate{Name: "other"}) {
		t.Error("expected miss for non-matching name")
	}
}

func TestPaymentErrorWrapsSentinel(t *testing.T) {
	perr := &paykit.PaymentError{Code: "x", Err: paykit.ErrInvalidProof}
	if perr.Unwrap() != paykit.ErrInvalidProof {
		t.Error("Unwrap should return sentinel")
	}
	if perr.Error() == "" {
		t.Error("Error() should produce a string")
	}
}

func TestGateErrorWrapsSentinel(t *testing.T) {
	gerr := &paykit.GateError{Reason: "x", Sentinel: paykit.ErrInvalidConfig}
	if gerr.Unwrap() != paykit.ErrInvalidConfig {
		t.Error("Unwrap mismatch")
	}
}

func TestNetworkCAIP2Devnet(t *testing.T) {
	want := "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	if paykit.SolanaDevnet.CAIP2() != want {
		t.Errorf("devnet caip2: got %s", paykit.SolanaDevnet.CAIP2())
	}
}

func TestNetworkMintsLabel(t *testing.T) {
	if paykit.SolanaMainnet.MintsLabel() != "mainnet" ||
		paykit.SolanaDevnet.MintsLabel() != "devnet" ||
		paykit.SolanaLocalnet.MintsLabel() != "localnet" {
		t.Error("mints label mismatch")
	}
}

func TestNetworkDefaultRPCMainnetAndDevnet(t *testing.T) {
	if paykit.SolanaMainnet.DefaultRPCURL() == "" || paykit.SolanaDevnet.DefaultRPCURL() == "" {
		t.Error("expected non-empty default RPCs")
	}
}

func TestParseEURAndGBP(t *testing.T) {
	if p, err := paykit.ParseEUR("1.50"); err != nil || p.Currency() != paykit.EUR {
		t.Error("EUR parse failed")
	}
	if p, err := paykit.ParseGBP("1.50"); err != nil || p.Currency() != paykit.GBP {
		t.Error("GBP parse failed")
	}
}

func TestMustParseEURAndGBPPanicOnBad(t *testing.T) {
	for _, fn := range []func(){
		func() { paykit.MustParseEUR("abc") },
		func() { paykit.MustParseGBP("abc") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("expected panic")
				}
			}()
			fn()
		}()
	}
}

func TestPriceSettlementsRoundTrip(t *testing.T) {
	p := paykit.MustParseUSD("0.10", paykit.USDC, paykit.USDT)
	settlements := p.Settlements()
	if len(settlements) != 2 || settlements[0] != paykit.USDC || settlements[1] != paykit.USDT {
		t.Errorf("settlements: got %v", settlements)
	}
	if p.Settlements() == nil {
		t.Error("expected non-nil settlements copy")
	}
}

func TestPriceSettlementsNilWhenUnset(t *testing.T) {
	p := paykit.MustParseUSD("0.10")
	if p.Settlements() != nil {
		t.Error("expected nil settlements when unset")
	}
}

func TestGatePayoutForRecipient(t *testing.T) {
	g := &paykit.Gate{
		Amount: paykit.MustParseUSD("10.00"),
		PayTo:  paykit.Address("SELLER"),
		FeeWithin: paykit.Fees{
			paykit.Address("PLATFORM"): paykit.MustParseUSD("0.3"),
		},
		FeeOnTop: paykit.Fees{
			paykit.Address("GATEWAY"): paykit.MustParseUSD("0.5"),
		},
	}
	if p, ok := g.Payout("PLATFORM"); !ok || p.Amount().String() != "0.3" {
		t.Errorf("PLATFORM payout: ok=%v amt=%s", ok, p.Amount())
	}
	if p, ok := g.Payout("GATEWAY"); !ok || p.Amount().String() != "0.5" {
		t.Errorf("GATEWAY payout: ok=%v amt=%s", ok, p.Amount())
	}
	if p, ok := g.Payout("SELLER"); !ok || p.Amount().String() != "9.7" {
		t.Errorf("SELLER payout: ok=%v amt=%s", ok, p.Amount())
	}
	if _, ok := g.Payout("UNKNOWN"); ok {
		t.Error("expected miss for unknown")
	}
}

func TestResolveMintTokenProgram(t *testing.T) {
	if paykit.TokenProgramFor(paykit.USDC, paykit.SolanaMainnet) == "" {
		t.Error("expected USDC token program")
	}
}

func errFor(s string) error { return testError(s) }

type testError string

func (e testError) Error() string { return string(e) }

func withPayment(ctx context.Context, pmt *paykit.Payment) context.Context {
	return paykit.ContextWithPaymentForTests(ctx, pmt)
}
