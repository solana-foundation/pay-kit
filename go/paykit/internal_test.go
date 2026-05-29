package paykit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSettlementWriterMergesHeadersOnWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &settlementWriter{
		ResponseWriter: rec,
		headers:        map[string]string{"x-payment-settlement-signature": "SIG123"},
	}
	// Write without an explicit WriteHeader: the wrapper must default
	// to 200 and merge the settlement headers exactly once.
	n, err := sw.Write([]byte("ok"))
	if err != nil || n != 2 {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d want 200", rec.Code)
	}
	if rec.Header().Get("x-payment-settlement-signature") != "SIG123" {
		t.Error("settlement header not merged")
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body: got %q", rec.Body.String())
	}
}

func TestSettlementWriterExplicitWriteHeaderMergesOnce(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &settlementWriter{
		ResponseWriter: rec,
		headers:        map[string]string{"payment-receipt": "R1"},
	}
	sw.WriteHeader(http.StatusCreated)
	sw.WriteHeader(http.StatusTeapot) // second call must be ignored by the guard
	if rec.Code != http.StatusCreated {
		t.Errorf("status: got %d want 201", rec.Code)
	}
	if rec.Header().Get("payment-receipt") != "R1" {
		t.Error("receipt header not merged")
	}
}

func TestMustParseUSDPanicsOnBadInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic on malformed amount")
		}
	}()
	_ = MustParseUSD("not-a-number")
}

func TestNetworkEnumDefaults(t *testing.T) {
	bogus := Network("solana_unknownnet")
	if bogus.DefaultRPCURL() != "" {
		t.Errorf("unknown network DefaultRPCURL: got %q want empty", bogus.DefaultRPCURL())
	}
	if bogus.MintsLabel() != "solana_unknownnet" {
		t.Errorf("unknown network MintsLabel passthrough: got %q", bogus.MintsLabel())
	}
	if bogus.CAIP2() != "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" {
		t.Errorf("unknown network CAIP2 fallback: got %q", bogus.CAIP2())
	}
}

func TestMustParseGBPPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic on malformed GBP amount")
		}
	}()
	_ = MustParseGBP("abc")
}

func TestPreflightEnabledDefaultsTrue(t *testing.T) {
	t.Setenv("PAY_KIT_DISABLE_PREFLIGHT", "")
	if !preflightEnabled(Config{}) {
		t.Error("preflight should default to enabled when unset")
	}
}

func TestMustParseHelpersSucceed(t *testing.T) {
	if MustParseGBP("1.50").Currency() != GBP {
		t.Error("MustParseGBP currency")
	}
	if MustParseEUR("2.50").Currency() != EUR {
		t.Error("MustParseEUR currency")
	}
}

func TestGateErrorVariants(t *testing.T) {
	plain := &GateError{Reason: "bad"}
	if plain.Error() == "" || plain.Unwrap() != nil {
		t.Error("plain GateError")
	}
	withSentinel := &GateError{Reason: "x", Sentinel: ErrMixedCurrencies}
	if withSentinel.Unwrap() != ErrMixedCurrencies {
		t.Error("sentinel unwrap")
	}
	var nilErr *GateError
	if nilErr.Error() != "<nil>" {
		t.Errorf("nil GateError: got %q", nilErr.Error())
	}
}
