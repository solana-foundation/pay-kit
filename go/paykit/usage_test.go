package paykit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChargeDefaultsToZero(t *testing.T) {
	c := NewCharge(1_000_000)
	if c.SettledBaseUnits() != 0 {
		t.Fatalf("expected 0, got %d", c.SettledBaseUnits())
	}
}

func TestChargeRecordsAmount(t *testing.T) {
	c := NewCharge(1_000_000)
	c.Charge(400_000)
	if c.SettledBaseUnits() != 400_000 {
		t.Fatalf("expected 400000, got %d", c.SettledBaseUnits())
	}
}

func TestChargeClampsAboveCeiling(t *testing.T) {
	c := NewCharge(1_000_000)
	c.Charge(2_000_000)
	if c.SettledBaseUnits() != 1_000_000 {
		t.Fatalf("expected clamped to 1000000, got %d", c.SettledBaseUnits())
	}
}

func TestChargeMaxBaseUnits(t *testing.T) {
	c := NewCharge(1_000_000)
	if c.MaxBaseUnits() != 1_000_000 {
		t.Fatalf("expected 1000000, got %d", c.MaxBaseUnits())
	}
}

func TestChargeFromContext(t *testing.T) {
	c := NewCharge(500_000)
	ctx := ContextWithChargeForTests(context.Background(), c)
	got, ok := ChargeFrom(ctx)
	if !ok || got != c {
		t.Fatalf("ChargeFrom: got %v, ok %v", got, ok)
	}
	_, ok = ChargeFrom(context.Background())
	if ok {
		t.Fatal("expected false for empty context")
	}
}

func TestChargeMarshalJSON(t *testing.T) {
	c := NewCharge(1_000_000)
	c.Charge(500_000)
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if !strings.Contains(string(raw), "1000000") || !strings.Contains(string(raw), "500000") {
		t.Fatalf("expected max and settled in JSON, got %s", raw)
	}
}

// stubUsageAdapter is a test-only UsageAdapter for middleware tests.
type stubUsageAdapter struct {
	challengeHeaders map[string]string
	acceptsEntry     AcceptsEntry
	detect           bool
	verifyOpenErr    error
	settleErr        error
	settleResult     *UsageSettlement
	verified         VerifiedUsageOpen
}

type stubAcceptsEntry struct{}

func (stubAcceptsEntry) AcceptsProtocol() Protocol { return X402 }

func (s *stubUsageAdapter) UsageChallengeHeaders(*Gate) map[string]string { return s.challengeHeaders }
func (s *stubUsageAdapter) UsageAcceptsEntry(*Gate) AcceptsEntry          { return s.acceptsEntry }
func (s *stubUsageAdapter) DetectUsage(*AdapterRequest) bool              { return s.detect }
func (s *stubUsageAdapter) VerifyOpen(context.Context, *AdapterRequest) (VerifiedUsageOpen, *Payment, error) {
	if s.verifyOpenErr != nil {
		return nil, nil, s.verifyOpenErr
	}
	pmt := &Payment{Protocol: X402, SettlementHeaders: map[string]string{}}
	return s.verified, pmt, nil
}
func (s *stubUsageAdapter) SettleActual(context.Context, VerifiedUsageOpen, uint64) (*UsageSettlement, error) {
	if s.settleErr != nil {
		return nil, s.settleErr
	}
	if s.settleResult != nil {
		return s.settleResult, nil
	}
	return &UsageSettlement{Transaction: "sig", Headers: map[string]string{"x-payment-response": "abc"}}, nil
}

func TestRequireUsageReturns402WhenNoPayment(t *testing.T) {
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: &stubUsageAdapter{detect: false, challengeHeaders: map[string]string{"payment-required": "abc"}, acceptsEntry: stubAcceptsEntry{}},
		errorHandler: DefaultErrorHandler,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rr.Code)
	}
}

func TestRequireUsageSettlesAfterHandler(t *testing.T) {
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: &stubUsageAdapter{detect: true, settleResult: &UsageSettlement{Transaction: "sig123", Headers: map[string]string{"x-payment-response": "encoded", "x-payment-settlement-signature": "sig123"}}},
		errorHandler: DefaultErrorHandler,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	handlerCalled := false
	chargeCalled := false
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		c, ok := ChargeFrom(r.Context())
		if !ok || c == nil {
			t.Fatal("expected Charge in context")
		}
		c.Charge(300_000)
		chargeCalled = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "abc")
	h.ServeHTTP(rr, req)
	if !handlerCalled {
		t.Fatal("handler was not called")
	}
	if !chargeCalled {
		t.Fatal("charge was not called")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Header().Get("x-payment-settlement-signature") != "sig123" {
		t.Fatalf("settlement header missing: %s", rr.Header().Get("x-payment-settlement-signature"))
	}
}

func TestRequireUsageRejectsNonUsageGate(t *testing.T) {
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: &stubUsageAdapter{},
		errorHandler: DefaultErrorHandler,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateFixed, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rr.Code)
	}
}

func TestRequireUsageRejectsVerifyOpenError(t *testing.T) {
	client := &Client{
		Config: Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: &stubUsageAdapter{
			detect:           true,
			verifyOpenErr:    &PaymentError{Code: "invalid_proof", Err: errors.New("bad signature")},
			challengeHeaders: map[string]string{"payment-required": "abc"},
			acceptsEntry:     stubAcceptsEntry{},
		},
		errorHandler: DefaultErrorHandler,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "bad")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rr.Code)
	}
}

func TestRequireUsageHandlesSettleError(t *testing.T) {
	client := &Client{
		Config: Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: &stubUsageAdapter{
			detect:    true,
			settleErr: errors.New("settlement broadcast failed"),
		},
		errorHandler: DefaultErrorHandler,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := ChargeFrom(r.Context())
		c.Charge(300_000)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "abc")
	h.ServeHTTP(rr, req)
	// Settlement failed but the handler already ran; the response still goes
	// out (without settlement headers, but with the handler's body).
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (handler already wrote)", rr.Code)
	}
}

func TestRequireUsageNilAdapterReturns402(t *testing.T) {
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: nil,
		errorHandler: DefaultErrorHandler,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rr.Code)
	}
}

func TestGateTotalBaseUnits(t *testing.T) {
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage}
	if got := gateTotalBaseUnits(&gate); got != 1_000_000 {
		t.Fatalf("gateTotalBaseUnits = %d, want 1000000", got)
	}
}
