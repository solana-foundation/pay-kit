package paykit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	settledActual    uint64
	settleCalls      int
	onSettle         func(ctx context.Context, actual uint64)
}

type releaseTrackingOpen struct {
	releases int
}

func (o *releaseTrackingOpen) Release() {
	o.releases++
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
func (s *stubUsageAdapter) SettleActual(ctx context.Context, verified VerifiedUsageOpen, actual uint64) (*UsageSettlement, error) {
	s.settleCalls++
	s.settledActual = actual
	if s.onSettle != nil {
		s.onSettle(ctx, actual)
	}
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

func TestRequireUsageSettlesAfterHandlerWritesFirst(t *testing.T) {
	adapter := &stubUsageAdapter{
		detect:       true,
		settleResult: &UsageSettlement{Transaction: "sig123", Headers: map[string]string{"x-payment-response": "encoded", "x-payment-settlement-signature": "sig123"}},
	}
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: adapter,
		errorHandler: DefaultErrorHandler,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":`))
		c, ok := ChargeFrom(r.Context())
		if !ok || c == nil {
			t.Fatal("expected Charge in context")
		}
		c.Charge(300_000)
		_, _ = w.Write([]byte(`true}`))
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "abc")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if adapter.settleCalls != 1 {
		t.Fatalf("settle calls = %d, want 1", adapter.settleCalls)
	}
	if adapter.settledActual != 300_000 {
		t.Fatalf("settled actual = %d, want 300000", adapter.settledActual)
	}
	if rr.Header().Get("x-payment-settlement-signature") != "sig123" {
		t.Fatalf("settlement header missing: %s", rr.Header().Get("x-payment-settlement-signature"))
	}
	if strings.TrimSpace(rr.Body.String()) != `{"ok":true}` {
		t.Fatalf("body = %q, want JSON from handler", rr.Body.String())
	}
}

func TestRequireUsageSettlesOnlyAfterHandlerReturns(t *testing.T) {
	handlerReturned := false
	adapter := &stubUsageAdapter{
		detect: true,
		onSettle: func(context.Context, uint64) {
			if !handlerReturned {
				t.Error("settlement ran before handler returned")
			}
		},
	}
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: adapter,
		errorHandler: DefaultErrorHandler,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { handlerReturned = true }()
		c, ok := ChargeFrom(r.Context())
		if !ok || c == nil {
			t.Fatal("expected Charge in context")
		}
		c.Charge(400_000)
		_, _ = w.Write([]byte("ok"))
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "abc")
	h.ServeHTTP(rr, req)

	if adapter.settleCalls != 1 {
		t.Fatalf("settle calls = %d, want 1", adapter.settleCalls)
	}
	if adapter.settledActual != 400_000 {
		t.Fatalf("settled actual = %d, want 400000", adapter.settledActual)
	}
}

func TestRequireUsageSettlesAndReleasesOnHandlerPanic(t *testing.T) {
	verified := &releaseTrackingOpen{}
	adapter := &stubUsageAdapter{detect: true, verified: verified}
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: adapter,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("handler boom")
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "abc")
	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("expected handler panic to propagate")
			}
		}()
		h.ServeHTTP(rr, req)
	}()

	if adapter.settleCalls != 1 {
		t.Fatalf("settle calls = %d, want 1", adapter.settleCalls)
	}
	if adapter.settledActual != 0 {
		t.Fatalf("settled actual = %d, want 0", adapter.settledActual)
	}
	if verified.releases != 1 {
		t.Fatalf("verified open releases = %d, want 1", verified.releases)
	}
	if strings.Contains(rr.Body.String(), `{"ok":true}`) {
		t.Fatalf("protected body leaked after panic: %s", rr.Body.String())
	}
}

func TestRequireUsageStartsSettlementTimeoutAfterHandlerReturns(t *testing.T) {
	previousTimeout := usageSettlementTimeout
	usageSettlementTimeout = 40 * time.Millisecond
	defer func() { usageSettlementTimeout = previousTimeout }()

	var remaining time.Duration
	adapter := &stubUsageAdapter{
		detect: true,
		onSettle: func(ctx context.Context, _ uint64) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Error("settlement context has no deadline")
				return
			}
			remaining = time.Until(deadline)
		},
	}
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: adapter,
		errorHandler: DefaultErrorHandler,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(25 * time.Millisecond)
		c, ok := ChargeFrom(r.Context())
		if !ok || c == nil {
			t.Fatal("expected Charge in context")
		}
		c.Charge(300_000)
		_, _ = w.Write([]byte("ok"))
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "abc")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if adapter.settleCalls != 1 {
		t.Fatalf("settle calls = %d, want 1", adapter.settleCalls)
	}
	if remaining < 30*time.Millisecond {
		t.Fatalf("settlement timeout started before handler returned: remaining %s", remaining)
	}
}

func TestRequireUsageRequiresChargeBeforeResponse(t *testing.T) {
	verified := &releaseTrackingOpen{}
	adapter := &stubUsageAdapter{detect: true, verified: verified}
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: adapter,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "abc")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rr.Code)
	}
	if adapter.settleCalls != 1 {
		t.Fatalf("settle calls = %d, want 1", adapter.settleCalls)
	}
	if adapter.settledActual != 0 {
		t.Fatalf("settled actual = %d, want 0", adapter.settledActual)
	}
	if verified.releases != 1 {
		t.Fatalf("verified open releases = %d, want 1", verified.releases)
	}
	if strings.Contains(rr.Body.String(), `{"ok":true}`) {
		t.Fatalf("protected body leaked when handler omitted Charge: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"settlement_failed"`) {
		t.Fatalf("expected settlement_failed code in body, got %s", rr.Body.String())
	}
}

func TestRequireUsageRejectsZeroChargeBeforeResponse(t *testing.T) {
	verified := &releaseTrackingOpen{}
	adapter := &stubUsageAdapter{detect: true, verified: verified}
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: adapter,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := ChargeFrom(r.Context())
		c.Charge(0)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "abc")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rr.Code)
	}
	if adapter.settleCalls != 1 {
		t.Fatalf("settle calls = %d, want 1", adapter.settleCalls)
	}
	if adapter.settledActual != 0 {
		t.Fatalf("settled actual = %d, want 0", adapter.settledActual)
	}
	if verified.releases != 1 {
		t.Fatalf("verified open releases = %d, want 1", verified.releases)
	}
	if strings.Contains(rr.Body.String(), `{"ok":true}`) {
		t.Fatalf("protected body leaked after zero Charge: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"settlement_failed"`) {
		t.Fatalf("expected settlement_failed code in body, got %s", rr.Body.String())
	}
}

func TestRequireUsagePreservesMissingChargeReasonWhenZeroSettlementFails(t *testing.T) {
	verified := &releaseTrackingOpen{}
	adapter := &stubUsageAdapter{
		detect:    true,
		verified:  verified,
		settleErr: errors.New("rpc unavailable"),
	}
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: adapter,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "abc")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rr.Code)
	}
	if adapter.settleCalls != 1 {
		t.Fatalf("settle calls = %d, want 1", adapter.settleCalls)
	}
	if adapter.settledActual != 0 {
		t.Fatalf("settled actual = %d, want 0", adapter.settledActual)
	}
	if verified.releases != 1 {
		t.Fatalf("verified open releases = %d, want 1", verified.releases)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`"code":"settlement_failed"`,
		"usage Charge must be called before the handler returns",
		"zero-amount settlement failed",
		"rpc unavailable",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected %q in body, got %s", want, body)
		}
	}
	if strings.Contains(body, `{"ok":true}`) {
		t.Fatalf("protected body leaked after zero settlement failure: %s", body)
	}
}

func TestRequireUsagePreservesZeroChargeReasonWhenZeroSettlementFails(t *testing.T) {
	verified := &releaseTrackingOpen{}
	adapter := &stubUsageAdapter{
		detect:    true,
		verified:  verified,
		settleErr: errors.New("rpc unavailable"),
	}
	client := &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: adapter,
	}
	gate := Gate{Amount: MustParseUSD("1.00"), Kind: GateUsage, Name: "test"}
	h := client.RequireUsage(gate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := ChargeFrom(r.Context())
		c.Charge(0)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/usage", nil)
	req.Header.Set("Payment-Signature", "abc")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rr.Code)
	}
	if adapter.settleCalls != 1 {
		t.Fatalf("settle calls = %d, want 1", adapter.settleCalls)
	}
	if adapter.settledActual != 0 {
		t.Fatalf("settled actual = %d, want 0", adapter.settledActual)
	}
	if verified.releases != 1 {
		t.Fatalf("verified open releases = %d, want 1", verified.releases)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`"code":"settlement_failed"`,
		"usage Charge must be greater than zero",
		"zero-amount settlement failed",
		"rpc unavailable",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected %q in body, got %s", want, body)
		}
	}
	if strings.Contains(body, `{"ok":true}`) {
		t.Fatalf("protected body leaked after zero settlement failure: %s", body)
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

func TestRequireUsageDefaultErrorHandlerPreservesUsageCode(t *testing.T) {
	client := &Client{
		Config: Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: &stubUsageAdapter{
			detect:           true,
			verifyOpenErr:    &PaymentError{Code: "invalid_proof", Err: errors.New("bad signature")},
			challengeHeaders: map[string]string{"payment-required": "abc"},
			acceptsEntry:     stubAcceptsEntry{},
		},
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
	if !strings.Contains(rr.Body.String(), `"code":"invalid_proof"`) {
		t.Fatalf("expected invalid_proof code in body, got %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"detail":"bad signature"`) {
		t.Fatalf("expected detail in body, got %s", rr.Body.String())
	}
}

func TestRequireUsageHandlesSettleError(t *testing.T) {
	client := &Client{
		Config: Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		usageAdapter: &stubUsageAdapter{
			detect:    true,
			settleErr: errors.New("settlement broadcast failed"),
		},
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
	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", rr.Code)
	}
	if strings.Contains(rr.Body.String(), `{"ok":true}`) {
		t.Fatalf("protected body leaked after settlement failure: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"settlement_failed"`) {
		t.Fatalf("expected settlement_failed code in body, got %s", rr.Body.String())
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
