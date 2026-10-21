package paykit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeAccepts struct{ s Protocol }

func (a fakeAccepts) AcceptsProtocol() Protocol { return a.s }

type fakeAdapter struct {
	protocol Protocol
	pmt      *Payment
	err      error
}

func (f *fakeAdapter) Protocol() Protocol              { return f.protocol }
func (f *fakeAdapter) AcceptsEntry(*Gate) AcceptsEntry { return fakeAccepts{f.protocol} }
func (f *fakeAdapter) ChallengeHeaders(*Gate) map[string]string {
	return map[string]string{"x-fake": "1"}
}
func (f *fakeAdapter) VerifyAndSettle(*AdapterRequest) (*Payment, error) {
	return f.pmt, f.err
}

func newTestClient(adapter Adapter) *Client {
	return &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{MPP}},
		mppAdapter:   adapter,
		errorHandler: DefaultErrorHandler,
	}
}

func paidRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Payment dGVzdA==")
	return r
}

func TestRequireFuncSuccess(t *testing.T) {
	pmt := &Payment{Protocol: MPP, Gate: "g", Transaction: "sig123", SettlementHeaders: map[string]string{"x-payment-settlement-signature": "sig123"}}
	c := newTestClient(&fakeAdapter{protocol: MPP, pmt: pmt})

	var seen bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PaymentFrom(r.Context())
		seen = ok && p.Transaction == "sig123"
		if !IsPaid(r.Context()) {
			t.Error("IsPaid should be true inside the gated handler")
		}
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	c.RequireFunc(func(*http.Request) (Gate, error) {
		return Gate{Amount: MustParseUSD("0.10")}, nil
	})(next).ServeHTTP(rec, paidRequest())

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", rec.Code)
	}
	if !seen {
		t.Error("payment not attached to context")
	}
	if rec.Header().Get("x-payment-settlement-signature") != "sig123" {
		t.Error("settlement header not stamped")
	}
}

func TestRequireFuncGateResolutionError(t *testing.T) {
	c := newTestClient(&fakeAdapter{protocol: MPP})
	rec := httptest.NewRecorder()
	c.RequireFunc(func(*http.Request) (Gate, error) {
		return Gate{}, errors.New("boom")
	})(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestRequireFuncInvalidGate(t *testing.T) {
	c := newTestClient(&fakeAdapter{protocol: MPP})
	rec := httptest.NewRecorder()
	// x402 + fees is an incompatible combination that fails Validate.
	bad := Gate{
		Amount:   MustParseUSD("1.00"),
		Accept:   []Protocol{X402},
		FeeOnTop: Fees{Address("PLATFORM"): MustParseUSD("0.50")},
	}
	c.RequireFunc(func(*http.Request) (Gate, error) { return bad, nil })(okHandler()).ServeHTTP(rec, paidRequest())
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestRequireFuncNoAdapter(t *testing.T) {
	c := newTestClient(nil) // mppAdapter nil -> pickAdapter returns nil
	rec := httptest.NewRecorder()
	c.RequireFunc(func(*http.Request) (Gate, error) {
		return Gate{Amount: MustParseUSD("0.10")}, nil
	})(okHandler()).ServeHTTP(rec, paidRequest())
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestRequireFuncWrapsNonPaymentError(t *testing.T) {
	c := newTestClient(&fakeAdapter{protocol: MPP, err: errors.New("plain")})
	rec := httptest.NewRecorder()
	c.RequireFunc(func(*http.Request) (Gate, error) {
		return Gate{Amount: MustParseUSD("0.10")}, nil
	})(okHandler()).ServeHTTP(rec, paidRequest())
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestRequireFuncPaymentError(t *testing.T) {
	c := newTestClient(&fakeAdapter{protocol: MPP, err: &PaymentError{Code: "charge_request_mismatch", Err: ErrInvalidProof}})
	rec := httptest.NewRecorder()
	c.RequireFunc(func(*http.Request) (Gate, error) {
		return Gate{Amount: MustParseUSD("0.10")}, nil
	})(okHandler()).ServeHTTP(rec, paidRequest())
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestRequireStaticGate(t *testing.T) {
	pmt := &Payment{Protocol: MPP, Gate: "g", Transaction: "sig"}
	c := newTestClient(&fakeAdapter{protocol: MPP, pmt: pmt})
	rec := httptest.NewRecorder()
	c.Require(Gate{Amount: MustParseUSD("0.10")})(okHandler()).ServeHTTP(rec, paidRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", rec.Code)
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

// A credential whose payment is still settling is answered with 409 and no
// challenge, so the client retries it instead of paying a fresh one; any
// other verification failure keeps the 402 re-challenge.
func TestRequireFuncSettlementInProgressIsNotRechallenged(t *testing.T) {
	gate := func(*http.Request) (Gate, error) { return Gate{Amount: MustParseUSD("0.10")}, nil }

	c := newTestClient(&fakeAdapter{protocol: MPP, err: &PaymentError{Code: CodeSettlementInProgress, Err: errors.New("pending")}})
	rec := httptest.NewRecorder()
	c.RequireFunc(gate)(okHandler()).ServeHTTP(rec, paidRequest())
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409", rec.Code)
	}
	if rec.Header().Get("x-fake") != "" {
		t.Error("settlement-in-progress response must not carry a challenge")
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After")
	}

	c = newTestClient(&fakeAdapter{protocol: MPP, err: &PaymentError{Code: "invalid_proof", Err: errors.New("bad")}})
	rec = httptest.NewRecorder()
	c.RequireFunc(gate)(okHandler()).ServeHTTP(rec, paidRequest())
	if rec.Code != http.StatusPaymentRequired || rec.Header().Get("x-fake") == "" {
		t.Fatalf("invalid proof: got %d challenge=%q, want 402 with a challenge", rec.Code, rec.Header().Get("x-fake"))
	}
}
