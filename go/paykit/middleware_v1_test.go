package paykit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// captureAdapter records the AdapterRequest it was handed so the
// X-PAYMENT (legacy) header threading can be asserted.
type captureAdapter struct {
	protocol Protocol
	pmt      *Payment
	seen     *AdapterRequest
}

func (a *captureAdapter) Protocol() Protocol              { return a.protocol }
func (a *captureAdapter) AcceptsEntry(*Gate) AcceptsEntry { return fakeAccepts{a.protocol} }
func (a *captureAdapter) ChallengeHeaders(*Gate) map[string]string {
	return map[string]string{"payment-required": "x"}
}
func (a *captureAdapter) VerifyAndSettle(req *AdapterRequest) (*Payment, error) {
	a.seen = req
	return a.pmt, nil
}

func x402Client(adapter Adapter) *Client {
	return &Client{
		Config:       Config{Network: SolanaLocalnet, Accept: []Protocol{X402}},
		x402Adapter:  adapter,
		errorHandler: DefaultErrorHandler,
	}
}

// TestPickAdapterSelectsX402OnLegacyHeader proves a request carrying only
// the legacy X-PAYMENT header (no Payment-Signature) still routes to the
// x402 adapter, and the header value is threaded as PaymentSigLegacy.
func TestPickAdapterSelectsX402OnLegacyHeader(t *testing.T) {
	pmt := &Payment{Protocol: X402, Gate: "g", Transaction: "sig"}
	ad := &captureAdapter{protocol: X402, pmt: pmt}
	c := x402Client(ad)

	var paid bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paid = IsPaid(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-PAYMENT", "legacy-credential")
	rec := httptest.NewRecorder()
	c.RequireFunc(func(*http.Request) (Gate, error) {
		return Gate{Amount: MustParseUSD("0.10")}, nil
	})(next).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", rec.Code)
	}
	if !paid {
		t.Error("legacy X-PAYMENT request should be treated as paid")
	}
	if ad.seen == nil || ad.seen.PaymentSigLegacy != "legacy-credential" {
		t.Errorf("PaymentSigLegacy not threaded: %+v", ad.seen)
	}
	if ad.seen.PaymentSig != "" {
		t.Error("PaymentSig should be empty when only X-PAYMENT is present")
	}
}

// TestPickAdapterThreadsBothHeaders proves the canonical Payment-Signature
// and the legacy X-PAYMENT are both surfaced to the adapter so it can apply
// its own precedence.
func TestPickAdapterThreadsBothHeaders(t *testing.T) {
	ad := &captureAdapter{protocol: X402, pmt: &Payment{Protocol: X402}}
	c := x402Client(ad)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Payment-Signature", "v2-cred")
	r.Header.Set("X-PAYMENT", "v1-cred")
	rec := httptest.NewRecorder()
	c.RequireFunc(func(*http.Request) (Gate, error) {
		return Gate{Amount: MustParseUSD("0.10")}, nil
	})(next).ServeHTTP(rec, r)

	if ad.seen.PaymentSig != "v2-cred" || ad.seen.PaymentSigLegacy != "v1-cred" {
		t.Errorf("both headers should be threaded: %+v", ad.seen)
	}
}
