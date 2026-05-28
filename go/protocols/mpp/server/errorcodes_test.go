package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/errorcodes"
)

// decode402Body asserts the response is a 402 with the canonical
// problem+json shape and returns the parsed body.
func decode402Body(t *testing.T, rr *httptest.ResponseRecorder) errorcodes.PaymentRequiredBody {
	t.Helper()
	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); !strings.Contains(got, "application/problem+json") {
		t.Fatalf("expected problem+json content type, got %q", got)
	}
	var body errorcodes.PaymentRequiredBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal 402 body: %v (raw=%s)", err, rr.Body.String())
	}
	if body.Status != 402 {
		t.Fatalf("expected status 402 in body, got %d", body.Status)
	}
	if body.Title != "Payment Required" {
		t.Fatalf("expected canonical title, got %q", body.Title)
	}
	if !errorcodes.IsCanonical(body.Code) {
		t.Fatalf("expected canonical code, got %q", body.Code)
	}
	if body.Code != body.Error {
		t.Fatalf("expected error alias to mirror code, got code=%q error=%q", body.Code, body.Error)
	}
	if !strings.HasSuffix(body.Type, "/"+body.Code) {
		t.Fatalf("expected type URL to end in canonical code, got %q", body.Type)
	}
	return body
}

func TestMiddlewareNoCredentialEmitsPaymentInvalidCode(t *testing.T) {
	m := newMiddlewareTestMpp(t)
	handler := PaymentMiddleware(m, constantCharge("0.001"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := decode402Body(t, rr)
	if body.Code != errorcodes.PaymentInvalid {
		t.Fatalf("expected payment_invalid on no-credential 402, got %q", body.Code)
	}
}

func TestMiddlewareMalformedCredentialEmitsPaymentInvalidCode(t *testing.T) {
	m := newMiddlewareTestMpp(t)
	handler := PaymentMiddleware(m, constantCharge("0.001"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	req.Header.Set(core.AuthorizationHeader, "Payment not-a-valid-credential")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := decode402Body(t, rr)
	if body.Code != errorcodes.PaymentInvalid {
		t.Fatalf("expected payment_invalid on malformed credential, got %q", body.Code)
	}
	if body.Message == "" {
		t.Fatal("expected non-empty message for malformed credential")
	}
}

func TestMiddlewareAmountMismatchEmitsChargeRequestMismatchCode(t *testing.T) {
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
		t.Fatalf("new mpp: %v", err)
	}
	// Build a credential against a 0.001 challenge, then submit it to
	// a route whose expected amount is 0.002 so the verifier returns
	// an amount-mismatch ErrCode that maps to charge_request_mismatch.
	challenge, err := m.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	authHeader, err := client.BuildCredentialHeader(context.Background(), signer, rpcClient, challenge)
	if err != nil {
		t.Fatalf("build credential: %v", err)
	}

	handler := PaymentMiddleware(m, constantCharge("0.002"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("downstream handler should not run on mismatch")
	}))
	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	req.Header.Set(core.AuthorizationHeader, authHeader)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := decode402Body(t, rr)
	if body.Code != errorcodes.ChargeRequestMismatch {
		t.Fatalf("expected charge_request_mismatch, got %q (message=%q)", body.Code, body.Message)
	}
}

func TestMiddlewareJSONBodyKeyOrderIsCanonical(t *testing.T) {
	// The JSON body keys must marshal alphabetically (code, error,
	// message, status, title, type) so cross-SDK canonicalization
	// stays byte-stable. Verifying the literal ordering catches a
	// regression if someone reorders the PaymentRequiredBody struct.
	m := newMiddlewareTestMpp(t)
	handler := PaymentMiddleware(m, constantCharge("0.001"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	raw := rr.Body.String()
	codeIdx := strings.Index(raw, `"code"`)
	errorIdx := strings.Index(raw, `"error"`)
	messageIdx := strings.Index(raw, `"message"`)
	statusIdx := strings.Index(raw, `"status"`)
	titleIdx := strings.Index(raw, `"title"`)
	typeIdx := strings.Index(raw, `"type"`)
	if codeIdx < 0 || codeIdx >= errorIdx || errorIdx >= messageIdx || messageIdx >= statusIdx || statusIdx >= titleIdx || titleIdx >= typeIdx {
		t.Fatalf("expected canonical key order (code,error,message,status,title,type), got %s", raw)
	}
}

func TestCanonicalMapperCoversEveryVerifierErrorCode(t *testing.T) {
	// Coverage net: every ErrorCode emitted by the verifier must map
	// to a canonical L6 code. The mapper falls back to payment_invalid
	// for anything else; this list mirrors what the server/verifier
	// can produce so we catch a regression if a new ErrorCode is added
	// without a mapping.
	tests := []struct {
		in  core.ErrorCode
		out string
	}{
		{core.ErrCodeAmountMismatch, errorcodes.ChargeRequestMismatch},
		{core.ErrCodeRecipientMismatch, errorcodes.ChargeRequestMismatch},
		{core.ErrCodeSplitsExceed, errorcodes.ChargeRequestMismatch},
		{core.ErrCodeTooManySplits, errorcodes.ChargeRequestMismatch},
		{core.ErrCodeChallengeRouteMismatch, errorcodes.ChallengeRouteMismatch},
		{core.ErrCodeMintMismatch, errorcodes.ChallengeRouteMismatch},
		{core.ErrCodeInvalidMethod, errorcodes.ChallengeRouteMismatch},
		{core.ErrCodeChallengeMismatch, errorcodes.ChallengeVerificationFailed},
		{core.ErrCodeChallengeExpired, errorcodes.ChallengeExpired},
		{core.ErrCodeWrongNetwork, errorcodes.WrongNetwork},
		{core.ErrCodeSignatureConsumed, errorcodes.SignatureConsumed},
		{core.ErrCodeInvalidPayload, errorcodes.PaymentInvalid},
		{core.ErrCodeMissingTransaction, errorcodes.PaymentInvalid},
		{core.ErrCodeMissingSignature, errorcodes.PaymentInvalid},
		{core.ErrCodeNoTransfer, errorcodes.PaymentInvalid},
		{core.ErrCodeTransactionFailed, errorcodes.PaymentInvalid},
		{core.ErrCodeTransactionNotFound, errorcodes.PaymentInvalid},
		{core.ErrCodeSimulationFailed, errorcodes.PaymentInvalid},
		{core.ErrCodeRPC, errorcodes.PaymentInvalid},
		{core.ErrCodeInvalidConfig, errorcodes.PaymentInvalid},
		{core.ErrCodeOther, errorcodes.PaymentInvalid},
	}
	for _, tc := range tests {
		t.Run(string(tc.in), func(t *testing.T) {
			if got := errorcodes.Canonical(tc.in); got != tc.out {
				t.Fatalf("Canonical(%q) = %q, want %q", tc.in, got, tc.out)
			}
			if got := errorcodes.CanonicalFromError(core.NewError(tc.in, "x")); got != tc.out {
				t.Fatalf("CanonicalFromError(NewError(%q, _)) = %q, want %q", tc.in, got, tc.out)
			}
		})
	}
}

func TestCanonicalFromErrorFallback(t *testing.T) {
	if got := errorcodes.CanonicalFromError(nil); got != errorcodes.PaymentInvalid {
		t.Fatalf("expected nil to map to payment_invalid, got %q", got)
	}
	if got := errorcodes.CanonicalFromError(errPlain("not an mpp error")); got != errorcodes.PaymentInvalid {
		t.Fatalf("expected non-SDK error to map to payment_invalid, got %q", got)
	}
	if got := errorcodes.Canonical(core.ErrorCode("brand-new-unknown-code")); got != errorcodes.PaymentInvalid {
		t.Fatalf("expected unknown code to map to payment_invalid, got %q", got)
	}
}

type errPlain string

func (e errPlain) Error() string { return string(e) }
