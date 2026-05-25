package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/protocol/intents"
)

// resignEcho recomputes the HMAC ID after a test mutates one of the
// echoed-but-not-HMAC'd fields (e.g. realm). HMAC is computed with the
// SERVER's realm at verify time, so a tampered echoed realm will pass the
// HMAC check unless re-signed with the server's secret. The Tier-2 backstop
// must catch it after HMAC succeeds.
func resignEcho(secret string, echo *mpp.ChallengeEcho) {
	echo.ID = mpp.ComputeChallengeID(
		secret,
		echo.Realm,
		string(echo.Method),
		string(echo.Intent),
		echo.Request.Raw(),
		echo.Expires,
		echo.Digest,
		opaqueRaw(echo.Opaque),
	)
}

// signatureCredentialFromEcho returns a credential whose payload is a bogus
// signature; the tests below all fail before settlement, so we never touch RPC.
func signatureCredentialFromEcho(t *testing.T, echo mpp.ChallengeEcho) mpp.PaymentCredential {
	t.Helper()
	cred, err := mpp.NewPaymentCredential(echo, map[string]any{
		"type":      "signature",
		"signature": "5UfDuX6nSqMzMR8W7n6K3b1GKLmaqEisBFCcYPRLjNHrCbVQJF3BVjkE7aQJMQ2Kx",
	})
	if err != nil {
		t.Fatalf("build credential: %v", err)
	}
	return cred
}

func opaqueRaw(o *mpp.Base64URLJSON) string {
	if o == nil {
		return ""
	}
	return o.Raw()
}

func TestVerifyCredentialTier2RejectsTamperedRealm(t *testing.T) {
	handler, _, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	echo := challenge.ToEcho()
	echo.Realm = "Attacker Realm"
	resignEcho(cfg.SecretKey, &echo)

	cred := signatureCredentialFromEcho(t, echo)
	_, err = handler.VerifyCredential(context.Background(), cred)
	if err == nil {
		t.Fatalf("expected Tier-2 to reject tampered realm")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "realm") {
		t.Fatalf("expected realm error, got: %v", err)
	}
}

func TestVerifyCredentialTier2RejectsTamperedMethod(t *testing.T) {
	handler, _, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	echo := challenge.ToEcho()
	echo.Method = mpp.NewMethodName("stripe")
	resignEcho(cfg.SecretKey, &echo)

	cred := signatureCredentialFromEcho(t, echo)
	_, err = handler.VerifyCredential(context.Background(), cred)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "method") {
		t.Fatalf("expected method error, got: %v", err)
	}
}

func TestVerifyCredentialTier2RejectsNonChargeIntent(t *testing.T) {
	handler, _, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	echo := challenge.ToEcho()
	echo.Intent = mpp.NewIntentName("session")
	resignEcho(cfg.SecretKey, &echo)

	cred := signatureCredentialFromEcho(t, echo)
	_, err = handler.VerifyCredential(context.Background(), cred)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "intent") {
		t.Fatalf("expected intent error, got: %v", err)
	}
}

func TestVerifyCredentialTier2RejectsTamperedCurrency(t *testing.T) {
	handler, _, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	var req intents.ChargeRequest
	if decErr := challenge.Request.Decode(&req); decErr != nil {
		t.Fatalf("decode request: %v", decErr)
	}
	req.Currency = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	tamperedReq, err := mpp.NewBase64URLJSONValue(req)
	if err != nil {
		t.Fatalf("re-encode request: %v", err)
	}

	echo := challenge.ToEcho()
	echo.Request = tamperedReq
	resignEcho(cfg.SecretKey, &echo)

	cred := signatureCredentialFromEcho(t, echo)
	_, err = handler.VerifyCredential(context.Background(), cred)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "currency") {
		t.Fatalf("expected currency error, got: %v", err)
	}
}

func TestVerifyCredentialTier2RejectsTamperedRecipient(t *testing.T) {
	handler, _, cfg := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	var req intents.ChargeRequest
	if decErr := challenge.Request.Decode(&req); decErr != nil {
		t.Fatalf("decode request: %v", decErr)
	}
	req.Recipient = testutil.NewPrivateKey().PublicKey().String()
	tamperedReq, err := mpp.NewBase64URLJSONValue(req)
	if err != nil {
		t.Fatalf("re-encode request: %v", err)
	}

	echo := challenge.ToEcho()
	echo.Request = tamperedReq
	resignEcho(cfg.SecretKey, &echo)

	cred := signatureCredentialFromEcho(t, echo)
	_, err = handler.VerifyCredential(context.Background(), cred)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "recipient") {
		t.Fatalf("expected recipient error, got: %v", err)
	}
}

// Cross-route replay: a credential whose claimed amount is 0.001 must not
// satisfy a route that expects 1.0.
func TestVerifyCredentialWithExpectedRejectsAmountMismatch(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	cheap, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	echo := cheap.ToEcho()
	cred := signatureCredentialFromEcho(t, echo)

	// Build the expensive route's expected request.
	expensive, err := handler.Charge(context.Background(), "1")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	var expected intents.ChargeRequest
	if decErr := expensive.Request.Decode(&expected); decErr != nil {
		t.Fatalf("decode: %v", decErr)
	}

	_, err = handler.VerifyCredentialWithExpected(context.Background(), cred, expected)
	if err == nil {
		t.Fatalf("expected route-aware verify to reject cross-route credential")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "amount") {
		t.Fatalf("expected amount mismatch error, got: %v", err)
	}
	var paymentErr *mpp.Error
	if !mppErrAs(err, &paymentErr) {
		t.Fatalf("expected mpp.Error, got %T: %v", err, err)
	}
	if paymentErr.Code != mpp.ErrCodeAmountMismatch {
		t.Fatalf("expected code amount-mismatch, got %s", paymentErr.Code)
	}
}

// Sanity check: a credential that matches the route's expected request must
// reach settlement (it'll fail downstream because the payload is bogus, but
// the failure must NOT be a binding/Tier-2 mismatch).
func TestVerifyCredentialWithExpectedAcceptsMatchingRoute(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	echo := challenge.ToEcho()
	cred := signatureCredentialFromEcho(t, echo)

	var expected intents.ChargeRequest
	if decErr := challenge.Request.Decode(&expected); decErr != nil {
		t.Fatalf("decode: %v", decErr)
	}

	_, err = handler.VerifyCredentialWithExpected(context.Background(), cred, expected)
	// We expect settlement-side failure (signature lookup will not find the
	// fake signature on the fake RPC), NOT a binding error.
	if err == nil {
		// If somehow this passes, fine — but it should never fail on
		// "amount mismatch" / "currency mismatch" / "recipient mismatch".
		return
	}
	bad := []string{"amount mismatch", "currency mismatch", "recipient does not match", "credential method", "credential intent", "credential realm"}
	low := strings.ToLower(err.Error())
	for _, snippet := range bad {
		if strings.Contains(low, snippet) {
			t.Fatalf("matching route incorrectly tripped binding check: %v", err)
		}
	}
}

// mppErrAs is a small wrapper to avoid pulling errors.As into every test.
func mppErrAs(err error, target **mpp.Error) bool {
	if err == nil {
		return false
	}
	if pe, ok := err.(*mpp.Error); ok {
		*target = pe
		return true
	}
	// Try unwrapping one level.
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		return mppErrAs(u.Unwrap(), target)
	}
	return false
}

// Self-check the test harness: ensure NewBase64URLJSONValue + Decode round-trip,
// otherwise the tampering tests would silently no-op.
func TestRequestRoundTrip(t *testing.T) {
	in := intents.ChargeRequest{Amount: "1000", Currency: "sol", Recipient: "x"}
	v, err := mpp.NewBase64URLJSONValue(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var out intents.ChargeRequest
	if err := v.Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Amount != in.Amount || out.Currency != in.Currency {
		t.Fatalf("round trip lost data: %+v", out)
	}
	// Sanity: ensure JSON marshal/unmarshal doesn't reorder in a way that
	// breaks raw-byte equality (used by HMAC).
	raw1, _ := json.Marshal(in)
	raw2, _ := json.Marshal(out)
	if string(raw1) != string(raw2) {
		t.Fatalf("json mismatch: %s vs %s", raw1, raw2)
	}
}

func TestVerifyCredentialWithExpectedRejectsCurrencyMismatchAssertsCode(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	cred := signatureCredentialFromEcho(t, challenge.ToEcho())

	var expected intents.ChargeRequest
	if decErr := challenge.Request.Decode(&expected); decErr != nil {
		t.Fatalf("decode: %v", decErr)
	}
	expected.Currency = "USDC"

	_, err = handler.VerifyCredentialWithExpected(context.Background(), cred, expected)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "currency") {
		t.Fatalf("expected currency mismatch, got: %v", err)
	}
	var paymentErr *mpp.Error
	if !mppErrAs(err, &paymentErr) || paymentErr.Code != mpp.ErrCodeChallengeRouteMismatch {
		t.Fatalf("expected challenge-route-mismatch mpp error, got %T: %v", err, err)
	}
}

func TestVerifyCredentialWithExpectedRejectsRecipientMismatchAssertsCode(t *testing.T) {
	handler, _, _ := newTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "0.001")
	if err != nil {
		t.Fatalf("charge: %v", err)
	}
	cred := signatureCredentialFromEcho(t, challenge.ToEcho())

	var expected intents.ChargeRequest
	if decErr := challenge.Request.Decode(&expected); decErr != nil {
		t.Fatalf("decode: %v", decErr)
	}
	expected.Recipient = testutil.NewPrivateKey().PublicKey().String()

	_, err = handler.VerifyCredentialWithExpected(context.Background(), cred, expected)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "recipient") {
		t.Fatalf("expected recipient mismatch, got: %v", err)
	}
	var paymentErr *mpp.Error
	if !mppErrAs(err, &paymentErr) || paymentErr.Code != mpp.ErrCodeRecipientMismatch {
		t.Fatalf("expected recipient-mismatch mpp error, got %T: %v", err, err)
	}
}
