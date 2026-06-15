package wire

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestWWWAuthenticateRoundTrip(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000", "currency": "sol"})
	challenge := NewChallengeWithSecretFull("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request, "2030-01-01T00:00:00Z", "", "desc", nil)
	header, err := FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format failed: %v", err)
	}
	parsed, err := ParseWWWAuthenticate(header)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.ID != challenge.ID || parsed.Realm != challenge.Realm || parsed.Request.Raw() != challenge.Request.Raw() {
		t.Fatalf("unexpected parsed challenge: %#v", parsed)
	}
}

func TestAuthorizationRoundTrip(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	challenge := NewChallengeWithSecret("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	credential, err := NewPaymentCredential(challenge.ToEcho(), map[string]string{"type": "transaction", "transaction": "abc"})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	header, err := FormatAuthorization(credential)
	if err != nil {
		t.Fatalf("format failed: %v", err)
	}
	parsed, err := ParseAuthorization(header)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.Challenge.ID != challenge.ID {
		t.Fatalf("unexpected parsed credential: %#v", parsed)
	}
}

func TestReceiptRoundTrip(t *testing.T) {
	header, err := FormatReceipt(Receipt{Status: ReceiptStatusSuccess, Method: "solana", Timestamp: "2026-01-01T00:00:00Z", Reference: "sig", ChallengeID: "id"})
	if err != nil {
		t.Fatalf("format failed: %v", err)
	}
	receipt, err := ParseReceipt(header)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if receipt.Reference != "sig" {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
}

func TestSortedHeaderParams(t *testing.T) {
	params := SortedHeaderParams(map[string]string{"b": "2", "a": "1"})
	if len(params) != 2 || params[0] != "a=1" || params[1] != "b=2" {
		t.Fatalf("unexpected params %#v", params)
	}
}

func TestParseWWWAuthenticateMissingRequiredFields(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	tests := []struct {
		name   string
		header string
	}{
		{"missing id", `Payment realm="r", method="solana", intent="charge", request="` + request.Raw() + `"`},
		{"missing realm", `Payment id="abc", method="solana", intent="charge", request="` + request.Raw() + `"`},
		{"missing intent", `Payment id="abc", realm="r", method="solana", request="` + request.Raw() + `"`},
		{"missing request", `Payment id="abc", realm="r", method="solana", intent="charge"`},
		{"wrong scheme", `Bearer id="abc", realm="r", method="solana", intent="charge", request="` + request.Raw() + `"`},
		{"invalid method", `Payment id="abc", realm="r", method="123", intent="charge", request="` + request.Raw() + `"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseWWWAuthenticate(tc.header); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseWWWAuthenticateWithOpaqueAndDigest(t *testing.T) {
	opaque, _ := NewBase64URLJSONValue(map[string]string{"session": "xyz"})
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	challenge := NewChallengeWithSecretFull("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request, "2030-01-01T00:00:00Z", "sha256=abc", "description", &opaque)
	header, err := FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format failed: %v", err)
	}
	parsed, err := ParseWWWAuthenticate(header)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.Digest != "sha256=abc" {
		t.Fatalf("expected digest, got %q", parsed.Digest)
	}
	if parsed.Opaque == nil {
		t.Fatal("expected opaque to be set")
	}
	if parsed.Opaque.Raw() != opaque.Raw() {
		t.Fatalf("opaque mismatch: got %q, want %q", parsed.Opaque.Raw(), opaque.Raw())
	}
	// description round-trips as a top-level header param to match the
	// canonical mpp-tools wire (format emits it, parse keeps it).
	if parsed.Description != "description" {
		t.Fatalf("expected description to round-trip, got %q", parsed.Description)
	}
}

func TestFormatWWWAuthenticateAllOptionalFields(t *testing.T) {
	opaque, _ := NewBase64URLJSONValue(map[string]string{"k": "v"})
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	challenge := PaymentChallenge{
		ID:          "test-id",
		Realm:       "test-realm",
		Method:      NewMethodName("solana"),
		Intent:      NewIntentName("charge"),
		Request:     request,
		Expires:     "2030-01-01T00:00:00Z",
		Description: "buy coffee",
		Digest:      "sha256=abc",
		Opaque:      &opaque,
	}
	header, err := FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format failed: %v", err)
	}
	for _, needle := range []string{`expires="`, `digest="`, `opaque="`} {
		if !contains(header, needle) {
			t.Fatalf("header missing %q: %s", needle, header)
		}
	}
}

func TestParseAuthorizationWrongScheme(t *testing.T) {
	if _, err := ParseAuthorization("Bearer abc123"); err == nil {
		t.Fatal("expected error for non-Payment scheme")
	}
}

func TestParseAuthorizationOversizedToken(t *testing.T) {
	// Build a header with a token > 16KB
	huge := "Payment " + string(make([]byte, 17*1024))
	if _, err := ParseAuthorization(huge); err == nil {
		t.Fatal("expected error for oversized token")
	}
}

func TestParseAuthorizationInvalidBase64(t *testing.T) {
	if _, err := ParseAuthorization("Payment !!!invalid-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestFormatAuthorizationRoundTrip(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "500"})
	challenge := NewChallengeWithSecret("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	original, _ := NewPaymentCredential(challenge.ToEcho(), map[string]string{"type": "transaction", "transaction": "data"})
	header, err := FormatAuthorization(original)
	if err != nil {
		t.Fatalf("format failed: %v", err)
	}
	parsed, err := ParseAuthorization(header)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.Challenge.ID != original.Challenge.ID {
		t.Fatalf("round-trip mismatch: %q != %q", parsed.Challenge.ID, original.Challenge.ID)
	}
	var payload map[string]string
	if err := parsed.PayloadAs(&payload); err != nil {
		t.Fatalf("payload decode failed: %v", err)
	}
	if payload["type"] != "transaction" {
		t.Fatalf("unexpected payload type: %q", payload["type"])
	}
}

func TestParseReceiptFormatReceiptRoundTrip(t *testing.T) {
	original := Receipt{
		Status:      ReceiptStatusSuccess,
		Method:      "solana",
		Timestamp:   "2026-01-01T00:00:00Z",
		Reference:   "sig123",
		ChallengeID: "cid",
		ExternalID:  "ext-1",
	}
	header, err := FormatReceipt(original)
	if err != nil {
		t.Fatalf("format failed: %v", err)
	}
	parsed, err := ParseReceipt(header)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.Reference != "sig123" || parsed.ExternalID != "ext-1" || parsed.ChallengeID != "cid" {
		t.Fatalf("round-trip mismatch: %+v", parsed)
	}
}

func TestExtractPaymentSchemeMultipleSchemes(t *testing.T) {
	header := "Bearer token123, Payment abc456"
	scheme, ok := ExtractPaymentScheme(header)
	if !ok {
		t.Fatal("expected Payment scheme to be found")
	}
	if scheme != "Payment abc456" {
		t.Fatalf("unexpected scheme: %q", scheme)
	}
}

func TestParseWWWAuthenticateAllFiltersNonPaymentChallenges(t *testing.T) {
	header := `Payment id="abc", realm="api", method="solana", intent="charge", request="e30"`
	challenges := ParseWWWAuthenticateAll([]string{
		`Bearer realm="api"`,
		header,
		`Digest realm="api", qop="auth"`,
	})

	if len(challenges) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(challenges))
	}
	if challenges[0].ID != "abc" {
		t.Fatalf("unexpected challenge ID: %q", challenges[0].ID)
	}
}

func TestParseWWWAuthenticateAllMergedPaymentChallenges(t *testing.T) {
	header := `Payment id="abc", realm="api", method="solana", intent="charge", request="e30", Payment id="def", realm="api", method="solana", intent="charge", request="e30"`
	challenges := ParseWWWAuthenticateAll([]string{header})

	if len(challenges) != 2 {
		t.Fatalf("expected 2 challenges, got %d", len(challenges))
	}
	if challenges[0].ID != "abc" || challenges[1].ID != "def" {
		t.Fatalf("unexpected challenge IDs: %#v", challenges)
	}
}

func TestParseWWWAuthenticateAllIgnoresPaymentInsideQuotes(t *testing.T) {
	header := `Payment id="abc", realm="api, Payment realm", method="solana", intent="charge", request="e30", Payment id="def", realm="api", method="solana", intent="charge", request="e30"`
	challenges := ParseWWWAuthenticateAll([]string{header})

	if len(challenges) != 2 {
		t.Fatalf("expected 2 challenges, got %d", len(challenges))
	}
	if challenges[0].Realm != "api, Payment realm" {
		t.Fatalf("unexpected realm: %q", challenges[0].Realm)
	}
	if challenges[1].ID != "def" {
		t.Fatalf("unexpected second challenge ID: %q", challenges[1].ID)
	}
}

func TestParseWWWAuthenticateAllStopsBeforeTrailingScheme(t *testing.T) {
	header := `Payment id="abc", realm="api", method="solana", intent="charge", request="e30", Bearer realm="fallback"`
	challenges := ParseWWWAuthenticateAll([]string{header})

	if len(challenges) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(challenges))
	}
	if challenges[0].ID != "abc" {
		t.Fatalf("unexpected challenge ID: %q", challenges[0].ID)
	}
}

func TestExtractPaymentSchemeNotPresent(t *testing.T) {
	if _, ok := ExtractPaymentScheme("Bearer token123"); ok {
		t.Fatal("expected no Payment scheme")
	}
}

func TestParseWWWAuthenticateInvalidRequestBase64(t *testing.T) {
	header := `Payment id="abc", realm="r", method="solana", intent="charge", request="!!!invalid"`
	if _, err := ParseWWWAuthenticate(header); err == nil {
		t.Fatal("expected error for invalid base64 in request")
	}
}

func TestParseWWWAuthenticateInvalidRequestJSON(t *testing.T) {
	// Valid base64 but not valid JSON
	notJSON := Base64URLEncode([]byte("not json"))
	header := fmt.Sprintf(`Payment id="abc", realm="r", method="solana", intent="charge", request="%s"`, notJSON)
	if _, err := ParseWWWAuthenticate(header); err == nil {
		t.Fatal("expected error for invalid JSON in request")
	}
}

func TestParseAuthParamsDuplicateKey(t *testing.T) {
	// This exercises the duplicate parameter error in parseAuthParams
	header := `Payment id="abc", id="def", realm="r", method="solana", intent="charge", request="dGVzdA"`
	if _, err := ParseWWWAuthenticate(header); err == nil {
		t.Fatal("expected error for duplicate parameter")
	}
}

func TestParseReceiptOversized(t *testing.T) {
	huge := string(make([]byte, 17*1024))
	if _, err := ParseReceipt(huge); err == nil {
		t.Fatal("expected error for oversized receipt")
	}
}

func TestParseReceiptInvalidBase64(t *testing.T) {
	if _, err := ParseReceipt("!!!invalid!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseReceiptInvalidJSON(t *testing.T) {
	notJSON := Base64URLEncode([]byte("not json"))
	if _, err := ParseReceipt(notJSON); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsInner(s, substr))
}

func containsInner(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestParseWWWAuthenticateRejectsMalformedParams(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	tests := []struct {
		name   string
		header string
	}{
		{"unterminated quote", `Payment id="abc, realm="r", method="solana", intent="charge", request="` + request.Raw() + `"`},
		{"duplicate parameter", `Payment id="abc", id="def", realm="r", method="solana", intent="charge", request="` + request.Raw() + `"`},
		{"invalid parameter", `Payment id, realm="r", method="solana", intent="charge", request="` + request.Raw() + `"`},
		{"invalid request json", `Payment id="abc", realm="r", method="solana", intent="charge", request="bm90LWpzb24"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseWWWAuthenticate(tc.header); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseAuthorizationInvalidJSON(t *testing.T) {
	header := PaymentScheme + " " + Base64URLEncode([]byte("not-json"))
	if _, err := ParseAuthorization(header); err == nil {
		t.Fatal("expected invalid credential JSON error")
	}
}

func TestParseReceiptRejectsMalformedValues(t *testing.T) {
	if _, err := ParseReceipt("not-base64"); err == nil {
		t.Fatal("expected invalid base64 receipt error")
	}
	if _, err := ParseReceipt(Base64URLEncode([]byte("not-json"))); err == nil {
		t.Fatal("expected invalid JSON receipt error")
	}
	if _, err := ParseReceipt(string(make([]byte, 17*1024))); err == nil {
		t.Fatal("expected oversized receipt error")
	}
}

func TestFormatAuthorizationRejectsInvalidRawPayload(t *testing.T) {
	raw := json.RawMessage(`{"unterminated"`)
	_, err := FormatAuthorization(PaymentCredential{Payload: &raw})
	if err == nil {
		t.Fatal("expected invalid raw payload to fail")
	}
}

// TestStripPaymentSchemeRejectsBadScheme proves that stripPaymentScheme returns
// (false) when the header does not start with the Payment keyword, covering the
// early-return branch at headers.go:290.
func TestStripPaymentSchemeRejectsBadScheme(t *testing.T) {
	if _, ok := stripPaymentScheme("Bearer abc123"); ok {
		t.Error("expected false for non-Payment scheme")
	}
	if _, ok := stripPaymentScheme(""); ok {
		t.Error("expected false for empty header")
	}
}

// TestIsPaymentSchemeStartRejectsNoTrailingSpace proves that
// isPaymentSchemeStart returns false when "Payment" appears in the header
// but is not followed by a space or tab, covering the branch at headers.go:277.
func TestIsPaymentSchemeStartRejectsNoTrailingSpace(t *testing.T) {
	// "Payment" at position 0 but immediately followed by '=' (no space).
	header := "Payment=abc"
	if isPaymentSchemeStart(header, 0) {
		t.Error("expected false when Payment is not followed by space")
	}
}

// TestIsAuthSchemeStartRejectsPastEnd proves that isAuthSchemeStart returns
// false when the supplied index is beyond the header length, covering the
// early-return branch at headers.go:252.
func TestIsAuthSchemeStartRejectsPastEnd(t *testing.T) {
	header := "Payment abc"
	if isAuthSchemeStart(header, len(header)+5) {
		t.Error("expected false for index past end of header")
	}
}

// TestIsAuthSchemeStartRejectsTokenRunningToEnd proves that
// isAuthSchemeStart returns false when the token fills the rest of the
// header without a trailing space, covering the tokenEnd >= len(header)
// branch at headers.go:263.
func TestIsAuthSchemeStartRejectsTokenRunningToEnd(t *testing.T) {
	// A bare word at the start with no space following it means it cannot
	// be an auth scheme (e.g. "Bearer" with nothing after it).
	header := "Bearer"
	if isAuthSchemeStart(header, 0) {
		t.Error("expected false for token with no trailing space")
	}
}

// TestParseAuthParamsTrailingCommaBreak proves the break-on-empty-input
// branch inside parseAuthParams fires when the input ends in trailing commas,
// preventing an infinite loop. This covers the branch at headers.go:311.
func TestParseAuthParamsTrailingCommaBreak(t *testing.T) {
	// Trailing commas after the last param: TrimLeft(" \t,") returns ""
	// after all entries are consumed, triggering the `break`.
	input := `id="abc",,,`
	params, err := parseAuthParams(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if params["id"] != "abc" {
		t.Errorf("expected id=abc, got %v", params)
	}
}

// TestParseAuthParamsMissingEquals proves that parseAuthParams permissively
// skips a stray token with no '=' separator instead of failing the parse,
// matching the canonical mpp-tools parser (this is what lets unescaped quotes
// in a description value truncate at the quote boundary with trailing text
// ignored, rather than aborting the parse).
func TestParseAuthParamsMissingEquals(t *testing.T) {
	// A stray token with no '=' is skipped; the valid param still parses.
	params, err := parseAuthParams(`noequalsign, id="abc"`)
	if err != nil {
		t.Fatalf("expected stray token to be skipped, got error: %v", err)
	}
	if params["id"] != "abc" {
		t.Fatalf("expected id=abc after skipping stray token, got %v", params)
	}
	if _, exists := params["noequalsign"]; exists {
		t.Fatalf("stray token must not become a param: %v", params)
	}
}

func TestFormatReceiptRoundTrip(t *testing.T) {
	r := Receipt{
		Status:      ReceiptStatusSuccess,
		Method:      NewMethodName("solana"),
		Reference:   "sig123",
		ChallengeID: "cid",
		Timestamp:   "2026-01-01T00:00:00Z",
	}
	header, err := FormatReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	if header == "" {
		t.Fatal("empty receipt header")
	}
	got, err := ParseReceipt(header)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reference != "sig123" || got.ChallengeID != "cid" {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestBase64URLJSONDecodeErrors(t *testing.T) {
	bad := NewBase64URLJSONRaw("!!!not-base64url!!!")
	var out map[string]any
	if err := bad.Decode(&out); err == nil {
		t.Error("expected decode error for invalid base64url")
	}
	if _, err := bad.DecodeValue(); err == nil {
		t.Error("expected DecodeValue error for invalid base64url")
	}
}
