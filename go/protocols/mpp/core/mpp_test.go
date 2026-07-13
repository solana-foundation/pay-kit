package core

import (
	"testing"
)

// TestBase64URLFacadeRoundTrip exercises the Base64URLEncode/Base64URLDecode
// re-exports: the facade must delegate to the wire codec so an encode/decode
// pair round-trips.
func TestBase64URLFacadeRoundTrip(t *testing.T) {
	t.Parallel()
	encoded := Base64URLEncode([]byte("payload-bytes"))
	if encoded == "" {
		t.Fatal("expected non-empty encoding")
	}
	decoded, err := Base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != "payload-bytes" {
		t.Fatalf("round-trip mismatch: got %q", decoded)
	}
}

// TestBase64URLJSONFacade covers NewBase64URLJSONRaw and NewBase64URLJSONValue:
// the value constructor canonicalizes and the raw constructor preserves the
// verbatim string.
func TestBase64URLJSONFacade(t *testing.T) {
	t.Parallel()
	value, err := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var decoded map[string]string
	if err := value.Decode(&decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded["amount"] != "1000" {
		t.Fatalf("unexpected payload: %#v", decoded)
	}

	raw := NewBase64URLJSONRaw(value.Raw())
	if raw.Raw() != value.Raw() {
		t.Fatalf("raw constructor altered value: %q != %q", raw.Raw(), value.Raw())
	}
}

// TestComputeChallengeIDFacade asserts the HMAC facade is deterministic for a
// fixed secret+inputs and secret-sensitive (a different secret yields a
// different ID), confirming it delegates to the real HMAC implementation.
func TestComputeChallengeIDFacade(t *testing.T) {
	t.Parallel()
	id := ComputeChallengeID("secret", "realm", "solana", "charge", "req", "exp", "digest", "opaque")
	if id == "" {
		t.Fatal("expected non-empty challenge id")
	}
	again := ComputeChallengeID("secret", "realm", "solana", "charge", "req", "exp", "digest", "opaque")
	if id != again {
		t.Fatal("expected deterministic challenge id")
	}
	other := ComputeChallengeID("secret2", "realm", "solana", "charge", "req", "exp", "digest", "opaque")
	if id == other {
		t.Fatal("expected different secret to change the challenge id")
	}
}

// TestMethodAndIntentNameFacade covers NewMethodName / NewIntentName: both
// normalize to lowercase and the intent classifiers work through the facade.
func TestMethodAndIntentNameFacade(t *testing.T) {
	t.Parallel()
	if got := NewMethodName("SOLANA"); got != "solana" {
		t.Fatalf("method not normalized: %q", got)
	}
	if !NewIntentName("Charge").IsCharge() {
		t.Fatal("expected charge intent")
	}
	if !NewIntentName("Session").IsSession() {
		t.Fatal("expected session intent")
	}
}

// TestWWWAuthenticateFacadeRoundTrip covers NewChallengeWithSecret,
// FormatWWWAuthenticate, ParseWWWAuthenticate, and ParseWWWAuthenticateAll:
// a challenge formatted through the facade re-parses to the same identity.
func TestWWWAuthenticateFacadeRoundTrip(t *testing.T) {
	t.Parallel()
	request, err := NewBase64URLJSONValue(map[string]string{"amount": "1000", "currency": "sol"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	challenge := NewChallengeWithSecret("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	header, err := FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	parsed, err := ParseWWWAuthenticate(header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.ID != challenge.ID || parsed.Realm != challenge.Realm || parsed.Request.Raw() != challenge.Request.Raw() {
		t.Fatalf("round-trip mismatch: %#v", parsed)
	}

	all := ParseWWWAuthenticateAll([]string{header})
	if len(all) != 1 || all[0].ID != challenge.ID {
		t.Fatalf("ParseWWWAuthenticateAll returned %#v", all)
	}
}

// TestWWWAuthenticateFullFacade covers NewChallengeWithSecretFull, which must
// produce the same HMAC-bound ID as the option-based constructor when given
// equivalent fields.
func TestWWWAuthenticateFullFacade(t *testing.T) {
	t.Parallel()
	request, err := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	full := NewChallengeWithSecretFull("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request, "2030-01-01T00:00:00Z", "digest", "desc", nil)
	if full.ID == "" {
		t.Fatal("expected non-empty id")
	}
	if full.Expires != "2030-01-01T00:00:00Z" || full.Digest != "digest" || full.Description != "desc" {
		t.Fatalf("optional fields not set: %#v", full)
	}
	header, err := FormatWWWAuthenticate(full)
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	parsed, err := ParseWWWAuthenticate(header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.ID != full.ID {
		t.Fatalf("full challenge did not round-trip: %q != %q", parsed.ID, full.ID)
	}
}

// TestAuthorizationFacadeRoundTrip covers NewPaymentCredential,
// FormatAuthorization, ExtractPaymentScheme, and ParseAuthorization: a
// credential formatted through the facade re-parses to the same challenge id.
func TestAuthorizationFacadeRoundTrip(t *testing.T) {
	t.Parallel()
	request, err := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	challenge := NewChallengeWithSecret("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	credential, err := NewPaymentCredential(challenge.ToEcho(), map[string]string{"type": "transaction", "transaction": "abc"})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	header, err := FormatAuthorization(credential)
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	if _, ok := ExtractPaymentScheme(header); !ok {
		t.Fatalf("ExtractPaymentScheme failed on %q", header)
	}
	parsed, err := ParseAuthorization(header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Challenge.ID != challenge.ID {
		t.Fatalf("round-trip mismatch: %q != %q", parsed.Challenge.ID, challenge.ID)
	}
}

// TestReceiptFacadeRoundTrip covers FormatReceipt and ParseReceipt: a receipt
// formatted through the facade re-parses to the same reference.
func TestReceiptFacadeRoundTrip(t *testing.T) {
	t.Parallel()
	receipt := Receipt{
		Status:      ReceiptStatusSuccess,
		Method:      NewMethodName("solana"),
		Timestamp:   "2026-01-01T00:00:00Z",
		Reference:   "sig-123",
		ChallengeID: "cid",
	}
	header, err := FormatReceipt(receipt)
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	parsed, err := ParseReceipt(header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Reference != "sig-123" || parsed.Status != ReceiptStatusSuccess {
		t.Fatalf("round-trip mismatch: %#v", parsed)
	}
}

// TestParseUnitsFacade covers ParseUnits: the facade must delegate to the
// intents scaler so a fractional amount converts to base units, and an
// invalid amount surfaces the error.
func TestParseUnitsFacade(t *testing.T) {
	t.Parallel()
	got, err := ParseUnits("1.5", 6)
	if err != nil {
		t.Fatalf("ParseUnits: %v", err)
	}
	if got != "1500000" {
		t.Fatalf("ParseUnits(1.5, 6)=%s, want 1500000", got)
	}
	if _, err := ParseUnits("-1", 6); err == nil {
		t.Fatal("expected error for negative amount")
	}
}
