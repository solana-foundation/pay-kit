package wire

import (
	"strings"
	"testing"
)

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

// TestParseAuthParamsMissingEquals proves that parseAuthParams returns an
// error when a parameter name has no '=' separator at all, covering the
// eq<=0 branch at headers.go:315.
func TestParseAuthParamsMissingEquals(t *testing.T) {
	// Input has no '=' character anywhere.
	_, err := parseAuthParams("noequalsign")
	if err == nil {
		t.Fatal("expected error for param with no '=' separator")
	}
	if !strings.Contains(err.Error(), "invalid auth parameter") {
		t.Fatalf("unexpected error: %v", err)
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
