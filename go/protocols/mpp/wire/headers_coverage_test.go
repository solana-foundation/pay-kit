package wire

import (
	"encoding/json"
	"testing"
)

// encodeAuthToken base64url-encodes a raw JSON object as a Payment
// authorization token, bypassing FormatAuthorization so tests can exercise
// the missing-field validation branches in ParseAuthorization.
func encodeAuthToken(t *testing.T, obj any) string {
	t.Helper()
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return PaymentScheme + " " + Base64URLEncode(raw)
}

func TestParseAuthorizationMissingChallenge(t *testing.T) {
	header := encodeAuthToken(t, map[string]any{"source": "x"})
	if _, err := ParseAuthorization(header); err == nil {
		t.Fatal("expected error for credential without challenge")
	}
}

func TestParseAuthorizationMissingChallengeID(t *testing.T) {
	header := encodeAuthToken(t, map[string]any{
		"challenge": map[string]any{"realm": "r"},
	})
	if _, err := ParseAuthorization(header); err == nil {
		t.Fatal("expected error for challenge without id")
	}
}

func TestParseReceiptMissingFields(t *testing.T) {
	cases := []struct {
		name    string
		receipt map[string]any
	}{
		{"missing status", map[string]any{"method": "solana", "reference": "s", "timestamp": "2026-01-01T00:00:00Z"}},
		{"missing method", map[string]any{"status": "success", "reference": "s", "timestamp": "2026-01-01T00:00:00Z"}},
		{"missing reference", map[string]any{"status": "success", "method": "solana", "timestamp": "2026-01-01T00:00:00Z"}},
		{"missing timestamp", map[string]any{"status": "success", "method": "solana", "reference": "s"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.receipt)
			if _, err := ParseReceipt(Base64URLEncode(raw)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestParseReceiptNonISO8601Timestamp(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"status":    "success",
		"method":    "solana",
		"reference": "sig",
		"timestamp": "not-a-timestamp",
	})
	if _, err := ParseReceipt(Base64URLEncode(raw)); err == nil {
		t.Fatal("expected error for non-ISO-8601 timestamp")
	}
}

func TestParseReceiptAcceptsRFC3339Nano(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"status":    "success",
		"method":    "solana",
		"reference": "sig",
		"timestamp": "2026-01-01T00:00:00.123456789Z",
	})
	if _, err := ParseReceipt(Base64URLEncode(raw)); err != nil {
		t.Fatalf("expected RFC3339Nano timestamp to be accepted: %v", err)
	}
}

func TestIsISO8601(t *testing.T) {
	if !isISO8601("2026-01-01T00:00:00Z") {
		t.Fatal("expected plain RFC3339 to be valid")
	}
	if !isISO8601("2026-01-01T00:00:00.5Z") {
		t.Fatal("expected RFC3339Nano to be valid")
	}
	if isISO8601("nope") {
		t.Fatal("expected garbage to be invalid")
	}
}

// TestParseWWWAuthenticateUnquotedAndStrayTokens exercises the permissive
// parseAuthParams branches: stray tokens without '=' are skipped, and unquoted
// token values are read to the next separator.
func TestParseWWWAuthenticateUnquotedAndStrayTokens(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	// stray token "foo" (no '='), unquoted id, then quoted fields.
	header := PaymentScheme + " foo id=abc realm=\"r\" method=\"solana\" intent=\"charge\" request=\"" + request.Raw() + "\""
	challenge, err := ParseWWWAuthenticate(header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if challenge.ID != "abc" {
		t.Fatalf("expected unquoted id=abc, got %q", challenge.ID)
	}
}

// TestParseWWWAuthenticateEscapedQuoteInValue exercises the backslash-escape
// branch inside the quoted-value scanner of parseAuthParams.
func TestParseWWWAuthenticateEscapedQuoteInValue(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	header := PaymentScheme + " id=\"a\\\"b\" realm=\"r\" method=\"solana\" intent=\"charge\" request=\"" + request.Raw() + "\""
	challenge, err := ParseWWWAuthenticate(header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if challenge.ID != `a"b` {
		t.Fatalf("expected escaped-quote id=a\"b, got %q", challenge.ID)
	}
}

// TestParseWWWAuthenticateAllQuotedComma covers the in-quote comma handling in
// splitPaymentChallengeValues and nextAuthSchemeStart: a comma inside a quoted
// value must not split the header.
func TestParseWWWAuthenticateAllQuotedComma(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	header := PaymentScheme + " id=\"a,b\" realm=\"r\" method=\"solana\" intent=\"charge\" request=\"" + request.Raw() + "\""
	challenges := ParseWWWAuthenticateAll([]string{header})
	if len(challenges) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(challenges))
	}
	if challenges[0].ID != "a,b" {
		t.Fatalf("expected id with embedded comma, got %q", challenges[0].ID)
	}
}
