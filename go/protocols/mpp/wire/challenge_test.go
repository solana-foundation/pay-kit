package wire

import (
	"testing"
	"time"
)

func TestChallengeVerify(t *testing.T) {
	request, err := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	if err != nil {
		t.Fatalf("request encode failed: %v", err)
	}
	challenge := NewChallengeWithSecret("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	if !challenge.Verify("secret") {
		t.Fatal("expected challenge verification to succeed")
	}
	if challenge.Verify("wrong") {
		t.Fatal("expected challenge verification to fail with wrong key")
	}
}

func TestChallengeIsExpired(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	challenge := NewChallengeWithSecretFull("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request, "2020-01-01T00:00:00Z", "", "", nil)
	if !challenge.IsExpired(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("expected challenge to be expired")
	}
}

func TestPaymentCredentialPayloadAs(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	challenge := NewChallengeWithSecret("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	credential, err := NewPaymentCredential(challenge.ToEcho(), map[string]string{"type": "transaction"})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	var payload map[string]string
	if err := credential.PayloadAs(&payload); err != nil {
		t.Fatalf("payload decode failed: %v", err)
	}
	if payload["type"] != "transaction" {
		t.Fatalf("unexpected payload %#v", payload)
	}
}

func TestIsExpiredEmptyString(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	challenge := NewChallengeWithSecretFull("s", "r", NewMethodName("solana"), NewIntentName("charge"), request, "", "", "", nil)
	if challenge.IsExpired(time.Now()) {
		t.Fatal("empty expires should not be expired")
	}
}

func TestIsExpiredRFC3339Corpus(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	before := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		expires string
		accept  bool
	}{
		{"jsts_date_time_005", "1998-12-31T23:59:60Z", true},
		{"jsts_date_time_006", "1998-12-31T15:59:60.123-08:00", true},
		{"jsts_date_time_011", "1990-12-31T15:59:59-24:00", false},
		{"jsts_date_time_015", "1990-12-31T10:00:00+10:60", false},
		{"jsts_date_time_017", "1963-06-19t08:30:06.283185z", true},
		{"leap_second_june_month_end", "1972-06-30T23:59:60Z", true},
		{"leap_second_offset_rolls_local_date_forward", "1999-01-01T00:59:60+01:00", true},
		{"lowercase_t_and_z", "1985-04-12t23:20:50.52z", true},
		{"lowercase_t_separator", "1985-04-12t23:20:50.52Z", true},
		{"lowercase_z_offset", "1985-04-12T23:20:50.52z", true},
		{"offset_hour_out_of_range", "2026-01-29T12:00:00+24:00", false},
		{"offset_minute_out_of_range", "2026-01-29T12:00:00+00:60", false},
		{"rfc_5_8_example_leap_second_offset", "1990-12-31T15:59:60-08:00", true},
		{"rfc_5_8_example_leap_second_z", "1990-12-31T23:59:60Z", true},
		{"secfrac_comma_separator", "2021-09-29T16:04:33,5Z", false},
		{"leap_second_not_at_utc_month_end", "1998-12-31T23:58:60Z", false},
		{"leap_second_not_on_utc_month_last_day", "1998-12-30T23:59:60Z", false},
		{"leap_second_not_in_utc_hour_23", "1998-12-31T22:59:60Z", false},
		{"day_out_of_range", "2026-02-30T00:00:00Z", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			challenge := NewChallengeWithSecretFull("s", "r", NewMethodName("solana"), NewIntentName("charge"), request, tc.expires, "", "", nil)
			if expired := challenge.IsExpired(before); expired == tc.accept {
				t.Fatalf("IsExpired(%q) = %v, want %v", tc.expires, expired, !tc.accept)
			}
		})
	}
}

// The leap second maps to the last nanosecond of :59, not the start of it, so
// the challenge is still live at .999999998 and dead from .999999999 on
// (IsExpired is inclusive at equality). One nanosecond either way pins it.
func TestIsExpiredLeapSecondBoundary(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	mapped := time.Date(1990, 12, 31, 23, 59, 59, 999999999, time.UTC)
	tests := []struct {
		name    string
		expires string
		now     time.Time
		expired bool
	}{
		{"z_one_ns_before_mapped", "1990-12-31T23:59:60Z", mapped.Add(-time.Nanosecond), false},
		{"z_at_mapped", "1990-12-31T23:59:60Z", mapped, true},
		{"z_one_ns_after_mapped", "1990-12-31T23:59:60Z", mapped.Add(time.Nanosecond), true},
		{"offset_one_ns_before_mapped", "1990-12-31T15:59:60-08:00", mapped.Add(-time.Nanosecond), false},
		{"offset_at_mapped", "1990-12-31T15:59:60-08:00", mapped, true},
		{"offset_one_ns_after_mapped", "1990-12-31T15:59:60-08:00", mapped.Add(time.Nanosecond), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			challenge := NewChallengeWithSecretFull("s", "r", NewMethodName("solana"), NewIntentName("charge"), request, tc.expires, "", "", nil)
			if expired := challenge.IsExpired(tc.now); expired != tc.expired {
				t.Fatalf("IsExpired(%q) at %s = %v, want %v", tc.expires, tc.now.Format(time.RFC3339Nano), expired, tc.expired)
			}
		})
	}
}

func TestIsExpiredInvalidTimestamp(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	challenge := NewChallengeWithSecretFull("s", "r", NewMethodName("solana"), NewIntentName("charge"), request, "not-a-date", "", "", nil)
	if !challenge.IsExpired(time.Now()) {
		t.Fatal("invalid timestamp should be treated as expired")
	}
}

func TestIsExpiredFutureTimestamp(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	challenge := NewChallengeWithSecretFull("s", "r", NewMethodName("solana"), NewIntentName("charge"), request, future, "", "", nil)
	if challenge.IsExpired(time.Now()) {
		t.Fatal("future timestamp should not be expired")
	}
}

func TestIsExpiredPastTimestamp(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	challenge := NewChallengeWithSecretFull("s", "r", NewMethodName("solana"), NewIntentName("charge"), request, past, "", "", nil)
	if !challenge.IsExpired(time.Now()) {
		t.Fatal("past timestamp should be expired")
	}
}

func TestPayloadAsNilPayload(t *testing.T) {
	credential := PaymentCredential{Payload: nil}
	var out map[string]string
	if err := credential.PayloadAs(&out); err != nil {
		t.Fatalf("nil payload should not error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil output, got %v", out)
	}
}

func TestComputeChallengeIDDeterministic(t *testing.T) {
	id1 := ComputeChallengeID("secret", "realm", "solana", "charge", "req", "exp", "digest", "opaque")
	id2 := ComputeChallengeID("secret", "realm", "solana", "charge", "req", "exp", "digest", "opaque")
	if id1 != id2 {
		t.Fatalf("challenge ID not deterministic: %q != %q", id1, id2)
	}
	id3 := ComputeChallengeID("different", "realm", "solana", "charge", "req", "exp", "digest", "opaque")
	if id1 == id3 {
		t.Fatal("different secret should produce different ID")
	}
}

func TestVerifyWithWrongSecretKey(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	challenge := NewChallengeWithSecret("correct-secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	if challenge.Verify("wrong-secret") {
		t.Fatal("verify with wrong secret should fail")
	}
	if !challenge.Verify("correct-secret") {
		t.Fatal("verify with correct secret should pass")
	}
}

func TestNewChallengeWithSecretFullAllFields(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	opaque, _ := NewBase64URLJSONValue(map[string]string{"session": "abc"})
	challenge := NewChallengeWithSecretFull("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request, "2030-01-01T00:00:00Z", "sha256=abc", "buy coffee", &opaque)
	if challenge.Realm != "realm" {
		t.Fatalf("unexpected realm: %q", challenge.Realm)
	}
	if challenge.Expires != "2030-01-01T00:00:00Z" {
		t.Fatalf("unexpected expires: %q", challenge.Expires)
	}
	if challenge.Digest != "sha256=abc" {
		t.Fatalf("unexpected digest: %q", challenge.Digest)
	}
	if challenge.Description != "buy coffee" {
		t.Fatalf("unexpected description: %q", challenge.Description)
	}
	if challenge.Opaque == nil || challenge.Opaque.Raw() != opaque.Raw() {
		t.Fatal("unexpected opaque")
	}
	if challenge.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if !challenge.Verify("secret") {
		t.Fatal("challenge should verify with correct secret")
	}
}

func TestToEchoPreservesFields(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	opaque, _ := NewBase64URLJSONValue(map[string]string{"k": "v"})
	challenge := NewChallengeWithSecretFull("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request, "2030-01-01T00:00:00Z", "sha256=abc", "desc", &opaque)
	echo := challenge.ToEcho()
	if echo.ID != challenge.ID || echo.Realm != challenge.Realm || echo.Expires != challenge.Expires {
		t.Fatal("echo did not preserve basic fields")
	}
	if echo.Digest != challenge.Digest {
		t.Fatal("echo did not preserve digest")
	}
	if echo.Opaque == nil || echo.Opaque.Raw() != challenge.Opaque.Raw() {
		t.Fatal("echo did not preserve opaque")
	}
}

func TestNewPaymentCredentialRejectsUnmarshalablePayload(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	challenge := NewChallengeWithSecret("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	if _, err := NewPaymentCredential(challenge.ToEcho(), map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("expected marshal error")
	}
}
