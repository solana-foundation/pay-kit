package wire

import "testing"

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
