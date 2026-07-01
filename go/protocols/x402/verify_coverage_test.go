package x402

import (
	"testing"
)

func TestVerifyFail(t *testing.T) {
	err := VerifyFail("test_code", "test message")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	ve, ok := err.(*VerifyError)
	if !ok {
		t.Fatalf("expected *VerifyError, got %T", err)
	}
	if ve.Code != "test_code" {
		t.Fatalf("code = %q, want test_code", ve.Code)
	}
	if ve.Msg != "test message" {
		t.Fatalf("msg = %q, want test message", ve.Msg)
	}
}

func TestVerifyFailErrorMessage(t *testing.T) {
	err := VerifyFail("code", "msg")
	if err.Error() != "x402: msg" {
		t.Fatalf("Error() = %q", err.Error())
	}
}

func TestParsePaymentSignatureInvalidBase64(t *testing.T) {
	_, _, err := ParsePaymentSignature("not-base64!!!")
	if err == nil {
		t.Fatal("expected error")
	}
}
