package paycore

import (
	"errors"
	"testing"
)

func TestErrorMessageAndNilReceiver(t *testing.T) {
	err := NewError(ErrCodeTooManySplits, "too many splits")
	if err.Error() != "too many splits" {
		t.Fatalf("Error() = %q", err.Error())
	}
	if err.Unwrap() != nil {
		t.Fatalf("Unwrap() = %v, want nil", err.Unwrap())
	}
	var nilErr *Error
	if nilErr.Error() != "<nil>" {
		t.Fatalf("nil Error() = %q", nilErr.Error())
	}
	if nilErr.Unwrap() != nil {
		t.Fatalf("nil Unwrap() = %v", nilErr.Unwrap())
	}
}

func TestWrapErrorAttachesCause(t *testing.T) {
	cause := errors.New("rpc timeout")
	wrapped := WrapError(ErrCodeSplitsExceed, "splits exceed amount", cause)
	if wrapped.Code != ErrCodeSplitsExceed {
		t.Fatalf("Code = %q", wrapped.Code)
	}
	if !errors.Is(wrapped, cause) {
		t.Fatal("wrapped error does not unwrap to its cause")
	}
	if wrapped.Error() != "splits exceed amount: rpc timeout" {
		t.Fatalf("Error() = %q", wrapped.Error())
	}

	// A nil cause degrades to NewError.
	plain := WrapError(ErrCodeSplitsExceed, "splits exceed amount", nil)
	if plain.Err != nil || plain.Error() != "splits exceed amount" {
		t.Fatalf("nil-cause wrap = %+v", plain)
	}
}
