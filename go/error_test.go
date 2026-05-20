package mpp

import (
	"errors"
	"testing"
)

func TestNewError(t *testing.T) {
	err := NewError(ErrCodeInvalidConfig, "bad config")
	if err.Error() != "bad config" {
		t.Fatalf("unexpected message %q", err.Error())
	}
}

func TestNilErrorMethods(t *testing.T) {
	var err *Error
	if err.Error() != "<nil>" {
		t.Fatalf("unexpected nil error string %q", err.Error())
	}
	if err.Unwrap() != nil {
		t.Fatal("expected nil unwrap")
	}
}

func TestWrapError(t *testing.T) {
	cause := errors.New("boom")
	err := WrapError(ErrCodeRPC, "rpc failed", cause)
	if err.Unwrap() != cause {
		t.Fatal("expected wrapped cause")
	}
}

func TestWrapErrorWithoutCause(t *testing.T) {
	err := WrapError(ErrCodeRPC, "rpc failed", nil)
	if err.Unwrap() != nil {
		t.Fatal("expected nil wrapped cause")
	}
	if err.Message != "rpc failed" {
		t.Fatalf("unexpected message %q", err.Message)
	}
}
