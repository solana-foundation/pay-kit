package mpp

import (
	"errors"
	"testing"
)

func TestNewError(t *testing.T) {
	t.Parallel()
	err := NewError(ErrCodeInvalidConfig, "bad config")
	if err.Error() != "bad config" {
		t.Fatalf("unexpected message %q", err.Error())
	}
}

func TestWrapError(t *testing.T) {
	t.Parallel()
	cause := errors.New("boom")
	err := WrapError(ErrCodeRPC, "rpc failed", cause)
	if err.Unwrap() != cause {
		t.Fatal("expected wrapped cause")
	}
}

func TestWrapErrorNilCauseFallsBackToNewError(t *testing.T) {
	t.Parallel()
	err := WrapError(ErrCodeRPC, "rpc failed", nil)
	if err.Err != nil {
		t.Fatal("expected no inner error when cause is nil")
	}
	if err.Unwrap() != nil {
		t.Fatal("expected nil wrapped cause")
	}
	if err.Message != "rpc failed" {
		t.Fatalf("unexpected message %q", err.Message)
	}
}

func TestErrorNilReceiverSafe(t *testing.T) {
	t.Parallel()
	var err *Error
	if got := err.Error(); got != "<nil>" {
		t.Fatalf("expected <nil>, got %q", got)
	}
	if got := err.Unwrap(); got != nil {
		t.Fatalf("expected nil unwrap, got %v", got)
	}
}
