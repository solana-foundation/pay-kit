package paycore

import "fmt"

// ErrorCode is a stable, protocol-agnostic error identifier for callers
// that need branching logic. It lives in PayCore so primitives shared by
// every protocol (transaction building, split validation) can signal
// failures without importing any protocol package.
type ErrorCode string

// Protocol-agnostic error codes raised by PayCore primitives. Protocol
// packages re-export and extend this vocabulary with their own codes.
const (
	// ErrCodeSplitsExceed signals that the secondary transfers consume
	// the entire (or more than the) charge amount.
	ErrCodeSplitsExceed ErrorCode = "splits-exceed-amount"
	// ErrCodeTooManySplits signals that the split set exceeds the
	// cross-SDK cap of eight secondary recipients.
	ErrCodeTooManySplits ErrorCode = "too-many-splits"
)

// Error is the common error type carried across the SDK. It is defined in
// PayCore so the shared primitives and every protocol package surface the
// same concrete type, keeping `errors.As` matching uniform regardless of
// which tier produced the failure.
type Error struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// NewError creates a new SDK error.
func NewError(code ErrorCode, message string) *Error {
	return &Error{Code: code, Message: message}
}

// WrapError attaches an underlying cause to an SDK error.
func WrapError(code ErrorCode, message string, err error) *Error {
	if err == nil {
		return NewError(code, message)
	}
	return &Error{Code: code, Message: fmt.Sprintf("%s: %v", message, err), Err: err}
}
