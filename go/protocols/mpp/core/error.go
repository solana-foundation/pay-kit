package core

import "fmt"

// ErrorCode is a stable error identifier for callers that need branching logic.
type ErrorCode string

// SDK error code constants. Each variant maps 1:1 to a Rust
// reference Error::* variant where possible so error strings stay
// diff-able across language SDKs.
const (
	ErrCodeRPC                    ErrorCode = "rpc-error"
	ErrCodeTransactionFailed      ErrorCode = "transaction-failed"
	ErrCodeTransactionNotFound    ErrorCode = "transaction-not-found"
	ErrCodeNoTransfer             ErrorCode = "no-transfer-instruction"
	ErrCodeAmountMismatch         ErrorCode = "amount-mismatch"
	ErrCodeRecipientMismatch      ErrorCode = "recipient-mismatch"
	ErrCodeMintMismatch           ErrorCode = "mint-mismatch"
	ErrCodeSignatureConsumed      ErrorCode = "signature-consumed"
	ErrCodeSimulationFailed       ErrorCode = "simulation-failed"
	ErrCodeMissingTransaction     ErrorCode = "missing-transaction"
	ErrCodeMissingSignature       ErrorCode = "missing-signature"
	ErrCodeInvalidPayload         ErrorCode = "invalid-payload-type"
	ErrCodeSplitsExceed           ErrorCode = "splits-exceed-amount"
	ErrCodeTooManySplits          ErrorCode = "too-many-splits"
	ErrCodeComputeBudgetExceeded  ErrorCode = "compute-budget-exceeded"
	ErrCodeInvalidConfig          ErrorCode = "invalid-config"
	ErrCodeChallengeExpired       ErrorCode = "challenge-expired"
	ErrCodeChallengeMismatch      ErrorCode = "challenge-mismatch"
	ErrCodeChallengeRouteMismatch ErrorCode = "challenge-route-mismatch"
	ErrCodeInvalidMethod          ErrorCode = "invalid-method"
	ErrCodeWrongNetwork           ErrorCode = "wrong-network"
	ErrCodeOther                  ErrorCode = "other"
)

// Error is the common error type returned by the SDK.
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
