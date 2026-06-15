package core

import "github.com/solana-foundation/pay-kit/go/paycore"

// ErrorCode is a stable error identifier for callers that need branching
// logic. It aliases the protocol-agnostic PayCore vocabulary so the MPP
// codes below extend the same type the shared primitives raise.
type ErrorCode = paycore.ErrorCode

// SDK error code constants. Each variant maps 1:1 to a Rust
// reference Error::* variant where possible so error strings stay
// diff-able across language SDKs.
//
// ErrCodeSplitsExceed and ErrCodeTooManySplits are raised by the shared
// split-validation primitive in PayCore and re-exported here so MPP
// callers keep a single error vocabulary.
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
	ErrCodeSplitsExceed                     = paycore.ErrCodeSplitsExceed
	ErrCodeTooManySplits                    = paycore.ErrCodeTooManySplits
	ErrCodeComputeBudgetExceeded  ErrorCode = "compute-budget-exceeded"
	ErrCodeInvalidConfig          ErrorCode = "invalid-config"
	ErrCodeChallengeExpired       ErrorCode = "challenge-expired"
	ErrCodeChallengeMismatch      ErrorCode = "challenge-mismatch"
	ErrCodeChallengeRouteMismatch ErrorCode = "challenge-route-mismatch"
	ErrCodeInvalidMethod          ErrorCode = "invalid-method"
	ErrCodeWrongNetwork           ErrorCode = "wrong-network"
	ErrCodeOther                  ErrorCode = "other"
)

// Error is the common error type returned by the SDK. It aliases the
// PayCore error type so a *core.Error raised by a protocol handler and a
// *paycore.Error raised by a shared primitive are the same concrete type
// and resolve identically through errors.As.
type Error = paycore.Error

// NewError creates a new SDK error.
func NewError(code ErrorCode, message string) *Error {
	return paycore.NewError(code, message)
}

// WrapError attaches an underlying cause to an SDK error.
func WrapError(code ErrorCode, message string, err error) *Error {
	return paycore.WrapError(code, message, err)
}
