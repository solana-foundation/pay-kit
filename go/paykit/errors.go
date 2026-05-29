package paykit

import (
	"errors"
	"fmt"
)

// Sentinel errors. Apps use errors.Is for stable comparisons and
// errors.As when they want the *PaymentError envelope's metadata.
var (
	ErrPaymentRequired     = errors.New("paykit: payment required")
	ErrInvalidProof        = errors.New("paykit: invalid proof")
	ErrChallengeExpired    = errors.New("paykit: challenge expired")
	ErrSchemeNotSupported  = errors.New("paykit: scheme not supported")
	ErrMixedCurrencies     = errors.New("paykit: mixed currencies in gate")
	ErrSchemeIncompatible  = errors.New("paykit: x402 incompatible with multi-recipient gates")
	ErrDemoSignerOnMainnet = errors.New("paykit: demo signer cannot be used on solana_mainnet")
	ErrInvalidConfig       = errors.New("paykit: invalid configuration")
)

// PaymentError carries the canonical L6 structured code (matches the
// G39 fault matrix used by the cross-language harness) plus the
// originating gate and accepted schemes. Wraps an underlying error;
// errors.Is sees both sentinels.
type PaymentError struct {
	Code    string
	Gate    *Gate
	Schemes []Scheme
	Err     error

	// Response payload prepared by Client.write402 for the error
	// handler. Unexported so only the kit populates them; the default
	// and custom error handlers render from these fields.
	status   int
	resource string
	accepts  []AcceptsEntry
	headers  map[string]string
}

func (e *PaymentError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Code != "" {
		return fmt.Sprintf("paykit: %s: %v", e.Code, e.Err)
	}
	return fmt.Sprintf("paykit: %v", e.Err)
}

func (e *PaymentError) Unwrap() error { return e.Err }

// GateError is what Gate.Validate returns. Carries a reason string
// suitable for log lines and a sentinel for errors.Is dispatch.
type GateError struct {
	Reason   string
	Sentinel error
}

func (e *GateError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Sentinel != nil {
		return fmt.Sprintf("%v: %s", e.Sentinel, e.Reason)
	}
	return "paykit: " + e.Reason
}

func (e *GateError) Unwrap() error { return e.Sentinel }
