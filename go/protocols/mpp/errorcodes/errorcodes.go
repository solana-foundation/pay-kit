// Package errorcodes carries the canonical L6 / P1 structured error
// codes shared across every MPP server SDK, plus a mapper from the Go
// SDK's legacy kebab-case ErrorCode constants to the canonical
// snake_case codes that a 402 response body emits.
//
// The canonical code set is locked across Python, Ruby, PHP, Lua, Rust,
// and Go so a polyglot client can route on the `code` field alone:
//
//   - charge_request_mismatch: the credential's claimed charge does not
//     match the route's expected charge (amount, recipient).
//   - challenge_route_mismatch: the credential was issued for a
//     different route than the one being requested (different pinned
//     fields like currency / method / intent / realm).
//   - challenge_verification_failed: HMAC verification failed.
//   - challenge_expired: the challenge's `expires` is in the past.
//   - payment_invalid: the credential payload is malformed or fails
//     on-chain verification (decode error, missing transaction, memo
//     allowlist violation, transaction failure).
//   - wrong_network: the credential was signed against a different
//     network than the one the server is configured for (e.g. a
//     Surfpool localnet blockhash submitted to a mainnet server).
//   - signature_consumed: the on-chain signature has already been used
//     to settle a previous charge.
//
// Use Canonical to translate a legacy ErrorCode emitted by the
// verifier into the canonical code surfaced in the 402 body.
package errorcodes

import (
	"errors"

	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// Canonical L6 structured error codes (snake_case).
const (
	ChargeRequestMismatch       = "charge_request_mismatch"
	ChallengeRouteMismatch      = "challenge_route_mismatch"
	ChallengeVerificationFailed = "challenge_verification_failed"
	ChallengeExpired            = "challenge_expired"
	PaymentInvalid              = "payment_invalid"
	WrongNetwork                = "wrong_network"
	SignatureConsumed           = "signature_consumed"
)

// All returns the canonical set in declaration order. Callers that
// need a stable set for switch coverage tests or documentation reuse
// this slice rather than rebuilding it.
func All() []string {
	return []string{
		ChargeRequestMismatch,
		ChallengeRouteMismatch,
		ChallengeVerificationFailed,
		ChallengeExpired,
		PaymentInvalid,
		WrongNetwork,
		SignatureConsumed,
	}
}

// IsCanonical reports whether code is one of the canonical L6 codes.
func IsCanonical(code string) bool {
	switch code {
	case ChargeRequestMismatch,
		ChallengeRouteMismatch,
		ChallengeVerificationFailed,
		ChallengeExpired,
		PaymentInvalid,
		WrongNetwork,
		SignatureConsumed:
		return true
	}
	return false
}

// Canonical maps a legacy Go SDK ErrorCode to the canonical L6 code.
// Unknown codes resolve to PaymentInvalid so a 402 body always carries
// a canonical code; matches the cross-SDK fallback policy.
func Canonical(code core.ErrorCode) string {
	switch code {
	case core.ErrCodeAmountMismatch,
		core.ErrCodeRecipientMismatch,
		core.ErrCodeSplitsExceed,
		core.ErrCodeTooManySplits:
		return ChargeRequestMismatch
	case core.ErrCodeChallengeRouteMismatch,
		core.ErrCodeMintMismatch,
		core.ErrCodeInvalidMethod:
		return ChallengeRouteMismatch
	case core.ErrCodeChallengeMismatch:
		return ChallengeVerificationFailed
	case core.ErrCodeChallengeExpired:
		return ChallengeExpired
	case core.ErrCodeWrongNetwork:
		return WrongNetwork
	case core.ErrCodeSignatureConsumed:
		return SignatureConsumed
	case core.ErrCodeRPC,
		core.ErrCodeTransactionFailed,
		core.ErrCodeTransactionNotFound,
		core.ErrCodeNoTransfer,
		core.ErrCodeSimulationFailed,
		core.ErrCodeMissingTransaction,
		core.ErrCodeMissingSignature,
		core.ErrCodeInvalidPayload,
		core.ErrCodeInvalidConfig,
		core.ErrCodeComputeBudgetExceeded,
		core.ErrCodeOther:
		return PaymentInvalid
	}
	return PaymentInvalid
}

// PaymentRequiredBody is the canonical 402 response body shape shared
// across MPP server SDKs. Struct fields are declared alphabetically so
// Go's encoding/json marshals them in canonical order (`code`, `error`,
// `message`, `status`, `title`, `type`) without needing a sort step.
//
// `code` is the new L6 canonical code. `error` mirrors `code` for
// backward compatibility with pre-L6 clients that read the legacy
// kebab-case error field. `message` is the human-readable detail.
type PaymentRequiredBody struct {
	Code    string `json:"code"`
	Error   string `json:"error"`
	Message string `json:"message"`
	Status  int    `json:"status"`
	Title   string `json:"title"`
	Type    string `json:"type"`
}

// NewPaymentRequiredBody builds a canonical 402 body for the given
// canonical code (or legacy code, normalized through Canonical-like
// fallback) and human-readable message. Unknown codes fall back to
// PaymentInvalid, matching the cross-SDK fallback policy.
func NewPaymentRequiredBody(code, message string) PaymentRequiredBody {
	canonical := code
	if !IsCanonical(canonical) {
		canonical = PaymentInvalid
	}
	return PaymentRequiredBody{
		Code:    canonical,
		Error:   canonical,
		Message: message,
		Status:  402,
		Title:   "Payment Required",
		Type:    "https://paymentauth.org/problems/" + canonical,
	}
}

// CanonicalFromError reads the ErrorCode out of an SDK *Error and
// returns the canonical code. Non-SDK errors and nil resolve to
// PaymentInvalid.
func CanonicalFromError(err error) string {
	if err == nil {
		return PaymentInvalid
	}
	var sdkErr *core.Error
	if errors.As(err, &sdkErr) && sdkErr != nil {
		return Canonical(sdkErr.Code)
	}
	return PaymentInvalid
}
