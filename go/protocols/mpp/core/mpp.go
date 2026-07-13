// Package core is the root of the Go Solana MPP SDK. It re-exports the
// protocol wire types, header helpers, intent request shapes, the
// replay-protection Store interface, the structured SDK Error type, and
// RFC 3339 challenge-expiry helpers, so downstream callers can import
// `mpp` alone instead of reaching into the protocol subpackages.
//
// Server-side handlers live in the `server` subpackage and client-side
// transaction builders live in the `client` subpackage. The wire format
// and module split mirror the Rust reference crate documented in
// skills/pay-sdk-implementation; cross-language behavior is locked via
// the harness at harness.
package core

import (
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/wire"
)

// Re-exported protocol types. Aliases keep the public surface flat so
// consumers can write `mpp.PaymentChallenge` instead of reaching into
// the protocol subpackages. Documentation lives on the underlying
// declarations in protocol/core and protocol/intents.
//
//revive:disable:exported
type (
	Base64URLJSON     = wire.Base64URLJSON
	ChallengeEcho     = wire.ChallengeEcho
	IntentName        = wire.IntentName
	MethodName        = wire.MethodName
	PaymentChallenge  = wire.PaymentChallenge
	PaymentCredential = wire.PaymentCredential
	Receipt           = wire.Receipt
	ReceiptStatus     = wire.ReceiptStatus
	ChargeRequest     = intents.ChargeRequest
	MethodDetails     = paycore.MethodDetails
	CredentialPayload = paycore.CredentialPayload
	Split             = paycore.Split
)

//revive:enable:exported

// Re-exported header name and scheme constants. The canonical values
// are defined in protocol/core; these aliases keep the public surface
// flat for downstream callers.
const (
	AuthorizationHeader   = wire.AuthorizationHeader
	PaymentReceiptHeader  = wire.PaymentReceiptHeader
	PaymentScheme         = wire.PaymentScheme
	ReceiptStatusSuccess  = wire.ReceiptStatusSuccess
	WWWAuthenticateHeader = wire.WWWAuthenticateHeader
)

// Re-exported helper functions for parsing and formatting MPP wire
// format. Each is an immutable wrapper that delegates to its canonical
// implementation in protocol/wire or protocol/intents; documentation
// lives on the underlying definitions.
//
//revive:disable:exported
func Base64URLDecode(input string) ([]byte, error) { return wire.Base64URLDecode(input) }

func Base64URLEncode(data []byte) string { return wire.Base64URLEncode(data) }

func ComputeChallengeID(secretKey, realm, method, intent, request, expires, digest, opaque string) string {
	return wire.ComputeChallengeID(secretKey, realm, method, intent, request, expires, digest, opaque)
}

func ExtractPaymentScheme(header string) (string, bool) { return wire.ExtractPaymentScheme(header) }

func FormatAuthorization(credential PaymentCredential) (string, error) {
	return wire.FormatAuthorization(credential)
}

func FormatReceipt(receipt Receipt) (string, error) { return wire.FormatReceipt(receipt) }

func FormatWWWAuthenticate(challenge PaymentChallenge) (string, error) {
	return wire.FormatWWWAuthenticate(challenge)
}

func NewBase64URLJSONRaw(raw string) Base64URLJSON { return wire.NewBase64URLJSONRaw(raw) }

func NewBase64URLJSONValue(value any) (Base64URLJSON, error) {
	return wire.NewBase64URLJSONValue(value)
}

func NewChallengeWithSecret(secretKey, realm string, method MethodName, intent IntentName, request Base64URLJSON, opts ...wire.ChallengeOption) PaymentChallenge {
	return wire.NewChallengeWithSecret(secretKey, realm, method, intent, request, opts...)
}

func NewChallengeWithSecretFull(secretKey, realm string, method MethodName, intent IntentName, request Base64URLJSON, expires, digest, description string, opaque *Base64URLJSON) PaymentChallenge {
	return wire.NewChallengeWithSecretFull(secretKey, realm, method, intent, request, expires, digest, description, opaque)
}

func NewPaymentCredential(challenge ChallengeEcho, payload any) (PaymentCredential, error) {
	return wire.NewPaymentCredential(challenge, payload)
}

func NewIntentName(name string) IntentName { return wire.NewIntentName(name) }

func NewMethodName(name string) MethodName { return wire.NewMethodName(name) }

func ParseAuthorization(header string) (PaymentCredential, error) {
	return wire.ParseAuthorization(header)
}

func ParseReceipt(header string) (Receipt, error) { return wire.ParseReceipt(header) }

func ParseUnits(amount string, decimals uint8) (string, error) {
	return intents.ParseUnits(amount, decimals)
}

func ParseWWWAuthenticateAll(headers []string) []PaymentChallenge {
	return wire.ParseWWWAuthenticateAll(headers)
}

func ParseWWWAuthenticate(header string) (PaymentChallenge, error) {
	return wire.ParseWWWAuthenticate(header)
}

//revive:enable:exported
