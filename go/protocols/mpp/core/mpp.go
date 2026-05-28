// Package mpp is the root of the Go Solana MPP SDK. It re-exports the
// protocol wire types, header helpers, intent request shapes, the
// replay-protection Store interface, the structured SDK Error type, and
// RFC 3339 challenge-expiry helpers, so downstream callers can import
// `mpp` alone instead of reaching into the protocol subpackages.
//
// Server-side handlers live in the `server` subpackage and client-side
// transaction builders live in the `client` subpackage. The wire format
// and module split mirror the Rust reference crate documented in
// skills/pay-sdk-implementation; cross-language behavior is locked via
// the interop harness at harness.
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
// format. Each function delegates to its canonical implementation in
// protocol/core or protocol/intents; documentation lives on the
// underlying definitions.
var (
	Base64URLDecode            = wire.Base64URLDecode
	Base64URLEncode            = wire.Base64URLEncode
	ComputeChallengeID         = wire.ComputeChallengeID
	ExtractPaymentScheme       = wire.ExtractPaymentScheme
	FormatAuthorization        = wire.FormatAuthorization
	FormatReceipt              = wire.FormatReceipt
	FormatWWWAuthenticate      = wire.FormatWWWAuthenticate
	NewBase64URLJSONRaw        = wire.NewBase64URLJSONRaw
	NewBase64URLJSONValue      = wire.NewBase64URLJSONValue
	NewChallengeWithSecret     = wire.NewChallengeWithSecret
	NewChallengeWithSecretFull = wire.NewChallengeWithSecretFull
	NewPaymentCredential       = wire.NewPaymentCredential
	NewIntentName              = wire.NewIntentName
	NewMethodName              = wire.NewMethodName
	ParseAuthorization         = wire.ParseAuthorization
	ParseReceipt               = wire.ParseReceipt
	ParseUnits                 = intents.ParseUnits
	ParseWWWAuthenticateAll    = wire.ParseWWWAuthenticateAll
	ParseWWWAuthenticate       = wire.ParseWWWAuthenticate
)
