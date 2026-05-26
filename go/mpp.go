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
package mpp

import (
	"github.com/solana-foundation/pay-kit/go/protocol"
	"github.com/solana-foundation/pay-kit/go/protocol/core"
	"github.com/solana-foundation/pay-kit/go/protocol/intents"
)

// Re-exported protocol types. Aliases keep the public surface flat so
// consumers can write `mpp.PaymentChallenge` instead of reaching into
// the protocol subpackages. Documentation lives on the underlying
// declarations in protocol/core and protocol/intents.
//
//revive:disable:exported
type (
	Base64URLJSON     = core.Base64URLJSON
	ChallengeEcho     = core.ChallengeEcho
	IntentName        = core.IntentName
	MethodName        = core.MethodName
	PaymentChallenge  = core.PaymentChallenge
	PaymentCredential = core.PaymentCredential
	Receipt           = core.Receipt
	ReceiptStatus     = core.ReceiptStatus
	ChargeRequest     = intents.ChargeRequest
	MethodDetails     = protocol.MethodDetails
	CredentialPayload = protocol.CredentialPayload
	Split             = protocol.Split
)

//revive:enable:exported

// Re-exported header name and scheme constants. The canonical values
// are defined in protocol/core; these aliases keep the public surface
// flat for downstream callers.
const (
	AuthorizationHeader   = core.AuthorizationHeader
	PaymentReceiptHeader  = core.PaymentReceiptHeader
	PaymentScheme         = core.PaymentScheme
	ReceiptStatusSuccess  = core.ReceiptStatusSuccess
	WWWAuthenticateHeader = core.WWWAuthenticateHeader
)

// Re-exported helper functions for parsing and formatting MPP wire
// format. Each function delegates to its canonical implementation in
// protocol/core or protocol/intents; documentation lives on the
// underlying definitions.
var (
	Base64URLDecode            = core.Base64URLDecode
	Base64URLEncode            = core.Base64URLEncode
	ComputeChallengeID         = core.ComputeChallengeID
	ExtractPaymentScheme       = core.ExtractPaymentScheme
	FormatAuthorization        = core.FormatAuthorization
	FormatReceipt              = core.FormatReceipt
	FormatWWWAuthenticate      = core.FormatWWWAuthenticate
	NewBase64URLJSONRaw        = core.NewBase64URLJSONRaw
	NewBase64URLJSONValue      = core.NewBase64URLJSONValue
	NewChallengeWithSecret     = core.NewChallengeWithSecret
	NewChallengeWithSecretFull = core.NewChallengeWithSecretFull
	NewPaymentCredential       = core.NewPaymentCredential
	NewIntentName              = core.NewIntentName
	NewMethodName              = core.NewMethodName
	ParseAuthorization         = core.ParseAuthorization
	ParseReceipt               = core.ParseReceipt
	ParseUnits                 = intents.ParseUnits
	ParseWWWAuthenticateAll    = core.ParseWWWAuthenticateAll
	ParseWWWAuthenticate       = core.ParseWWWAuthenticate
)
