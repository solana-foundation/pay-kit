package mpp

import (
	"github.com/solana-foundation/pay-kit/go/protocol"
	"github.com/solana-foundation/pay-kit/go/protocol/core"
	"github.com/solana-foundation/pay-kit/go/protocol/intents"
)

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

const (
	AuthorizationHeader   = core.AuthorizationHeader
	PaymentReceiptHeader  = core.PaymentReceiptHeader
	PaymentScheme         = core.PaymentScheme
	ReceiptStatusSuccess  = core.ReceiptStatusSuccess
	WWWAuthenticateHeader = core.WWWAuthenticateHeader
)

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
