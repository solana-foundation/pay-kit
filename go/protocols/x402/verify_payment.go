package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
)

// Canonical reason codes for the envelope-level checks VerifyPaymentHeader
// runs before the structural transaction checks (which carry their own
// invalid_exact_svm_payload_* codes).
const (
	ReasonInvalidPayload            = "invalid_payload"
	ReasonVersionMismatch           = "version_mismatch"
	ReasonChargeRequestMismatch     = "charge_request_mismatch"
	ReasonPaymentIdentifierRequired = "payment_identifier_required"
)

// ExactRoute is the server-side configuration an exact credential is
// verified against: what the route charges (Requirements), on which
// network, and whether it requires a payment-identifier.
type ExactRoute struct {
	// Network is the route network; cluster slugs, legacy slugs and CAIP-2
	// ids are all accepted and normalized to CAIP-2.
	Network                  string
	Requirements             TransferRequirements
	RequirePaymentIdentifier bool
}

// ExactRouteConfig is the operator-facing description of an exact route.
// The token program is not part of it: NewExactRoute reads it from the
// mint account so a Token-2022 mint is never verified as legacy Token.
type ExactRouteConfig struct {
	Network                  string
	PayTo                    string
	Asset                    string
	Amount                   string
	FeePayer                 string
	ExpectedMemo             string
	RequirePaymentIdentifier bool
}

// NewExactRoute parses an ExactRouteConfig and resolves the asset's token
// program from the mint account.
func NewExactRoute(ctx context.Context, rpc solanatx.RPCClient, cfg ExactRouteConfig) (ExactRoute, error) {
	payTo, err := solana.PublicKeyFromBase58(cfg.PayTo)
	if err != nil {
		return ExactRoute{}, fmt.Errorf("x402: route payTo %q: %w", cfg.PayTo, err)
	}
	mint, err := solana.PublicKeyFromBase58(cfg.Asset)
	if err != nil {
		return ExactRoute{}, fmt.Errorf("x402: route asset %q: %w", cfg.Asset, err)
	}
	feePayer, err := solana.PublicKeyFromBase58(cfg.FeePayer)
	if err != nil {
		return ExactRoute{}, fmt.Errorf("x402: route fee payer %q: %w", cfg.FeePayer, err)
	}
	amount, err := strconv.ParseUint(cfg.Amount, 10, 64)
	if err != nil || amount == 0 {
		return ExactRoute{}, fmt.Errorf("x402: route amount %q must be a positive integer of atomic units", cfg.Amount)
	}
	info, err := solanatx.FetchMint(ctx, rpc, mint)
	if err != nil {
		return ExactRoute{}, fmt.Errorf("x402: read route mint %s: %w", mint, err)
	}
	return ExactRoute{
		Network: cfg.Network,
		Requirements: TransferRequirements{
			PayTo:        payTo,
			Mint:         mint,
			TokenProgram: info.TokenProgram,
			Amount:       amount,
			FeePayer:     feePayer,
			ExpectedMemo: cfg.ExpectedMemo,
		},
		RequirePaymentIdentifier: cfg.RequirePaymentIdentifier,
	}, nil
}

// VerifiedPayment is a credential that passed every pre-broadcast check.
type VerifiedPayment struct {
	Credential  Credential
	Transaction *solana.Transaction
	// RawTransaction is the decoded wire transaction, ready to cosign.
	RawTransaction []byte
}

// VerifyPaymentHeader decodes a base64 PAYMENT-SIGNATURE (v2) or X-PAYMENT
// (v1) header and runs every check a server performs before it cosigns or
// broadcasts: version dispatch, the envelope binding to the route (v1:
// scheme + network; v2: the echoed accepted requirements), the
// payment-identifier gate, the structural exact-SVM transaction checks
// (VerifyExactTransaction) and the client signatures
// (solanatx.VerifyClientSignatures). Failures are *VerifyError values carrying a
// canonical reason code.
func VerifyPaymentHeader(header string, route ExactRoute) (*VerifiedPayment, error) {
	credBytes, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, VerifyFail(ReasonInvalidPayload, fmt.Sprintf("invalid payload: base64 decode: %v", err))
	}
	var credential Credential
	if err := json.Unmarshal(credBytes, &credential); err != nil {
		return nil, VerifyFail(ReasonInvalidPayload, fmt.Sprintf("invalid payload: decode credential: %v", err))
	}
	network := normalizeNetwork(route.Network)
	switch credential.X402Version {
	case X402VersionLegacy:
		if credential.Scheme != ExactScheme {
			return nil, VerifyFail(ReasonChargeRequestMismatch,
				fmt.Sprintf("scheme mismatch: expected %s, got %q", ExactScheme, credential.Scheme))
		}
		if got := normalizeNetwork(credential.Network); got != network {
			return nil, VerifyFail(ReasonChargeRequestMismatch,
				fmt.Sprintf("network mismatch: expected %s, got %s", network, credential.Network))
		}
	case X402Version:
		if err := verifyAccepted(credential.Accepted, network, route.Requirements); err != nil {
			return nil, err
		}
	default:
		return nil, VerifyFail(ReasonVersionMismatch, fmt.Sprintf("unsupported x402 version %d", credential.X402Version))
	}
	if route.RequirePaymentIdentifier {
		id := credential.Extensions.PaymentIdentifierID()
		if id == "" {
			return nil, VerifyFail(ReasonPaymentIdentifierRequired, "payment-identifier required but credential echoed no id")
		}
		if !IsValidPaymentIdentifierID(id) {
			return nil, VerifyFail(ReasonPaymentIdentifierRequired,
				fmt.Sprintf("payment-identifier id is invalid: %q does not match ^[A-Za-z0-9_-]{16,128}$", id))
		}
	}
	if credential.Payload.Transaction == "" {
		return nil, VerifyFail(ReasonInvalidPayload, "invalid payload: missing transaction payload")
	}
	rawTx, err := base64.StdEncoding.DecodeString(credential.Payload.Transaction)
	if err != nil {
		return nil, VerifyFail(ReasonInvalidPayload, fmt.Sprintf("invalid payload: transaction base64: %v", err))
	}
	tx, err := solanatx.DecodeTransaction(rawTx)
	if err != nil {
		return nil, VerifyFail(ReasonInvalidPayload, fmt.Sprintf("invalid payload: transaction decode: %v", err))
	}
	if len(tx.Signatures) == 0 {
		return nil, VerifyFail(ReasonInvalidPayload, "invalid payload: transaction carries no signatures")
	}
	if err := VerifyExactTransaction(tx, route.Requirements); err != nil {
		return nil, err
	}
	// The client's signatures must verify over this message before the
	// server co-signs or sends it; only the facilitator's fee-payer slot
	// (account zero) may be empty (RULINGS SIG1).
	feePayer := route.Requirements.FeePayer
	if err := solanatx.VerifyClientSignatures(tx, &feePayer); err != nil {
		return nil, VerifyFail(ReasonInvalidPayload, fmt.Sprintf("invalid payload: %v", err))
	}
	return &VerifiedPayment{Credential: credential, Transaction: tx, RawTransaction: rawTx}, nil
}

// verifyAccepted binds a v2 credential's echoed requirements to the route
// on the PaymentRequirements fields the spec defines (scheme, network,
// amount, asset, payTo). Fields a server added are not compared here.
func verifyAccepted(accepted *AcceptsEntry, network string, req TransferRequirements) error {
	if accepted == nil {
		return VerifyFail(ReasonInvalidPayload, "invalid payload: v2 credential is missing accepted")
	}
	mismatch := func(err error) error { return VerifyFail(ReasonChargeRequestMismatch, err.Error()) }
	if accepted.Scheme != ExactScheme {
		return mismatch(fmt.Errorf("scheme mismatch: expected %s, got %q", ExactScheme, accepted.Scheme))
	}
	if accepted.Network != network {
		return mismatch(fmt.Errorf("network mismatch: expected %s, got %s", network, accepted.Network))
	}
	if want := strconv.FormatUint(req.Amount, 10); accepted.Amount != want {
		return mismatch(fmt.Errorf("amount mismatch: expected %s, got %s", want, accepted.Amount))
	}
	if accepted.PayTo != req.PayTo.String() {
		return mismatch(errors.New("recipient mismatch: credential claims a different recipient"))
	}
	if accepted.Asset != req.Mint.String() {
		return mismatch(fmt.Errorf("currency mismatch: expected %s, got %s", req.Mint, accepted.Asset))
	}
	return nil
}
