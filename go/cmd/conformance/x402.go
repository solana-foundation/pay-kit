package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	solana "github.com/gagliardetto/solana-go"

	x402 "github.com/solana-foundation/pay-kit/go/protocols/x402"
	x402client "github.com/solana-foundation/pay-kit/go/protocols/x402/client"
)

// x402 conformance support for the cross-SDK vector runner.
//
// The x402 oracle is the DECODED ENVELOPE shape of the payment header, but
// both directions run the real SDK on real transactions:
//   - build  -> the Go x402 client selects nothing (the vector names the
//               offer) and builds and signs a real exact transfer through
//               the fixture RPC (mint owner and decimals read on-chain,
//               fee payer = extra.feePayer), wrapped as v1 or v2.
//   - verify -> the shared server verifier x402.VerifyPaymentHeader (the
//               same code the paykit adapter runs before cosigning): version
//               dispatch, envelope binding, payment-identifier gate and the
//               structural exact-SVM transaction checks. No broadcast.

// X402EnvelopeShape mirrors schema.ts X402EnvelopeShape: the decoded
// semantic shape of an x402 `exact` envelope the conformance oracle
// asserts against.
type X402EnvelopeShape struct {
	X402Version           int    `json:"x402Version"`
	Scheme                string `json:"scheme,omitempty"`
	Network               string `json:"network,omitempty"`
	HasAccepted           bool   `json:"hasAccepted"`
	PayloadHasTransaction bool   `json:"payloadHasTransaction"`
	AcceptedScheme        string `json:"acceptedScheme,omitempty"`
	AcceptedNetwork       string `json:"acceptedNetwork,omitempty"`
	AcceptedAsset         string `json:"acceptedAsset,omitempty"`
	AcceptedPayTo         string `json:"acceptedPayTo,omitempty"`
	AcceptedAmount        string `json:"acceptedAmount,omitempty"`

	// v2 extensions echo shape (mirrors schema.ts X402EnvelopeShape).
	// HasExtensions / HasPaymentIdentifier are NOT omitempty: a vector
	// asserts the false case (echo-and-omit) explicitly, so the decoder
	// must always emit the boolean. PaymentIdentifierRequired is a pointer
	// so an absent `required` is distinguishable from `required:false`.
	HasExtensions             bool     `json:"hasExtensions"`
	HasPaymentIdentifier      bool     `json:"hasPaymentIdentifier"`
	PaymentIdentifierRequired *bool    `json:"paymentIdentifierRequired,omitempty"`
	PaymentIdentifierID       string   `json:"paymentIdentifierId,omitempty"`
	ExtensionKeys             []string `json:"extensionKeys"`
}

const (
	x402VersionV1 = 1
	x402VersionV2 = 2
)

// runX402 dispatches an x402-exact vector by mode. build-transaction
// produces an envelope and emits its shape; verify-transaction runs the
// server verifier and emits accept/reject (+ rejectCode).
func runX402(vector Vector) RunnerResult {
	switch vector.Mode {
	case "build-transaction":
		shape, header, err := buildX402Envelope(vector)
		if err != nil {
			return rejected(vector.ID, err)
		}
		return RunnerResult{ID: vector.ID, Outcome: "accept", X402EnvelopeShape: shape, X402PaymentHeader: header}
	case "verify-transaction":
		shape, err := verifyX402Envelope(vector)
		if err != nil {
			return rejected(vector.ID, err)
		}
		return RunnerResult{ID: vector.ID, Outcome: "accept", X402EnvelopeShape: shape}
	default:
		return rejected(vector.ID, fmt.Errorf("unsupported x402 mode %q", vector.Mode))
	}
}

// offerToAcceptsEntry hands the vector offer, byte for byte, to the
// production AcceptsEntry parser so the credential echoes it exactly as the
// real client would (raw bytes retained for the verbatim v2 `accepted` echo,
// network normalized, unknown keys kept).
func offerToAcceptsEntry(offer json.RawMessage) (*x402.AcceptsEntry, error) {
	var entry x402.AcceptsEntry
	if err := json.Unmarshal(offer, &entry); err != nil {
		return nil, fmt.Errorf("x402: parse offer: %w", err)
	}
	return &entry, nil
}

// advertisedExtensions returns the server-advertised extensions the client
// echoes. When the vector pins a payment-identifier id, it is set through
// the production WithPaymentIdentifierID, standing in for an application
// that supplies its own id; otherwise the client generates one.
func advertisedExtensions(in VectorInput) (json.RawMessage, error) {
	if len(in.X402AdvertisedExtensions) == 0 || string(in.X402AdvertisedExtensions) == "null" {
		return nil, nil
	}
	if in.X402PaymentIdentifierID == "" {
		return in.X402AdvertisedExtensions, nil
	}
	extensions, err := x402.EchoExtensions(in.X402AdvertisedExtensions)
	if err != nil {
		return nil, fmt.Errorf("x402: echo extensions: %w", err)
	}
	if extensions != nil && extensions.RequiresPaymentIdentifier() {
		extensions.WithPaymentIdentifierID(in.X402PaymentIdentifierID)
	}
	return json.Marshal(extensions)
}

// buildX402Envelope builds and signs a real payment with the Go x402
// client and returns the decoded envelope shape plus the header itself.
func buildX402Envelope(vector Vector) (*X402EnvelopeShape, string, error) {
	in := vector.Input
	if len(in.X402Offer) == 0 || string(in.X402Offer) == "null" {
		return nil, "", fmt.Errorf("x402 build vector is missing input.x402Offer")
	}
	signer, err := newLocalSigner(in.SignerSecretKey)
	if err != nil {
		return nil, "", err
	}
	rpcClient, err := sdkRPC(in)
	if err != nil {
		return nil, "", err
	}
	entry, err := offerToAcceptsEntry(in.X402Offer)
	if err != nil {
		return nil, "", err
	}
	ctx := context.Background()
	var header string
	switch in.X402Version {
	case x402VersionV1:
		header, err = x402client.BuildPaymentHeaderV1(ctx, signer, rpcClient, entry)
	case 0, x402VersionV2:
		// An absent version exercises the default producer (v2).
		advertised, aerr := advertisedExtensions(in)
		if aerr != nil {
			return nil, "", aerr
		}
		header, err = x402client.BuildPaymentHeaderWithExtensions(ctx, signer, rpcClient, entry, advertised)
	default:
		return nil, "", fmt.Errorf("x402 build vector has unsupported input.x402Version %d", in.X402Version)
	}
	if err != nil {
		return nil, "", err
	}
	shape, err := decodeX402EnvelopeShape(header)
	return shape, header, err
}

// credentialWire is the decode-side shape of a base64(JSON) x402 envelope.
// It is read leniently (accepted as a raw object) so the oracle can report
// the decoded shape without re-running the production AcceptsEntry
// precedence rules, matching the TS reference decodeEnvelopeShape.
type credentialWire struct {
	X402Version int             `json:"x402Version"`
	Scheme      *string         `json:"scheme"`
	Network     *string         `json:"network"`
	Accepted    json.RawMessage `json:"accepted"`
	Payload     struct {
		Transaction string `json:"transaction"`
	} `json:"payload"`
	Extensions json.RawMessage `json:"extensions"`
}

type acceptedWire struct {
	Scheme  string `json:"scheme"`
	Network string `json:"network"`
	Amount  string `json:"amount"`
	Asset   string `json:"asset"`
	PayTo   string `json:"payTo"`
}

// decodeX402EnvelopeShape decodes a base64(JSON) envelope header into the
// conformance shape oracle. Mirrors harness/src/conformance/x402.ts
// decodeEnvelopeShape: scheme/network are reported only when present
// (v1 carries them, v2 must not), hasAccepted is true iff an accepted
// object exists, payloadHasTransaction is true iff a non-empty proof is
// present, and the accepted* fields echo the v2 offer.
func decodeX402EnvelopeShape(header string) (*X402EnvelopeShape, error) {
	rawBytes, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("invalid payload: undecodable payment header: %w", err)
	}
	var cw credentialWire
	if err := json.Unmarshal(rawBytes, &cw); err != nil {
		return nil, fmt.Errorf("invalid payload: malformed envelope JSON: %w", err)
	}
	shape := &X402EnvelopeShape{
		X402Version:           cw.X402Version,
		HasAccepted:           len(cw.Accepted) > 0 && string(cw.Accepted) != "null",
		PayloadHasTransaction: cw.Payload.Transaction != "",
		ExtensionKeys:         []string{},
	}
	if cw.Scheme != nil {
		shape.Scheme = *cw.Scheme
	}
	if cw.Network != nil {
		shape.Network = *cw.Network
	}
	if shape.HasAccepted {
		var aw acceptedWire
		if err := json.Unmarshal(cw.Accepted, &aw); err != nil {
			return nil, fmt.Errorf("invalid payload: malformed accepted object: %w", err)
		}
		shape.AcceptedScheme = aw.Scheme
		shape.AcceptedNetwork = aw.Network
		shape.AcceptedAsset = aw.Asset
		shape.AcceptedPayTo = aw.PayTo
		shape.AcceptedAmount = aw.Amount
	}

	// Surface the v2 extensions object via the production PaymentExtensions
	// parser (rename + flatten). hasExtensions is false when the key is
	// absent OR present-but-empty (a conforming build never emits an empty
	// `extensions: {}`, but a decoder must still classify a stray {} as
	// "no extensions"). Mirrors harness/src/conformance/x402.ts
	// decodeEnvelopeShape.
	if len(cw.Extensions) > 0 && string(cw.Extensions) != "null" {
		var ext x402.PaymentExtensions
		if err := json.Unmarshal(cw.Extensions, &ext); err != nil {
			return nil, fmt.Errorf("invalid payload: malformed extensions object: %w", err)
		}
		keys := ext.Keys()
		if keys == nil {
			keys = []string{}
		}
		shape.ExtensionKeys = keys
		shape.HasExtensions = len(keys) > 0
		if ext.PaymentIdentifier != nil {
			shape.HasPaymentIdentifier = true
			if r := ext.PaymentIdentifier.Info.Required; r != nil {
				shape.PaymentIdentifierRequired = r
			}
			shape.PaymentIdentifierID = ext.PaymentIdentifier.Info.Id
		}
	}
	return shape, nil
}

// verifyX402Envelope configures an exact route the way an operator would
// (token program read from the mint via the fixture RPC) and runs the
// shared pre-broadcast verifier on the vector's real transaction.
func verifyX402Envelope(vector Vector) (*X402EnvelopeShape, error) {
	in := vector.Input
	if in.X402PaymentHeader == "" {
		return nil, fmt.Errorf("x402 verify vector is missing input.x402PaymentHeader")
	}
	feePayer, err := serverFeePayer(in)
	if err != nil {
		return nil, err
	}
	rpcClient, err := sdkRPC(in)
	if err != nil {
		return nil, err
	}
	route, err := x402.NewExactRoute(context.Background(), rpcClient, x402.ExactRouteConfig{
		Network:                  in.X402ServerNetwork,
		PayTo:                    in.X402ServerRecipient,
		Asset:                    in.X402ServerCurrency,
		Amount:                   in.X402ServerAmount,
		FeePayer:                 feePayer,
		ExpectedMemo:             in.X402ServerMemo,
		RequirePaymentIdentifier: in.X402ServerRequiresPaymentIdentifier,
	})
	if err != nil {
		return nil, err
	}
	if _, err := x402.VerifyPaymentHeader(in.X402PaymentHeader, route); err != nil {
		// A v2 credential names its network inside `accepted`, so the
		// shared code for a v2 network mismatch is accepted-mismatch.
		if shape, shapeErr := decodeX402EnvelopeShape(in.X402PaymentHeader); shapeErr == nil &&
			shape.X402Version == 2 && strings.Contains(strings.ToLower(err.Error()), "network mismatch") {
			return nil, fmt.Errorf("accepted network does not match the route: %w", err)
		}
		return nil, err
	}
	return decodeX402EnvelopeShape(in.X402PaymentHeader)
}

// serverFeePayer returns the route fee payer, checking that the vector's
// secret key belongs to it (the key an operator would cosign with).
func serverFeePayer(in VectorInput) (string, error) {
	if in.X402ServerFeePayer == "" {
		return "", fmt.Errorf("x402 verify vector is missing input.x402ServerFeePayer")
	}
	if len(in.X402ServerFeePayerSecretKey) == ed25519.PrivateKeySize {
		derived := solana.PrivateKey(in.X402ServerFeePayerSecretKey).PublicKey().String()
		if derived != in.X402ServerFeePayer {
			return "", fmt.Errorf("x402ServerFeePayerSecretKey does not match x402ServerFeePayer")
		}
	}
	return in.X402ServerFeePayer, nil
}
