package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	x402 "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// x402 conformance support for the cross-SDK vector runner.
//
// The x402 charge is HTTP-shaped, not transaction-shaped: a CLIENT build
// produces a base64(JSON) payment header and a SERVER verify consumes one.
// The cross-SDK oracle is therefore the DECODED ENVELOPE shape, never the
// signed Solana transaction inside `payload.transaction` (that is the
// harness matrix's job, see harness/src/conformance/x402.ts). This runner
// path mirrors the TypeScript reference (harness/src/conformance/x402.ts)
// and drives the real Go pay_kit x402 wire types:
//   - build  -> x402.Credential envelope wrapping (v2 echoes the offer in
//               `accepted` with no top-level scheme/network leakage)
//   - verify -> the version dispatch + network gate + accepted-vs-route
//               field comparison the Adapter.VerifyAndSettle performs at
//               the envelope level (verifyAcceptedBinding). An unknown
//               x402Version is rejected as unsupported-version.
//
// The signed-transaction settlement (decode/transferChecked validation,
// replay, cosign, broadcast) is intentionally out of scope here: the verify
// vectors carry a pinned placeholder proof, so this path validates the
// envelope contract only, matching the reference oracle.

// X402Offer mirrors schema.ts X402Offer.
type X402Offer struct {
	Scheme            string                 `json:"scheme"`
	Network           string                 `json:"network"`
	Amount            string                 `json:"amount"`
	Asset             string                 `json:"asset"`
	PayTo             string                 `json:"payTo"`
	MaxTimeoutSeconds *int                   `json:"maxTimeoutSeconds"`
	Extra             map[string]interface{} `json:"extra"`
}

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

	// exactScheme is the only x402 scheme. The legacy v1 envelope carries
	// it as a top-level sibling of network and payload.
	exactScheme = "exact"

	// Plain legacy SVM network slugs the v1 wire uses instead of CAIP-2.
	legacyNetworkMainnet = "solana"
	legacyNetworkDevnet  = "solana-devnet"

	solanaDevnetCAIP2 = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
)

// runX402 dispatches an x402-exact vector by mode. build-transaction
// produces an envelope and emits its shape; verify-transaction runs the
// server-side envelope gate and emits accept/reject (+ rejectCode).
func runX402(vector Vector) RunnerResult {
	switch vector.Mode {
	case "build-transaction":
		shape, err := buildX402Envelope(vector)
		if err != nil {
			return rejected(vector.ID, err)
		}
		return RunnerResult{ID: vector.ID, Outcome: "accept", X402EnvelopeShape: shape}
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

// offerToAcceptsEntry round-trips the vector offer through the production
// AcceptsEntry parser so the credential echoes it exactly as the real
// client would (raw bytes retained for the verbatim v2 `accepted` echo,
// network normalized, original slug retained for the v1 legacy mapping).
func offerToAcceptsEntry(offer *X402Offer) (*x402.AcceptsEntry, error) {
	raw, err := json.Marshal(offer)
	if err != nil {
		return nil, fmt.Errorf("x402: marshal offer: %w", err)
	}
	var entry x402.AcceptsEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, fmt.Errorf("x402: parse offer: %w", err)
	}
	return &entry, nil
}

// buildX402Envelope mirrors the production client's envelope wrapping
// (client.BuildPaymentHeader): v2 echoes the offer in `accepted` with no
// top-level scheme/network leakage. The signed-transaction proof is the
// vector's pinned placeholder, because the envelope is the conformance
// oracle, not the tx bytes.
func buildX402Envelope(vector Vector) (*X402EnvelopeShape, error) {
	in := vector.Input
	if in.X402Offer == nil {
		return nil, fmt.Errorf("x402 build vector is missing input.x402Offer")
	}
	tx := in.X402PinnedTransaction
	if tx == "" {
		return nil, fmt.Errorf("x402 build vector is missing input.x402PinnedTransaction")
	}
	entry, err := offerToAcceptsEntry(in.X402Offer)
	if err != nil {
		return nil, err
	}

	var credential x402.Credential
	switch in.X402Version {
	case x402VersionV1:
		// Mirrors client.BuildPaymentHeaderV1: top-level scheme + plain
		// legacy network slug, NO accepted object (the v1 envelope binds
		// only scheme+network). The legacy wire carries no extensions.
		credential = x402.Credential{
			X402Version: x402VersionV1,
			Scheme:      exactScheme,
			Network:     v1NetworkForEntry(entry),
			Payload:     x402.CredentialPayload{Transaction: tx},
		}
	case 0, x402VersionV2:
		// Default producer: v2. No top-level scheme/network leakage,
		// accepted echoes the selected offer verbatim. An absent version
		// in the vector means "exercise the default producer".
		//
		// Echo-and-append the advertised extensions (x402 v2 §5.1.2): echo
		// the inbound challenge `extensions` object verbatim, and when the
		// server marked payment-identifier info.required=true append a
		// client id — the vector's pinned id when present, else a fresh
		// generated one. This drives the production EchoExtensions /
		// WithPaymentIdentifierID / GeneratePaymentIdentifierID, matching
		// client.BuildPaymentHeaderWithExtensions and the rust spine.
		extensions, err := x402.EchoExtensions(in.X402AdvertisedExtensions)
		if err != nil {
			return nil, fmt.Errorf("x402: echo extensions: %w", err)
		}
		if extensions != nil && extensions.RequiresPaymentIdentifier() && extensions.PaymentIdentifierID() == "" {
			id := in.X402PaymentIdentifierID
			if id == "" {
				id = x402.GeneratePaymentIdentifierID()
			}
			extensions.WithPaymentIdentifierID(id)
		}
		if extensions != nil && extensions.IsEmpty() {
			extensions = nil
		}
		credential = x402.Credential{
			X402Version: x402VersionV2,
			Payload:     x402.CredentialPayload{Transaction: tx},
			Accepted:    entry,
			Extensions:  extensions,
		}
	default:
		return nil, fmt.Errorf("x402 build vector has unsupported input.x402Version %d", in.X402Version)
	}

	raw, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("x402: marshal credential: %w", err)
	}
	header := base64.StdEncoding.EncodeToString(raw)
	return decodeX402EnvelopeShape(header)
}

// v1NetworkForEntry maps an offer's network to the plain legacy SVM slug
// the v1 wire uses, mirroring the production client v1NetworkForEntry and
// the rust v1_network_for_requirements: only the devnet family is
// special-cased, everything else (mainnet, testnet) collapses to "solana".
func v1NetworkForEntry(entry *x402.AcceptsEntry) string {
	switch entry.Network {
	case "devnet", "solana-devnet", "localnet", solanaDevnetCAIP2:
		return legacyNetworkDevnet
	default:
		return legacyNetworkMainnet
	}
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

// verifyX402Envelope runs the server-side envelope gate against the
// configured route, mirroring the version dispatch + network gate in
// Adapter.VerifyAndSettle (server/exact.rs parse_payment_signature) and
// the accepted-vs-route comparison in verifyAcceptedBinding
// (verify_envelope_payload). RPC-free: a structurally valid,
// route-matching envelope is accepted; the signed-transaction settlement
// is out of scope for the envelope oracle.
func verifyX402Envelope(vector Vector) (*X402EnvelopeShape, error) {
	in := vector.Input
	if in.X402PaymentHeader == "" {
		return nil, fmt.Errorf("x402 verify vector is missing input.x402PaymentHeader")
	}
	shape, err := decodeX402EnvelopeShape(in.X402PaymentHeader)
	if err != nil {
		return nil, err
	}

	expectedNetwork := caip2NetworkForCluster(in.X402ServerNetwork)

	switch shape.X402Version {
	case x402VersionV1:
		// v1 dual-accept arm: the envelope has no accepted object, so the
		// server binds only the top-level scheme + network. The scheme
		// must be "exact" and the plain network slug must normalize to
		// the route's network. Mirrors the rust parse_payment_signature
		// v1 arm (server/exact.rs) and the production verifyLegacyBinding.
		if shape.Scheme != exactScheme {
			return nil, fmt.Errorf("invalid payload: v1 scheme mismatch: expected %s, got %q", exactScheme, shape.Scheme)
		}
		if caip2NetworkForCluster(shape.Network) != expectedNetwork {
			return nil, fmt.Errorf("network mismatch: expected %s, got %s", expectedNetwork, shape.Network)
		}
	case x402VersionV2:
		// v2 gate: accepted must exist, its network/amount/recipient/asset
		// must all match the route (accepted-vs-route comparison).
		if !shape.HasAccepted {
			return nil, fmt.Errorf("invalid payload: v2 envelope missing accepted")
		}
		if caip2NetworkForCluster(shape.AcceptedNetwork) != expectedNetwork {
			return nil, fmt.Errorf("network mismatch: expected %s, got %s", expectedNetwork, shape.AcceptedNetwork)
		}
		if shape.AcceptedAmount != in.X402ServerAmount {
			return nil, fmt.Errorf("amount mismatch: expected %s, got %s", in.X402ServerAmount, shape.AcceptedAmount)
		}
		if shape.AcceptedPayTo != in.X402ServerRecipient {
			return nil, fmt.Errorf("recipient mismatch: credential claims a different recipient")
		}
		if shape.AcceptedAsset != in.X402ServerCurrency {
			return nil, fmt.Errorf("currency mismatch: expected %s, got %s", in.X402ServerCurrency, shape.AcceptedAsset)
		}
		// payment-identifier gate: when the route requires a
		// payment-identifier, the echoed credential must carry a valid
		// `pay_`-shaped id. Missing, empty, or pattern-violating ids are
		// rejected (coinbase x402 spec: HTTP 400). Drives the production
		// PaymentExtensions parse + IsValidPaymentIdentifierID, matching
		// Adapter.VerifyAndSettle's payment-identifier reject and the rust
		// spine's requires_payment_identifier gate.
		if in.X402ServerRequiresPaymentIdentifier {
			id := shape.PaymentIdentifierID
			if id == "" {
				return nil, fmt.Errorf("payment-identifier required but credential echoed no id")
			}
			if !x402.IsValidPaymentIdentifierID(id) {
				return nil, fmt.Errorf("payment-identifier id is invalid: %q does not match ^[A-Za-z0-9_-]{16,128}$", id)
			}
		}
	default:
		return nil, fmt.Errorf("invalid payload: unsupported x402 version: %d", shape.X402Version)
	}

	if !shape.PayloadHasTransaction {
		return nil, fmt.Errorf("invalid payload: missing transaction proof")
	}
	return shape, nil
}

// caip2NetworkForCluster maps a cluster/network identifier to its CAIP-2
// form, mirroring the Go x402 normalizeNetwork / client normalizeNetworkSlug
// (and the TS reference caip2NetworkForCluster). Cluster slugs, legacy
// network slugs, and CAIP-2 ids all collapse to a canonical CAIP-2 id so
// the network gate compares like with like.
func caip2NetworkForCluster(cluster string) string {
	const (
		mainnet = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
		devnet  = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
		testnet = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
	)
	switch cluster {
	case mainnet, "solana", "mainnet", "mainnet-beta", "solana_mainnet":
		return mainnet
	case testnet, "testnet", "solana-testnet":
		return testnet
	case devnet, "devnet", "localnet", "solana-devnet", "solana_devnet", "solana_localnet":
		return devnet
	default:
		return mainnet
	}
}
