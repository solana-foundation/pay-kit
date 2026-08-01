// Command conformance is the Go cross-SDK conformance-vector runner.
//
// It honors the harness conformance runner stdin/stdout contract: read one
// conformance vector as JSON on stdin, drive the real Go pay_kit SDK
// (paycore + protocols/mpp client build, server pre-broadcast verify, and
// the wire canonical-JSON / base64url encoders) for the requested mode, and
// emit one RunnerResult line as JSON on stdout.
//
// The oracle for build/verify vectors is the DECODED SEMANTIC SHAPE of the
// transaction (fee payer, transfer set, compute caps, memos) rather than raw
// bytes, because signatures and account ordering can legitimately differ
// across SDKs. The canonical-bytes mode pins exact bytes for the JCS /
// base64url vectors where byte-for-byte agreement is the whole point.
//
// The run is deterministic and RPC-free: build/verify vectors pin a recent
// blockhash and either an explicit token program or one resolvable by
// currency, so no live validator is contacted.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/server"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/wire"
)

const (
	tokenProgram         = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	token2022Program     = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
	systemProgram        = "11111111111111111111111111111111"
	computeBudgetProgram = "ComputeBudget111111111111111111111111111111"
	memoProgram          = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
	defaultNetwork       = "mainnet"
	defaultSPLDecimals   = 6
)

// Vector is the top-level conformance-vector shape consumed from stdin.
type Vector struct {
	// ID is the unique vector identifier, echoed back in RunnerResult so
	// the harness can pair each result line with its vector.
	ID string `json:"id"`
	// Intent selects the runner path: "x402-exact" dispatches to the x402
	// envelope oracle, anything else runs the MPP charge paths.
	Intent string `json:"intent"`
	// Mode picks what to exercise: "build-transaction",
	// "verify-transaction", or "canonical-bytes".
	Mode string `json:"mode"`
	// Description is the human-readable summary of what the vector
	// exercises; the runner never branches on it.
	Description string `json:"description"`
	// Input carries the per-mode inputs (request, pinned fixtures,
	// encoder payloads) this runner consumes.
	Input VectorInput `json:"input"`
	// Expect is the expected-outcome JSON asserted by the harness driver;
	// it is opaque to this runner and passed through unread.
	Expect json.RawMessage `json:"expect"`
}

// VectorInput carries the per-mode inputs of a conformance vector.
type VectorInput struct {
	// Request is the charge request that drives the build/verify modes;
	// nil for encoder-only (canonical-bytes) vectors.
	Request *ChargeRequest `json:"request"`
	// Transaction is a pinned base64 wire transaction to verify; empty in
	// verify mode means build one from Request first and verify that.
	Transaction string `json:"transaction"`
	// SignerSecretKey is the 64-byte ed25519 secret key (carried as a JSON
	// byte array) acting as transfer authority and default fee payer on
	// the client build path.
	SignerSecretKey []byte `json:"signerSecretKey"`
	// RPCFixtures pins RPC-derived values (mint owners) so build/verify
	// stay RPC-free; nil when the vector needs none.
	RPCFixtures *RPCFixtures `json:"rpcFixtures"`
	// Value is a raw JSON value to canonicalize (JCS) and base64url-encode
	// in canonical-bytes mode; absent otherwise.
	Value json.RawMessage `json:"value"`
	// EncodeBase64URL supplies raw bytes (hex or UTF-8) to base64url-encode
	// in canonical-bytes mode; nil otherwise.
	EncodeBase64URL *EncodeBase64URL `json:"encodeBase64Url"`
	// ChallengeID supplies the inputs to the MPP challenge-id HMAC-SHA256
	// derivation in canonical-bytes mode; nil otherwise.
	ChallengeID *ChallengeID `json:"challengeId"`
	// VoucherPreimage supplies the inputs to the 50-byte session voucher
	// preimage in canonical-bytes mode; nil otherwise.
	VoucherPreimage *VoucherPreimage `json:"voucherPreimage"`
	// SessionAuthenticationMessage and SessionWire drive the session wire
	// vectors (production authentication-message bytes and wire-shape
	// round-trips). The Go session layer has not migrated to the final wire
	// contract yet, so these are declared only to be skipped explicitly
	// (unsupported-mode) instead of failing on empty exactBytes. Tracked
	// follow-up: implement once go/protocols/mpp/intents/session.go is on
	// the final shapes.
	SessionAuthenticationMessage json.RawMessage `json:"sessionAuthenticationMessage"`
	SessionWire                  json.RawMessage `json:"sessionWire"`

	// x402-exact inputs.
	X402Offer *X402Offer `json:"x402Offer"`
	// X402Version is the x402Version the build path should produce:
	// 1 builds the legacy top-level scheme/network envelope, 2 the
	// accepted-echo envelope, and 0 (absent) exercises the default
	// producer, which also emits 2.
	X402Version int `json:"x402Version"`
	// X402PinnedTransaction is the placeholder base64 transaction proof
	// placed in payload.transaction on build; the envelope shape, not
	// these bytes, is the conformance oracle.
	X402PinnedTransaction string `json:"x402PinnedTransaction"`
	// X402ServerNetwork is the route network the verify gate expects;
	// cluster slugs, legacy slugs, and CAIP-2 ids are all normalized to
	// CAIP-2 before comparison.
	X402ServerNetwork string `json:"x402ServerNetwork"`
	// X402ServerRecipient is the route recipient (base58 address) the
	// envelope's accepted.payTo must equal on verify.
	X402ServerRecipient string `json:"x402ServerRecipient"`
	// X402ServerCurrency is the route asset the envelope's accepted.asset
	// must equal on verify.
	X402ServerCurrency string `json:"x402ServerCurrency"`
	// X402ServerAmount is the route amount (decimal string of token base
	// units) the envelope's accepted.amount must equal on verify.
	X402ServerAmount string `json:"x402ServerAmount"`
	// X402PaymentHeader is the base64(JSON) x402 payment header the verify
	// mode decodes and gates against the route.
	X402PaymentHeader string `json:"x402PaymentHeader"`

	// x402-exact extensions inputs.
	X402AdvertisedExtensions json.RawMessage `json:"x402AdvertisedExtensions"`
	// X402PaymentIdentifierID pins the payment-identifier id appended when
	// the advertised extensions require one; empty means generate a fresh
	// id via the production helper.
	X402PaymentIdentifierID string `json:"x402PaymentIdentifierId"`
	// X402ServerRequiresPaymentIdentifier makes verify reject envelopes
	// whose echoed extensions carry no valid payment-identifier id.
	X402ServerRequiresPaymentIdentifier bool `json:"x402ServerRequiresPaymentIdentifier"`
}

// ChargeRequest is the charge-intent request carried in a vector input.
type ChargeRequest struct {
	// Amount is the total charge as a decimal string of integer base units
	// (lamports for SOL, token base units for SPL); no display decimals.
	Amount string `json:"amount"`
	// Currency is the asset symbol (e.g. "USDC", "SOL") or mint address;
	// Asset takes precedence over it when both are set.
	Currency string `json:"currency"`
	// ExternalID is an external reference recorded on-chain as a Memo
	// instruction; empty means no memo is added.
	ExternalID string `json:"externalId"`
	// Recipient is the destination address (base58); PayTo takes
	// precedence over it when both are set.
	Recipient string `json:"recipient"`
	// PayTo is the preferred recipient field; per the conformance
	// precedence rules it wins over Recipient.
	PayTo string `json:"payTo"`
	// Asset is the preferred asset field; per the conformance precedence
	// rules it wins over Currency.
	Asset string `json:"asset"`
	// MethodDetails carries the Solana-specific build/verify knobs
	// (network, blockhash, token program, splits); nil uses defaults.
	MethodDetails *MethodDetails `json:"methodDetails"`
	// ComputeUnitLimit caps compute units for the built transaction;
	// nil leaves the SDK default in effect.
	ComputeUnitLimit *uint32 `json:"computeUnitLimit"`
	// ComputeUnitPrice is the priority fee in micro-lamports per compute
	// unit, as a decimal string; nil leaves the SDK default in effect.
	ComputeUnitPrice *string `json:"computeUnitPrice"`
}

// MethodDetails is the methodDetails block of a vector charge request.
type MethodDetails struct {
	// Network is the Solana cluster slug (e.g. "mainnet", "devnet");
	// empty defaults to mainnet.
	Network string `json:"network"`
	// Decimals is the SPL mint decimals used for transferChecked; nil
	// defaults to 6 for non-SOL currencies and is unused for SOL.
	Decimals *uint8 `json:"decimals"`
	// TokenProgram is the base58 id of the program owning the mint (Token
	// or Token-2022); empty resolves via the rpc-fixture mint owner, then
	// the default-by-currency table, keeping the run RPC-free.
	TokenProgram string `json:"tokenProgram"`
	// RecentBlockhash pins the blockhash (base58) used to build the
	// transaction so no live validator is contacted.
	RecentBlockhash string `json:"recentBlockhash"`
	// FeePayer enables server fee sponsorship when true and FeePayerKey is
	// set; nil or false keeps the signer as fee payer.
	FeePayer *bool `json:"feePayer"`
	// FeePayerKey is the base58 public key of the sponsoring fee payer
	// account used when FeePayer is true.
	FeePayerKey string `json:"feePayerKey"`
	// Splits lists additional same-asset transfers carved out of the total
	// amount, each with its own recipient.
	Splits []paycore.Split `json:"splits"`
}

// RPCFixtures pins the RPC-derived values a vector needs so the run stays
// RPC-free.
type RPCFixtures struct {
	// RecentBlockhash is a pinned blockhash (base58) a vector may carry;
	// the build path reads the blockhash from methodDetails, so this stays
	// informational for this runner.
	RecentBlockhash string `json:"recentBlockhash"`
	// MintOwners maps mint address (base58) to its owning token program
	// (base58), standing in for the getAccountInfo owner lookup.
	MintOwners map[string]string `json:"mintOwners"`
}

// EncodeBase64URL holds the raw bytes (hex or UTF-8) to base64url-encode.
type EncodeBase64URL struct {
	// HexBytes is a hex string decoded to raw bytes before base64url
	// encoding; it takes precedence over UTF8 when both are set.
	HexBytes string `json:"hexBytes"`
	// UTF8 is a literal string whose UTF-8 bytes are base64url-encoded
	// when HexBytes is empty.
	UTF8 string `json:"utf8"`
}

// ChallengeID holds the inputs to the MPP charge challenge-id HMAC
// derivation.
type ChallengeID struct {
	// SecretKey is the server-side secret keying the HMAC-SHA256; it never
	// appears in the HMAC input itself.
	SecretKey string `json:"secretKey"`
	// Realm is the challenge realm parameter, the first "|"-joined segment
	// of the HMAC input.
	Realm string `json:"realm"`
	// Method is the HTTP method bound into the challenge id.
	Method string `json:"method"`
	// Intent is the MPP intent (e.g. "charge") bound into the challenge id.
	Intent string `json:"intent"`
	// Request is the request binding segment of the HMAC input, joined
	// verbatim; empty when the challenge omits it.
	Request string `json:"request"`
	// Expires is the challenge expiry exactly as carried on the wire,
	// joined verbatim into the HMAC input.
	Expires string `json:"expires"`
	// Digest is the body digest challenge parameter; absent optionals join
	// as empty strings.
	Digest string `json:"digest"`
	// Opaque is the opaque challenge parameter (base64url JSON on the
	// wire), joined verbatim; empty when absent.
	Opaque string `json:"opaque"`
}

// VoucherPreimage holds the inputs to the 50-byte session voucher message
// bytes (a constant [0x56, 0x01] magic prefix leads the payload).
type VoucherPreimage struct {
	// ChannelID is the payment-channel address (base58); its 32 raw bytes
	// follow the 2-byte magic prefix.
	ChannelID string `json:"channelId"`
	// CumulativeAmount is the channel's cumulative spend in token base
	// units, as a decimal u64 string; encoded little-endian at offset 34.
	CumulativeAmount string `json:"cumulativeAmount"`
	// ExpiresAt is the voucher expiry as unix epoch seconds; encoded as a
	// little-endian i64 at offset 42.
	ExpiresAt int64 `json:"expiresAt"`
}

// Transfer is one decoded transfer in a transaction shape.
type Transfer struct {
	// Kind is the transfer family: "sol" for System Program transfers,
	// "spl" for token-program transferChecked.
	Kind string `json:"kind"`
	// Destination is the base58 receiving account: the recipient wallet
	// for SOL, the destination token account for SPL.
	Destination string `json:"destination,omitempty"`
	// DestinationOwner is the base58 wallet owning the destination token
	// account; this decoder leaves it empty (omitted on the wire).
	DestinationOwner string `json:"destinationOwner,omitempty"`
	// Mint is the base58 token mint of an SPL transfer; omitted for SOL.
	Mint string `json:"mint,omitempty"`
	// Amount is the transferred quantity as a decimal u64 string in base
	// units: lamports for SOL, token base units for SPL.
	Amount string `json:"amount"`
	// Decimals is the decimals byte asserted by transferChecked; nil for
	// SOL transfers, which carry none.
	Decimals *uint8 `json:"decimals,omitempty"`
	// TokenProgram is the base58 id of the program executing the transfer
	// (Token or Token-2022); omitted for SOL.
	TokenProgram string `json:"tokenProgram,omitempty"`
}

// TransactionShape is the decoded semantic shape of a built transaction.
type TransactionShape struct {
	// FeePayer is the base58 key of account[0], the transaction fee payer.
	FeePayer string `json:"feePayer,omitempty"`
	// Transfers lists the decoded SOL and SPL transfers in instruction
	// order.
	Transfers []Transfer `json:"transfers,omitempty"`
	// ForbiddenPrograms lists base58 ids of disallowed programs found in
	// the transaction; this decoder reports none, so it stays empty and is
	// omitted on the wire.
	ForbiddenPrograms []string `json:"forbiddenPrograms,omitempty"`
	// MaxComputeUnitLimit is the cap from the ComputeBudget
	// SetComputeUnitLimit instruction; nil when the transaction sets none.
	MaxComputeUnitLimit *uint32 `json:"maxComputeUnitLimit,omitempty"`
	// MaxComputeUnitPrice is the SetComputeUnitPrice value in
	// micro-lamports per compute unit, as a decimal u64 string; empty when
	// the transaction sets none.
	MaxComputeUnitPrice string `json:"maxComputeUnitPrice,omitempty"`
	// Memo lists the Memo Program instruction payloads as UTF-8 strings,
	// in instruction order.
	Memo []string `json:"memo,omitempty"`
}

// ExactBytes carries the exact encoder outputs for canonical-bytes vectors.
type ExactBytes struct {
	// CanonicalJSON is the canonical (JCS) JSON text produced by the wire
	// encoder, where byte-for-byte agreement across SDKs is asserted.
	CanonicalJSON string `json:"canonicalJson,omitempty"`
	// Base64URL is the unpadded base64url encoding of the produced bytes
	// (canonical JSON, raw input bytes, challenge id, or voucher preimage).
	Base64URL string `json:"base64Url,omitempty"`
	// Bytes is the raw output, one int (0-255) per byte, so the harness
	// can diff exact bytes across SDKs.
	Bytes []int `json:"bytes,omitempty"`
}

// RunnerResult is the single JSON result line emitted on stdout.
type RunnerResult struct {
	// ID echoes the vector's id so the harness can pair result to vector.
	ID string `json:"id"`
	// Outcome is "accept" or "reject".
	Outcome string `json:"outcome"`
	// TransactionShape is the decoded semantic shape for accepted MPP
	// build/verify vectors; nil for other modes and on reject.
	TransactionShape *TransactionShape `json:"transactionShape,omitempty"`
	// X402EnvelopeShape is the decoded envelope shape for accepted
	// x402-exact vectors; nil for other intents and on reject.
	X402EnvelopeShape *X402EnvelopeShape `json:"x402EnvelopeShape,omitempty"`
	// ExactBytes carries the encoder outputs for canonical-bytes vectors;
	// nil for other modes.
	ExactBytes *ExactBytes `json:"exactBytes,omitempty"`
	// Error is the SDK's native error message when Outcome is "reject";
	// omitted on accept.
	Error string `json:"error,omitempty"`
	// RejectCode is the normalized cross-SDK reject category from
	// classifyReject; empty when the message is unclassified so the
	// harness can surface it instead of silently passing.
	RejectCode string `json:"rejectCode,omitempty"`
}

// rejectPattern pairs a compiled regex with the normalized RejectCode it
// classifies a Go SDK reject message into.
type rejectPattern struct {
	re   *regexp.Regexp // case-insensitive pattern matched against the SDK reject message
	code string         // normalized cross-SDK RejectCode emitted when re matches
}

// rejectPatterns maps the Go pay_kit SDK's native reject error strings onto
// the shared cross-SDK RejectCode vocabulary. The Go messages are tuned here
// against the real strings the SDK emits (e.g. "no matching token transfer
// for ..."), so the alternation includes "token". A transferChecked decimals
// mismatch is enforced through the transfer match key and so honestly
// surfaces as the generic no-matching-transfer category, not a
// decimals-specific code.
var rejectPatterns = []rejectPattern{
	{regexp.MustCompile(`(?i)compute unit price .* exceeds (maximum|cap)`), "compute-price-over-cap"},
	{regexp.MustCompile(`(?i)compute unit limit .* exceeds (maximum|cap)`), "compute-limit-over-cap"},
	{regexp.MustCompile(`(?i)fee payer cannot authorize`), "fee-payer-not-authority"},
	{regexp.MustCompile(`(?i)fee payer .* (funding source|funds source)`), "fee-payer-is-funds-source"},
	{regexp.MustCompile(`(?i)splits consume the entire amount`), "splits-exceed-amount"},
	{regexp.MustCompile(`(?i)too many splits`), "too-many-splits"},
	{regexp.MustCompile(`(?i)no matching (spl )?(token )?(transfer|transferchecked|sol transfer)`), "no-matching-transfer"},
	{regexp.MustCompile(`(?i)unexpected .* (instruction|transfer)`), "unexpected-instruction"},
	{regexp.MustCompile(`(?i)amount .* (mismatch|does not match)`), "amount-mismatch"},
	// x402-exact reject categories. `unsupported x402 version` must be
	// checked before the generic invalid/payload fallback (the message is
	// "invalid payload: unsupported x402 version: N"). `network mismatch`
	// likewise precedes the fallback.
	{regexp.MustCompile(`(?i)unsupported x402 version`), "unsupported-version"},
	{regexp.MustCompile(`(?i)network mismatch`), "wrong-network"},
	// payment-identifier gate: required-but-missing/invalid id.
	{regexp.MustCompile(`(?i)payment.identifier .*(required|missing|invalid)`), "payment-identifier-required"},
}

var invalidPayloadPattern = regexp.MustCompile(`(?i)invalid|malformed|decode|payload`)

// classifyReject normalizes a Go SDK reject message onto the shared
// RejectCode vocabulary. It returns "" when no pattern matches so the harness
// can surface an unclassified rejection instead of silently passing it.
func classifyReject(message string) string {
	if message == "" {
		return ""
	}
	for _, p := range rejectPatterns {
		if p.re.MatchString(message) {
			return p.code
		}
	}
	if invalidPayloadPattern.MatchString(message) {
		return "invalid-payload"
	}
	return ""
}

// localSigner adapts a 64-byte ed25519 secret key to solanatx.Signer, the
// same interface the Go client build path consumes. The vectors carry the
// signer as the transfer authority / fee payer.
type localSigner struct {
	priv solana.PrivateKey // 64-byte ed25519 keypair (seed || public key) backing PublicKey and Sign
}

func newLocalSigner(secret []byte) (*localSigner, error) {
	if len(secret) != 64 {
		return nil, fmt.Errorf("signerSecretKey must be 64 bytes, got %d", len(secret))
	}
	priv := solana.PrivateKey(secret)
	return &localSigner{priv: priv}, nil
}

func (s *localSigner) PublicKey() solana.PublicKey { return s.priv.PublicKey() }

func (s *localSigner) Sign(payload []byte) (solana.Signature, error) {
	return s.priv.Sign(payload)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return fmt.Errorf("go conformance runner received empty stdin")
	}
	var vector Vector
	if err := json.Unmarshal([]byte(trimmed), &vector); err != nil {
		return err
	}

	result := runVector(vector)
	out, err := json.Marshal(result)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func runVector(vector Vector) RunnerResult {
	if vector.Intent == "x402-exact" {
		return runX402(vector)
	}
	switch vector.Mode {
	case "canonical-bytes":
		if vector.Input.SessionAuthenticationMessage != nil || vector.Input.SessionWire != nil {
			// Session wire vectors need the final session wire contract,
			// which the Go SDK has not migrated to yet. Skip loudly instead
			// of failing on empty exactBytes.
			return RunnerResult{
				ID:      vector.ID,
				Outcome: "unsupported-mode",
				Error:   "unsupported-mode: session wire vectors are not implemented for the Go SDK yet",
			}
		}
		eb, err := runCanonicalBytes(vector)
		if err != nil {
			return rejected(vector.ID, err)
		}
		return RunnerResult{ID: vector.ID, Outcome: "accept", ExactBytes: eb}
	case "build-transaction":
		tx, err := buildTransaction(vector)
		if err != nil {
			return rejected(vector.ID, err)
		}
		shape, err := shapeFromTransaction(tx)
		if err != nil {
			return rejected(vector.ID, err)
		}
		return RunnerResult{ID: vector.ID, Outcome: "accept", TransactionShape: shape}
	case "verify-transaction":
		tx := vector.Input.Transaction
		if tx == "" {
			built, err := buildTransaction(vector)
			if err != nil {
				return rejected(vector.ID, err)
			}
			tx = built
		}
		if err := verifyTransaction(vector, tx); err != nil {
			return rejected(vector.ID, err)
		}
		shape, err := shapeFromTransaction(tx)
		if err != nil {
			return rejected(vector.ID, err)
		}
		return RunnerResult{ID: vector.ID, Outcome: "accept", TransactionShape: shape}
	default:
		return rejected(vector.ID, fmt.Errorf("unsupported mode %q", vector.Mode))
	}
}

func rejected(id string, err error) RunnerResult {
	msg := err.Error()
	return RunnerResult{ID: id, Outcome: "reject", Error: msg, RejectCode: classifyReject(msg)}
}

// flattenRequest applies the conformance contract's precedence rules:
// top-level asset / payTo win over currency / recipient, and the
// token program resolves explicit -> rpc-fixture mint owner ->
// default-by-currency so the build path stays RPC-free. It returns the
// charge fields plus the resolved paycore.MethodDetails the Go SDK consumes.
func flattenRequest(req *ChargeRequest, mintOwners map[string]string) (amount, currency, recipient string, details paycore.MethodDetails, err error) {
	currency = req.Currency
	if req.Asset != "" {
		currency = req.Asset
	}
	recipient = req.Recipient
	if req.PayTo != "" {
		recipient = req.PayTo
	}
	if recipient == "" {
		return "", "", "", paycore.MethodDetails{}, fmt.Errorf("vector request is missing recipient/payTo")
	}

	md := req.MethodDetails
	network := defaultNetwork
	if md != nil && md.Network != "" {
		network = md.Network
	}

	details = paycore.MethodDetails{Network: network}
	if md != nil {
		details.RecentBlockhash = md.RecentBlockhash
		details.FeePayer = md.FeePayer
		details.FeePayerKey = md.FeePayerKey
		details.Splits = md.Splits
		details.Decimals = md.Decimals
		details.TokenProgram = md.TokenProgram
	}

	isSOL := strings.EqualFold(currency, "sol")

	if details.TokenProgram == "" && !isSOL {
		resolvedMint := paycore.ResolveMint(currency, network)
		if resolvedMint == "" {
			resolvedMint = currency
		}
		if owner, ok := mintOwners[resolvedMint]; ok {
			details.TokenProgram = owner
		} else {
			details.TokenProgram = paycore.DefaultTokenProgramForCurrency(currency, network)
		}
	}

	if details.Decimals == nil && !isSOL {
		d := uint8(defaultSPLDecimals)
		details.Decimals = &d
	}

	return req.Amount, currency, recipient, details, nil
}

// buildTransaction drives the real Go client build path
// (client.BuildChargeTransaction) and returns the base64 wire transaction.
// recentBlockhash and the resolved token program keep the build RPC-free;
// the bogus rpcUrl ensures a missing blockhash surfaces as a clear failure.
func buildTransaction(vector Vector) (string, error) {
	in := vector.Input
	if in.Request == nil {
		return "", fmt.Errorf("build/verify vector is missing input.request")
	}
	if len(in.SignerSecretKey) == 0 {
		return "", fmt.Errorf("build/verify vector is missing input.signerSecretKey")
	}
	signer, err := newLocalSigner(in.SignerSecretKey)
	if err != nil {
		return "", err
	}
	var mintOwners map[string]string
	if in.RPCFixtures != nil {
		mintOwners = in.RPCFixtures.MintOwners
	}
	amount, currency, recipient, details, err := flattenRequest(in.Request, mintOwners)
	if err != nil {
		return "", err
	}

	options := client.BuildOptions{ExternalID: in.Request.ExternalID}
	if in.Request.ComputeUnitLimit != nil {
		options.ComputeUnitLimit = *in.Request.ComputeUnitLimit
	}
	if in.Request.ComputeUnitPrice != nil {
		price, perr := parseUint64(*in.Request.ComputeUnitPrice)
		if perr != nil {
			return "", perr
		}
		options.ComputeUnitPrice = price
	}

	payload, err := client.BuildChargeTransaction(
		context.Background(),
		signer,
		newOfflineRPC(),
		amount,
		currency,
		recipient,
		details,
		options,
	)
	if err != nil {
		return "", err
	}
	if payload.Transaction == "" {
		return "", fmt.Errorf("build produced no transaction payload")
	}
	return payload.Transaction, nil
}

// verifyTransaction drives the Go server's RPC-free pre-broadcast verify.
func verifyTransaction(vector Vector, transactionBase64 string) error {
	in := vector.Input
	if in.Request == nil {
		return fmt.Errorf("verify vector is missing input.request")
	}
	var mintOwners map[string]string
	if in.RPCFixtures != nil {
		mintOwners = in.RPCFixtures.MintOwners
	}
	amount, currency, recipient, details, err := flattenRequest(in.Request, mintOwners)
	if err != nil {
		return err
	}
	request := intents.ChargeRequest{
		Amount:     amount,
		Currency:   currency,
		Recipient:  recipient,
		ExternalID: in.Request.ExternalID,
	}
	return server.VerifyChargeTransactionPreBroadcast(transactionBase64, request, details, details.Network)
}

// runCanonicalBytes drives the wire canonical-JSON / base64url encoders.
func runCanonicalBytes(vector Vector) (*ExactBytes, error) {
	eb := &ExactBytes{}
	in := vector.Input
	if len(in.Value) > 0 {
		decoder := json.NewDecoder(strings.NewReader(string(in.Value)))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		canonical, err := wire.NewBase64URLJSONValue(value)
		if err != nil {
			return nil, err
		}
		decoded, err := wire.Base64URLDecode(canonical.Raw())
		if err != nil {
			return nil, err
		}
		eb.CanonicalJSON = string(decoded)
		eb.Base64URL = canonical.Raw()
	}
	if in.EncodeBase64URL != nil {
		enc := in.EncodeBase64URL
		switch {
		case enc.HexBytes != "":
			bytes, err := hex.DecodeString(enc.HexBytes)
			if err != nil {
				return nil, err
			}
			ints := make([]int, len(bytes))
			for i, b := range bytes {
				ints[i] = int(b)
			}
			eb.Bytes = ints
			eb.Base64URL = wire.Base64URLEncode(bytes)
		case enc.UTF8 != "":
			eb.Base64URL = wire.Base64URLEncode([]byte(enc.UTF8))
		}
	}
	if c := in.ChallengeID; c != nil {
		// base64url(HMAC-SHA256(secret, realm|method|intent|request|expires|
		// digest|opaque)); absent optionals join as empty strings. Drives the
		// production SDK derivation (wire.ComputeChallengeID).
		eb.Base64URL = wire.ComputeChallengeID(
			c.SecretKey, c.Realm, c.Method, c.Intent, c.Request, c.Expires, c.Digest, c.Opaque,
		)
	}
	if v := in.VoucherPreimage; v != nil {
		// The 50-byte session voucher preimage, computed by the production SDK
		// glue (paymentchannels.VoucherMessageBytes) so a byte mismatch is
		// caught here cross-SDK rather than behind a live channel.
		channel, err := solana.PublicKeyFromBase58(v.ChannelID)
		if err != nil {
			return nil, fmt.Errorf("invalid voucher channelId: %w", err)
		}
		cumulative, err := strconv.ParseUint(v.CumulativeAmount, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid voucher cumulativeAmount: %w", err)
		}
		preimage, err := paymentchannels.VoucherMessageBytes(channel, cumulative, v.ExpiresAt)
		if err != nil {
			return nil, err
		}
		ints := make([]int, len(preimage))
		for i, b := range preimage {
			ints[i] = int(b)
		}
		eb.Bytes = ints
		eb.Base64URL = wire.Base64URLEncode(preimage)
	}
	return eb, nil
}

// shapeFromTransaction decodes a base64 wire transaction into the semantic
// shape the conformance driver asserts against: fee payer is account[0], SPL
// transfers come from transferChecked (discriminator 12), SOL transfers from
// the System Program transfer (discriminator 2), memos from the Memo Program,
// and compute caps from the ComputeBudget program.
func shapeFromTransaction(transactionBase64 string) (*TransactionShape, error) {
	tx, err := solanatx.DecodeTransactionBase64(transactionBase64)
	if err != nil {
		return nil, err
	}
	keys := tx.Message.AccountKeys
	if len(keys) == 0 {
		return nil, fmt.Errorf("transaction has no account keys")
	}

	shape := &TransactionShape{
		FeePayer:          keys[0].String(),
		ForbiddenPrograms: []string{},
		Transfers:         []Transfer{},
		Memo:              []string{},
	}

	for _, ix := range tx.Message.Instructions {
		programIdx := int(ix.ProgramIDIndex)
		if programIdx < 0 || programIdx >= len(keys) {
			continue
		}
		program := keys[programIdx].String()
		data := []byte(ix.Data)

		switch program {
		case computeBudgetProgram:
			if len(data) == 5 && data[0] == 2 {
				limit := binary.LittleEndian.Uint32(data[1:5])
				shape.MaxComputeUnitLimit = &limit
			} else if len(data) == 9 && data[0] == 3 {
				price := binary.LittleEndian.Uint64(data[1:9])
				shape.MaxComputeUnitPrice = fmt.Sprintf("%d", price)
			}
		case memoProgram:
			shape.Memo = append(shape.Memo, string(data))
		case systemProgram:
			// System transfer: u32 LE discriminator 2 + u64 LE lamports.
			if len(data) >= 12 && binary.LittleEndian.Uint32(data[0:4]) == 2 {
				if len(ix.Accounts) < 2 {
					continue
				}
				dest := accountAt(keys, ix.Accounts, 1)
				if dest == "" {
					continue
				}
				shape.Transfers = append(shape.Transfers, Transfer{
					Kind:        "sol",
					Destination: dest,
					Amount:      fmt.Sprintf("%d", binary.LittleEndian.Uint64(data[4:12])),
				})
			}
		case tokenProgram, token2022Program:
			// transferChecked: discriminator 12, u64 amount at [1], decimals [9].
			if len(data) >= 10 && data[0] == 12 && len(ix.Accounts) >= 4 {
				mint := accountAt(keys, ix.Accounts, 1)
				dest := accountAt(keys, ix.Accounts, 2)
				if mint == "" || dest == "" {
					continue
				}
				decimals := data[9]
				shape.Transfers = append(shape.Transfers, Transfer{
					Kind:         "spl",
					Destination:  dest,
					Mint:         mint,
					Amount:       fmt.Sprintf("%d", binary.LittleEndian.Uint64(data[1:9])),
					Decimals:     &decimals,
					TokenProgram: program,
				})
			}
		}
	}

	return shape, nil
}

func accountAt(keys []solana.PublicKey, accounts []uint16, pos int) string {
	if pos < 0 || pos >= len(accounts) {
		return ""
	}
	idx := int(accounts[pos])
	if idx < 0 || idx >= len(keys) {
		return ""
	}
	return keys[idx].String()
}

func parseUint64(value string) (uint64, error) {
	var out uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(value), "%d", &out); err != nil {
		return 0, fmt.Errorf("invalid uint64 %q: %w", value, err)
	}
	return out, nil
}
