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
// The runner passes each vector's request to the SDK verbatim and hands the
// SDK an RPC client pointed at the driver's fixture JSON-RPC
// (input.rpcUrl). It never fills defaults, applies field precedence or
// resolves chain state itself (harness/expectations/RULINGS.md).
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

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

// SessionVoucherVerify is one voucher checked against a fresh channel whose
// authorized signer is the vector's SignerSecretKey.
type SessionVoucherVerify struct {
	ChannelID               string `json:"channelId"`
	CumulativeAmount        string `json:"cumulativeAmount"`
	ExpiresAt               int64  `json:"expiresAt"`
	NowSeconds              int64  `json:"nowSeconds"`
	SettlementWindowSeconds int64  `json:"settlementWindowSeconds"`
	Deposit                 string `json:"deposit"`
}

// VectorInput carries the per-mode inputs of a conformance vector.
type VectorInput struct {
	// Request is the decoded charge request that drives the build/verify
	// modes, kept raw so it reaches the SDK's own wire type verbatim; empty
	// for encoder-only (canonical-bytes) vectors.
	Request json.RawMessage `json:"request"`
	// Transaction is a pinned base64 wire transaction to verify; empty in
	// verify mode means build one from Request first and verify that.
	Transaction string `json:"transaction"`
	// SignerSecretKey is the 64-byte ed25519 secret key (carried as a JSON
	// byte array) acting as transfer authority and default fee payer on
	// the client build path.
	SignerSecretKey []byte `json:"signerSecretKey"`
	// RPCURL is the fixture JSON-RPC the driver injects; the SDK reads all
	// chain state (blockhash, mint owner and decimals) through it.
	RPCURL string `json:"rpcUrl"`
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
	// SessionVoucherVerify drives the production voucher verifier against a
	// fresh channel at a pinned clock (verify-transaction, session intent).
	SessionVoucherVerify *SessionVoucherVerify `json:"sessionVoucherVerify"`
	SessionWire          json.RawMessage       `json:"sessionWire"`

	// x402-exact inputs.
	X402Offer json.RawMessage `json:"x402Offer"`
	// X402Version is the x402Version the build path should produce:
	// 1 builds the legacy top-level scheme/network envelope, 2 the
	// accepted-echo envelope, and 0 (absent) exercises the default
	// producer, which also emits 2.
	X402Version int `json:"x402Version"`
	// X402ServerFeePayer is the route's fee payer (sponsor) public key and
	// X402ServerFeePayerSecretKey its 64-byte secret, used to configure the
	// verifier the way an operator would.
	X402ServerFeePayer          string `json:"x402ServerFeePayer"`
	X402ServerFeePayerSecretKey []byte `json:"x402ServerFeePayerSecretKey"`
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
	// X402ServerMemo is the route's extra.memo; the verifier requires the
	// transaction's single Memo to carry it.
	X402ServerMemo string `json:"x402ServerMemo"`
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

// buildKnobs are the vector-only build options carried next to the charge
// request (compute budget overrides). They are client build options, not
// request fields, so they are read separately from the verbatim request.
type buildKnobs struct {
	ComputeUnitLimit *uint32 `json:"computeUnitLimit"`
	ComputeUnitPrice *string `json:"computeUnitPrice"`
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
	// Transaction is the built base64 wire transaction on an accepted charge
	// build; pkc verifies it with the Rust kit and compares its instruction
	// multiset with the kit's own build.
	Transaction string `json:"transaction,omitempty"`
	// X402PaymentHeader is the built base64 payment header on an accepted
	// x402 build, judged the same way.
	X402PaymentHeader string `json:"x402PaymentHeader,omitempty"`
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
	// Charge verification policy and client challenge checks (mirrors the
	// block at the top of harness/src/conformance/reject.ts), then the Go x402
	// verifier's static-layout and memo-count messages.
	{regexp.MustCompile(`(?i)fee payer (token account )?cannot fund`), "fee-payer-is-funds-source"},
	{regexp.MustCompile(`(?i)primary amount is zero after splits|split amounts exceed`), "splits-exceed-amount"},
	{regexp.MustCompile(`(?i)splits exceed maximum`), "too-many-splits"},
	{regexp.MustCompile(`(?i)ata creation owner is not authorized|unsupported compute budget|unexpected_signer|x402: unexpected instruction`), "unexpected-instruction"},
	{regexp.MustCompile(`(?i)atacreationrequired requires|unsupported challenge network|invalid amount|requires feepayerkey|invalid payment requirement: missing`), "invalid-challenge"},
	{regexp.MustCompile(`(?i)ata creation|ata payer|transaction fee payer (must be|mismatch)|memo cannot exceed|is not a computebudget|exactly one memo`), "invalid-payload"},
	{regexp.MustCompile(`(?i)compute unit price .* exceeds (maximum|cap)`), "compute-price-over-cap"},
	{regexp.MustCompile(`(?i)compute unit limit .* exceeds (maximum|cap)`), "compute-limit-over-cap"},
	{regexp.MustCompile(`(?i)fee payer cannot authorize|transfer authority is the fee-payer|references the fee payer in its accounts`), "fee-payer-not-authority"},
	// x402 v2: the credential's `accepted` disagrees with the route.
	{regexp.MustCompile(`(?i)recipient mismatch|currency mismatch|amount mismatch: expected \d+, got \d+|accepted .*does not match`), "accepted-mismatch"},
	{regexp.MustCompile(`(?i)amount mismatch: got \d+, want at least`), "amount-mismatch"},
	{regexp.MustCompile(`(?i)expected exactly one matching transferchecked, found \d+`), "unexpected-instruction"},
	{regexp.MustCompile(`(?i)is not an spl token transfer|found 0 matching`), "no-matching-transfer"},
	{regexp.MustCompile(`(?i)no memo instruction found|memo mismatch|memo count|does not match extra\.memo`), "invalid-payload"},
	{regexp.MustCompile(`(?i)fee payer .* (funding source|funds source)`), "fee-payer-is-funds-source"},
	{regexp.MustCompile(`(?i)splits consume the entire amount`), "splits-exceed-amount"},
	{regexp.MustCompile(`(?i)too many splits`), "too-many-splits"},
	{regexp.MustCompile(`(?i)no matching (spl )?(token )?(transfer|transferchecked|sol transfer)`), "no-matching-transfer"},
	{regexp.MustCompile(`(?i)unexpected .* (instruction|transfer)`), "unexpected-instruction"},
	{regexp.MustCompile(`(?i)amount .* (mismatch|does not match)`), "amount-mismatch"},
	{regexp.MustCompile(`(?i)share one funding authority`), "mixed-funding-authority"},
	{regexp.MustCompile(`(?i)unexpected signer`), "unexpected-signer"},
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
	for _, arg := range os.Args[1:] {
		if arg == "--serve" {
			if err := serve(os.Stdin, os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// claimedIntents are the intents this runner implements; pkc checks them against
// harness/expectations/go.toml.
var claimedIntents = []string{"charge", "x402-exact", "session"}

// serve speaks testee ABI v2 (harness/README.md): newline JSON
// {id, op, input} in, {id, ok, result | error} out, one long-lived process.
// input is the v1 vector and result the v1 RunnerResult.
func serve(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	encoder := json.NewEncoder(out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var request struct {
			ID    json.RawMessage `json:"id"`
			Op    string          `json:"op"`
			Input json.RawMessage `json:"input"`
		}
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			if err := encoder.Encode(map[string]any{"id": nil, "ok": false, "error": "bad-request", "detail": err.Error()}); err != nil {
				return err
			}
			continue
		}
		var response map[string]any
		switch request.Op {
		case "capabilities":
			response = map[string]any{"id": request.ID, "ok": true, "result": map[string]any{
				"abi": 2, "language": "go", "intents": claimedIntents, "honoursClock": true,
			}}
		case "build", "verify", "canonical-bytes":
			var vector Vector
			if err := json.Unmarshal(request.Input, &vector); err != nil {
				response = map[string]any{"id": request.ID, "ok": false, "error": "bad-request", "detail": err.Error()}
				break
			}
			response = map[string]any{"id": request.ID, "ok": true, "result": runVector(vector)}
		default:
			response = map[string]any{"id": request.ID, "ok": false, "error": "unknown-op", "detail": request.Op}
		}
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
	return scanner.Err()
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
	if vector.Intent == "session" && vector.Mode == "verify-transaction" {
		if vector.Input.SessionVoucherVerify == nil {
			return RunnerResult{ID: vector.ID, Outcome: "unsupported-mode", Error: "unsupported-mode: session verify input"}
		}
		result, err := runSessionVoucherVerify(vector)
		if err != nil {
			return rejected(vector.ID, err)
		}
		return result
	}
	switch vector.Mode {
	case "canonical-bytes":
		if vector.Input.SessionAuthenticationMessage != nil || vector.Input.SessionWire != nil {
			// The Go session wire types have not migrated to the final
			// contract, so a round-trip through them would assert the
			// superseded draft. Skip loudly instead of failing on empty
			// exactBytes.
			return RunnerResult{
				ID:      vector.ID,
				Outcome: "unsupported-mode",
				Error:   "unsupported-mode: Go session wire types are on the superseded draft, not mpp-specs e702dd8: intents.OpenPayload carries recentSlot instead of openSlot and SignedVoucher nests the voucher under data instead of voucher (go/protocols/mpp/intents/session.go)",
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
		return RunnerResult{ID: vector.ID, Outcome: "accept", TransactionShape: shape, Transaction: tx}
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

// runSessionVoucherVerify signs one voucher with the vector key and drives
// the production verifier against a fresh channel at the pinned clock.
func runSessionVoucherVerify(vector Vector) (RunnerResult, error) {
	in := vector.Input.SessionVoucherVerify
	if len(vector.Input.SignerSecretKey) != ed25519.PrivateKeySize {
		return RunnerResult{}, fmt.Errorf("signerSecretKey must be %d bytes", ed25519.PrivateKeySize)
	}
	key := ed25519.PrivateKey(vector.Input.SignerSecretKey)
	signer := solana.PublicKeyFromBytes(key.Public().(ed25519.PublicKey)).String()
	deposit, err := strconv.ParseUint(in.Deposit, 10, 64)
	if err != nil {
		return RunnerResult{}, fmt.Errorf("invalid deposit: %w", err)
	}
	data := intents.VoucherData{ChannelID: in.ChannelID, Cumulative: in.CumulativeAmount, ExpiresAt: in.ExpiresAt}
	message, err := data.MessageBytes()
	if err != nil {
		return RunnerResult{}, err
	}
	signed := intents.SignedVoucher{Data: data, Signature: solana.SignatureFromBytes(ed25519.Sign(key, message)).String()}
	now := in.NowSeconds
	result := server.VerifyVoucherForChannel(server.VerifyVoucherArgs{
		State:                   server.ChannelState{ChannelID: in.ChannelID, AuthorizedSigner: signer, Deposit: deposit},
		Signed:                  signed,
		Deposit:                 deposit,
		SettlementWindowSeconds: in.SettlementWindowSeconds,
		NowSeconds:              &now,
	})
	switch result.Status {
	case server.VoucherVerifyAccepted:
		return RunnerResult{ID: vector.ID, Outcome: "accept"}, nil
	case server.VoucherVerifyRejected:
		out := RunnerResult{ID: vector.ID, Outcome: "reject", Error: fmt.Sprintf("%s: %s", result.Reason, result.Detail)}
		switch result.Reason {
		case server.VoucherRejectExpired:
			out.RejectCode = "voucher-expired"
		case server.VoucherRejectExpiryTooSoon:
			out.RejectCode = "voucher-expires-before-settlement"
		}
		return out, nil
	default:
		return RunnerResult{ID: vector.ID, Outcome: "reject", Error: "unexpected replay"}, nil
	}
}

func rejected(id string, err error) RunnerResult {
	msg := err.Error()
	return RunnerResult{ID: id, Outcome: "reject", Error: msg, RejectCode: rejectCodeOf(err)}
}

// rejectCodeOf maps the SDK's structured error code first (a challenge the
// client refuses is paycore code "invalid-challenge"), then falls back to
// the message classifier.
func rejectCodeOf(err error) string {
	var sdkErr *paycore.Error
	if errors.As(err, &sdkErr) && sdkErr.Code == "invalid-challenge" {
		return "invalid-challenge"
	}
	return classifyReject(err.Error())
}

// sdkRPC returns the SDK RPC client for the driver's fixture JSON-RPC.
func sdkRPC(in VectorInput) (*rpc.Client, error) {
	if in.RPCURL == "" {
		return nil, fmt.Errorf("driver did not inject input.rpcUrl")
	}
	return rpc.New(in.RPCURL), nil
}

// decodeRequest decodes the vector request into the SDK's wire types
// exactly as the client decodes a challenge request: intents.ChargeRequest,
// then its methodDetails into paycore.MethodDetails. Nothing is defaulted.
func decodeRequest(raw json.RawMessage) (intents.ChargeRequest, paycore.MethodDetails, error) {
	if len(raw) == 0 {
		return intents.ChargeRequest{}, paycore.MethodDetails{}, fmt.Errorf("build/verify vector is missing input.request")
	}
	var request intents.ChargeRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return intents.ChargeRequest{}, paycore.MethodDetails{}, fmt.Errorf("invalid payload: decode request: %w", err)
	}
	var details paycore.MethodDetails
	if request.MethodDetails != nil {
		mdRaw, err := json.Marshal(request.MethodDetails)
		if err != nil {
			return intents.ChargeRequest{}, paycore.MethodDetails{}, err
		}
		if err := json.Unmarshal(mdRaw, &details); err != nil {
			return intents.ChargeRequest{}, paycore.MethodDetails{}, fmt.Errorf("invalid payload: decode methodDetails: %w", err)
		}
	}
	return request, details, nil
}

// buildTransaction drives the real Go client build path
// (client.BuildChargeTransaction) against the fixture RPC and returns the
// base64 wire transaction.
func buildTransaction(vector Vector) (string, error) {
	in := vector.Input
	if len(in.SignerSecretKey) == 0 {
		return "", fmt.Errorf("build/verify vector is missing input.signerSecretKey")
	}
	signer, err := newLocalSigner(in.SignerSecretKey)
	if err != nil {
		return "", err
	}
	request, details, err := decodeRequest(in.Request)
	if err != nil {
		return "", err
	}
	var knobs buildKnobs
	if err := json.Unmarshal(in.Request, &knobs); err != nil {
		return "", err
	}
	rpcClient, err := sdkRPC(in)
	if err != nil {
		return "", err
	}

	options := client.BuildOptions{ExternalID: request.ExternalID}
	if knobs.ComputeUnitLimit != nil {
		options.ComputeUnitLimit = *knobs.ComputeUnitLimit
	}
	if knobs.ComputeUnitPrice != nil {
		price, perr := parseUint64(*knobs.ComputeUnitPrice)
		if perr != nil {
			return "", perr
		}
		options.ComputeUnitPrice = price
	}

	payload, err := client.BuildChargeTransaction(
		context.Background(),
		signer,
		rpcClient,
		request.Amount,
		request.Currency,
		request.Recipient,
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

// verifyTransaction drives the Go server's pre-broadcast verify with the
// request exactly as the challenge carries it.
func verifyTransaction(vector Vector, transactionBase64 string) error {
	request, details, err := decodeRequest(vector.Input.Request)
	if err != nil {
		return err
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
