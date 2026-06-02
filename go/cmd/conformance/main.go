// Command conformance is the Go cross-SDK conformance-vector runner.
//
// It honors the same stdin/stdout contract as the TypeScript reference
// runner (harness/src/conformance/ts-runner.ts): read one conformance
// vector as JSON on stdin, drive the real Go pay_kit SDK
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
	"strings"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/paycore"
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

// Vector mirrors harness/src/conformance/schema.ts ConformanceVector.
type Vector struct {
	ID          string          `json:"id"`
	Intent      string          `json:"intent"`
	Mode        string          `json:"mode"`
	Description string          `json:"description"`
	Input       VectorInput     `json:"input"`
	Expect      json.RawMessage `json:"expect"`
}

// VectorInput mirrors schema.ts VectorInput.
type VectorInput struct {
	Request         *ChargeRequest   `json:"request"`
	Transaction     string           `json:"transaction"`
	SignerSecretKey []byte           `json:"signerSecretKey"`
	RPCFixtures     *RPCFixtures     `json:"rpcFixtures"`
	Value           json.RawMessage  `json:"value"`
	EncodeBase64URL *EncodeBase64URL `json:"encodeBase64Url"`
	ChallengeID     *ChallengeID     `json:"challengeId"`

	// x402-exact inputs (mirror schema.ts VectorInput x402 fields).
	X402Offer             *X402Offer `json:"x402Offer"`
	X402Version           int        `json:"x402Version"`
	X402PinnedTransaction string     `json:"x402PinnedTransaction"`
	X402ServerNetwork     string     `json:"x402ServerNetwork"`
	X402ServerRecipient   string     `json:"x402ServerRecipient"`
	X402ServerCurrency    string     `json:"x402ServerCurrency"`
	X402ServerAmount      string     `json:"x402ServerAmount"`
	X402PaymentHeader     string     `json:"x402PaymentHeader"`
}

// ChargeRequest mirrors schema.ts VectorChargeRequest.
type ChargeRequest struct {
	Amount           string         `json:"amount"`
	Currency         string         `json:"currency"`
	ExternalID       string         `json:"externalId"`
	Recipient        string         `json:"recipient"`
	PayTo            string         `json:"payTo"`
	Asset            string         `json:"asset"`
	MethodDetails    *MethodDetails `json:"methodDetails"`
	ComputeUnitLimit *uint32        `json:"computeUnitLimit"`
	ComputeUnitPrice *string        `json:"computeUnitPrice"`
}

// MethodDetails mirrors schema.ts VectorChargeRequest.methodDetails.
type MethodDetails struct {
	Network         string          `json:"network"`
	Decimals        *uint8          `json:"decimals"`
	TokenProgram    string          `json:"tokenProgram"`
	RecentBlockhash string          `json:"recentBlockhash"`
	FeePayer        *bool           `json:"feePayer"`
	FeePayerKey     string          `json:"feePayerKey"`
	Splits          []paycore.Split `json:"splits"`
}

// RPCFixtures mirrors schema.ts VectorRpcFixtures.
type RPCFixtures struct {
	RecentBlockhash string            `json:"recentBlockhash"`
	MintOwners      map[string]string `json:"mintOwners"`
}

// EncodeBase64URL mirrors schema.ts encodeBase64Url.
type EncodeBase64URL struct {
	HexBytes string `json:"hexBytes"`
	UTF8     string `json:"utf8"`
}

// ChallengeID mirrors schema.ts VectorInput.challengeId: the inputs to the
// MPP charge challenge-id HMAC derivation.
type ChallengeID struct {
	SecretKey string `json:"secretKey"`
	Realm     string `json:"realm"`
	Method    string `json:"method"`
	Intent    string `json:"intent"`
	Request   string `json:"request"`
	Expires   string `json:"expires"`
	Digest    string `json:"digest"`
	Opaque    string `json:"opaque"`
}

// Transfer mirrors schema.ts TransactionShape.transfers element.
type Transfer struct {
	Kind             string `json:"kind"`
	Destination      string `json:"destination,omitempty"`
	DestinationOwner string `json:"destinationOwner,omitempty"`
	Mint             string `json:"mint,omitempty"`
	Amount           string `json:"amount"`
	Decimals         *uint8 `json:"decimals,omitempty"`
	TokenProgram     string `json:"tokenProgram,omitempty"`
}

// TransactionShape mirrors schema.ts TransactionShape.
type TransactionShape struct {
	FeePayer            string     `json:"feePayer,omitempty"`
	Transfers           []Transfer `json:"transfers,omitempty"`
	ForbiddenPrograms   []string   `json:"forbiddenPrograms,omitempty"`
	MaxComputeUnitLimit *uint32    `json:"maxComputeUnitLimit,omitempty"`
	MaxComputeUnitPrice string     `json:"maxComputeUnitPrice,omitempty"`
	Memo                []string   `json:"memo,omitempty"`
}

// ExactBytes mirrors schema.ts RunnerResult.exactBytes.
type ExactBytes struct {
	CanonicalJSON string `json:"canonicalJson,omitempty"`
	Base64URL     string `json:"base64Url,omitempty"`
	Bytes         []int  `json:"bytes,omitempty"`
}

// RunnerResult mirrors schema.ts RunnerResult.
type RunnerResult struct {
	ID                string             `json:"id"`
	Outcome           string             `json:"outcome"`
	TransactionShape  *TransactionShape  `json:"transactionShape,omitempty"`
	X402EnvelopeShape *X402EnvelopeShape `json:"x402EnvelopeShape,omitempty"`
	ExactBytes        *ExactBytes        `json:"exactBytes,omitempty"`
	Error             string             `json:"error,omitempty"`
	RejectCode        string             `json:"rejectCode,omitempty"`
}

// rejectPattern pairs a compiled regex with the normalized RejectCode it
// classifies a Go SDK reject message into.
type rejectPattern struct {
	re   *regexp.Regexp
	code string
}

// rejectPatterns mirrors harness/src/conformance/reject.ts: it maps the Go
// pay_kit SDK's native reject error strings onto the shared cross-SDK
// RejectCode vocabulary. The Go messages are tuned here against the real
// strings the SDK emits (e.g. "no matching token transfer for ..."), so the
// alternation includes "token". As in the reference, a transferChecked
// decimals mismatch is enforced through the transfer match key and so
// honestly surfaces as the generic no-matching-transfer category, not a
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
	// likewise precedes the fallback. Mirrors harness/src/conformance/reject.ts.
	{regexp.MustCompile(`(?i)unsupported x402 version`), "unsupported-version"},
	{regexp.MustCompile(`(?i)network mismatch`), "wrong-network"},
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
	priv solana.PrivateKey
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

// flattenRequest applies the same precedence rules as the TS reference
// runner: top-level asset / payTo win over currency / recipient, and the
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
		// production SDK derivation (wire.ComputeChallengeID), which mirrors
		// rust compute_challenge_id (protocol/core/challenge.rs).
		eb.Base64URL = wire.ComputeChallengeID(
			c.SecretKey, c.Realm, c.Method, c.Intent, c.Request, c.Expires, c.Digest, c.Opaque,
		)
	}
	return eb, nil
}

// shapeFromTransaction decodes a base64 wire transaction into the semantic
// shape the conformance driver asserts against. It mirrors the TS reference
// decoder (harness/src/conformance/decode.ts): fee payer is account[0], SPL
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
