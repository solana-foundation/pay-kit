// Package client implements the x402 (exact scheme, Solana) client side,
// modelled on the Rust reference rather than the MPP challenge-response
// client: it parses a server's `payment-required` offer list, selects one
// offer by client preference (preferred network, then currency priority,
// then cheapest), builds and signs the SPL transferChecked (or native SOL)
// transaction the offer asks for, and resubmits it in the base64
// `Payment-Signature` credential envelope.
//
// Reference: rust/crates/x402/src/client/exact/payment.rs
// (build_payment, parse_x402_challenge_with_selection, select_requirement).
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	x402 "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// nonceBytes is the size of the random memo nonce the client appends when the
// offer does not pin an extra.memo. 16 bytes matches the x402 SVM spec
// minimum, and hex-encoding keeps the memo data valid UTF-8.
const nonceBytes = 16

// nonceSource produces the raw nonce bytes for the per-payment memo. It is a
// package var so deterministic/golden-vector tests can swap in a fixed nonce;
// production callers get a secure RNG via crypto/rand.
var nonceSource = func() ([]byte, error) {
	buf := make([]byte, nonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

const (
	paymentRequiredHeader  = "Payment-Required"
	paymentSignatureHeader = "Payment-Signature"
	x402Version            = 2

	// Legacy v1 wire names. A v1 server advertises its challenge either in
	// the X-PAYMENT-REQUIRED header or as a 402 JSON body, and a v1 client
	// posts its credential in the X-PAYMENT header. The default producer
	// stays v2 (Payment-Signature); the v1 producer is opt-in and only
	// emitted when the challenge itself declared v1. Mirrors the rust
	// constants X402_V1_PAYMENT_HEADER / X402_V1_PAYMENT_REQUIRED_HEADER
	// (constants.rs) and the v1 dual-read precedence (client/exact/payment.rs).
	paymentRequiredHeaderLegacy = "X-PAYMENT-REQUIRED"
	paymentHeaderLegacy         = "X-PAYMENT"
	x402VersionLegacy           = 1

	// exactScheme is the only x402 scheme; the v1 envelope carries it as a
	// top-level sibling of network and payload.
	exactScheme = "exact"

	// Plain legacy SVM network slugs. The v1 wire uses these instead of
	// the v2 CAIP-2 ids. Mirrors the rust v1_network_for_requirements
	// mapping (client/exact/payment.rs).
	legacyNetworkMainnet = "solana"
	legacyNetworkDevnet  = "solana-devnet"

	// solanaDevnetCAIP2 is the canonical devnet/localnet chain id offers
	// normalize to, used by the v1 network mapping to recognize a
	// devnet-family offer regardless of which slug it arrived as.
	solanaDevnetCAIP2 = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"

	// Compute-budget values mirror the Rust client: a small fixed limit
	// and a 1 microLamport priority price, both well under the server
	// caps (maxComputeUnitLimit / maxComputeUnitPriceMicroLamports).
	defaultComputeUnitLimit uint32 = 20_000
	defaultComputeUnitPrice uint64 = 1

	// maxMemoBytes is the x402-specific cap on a seller-pinned extra.memo,
	// matching Rust MAX_MEMO_BYTES (types.rs:9). Wider than this the
	// client rejects the offer before building the memo instruction.
	maxMemoBytes = 256
)

// mintResolutionLabels are the network labels a preferred currency symbol
// is resolved against when matching it to an offer's mint. Covers every
// cluster the offer could be on without needing a CAIP-2 -> label reverse
// map (localnet/devnet share a CAIP-2 id, and ResolveMint falls back to
// the mainnet mint for unknown labels).
var mintResolutionLabels = []string{"mainnet-beta", "devnet", "localnet"}

// solanaMainnetCAIP2 is the canonical mainnet chain id selectEntry
// defaults the preferred network to when the selection leaves it empty,
// matching the Rust select_requirement default (payment.rs:282-285).
const solanaMainnetCAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

// normalizeNetworkSlug maps cluster slugs and aliases to their canonical
// CAIP-2 id so a "devnet"/"mainnet" preference compares against an
// offer's normalized network. Mirrors the Rust caip2_network_for_cluster
// path (payment.rs:282-298). The AcceptsEntry parser already normalizes
// the offer side, so only the selection's preferred network needs it.
func normalizeNetworkSlug(network string) string {
	switch network {
	case "", "mainnet", "mainnet-beta", "solana", "solana_mainnet":
		return solanaMainnetCAIP2
	case "devnet", "solana-devnet", "localnet", "solana_devnet", "solana_localnet":
		return "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	case "testnet", "solana-testnet":
		return "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
	default:
		return network
	}
}

// ChallengeSelection captures client-side preferences for picking one offer
// from a server's accepts[] list. Mirrors the Rust ChallengeSelection.
type ChallengeSelection struct {
	// Network is the preferred CAIP-2 chain id. "" matches any Solana
	// offer.
	Network string
	// Currencies is a priority-ordered list of symbols ("USDC") or mint
	// addresses the client is willing to pay in. The first offer matching
	// the highest-priority currency wins; if none match, selection fails
	// (no cheapest fallback, matching the Rust behavior: the client
	// listed what it will pay, offering it anything else would be wrong).
	// nil falls back to cheapest-by-amount on the preferred network.
	Currencies []string
}

// challengeEnvelope is the parse-side shape of the base64 `payment-required`
// header body and the x402-express response body. Accepts decodes into the
// concrete x402 entry rather than the paykit.AcceptsEntry interface the
// server marshals from.
type challengeEnvelope struct {
	X402Version int                 `json:"x402Version"`
	Accepts     []x402.AcceptsEntry `json:"accepts"`
	// Extensions is the untyped v2 `extensions` passthrough the server
	// advertised on the challenge (rust PaymentRequiredEnvelope.extensions).
	// The client echoes it into the outbound credential. nil when absent.
	Extensions json.RawMessage `json:"extensions"`
}

// ParseChallenge parses an x402 challenge and selects one offer per the
// given preferences. Returns (nil, false) when no x402 offer is present or
// none matches the selection. It discards the declared wire version; use
// [ParseChallengeVersioned] when the caller needs to emit the matching
// producer.
func ParseChallenge(h http.Header, body []byte, sel ChallengeSelection) (*x402.AcceptsEntry, bool) {
	entry, _, ok := ParseChallengeVersioned(h, body, sel)
	return entry, ok
}

// ParseChallengeVersioned parses an x402 challenge and reports both the
// selected offer and the wire version the challenge declared, so the
// client can emit the producer the server expects. The dual-read
// precedence mirrors the rust spine (client/exact/payment.rs
// parse_x402_challenge_with_selection): the canonical PAYMENT-REQUIRED
// header first, then the legacy X-PAYMENT-REQUIRED header, then the 402
// JSON body. The returned version is the envelope's declared x402Version
// (defaulting to the canonical version when the field is absent), so the
// transport can stay a v2 producer by default and only fall back to the
// v1 producer when the server itself spoke v1.
func ParseChallengeVersioned(h http.Header, body []byte, sel ChallengeSelection) (*x402.AcceptsEntry, int, bool) {
	entry, version, _, ok := ParseChallengeVersionedWithExtensions(h, body, sel)
	return entry, version, ok
}

// ParseChallengeWithExtensions is ParseChallenge plus the verbatim v2
// `extensions` object the server advertised on the matched challenge
// envelope (rust PaymentRequiredEnvelope.extensions). The returned raw is
// nil when the server advertised none; pass it to
// BuildPaymentHeaderWithExtensions so the client echoes it back per x402
// v2 §5.1.2.
func ParseChallengeWithExtensions(h http.Header, body []byte, sel ChallengeSelection) (*x402.AcceptsEntry, json.RawMessage, bool) {
	entry, _, ext, ok := ParseChallengeVersionedWithExtensions(h, body, sel)
	return entry, ext, ok
}

// ParseChallengeVersionedWithExtensions is the unified challenge parser: it
// reports the selected offer, the declared wire version (so the transport
// emits the matching producer), and the verbatim v2 `extensions` object the
// server advertised (so the client echoes it per x402 v2 §5.1.2). The
// dual-read precedence mirrors the rust spine: the canonical
// PAYMENT-REQUIRED header first, then the legacy X-PAYMENT-REQUIRED header,
// then the 402 JSON body. The version defaults to the canonical version
// when the field is absent; advertised is nil when the server advertised
// no extensions (the legacy v1 wire never carries them).
func ParseChallengeVersionedWithExtensions(h http.Header, body []byte, sel ChallengeSelection) (*x402.AcceptsEntry, int, json.RawMessage, bool) {
	if raw := h.Get(paymentRequiredHeader); raw != "" {
		if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
			if entry, version, ext := selectFromJSON(decoded, sel); entry != nil {
				return entry, version, ext, true
			}
		}
	}
	if raw := h.Get(paymentRequiredHeaderLegacy); raw != "" {
		if entry, version, ext := selectFromJSON([]byte(raw), sel); entry != nil {
			return entry, version, ext, true
		}
	}
	if len(body) > 0 {
		if entry, version, ext := selectFromJSON(body, sel); entry != nil {
			return entry, version, ext, true
		}
	}
	return nil, 0, nil, false
}

func selectFromJSON(raw []byte, sel ChallengeSelection) (*x402.AcceptsEntry, int, json.RawMessage) {
	var env challengeEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, 0, nil
	}
	entry := selectEntry(env.Accepts, sel)
	if entry == nil {
		return nil, 0, nil
	}
	version := env.X402Version
	if version == 0 {
		version = x402Version
	}
	return entry, version, env.Extensions
}

// selectEntry implements the Rust select_requirement logic: keep Solana
// x402 offers, prefer the chosen network, then either match the client's
// currency priority order (first wins, no fallback) or pick the cheapest.
func selectEntry(accepts []x402.AcceptsEntry, sel ChallengeSelection) *x402.AcceptsEntry {
	solana := make([]x402.AcceptsEntry, 0, len(accepts))
	for _, e := range accepts {
		if e.Protocol == "x402" && strings.HasPrefix(e.Network, "solana:") {
			solana = append(solana, e)
		}
	}
	if len(solana) == 0 {
		return nil
	}

	// Rust defaults the preferred network to mainnet when the selection
	// leaves it empty and normalizes cluster slugs to CAIP-2 on both
	// sides before comparing (select_requirement, payment.rs:282-309).
	preferred := normalizeNetworkSlug(sel.Network)
	filtered := make([]x402.AcceptsEntry, 0, len(solana))
	for _, e := range solana {
		if e.Network == preferred {
			filtered = append(filtered, e)
		}
	}
	onNetwork := filtered

	if len(sel.Currencies) > 0 {
		for _, currency := range sel.Currencies {
			for i := range onNetwork {
				if currencyMatches(onNetwork[i].Asset, currency) {
					return &onNetwork[i]
				}
			}
		}
		return nil
	}

	if e := cheapest(onNetwork); e != nil {
		return e
	}
	return cheapest(solana)
}

// currencyMatches reports whether an offer's mint corresponds to a client
// currency preference. Both sides may be a symbol ("USDC") or a mint
// address; Rust currencies_match resolves BOTH through
// resolve_stablecoin_mint before comparing (payment.rs:344-348), so a
// symbol offer matches a mint-address preference and vice versa.
func currencyMatches(offerMint, preferred string) bool {
	if offerMint == preferred {
		return true
	}
	for _, label := range mintResolutionLabels {
		offerResolved := paycore.ResolveMint(offerMint, label)
		preferredResolved := paycore.ResolveMint(preferred, label)
		if offerResolved == preferredResolved {
			return true
		}
	}
	return false
}

// isNativeSOL reports whether an offer's asset is native SOL. An empty
// asset is native, and so is any currency that resolves to no mint
// (ResolveMint returns "" for "SOL"/"sol"), matching Rust resolve_mint
// -> None (payment.rs:60-73, solana.go:74-79).
func isNativeSOL(asset string) bool {
	if asset == "" {
		return true
	}
	for _, label := range mintResolutionLabels {
		if paycore.ResolveMint(asset, label) == "" {
			return true
		}
	}
	return false
}

func cheapest(entries []x402.AcceptsEntry) *x402.AcceptsEntry {
	best := -1
	var bestAmount uint64
	for i := range entries {
		amount, err := strconv.ParseUint(entries[i].Amount, 10, 64)
		if err != nil {
			continue
		}
		if best < 0 || amount < bestAmount {
			best, bestAmount = i, amount
		}
	}
	if best < 0 {
		return nil
	}
	return &entries[best]
}

// BuildPaymentHeader builds and signs the transaction the selected offer
// asks for and returns the base64 `Payment-Signature` credential envelope.
// The fee payer is the server's advertised `extra.feePayer` when present,
// leaving that signature slot empty for the server to cosign; otherwise the
// local signer pays fees.
func BuildPaymentHeader(
	ctx context.Context,
	signer solanatx.Signer,
	rpc solanatx.RPCClient,
	entry *x402.AcceptsEntry,
) (string, error) {
	return BuildPaymentHeaderWithExtensions(ctx, signer, rpc, entry, nil)
}

// BuildPaymentHeaderWithExtensions is BuildPaymentHeader plus the x402 v2
// echo-and-append rule (§5.1.2). It echoes the inbound challenge
// `extensions` object (advertised) into the outbound credential verbatim,
// preserving unknown extensions, and when the server marks payment-identifier
// info.required=true it appends a freshly generated `pay_`-shaped id
// (GeneratePaymentIdentifierID) without overwriting the server's fields.
// Pass advertised=nil (the server advertised no extensions) to omit the
// `extensions` object entirely. Mirrors rust build_payment_header(...,
// extensions) + PaymentExtensions::echoing + with_payment_identifier_id
// (payment.rs:132-150, types.rs:548-565).
func BuildPaymentHeaderWithExtensions(
	ctx context.Context,
	signer solanatx.Signer,
	rpc solanatx.RPCClient,
	entry *x402.AcceptsEntry,
	advertised json.RawMessage,
) (string, error) {
	if entry == nil {
		return "", errors.New("x402 client: nil accept entry")
	}
	extensions, err := echoAndAppendExtensions(advertised)
	if err != nil {
		return "", err
	}
	txBase64, err := buildTransaction(ctx, signer, rpc, entry)
	if err != nil {
		return "", err
	}
	credential := x402.Credential{
		X402Version: x402Version,
		// v2 omits top-level scheme/network (they ride in `accepted`),
		// matching the rust spine; only the v1 producer sets them.
		Payload:    x402.CredentialPayload{Transaction: txBase64},
		Accepted:   entry,
		Extensions: extensions,
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		return "", fmt.Errorf("x402 client: marshal credential: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// echoAndAppendExtensions implements the x402 v2 §5.1.2 echo-and-append
// rule: echo the inbound challenge extensions verbatim, and when the server
// requires a payment-identifier and the client has not already supplied an
// id, generate a fresh `pay_`-shaped one. Returns nil when the server
// advertised no extensions or the echoed object is empty, so the outbound
// omits the `extensions` key (never an empty {}), matching rust
// skip_serializing_if = Option::is_none + PaymentExtensions::is_empty.
func echoAndAppendExtensions(advertised json.RawMessage) (*x402.PaymentExtensions, error) {
	extensions, err := x402.EchoExtensions(advertised)
	if err != nil {
		return nil, fmt.Errorf("x402 client: echo extensions: %w", err)
	}
	if extensions == nil {
		return nil, nil
	}
	if extensions.RequiresPaymentIdentifier() && extensions.PaymentIdentifierID() == "" {
		extensions.WithPaymentIdentifierID(x402.GeneratePaymentIdentifierID())
	}
	if extensions.IsEmpty() {
		return nil, nil
	}
	return extensions, nil
}

// BuildPaymentHeaderV1 builds and signs the transaction the selected offer
// asks for and returns the base64 legacy `X-PAYMENT` credential envelope.
// The v1 wire shape carries the scheme and a plain network slug as
// top-level siblings of payload and commits to NO `accepted` object
// (unlike v2, the server binds only scheme+network). This is opt-in: the
// default producer stays v2 ([BuildPaymentHeader]); a client emits this
// only when the server's challenge declared v1. Mirrors the rust
// build_payment_header_v1 (client/exact/payment.rs).
func BuildPaymentHeaderV1(
	ctx context.Context,
	signer solanatx.Signer,
	rpc solanatx.RPCClient,
	entry *x402.AcceptsEntry,
) (string, error) {
	if entry == nil {
		return "", errors.New("x402 client: nil accept entry")
	}
	txBase64, err := buildTransaction(ctx, signer, rpc, entry)
	if err != nil {
		return "", err
	}
	credential := x402.Credential{
		X402Version: x402VersionLegacy,
		Scheme:      exactScheme,
		Network:     v1NetworkForEntry(entry),
		Payload:     x402.CredentialPayload{Transaction: txBase64},
		// No Accepted: the v1 envelope binds only scheme+network.
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		return "", fmt.Errorf("x402 client: marshal v1 credential: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// v1NetworkForEntry maps an offer's network to the plain legacy SVM slug
// the v1 wire uses: the devnet family (devnet/localnet, by cluster slug or
// the shared devnet CAIP-2 id) maps to "solana-devnet" and everything else
// maps to "solana". Mirrors the rust v1_network_for_requirements
// (client/exact/payment.rs): only the devnet family is special-cased;
// mainnet and testnet both collapse to the plain "solana" slug.
func v1NetworkForEntry(entry *x402.AcceptsEntry) string {
	switch entry.Network {
	case "devnet", "solana-devnet", "localnet", solanaDevnetCAIP2:
		return legacyNetworkDevnet
	default:
		return legacyNetworkMainnet
	}
}

func buildTransaction(
	ctx context.Context,
	signer solanatx.Signer,
	rpc solanatx.RPCClient,
	entry *x402.AcceptsEntry,
) (string, error) {
	amount, err := strconv.ParseUint(entry.Amount, 10, 64)
	if err != nil {
		return "", fmt.Errorf("x402 client: amount %q: %w", entry.Amount, err)
	}
	recipient, err := solana.PublicKeyFromBase58(entry.PayTo)
	if err != nil {
		return "", fmt.Errorf("x402 client: recipient %q: %w", entry.PayTo, err)
	}

	// Compute budget first; the verifier validates these by index.
	limitIx, err := solanatx.BuildComputeUnitLimit(defaultComputeUnitLimit)
	if err != nil {
		return "", err
	}
	priceIx, err := solanatx.BuildComputeUnitPrice(defaultComputeUnitPrice)
	if err != nil {
		return "", err
	}
	instructions := []solana.Instruction{limitIx, priceIx}

	// Native SOL when the currency resolves to no mint, mirroring Rust
	// resolve_mint -> None (payment.rs:60-73). ResolveMint returns "" for
	// SOL and any currency that maps to native SOL, so a literal "SOL"
	// asset routes to the system-transfer path, not transferChecked.
	if isNativeSOL(entry.Asset) {
		transfer, err := solanatx.BuildSOLTransfer(signer.PublicKey(), recipient, amount)
		if err != nil {
			return "", err
		}
		instructions = append(instructions, transfer)
	} else {
		transfer, err := buildSPLTransfer(signer, recipient, amount, entry)
		if err != nil {
			return "", err
		}
		instructions = append(instructions, transfer)
	}

	// The x402 SVM spec requires the client to ALWAYS append exactly one Memo
	// instruction so that otherwise-identical payments (same amount, mint,
	// recipient, blockhash) stay unique on-chain. Use the seller-pinned
	// extra.memo when present, otherwise a random >=16-byte nonce hex-encoded
	// to UTF-8.
	memoValue := entry.Extra.Memo
	if memoValue != "" {
		// Seller-pinned memo: reject when it exceeds the x402 256-byte
		// cap, matching Rust memo_instruction (payment.rs:357-362,
		// MAX_MEMO_BYTES=256). The shared BuildMemoInstruction 566-byte
		// bound is a wider Solana limit; this is the x402-specific cap.
		if len(memoValue) > maxMemoBytes {
			return "", fmt.Errorf("x402 client: extra.memo exceeds maximum %d bytes", maxMemoBytes)
		}
	} else {
		nonce, err := nonceSource()
		if err != nil {
			return "", fmt.Errorf("x402 client: generate memo nonce: %w", err)
		}
		memoValue = hex.EncodeToString(nonce)
	}
	memoIx, err := solanatx.BuildMemoInstruction(memoValue)
	if err != nil {
		return "", err
	}
	instructions = append(instructions, memoIx)

	blockhash, err := solanatx.ResolveRecentBlockhash(ctx, rpc, entry.Extra.RecentBlockhash)
	if err != nil {
		return "", fmt.Errorf("x402 client: recent blockhash: %w", err)
	}

	// Fee payer is the server when it advertises one AND opts in via the
	// boolean toggle, so the server cosigns the empty slot; otherwise the
	// local signer pays. Matches Rust use_fee_payer =
	// fee_payer.unwrap_or(false) && fee_payer_key.is_some()
	// (payment.rs:43-50): an explicit feePayer:false opts out even when a
	// key is present.
	payer := signer.PublicKey()
	if entry.Extra.FeePayer && entry.Extra.FeePayerKey != "" {
		payer, err = solana.PublicKeyFromBase58(entry.Extra.FeePayerKey)
		if err != nil {
			return "", fmt.Errorf("x402 client: fee payer %q: %w", entry.Extra.FeePayerKey, err)
		}
	}

	tx, err := solana.NewTransaction(instructions, blockhash, solana.TransactionPayer(payer))
	if err != nil {
		return "", fmt.Errorf("x402 client: build transaction: %w", err)
	}
	if err := solanatx.SignTransaction(tx, signer); err != nil {
		return "", fmt.Errorf("x402 client: sign: %w", err)
	}
	return solanatx.EncodeTransactionBase64(tx)
}

func buildSPLTransfer(
	signer solanatx.Signer,
	recipient solana.PublicKey,
	amount uint64,
	entry *x402.AcceptsEntry,
) (solana.Instruction, error) {
	mint, err := solana.PublicKeyFromBase58(entry.Asset)
	if err != nil {
		return nil, fmt.Errorf("x402 client: mint %q: %w", entry.Asset, err)
	}
	// Default the token program to the per-currency default when the
	// offer omits extra.tokenProgram, matching Rust
	// token_program.unwrap_or_else(default_token_program_for_currency)
	// (payment.rs:445-452). Resolved against every cluster label so a
	// Token-2022 mint (PYUSD/USDG/CASH) picks the right program.
	tokenProgramStr := entry.Extra.TokenProgram
	if tokenProgramStr == "" {
		for _, label := range mintResolutionLabels {
			if tp := paycore.DefaultTokenProgramForCurrency(entry.Asset, label); paycore.StablecoinSymbol(paycore.ResolveMint(entry.Asset, label)) != "" {
				tokenProgramStr = tp
				break
			}
		}
		if tokenProgramStr == "" {
			tokenProgramStr = paycore.DefaultTokenProgramForCurrency(entry.Asset, "mainnet-beta")
		}
	}
	tokenProgram, err := solana.PublicKeyFromBase58(tokenProgramStr)
	if err != nil {
		return nil, fmt.Errorf("x402 client: token program %q: %w", tokenProgramStr, err)
	}
	sourceATA, err := solanatx.FindAssociatedTokenAddressWithProgram(signer.PublicKey(), mint, tokenProgram)
	if err != nil {
		return nil, fmt.Errorf("x402 client: source ATA: %w", err)
	}
	destATA, err := solanatx.FindAssociatedTokenAddressWithProgram(recipient, mint, tokenProgram)
	if err != nil {
		return nil, fmt.Errorf("x402 client: recipient ATA: %w", err)
	}
	return solanatx.BuildTransferChecked(amount, uint8(entry.Extra.Decimals), sourceATA, mint, destATA, signer.PublicKey(), tokenProgram)
}

// PaymentTransport wraps an http.RoundTripper and transparently settles an
// x402 `402 Payment Required` challenge by building a credential and
// retrying the request once with the `Payment-Signature` header.
type PaymentTransport struct {
	Base      http.RoundTripper
	Signer    solanatx.Signer
	RPC       solanatx.RPCClient
	Selection ChallengeSelection
}

func (t *PaymentTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// RoundTrip implements http.RoundTripper.
func (t *PaymentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	resp, err := t.base().RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusPaymentRequired {
		return resp, nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	entry, version, advertised, ok := ParseChallengeVersionedWithExtensions(resp.Header, respBody, t.Selection)
	if !ok {
		return resp, nil // not an x402 offer we can satisfy; hand back the 402.
	}

	retry := req.Clone(req.Context())
	if bodyBytes != nil {
		retry.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Emit the wire version the server declared: a v1 challenge gets the
	// legacy X-PAYMENT producer, everything else stays on the canonical
	// Payment-Signature producer (the default). Mirrors the rust client
	// emitting the version the server's challenge declared while keeping
	// v2 the default producer. The legacy v1 wire carries no extensions;
	// the v2 producer echoes the advertised challenge extensions (§5.1.2).
	if version == x402VersionLegacy {
		header, err := BuildPaymentHeaderV1(req.Context(), t.Signer, t.RPC, entry)
		if err != nil {
			return nil, err
		}
		retry.Header.Set(paymentHeaderLegacy, header)
		return t.base().RoundTrip(retry)
	}

	header, err := BuildPaymentHeaderWithExtensions(req.Context(), t.Signer, t.RPC, entry, advertised)
	if err != nil {
		return nil, err
	}
	retry.Header.Set(paymentSignatureHeader, header)
	return t.base().RoundTrip(retry)
}

// NewClient returns an *http.Client whose transport settles x402 challenges
// with the given signer and RPC client, picking the cheapest Solana offer.
func NewClient(signer solanatx.Signer, rpc solanatx.RPCClient) *http.Client {
	return &http.Client{Transport: &PaymentTransport{Signer: signer, RPC: rpc}}
}
