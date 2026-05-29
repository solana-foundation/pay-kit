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
	"encoding/base64"
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

const (
	paymentRequiredHeader  = "Payment-Required"
	paymentSignatureHeader = "Payment-Signature"
	x402Version            = 2

	// Compute-budget values mirror the Rust client: a small fixed limit
	// and a 1 microLamport priority price, both well under the server
	// caps (maxComputeUnitLimit / maxComputeUnitPriceMicroLamports).
	defaultComputeUnitLimit uint32 = 20_000
	defaultComputeUnitPrice uint64 = 1
)

// mintResolutionLabels are the network labels a preferred currency symbol
// is resolved against when matching it to an offer's mint. Covers every
// cluster the offer could be on without needing a CAIP-2 -> label reverse
// map (localnet/devnet share a CAIP-2 id, and ResolveMint falls back to
// the mainnet mint for unknown labels).
var mintResolutionLabels = []string{"mainnet-beta", "devnet", "localnet"}

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
}

// ParseChallenge parses an x402 challenge from the `payment-required`
// header and, failing that, the x402-express response body, then selects
// one offer per the given preferences. Returns (nil, false) when no x402
// offer is present or none matches the selection.
func ParseChallenge(h http.Header, body []byte, sel ChallengeSelection) (*x402.AcceptsEntry, bool) {
	if raw := h.Get(paymentRequiredHeader); raw != "" {
		if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
			if entry := selectFromJSON(decoded, sel); entry != nil {
				return entry, true
			}
		}
	}
	if len(body) > 0 {
		if entry := selectFromJSON(body, sel); entry != nil {
			return entry, true
		}
	}
	return nil, false
}

func selectFromJSON(raw []byte, sel ChallengeSelection) *x402.AcceptsEntry {
	var env challengeEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil
	}
	return selectEntry(env.Accepts, sel)
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

	onNetwork := solana
	if sel.Network != "" {
		filtered := make([]x402.AcceptsEntry, 0, len(solana))
		for _, e := range solana {
			if e.Network == sel.Network {
				filtered = append(filtered, e)
			}
		}
		onNetwork = filtered
	}

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
// currency preference, which may be a symbol ("USDC") or a mint address.
func currencyMatches(offerMint, preferred string) bool {
	if offerMint == preferred {
		return true
	}
	for _, label := range mintResolutionLabels {
		if paycore.ResolveMint(preferred, label) == offerMint {
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
	if entry == nil {
		return "", errors.New("x402 client: nil accept entry")
	}
	txBase64, err := buildTransaction(ctx, signer, rpc, entry)
	if err != nil {
		return "", err
	}
	credential := x402.Credential{
		X402Version: x402Version,
		Scheme:      entry.Scheme,
		Network:     entry.Network,
		Payload:     x402.CredentialPayload{Transaction: txBase64},
		Accepted:    entry,
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		return "", fmt.Errorf("x402 client: marshal credential: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
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

	// Asset == "" is a native SOL offer (Rust resolve_mint -> None);
	// otherwise it is an SPL mint and we transfer with transferChecked.
	if entry.Asset == "" {
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

	if entry.Extra.Memo != "" {
		memoIx, err := solanatx.BuildMemoInstruction(entry.Extra.Memo)
		if err != nil {
			return "", err
		}
		instructions = append(instructions, memoIx)
	}

	blockhash, err := solanatx.ResolveRecentBlockhash(ctx, rpc, entry.Extra.RecentBlockhash)
	if err != nil {
		return "", fmt.Errorf("x402 client: recent blockhash: %w", err)
	}

	// Fee payer is the server when it advertises one, so the server
	// cosigns the empty slot; otherwise the local signer pays.
	payer := signer.PublicKey()
	if entry.Extra.FeePayer != "" {
		payer, err = solana.PublicKeyFromBase58(entry.Extra.FeePayer)
		if err != nil {
			return "", fmt.Errorf("x402 client: fee payer %q: %w", entry.Extra.FeePayer, err)
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
	tokenProgram, err := solana.PublicKeyFromBase58(entry.Extra.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("x402 client: token program %q: %w", entry.Extra.TokenProgram, err)
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

	entry, ok := ParseChallenge(resp.Header, respBody, t.Selection)
	if !ok {
		return resp, nil // not an x402 offer we can satisfy; hand back the 402.
	}
	header, err := BuildPaymentHeader(req.Context(), t.Signer, t.RPC, entry)
	if err != nil {
		return nil, err
	}

	retry := req.Clone(req.Context())
	if bodyBytes != nil {
		retry.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	retry.Header.Set(paymentSignatureHeader, header)
	return t.base().RoundTrip(retry)
}

// NewClient returns an *http.Client whose transport settles x402 challenges
// with the given signer and RPC client, picking the cheapest Solana offer.
func NewClient(signer solanatx.Signer, rpc solanatx.RPCClient) *http.Client {
	return &http.Client{Transport: &PaymentTransport{Signer: signer, RPC: rpc}}
}
