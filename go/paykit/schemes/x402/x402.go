// Package x402 implements the x402 (exact scheme, Solana) adapter for
// the paykit umbrella. Issues challenges with a recent blockhash baked
// into `accepted.extra.recentBlockhash` (Ruby PR #142 caveat #5),
// runs base64 + signature validation on submitted credentials,
// partial-signs as the facilitator using the operator signer, and
// broadcasts via the configured RPC client. Delegated mode is gated
// off in v1; X402Config.FacilitatorURL must be empty.
package x402

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/paykit"
	"github.com/solana-foundation/pay-kit/go/protocol"
)

const (
	paymentRequiredHeader = "payment-required"
	paymentResponseHeader = "payment-response"
	settlementHeader      = "x-payment-settlement-signature"
	x402Version           = 2
	tokenProgramID        = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
)

// Adapter is the paykit.Adapter implementation for x402-exact.
type Adapter struct {
	cfg               paykit.Config
	rpc               *rpc.Client
	replay            sync.Map // credential signature -> struct{}
	blockhashProvider func() (string, error)
}

// New builds an x402 adapter from the resolved config.
func New(cfg paykit.Config) (paykit.Adapter, error) {
	if cfg.X402.FacilitatorURL != "" {
		return nil, errors.New("paykit/schemes/x402: delegated mode (FacilitatorURL) not yet implemented; leave empty for self-hosted")
	}
	rpcURL := cfg.RPCURL
	if rpcURL == "" {
		rpcURL = cfg.Network.DefaultRPCURL()
	}
	a := &Adapter{
		cfg:               cfg,
		rpc:               rpc.New(rpcURL),
		blockhashProvider: cfg.RecentBlockhashProvider,
	}
	return a, nil
}

func (a *Adapter) Scheme() paykit.Scheme { return paykit.X402 }

func (a *Adapter) AcceptsEntry(gate *paykit.Gate) map[string]any {
	coin := a.settlementCoin(gate)
	mint := protocol.ResolveMint(coin, a.cfg.Network.MintsLabel())
	amount := a.totalUnits(gate, coin)
	payTo := a.payTo(gate)
	extra := map[string]any{
		"feePayer":     string(a.cfg.Operator.Signer.Pubkey()),
		"decimals":     decimalsFor(coin),
		"tokenProgram": tokenProgramID,
		"memo":         gate.Desc,
	}
	if bh, err := a.recentBlockhash(); err == nil && bh != "" {
		// Caveat #5: stamp the server's recent blockhash so the
		// pay-kit Rust client can pin to it when building the tx
		// against a surfpool/forked-mainnet ledger the public RPC
		// has never seen.
		extra["recentBlockhash"] = bh
	}
	return map[string]any{
		"protocol":          "x402",
		"scheme":            a.cfg.X402.Scheme,
		"network":           a.cfg.Network.CAIP2(),
		"asset":             mint,
		"amount":            amount,
		"maxAmountRequired": amount,
		"payTo":             string(payTo),
		"maxTimeoutSeconds": 60,
		"extra":             extra,
	}
}

func (a *Adapter) ChallengeHeaders(gate *paykit.Gate) map[string]string {
	envelope := map[string]any{
		"x402Version": x402Version,
		"resource":    map[string]any{"type": "http", "url": gate.Desc},
		"accepts":     []any{a.AcceptsEntry(gate)},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil
	}
	return map[string]string{
		paymentRequiredHeader: base64.StdEncoding.EncodeToString(raw),
	}
}

func (a *Adapter) VerifyAndSettle(req *paykit.AdapterRequest) (*paykit.Payment, error) {
	sig := req.PaymentSig
	if sig == "" {
		return nil, &paykit.PaymentError{Code: "payment_required", Err: paykit.ErrPaymentRequired, Gate: req.Gate}
	}
	credBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: fmt.Errorf("base64 decode: %w", err), Gate: req.Gate}
	}
	var credential struct {
		X402Version int            `json:"x402Version"`
		Scheme      string         `json:"scheme"`
		Network     string         `json:"network"`
		Payload     map[string]any `json:"payload"`
		Accepted    map[string]any `json:"accepted"`
	}
	if err := json.Unmarshal(credBytes, &credential); err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: fmt.Errorf("decode credential: %w", err), Gate: req.Gate}
	}
	if credential.X402Version != x402Version {
		return nil, &paykit.PaymentError{Code: "version_mismatch", Err: fmt.Errorf("unsupported x402Version %d", credential.X402Version), Gate: req.Gate}
	}
	txBase64, _ := credential.Payload["transaction"].(string)
	if txBase64 == "" {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: errors.New("missing transaction payload"), Gate: req.Gate}
	}
	rawTx, err := base64.StdEncoding.DecodeString(txBase64)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: fmt.Errorf("transaction base64: %w", err), Gate: req.Gate}
	}
	// Deserialize as a versioned (v0 or legacy) transaction.
	tx, err := solana.TransactionFromDecoder(bin.NewBinDecoder(bytes.NewBuffer(rawTx).Bytes()))
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: fmt.Errorf("transaction decode: %w", err), Gate: req.Gate}
	}
	// Replay-store reservation.
	hash := tx.Signatures[0].String()
	if _, loaded := a.replay.LoadOrStore(hash, struct{}{}); loaded {
		return nil, &paykit.PaymentError{Code: "signature_consumed", Err: errors.New("replay rejected"), Gate: req.Gate}
	}
	// Partial-sign as the operator signer if it isn't already a
	// signature on the transaction (the client may have signed with
	// the operator's pubkey when the operator is fee-payer).
	if priv := a.cfg.Operator.Signer.SecretKey(); priv != nil {
		msg, err := tx.Message.MarshalBinary()
		if err != nil {
			return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
		}
		// Find the fee-payer index; for a versioned tx that is the
		// first account in the static accounts list. Replace the
		// placeholder zero-signature at that index with our signature
		// when needed.
		operatorPub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
		var operatorKey solana.PublicKey
		copy(operatorKey[:], operatorPub)
		for i, key := range tx.Message.AccountKeys {
			if key == operatorKey && i < len(tx.Signatures) {
				if tx.Signatures[i].IsZero() {
					sig := ed25519.Sign(ed25519.PrivateKey(priv), msg)
					var solSig solana.Signature
					copy(solSig[:], sig)
					tx.Signatures[i] = solSig
				}
			}
		}
	}
	wire, err := tx.MarshalBinary()
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
	}
	signature, err := a.rpc.SendEncodedTransactionWithOpts(context.Background(),
		base64.StdEncoding.EncodeToString(wire),
		rpc.TransactionOpts{
			Encoding:            solana.EncodingBase64,
			PreflightCommitment: rpc.CommitmentConfirmed,
		},
	)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "send_failed", Err: err, Gate: req.Gate}
	}
	respEnvelope := map[string]any{
		"success":     true,
		"transaction": signature.String(),
		"network":     a.cfg.Network.CAIP2(),
		"payer":       "",
	}
	respRaw, _ := json.Marshal(respEnvelope)
	headers := map[string]string{
		paymentResponseHeader: base64.StdEncoding.EncodeToString(respRaw),
		settlementHeader:      signature.String(),
	}
	return &paykit.Payment{
		Scheme:            paykit.X402,
		Gate:              req.Gate.Name,
		Transaction:       signature.String(),
		SettlementHeaders: headers,
		Raw:               sig,
	}, nil
}

func (a *Adapter) recentBlockhash() (string, error) {
	if a.blockhashProvider != nil {
		return a.blockhashProvider()
	}
	if a.rpc == nil {
		return "", errors.New("rpc client nil")
	}
	resp, err := a.rpc.GetLatestBlockhash(context.Background(), rpc.CommitmentConfirmed)
	if err != nil {
		return "", err
	}
	return resp.Value.Blockhash.String(), nil
}

func (a *Adapter) settlementCoin(gate *paykit.Gate) string {
	for _, s := range gate.Amount.Settlements() {
		return string(s)
	}
	for _, s := range a.cfg.Stablecoins {
		return string(s)
	}
	return "USDC"
}

func (a *Adapter) payTo(gate *paykit.Gate) paykit.Address {
	if gate.PayTo != "" {
		return gate.PayTo
	}
	return a.cfg.Operator.Recipient
}

func (a *Adapter) totalUnits(gate *paykit.Gate, coin string) string {
	dec := decimalsFor(coin)
	scaled := gate.Total().Amount().Shift(int32(dec))
	return scaled.Truncate(0).String()
}

func decimalsFor(_ string) int { return 6 }

func init() {
	paykit.RegisterAdapter(paykit.X402, New)
}
