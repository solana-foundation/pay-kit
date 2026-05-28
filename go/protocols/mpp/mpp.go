// Package mpp wires the legacy server.Mpp charge handler into the
// paykit umbrella adapter contract. The adapter holds a per-(payTo,
// coin) cache of server.Mpp instances so the same Client can serve
// multiple gates with different recipients without rebuilding the
// charge handler per request.
package mpp

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"crypto/ed25519"

	solana "github.com/gagliardetto/solana-go"
	mpp "github.com/solana-foundation/pay-kit/go"
	"github.com/solana-foundation/pay-kit/go/internal/utils"
	"github.com/solana-foundation/pay-kit/go/paykit"
	"github.com/solana-foundation/pay-kit/go/protocol"
	"github.com/solana-foundation/pay-kit/go/server"
)

// signerBridge adapts a paykit.Signer (Sign(ctx, []byte) ([]byte,
// error)) to the utils.Signer the legacy server.Mpp expects
// (PublicKey() + Sign([]byte) (solana.Signature, error)). Only viable
// for in-process signers where SecretKey() exposes the 64-byte blob;
// remote KMS signers would need a separate bridge that respects ctx.
type signerBridge struct {
	paykit paykit.Signer
}

func (b *signerBridge) PublicKey() solana.PublicKey {
	pub, _ := solana.PublicKeyFromBase58(string(b.paykit.Pubkey()))
	return pub
}

func (b *signerBridge) Sign(payload []byte) (solana.Signature, error) {
	sk := b.paykit.SecretKey()
	if sk == nil {
		return solana.Signature{}, fmt.Errorf("signerBridge: signer does not expose a local secret key")
	}
	raw := ed25519.Sign(ed25519.PrivateKey(sk), payload)
	var sig solana.Signature
	copy(sig[:], raw)
	return sig, nil
}

// Adapter is the paykit.Adapter implementation for MPP charge intent.
// Holds the resolved paykit.Config and a per-(payTo,coin) cache of
// server.Mpp instances.
type Adapter struct {
	cfg     paykit.Config
	servers sync.Map // key: "<payTo>|<coin>" -> *server.Mpp
}

// New constructs a paykit.Adapter using the resolved config. Registered
// via the package init() below so paykit.New picks it up automatically
// when callers import the package as a blank import:
//
//	import _ "github.com/solana-foundation/pay-kit/go/protocols/mpp"
func New(cfg paykit.Config) (paykit.Adapter, error) {
	if len(cfg.MPP.ChallengeBindingSecret) == 0 {
		return nil, fmt.Errorf("protocols/mpp: MPP.ChallengeBindingSecret is required")
	}
	return &Adapter{cfg: cfg}, nil
}

func (a *Adapter) Scheme() paykit.Scheme { return paykit.MPP }

// AcceptsEntry is the typed JSON shape MPP emits into the 402
// body's `accepts[]` array. Mirrors Ruby's PayKit::Protocols::MPP
// accepts_entry hash and PHP's Adapter::acceptsEntry array.
type AcceptsEntry struct {
	Protocol string  `json:"protocol"`
	Scheme   string  `json:"scheme"`
	Network  string  `json:"network"`
	Amount   string  `json:"amount"`
	Currency string  `json:"currency"`
	PayTo    string  `json:"payTo"`
	Realm    string  `json:"realm"`
	Splits   []Split `json:"splits,omitempty"`
}

// Split is one fee-recipient entry inside [AcceptsEntry.Splits].
type Split struct {
	Recipient string `json:"recipient"`
	Amount    string `json:"amount"`
}

// AcceptsProtocol satisfies [paykit.AcceptsEntry].
func (e AcceptsEntry) AcceptsProtocol() paykit.Scheme { return paykit.MPP }

func (a *Adapter) AcceptsEntry(gate *paykit.Gate) paykit.AcceptsEntry {
	coin := a.settlementCoin(gate)
	payTo := a.payTo(gate)
	entry := AcceptsEntry{
		Protocol: "mpp",
		Scheme:   "charge",
		Network:  a.cfg.Network.CAIP2(),
		Amount:   a.totalUnits(gate, coin),
		Currency: coin,
		PayTo:    string(payTo),
		Realm:    a.cfg.MPP.Realm,
	}
	if gate.HasFees() {
		for addr, fee := range gate.FeeWithin {
			entry.Splits = append(entry.Splits, Split{Recipient: string(addr), Amount: a.priceUnits(fee)})
		}
		for addr, fee := range gate.FeeOnTop {
			entry.Splits = append(entry.Splits, Split{Recipient: string(addr), Amount: a.priceUnits(fee)})
		}
	}
	return entry
}

func (a *Adapter) ChallengeHeaders(gate *paykit.Gate) map[string]string {
	srv, err := a.serverFor(gate)
	if err != nil {
		return nil
	}
	challenge, err := srv.ChargeWithOptions(context.Background(), a.amountString(gate), a.chargeOptions(gate))
	if err != nil {
		return nil
	}
	wwwAuth, err := mpp.FormatWWWAuthenticate(challenge)
	if err != nil {
		return nil
	}
	return map[string]string{mpp.WWWAuthenticateHeader: wwwAuth}
}

func (a *Adapter) VerifyAndSettle(req *paykit.AdapterRequest) (*paykit.Payment, error) {
	auth := req.Authorization
	if !strings.HasPrefix(auth, "Payment ") {
		return nil, &paykit.PaymentError{
			Code: "payment_required",
			Err:  paykit.ErrPaymentRequired,
			Gate: req.Gate,
		}
	}
	srv, err := a.serverFor(req.Gate)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_proof", Err: err, Gate: req.Gate}
	}
	credential, err := mpp.ParseAuthorization(auth)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
	}
	// Rebuild the expected ChargeRequest from the gate so the
	// credential's pinned fields are verified against the route's
	// declared amount / recipient.
	challenge, err := srv.ChargeWithOptions(context.Background(), a.amountString(req.Gate), a.chargeOptions(req.Gate))
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_proof", Err: err, Gate: req.Gate}
	}
	var expected mpp.ChargeRequest
	if err := challenge.Request.Decode(&expected); err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
	}
	receipt, err := srv.VerifyCredentialWithExpected(context.Background(), credential, expected)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_proof", Err: err, Gate: req.Gate}
	}
	receiptHeader, err := mpp.FormatReceipt(receipt)
	headers := map[string]string{}
	if err == nil {
		headers[mpp.PaymentReceiptHeader] = receiptHeader
	}
	headers["x-payment-settlement-signature"] = receipt.Reference
	return &paykit.Payment{
		Scheme:            paykit.MPP,
		Gate:              req.Gate.Name,
		Transaction:       receipt.Reference,
		SettlementHeaders: headers,
		Raw:               auth,
	}, nil
}

// serverFor returns a cached *server.Mpp instance for the gate's
// (payTo, coin) tuple, building it on first miss.
func (a *Adapter) serverFor(gate *paykit.Gate) (*server.Mpp, error) {
	coin := a.settlementCoin(gate)
	payTo := a.payTo(gate)
	key := string(payTo) + "|" + coin
	if v, ok := a.servers.Load(key); ok {
		return v.(*server.Mpp), nil
	}
	var feePayer utils.Signer
	if a.cfg.Operator.FeePayer && a.cfg.Operator.Signer != nil && a.cfg.Operator.Signer.SecretKey() != nil {
		feePayer = &signerBridge{paykit: a.cfg.Operator.Signer}
	}
	srv, err := server.New(server.Config{
		Recipient:      string(payTo),
		SecretKey:      string(a.cfg.MPP.ChallengeBindingSecret),
		Currency:       coin,
		Network:        a.cfg.Network.MintsLabel(),
		Realm:          a.cfg.MPP.Realm,
		RPCURL:         a.cfg.RPCURL,
		Decimals:       uint8(decimalsFor(coin)), //nolint:gosec
		FeePayerSigner: feePayer,
	})
	if err != nil {
		return nil, err
	}
	a.servers.Store(key, srv)
	return srv, nil
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

func (a *Adapter) amountString(gate *paykit.Gate) string {
	return gate.Total().Amount().String()
}

func (a *Adapter) totalUnits(gate *paykit.Gate, coin string) string {
	dec := decimalsFor(coin)
	total := gate.Total().Amount()
	scaled := total.Shift(int32(dec))
	return scaled.Truncate(0).String()
}

func (a *Adapter) priceUnits(p paykit.Price) string {
	dec := decimalsFor(a.priceCoin(p))
	scaled := p.Amount().Shift(int32(dec))
	return scaled.Truncate(0).String()
}

func (a *Adapter) priceCoin(p paykit.Price) string {
	for _, s := range p.Settlements() {
		return string(s)
	}
	for _, s := range a.cfg.Stablecoins {
		return string(s)
	}
	return "USDC"
}

func (a *Adapter) chargeOptions(gate *paykit.Gate) server.ChargeOptions {
	opts := server.ChargeOptions{
		Description: gate.Desc,
		FeePayer:    a.cfg.Operator.FeePayer,
	}
	for addr, fee := range gate.FeeWithin {
		opts.Splits = append(opts.Splits, protocol.Split{
			Recipient: string(addr),
			Amount:    a.priceUnits(fee),
		})
	}
	for addr, fee := range gate.FeeOnTop {
		opts.Splits = append(opts.Splits, protocol.Split{
			Recipient: string(addr),
			Amount:    a.priceUnits(fee),
		})
	}
	return opts
}

func decimalsFor(coin string) int {
	// Mirrors the canonical mint table; all six-decimal stablecoins
	// share the same number, but PYUSD / USDG / CASH on Token-2022
	// still return 6 today.
	_ = protocol.ResolveMint
	return 6
}

func init() {
	paykit.RegisterAdapter(paykit.MPP, New)
}
