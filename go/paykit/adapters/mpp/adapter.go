package mpp

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/server"
	solana "github.com/solana-foundation/solana-go/v2"
)

type signerBridge struct {
	signer paykit.Signer
	// pub is the operator public key, decoded once in serverFor where the
	// base58 error can propagate. Storing it keeps PublicKey (which the
	// solanatx.Signer interface forbids from returning an error) from
	// having to swallow a decode failure.
	pub solana.PublicKey
}

func (b *signerBridge) PublicKey() solana.PublicKey {
	return b.pub
}

func (b *signerBridge) Sign(payload []byte) (solana.Signature, error) {
	raw, err := b.signer.Sign(context.Background(), payload)
	if err != nil {
		return solana.Signature{}, fmt.Errorf("signerBridge: %w", err)
	}
	if len(raw) != 64 {
		return solana.Signature{}, fmt.Errorf("signerBridge: signature length %d, want 64", len(raw))
	}
	var sig solana.Signature
	copy(sig[:], raw)
	return sig, nil
}

type Adapter struct {
	cfg       paykit.Config
	servers   sync.Map
	serversMu sync.Mutex
}

func New(cfg paykit.Config) (paykit.Adapter, error) {
	if len(cfg.MPP.ChallengeBindingSecret) == 0 {
		return nil, fmt.Errorf("protocols/mpp: MPP.ChallengeBindingSecret is required")
	}
	return &Adapter{cfg: cfg}, nil
}

func (a *Adapter) Protocol() paykit.Protocol { return paykit.MPP }

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

type Split struct {
	Recipient string `json:"recipient"`
	Amount    string `json:"amount"`
}

func (e AcceptsEntry) AcceptsProtocol() paykit.Protocol { return paykit.MPP }

func (a *Adapter) AcceptsEntry(gate *paykit.Gate) (paykit.AcceptsEntry, error) {
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
	return entry, nil
}

func (a *Adapter) ChallengeHeaders(gate *paykit.Gate) (map[string]string, error) {
	srv, err := a.serverFor(gate)
	if err != nil {
		return nil, err
	}
	challenge, err := srv.ChargeWithOptions(context.Background(), a.amountString(gate), a.chargeOptions(gate))
	if err != nil {
		return nil, fmt.Errorf("protocols/mpp: build charge challenge: %w", err)
	}
	wwwAuth, err := core.FormatWWWAuthenticate(challenge)
	if err != nil {
		return nil, fmt.Errorf("protocols/mpp: format WWW-Authenticate: %w", err)
	}
	return map[string]string{core.WWWAuthenticateHeader: wwwAuth}, nil
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
	credential, err := core.ParseAuthorization(auth)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
	}
	challenge, err := srv.ChargeWithOptions(context.Background(), a.amountString(req.Gate), a.chargeOptions(req.Gate))
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_proof", Err: err, Gate: req.Gate}
	}
	var expected core.ChargeRequest
	if err := challenge.Request.Decode(&expected); err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
	}
	receipt, err := srv.VerifyCredentialWithExpected(context.Background(), credential, expected)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_proof", Err: err, Gate: req.Gate}
	}
	receiptHeader, err := core.FormatReceipt(receipt)
	headers := map[string]string{}
	if err == nil {
		headers[core.PaymentReceiptHeader] = receiptHeader
	}
	headers["x-payment-settlement-signature"] = receipt.Reference
	return &paykit.Payment{
		Protocol:          paykit.MPP,
		Gate:              req.Gate.Name,
		Transaction:       receipt.Reference,
		SettlementHeaders: headers,
		Raw:               auth,
	}, nil
}

func (a *Adapter) serverFor(gate *paykit.Gate) (*server.Mpp, error) {
	coin := a.settlementCoin(gate)
	payTo := a.payTo(gate)
	key := string(payTo) + "|" + coin
	if v, ok := a.servers.Load(key); ok {
		return v.(*server.Mpp), nil
	}
	a.serversMu.Lock()
	defer a.serversMu.Unlock()
	if v, ok := a.servers.Load(key); ok {
		return v.(*server.Mpp), nil
	}
	var feePayer solanatx.Signer
	if a.cfg.Operator.FeePayer && a.cfg.Operator.Signer != nil {
		pub, err := solana.PublicKeyFromBase58(string(a.cfg.Operator.Signer.Pubkey()))
		if err != nil {
			return nil, fmt.Errorf("protocols/mpp: fee-payer pubkey: %w", err)
		}
		feePayer = &signerBridge{signer: a.cfg.Operator.Signer, pub: pub}
	}
	srv, err := server.New(server.Config{
		Recipient:      string(payTo),
		SecretKey:      string(a.cfg.MPP.ChallengeBindingSecret),
		Currency:       coin,
		Network:        a.cfg.Network.MintsLabel(),
		Realm:          a.cfg.MPP.Realm,
		RPCURL:         a.cfg.RPCURL,
		Decimals:       paycore.DefaultDecimalsForCurrency(coin, a.cfg.Network.MintsLabel()),
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
	dec := paycore.DefaultDecimalsForCurrency(coin, a.cfg.Network.MintsLabel())
	total := gate.Total().Amount()
	scaled := total.Shift(int32(dec))
	return scaled.Truncate(0).String()
}

func (a *Adapter) priceUnits(p paykit.Price) string {
	dec := paycore.DefaultDecimalsForCurrency(a.priceCoin(p), a.cfg.Network.MintsLabel())
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
	if a.cfg.MPP.ExpiresIn > 0 {
		opts.Expires = core.Seconds(uint64(a.cfg.MPP.ExpiresIn.Seconds()))
	}
	for addr, fee := range gate.FeeWithin {
		opts.Splits = append(opts.Splits, paycore.Split{
			Recipient: string(addr),
			Amount:    a.priceUnits(fee),
		})
	}
	for addr, fee := range gate.FeeOnTop {
		opts.Splits = append(opts.Splits, paycore.Split{
			Recipient: string(addr),
			Amount:    a.priceUnits(fee),
		})
	}
	return opts
}

func init() {
	paykit.RegisterAdapter(paykit.MPP, New)
}
