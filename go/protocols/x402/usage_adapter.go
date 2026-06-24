package x402

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/solana-foundation/pay-kit/go/paykit"
)

// usageAdapter bridges the x402 upto engine to the paykit.UsageAdapter
// interface, translating between paykit-level types (Gate, AdapterRequest)
// and the x402-level types (UptoRequirements, UptoPayload, etc.). It is
// constructed from a paykit.Config and registered via paykit.RegisterUsageAdapter
// in the package init().
type usageAdapter struct {
	engine *X402Upto
	cfg    paykit.Config
}

// NewUsageAdapter builds a paykit.UsageAdapter from the resolved config.
// It constructs an X402Upto engine with the operator signer, recipient,
// network, and currency from the paykit config. Returns nil (no error)
// when x402 is not accepted, so the caller can skip wiring.
func NewUsageAdapter(cfg paykit.Config) (paykit.UsageAdapter, error) {
	if cfg.Operator.Signer == nil {
		return nil, errors.New("usage adapter requires an operator signer")
	}
	coin := "USDC"
	if len(cfg.Stablecoins) > 0 {
		coin = string(cfg.Stablecoins[0])
	}
	uptoCfg := UptoConfig{
		Recipient:               string(cfg.Operator.Recipient),
		Currency:                coin,
		Decimals:                stablecoinDecimals,
		Network:                 cfg.Network,
		RPCURL:                  cfg.RPCURL,
		MaxTimeoutSeconds:       defaultMaxTimeoutSeconds,
		OperatorSigner:          cfg.Operator.Signer,
		RecentBlockhashProvider: cfg.RecentBlockhashProvider,
	}
	engine, err := NewX402Upto(uptoCfg)
	if err != nil {
		return nil, err
	}
	return &usageAdapter{engine: engine, cfg: cfg}, nil
}

func (u *usageAdapter) UsageChallengeHeaders(gate *paykit.Gate) map[string]string {
	header, value, err := u.engine.PaymentRequiredHeader(gateAmount(gate))
	if err != nil {
		return nil
	}
	return map[string]string{header: value}
}

func (u *usageAdapter) UsageAcceptsEntry(gate *paykit.Gate) paykit.AcceptsEntry {
	req, err := u.engine.UptoRequirements(gateAmount(gate))
	if err != nil {
		return nil
	}
	return uptoAcceptsEntry{req: req}
}

func (u *usageAdapter) DetectUsage(req *paykit.AdapterRequest) bool {
	return req.PaymentSig != "" || req.PaymentSigLegacy != ""
}

func (u *usageAdapter) VerifyOpen(ctx context.Context, req *paykit.AdapterRequest) (paykit.VerifiedUsageOpen, *paykit.Payment, error) {
	sig := req.PaymentSig
	if sig == "" {
		sig = req.PaymentSigLegacy
	}
	if sig == "" {
		return nil, nil, &paykit.PaymentError{Code: "payment_required", Err: paykit.ErrPaymentRequired, Gate: req.Gate}
	}
	maxAmount := gateAmount(req.Gate)
	verified, err := u.engine.VerifyOpen(ctx, sig, maxAmount)
	if err != nil {
		return nil, nil, &paykit.PaymentError{Code: "invalid_proof", Err: err, Gate: req.Gate}
	}
	pmt := &paykit.Payment{
		Protocol:          paykit.X402,
		Gate:              req.Gate.Name,
		Transaction:       "",
		SettlementHeaders: map[string]string{},
		Raw:               sig,
	}
	return verified, pmt, nil
}

func (u *usageAdapter) SettleActual(ctx context.Context, verified paykit.VerifiedUsageOpen, actual uint64) (*paykit.UsageSettlement, error) {
	open, ok := verified.(*UptoVerifiedOpen)
	if !ok || open == nil {
		return nil, errors.New("invalid verified open type")
	}
	settlement, err := u.engine.SettleActual(ctx, open, actual)
	if err != nil {
		return nil, err
	}
	headerName, headerValue, err := u.engine.SettlementHeader(settlement)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		headerName:       headerValue,
		settlementHeader: settlement.Transaction,
	}
	return &paykit.UsageSettlement{
		Transaction: settlement.Transaction,
		Headers:     headers,
	}, nil
}

// uptoAcceptsEntry wraps UptoRequirements to satisfy paykit.AcceptsEntry.
type uptoAcceptsEntry struct {
	req UptoRequirements
}

func (e uptoAcceptsEntry) AcceptsProtocol() paykit.Protocol { return paykit.X402 }

// MarshalJSON renders the upto requirements as the accepts[] entry shape.
func (e uptoAcceptsEntry) MarshalJSON() ([]byte, error) {
	type wireEntry struct {
		Protocol          string          `json:"protocol"`
		Scheme            string          `json:"scheme"`
		Network           string          `json:"network"`
		Amount            string          `json:"amount"`
		Asset             string          `json:"asset"`
		PayTo             string          `json:"payTo"`
		MaxTimeoutSeconds uint64          `json:"maxTimeoutSeconds"`
		Extra             json.RawMessage `json:"extra"`
	}
	extraRaw, err := json.Marshal(e.req.Extra)
	if err != nil {
		return nil, err
	}
	return json.Marshal(wireEntry{
		Protocol:          "x402",
		Scheme:            e.req.Scheme,
		Network:           e.req.Network,
		Amount:            e.req.Amount,
		Asset:             e.req.Asset,
		PayTo:             e.req.PayTo,
		MaxTimeoutSeconds: e.req.MaxTimeoutSeconds,
		Extra:             extraRaw,
	})
}

// gateAmount returns the gate's total as a human-decimal string for the
// upto engine (which converts to base units internally).
func gateAmount(gate *paykit.Gate) string {
	return gate.Total().Amount().String()
}

func init() {
	paykit.RegisterUsageAdapter(NewUsageAdapter)
}
