package paykit

import (
	"fmt"

	"github.com/shopspring/decimal"
)

// Fees maps a payout recipient to the fee they receive. Map shape so
// one or many recipients use the same literal:
//
//	FeeOnTop: paykit.Fees{platform: paykit.MustParseUSD("0.30")}
type Fees = map[Address]Price

// Gate is a protected unit. It carries the base amount, optional fees,
// optional override of the operator recipient, and optional accepted-
// scheme override.
type Gate struct {
	Amount    Price
	PayTo     Address
	Accept    []Protocol
	Desc      string
	Name      string
	FeeWithin Fees
	FeeOnTop  Fees
}

// Total returns the customer-facing amount: Amount + sum(FeeOnTop).
// Advertised in the 402 challenge as `maxAmountRequired` (x402) /
// `amount` (MPP).
func (g *Gate) Total() Price {
	total := g.Amount.amount
	for _, p := range g.FeeOnTop {
		total = total.Add(p.amount)
	}
	return Price{amount: total, currency: g.Amount.currency, settlements: g.Amount.settlements}
}

// Payout returns the amount that lands at the given recipient address.
// Returns (zero, false) when the address is not part of the gate.
func (g *Gate) Payout(addr Address) (Price, bool) {
	if fee, ok := g.FeeOnTop[addr]; ok {
		return fee, true
	}
	if fee, ok := g.FeeWithin[addr]; ok {
		return fee, true
	}
	// The gate's main recipient nets Amount - sum(FeeWithin).
	if addr != "" && addr == g.PayTo {
		net := g.Amount.amount
		for _, p := range g.FeeWithin {
			net = net.Sub(p.amount)
		}
		return Price{amount: net, currency: g.Amount.currency, settlements: g.Amount.settlements}, true
	}
	return Price{}, false
}

// HasFees reports whether the gate ships any FeeWithin or FeeOnTop
// entries (used by the resolver to silently strip x402 when fees are
// present -- caveat #5 in design rule list).
func (g *Gate) HasFees() bool {
	return len(g.FeeWithin) > 0 || len(g.FeeOnTop) > 0
}

// Validate enforces the static gate invariants. Called automatically by
// Client.Require; safe to call manually inside a unit test.
func (g *Gate) Validate() error {
	if g == nil {
		return &GateError{Reason: "nil gate"}
	}
	if g.Amount.currency == "" {
		return &GateError{Reason: "gate amount must be a typed Price (use paykit.MustParseUSD)"}
	}
	currencies := map[Currency]struct{}{g.Amount.currency: {}}
	for addr, p := range g.FeeWithin {
		if addr == "" {
			return &GateError{Reason: "feeWithin recipient must be non-empty"}
		}
		currencies[p.currency] = struct{}{}
	}
	for addr, p := range g.FeeOnTop {
		if addr == "" {
			return &GateError{Reason: "feeOnTop recipient must be non-empty"}
		}
		currencies[p.currency] = struct{}{}
	}
	if len(currencies) > 1 {
		return &GateError{
			Reason:   fmt.Sprintf("gate mixes denominations %v", currencyKeys(currencies)),
			Sentinel: ErrMixedCurrencies,
		}
	}
	// sum(FeeWithin) <= Amount
	sumWithin := decimal.NewFromInt(0)
	for _, p := range g.FeeWithin {
		sumWithin = sumWithin.Add(p.amount)
	}
	if sumWithin.GreaterThan(g.Amount.amount) {
		return &GateError{
			Reason:   fmt.Sprintf("sum(FeeWithin)=%s exceeds Amount=%s", sumWithin, g.Amount.amount),
			Sentinel: ErrInvalidConfig,
		}
	}
	// x402 explicit + fees = boom (rule 5).
	if g.HasFees() {
		for _, s := range g.Accept {
			if s == X402 {
				return &GateError{
					Reason:   "x402 cannot settle multi-recipient gates",
					Sentinel: ErrSchemeIncompatible,
				}
			}
		}
	}
	return nil
}

func currencyKeys(m map[Currency]struct{}) []Currency {
	out := make([]Currency, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
