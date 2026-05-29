package paykit

import (
	"fmt"

	"github.com/shopspring/decimal"
)

// ParseUSD builds a USD-denominated Price. Variadic settlements are
// preference order (first match wins against Config.Stablecoins). Use
// the splat form to pass a config field:
//
//	p, err := paykit.ParseUSD("0.10", cfg.Stablecoins...)
func ParseUSD(amount string, settlements ...Stablecoin) (Price, error) {
	return parsePrice(amount, USD, settlements)
}

// MustParseUSD is the boot-time variant; panics on a malformed amount.
func MustParseUSD(amount string, settlements ...Stablecoin) Price {
	p, err := ParseUSD(amount, settlements...)
	if err != nil {
		panic(err)
	}
	return p
}

// ParseEUR mirrors [ParseUSD] for euro-denominated prices.
func ParseEUR(amount string, settlements ...Stablecoin) (Price, error) {
	return parsePrice(amount, EUR, settlements)
}

// MustParseEUR is the boot-time variant; panics on a malformed amount.
func MustParseEUR(amount string, settlements ...Stablecoin) Price {
	p, err := ParseEUR(amount, settlements...)
	if err != nil {
		panic(err)
	}
	return p
}

// ParseGBP mirrors [ParseUSD] for pound-denominated prices.
func ParseGBP(amount string, settlements ...Stablecoin) (Price, error) {
	return parsePrice(amount, GBP, settlements)
}

// MustParseGBP is the boot-time variant; panics on a malformed amount.
func MustParseGBP(amount string, settlements ...Stablecoin) Price {
	p, err := ParseGBP(amount, settlements...)
	if err != nil {
		panic(err)
	}
	return p
}

func parsePrice(amount string, currency Currency, settlements []Stablecoin) (Price, error) {
	d, err := decimal.NewFromString(amount)
	if err != nil {
		return Price{}, fmt.Errorf("paykit: invalid %s amount %q: %w", currency, amount, err)
	}
	if d.IsNegative() {
		return Price{}, fmt.Errorf("paykit: %s amount %s must be non-negative", currency, amount)
	}
	out := Price{amount: d, currency: currency}
	if len(settlements) > 0 {
		out.settlements = make([]Stablecoin, len(settlements))
		copy(out.settlements, settlements)
	}
	return out, nil
}

// String renders the price in `<amount> <currency>` form for log lines.
func (p Price) String() string {
	return fmt.Sprintf("%s %s", p.amount.String(), p.currency)
}
