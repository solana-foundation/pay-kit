// Package intents carries the MPP intent request bodies: the charge intent
// (ChargeRequest, with string-encoded base-unit amounts so JSON consumers
// without u64 safety stay correct) and the session intent (SessionRequest plus
// the SessionAction credential union and signed vouchers). It also exposes the
// ParseUnits helper that converts a human-readable decimal amount into base
// units at the SDK boundary. The JSON wire format is identical across the
// language SDKs; the cross-language harness pins it.
package intents

import (
	"fmt"
	"math/big"
	"strings"
)

// ChargeRequest is the method-agnostic charge intent body.
type ChargeRequest struct {
	// Amount is the charge amount in token base units, as an unsigned
	// decimal string so JSON consumers without u64 safety stay exact
	// (e.g. "100000" = 0.10 USDC at 6 decimals).
	Amount string `json:"amount"`
	// Currency is the asset identifier (e.g. "USDC" or a mint address).
	Currency string `json:"currency"`
	// Recipient is the payee address (base58 for the Solana method);
	// omitted when the payment method's details carry the destination.
	Recipient string `json:"recipient,omitempty"`
	// Description is an optional human-readable label for the charge.
	Description string `json:"description,omitempty"`
	// ExternalID is an optional merchant reference, echoed back in the
	// payment receipt.
	ExternalID string `json:"externalId,omitempty"`
	// MethodDetails is the method-specific payload, opaque at the intent
	// layer; omitted when nil.
	MethodDetails any `json:"methodDetails,omitempty"`

	// Decimals, when non-nil, marks Amount as a human-readable decimal
	// that WithBaseUnits converts to base units. Never serialized.
	Decimals *uint8 `json:"-"`
}

// WithBaseUnits converts a decimal string to base units when Decimals is set.
func (r ChargeRequest) WithBaseUnits() (ChargeRequest, error) {
	if r.Decimals == nil {
		return r, nil
	}
	amount, err := ParseUnits(r.Amount, *r.Decimals)
	if err != nil {
		return ChargeRequest{}, err
	}
	r.Amount = amount
	r.Decimals = nil
	return r, nil
}

// ParseAmount parses the amount as an unsigned integer.
func (r ChargeRequest) ParseAmount() (uint64, error) {
	value := new(big.Int)
	if _, ok := value.SetString(r.Amount, 10); !ok || value.Sign() < 0 || !value.IsUint64() {
		return 0, fmt.Errorf("invalid amount: %s", r.Amount)
	}
	return value.Uint64(), nil
}

// ValidateMaxAmount rejects amounts above the provided maximum base units.
func (r ChargeRequest) ValidateMaxAmount(maxAmount string) error {
	actual, err := r.ParseAmount()
	if err != nil {
		return err
	}
	maxValue := new(big.Int)
	if _, ok := maxValue.SetString(maxAmount, 10); !ok || !maxValue.IsUint64() {
		return fmt.Errorf("invalid max amount: %s", maxAmount)
	}
	if actual > maxValue.Uint64() {
		return fmt.Errorf("amount %d exceeds maximum %d", actual, maxValue.Uint64())
	}
	return nil
}

// ParseUnits converts a human-readable decimal amount to base units.
func ParseUnits(amount string, decimals uint8) (string, error) {
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return "", fmt.Errorf("amount is required")
	}
	if strings.HasPrefix(amount, "-") {
		return "", fmt.Errorf("amount cannot be negative")
	}
	parts := strings.Split(amount, ".")
	if len(parts) > 2 {
		return "", fmt.Errorf("invalid amount: %s", amount)
	}
	whole := parts[0]
	if whole == "" {
		whole = "0"
	}
	fractional := ""
	if len(parts) == 2 {
		fractional = parts[1]
	}
	if len(fractional) > int(decimals) {
		return "", fmt.Errorf("amount %s has too many decimal places for %d decimals", amount, decimals)
	}
	value := whole + fractional + strings.Repeat("0", int(decimals)-len(fractional))
	value = strings.TrimLeft(value, "0")
	if value == "" {
		return "0", nil
	}
	bigValue := new(big.Int)
	if _, ok := bigValue.SetString(value, 10); !ok {
		return "", fmt.Errorf("invalid amount: %s", amount)
	}
	return bigValue.String(), nil
}
