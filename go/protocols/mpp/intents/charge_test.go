package intents

import "testing"

func TestParseUnits(t *testing.T) {
	value, err := ParseUnits("1.5", 6)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if value != "1500000" {
		t.Fatalf("unexpected units %q", value)
	}
}

func TestChargeRequestWithBaseUnits(t *testing.T) {
	decimals := uint8(6)
	request, err := (ChargeRequest{Amount: "2.25", Decimals: &decimals}).WithBaseUnits()
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	if request.Amount != "2250000" || request.Decimals != nil {
		t.Fatalf("unexpected request: %#v", request)
	}
}

func TestValidateMaxAmount(t *testing.T) {
	if err := (ChargeRequest{Amount: "10"}).ValidateMaxAmount("9"); err == nil {
		t.Fatal("expected max amount validation to fail")
	}
}

func TestParseUnitsZeroAmount(t *testing.T) {
	value, err := ParseUnits("0", 6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "0" {
		t.Fatalf("expected 0, got %q", value)
	}
}

func TestParseUnitsNegativeAmount(t *testing.T) {
	if _, err := ParseUnits("-1.5", 6); err == nil {
		t.Fatal("expected error for negative amount")
	}
}

func TestParseUnitsTooManyDecimalPlaces(t *testing.T) {
	if _, err := ParseUnits("1.1234567", 6); err == nil {
		t.Fatal("expected error for too many decimal places")
	}
}

func TestParseUnitsIntegerAmount(t *testing.T) {
	value, err := ParseUnits("42", 6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "42000000" {
		t.Fatalf("expected 42000000, got %q", value)
	}
}

func TestParseUnitsEmptyAmount(t *testing.T) {
	if _, err := ParseUnits("", 6); err == nil {
		t.Fatal("expected error for empty amount")
	}
}

func TestParseUnitsWhitespaceAmount(t *testing.T) {
	if _, err := ParseUnits("   ", 6); err == nil {
		t.Fatal("expected error for whitespace amount")
	}
}

func TestParseUnitsMultipleDots(t *testing.T) {
	if _, err := ParseUnits("1.2.3", 6); err == nil {
		t.Fatal("expected error for multiple dots")
	}
}

func TestParseAmountValidStrings(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
	}{
		{"0", 0},
		{"1", 1},
		{"1000000", 1000000},
		{"18446744073709551615", 18446744073709551615},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			r := ChargeRequest{Amount: tc.input}
			got, err := r.ParseAmount()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, got)
			}
		})
	}
}

func TestParseAmountInvalidStrings(t *testing.T) {
	invalids := []string{"-1", "abc", "1.5", "", "99999999999999999999999999999"}
	for _, input := range invalids {
		t.Run(input, func(t *testing.T) {
			r := ChargeRequest{Amount: input}
			if _, err := r.ParseAmount(); err == nil {
				t.Fatalf("expected error for %q", input)
			}
		})
	}
}

func TestWithBaseUnitsRoundTrip(t *testing.T) {
	decimals := uint8(9)
	r := ChargeRequest{Amount: "1.5", Decimals: &decimals}
	converted, err := r.WithBaseUnits()
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	if converted.Amount != "1500000000" {
		t.Fatalf("expected 1500000000, got %q", converted.Amount)
	}
	if converted.Decimals != nil {
		t.Fatal("decimals should be nil after conversion")
	}
}

func TestWithBaseUnitsNoDecimals(t *testing.T) {
	r := ChargeRequest{Amount: "1000"}
	converted, err := r.WithBaseUnits()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if converted.Amount != "1000" {
		t.Fatalf("amount should be unchanged, got %q", converted.Amount)
	}
}

func TestValidateMaxAmountEdgeCases(t *testing.T) {
	// Exact match should pass
	if err := (ChargeRequest{Amount: "100"}).ValidateMaxAmount("100"); err != nil {
		t.Fatalf("exact match should pass: %v", err)
	}
	// Below max should pass
	if err := (ChargeRequest{Amount: "99"}).ValidateMaxAmount("100"); err != nil {
		t.Fatalf("below max should pass: %v", err)
	}
	// Above max should fail
	if err := (ChargeRequest{Amount: "101"}).ValidateMaxAmount("100"); err == nil {
		t.Fatal("above max should fail")
	}
	// Invalid max amount
	if err := (ChargeRequest{Amount: "100"}).ValidateMaxAmount("not-a-number"); err == nil {
		t.Fatal("invalid max amount should fail")
	}
	// Invalid amount
	if err := (ChargeRequest{Amount: "not-a-number"}).ValidateMaxAmount("100"); err == nil {
		t.Fatal("invalid amount should fail")
	}
}
