package server

import (
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	mpp "github.com/solana-foundation/mpp-sdk/go"
	"github.com/solana-foundation/mpp-sdk/go/protocol"
)

// TestValidateSplitsCount table-tests the cap that prevents a client from
// submitting more than the cross-SDK maximum of 8 splits.
func TestValidateSplitsCount(t *testing.T) {
	cases := []struct {
		name    string
		count   int
		wantErr bool
	}{
		{"empty", 0, false},
		{"single", 1, false},
		{"at_cap", 8, false},
		{"over_cap_by_one", 9, true},
		{"over_cap_by_many", 20, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			splits := make([]protocol.Split, tc.count)
			err := validateSplitsCount(splits)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				sdkErr, ok := err.(*mpp.Error)
				if !ok {
					t.Fatalf("expected *mpp.Error, got %T", err)
				}
				if sdkErr.Code != mpp.ErrCodeTooManySplits {
					t.Fatalf("code = %q, want %q", sdkErr.Code, mpp.ErrCodeTooManySplits)
				}
				if !strings.Contains(sdkErr.Message, "maximum 8") {
					t.Fatalf("message missing cap text: %q", sdkErr.Message)
				}
				countStr := []string{"9", "20"}[map[int]int{9: 0, 20: 1}[tc.count]]
				if !strings.Contains(sdkErr.Message, countStr) {
					t.Fatalf("message missing observed count %q: %q", countStr, sdkErr.Message)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

// buildTxWithComputeBudgetIx builds a single-instruction transaction whose
// only instruction targets the ComputeBudget program with the given data
// bytes. Account list is empty (the on-chain program takes none).
func buildTxWithComputeBudgetIx(_ *testing.T, data []byte) *solana.Transaction {
	return &solana.Transaction{
		Message: solana.Message{
			AccountKeys: []solana.PublicKey{computeBudgetProgramID},
			Instructions: []solana.CompiledInstruction{
				{ProgramIDIndex: 0, Accounts: []uint16{}, Data: solana.Base58(data)},
			},
		},
	}
}

// encodeUnitLimit emits the on-chain wire bytes for SetComputeUnitLimit(units).
func encodeUnitLimit(units uint32) []byte {
	return []byte{2,
		byte(units), byte(units >> 8), byte(units >> 16), byte(units >> 24),
	}
}

// encodeUnitPrice emits the on-chain wire bytes for SetComputeUnitPrice(micro).
func encodeUnitPrice(micro uint64) []byte {
	return []byte{3,
		byte(micro), byte(micro >> 8), byte(micro >> 16), byte(micro >> 24),
		byte(micro >> 32), byte(micro >> 40), byte(micro >> 48), byte(micro >> 56),
	}
}

// TestValidateComputeBudgetInstructions table-tests the cap that mirrors
// the rust/typescript reference. Values at the cap pass; one over rejects
// with a payment_invalid-routed error whose message names both the
// observed value and the cap.
func TestValidateComputeBudgetInstructions(t *testing.T) {
	cases := []struct {
		name       string
		data       []byte
		wantErr    bool
		wantSubstr []string
	}{
		{"limit_at_cap", encodeUnitLimit(maxComputeUnitLimit), false, nil},
		{"limit_one_over", encodeUnitLimit(maxComputeUnitLimit + 1), true,
			[]string{"200001", "200000", "compute unit limit"}},
		{"limit_far_over", encodeUnitLimit(1_000_000), true,
			[]string{"1000000", "200000"}},
		{"price_at_cap", encodeUnitPrice(maxComputeUnitPriceMicroLamports), false, nil},
		{"price_one_over", encodeUnitPrice(maxComputeUnitPriceMicroLamports + 1), true,
			[]string{"5000001", "5000000", "compute unit price"}},
		{"unsupported_discriminator", []byte{42, 0, 0, 0, 0}, true,
			[]string{"unsupported", "42"}},
		{"empty_data", []byte{}, true, []string{"empty"}},
		{"truncated_limit", []byte{2, 1, 2}, true, []string{"3 data bytes"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := buildTxWithComputeBudgetIx(t, tc.data)
			err := validateComputeBudgetInstructions(tx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				sdkErr, ok := err.(*mpp.Error)
				if !ok {
					t.Fatalf("expected *mpp.Error, got %T", err)
				}
				if sdkErr.Code != mpp.ErrCodeComputeBudgetExceeded {
					t.Fatalf("code = %q, want %q", sdkErr.Code, mpp.ErrCodeComputeBudgetExceeded)
				}
				for _, want := range tc.wantSubstr {
					if !strings.Contains(sdkErr.Message, want) {
						t.Fatalf("message %q missing substring %q", sdkErr.Message, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

// TestValidateComputeBudgetInstructions_NonComputeBudgetIgnored confirms
// that instructions targeting other programs do not trip the validator.
func TestValidateComputeBudgetInstructions_NonComputeBudgetIgnored(t *testing.T) {
	other := solana.MustPublicKeyFromBase58("11111111111111111111111111111111")
	tx := &solana.Transaction{
		Message: solana.Message{
			AccountKeys: []solana.PublicKey{other},
			Instructions: []solana.CompiledInstruction{
				{ProgramIDIndex: 0, Data: solana.Base58{0xff, 0xff, 0xff, 0xff, 0xff}},
			},
		},
	}
	if err := validateComputeBudgetInstructions(tx); err != nil {
		t.Fatalf("expected nil error for non-compute-budget instruction, got %v", err)
	}
}

// TestValidateComputeBudgetInstructions_RejectsAccounts ensures a
// ComputeBudget instruction that smuggles account refs is rejected.
func TestValidateComputeBudgetInstructions_RejectsAccounts(t *testing.T) {
	tx := &solana.Transaction{
		Message: solana.Message{
			AccountKeys: []solana.PublicKey{computeBudgetProgramID, solana.SystemProgramID},
			Instructions: []solana.CompiledInstruction{
				{ProgramIDIndex: 0, Accounts: []uint16{1}, Data: solana.Base58(encodeUnitLimit(1000))},
			},
		},
	}
	err := validateComputeBudgetInstructions(tx)
	if err == nil {
		t.Fatal("expected error for compute-budget instruction with accounts")
	}
	sdkErr, ok := err.(*mpp.Error)
	if !ok {
		t.Fatalf("expected *mpp.Error, got %T", err)
	}
	if sdkErr.Code != mpp.ErrCodeComputeBudgetExceeded {
		t.Fatalf("code = %q, want %q", sdkErr.Code, mpp.ErrCodeComputeBudgetExceeded)
	}
}

