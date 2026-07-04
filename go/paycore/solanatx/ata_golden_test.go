package solanatx

import (
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/paycore"
)

// TestFindAssociatedTokenAddressGoldenVectors pins the token-program-aware ATA
// derivation to fixed, canonical SPL associated-token addresses. The vectors are
// derived from the canonical program-derived-address seeds
// [wallet, tokenProgram, mint] over the SPL associated-token-account program and
// are independently reproducible with any conformant SPL implementation (they
// match the Rust SDK's get_associated_token_address output for the same inputs).
//
// This guards the derivation itself, so that swapping the underlying solana-go
// dependency cannot silently change any ATA the SDK produces.
func TestFindAssociatedTokenAddressGoldenVectors(t *testing.T) {
	// A stable, valid 32-byte public key used purely as a deterministic fixture.
	wallet := solana.MustPublicKeyFromBase58("So11111111111111111111111111111111111111112")
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	token2022 := solana.MustPublicKeyFromBase58(paycore.Token2022Program)

	cases := []struct {
		name         string
		tokenProgram solana.PublicKey
		want         string
	}{
		{
			name:         "classic token program",
			tokenProgram: solana.TokenProgramID,
			want:         "DHe62eeQVEnNK7vg5xUpDkJm7tuqHadjhvmPRFBG9UPo",
		},
		{
			name:         "token-2022 program",
			tokenProgram: token2022,
			want:         "taYqGwEHpcdcznSxzJVnctU3PV2XFzZq8zvyeK2KG9P",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ata, err := FindAssociatedTokenAddressWithProgram(wallet, mint, tc.tokenProgram)
			if err != nil {
				t.Fatalf("derive ATA: %v", err)
			}
			if ata.String() != tc.want {
				t.Fatalf("ATA mismatch: got %s, want %s", ata, tc.want)
			}
		})
	}

	// The two programs must yield distinct ATAs for the same wallet+mint; a
	// regression that collapses the token-program seed would surface here.
	classic, err := FindAssociatedTokenAddressWithProgram(wallet, mint, solana.TokenProgramID)
	if err != nil {
		t.Fatalf("derive classic ATA: %v", err)
	}
	alt, err := FindAssociatedTokenAddressWithProgram(wallet, mint, token2022)
	if err != nil {
		t.Fatalf("derive token-2022 ATA: %v", err)
	}
	if classic.Equals(alt) {
		t.Fatal("token and token-2022 ATAs must differ for the same wallet and mint")
	}
}
