package client

import (
	"context"
	"errors"
	"testing"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

// TestBuildChargeTransactionRefusesInvalidChallenge pins RULINGS C2/C3:
// a mint challenge without decimals, or with tokenProgram omitted and a
// mint lookup that fails or returns an unexpected owner, is refused as an
// invalid challenge (never defaulted). The positive control resolves the
// program from a Token-owned mint.
func TestBuildChargeTransactionRefusesInvalidChallenge(t *testing.T) {
	signer := testutil.NewPrivateKey()
	recipient := testutil.NewPrivateKey().PublicKey().String()
	mint := testutil.NewPrivateKey().PublicKey()
	decimals := uint8(6)

	cases := []struct {
		name    string
		owner   *solana.PublicKey
		details paycore.MethodDetails
		wantErr bool
	}{
		{name: "missing_decimals", owner: &solana.TokenProgramID, details: paycore.MethodDetails{TokenProgram: paycore.TokenProgram}, wantErr: true},
		{name: "mint_not_found", details: paycore.MethodDetails{Decimals: &decimals}, wantErr: true},
		{name: "unexpected_owner", owner: &solana.SystemProgramID, details: paycore.MethodDetails{Decimals: &decimals}, wantErr: true},
		{name: "token_owner_resolves", owner: &solana.TokenProgramID, details: paycore.MethodDetails{Decimals: &decimals}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rpcClient := testutil.NewFakeRPC()
			if tc.owner != nil {
				rpcClient.MintOwners[mint.String()] = *tc.owner
			}
			_, err := BuildChargeTransaction(context.Background(), signer, rpcClient, "1000", mint.String(), recipient, tc.details, BuildOptions{})
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("build failed: %v", err)
				}
				return
			}
			var sdkErr *core.Error
			if !errors.As(err, &sdkErr) || sdkErr.Code != core.ErrCodeInvalidChallenge {
				t.Fatalf("err = %v, want code %s", err, core.ErrCodeInvalidChallenge)
			}
		})
	}
}
