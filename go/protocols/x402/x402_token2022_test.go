package x402_test

import (
	"testing"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paykit"
	x402adapter "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// TestAcceptsEntryTokenProgramByCurrency guards the Token-2022 fix: the
// advertised token program must follow the settlement currency, not a
// hardcoded legacy Token program. USDG / PYUSD / CASH are Token-2022 mints,
// so a client building against the challenge would otherwise derive the
// wrong ATA and fail verification.
func TestAcceptsEntryTokenProgramByCurrency(t *testing.T) {
	a, err := x402adapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		coin string
		want string
	}{
		{"USDC", paycore.TokenProgram},
		{"USDT", paycore.TokenProgram},
		{"USDG", paycore.Token2022Program},
		{"PYUSD", paycore.Token2022Program},
		{"CASH", paycore.Token2022Program},
	}
	for _, tc := range cases {
		g := paykit.Gate{
			Amount: paykit.MustParseUSD("0.10", paykit.Stablecoin(tc.coin)),
			Desc:   "/x",
		}
		entry := a.AcceptsEntry(&g).(x402adapter.AcceptsEntry)
		if entry.Extra.TokenProgram != tc.want {
			t.Errorf("%s: token program got %s want %s", tc.coin, entry.Extra.TokenProgram, tc.want)
		}
	}
}
