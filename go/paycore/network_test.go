package paycore

import "testing"

// TestParseSolanaNetwork pins the alias folding and pass-through rules.
func TestParseSolanaNetwork(t *testing.T) {
	cases := []struct {
		in   string
		want SolanaNetwork
	}{
		{"mainnet", NetworkMainnet},
		{"mainnet-beta", NetworkMainnet},
		{"MAINNET-BETA", NetworkMainnet},
		{"devnet", NetworkDevnet},
		{"testnet", NetworkTestnet},
		{"localnet", NetworkLocalnet},
		{"", SolanaNetwork("")},
		{"surfnet", SolanaNetwork("surfnet")},
	}
	for _, c := range cases {
		if got := ParseSolanaNetwork(c.in); got != c.want {
			t.Fatalf("ParseSolanaNetwork(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
