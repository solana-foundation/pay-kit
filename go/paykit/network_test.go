package paykit

import "testing"

// TestParseNetwork covers every accepted spelling and the error path.
func TestParseNetwork(t *testing.T) {
	cases := []struct {
		tag  string
		want Network
	}{
		{"localnet", SolanaLocalnet},
		{"devnet", SolanaDevnet},
		{"mainnet", SolanaMainnet},
		{"mainnet-beta", SolanaMainnet},
		{"solana_localnet", SolanaLocalnet},
		{"solana_devnet", SolanaDevnet},
		{"solana_mainnet", SolanaMainnet},
		{"MAINNET", SolanaMainnet},
		{" devnet ", SolanaDevnet},
	}
	for _, c := range cases {
		got, err := ParseNetwork(c.tag)
		if err != nil {
			t.Fatalf("ParseNetwork(%q): unexpected error %v", c.tag, err)
		}
		if got != c.want {
			t.Fatalf("ParseNetwork(%q) = %q, want %q", c.tag, got, c.want)
		}
	}
}

// TestParseNetworkRejectsUnknownTags pins the error path.
func TestParseNetworkRejectsUnknownTags(t *testing.T) {
	for _, tag := range []string{"", "testnet", "solana", "main net"} {
		if _, err := ParseNetwork(tag); err == nil {
			t.Fatalf("ParseNetwork(%q): expected error", tag)
		}
	}
}
