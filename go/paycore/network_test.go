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

// #37: the boot-time allowlist accepts only canonical slugs and rejects the
// legacy mainnet-beta spelling, empty, and unknown values.
func TestRequireKnownNetwork(t *testing.T) {
	for _, ok := range []string{"mainnet", "devnet", "localnet"} {
		if got, err := RequireKnownNetwork(ok); err != nil || string(got) != ok {
			t.Fatalf("RequireKnownNetwork(%q) = (%q, %v), want accepted", ok, got, err)
		}
	}
	for _, bad := range []string{"mainnet-beta", "testnet", "", "MAINNET"} {
		if _, err := RequireKnownNetwork(bad); err == nil {
			t.Fatalf("RequireKnownNetwork(%q) should be rejected", bad)
		}
	}
}

func TestResolveMintCanonicalMainnet(t *testing.T) {
	// The canonical "mainnet" slug must resolve known mints just like the
	// legacy table key.
	if got := ResolveMint("USDC", "mainnet"); got != USDCMainnetMint {
		t.Fatalf("ResolveMint(USDC, mainnet) = %q, want %q", got, USDCMainnetMint)
	}
}
