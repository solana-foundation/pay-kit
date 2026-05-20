package protocol

import (
	"encoding/json"
	"testing"
)

func TestDefaultRPCURL(t *testing.T) {
	if DefaultRPCURL("devnet") != "https://api.devnet.solana.com" {
		t.Fatal("unexpected devnet rpc url")
	}
	if DefaultRPCURL("localnet") != "http://localhost:8899" {
		t.Fatal("unexpected localnet rpc url")
	}
	if DefaultRPCURL("unknown") != "https://api.mainnet-beta.solana.com" {
		t.Fatal("unexpected default rpc url")
	}
}

func TestResolveMint(t *testing.T) {
	if ResolveMint("sol", "localnet") != "" {
		t.Fatal("expected SOL to resolve to native asset")
	}
	if ResolveMint("USDC", "localnet") != USDCMainnetMint {
		t.Fatal("unexpected localnet usdc mint")
	}
	if ResolveMint("USDC", "devnet") != USDCDevnetMint {
		t.Fatal("unexpected devnet usdc mint")
	}
	if ResolveMint("USDT", "localnet") != USDTMainnetMint {
		t.Fatal("unexpected localnet usdt mint")
	}
	if ResolveMint("USDG", "devnet") != USDGDevnetMint {
		t.Fatal("unexpected devnet usdg mint")
	}
	if ResolveMint("PYUSD", "localnet") != PYUSDMainnetMint {
		t.Fatal("unexpected localnet pyusd mint")
	}
	if ResolveMint("CASH", "localnet") != CASHMainnetMint {
		t.Fatal("unexpected localnet cash mint")
	}
	if ResolveMint("SomeMint1111111111111111111111111111111111", "localnet") != "SomeMint1111111111111111111111111111111111" {
		t.Fatal("unexpected passthrough mint")
	}
}

func TestStablecoinSymbol(t *testing.T) {
	if StablecoinSymbol("USDG") != "USDG" {
		t.Fatal("expected USDG symbol")
	}
	if StablecoinSymbol(USDGMainnetMint) != "USDG" {
		t.Fatal("expected USDG mint to resolve to symbol")
	}
	if StablecoinSymbol("SomeMint1111111111111111111111111111111111") != "" {
		t.Fatal("expected unknown mint to have no symbol")
	}
}

func TestDefaultTokenProgramForCurrency(t *testing.T) {
	for _, currency := range []string{"PYUSD", PYUSDMainnetMint, "USDG", USDGMainnetMint, "CASH", CASHMainnetMint} {
		if DefaultTokenProgramForCurrency(currency, "mainnet-beta") != Token2022Program {
			t.Fatalf("expected %s to default to Token-2022", currency)
		}
	}
	for _, currency := range []string{"USDC", USDCMainnetMint, "USDT", USDTMainnetMint} {
		if DefaultTokenProgramForCurrency(currency, "mainnet-beta") != TokenProgram {
			t.Fatalf("expected %s to default to SPL Token", currency)
		}
	}
}

func TestSplitJSONIncludesAtaCreationRequired(t *testing.T) {
	ataCreationRequired := true
	raw, err := json.Marshal(Split{
		Recipient:           "recipient",
		Amount:              "250",
		AtaCreationRequired: &ataCreationRequired,
	})
	if err != nil {
		t.Fatalf("marshal split: %v", err)
	}
	want := `{"recipient":"recipient","amount":"250","ataCreationRequired":true}`
	if string(raw) != want {
		t.Fatalf("unexpected split json:\n got %s\nwant %s", raw, want)
	}
}
