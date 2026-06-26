package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
)

func TestRawAcceptedAndClearRaw(t *testing.T) {
	e := AcceptsEntry{raw: []byte(`{"foo":"bar"}`)}
	r := e.RawAccepted()
	if string(r) != `{"foo":"bar"}` {
		t.Fatalf("raw = %s", r)
	}
	e.ClearRaw()
	if e.raw != nil {
		t.Fatal("expected nil after ClearRaw")
	}
}

func TestExtractDecimals(t *testing.T) {
	if d := ExtractDecimals(nil); d != DefaultDecimals {
		t.Fatalf("default = %d", d)
	}
	e := &AcceptsEntry{}
	if d := ExtractDecimals(e); d != 0 {
		t.Fatalf("empty = %d", d)
	}
	e.Extra.Decimals = 9
	if d := ExtractDecimals(e); d != 9 {
		t.Fatalf("got %d", d)
	}
}

func TestParsePaymentSignatureMissingTransaction(t *testing.T) {
	_, _, err := ParsePaymentSignature("e30=")
	if err == nil {
		t.Fatal("expected error for missing transaction")
	}
}

func TestParsePaymentSignatureValid(t *testing.T) {
	cred, sig, err := ParsePaymentSignature("eyJ4NDAyVmVyc2lvbiI6MiwicGF5bG9hZCI6eyJ0cmFuc2FjdGlvbiI6InR4IiwiY2hhbGxlbmdlSWQiOiJjaDEifX0=")
	if err != nil {
		t.Fatalf("ParsePaymentSignature: %v", err)
	}
	if cred.Payload.Transaction != "tx" {
		t.Fatalf("transaction = %q", cred.Payload.Transaction)
	}
	if sig != "" {
		t.Fatalf("sig = %q", sig)
	}
}

func TestNormalizeNetworkAllCases(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"solana", solanaMainnetCAIP2},
		{"mainnet", solanaMainnetCAIP2},
		{"mainnet-beta", solanaMainnetCAIP2},
		{"solana-devnet", solanaDevnetCAIP2},
		{"devnet", solanaDevnetCAIP2},
		{"localnet", solanaDevnetCAIP2},
		{"solana-testnet", solanaTestnetCAIP2},
		{"testnet", solanaTestnetCAIP2},
		{"custom:network", "custom:network"},
	}
	for _, c := range cases {
		got := normalizeNetwork(c.in)
		if got != c.want {
			t.Errorf("normalizeNetwork(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseDecimalUnits(t *testing.T) {
	v, err := parseDecimalUnits("1.00", 6)
	if err != nil {
		t.Fatalf("parseDecimalUnits: %v", err)
	}
	if v != "1000000" {
		t.Fatalf("got %s", v)
	}
	_, err = parseDecimalUnits("", 6)
	if err == nil {
		t.Fatal("expected error for empty")
	}
}

func TestParseDecimalUnitsEdgeCases(t *testing.T) {
	v, err := parseDecimalUnits("0.000001", 6)
	if err != nil {
		t.Fatalf("parseDecimalUnits: %v", err)
	}
	if v != "1" {
		t.Fatalf("got %s", v)
	}
	_, err = parseDecimalUnits("abc", 6)
	if err == nil {
		t.Fatal("expected error for non-numeric")
	}
	v, err = parseDecimalUnits("0", 6)
	if err != nil {
		t.Fatalf("parseDecimalUnits(0): %v", err)
	}
	if v != "0" {
		t.Fatalf("got %s", v)
	}
	// Fractional sub-units should be truncated.
	v, err = parseDecimalUnits("1.9999999", 6)
	if err != nil {
		t.Fatalf("parseDecimalUnits(1.9999999,6): %v", err)
	}
	if v != "1999999" {
		t.Fatalf("got %s, want 1999999", v)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if v := firstNonEmpty("", "b"); v != "b" {
		t.Fatalf("got %q", v)
	}
	if v := firstNonEmpty("a", "b"); v != "a" {
		t.Fatalf("got %q", v)
	}
	if v := firstNonEmpty("", ""); v != "" {
		t.Fatalf("got %q", v)
	}
}

func TestKeyForIndexOutOfRange(t *testing.T) {
	_, err := keyForIndex(uint8(99), solana.PublicKeySlice{})
	if err == nil {
		t.Fatal("expected out of range error")
	}
}

func TestProgramIDForIx(t *testing.T) {
	pk := solana.NewWallet().PublicKey()
	ix := solana.CompiledInstruction{ProgramIDIndex: 0}
	got, err := programIDForIx(ix, solana.PublicKeySlice{pk})
	if err != nil {
		t.Fatalf("programIDForIx: %v", err)
	}
	if !got.Equals(pk) {
		t.Fatalf("got %s", got)
	}
}

func TestEmptyDistributionHash(t *testing.T) {
	h := emptyDistributionHash()
	if len(h) != 32 {
		t.Fatalf("len = %d", len(h))
	}
	expected := []byte{
		0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb,
		0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d, 0xd7, 0x48,
		0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc, 0x49, 0x8c,
		0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19,
	}
	if !bytes.Equal(h, expected) {
		t.Fatalf("empty distribution hash = %x, want %x", h, expected)
	}
}

func TestUptoVerifyOpenRejectsInvalidPayload(t *testing.T) {
	signer := testutil.NewPrivateKey()
	engine := newUptoEngineWithSigner(t, signer)
	env := UptoSignatureEnvelope{
		X402Version: X402Version,
		Scheme:      UptoScheme,
	}
	raw, _ := json.Marshal(env)
	_, err := engine.VerifyOpen(context.Background(), base64.StdEncoding.EncodeToString(raw), "1.00")
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestParseUptoPaymentSignatureInvalid(t *testing.T) {
	_, err := ParseUptoPaymentSignature("")
	if err == nil {
		t.Fatal("expected error for empty")
	}
	_, err = ParseUptoPaymentSignature("!!!invalid-base64")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestSettlementHeaderEmpty(t *testing.T) {
	engine := newUptoEngine(t)
	settlement := UptoSettlementResponse{}
	_, _, err := engine.SettlementHeader(settlement)
	if err != nil {
		t.Fatalf("SettlementHeader: %v", err)
	}
}
