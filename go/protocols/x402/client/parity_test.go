package client

import (
	"context"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	x402 "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// parseEntry runs the canonical AcceptsEntry parse so these tests see the
// same resolved view of an offer that the production client does.
func parseEntry(t *testing.T, raw string) x402.AcceptsEntry {
	t.Helper()
	var e x402.AcceptsEntry
	if err := (&e).UnmarshalJSON([]byte(raw)); err != nil {
		t.Fatalf("parse entry: %v", err)
	}
	return e
}

// transferCheckedOf returns the program and decimals byte of the single
// transferChecked in a credential transaction.
func transferCheckedOf(t *testing.T, header string) (string, uint8) {
	t.Helper()
	tx := decodeCredentialTx(t, header)
	keys := tx.Message.AccountKeys
	for _, ix := range tx.Message.Instructions {
		program := keys[ix.ProgramIDIndex].String()
		if (program == paycore.TokenProgram || program == paycore.Token2022Program) && len(ix.Data) == 10 && ix.Data[0] == 12 {
			return program, ix.Data[9]
		}
	}
	t.Fatal("no transferChecked in credential transaction")
	return "", 0
}

// RULINGS S1: the exact SVM offer carries neither decimals nor a token
// program, so the client reads both from the mint account instead of
// defaulting to the Token program and 6 decimals.
func TestBuildSPLReadsTokenProgramAndDecimalsFromMint(t *testing.T) {
	signer := testutil.NewPrivateKey()
	mint := testutil.NewPrivateKey().PublicKey()
	rpc := testutil.NewFakeRPC()
	rpc.MintOwners[mint.String()] = solana.MustPublicKeyFromBase58(paycore.Token2022Program)
	rpc.MintDecimals[mint.String()] = 9
	e := parseEntry(t, `{"scheme":"exact","network":"`+mainnetCAIP2+`","asset":"`+mint.String()+`","amount":"100000","payTo":"`+testutil.NewPrivateKey().PublicKey().String()+`","extra":{"feePayer":"`+testutil.NewPrivateKey().PublicKey().String()+`"}}`)

	header, err := BuildPaymentHeader(context.Background(), signer, rpc, &e)
	if err != nil {
		t.Fatalf("build from mint account: %v", err)
	}
	program, decimals := transferCheckedOf(t, header)
	if program != paycore.Token2022Program || decimals != 9 {
		t.Fatalf("transferChecked program=%s decimals=%d, want Token-2022 and 9 from the mint", program, decimals)
	}
}

// A missing mint is a build error, never a guessed program or decimals.
func TestBuildSPLRejectsUnreadableMint(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := parseEntry(t, `{"scheme":"exact","network":"`+mainnetCAIP2+`","asset":"`+paycore.USDCMainnetMint+`","amount":"100000","payTo":"`+testutil.NewPrivateKey().PublicKey().String()+`","extra":{}}`)
	if _, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e); err == nil {
		t.Fatal("expected a build error when the mint account cannot be read")
	}
}

// Positive control: the non-spec extra.tokenProgram + extra.decimals hints
// are honored without an RPC lookup.
func TestBuildSPLUsesServerHintsWhenComplete(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := parseEntry(t, `{"scheme":"exact","network":"`+mainnetCAIP2+`","asset":"`+paycore.USDCMainnetMint+`","amount":"100000","payTo":"`+testutil.NewPrivateKey().PublicKey().String()+`","extra":{"tokenProgram":"`+paycore.TokenProgram+`","decimals":6}}`)
	header, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err != nil {
		t.Fatalf("build with hints: %v", err)
	}
	if program, decimals := transferCheckedOf(t, header); program != paycore.TokenProgram || decimals != 6 {
		t.Fatalf("transferChecked program=%s decimals=%d, want Token and 6", program, decimals)
	}
}

// Finding #5: a literal "SOL" asset is native SOL and routes to a system
// transfer, not transferChecked, matching Rust resolve_mint -> None.
func TestBuildLiteralSOLAssetIsNative(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := parseEntry(t, `{"protocol":"x402","scheme":"exact","network":"`+mainnetCAIP2+`","asset":"SOL","amount":"5000","payTo":"`+testutil.NewPrivateKey().PublicKey().String()+`"}`)

	header, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err != nil {
		t.Fatalf("build native SOL: %v", err)
	}
	tx := decodeCredentialTx(t, header)
	for _, k := range tx.Message.AccountKeys {
		if k.String() == paycore.TokenProgram || k.String() == paycore.Token2022Program {
			t.Error("literal SOL offer must not produce an SPL token transfer")
		}
	}
	// system transfer present.
	hasSystem := false
	for _, k := range tx.Message.AccountKeys {
		if k.Equals(solana.SystemProgramID) {
			hasSystem = true
		}
	}
	if !hasSystem {
		t.Error("native SOL offer must produce a system transfer")
	}
}

// Finding #7: a seller-pinned extra.memo over 256 bytes is rejected at
// build time, matching Rust memo_instruction MAX_MEMO_BYTES.
func TestBuildRejectsOversizedSellerMemo(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := parseEntry(t, `{"protocol":"x402","scheme":"exact","network":"`+mainnetCAIP2+`","asset":"`+paycore.USDCMainnetMint+`","amount":"1","payTo":"`+testutil.NewPrivateKey().PublicKey().String()+`","extra":{"memo":"`+strings.Repeat("x", 257)+`","tokenProgram":"`+paycore.TokenProgram+`","decimals":6}}`)

	_, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err == nil || !strings.Contains(err.Error(), "extra.memo exceeds maximum") {
		t.Errorf("expected oversized memo rejection, got %v", err)
	}
}

// Finding #8: currency matching resolves BOTH the offer's asset and the
// client's preference, so a symbol offer matches a mint-address
// preference and vice versa.
func TestCurrencyMatchesBothSidesResolved(t *testing.T) {
	// Offer side is the symbol, preference side is the mint address.
	if !currencyMatches("USDC", paycore.USDCMainnetMint) {
		t.Error("symbol offer should match mint-address preference")
	}
	// Offer side is the mint, preference side is the symbol.
	if !currencyMatches(paycore.USDCMainnetMint, "USDC") {
		t.Error("mint offer should match symbol preference")
	}
}

// Finding #9: an empty preferred network defaults to mainnet, so a
// mainnet offer is selected over a devnet one rather than the cheapest
// across all networks.
func TestSelectDefaultsPreferredNetworkToMainnet(t *testing.T) {
	mainnet := entry(testutil.NewPrivateKey().PublicKey().String(), "999999", mainnetCAIP2)
	devnet := entry(testutil.NewPrivateKey().PublicKey().String(), "1", devnetCAIP2)
	got := selectEntry([]x402.AcceptsEntry{devnet, mainnet}, ChallengeSelection{})
	if got == nil || got.Network != mainnetCAIP2 {
		t.Fatalf("expected mainnet default, got %+v", got)
	}
}
