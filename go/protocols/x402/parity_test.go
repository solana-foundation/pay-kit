package x402

import (
	"encoding/json"
	"testing"
)

// These tests pin the canonical-wire parse precedence to the Rust spine
// (rust/crates/x402/src/protocol/schemes/exact/types.rs Deserialize and
// client/exact/payment.rs build_payment). Each one fails before the
// AcceptsEntry.UnmarshalJSON precedence/default fix and passes after.

// Finding #1: amount falls back to maxAmountRequired when amount absent.
func TestParseAmountFallsBackToMaxAmountRequired(t *testing.T) {
	raw := []byte(`{"protocol":"x402","scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","maxAmountRequired":"123456","payTo":"abc"}`)
	var e AcceptsEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.Amount != "123456" {
		t.Errorf("amount fallback: got %q want 123456", e.Amount)
	}
}

// Finding #2: decimals default to 6 when absent (rust unwrap_or(6)).
func TestParseDecimalsDefaultsToSix(t *testing.T) {
	raw := []byte(`{"protocol":"x402","scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","amount":"1","payTo":"abc"}`)
	var e AcceptsEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.Extra.Decimals != 6 {
		t.Errorf("decimals default: got %d want 6", e.Extra.Decimals)
	}
}

// Finding #4: explicit feePayer:false opts out even with a key present
// (rust use_fee_payer = fee_payer.unwrap_or(false) && key.is_some()).
func TestParseFeePayerExplicitFalseOptsOut(t *testing.T) {
	raw := []byte(`{"protocol":"x402","scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","amount":"1","payTo":"abc","feePayer":false,"feePayerKey":"FEE"}`)
	var e AcceptsEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.Extra.FeePayer {
		t.Error("explicit feePayer:false should opt out of server fee payer")
	}
	if e.Extra.FeePayerKey != "FEE" {
		t.Errorf("feePayerKey: got %q want FEE", e.Extra.FeePayerKey)
	}
}

// Finding #4: extra.feePayer string is the key, fee_payer defaults true.
func TestParseFeePayerKeyFromExtraDefaultsTrue(t *testing.T) {
	raw := []byte(`{"protocol":"x402","scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","amount":"1","payTo":"abc","extra":{"feePayer":"FEEKEY"}}`)
	var e AcceptsEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if !e.Extra.FeePayer || e.Extra.FeePayerKey != "FEEKEY" {
		t.Errorf("extra.feePayer: feePayer=%v key=%q want true/FEEKEY", e.Extra.FeePayer, e.Extra.FeePayerKey)
	}
}

// Finding #6: top-level canonical fields win over extra.* mirrors, and
// payTo falls back to recipient, asset to currency.
func TestParseTopLevelPrecedence(t *testing.T) {
	raw := []byte(`{"protocol":"x402","scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","currency":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","amount":"7","recipient":"RCPT","tokenProgram":"TopLvlTP","decimals":9,"extra":{"tokenProgram":"ExtraTP","decimals":2}}`)
	var e AcceptsEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.Asset != "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" {
		t.Errorf("asset from currency: got %q", e.Asset)
	}
	if e.PayTo != "RCPT" {
		t.Errorf("payTo from recipient: got %q", e.PayTo)
	}
	if e.Extra.TokenProgram != "TopLvlTP" {
		t.Errorf("tokenProgram top-level precedence: got %q want TopLvlTP", e.Extra.TokenProgram)
	}
	if e.Extra.Decimals != 9 {
		t.Errorf("decimals top-level precedence: got %d want 9", e.Extra.Decimals)
	}
}

// Finding #9: cluster-slug network normalizes to its canonical CAIP-2.
func TestParseNetworkNormalization(t *testing.T) {
	cases := map[string]string{
		"mainnet":       solanaMainnetCAIP2,
		"mainnet-beta":  solanaMainnetCAIP2,
		"devnet":        solanaDevnetCAIP2,
		"solana-devnet": solanaDevnetCAIP2,
		"localnet":      solanaDevnetCAIP2,
		"testnet":       solanaTestnetCAIP2,
	}
	for slug, want := range cases {
		raw := []byte(`{"protocol":"x402","scheme":"exact","network":"` + slug + `","asset":"A","amount":"1","payTo":"abc"}`)
		var e AcceptsEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		if e.Network != want {
			t.Errorf("network %q normalized to %q, want %q", slug, e.Network, want)
		}
	}
}

// Finding #12: the parsed offer retains its verbatim bytes so the client
// can echo accepted without dropping unknown keys, and MarshalJSON emits
// them verbatim.
func TestParsedAcceptedEchoesVerbatim(t *testing.T) {
	raw := []byte(`{"protocol":"x402","scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","asset":"A","amount":"1","payTo":"abc","futureUnknownKey":{"nested":true}}`)
	var e AcceptsEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(&e)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["futureUnknownKey"]; !ok {
		t.Errorf("verbatim echo dropped unknown key: %s", out)
	}
}

// Finding #13: maxTimeoutSeconds defaults to 300 when absent (rust
// max_age.unwrap_or(300)).
func TestParseMaxTimeoutDefaultsTo300(t *testing.T) {
	raw := []byte(`{"protocol":"x402","scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","asset":"A","amount":"1","payTo":"abc"}`)
	var e AcceptsEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.MaxTimeoutSeconds != 300 {
		t.Errorf("maxTimeoutSeconds default: got %d want 300", e.MaxTimeoutSeconds)
	}
}
