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
	raw := []byte(`{"protocol":"x402","scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","amount":"1","payTo":"abc","feePayer":false,"extra":{"feePayer":"FEE"}}`)
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

// RULINGS X1: a field a server adds beside the x402 ones is ignored, so a
// legacy-only offer names no payTo, asset or extra.* terms.
func TestParseIgnoresNonSpecTopLevelFields(t *testing.T) {
	raw := []byte(`{"protocol":"x402","scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","currency":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","amount":"7","recipient":"RCPT","tokenProgram":"TopLvlTP","decimals":9,"feePayerKey":"FEE"}`)
	var e AcceptsEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.PayTo != "" || e.Asset != "" {
		t.Errorf("payTo %q / asset %q read from recipient / currency", e.PayTo, e.Asset)
	}
	if e.Extra.TokenProgram != "" || e.Extra.DecimalsSet || e.Extra.FeePayerKey != "" {
		t.Errorf("extra %+v read from top-level fields", e.Extra)
	}
}

const v2Offer = `{"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"1000","asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","payTo":"CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY","maxTimeoutSeconds":300,"extra":{"decimals":6,"tokenProgram":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","recentBlockhash":"11111111111111111111111111111111","feePayer":"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"}}`

func v2OfferWith(t *testing.T, key string, value any) []byte {
	t.Helper()
	var offer map[string]any
	if err := json.Unmarshal([]byte(v2Offer), &offer); err != nil {
		t.Fatal(err)
	}
	offer[key] = value
	raw, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// SOLA1-273: the signed transfer must pay what the echoed `accepted` names,
// so a disagreeing legacy alias never replaces its x402 field (RULINGS X1).
func TestParseIgnoresDisagreeingLegacyAliases(t *testing.T) {
	other := "11111111111111111111111111111112"
	for key, value := range map[string]any{
		"recipient":         other,
		"currency":          "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
		"maxAmountRequired": "999999",
		"tokenProgram":      "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
		"recentBlockhash":   other,
		"feePayerKey":       other,
		"decimals":          9,
		"maxAge":            60,
	} {
		var e AcceptsEntry
		if err := json.Unmarshal(v2OfferWith(t, key, value), &e); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if e.PayTo != "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY" ||
			e.Asset != "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" ||
			e.Amount != "1000" || e.MaxTimeoutSeconds != 300 ||
			e.Extra.TokenProgram != "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" ||
			e.Extra.RecentBlockhash != "11111111111111111111111111111111" ||
			e.Extra.FeePayerKey != "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin" ||
			e.Extra.Decimals != 6 {
			t.Errorf("%s replaced an x402 field: %+v", key, e)
		}
	}
}

func TestParseAcceptsAgreeingLegacyAliases(t *testing.T) {
	var canonical map[string]any
	if err := json.Unmarshal([]byte(v2Offer), &canonical); err != nil {
		t.Fatal(err)
	}
	extra := canonical["extra"].(map[string]any)
	canonical["recipient"] = canonical["payTo"]
	canonical["currency"] = canonical["asset"]
	canonical["maxAmountRequired"] = canonical["amount"]
	canonical["maxAge"] = canonical["maxTimeoutSeconds"]
	canonical["decimals"] = extra["decimals"]
	canonical["tokenProgram"] = extra["tokenProgram"]
	canonical["feePayerKey"] = extra["feePayer"]
	raw, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	var e AcceptsEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("agreeing aliases rejected: %v", err)
	}
	if e.PayTo != canonical["payTo"] || e.Asset != canonical["asset"] || e.Amount != "1000" {
		t.Errorf("parsed %+v, want the canonical terms", e)
	}
	if e.Extra.FeePayerKey != extra["feePayer"] || e.Extra.Decimals != 6 {
		t.Errorf("extra %+v, want the canonical fee payer and decimals", e.Extra)
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

// `network` is required: an offer without it is refused rather than signed
// for a network the client would have to guess.
func TestParseRejectsOfferWithoutNetwork(t *testing.T) {
	var offer map[string]any
	if err := json.Unmarshal([]byte(v2Offer), &offer); err != nil {
		t.Fatal(err)
	}
	delete(offer, "network")
	raw, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	var e AcceptsEntry
	if err := json.Unmarshal(raw, &e); err == nil {
		t.Fatalf("parsed an offer without network: %+v", e)
	}
}
