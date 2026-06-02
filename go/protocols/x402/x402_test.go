package x402_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	x402adapter "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

func cfg() paykit.Config {
	return paykit.Config{
		Network: paykit.SolanaLocalnet,
		Accept:  []paykit.Protocol{paykit.X402},
		Operator: paykit.Operator{
			Signer:    signer.Demo(),
			Recipient: signer.Demo().Pubkey(),
		},
		X402: paykit.X402Config{Scheme: "exact"},
		RecentBlockhashProvider: func() (string, error) {
			return "BLOCKHASH-STUB-111111111111111111111111111", nil
		},
	}
}

func TestNewRejectsDelegatedMode(t *testing.T) {
	c := cfg()
	c.X402.FacilitatorURL = "https://facilitator.example.com"
	if _, err := x402adapter.New(c); err == nil {
		t.Fatal("expected error for delegated mode")
	}
}

func TestAcceptsEntryShape(t *testing.T) {
	a, err := x402adapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "/x"}
	entry := a.AcceptsEntry(&g).(x402adapter.AcceptsEntry)
	if entry.Protocol != "x402" || entry.Scheme != "exact" {
		t.Errorf("protocol/scheme: got %s/%s", entry.Protocol, entry.Scheme)
	}
	if entry.Network != paykit.SolanaLocalnet.CAIP2() {
		t.Errorf("network: got %s", entry.Network)
	}
	if entry.Amount != "100000" || entry.MaxAmountRequired != "100000" {
		t.Errorf("amount: got %s / %s", entry.Amount, entry.MaxAmountRequired)
	}
	if entry.Extra.RecentBlockhash != "BLOCKHASH-STUB-111111111111111111111111111" {
		t.Errorf("recentBlockhash: got %s", entry.Extra.RecentBlockhash)
	}
	if entry.Extra.Decimals != 6 {
		t.Errorf("decimals: got %d", entry.Extra.Decimals)
	}
	if entry.AcceptsProtocol() != paykit.X402 {
		t.Error("AcceptsProtocol mismatch")
	}
}

func TestChallengeHeadersEmitsPaymentRequiredBase64(t *testing.T) {
	a, err := x402adapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "/x"}
	h := a.ChallengeHeaders(&g)
	if h["payment-required"] == "" {
		t.Fatal("missing header")
	}
	raw, err := base64.StdEncoding.DecodeString(h["payment-required"])
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		X402Version int `json:"x402Version"`
		Resource    struct {
			Type, URL string
		} `json:"resource"`
		Accepts []struct {
			Protocol, Network, PayTo string
		} `json:"accepts"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.X402Version != 2 {
		t.Errorf("x402Version: got %d", env.X402Version)
	}
	if len(env.Accepts) == 0 || env.Accepts[0].Protocol != "x402" {
		t.Errorf("accepts: got %+v", env.Accepts)
	}
}

func TestVerifyAndSettleRejectsMissingCredential(t *testing.T) {
	a, err := x402adapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &g})
	if err == nil {
		t.Error("expected payment_required")
	}
}

func TestVerifyAndSettleRejectsMalformedBase64(t *testing.T) {
	a, err := x402adapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &g, PaymentSig: "!!!"})
	if err == nil {
		t.Error("expected base64 decode error")
	}
}

func TestVerifyAndSettleRejectsWrongVersion(t *testing.T) {
	a, err := x402adapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	cred := x402adapter.Credential{X402Version: 99}
	raw, _ := json.Marshal(cred)
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{
		Gate:       &g,
		PaymentSig: base64.StdEncoding.EncodeToString(raw),
	})
	if err == nil {
		t.Error("expected version_mismatch")
	}
}

func TestVerifyAndSettleRejectsMissingTransaction(t *testing.T) {
	a, err := x402adapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	cred := x402adapter.Credential{X402Version: 2}
	raw, _ := json.Marshal(cred)
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{
		Gate:       &g,
		PaymentSig: base64.StdEncoding.EncodeToString(raw),
	})
	if err == nil {
		t.Error("expected missing transaction")
	}
}

func TestSchemeAccessor(t *testing.T) {
	a, err := x402adapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	if a.Protocol() != paykit.X402 {
		t.Errorf("scheme: got %v", a.Protocol())
	}
}
