package mpp_test

import (
	"testing"

	"github.com/solana-foundation/pay-kit/go/paykit"
	mppadapter "github.com/solana-foundation/pay-kit/go/paykit/schemes/mpp"
	"github.com/solana-foundation/pay-kit/go/paykit/signer"
)

func cfg() paykit.Config {
	return paykit.Config{
		Network: paykit.SolanaLocalnet,
		Accept:  []paykit.Scheme{paykit.MPP},
		Operator: paykit.Operator{
			Signer:    signer.Demo(),
			Recipient: signer.Demo().Pubkey(),
		},
		MPP: paykit.MPPConfig{
			Realm:                  "Unit",
			ChallengeBindingSecret: []byte("unit-secret"),
		},
	}
}

func TestNewRejectsMissingSecret(t *testing.T) {
	c := cfg()
	c.MPP.ChallengeBindingSecret = nil
	if _, err := mppadapter.New(c); err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestAcceptsEntryShape(t *testing.T) {
	a, err := mppadapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10"), Desc: "/x"}
	entry := a.AcceptsEntry(&g)
	if entry["protocol"] != "mpp" {
		t.Errorf("protocol: got %v", entry["protocol"])
	}
	if entry["scheme"] != "charge" {
		t.Errorf("scheme: got %v", entry["scheme"])
	}
	if entry["realm"] != "Unit" {
		t.Errorf("realm: got %v", entry["realm"])
	}
	if entry["network"] != paykit.SolanaLocalnet.CAIP2() {
		t.Errorf("network: got %v", entry["network"])
	}
	if entry["amount"] != "100000" {
		t.Errorf("amount: got %v want 100000", entry["amount"])
	}
}

func TestAcceptsEntryAddsSplitsForFeeGate(t *testing.T) {
	a, err := mppadapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	g := paykit.Gate{
		Amount: paykit.MustParseUSD("10.00"),
		PayTo:  paykit.Address("SELLER"),
		FeeWithin: paykit.Fees{
			paykit.Address("PLATFORM"): paykit.MustParseUSD("0.30"),
		},
	}
	entry := a.AcceptsEntry(&g)
	splits, ok := entry["splits"].([]map[string]any)
	if !ok || len(splits) == 0 {
		t.Fatalf("expected splits[], got %T %v", entry["splits"], entry["splits"])
	}
}

func TestVerifyAndSettleRejectsMissingAuthorization(t *testing.T) {
	a, err := mppadapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{
		Method: "GET", Path: "/x", Gate: &g,
	})
	if err == nil {
		t.Error("expected payment_required error")
	}
}

func TestVerifyAndSettleRejectsMalformedAuthorization(t *testing.T) {
	a, err := mppadapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{
		Method:        "GET",
		Path:          "/x",
		Authorization: "Payment garbage-not-base64",
		Gate:          &g,
	})
	if err == nil {
		t.Error("expected invalid_payload error")
	}
}

func TestSchemeAccessor(t *testing.T) {
	a, err := mppadapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	if a.Scheme() != paykit.MPP {
		t.Errorf("scheme: got %v", a.Scheme())
	}
}
