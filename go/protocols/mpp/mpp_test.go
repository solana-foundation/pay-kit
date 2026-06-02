package mpp_test

import (
	"testing"

	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	mppadapter "github.com/solana-foundation/pay-kit/go/protocols/mpp"
)

func cfg() paykit.Config {
	return paykit.Config{
		Network: paykit.SolanaLocalnet,
		Accept:  []paykit.Protocol{paykit.MPP},
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
	entry, ok := a.AcceptsEntry(&g).(mppadapter.AcceptsEntry)
	if !ok {
		t.Fatal("expected mppadapter.AcceptsEntry")
	}
	if entry.Protocol != "mpp" || entry.Scheme != "charge" {
		t.Errorf("protocol/scheme: got %s/%s", entry.Protocol, entry.Scheme)
	}
	if entry.Realm != "Unit" {
		t.Errorf("realm: got %s", entry.Realm)
	}
	if entry.Network != paykit.SolanaLocalnet.CAIP2() {
		t.Errorf("network: got %s", entry.Network)
	}
	if entry.Amount != "100000" {
		t.Errorf("amount: got %s want 100000", entry.Amount)
	}
	if entry.AcceptsProtocol() != paykit.MPP {
		t.Error("AcceptsProtocol mismatch")
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
	entry := a.AcceptsEntry(&g).(mppadapter.AcceptsEntry)
	if len(entry.Splits) == 0 {
		t.Fatal("expected splits[]")
	}
	if entry.Splits[0].Recipient != "PLATFORM" {
		t.Errorf("split recipient: got %s", entry.Splits[0].Recipient)
	}
}

func TestVerifyAndSettleRejectsMissingAuthorization(t *testing.T) {
	a, err := mppadapter.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Method: "GET", Path: "/x", Gate: &g})
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
	if a.Protocol() != paykit.MPP {
		t.Errorf("scheme: got %v", a.Protocol())
	}
}
