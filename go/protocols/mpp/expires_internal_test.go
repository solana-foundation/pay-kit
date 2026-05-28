package mpp

import (
	"testing"
	"time"

	"github.com/solana-foundation/pay-kit/go/paykit"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
)

func TestChargeOptionsThreadsExpiresIn(t *testing.T) {
	a := &Adapter{cfg: paykit.Config{
		Network: paykit.SolanaLocalnet,
		MPP:     paykit.MPPConfig{ExpiresIn: 90 * time.Second},
	}}
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	opts := a.chargeOptions(&gate)
	if opts.Expires == "" {
		t.Fatal("expected Expires to be set from MPPConfig.ExpiresIn")
	}
	exp, err := time.Parse(time.RFC3339, opts.Expires)
	if err != nil {
		t.Fatalf("Expires is not RFC3339: %v", err)
	}
	delta := time.Until(exp)
	if delta < 60*time.Second || delta > 120*time.Second {
		t.Errorf("expiry %s is not ~90s out (delta %s)", opts.Expires, delta)
	}
}

func TestChargeOptionsZeroExpiresInLeavesDefault(t *testing.T) {
	a := &Adapter{cfg: paykit.Config{Network: paykit.SolanaLocalnet}}
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	if opts := a.chargeOptions(&gate); opts.Expires != "" {
		t.Errorf("expected empty Expires (server default 5min) when ExpiresIn==0, got %q", opts.Expires)
	}
}

// guard the core.Seconds helper stays available for the threading above.
var _ = core.Seconds
