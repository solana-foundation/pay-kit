package x402

// Branch-coverage tests for the usage adapter's challenge/accepts fail-soft
// paths and the settlement error propagation. The happy paths are pinned by
// TestUsageAdapterChallengeHeaders / TestUsageAdapterAcceptsEntry / the
// VerifyOpen-and-settle end-to-end test.

import (
	"context"
	"testing"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paykit"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// usageCoverageGate is the shared usage gate for these tests.
func usageCoverageGate() paykit.Gate {
	return paykit.Gate{Amount: paykit.MustParseUSD("1.00"), Kind: paykit.GateUsage, Name: "test"}
}

func TestUsageAdapterChallengeHeadersNilOnLifetimeFailure(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:  paykit.SolanaLocalnet,
		RPCURL:   "http://localhost:8899",
		Operator: paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: testSigner{signer}},
		// A blockhash provider without a slot provider fails the challenge
		// lifetime fetch (extra.recentSlot cannot be populated), so the
		// header builder fails soft with nil.
		RecentBlockhashProvider: func() (string, error) { return "4vJ9JU1bJJbzZ4aJ8AqGxH9bK5VwY8bGf3sD5QG6h7h", nil },
	}
	adapter, err := NewUsageAdapter(cfg)
	if err != nil {
		t.Fatalf("NewUsageAdapter: %v", err)
	}
	gate := usageCoverageGate()
	if headers := adapter.UsageChallengeHeaders(&gate); headers != nil {
		t.Fatalf("headers = %v, want nil on lifetime failure", headers)
	}
}

func TestUsageAdapterAcceptsEntryNilForNativeSOL(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:     paykit.SolanaLocalnet,
		RPCURL:      "http://localhost:8899",
		Operator:    paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: testSigner{signer}},
		Stablecoins: []paykit.Stablecoin{"SOL"},
	}
	adapter, err := NewUsageAdapter(cfg)
	if err != nil {
		t.Fatalf("NewUsageAdapter: %v", err)
	}
	gate := usageCoverageGate()
	if entry := adapter.UsageAcceptsEntry(&gate); entry != nil {
		t.Fatalf("entry = %v, want nil for native SOL (no SPL mint)", entry)
	}
	if headers := adapter.UsageChallengeHeaders(&gate); headers != nil {
		t.Fatalf("headers = %v, want nil for native SOL (no SPL mint)", headers)
	}
}

func TestUsageAdapterSettleActualPropagatesEngineError(t *testing.T) {
	signer := testutil.NewPrivateKey()
	cfg := paykit.Config{
		Network:  paykit.SolanaLocalnet,
		RPCURL:   "http://localhost:8899",
		Operator: paykit.Operator{Recipient: paykit.Address(signer.PublicKey().String()), Signer: testSigner{signer}},
	}
	adapter, err := NewUsageAdapter(cfg)
	if err != nil {
		t.Fatalf("NewUsageAdapter: %v", err)
	}
	// A zero-MaxAmount verified open makes any positive actual exceed the
	// authorized ceiling, so the engine settlement error must propagate.
	if _, err := adapter.SettleActual(context.Background(), &proto.UptoVerifiedOpen{}, 100); err == nil {
		t.Fatal("expected engine settlement error to propagate")
	}
}
