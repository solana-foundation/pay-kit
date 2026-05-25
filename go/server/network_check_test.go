package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go"
)

// Pure-function tests for CheckNetworkBlockhash. The check is asymmetric:
// a Surfpool-prefixed blockhash is only valid on `localnet`, but a
// non-prefixed blockhash is accepted on any network (we can't tell from a
// non-prefixed hash which real cluster it came from).

// ── happy paths ───────────────────────────────────────────────────────────

func TestNetworkCheck_LocalnetWithSurfpoolHash_OK(t *testing.T) {
	if err := CheckNetworkBlockhash("localnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestNetworkCheck_LocalnetWithRealHash_OK(t *testing.T) {
	// Real localnet validator (not Surfpool) — also valid.
	if err := CheckNetworkBlockhash("localnet", "11111111111111111111111111111111"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestNetworkCheck_MainnetWithRealHash_OK(t *testing.T) {
	if err := CheckNetworkBlockhash("mainnet", "9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestNetworkCheck_DevnetWithRealHash_OK(t *testing.T) {
	if err := CheckNetworkBlockhash("devnet", "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// ── the actual bug surface ────────────────────────────────────────────────

func TestNetworkCheck_MainnetRejectsSurfpoolHash(t *testing.T) {
	err := CheckNetworkBlockhash("mainnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var sdkErr *mpp.Error
	if !errors.As(err, &sdkErr) {
		t.Fatalf("expected *mpp.Error, got %T", err)
	}
	if sdkErr.Code != mpp.ErrCodeWrongNetwork {
		t.Errorf("expected code %q, got %q", mpp.ErrCodeWrongNetwork, sdkErr.Code)
	}
	if !strings.Contains(sdkErr.Message, "Signed against localnet") {
		t.Errorf("missing received-side: %s", sdkErr.Message)
	}
	if !strings.Contains(sdkErr.Message, "server expects mainnet") {
		t.Errorf("missing expected-side: %s", sdkErr.Message)
	}
	if !strings.Contains(sdkErr.Message, "re-sign") {
		t.Errorf("missing actionable hint: %s", sdkErr.Message)
	}
}

func TestNetworkCheck_DevnetRejectsSurfpoolHash(t *testing.T) {
	err := CheckNetworkBlockhash("devnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "server expects devnet") {
		t.Errorf("missing expected devnet: %s", err.Error())
	}
}

// ── edge cases ────────────────────────────────────────────────────────────

func TestNetworkCheck_PartialPrefixDoesNotMatch(t *testing.T) {
	// "SURFNETx" alone (8 chars) is NOT the full prefix.
	if err := CheckNetworkBlockhash("mainnet", "SURFNETx9zrUHnA1nCByPksy"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestNetworkCheck_ExactPrefixOnlyIsTreatedAsSurfpool(t *testing.T) {
	if err := CheckNetworkBlockhash("localnet", SurfpoolBlockhashPrefix); err != nil {
		t.Errorf("localnet+exact prefix should be ok: %v", err)
	}
	if err := CheckNetworkBlockhash("mainnet", SurfpoolBlockhashPrefix); err == nil {
		t.Error("mainnet+exact prefix should be wrong-network")
	}
}

func TestNetworkCheck_NonSurfpoolHashPassesAnywhere(t *testing.T) {
	// The check is asymmetric: a real-cluster-looking blockhash is
	// accepted on every network. Pin the design intent.
	for _, n := range []string{"mainnet", "devnet", "localnet"} {
		if err := CheckNetworkBlockhash(n, "11111111111111111111111111111111"); err != nil {
			t.Errorf("%s + real hash should be ok: %v", n, err)
		}
	}
}
